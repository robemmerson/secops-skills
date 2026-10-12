"""Offline tests for input-hardening fixes in devo.py: the helper also runs as a subprocess for MCP clients,
so file paths, cache writes, redirects and regexes must be safe on input the person at the keyboard didn't
type. Run: python3 -m unittest discover plugins/devo/tests"""
import contextlib, io, json, os, socket, subprocess, sys, tempfile, threading, time, unittest
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "devo", "scripts"))
import devo  # noqa: E402
from test_devo import CFG, FakeResp, NOW, run_cli  # noqa: E402

SPECS = os.path.join(devo.SKILL_DIR, "references", "specs")
SCRIPTS = os.path.join(devo.SKILL_DIR, "scripts")


class CacheCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.cache = devo.Cache(CFG, root=self.root, env={})
        devo.CACHE = self.cache
        self.err = io.StringIO()
        self.quiet = contextlib.redirect_stderr(self.err)
        self.quiet.__enter__()

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        devo.CACHE = None


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class QueryFileTests(unittest.TestCase):
    """1. query_file must stay inside the spec's folder and be a .linq file."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dir = os.path.join(self.tmp, "spec")
        write(os.path.join(self.dir, "sub", "q.linq"), "from t.x select a")
        self.secret = write(os.path.join(self.tmp, "secret.linq"), "TOKEN=hunter2")
        write(os.path.join(self.tmp, "env"), "TOKEN=hunter2")

    def load(self, query_file):
        spec = os.path.join(self.dir, "spec.json")
        with open(spec, "w", encoding="utf-8") as f:
            json.dump([{"name": "j", "query_file": query_file}], f)
        return devo.load_spec(spec)

    def test_a_file_under_the_spec_folder_loads(self):
        self.assertEqual(self.load("sub/q.linq")[0]["query"], "from t.x select a")

    def test_paths_outside_the_folder_are_refused(self):
        for bad in (self.secret, "../secret.linq", "sub/../../secret.linq", "~/secret.linq", "../env",
                    "/proc/self/environ", "sub/q.txt", "sub", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(devo.DevoError) as cm:
                    self.load(bad)
                self.assertNotIn("hunter2", str(cm.exception))

    @unittest.skipIf(os.name == "nt", "symlinks need extra rights on Windows")
    def test_a_symlink_out_of_the_folder_is_refused(self):
        os.symlink(self.secret, os.path.join(self.dir, "link.linq"))
        with self.assertRaises(devo.DevoError):
            self.load("link.linq")

    def test_bundled_specs_still_load(self):
        specs = [f for f in os.listdir(SPECS) if f.endswith(".jsonl")]
        self.assertTrue(specs)
        for name in specs:
            with self.subTest(spec=name):
                jobs = devo.load_spec(os.path.join(SPECS, name))
                self.assertTrue(all(j.get("query") for j in jobs))


class MismatchTests(CacheCase):
    """2. Only the table the error names is marked unqueryable, and only after a schema lookup agrees."""

    def setUp(self):
        super().setUp()
        self.cache.put("tables", [["t.a", 5], ["t.b", 4], ["t.c", 3]])

    def test_only_the_named_table_is_marked(self):
        q = 'from t.a where x in (from t.b select x), msg = "from t.c"'
        with mock.patch.object(devo, "table_missing", return_value=True) as look:
            devo.cache_mismatch(q, devo.DevoError("HTTP 500: Unknown table `t.b`"), CFG)
        look.assert_called_once_with(CFG, "t.b")
        self.assertEqual(self.cache.read("tables")["unqueryable"], ["t.b"])
        self.assertEqual([t for t, _ in self.cache.get("tables")], ["t.a", "t.c"])

    def test_table_names_inside_strings_are_ignored(self):
        q = 'from t.a where msg = "Unknown table `t.c`"'
        with mock.patch.object(devo, "table_missing", return_value=True):
            devo.cache_mismatch(q, devo.DevoError("HTTP 500: Unknown table `t.c`"), CFG)
        self.assertEqual(self.cache.state("tables"), "fresh")
        self.assertEqual(len(self.cache.get("tables")), 3)

    def test_a_schema_lookup_that_finds_the_table_writes_nothing(self):
        with mock.patch.object(devo, "table_missing", return_value=False):
            devo.cache_mismatch("from t.a select *", devo.DevoError("HTTP 403: Access not allowed for table t.a"), CFG)
        self.assertEqual(len(self.cache.get("tables")), 3)
        self.assertNotIn("unqueryable", self.cache.read("tables"))

    def test_no_name_or_no_credentials_writes_nothing(self):
        with mock.patch.object(devo, "table_missing", return_value=True):
            devo.cache_mismatch("from t.a select *", devo.DevoError("HTTP 403: Access not allowed for table"), CFG)
            devo.cache_mismatch("from t.a select *", devo.DevoError("Unknown table `t.a`"), None)
        self.assertEqual(len(self.cache.get("tables")), 3)

    def test_table_missing_reads_the_schema_status(self):
        with mock.patch.object(devo, "get_json", side_effect=devo.DevoError("HTTP 403: Access not allowed")):
            self.assertTrue(devo.table_missing(CFG, "t.a"))
        with mock.patch.object(devo, "get_json", side_effect=devo.DevoError("HTTP 404: not found")):
            self.assertTrue(devo.table_missing(CFG, "t.a"))
        with mock.patch.object(devo, "get_json", return_value={"object": [{"fieldName": "a", "type": "str"}]}):
            self.assertFalse(devo.table_missing(CFG, "t.a"))
        with mock.patch.object(devo, "get_json", side_effect=devo.DevoError("HTTP 503: busy")):
            self.assertFalse(devo.table_missing(CFG, "t.a"))  # can't tell: don't touch the cache


class StreamTests(unittest.TestCase):
    """3 and 4: multi-byte characters across reads, and a quiet socket."""

    def test_utf8_split_across_reads(self):
        body = ('{"m":{"u":{"type":"str","index":0}}}\n{"d":["José Ñúñez 日本"]}\n').encode("utf-8")
        with mock.patch.object(devo, "http_open", return_value=FakeResp(body, chunk=1)):
            rows = [r for _, r in devo.run_query(CFG, "from t.x", 1, 2, 0, 60) if r]
        self.assertEqual(rows, [["José Ñúñez 日本"]])

    def test_a_read_timeout_ends_the_attempt_without_a_retry(self):
        class Quiet(FakeResp):
            def __init__(self):
                super().__init__(b"")
                self.timed_out = False

            def read1(self, n):
                if self.timed_out:  # what CPython's SocketIO does after a timeout
                    raise OSError("cannot read from timed out object")
                self.timed_out = True
                raise socket.timeout("timed out")

        calls = []

        def opener(*a, **k):
            calls.append(1)
            return Quiet()

        with mock.patch.object(devo, "http_open", opener), mock.patch.object(devo, "RETRY_DELAY", 0):
            with self.assertRaises(devo.DevoError) as cm:
                devo.fetch(CFG, "from t.x select *", 1, 2, 10, 600)
        self.assertEqual(len(calls), 1)
        self.assertEqual(cm.exception.code, 3)
        self.assertNotIn("connection dropped", str(cm.exception))
        self.assertIn("no data", str(cm.exception))


class LockTests(CacheCase):
    """5. Read-modify-write sequences hold <cache dir>/.lock; the field map knows which profiles it holds."""

    def test_the_lock_excludes_another_process(self):
        code = ("import sys, time; sys.path.insert(0, sys.argv[1]); import devo; "
                "c = devo.Cache({'token': 'x', 'region': 'eu'}, root=sys.argv[2], env={})\n"
                "with c.lock():\n    print('locked', flush=True); time.sleep(1.5)\n")
        p = subprocess.Popen([sys.executable, "-c", code, SCRIPTS, self.root], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(p.stdout.readline().strip(), "locked")
            mine = devo.Cache({"token": "x", "region": "eu"}, root=self.root, env={})
            start = time.time()
            with mine.lock():
                waited = time.time() - start
            self.assertGreater(waited, 0.5)
        finally:
            p.wait(10)
            p.stdout.close()

    def test_the_lock_is_reentrant_in_one_thread(self):
        with self.cache.lock():
            with self.cache.lock():
                self.cache.invalidate("tables")

    def test_parallel_note_adds_keep_every_note(self):
        def add(i):
            devo.cmd_cache(CFG, argparse_ns(action="note", what=["add", f"note {i}"], json=False))

        threads = [threading.Thread(target=add, args=(i,)) for i in range(20)]
        with contextlib.redirect_stdout(io.StringIO()):  # once: redirect_stdout isn't thread-safe
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        notes = devo.load_notes()["notes"]
        self.assertEqual(len(notes), 20)
        self.assertEqual(len({n["id"] for n in notes}), 20)

    def test_read_modify_writes_take_the_lock(self):
        taken = []
        real = devo.Cache.lock

        def spy(self_):
            taken.append(1)
            return real(self_)

        self.cache.put("tables", [["t.a", 1]])
        self.cache.put("sources", {"sources": []})
        with mock.patch.object(devo.Cache, "lock", spy):
            self.cache.invalidate("sources", "x")
            self.assertTrue(taken, "invalidate")
            taken.clear()
            with mock.patch.object(devo, "table_missing", return_value=True):
                devo.cache_mismatch("from t.a select *", devo.DevoError("Unknown table `t.a`"), CFG)
            self.assertTrue(taken, "cache_mismatch")
            taken.clear()
            with contextlib.redirect_stdout(io.StringIO()):
                devo.cmd_cache(CFG, argparse_ns(action="naming", what=["set", "{upn}"], json=False))
            self.assertTrue(taken, "naming set")

    def test_a_field_map_built_before_a_new_profile_is_rebuilt(self):
        self.cache.put("fields/t.a", {"fields": {"x": {"type": "str"}}, "empty": []})
        self.assertEqual(set(devo.cached_field_map()["tables"]), {"t.a"})
        # a profile written after the map, without dropping it (a reader that raced the writer)
        self.cache.put("fields/t.b", {"fields": {"y": {"type": "str"}}, "empty": []})
        self.assertEqual(set(devo.cached_field_map()["tables"]), {"t.a", "t.b"})
        # unchanged profiles: the cached map is served as is
        with mock.patch.object(devo, "apply_roles", side_effect=AssertionError("rebuilt")):
            devo.cached_field_map()


def argparse_ns(**kw):
    import argparse
    kw.setdefault("what", [])
    return argparse.Namespace(**kw)


ALERT = {"id": 1, "createDate": 1000, "status": 0, "priority": 5, "context": "my.alert.x.Rule",
         "alertDefinition": {"name": "Rule"}, "extraData": "{}"}


class AlertPagingTests(unittest.TestCase):
    """6. Paging ends when the API repeats itself, and at a hard page cap."""

    def test_a_repeated_page_ends_the_loop(self):
        def same_page():
            for _ in range(50):  # a loop that never stops fails here instead of hanging
                yield FakeResp(json.dumps([dict(ALERT, id=1), dict(ALERT, id=2)]))

        code, out, err, reqs = run_cli(["alerts", "--format", "json"], same_page())
        self.assertEqual(code, 0)
        self.assertEqual(len(reqs), 1 + devo.STALE_ALERT_PAGES)
        self.assertEqual(sorted(x["id"] for x in json.loads(out)), [1, 2])

    def test_short_pages_do_not_end_the_loop(self):
        # the API often returns fewer than PAGE items while more exist, and pages can overlap
        pages = [[dict(ALERT, id=1), dict(ALERT, id=2)], [dict(ALERT, id=2)], [dict(ALERT, id=3)],
                 [dict(ALERT, id=4), dict(ALERT, id=5)], []]
        code, out, err, reqs = run_cli(["alerts", "--format", "json"], [FakeResp(json.dumps(p)) for p in pages])
        self.assertEqual(code, 0)
        self.assertEqual(len(reqs), 5)
        self.assertEqual(sorted(x["id"] for x in json.loads(out)), [1, 2, 3, 4, 5])

    def test_a_page_cap_stops_an_endless_api(self):
        def endless():
            for n in range(1, 50):
                yield FakeResp(json.dumps([dict(ALERT, id=n)]))

        with mock.patch.object(devo, "MAX_ALERT_PAGES", 5):
            code, out, err, reqs = run_cli(["alerts", "--format", "json", "--max", "100000"], endless())
        self.assertEqual(code, 0)
        self.assertEqual(len(reqs), 5)
        self.assertIn("page", err)


class RedirectTests(unittest.TestCase):
    """7. The token never follows a redirect off *.devo.com."""

    def redirect(self, to, frm="https://apiv2-eu.devo.com/search/query"):
        req = urllib.request.Request(frm, headers={"Authorization": "Bearer T", "standAloneToken": "T"})
        h = devo.SafeRedirect()
        return h.redirect_request(req, io.BytesIO(), 302, "Found", {}, to)

    def test_off_domain_and_plain_http_are_refused(self):
        for to in ("https://evil.example.com/x", "https://devo.com.example.com/x", "http://apiv2-eu.devo.com/x",
                   "https://example.com/?h=.devo.com"):
            with self.subTest(to=to):
                with self.assertRaises(devo.DevoError):
                    self.redirect(to)

    def test_another_devo_host_gets_no_token(self):
        new = self.redirect("https://other.devo.com/x")
        self.assertIsNone(new.get_header("Authorization"))
        self.assertIsNone(new.get_header("Standalonetoken"))

    def test_same_host_keeps_the_token(self):
        new = self.redirect("https://apiv2-eu.devo.com/other")
        self.assertEqual(new.get_header("Authorization"), "Bearer T")

    def test_requests_go_through_the_safe_opener(self):
        self.assertTrue(any(isinstance(h, devo.SafeRedirect) for h in devo.OPENER.handlers))


class BadInputTests(unittest.TestCase):
    """8. Bad input gives `ERROR:` and a hint, never a traceback."""

    def assert_clean(self, argv, responses=()):
        code, out, err, _ = run_cli(argv, list(responses))
        self.assertEqual(code, 1, err)
        self.assertIn("ERROR:", err)
        self.assertNotIn("Traceback", err)
        return err

    def test_impossible_dates(self):
        for v in ("2026-02-30", "2026-09-28T25:00", "2026-13-01"):
            with self.subTest(v=v):
                with self.assertRaises(devo.DevoError):
                    devo.resolve_time(v, now=NOW)
        self.assert_clean(["query", "from t.x select *", "--from", "2026-02-30"])

    def test_bad_regexes(self):
        self.assert_clean(["schema", "t.x", "--grep", "("])
        self.assert_clean(["tables", "--grep", "("])
        self.assert_clean(["boards", "--grep", "("])
        self.assert_clean(["lag", "--tables", "("])
        self.assert_clean(["alerts", "--group-by", "user,("])

    def test_non_integer_board_layout(self):
        d = tempfile.mkdtemp()
        spec = write(os.path.join(d, "spec.json"), json.dumps(
            {"name": "N", "widgets": [{"type": "Table", "query": "from a select b", "w": "wide"}]}))
        self.assert_clean(["board-new", spec, "--out", os.path.join(d, "b.json")])

    def test_a_json_line_that_is_not_an_object(self):
        with self.assertRaises(devo.DevoError):
            devo.CompactStream().feed('[1, 2]\n')
        with self.assertRaises(devo.DevoError):
            devo.CompactStream().feed('"text"\n')

    def test_unexpected_errors_are_one_line(self):
        with mock.patch.object(devo, "cmd_check", side_effect=RuntimeError("boom")):
            code, out, err, _ = run_cli(["check"], [])
        self.assertEqual(code, 1)
        self.assertIn("ERROR: RuntimeError: boom", err)
        self.assertNotIn("Traceback", err)


class RegexCostTests(unittest.TestCase):
    """9. Profiling a crafted 64 KB value takes milliseconds, not seconds."""

    def test_crafted_values_classify_fast(self):
        n = 65536
        for s in ('"a@' + "." * n + "x", '"a@' + "a." * (n // 2), "a@" + "a." * (n // 2) + " ",
                  "a@" + "." * n + "@", "x" * n + "@" + "." * n):
            start = time.time()
            devo.classify(s)
            self.assertLess(time.time() - start, 0.5, s[:20])

    def test_emails_still_classify(self):
        self.assertEqual(devo.classify("jsmith@example.com"), "email")
        self.assertEqual(devo.classify('"jsmith@mail.example.co.uk"'), "email-quoted")
        self.assertEqual(devo.classify("o'brien+tag@example.com"), "email")


class LinqStringTests(unittest.TestCase):
    """10. One quoting helper: escape backslash and double quote, keep UTF-8."""

    def test_linq_str(self):
        self.assertEqual(devo.linq_str('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(devo.linq_str("José"), '"José"')

    def test_teams_subject_condition_escapes_log_values(self):
        cond = devo.teams_subject_cond({"aaaaaaaa-0000-0000-0000-000000000001"}, {'a"b@example.com'})
        self.assertIn('weakhas(message, "a\\"b@example.com")', cond)
        self.assertIn('message -> "aaaaaaaa-0000-0000-0000-000000000001"', cond)

    def test_board_inputs_keep_utf8(self):
        linq, missing = devo.board_fill_inputs("from t where u = $Input0.value", {"Input0": 'José "J"'})
        self.assertEqual((linq, missing), ('from t where u = "José \\"J\\""', set()))

    def test_linq_set_escapes(self):
        self.assertEqual(devo.linq_set(['a"b', "c"]), '{"a\\"b", "c"}')

    def test_no_json_dumps_quoting_left_in_linq(self):
        with open(devo.__file__, encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn('", ".join(json.dumps(', src)
        self.assertNotIn("return json.dumps(v)\n\n    return BOARD_INPUT", src)


class BatchParallelTests(unittest.TestCase):
    """11. A batch job's `parallel` is clamped to MAX_PARALLEL; `query --parallel` has no cap."""

    def test_job_parallel_is_clamped(self):
        d = tempfile.mkdtemp()
        spec = write(os.path.join(d, "spec.json"), json.dumps(
            [{"name": "j", "query": "from t.x select a", "from": "1h", "to": "now", "parallel": 500}]))
        seen = []

        def fake_fetch(cfg, linq, frm, to, limit, timeout, chunk=None, parallel=4, *a, **k):
            seen.append(parallel)
            return [("a", "str")], [["v"]], {"windows": 1, "retried": 0, "full": [], "splits": 0, "failed": []}

        with mock.patch.object(devo, "fetch", fake_fetch):
            code, out, err, _ = run_cli(["batch", spec, "--out-dir", os.path.join(d, "out")], [])
        self.assertEqual(code, 0, err)
        self.assertEqual(seen, [devo.MAX_PARALLEL])
        self.assertIn("parallel", err)

    def test_query_parallel_is_not_clamped(self):  # the cap is for batch jobs only
        seen = []

        def fake_fetch(cfg, linq, frm, to, limit, timeout, chunk=None, parallel=4, *a, **k):
            seen.append(parallel)
            return [("a", "str")], [["v"]], {"windows": 1, "retried": 0, "full": [], "splits": 0, "failed": []}

        with mock.patch.object(devo, "fetch", fake_fetch):
            code, out, err, _ = run_cli(["query", "from t.x select a", "--from", "2h", "--to", "1h", "--chunk", "1h",
                                         "--parallel", "64"], [])
        self.assertEqual(code, 0, err)
        self.assertEqual(seen, [64])
        self.assertNotIn("clamped", err)


class SummaryPathTests(unittest.TestCase):
    """12. File paths read back from summary.json resolve inside the activity directory only."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dir = os.path.join(self.tmp, "act")
        rec = {"eventdate": "2026-10-01T09:05:00.000Z", "UserId": "outside@example.com", "Operation": "X",
               "properties_userId": "99999999-0000-0000-0000-000000000009"}
        self.outside = write(os.path.join(self.tmp, "elsewhere", "o365.jsonl"), json.dumps(rec) + "\n")
        os.makedirs(self.dir)
        self.summary = {"term": "j", "terms": ["j"], "window": ["2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"],
                        "seconds": 1, "sources": [
                            {"source": "o365_x", "table": "cloud.office365.management.sharepoint", "rows": 1,
                             "events": 1, "accounts": [], "first": None, "last": None, "mode": "rows",
                             "file": self.outside},
                            {"source": "entra_x", "table": "cloud.azure.ad.signin", "rows": 1, "events": 1,
                             "accounts": [], "first": None, "last": None, "mode": "rows", "file": self.outside}]}
        write(os.path.join(self.dir, "summary.json"), json.dumps(self.summary))

    def test_timeline_reads_only_inside_the_directory(self):
        events, notes, _ = devo.build_timeline(self.dir, fm={"tables": {}})
        self.assertEqual(events, [])
        self.assertTrue(any("missing" in n for n in notes))
        write(os.path.join(self.dir, "o365.jsonl"), open(self.outside, encoding="utf-8").read())
        events, _, _ = devo.build_timeline(self.dir, fm={"tables": {}})
        self.assertTrue(events)

    def test_print_activity_reads_only_inside_the_directory(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            devo.print_activity(self.summary, 0, self.dir)
        self.assertNotIn("99999999", err.getvalue())


class HelpAndTimeTests(unittest.TestCase):
    """Also: --limit is documented as per window; ISO forms parse the same on every Python."""

    def test_limit_help_says_per_window(self):
        import argparse
        p = devo.build_parser()
        sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction)).choices["query"]
        limit = next(a for a in sub._actions if "--limit" in a.option_strings)
        self.assertIn("per window", limit.help)
        with open(os.path.join(devo.SKILL_DIR, "references", "commands.md"), encoding="utf-8") as f:
            self.assertIn("per window", f.read())

    def test_iso_forms(self):
        r = lambda v: devo.resolve_time(v, now=NOW)[1]
        base = r("2026-09-28T14:00:00Z")
        self.assertEqual(r("2026-09-28T14:00:00.123456789Z"), base)
        self.assertEqual(r("2026-09-28T14:00:00.5Z"), base)
        self.assertEqual(r("2026-09-28T15:00:00+0100"), base)
        self.assertEqual(r("2026-09-28+01:00"), r("2026-09-27T23:00Z"))
        self.assertEqual(r("2026-09-28 14:00"), base)
        self.assertEqual(devo.iso_utc(devo.parse_utc("2026-09-28T14:00:00.5Z")), "2026-09-28T14:00:00Z")


if __name__ == "__main__":
    unittest.main()
