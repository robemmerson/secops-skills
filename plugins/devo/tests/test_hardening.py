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


if __name__ == "__main__":
    unittest.main()
