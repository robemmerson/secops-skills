"""Offline tests for the local domain cache in devo.py. Run: python3 -m unittest discover plugins/devo/tests"""
import contextlib, io, json, os, re, stat, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "devo", "scripts"))
import devo  # noqa: E402

os.environ["DEVO_CACHE_DIR"] = tempfile.mkdtemp(prefix="devo-cache-test-")
os.environ.pop("DEVO_CACHE_KEY", None)
CFG = {"token": "SECRET-TOKEN-123", "region": "eu"}
REFS = os.path.join(devo.SKILL_DIR, "references")


class CacheCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.cache = devo.Cache(CFG, root=self.root, env={})
        devo.CACHE = self.cache
        devo._EVENT_TIME_CACHE.clear()
        self.err = io.StringIO()
        self.quiet = contextlib.redirect_stderr(self.err)
        self.quiet.__enter__()

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        devo.CACHE = None
        devo._EVENT_TIME_CACHE.clear()


class StoreTests(CacheCase):
    def test_key_hides_the_token(self):
        self.assertNotIn("SECRET", self.cache.dir)
        self.assertTrue(os.path.basename(self.cache.dir).startswith("eu-"))
        other = devo.Cache(dict(CFG, token="other"), root=self.root, env={})
        self.assertNotEqual(other.dir, self.cache.dir)
        named = devo.Cache(CFG, root=self.root, env={"DEVO_CACHE_KEY": "acme-prod"})
        self.assertEqual(os.path.basename(named.dir), "acme-prod")
        with self.assertRaises(devo.DevoError):
            devo.Cache(CFG, root=self.root, env={"DEVO_CACHE_KEY": "../x"})

    def test_never_inside_the_skill(self):
        with self.assertRaises(devo.DevoError):
            devo.Cache(CFG, root=os.path.join(devo.SKILL_DIR, "cache"), env={})

    def test_put_get_expire_invalidate(self):
        c = self.cache
        self.assertEqual(c.state("tables"), "missing")
        c.put("tables", [["a.b", 1]])
        self.assertEqual((c.state("tables"), c.get("tables")), ("fresh", [["a.b", 1]]))
        mode = stat.S_IMODE(os.stat(c.path("tables")).st_mode)
        if os.name != "nt":
            self.assertEqual(mode & 0o077, 0, oct(mode))  # private to the user
        with mock.patch.object(devo.time, "time", lambda: c.read("tables")["fetched"] + 8 * devo.DAY):
            self.assertEqual(c.state("tables"), "expired")
            self.assertIsNone(c.get("tables"))
            self.assertEqual(c.get("tables", allow_old=True), [["a.b", 1]])
        self.assertTrue(c.invalidate("tables", "because"))
        self.assertFalse(c.invalidate("tables"))  # already stale
        self.assertEqual(c.state("tables"), "stale")
        self.assertIsNone(c.get("tables"))
        self.assertEqual(c.get("tables", allow_old=True), [["a.b", 1]])  # kept as a fallback

    @unittest.skipIf(os.name == "nt", "POSIX modes; Windows relies on the profile's ACLs")
    def test_directories_are_private_from_the_root_down(self):
        root = os.path.join(tempfile.mkdtemp(), "devo-skill")
        old = os.umask(0o002)  # a permissive umask, as on many desktops
        try:
            c = devo.Cache(CFG, root=root, env={})
            c.put("fields/a.b", {})
        finally:
            os.umask(old)
        for d in (root, c.dir, os.path.join(c.dir, "fields")):
            self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700, d)
        self.assertEqual(stat.S_IMODE(os.stat(c.path("fields/a.b")).st_mode), 0o600)
        os.chmod(root, 0o775)  # created loosely by something else: tightened on the next write
        c.put("tables", [])
        self.assertEqual(stat.S_IMODE(os.stat(root).st_mode), 0o700)

    @unittest.skipIf(os.name == "nt", "POSIX modes; Windows relies on the profile's ACLs")
    def test_warns_about_a_readable_token_file(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "env")
        with open(path, "w", encoding="utf-8") as f:
            f.write("DEVO_TOKEN=x\n")
        os.chmod(path, 0o644)
        devo._WARNED.clear()
        devo.load_config({"DEVO_ENV_FILE": path})
        self.assertIn(f"chmod 600 {path}", self.err.getvalue())
        self.assertNotIn("x\n", self.err.getvalue())

    def test_max_age_cap_and_version(self):
        capped = devo.Cache(CFG, root=self.root, env={"DEVO_CACHE_MAX_AGE_DAYS": "0.5"})
        self.assertEqual(capped.ttl("fields/x.y"), devo.DAY / 2)
        self.assertIsNone(capped.ttl("notes"))  # notes never expire
        self.cache.put("tables", [])
        with open(self.cache.path("tables"), "w", encoding="utf-8") as f:
            json.dump({"version": 0, "fetched": 0, "data": []}, f)
        self.assertEqual(self.cache.state("tables"), "missing")  # an old format is ignored

    def test_names_and_wipe_keep_notes(self):
        c = self.cache
        for n in ("tables", "fields/a.b", "schema/a.b", "notes"):
            c.put(n, {})
        self.assertEqual(c.names("fields/"), ["fields/a.b"])
        self.assertEqual(c.wipe(), 3)
        self.assertEqual(c.names(), ["notes"])
        with self.assertRaises(devo.DevoError):
            c.path("../escape")


class MismatchTests(CacheCase):
    def test_unknown_table_is_dropped_from_the_list(self):
        self.cache.put("tables", [["t.gone", 5], ["t.ok", 3]])
        self.cache.put("sources", {"sources": []})
        devo.cache_mismatch("from t.gone select *", devo.DevoError("Unknown table `t.gone`"))
        self.assertEqual(self.cache.get("tables"), [["t.ok", 3]])
        self.assertEqual(self.cache.read("tables")["unqueryable"], ["t.gone"])
        self.assertEqual(self.cache.state("sources"), "stale")
        self.assertIn("dropped from the cached table list", self.err.getvalue())
        # an automatic refetch keeps it out; an explicit --live refresh starts over
        live = lambda cfg, frm, timeout: [["t.gone", 5], ["t.ok", 3]]
        with mock.patch.object(devo, "live_tables", live):
            self.cache.invalidate("tables")
            self.assertEqual(devo.domain_tables(CFG), [("t.ok", 3)])
            self.assertEqual(devo.domain_tables(CFG, refresh=True), [("t.gone", 5), ("t.ok", 3)])

    def test_unknown_table_not_in_the_cache_changes_nothing(self):
        self.cache.put("tables", [["t.other", 5]])
        devo.cache_mismatch("from t.typo select *", devo.DevoError("Unknown table `t.typo`"))
        self.assertEqual(self.cache.state("tables"), "fresh")

    def test_unknown_identifier_for_a_cached_field(self):
        self.cache.put("schema/t.x", [["eventdate", "timestamp"], ["gone", "str"]])
        self.cache.put("fields/t.x", {"fields": {"gone": {}}, "empty": []})
        devo.cache_mismatch("from t.x where gone = 1", devo.DevoError("HTTP 400: Unknown identifier `gone`"))
        self.assertEqual(self.cache.state("schema/t.x"), "stale")
        self.assertEqual(self.cache.state("fields/t.x"), "stale")
        devo.cache_mismatch("from t.x where typo = 1", devo.DevoError("Unknown identifier `typo`"))  # user typo

    def test_collect_reports_the_mismatch(self):
        self.cache.put("tables", [["t.gone", 5]])
        with mock.patch.object(devo, "run_query", side_effect=devo.DevoError("Unknown table `t.gone`")):
            with self.assertRaises(devo.DevoError):
                devo.collect(CFG, "from t.gone select *", 0, 1, 10, 10)
        self.assertEqual(self.cache.get("tables"), [])

    def test_live_failure_falls_back_to_the_stale_copy(self):
        self.cache.put("tables", [["t.a", 5]])
        self.cache.invalidate("tables")
        with mock.patch.object(devo, "live_tables", side_effect=devo.DevoError("HTTP 503")):
            self.assertEqual(devo.domain_tables(CFG), [("t.a", 5)])
        self.assertIn("using the cached copy", self.err.getvalue())


class SourceTests(CacheCase):
    def test_identifiers(self):
        self.assertEqual(devo.linq_identifiers('weakhas(user, {T}) or eqic(x__y, "a b") and not z in {"q"}'),
                         {"user", "x__y", "z"})
        src = {"filter": "EventID = 4625, weakhas(Message, {T})",
               "pre": 'peek(Message, re("Account Name:\\\\s*(\\\\S+)"), 1) as acct', "group": "host, acct"}
        self.assertEqual(devo.source_fields(src), {"EventID", "Message", "host"})
        self.assertEqual(devo.linq_identifiers("`in`(ip, 10.0.0.0/8)", "*"), {"ip"})

    def test_every_hint_source_parses(self):
        conf = devo.load_activity_sources(devo.HINT_SOURCES)
        for s in conf["sources"] + [conf["graph"]]:
            f = devo.source_fields(s)
            self.assertTrue(f, s["name"])
            self.assertFalse(f & devo.LINQ_WORDS, s["name"])

    def test_build_keeps_valid_skips_missing_and_generates(self):
        hints = {"sources": [
            {"by": "user", "name": "ok", "table": "t.a", "filter": "weakhas(user, {T})", "group": "user, act"},
            {"by": "user", "name": "badfield", "table": "t.a", "filter": "weakhas(nope, {T})", "group": "nope"},
            {"by": "user", "name": "absent", "table": "t.none", "filter": "weakhas(u, {T})", "group": "u"}],
            "graph": {"name": "graph", "table": "t.none", "filter": "id -> {T}", "group": "id"}}
        path = os.path.join(self.root, "hints.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(hints, f)
        self.cache.put("tables", [["t.a", 10], ["t.b", 5], ["siem.logtrust.x", 9]])
        self.cache.put("fields/t.b", {"fields": {
            "srcIp": {"type": "ip4", "fill": 1.0, "role": "ip"},
            "account": {"type": "str", "fill": 0.9, "role": "user", "len": 12},
            "action": {"type": "str", "fill": 1.0, "role": "action"},
            "blob": {"type": "json", "fill": 1.0, "role": "user"}}, "empty": []})
        self.cache.put("fields/siem.logtrust.x", {"fields": {"u": {"type": "str", "fill": 1.0, "role": "user"}}})
        with mock.patch.object(devo, "HINT_SOURCES", path), \
                mock.patch.object(devo, "table_fields", lambda cfg, t: ([("eventdate", "timestamp"), ("user", "str"),
                                                                         ("act", "str")], "schema API")):
            d = devo.build_sources(CFG)
        names = [s["name"] for s in d["sources"]]
        self.assertIn("ok", names)
        self.assertNotIn("badfield", names)
        self.assertEqual(d["skipped"][0]["name"], "badfield")
        self.assertIn("nope", d["skipped"][0]["reason"])
        self.assertIsNone(d["graph"])
        self.assertEqual(d["counts"]["hint_tables_absent"], 2)
        gen = {s["name"]: s for s in d["sources"] if s.get("generated")}
        self.assertEqual(set(gen), {"auto_user_t_b", "auto_ip_t_b"})  # not the internal siem.* table
        self.assertEqual(gen["auto_ip_t_b"]["filter"], "srcIp = {T}")
        self.assertEqual(gen["auto_user_t_b"]["filter"], "weakhas(account, {T})")  # the json field is never matched
        self.assertIn("action", gen["auto_user_t_b"]["group"])
        self.assertEqual(self.cache.get("sources")["counts"]["generated"], 2)
        self.assertEqual(devo.domain_sources(CFG)["counts"], d["counts"])  # served from the cache

    def test_table_list_change_invalidates_derived_entries(self):
        self.cache.put("tables", [["t.a", 1]])
        self.cache.put("sources", {})
        self.cache.put("event-time", [])
        with mock.patch.object(devo, "live_tables", lambda cfg, frm, timeout: [["t.a", 1], ["t.new", 2]]):
            devo.domain_tables(CFG, refresh=True)
        self.assertEqual((self.cache.state("sources"), self.cache.state("event-time")), ("stale", "stale"))


class EventTimeCacheTests(CacheCase):
    def test_failed_expression_falls_back_to_eventdate(self):
        def fake_fetch(cfg, linq, *args, **kw):
            if "office365" in linq:
                raise devo.DevoError("No function named `jsonparse`")
            return [("eventdate", "timestamp"), ("event_time", "timestamp")], [[1, 2]], {}

        tables = [("cloud.office365.management.exchange", 10), ("box.win_nxlog.security", 5), ("box.unix", 3)]
        with mock.patch.object(devo, "fetch", fake_fetch):
            fams = devo.verify_event_time(CFG, tables)
        by = {f["family"]: f for f in fams}
        self.assertIsNone(by["Microsoft 365"]["linq"])
        self.assertIn("using eventdate", by["Microsoft 365"]["check"])
        self.assertEqual(by["Windows (nxlog)"]["check"], "ok on box.win_nxlog.security")
        self.assertEqual(by["Windows (nxlog)"]["lag"], ["box.win_nxlog.security"])  # only tables the domain has
        self.assertIn("no matching tables", by["Fortinet"]["check"])
        self.cache.put("event-time", fams)
        self.assertIsNone(devo.event_time_for("cloud.office365.management.exchange")["linq"])  # the cached copy wins


class QueryHelperTests(CacheCase):
    COLS = [("host", "str"), ("n", "int8"), ("first", "timestamp"), ("last", "timestamp"), ("u", "float8")]

    def test_merge_grouped_across_windows(self):
        q = ('from t.x where a = "group by" group by host select count() as n, min(eventdate) as first, '
             'max(eventdate) as last, hllppcount(user) as u')
        rows = [["h1", 2, 10, 20, 3.0004], ["h2", 1, 5, 5, 1.0], ["h1", 3, 7, 30, 2.0]]
        merged, note = devo.merge_grouped(q, self.COLS, rows)
        self.assertEqual(sorted(merged), [["h1", 5, 7, 30, 3.0004], ["h2", 1, 5, 5, 1.0]])
        self.assertIn("lower bound", note)
        self.assertEqual(devo.round_approx(q, self.COLS, merged)[0][4], 3)
        self.assertIsNone(devo.merge_grouped("from t group by h select avg(x) as a", [("h", "str"), ("a", "float8")],
                                             [])[0])
        _, note = devo.merge_grouped("from t group by h select count() as n where n > 5", [("h", "str"), ("n", "int8")],
                                     [["a", 1]])
        self.assertIn("ran per window", note)

    def test_field_precheck_uses_the_cached_schema(self):
        self.cache.put("schema/t.x", [["eventdate", "timestamp"], ["user", "str"], ["ip", "ip4"]])
        q = 'from t.x where weakhas(user, "a"), message -> "x" select peek(user, re("(.)"), 1) as u group by u, ip select count() as n'
        self.assertEqual(devo.unknown_fields(q), [("t.x", ["message"])])
        self.assertEqual(devo.unknown_fields("from t.other where zzz = 1"), [])  # no schema cached: silent

    def test_extra_data_values_are_unquoted(self):
        alert = {"extraData": json.dumps({"name": "%22JS%2FFoo%22", "raw": "%5B%7B%22a%22%3A1%7D%5D", "x": "a+b"})}
        self.assertEqual(devo.decode_extra(alert), {"name": "JS/Foo", "raw": [{"a": 1}], "x": "a b"})


class FieldMapTests(CacheCase):
    def test_merged_map_is_cached_and_rebuilt_after_a_profile(self):
        self.cache.put("fields/t.a", {"fields": {"x": {"type": "str", "fill": 1.0, "role": "user"}}, "empty": []})
        fm = devo.load_field_map()
        self.assertIn("t.a", fm["tables"])
        self.assertEqual(self.cache.state("field-map"), "fresh")
        self.assertTrue(devo.table_has_field("t.a", "x"))
        cols = [("eventdate", "timestamp"), ("y", "str")]
        with mock.patch.object(devo, "sample_table", lambda *a, **k: (cols, [[1, "v"]], "15m")):
            devo.table_profile(CFG, "t.b")
        self.assertEqual(self.cache.state("field-map"), "missing")
        self.assertEqual(set(devo.load_field_map()["tables"]), {"t.a", "t.b"})
        self.assertEqual(self.cache.get("schema/t.b"), [["eventdate", "timestamp"], ["y", "str"]])

    def test_roles_by_field_name_apply_to_every_table(self):
        path = os.path.join(self.root, "roles.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"*": {"pid": None, "who": "user"}, "t.b": {"who": "host"}}, f)
        fm = {"tables": {"t.a": {"fields": {"pid": {"role": "join-id"}, "who": {}}},
                         "t.b": {"fields": {"who": {"role": "user"}}}}}
        devo.apply_roles(fm, path)
        self.assertNotIn("role", fm["tables"]["t.a"]["fields"]["pid"])
        self.assertEqual(fm["tables"]["t.a"]["fields"]["who"]["role"], "user")
        self.assertEqual(fm["tables"]["t.b"]["fields"]["who"]["role"], "host")  # a table key wins


class CommandTests(unittest.TestCase):
    def run_main(self, argv, root):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"DEVO_CACHE_DIR": root}), \
                mock.patch.object(devo, "load_config", lambda: dict(CFG)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = devo.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_notes_naming_status_clear(self):
        root = tempfile.mkdtemp()
        self.assertEqual(self.run_main(["cache", "note", "add", "admin", "accounts", "start", "adm-"], root)[0], 0)
        code, out, err = self.run_main(["cache", "notes"], root)
        self.assertIn("admin accounts start adm-", out)
        self.assertEqual(self.run_main(["cache", "note", "verify", "1"], root)[0], 0)
        self.assertEqual(self.run_main(["cache", "naming", "set", "{upn},adm-{f}{last}"], root)[0], 0)
        self.assertIn("adm-{f}{last}", self.run_main(["cache", "naming", "show"], root)[1])
        self.assertEqual(self.run_main(["cache", "naming", "set", "{bad}"], root)[0], 1)
        code, out, _ = self.run_main(["cache", "status", "--json"], root)
        s = json.loads(out)
        self.assertEqual((s["notes"]["count"], s["tables"]["state"]), (1, "missing"))
        self.assertIn("kept", self.run_main(["cache", "clear"], root)[1])
        self.assertIn("admin accounts", self.run_main(["cache", "notes"], root)[1])  # clear keeps notes
        self.run_main(["cache", "clear", "--include-notes"], root)
        self.assertNotIn("admin accounts", self.run_main(["cache", "notes"], root)[1])
        self.assertEqual(self.run_main(["cache", "note", "rm", "9"], root)[0], 1)

    def test_old_notes_are_flagged_for_review(self):
        root = tempfile.mkdtemp()
        self.run_main(["cache", "note", "add", "x"], root)
        with mock.patch.object(devo.time, "time", lambda: 4102444800):  # far in the future
            code, out, _ = self.run_main(["cache", "notes"], root)
        self.assertIn("[re-verify]", out)


class PublicRepoTests(unittest.TestCase):
    """The public skill ships generic knowledge only: no snapshot of a particular domain."""

    def test_no_domain_snapshot_files(self):
        shipped = {os.path.relpath(os.path.join(d, f), REFS) for d, _, fs in os.walk(REFS) for f in fs}
        for banned in ("domain-tables.md", "domain-tables.tsv", "field-map.json", "activity-sources.json",
                       "event-time.json", "field-roles.json"):
            self.assertNotIn(banned, shipped)  # only under references/hints/, as seeds

    def test_no_real_addresses(self):
        email = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
        ok = re.compile(r"@(([a-z0-9-]+\.)*example\.(com|org|net)|domain|company\.com|tenant\.onmicrosoft\.com|"
                        r"unq\.gbl\.spaces|thread\.(v2|tacv2|skype))$", re.I)
        for d, _, fs in os.walk(devo.SKILL_DIR):
            for fn in fs:
                if not fn.endswith((".md", ".json", ".py")) or "library" in d:
                    continue
                with open(os.path.join(d, fn), encoding="utf-8") as f:
                    for m in email.finditer(f.read()):
                        self.assertRegex(m.group(0), ok, f"{fn}: {m.group(0)}")


if __name__ == "__main__":
    unittest.main()


class Round1LessonTests(unittest.TestCase):
    def test_account_kinds(self):
        k = lambda a, n=5, pats=(): devo.account_kind(a, n, 1, list(pats))[0]
        self.assertEqual(k("Window Manager\\DWM-3"), "system")
        self.assertEqual(k("Font Driver Host\\UMFD-12"), "system")
        self.assertEqual(k("CORP\\HOST01$"), "system")
        self.assertEqual(k("CORP\\jsmith"), "person")
        self.assertEqual(k("svc-backup"), "service?")
        self.assertEqual(k("ec2-user"), "service?")
        self.assertEqual(k("jsmith", n=5000), "service?")  # far more logons than a person makes
        self.assertEqual(k("CORP\\acmefeed", pats=["acme*"]), "service")

    def test_duplicate_sources_are_marked_once(self):
        res = [{"source": "zpa", "events": 10, "first": "a", "last": "b", "matched": {"x": 10}},
               {"source": "auto_user_zpa_copy", "generated": True, "events": 10, "first": "a", "last": "b",
                "matched": {"x": 10}},
               {"source": "other", "events": 3, "first": "a", "last": "b", "matched": {"x": 3}}]
        devo.mark_duplicates(res)
        self.assertEqual(res[1].get("duplicate_of"), "zpa")
        self.assertNotIn("duplicate_of", res[0])
        self.assertNotIn("duplicate_of", res[2])

    def test_offset_note(self):
        self.assertIn("time-zone", devo.offset_note({"p50_s": 5, "p95_s": 14400, "worst_hour_p95_s": 14410}))
        self.assertIn("every sender", devo.offset_note({"p50_s": 3600, "p95_s": 3650, "worst_hour_p95_s": 3700}))
        self.assertEqual(devo.offset_note({"p50_s": 60, "p95_s": 900, "worst_hour_p95_s": 20000}), "")
        self.assertEqual(devo.offset_note({"p50_s": 5, "p95_s": 14400, "worst_hour_p95_s": 60000}), "")

    def test_ephemeral_hosts(self):
        for h in ("ip-10-1-2-3", "i-0abc12345def", "gke-pool-1-abc", "3f2a9c1b7d4e"):
            self.assertTrue(devo.EPHEMERAL.search(h), h)
        for h in ("host01", "dc01.corp.example", "web-prod-1"):
            self.assertFalse(devo.EPHEMERAL.search(h), h)

    def test_norm_msg_groups_repeats(self):
        a = devo.norm_msg("Processing time (31.2s) exceeded visibility timeout (30s) for id 3f2a9c1b-0000-1111-2222-333344445555")
        b = devo.norm_msg("Processing time (45.9s) exceeded visibility timeout (30s) for id 9a9a9a9a-0000-1111-2222-333344445555")
        self.assertEqual(a, b)

    def test_alert_name_filter_ignores_the_context_prefix(self):
        alerts = [{"id": 1, "context": "my.alert.acme.BruteForce", "createDate": 2, "status": 0},
                  {"id": 2, "context": "my.alert.acme.MalwareFile", "createDate": 1, "status": 0}]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(devo, "fetch_alerts", lambda cfg, f, t, m: (alerts, False)), \
                mock.patch.object(devo, "load_config", lambda: dict(CFG)), \
                mock.patch.dict(os.environ, {"DEVO_CACHE_DIR": tempfile.mkdtemp()}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(devo.main(["alerts", "--name", "acme"]), 0)
            self.assertIn("# 0 alerts", err.getvalue())  # "acme" is only in the shared prefix
            self.assertEqual(devo.main(["alerts", "--name", "malware", "--format", "json"]), 0)
            self.assertEqual(devo.main(["alerts", "--by-def"]), 0)
        self.assertIn('"id": 2', out.getvalue())
        self.assertIn("BruteForce", out.getvalue())


class Round2LessonTests(unittest.TestCase):
    def test_raw_event_time_from_nested_records(self):
        ex = {"eventdate": "2026-10-01 16:40:00.000",
              "raw_messages": [{"CreationTime": "2026-09-28T09:00:00", "Operation": "FileMalwareDetected"}]}
        t, gap = devo.raw_event_time(ex)
        self.assertEqual(t, "2026-09-28T09:00:00Z")
        self.assertIn("before the alert's eventdate", gap)
        self.assertEqual(devo.raw_event_time({"eventdate": "2026-10-01 16:40:00", "x": "y"}), (None, ""))
        t, gap = devo.raw_event_time({"eventdate": "2026-10-01 16:40:00", "r": {"timestamp": "2026-10-01T16:30:00Z"}})
        self.assertEqual(gap, "")  # within the hour

    def test_custom_status_points_to_comments(self):
        self.assertIn("comments", devo.status_label(850))

    def test_fields_grep_filters_a_table(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            devo.print_profile("t.x", {"rows": 1, "window": "15m", "fields": {"userName": {"type": "str", "fill": 1.0},
                                                                            "srcIp": {"type": "ip4", "fill": 1.0}}},
                               grep="user")
        self.assertIn("userName", out.getvalue())
        self.assertNotIn("srcIp", out.getvalue())


class BatchQueryFileTests(unittest.TestCase):
    def test_query_file_next_to_the_spec(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "q.linq"), "w", encoding="utf-8") as f:
            f.write('from t.x where a = "quoted \\"value\\""')
        with open(os.path.join(d, "spec.json"), "w", encoding="utf-8") as f:
            json.dump([{"name": "j", "query_file": "q.linq"}], f)
        jobs = devo.load_spec(os.path.join(d, "spec.json"))
        self.assertIn('"quoted', jobs[0]["query"])
        with open(os.path.join(d, "bad.json"), "w", encoding="utf-8") as f:
            json.dump([{"name": "j", "query_file": "missing.linq"}], f)
        with self.assertRaises(devo.DevoError):
            devo.load_spec(os.path.join(d, "bad.json"))


class Round2bLessonTests(unittest.TestCase):
    def test_fit_chunk(self):
        self.assertEqual(devo.fit_chunk("30m", 0, 7 * 86400), "2h")
        self.assertEqual(devo.fit_chunk("1h", 0, 86400), "1h")
        self.assertIsNone(devo.fit_chunk(None, 0, 10))

    def test_copies_in_sibling_tables(self):
        res = [{"source": "zpa", "table": "vpn.x.access", "events": 500, "first": "a", "last": "b"},
               {"source": "auto_zpa_status", "table": "vpn.x.status_user", "generated": True, "events": 500,
                "first": "a2", "last": "b2"},
               {"source": "aws_a", "table": "cloud.aws.cloudtrail.a", "events": 3, "first": "1", "last": "2"},
               {"source": "aws_b", "table": "cloud.aws.cloudtrail.b", "events": 3, "first": "5", "last": "6"}]
        devo.mark_duplicates(res)
        self.assertEqual(res[1].get("duplicate_of"), "zpa")
        self.assertNotIn("duplicate_of", res[3])  # small, different times: not a copy

    def test_grouped_rows_spread_over_days(self):
        ev = [{"t_utc": "2026-10-01T10:00:00Z", "t_last_utc": "2026-10-03T10:00:00Z", "count": 30, "source": "s"}]
        text = devo.day_summary(ev, None)
        self.assertIn("2026-10-01 Thu: 10 direct events", text)
        self.assertIn("2026-10-03 Sat: 10 direct events", text)
        self.assertIn("spread evenly", text)


class MismatchLiveConfirmTests(CacheCase):
    def test_field_that_exists_live_is_not_marked_stale(self):
        self.cache.put("schema/t.x", [["eventdate", "timestamp"], ["user", "str"]])
        err = devo.DevoError("Unknown identifier `user`")
        with mock.patch.object(devo, "table_fields", lambda cfg, t: ([("eventdate", "timestamp"), ("user", "str")], "x")):
            devo.cache_mismatch("from t.x group by host select user", err, CFG)
        self.assertEqual(self.cache.state("schema/t.x"), "fresh")
        self.assertIn("group by", err.hint)

    def test_heal_schema_drops_an_incomplete_entry(self):
        self.cache.put("schema/t.x", [["eventdate", "timestamp"]])
        devo.heal_schema([("t.x", ["late_field"])], [("late_field", "str")])
        self.assertEqual(self.cache.state("schema/t.x"), "missing")


class GrantsTests(unittest.TestCase):
    def test_pim_kinds(self):
        k = devo.pim_kind
        self.assertEqual(k("Add member to role completed (PIM activation)", "PIM", None), "activation")
        self.assertEqual(k("Add member to role in PIM completed (permanent)", "PIM", None), "permanent active (via PIM)")
        self.assertEqual(k("Add eligible member to role in PIM completed (timebound)", "PIM", None), "eligible")
        self.assertIsNone(k("Add member to role", "Core Directory", "MS-PIM"))  # PIM's own copy
        self.assertEqual(k("Add member to role", "Core Directory", None), "direct (not PIM)")
        self.assertIsNone(k("Add member to role requested (PIM activation)", "PIM", None))

    def test_grants_summary_offline(self):
        d = tempfile.mkdtemp()
        tr = json.dumps([{"type": "Role", "displayName": "Global Administrator"},
                         {"type": "User", "userPrincipalName": "svc-backup@example.com"}])
        det = json.dumps([{"key": "Justification", "value": "troubleshooting"}])
        recs = [{"eventdate": "2026-09-04T12:00:00Z", "tenantId": "t", "properties_id": "1",
                 "properties_category": "RoleManagement", "properties_loggedByService": "PIM",
                 "operationName": "Add member to role in PIM completed (permanent)", "properties_result": "success",
                 "properties_initiatedBy_user_userPrincipalName": "admin@example.com", "targets": tr, "details": det},
                {"eventdate": "2026-09-04T14:00:00Z", "tenantId": "t", "properties_id": "2",
                 "properties_category": "RoleManagement", "properties_loggedByService": "PIM",
                 "operationName": "Remove member from role in PIM completed (permanent)", "properties_result": "success",
                 "properties_initiatedBy_user_userPrincipalName": "admin@example.com", "targets": tr, "details": "[]"}]
        with open(os.path.join(d, "entra_role_changes.jsonl"), "w", encoding="utf-8") as f:
            f.write("\n".join(json.dumps(r) for r in recs))
        with open(os.path.join(d, "ad_group_changes.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"host": "srv01", "EventID": 4732, "TargetUserName": "Administrators",
                                "SubjectUserName": "SRV01$", "MemberSid": "S-1-5-21-1-512", "n": 300}) + "\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(devo.cmd_grants(None, argparse_ns(dir=d, limit=10)), 0)
        text = out.getvalue()
        self.assertIn("Global Administrator → svc-backup@example.com", text)
        self.assertIn("privileged role, service account", text)
        self.assertIn("2.0h later", text)
        self.assertIn("1 by machine accounts", text)


def argparse_ns(**kw):
    import argparse
    return argparse.Namespace(**kw)


class DistinctIdMergeTests(unittest.TestCase):
    def test_hllppcount_of_event_ids_is_summed(self):
        q = "from t group by ip select hllppcount(properties_id) as ids, hllppcount(user) as users"
        cols = [("ip", "str"), ("ids", "float8"), ("users", "float8")]
        merged, note = devo.merge_grouped(q, cols, [["a", 10.0, 3.0], ["a", 5.0, 4.0]])
        self.assertEqual(merged, [["a", 15.0, 4.0]])  # ids add up, users can't (largest window)
        self.assertIn("summed", note)


class AttributionTests(unittest.TestCase):
    def test_day_summary_separates_direct_from_raw_text(self):
        ev = [{"t_utc": "2026-10-03T10:00:00Z", "count": 5, "source": "signin", "attribution": "direct"},
              {"t_utc": "2026-10-03T11:00:00Z", "count": 400, "source": "ps4104", "attribution": "raw-text"}]
        text = devo.day_summary(ev, None)
        self.assertIn("2026-10-03 Sat: 5 direct events (+ raw-text 400)", text)
        self.assertIn("raw-text = the term only appears in raw text", text)


class MultiTermTests(unittest.TestCase):
    def test_term_field_added_to_group_for_several_terms(self):
        src = {"name": "x", "table": "t", "filter": "properties_ipAddress = {T}", "group": "user, app"}
        q2 = devo.source_query(src, ["203.0.113.1", "203.0.113.2"])
        self.assertIn("group by user, app, properties_ipAddress", q2)
        q1 = devo.source_query(src, ["203.0.113.1"])
        self.assertIn("group by user, app select", q1)
        self.assertEqual(devo.term_fields('weakhas(Host, {T}) or ServerIP = {T} or weakhas(message, {T})'),
                         ["Host", "ServerIP"])


class AlertGroupingTests(unittest.TestCase):
    def test_extra_value_finds_nested_keys(self):
        ex = {"eventdate": "x", "raw_messages": [{"UserId": "jsmith@example.com", "SiteUrl": "https://t/sites/a",
                                                   "SourceFileName": "a.html"}]}
        self.assertEqual(devo.extra_value(ex, devo.GROUP_KEYS["user"]), "jsmith@example.com")
        self.assertEqual(devo.extra_value(ex, devo.GROUP_KEYS["file"]), "a.html")
        self.assertIsNone(devo.extra_value(ex, devo.GROUP_KEYS["hash"]))


class Round5LogonKindTests(unittest.TestCase):
    def test_admin_and_shared_admin_kinds(self):
        k = lambda a: devo.account_kind(a, 5, 1, [])[0]
        self.assertEqual(k("CORP\\adm.jsmith"), "person (admin)")
        self.assertEqual(k("Jane.Smith_Admin"), "person (admin)")
        self.assertEqual(k("HOST01\\Administrator"), "shared-admin")
        self.assertEqual(k("root"), "shared-admin")
        self.assertEqual(k("svc-backup"), "service?")
        self.assertEqual(k("jane.smith"), "person")


class PartialFetchTests(unittest.TestCase):
    def test_failed_window_keeps_the_others(self):
        calls = []

        def fake_collect(cfg, linq, f, t, limit, timeout, ip):
            calls.append(f)
            if f == 0:
                raise devo.DevoError("HTTP 400: some permanent problem")
            return [("eventdate", "timestamp")], [[f * 1000]]

        with mock.patch.object(devo, "collect", fake_collect):
            cols, rows, info = devo.fetch(CFG, "from t select *", 0, 3 * 86400, 0, 10, "1d", 2, partial=True)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(info["failed"]), 1)

    def test_retryable_errors_are_retried(self):
        n = {"i": 0}

        def flaky(cfg, linq, f, t, limit, timeout, ip):
            n["i"] += 1
            if n["i"] == 1:
                raise devo.DevoError("HTTP 500: Log file listed but not found INTERNAL_ERROR")
            return [("eventdate", "timestamp")], [[1]]

        with mock.patch.object(devo, "collect", flaky), mock.patch.object(devo, "RETRY_DELAY", 0):
            _, rows, info = devo.fetch(CFG, "from t select *", 0, 3600, 0, 10)
        self.assertEqual((len(rows), info["retried"]), (1, 1))
