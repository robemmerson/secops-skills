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
