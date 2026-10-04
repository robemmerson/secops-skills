"""Offline tests for action-deps.py (gh is faked). Run: python3 -m unittest discover plugins/dependency-updates/tests"""
import base64, contextlib, importlib.util, io, json, os, tempfile, unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "skills", "dependency-updates", "scripts")

try:
    import yaml  # noqa: F401
except ImportError:
    yaml = None


def load():
    spec = importlib.util.spec_from_file_location("action_deps", os.path.join(SCRIPTS, "action-deps.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ago(hours):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


SHA_A, SHA_B, SHA_C, TAGOBJ = "a" * 40, "b" * 40, "c" * 40, "d" * 40


def fake_api(routes):
    """Build a gh() stand-in from {path: python object}; unknown paths raise like gh does."""
    def gh(path, jq=None):
        if path not in routes:
            raise RuntimeError(f"gh api {path} failed: HTTP 404")
        val = routes[path]
        if jq == ".content":
            return base64.b64encode(yaml.safe_dump(val).encode()).decode()
        return json.dumps(val)
    return gh


@unittest.skipIf(yaml is None, "PyYAML not installed")
class ActionDepsTest(unittest.TestCase):
    def setUp(self):
        self.m = load()

    def workflow(self, text):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "ci.yml"), "w") as f:
            f.write(text)
        return d

    def test_split_uses_keeps_sub_path(self):
        self.assertEqual(self.m.split_uses("github/codeql-action/init@v3"),
                         ("github/codeql-action", "init", "v3"))
        self.assertEqual(self.m.split_uses("o/r/.github/workflows/x.yml@" + SHA_A),
                         ("o/r", ".github/workflows/x.yml", SHA_A))

    def test_find_usages_reads_comments_steps_and_reusable_workflows(self):
        d = self.workflow(f"""
jobs:
  a:
    steps:
      - uses: actions/checkout@{SHA_A} # v4.1.0
        with: {{fetch-depth: 0}}
      - uses: github/codeql-action/init@v3
        with: {{languages: python}}
      - uses: ./local
  b:
    uses: o/r/.github/workflows/build.yml@{SHA_B} # tag=v2.0.0
    with: {{target: x}}
""")
        u = self.m.find_usages([d])
        self.assertEqual(set(u), {"actions/checkout", "github/codeql-action", "o/r"})
        self.assertEqual(u["actions/checkout"]["commented"], {"v4.1.0": {SHA_A}})
        self.assertEqual(u["actions/checkout"]["subs"][""], {"fetch-depth"})
        self.assertEqual(u["github/codeql-action"]["subs"]["init"], {"languages"})
        self.assertEqual(u["o/r"]["subs"][".github/workflows/build.yml"], {"target"})
        self.assertEqual(u["o/r"]["commented"], {"v2.0.0": {SHA_B}})

    def test_candidates_sort_by_semver_not_publish_order(self):
        self.m.gh = fake_api({"/repos/o/r/releases?per_page=100": [
            {"tag_name": "v3.1.0", "draft": False, "prerelease": False, "published_at": ago(1)},
            {"tag_name": "v8.0.1", "draft": False, "prerelease": False, "published_at": ago(500)},
            {"tag_name": "v9.0.0-rc1", "draft": False, "prerelease": True, "published_at": ago(1)},
        ]})
        self.assertEqual([t for t, _ in self.m.candidates("o/r")], ["v8.0.1", "v3.1.0"])

    def test_candidates_fall_back_to_tags(self):
        self.m.gh = fake_api({"/repos/o/r/releases?per_page=100": [],
                              "/repos/o/r/tags?per_page=100": [{"name": "v1.2.0"}, {"name": "v1.10.0"}]})
        self.assertEqual(self.m.candidates("o/r"), [("v1.10.0", None), ("v1.2.0", None)])

    def test_resolve_follows_annotated_tag(self):
        self.m.gh = fake_api({
            "/repos/o/r/git/ref/tags/v1.0.0": {"object": {"type": "tag", "sha": TAGOBJ}},
            f"/repos/o/r/git/tags/{TAGOBJ}": {"object": {"type": "commit", "sha": SHA_A}},
            f"/repos/o/r/commits/{SHA_A}": {"commit": {"committer": {"date": ago(10)}}},
        })
        self.assertEqual(self.m.resolve("o/r", "v1.0.0")[0], SHA_A)

    def routes_two_releases(self, newest_age):
        return {
            "/repos/o/r/releases?per_page=100": [
                {"tag_name": "v2.0.0", "draft": False, "prerelease": False, "published_at": ago(newest_age)},
                {"tag_name": "v1.9.0", "draft": False, "prerelease": False, "published_at": ago(400)},
            ],
            "/repos/o/r/git/ref/tags/v2.0.0": {"object": {"type": "commit", "sha": SHA_B}},
            "/repos/o/r/git/ref/tags/v1.9.0": {"object": {"type": "commit", "sha": SHA_C}},
            f"/repos/o/r/commits/{SHA_B}": {"commit": {"committer": {"date": ago(newest_age + 1)}}},
            f"/repos/o/r/commits/{SHA_C}": {"commit": {"committer": {"date": ago(401)}}},
        }

    def test_pick_falls_back_past_a_fresh_release(self):
        self.m.gh = fake_api(self.routes_two_releases(newest_age=5))
        newest, chosen = self.m.pick("o/r", 72)
        self.assertEqual(newest["tag"], "v2.0.0")
        self.assertEqual((chosen["tag"], chosen["sha"]), ("v1.9.0", SHA_C))

    def test_pick_takes_newest_when_old_enough(self):
        self.m.gh = fake_api(self.routes_two_releases(newest_age=100))
        self.assertEqual(self.m.pick("o/r", 72)[1]["tag"], "v2.0.0")

    def test_age_uses_the_newer_of_commit_and_release(self):
        self.assertLess(self.m.age_hours(ago(1000), ago(2)), 3)

    def test_comment_mismatch_is_flagged(self):
        self.m.gh = fake_api({
            "/repos/o/r/git/ref/tags/v1.0.0": {"object": {"type": "commit", "sha": SHA_A}},
            f"/repos/o/r/commits/{SHA_A}": {"commit": {"committer": {"date": ago(10)}}},
        })
        self.assertEqual(self.m.check_comment_pins("o/r", {"v1.0.0": {SHA_A}}), [])
        problems = self.m.check_comment_pins("o/r", {"v1.0.0": {SHA_B}, "v9.9.9": {SHA_C}})
        self.assertEqual(len(problems), 2)

    def test_declared_inputs_for_actions_and_workflows(self):
        action = {"inputs": {"a": {"required": True}, "b": {"required": True, "default": "x"}, "c": None}}
        self.assertEqual(self.m.declared_inputs("action", action), ({"a", "b", "c"}, {"a"}))
        wf = yaml.safe_load("on:\n  workflow_call:\n    inputs:\n      t: {required: true, type: string}\n")
        self.assertEqual(self.m.declared_inputs("workflow", wf), ({"t"}, {"t"}))

    def test_transitive_flags_unpinned_inner_dependencies(self):
        comp = {"runs": {"using": "composite", "steps": [
            {"uses": "actions/setup-node@v4"}, {"uses": f"actions/cache@{SHA_A}"},
            {"uses": "docker://alpine:3"}, {"uses": "docker://alpine@sha256:" + "0" * 64}, {"run": "x"}]}}
        self.assertEqual(self.m.transitive("action", comp), ["actions/setup-node@v4", "docker://alpine:3"])
        self.assertEqual(self.m.transitive("action", {"runs": {"using": "docker", "image": "docker://x:1"}}),
                         ["docker://x:1"])
        self.assertEqual(self.m.transitive("action", {"runs": {"using": "node24", "main": "i.js"}}), [])

    def test_check_survives_a_broken_repo_and_pins_the_gated_release(self):
        d = self.workflow(f"jobs:\n  a:\n    steps:\n      - uses: o/r@{SHA_C} # v1.0.0\n"
                          "      - uses: gone/away@v1\n")
        routes = self.routes_two_releases(newest_age=5)
        routes["/repos/o/r/git/ref/tags/v1.0.0"] = {"object": {"type": "commit", "sha": SHA_C}}
        routes[f"/repos/o/r/contents/action.yml?ref={SHA_C}"] = {"inputs": {}, "runs": {"using": "node24"}}
        self.m.gh = fake_api(routes)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = self.m.main(["check", d])
        text = out.getvalue()
        self.assertEqual(rc, 1)  # gone/away errored
        self.assertIn("ERROR", text)
        self.assertIn(f"pin as       o/r@{SHA_C} # v1.9.0", text)
        self.assertIn("use instead  v1.9.0", text)
        self.assertNotIn(f"o/r@{SHA_B}", text)


if __name__ == "__main__":
    unittest.main()
