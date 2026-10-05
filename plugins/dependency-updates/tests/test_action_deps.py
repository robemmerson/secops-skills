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
        with open(os.path.join(d, "ci.yml"), "w", encoding="utf-8") as f:
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



NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def at(hours):
    """An ISO time `hours` before the frozen NOW (fractions allowed)."""
    return (NOW - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Frozen(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def release(tag, hours, prerelease=False, draft=False):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease, "published_at": at(hours)}


def lightweight(routes, tag, sha, commit_hours, repo="o/r"):
    routes[f"/repos/{repo}/git/ref/tags/{tag}"] = {"object": {"type": "commit", "sha": sha}}
    routes[f"/repos/{repo}/commits/{sha}"] = {"commit": {"committer": {"date": at(commit_hours)}}}
    return routes


def run(m, argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = m.main(argv)
    return rc, out.getvalue(), err.getvalue()


@unittest.skipIf(yaml is None, "PyYAML not installed")
class Base(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.m.datetime = Frozen

    def workflow(self, text, name="ci.yml"):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d)
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write(text)
        return d

    def releases(self, *rels, repo="o/r"):
        return {f"/repos/{repo}/releases?per_page=100": list(rels)}


class AgeGateTest(Base):
    def gated(self, newest_hours, min_age=72):
        routes = self.releases(release("v2.0.0", newest_hours), release("v1.9.0", 400))
        lightweight(routes, "v2.0.0", SHA_B, 500)  # an old commit: the release date decides
        lightweight(routes, "v1.9.0", SHA_C, 500)
        self.m.gh = fake_api(routes)
        return self.m.pick("o/r", min_age)[1]["tag"]

    def test_boundary_is_exact(self):
        self.assertEqual(self.gated(71), "v1.9.0")
        self.assertEqual(self.gated(71.99), "v1.9.0")
        self.assertEqual(self.gated(72), "v2.0.0")  # exactly 72 h passes
        self.assertEqual(self.gated(73), "v2.0.0")

    def test_min_age_override(self):
        self.assertEqual(self.gated(1, min_age=0), "v2.0.0")
        self.assertEqual(self.gated(100, min_age=168), "v1.9.0")

    def test_cli_min_age_zero_adopts_a_fresh_release(self):
        d = self.workflow(f"jobs:\n  a:\n    steps:\n      - uses: o/r@{SHA_C} # v1.9.0\n")
        routes = self.releases(release("v2.0.0", 1), release("v1.9.0", 400))
        lightweight(routes, "v2.0.0", SHA_B, 2)
        lightweight(routes, "v1.9.0", SHA_C, 500)
        routes[f"/repos/o/r/contents/action.yml?ref={SHA_B}"] = {"runs": {"using": "node24"}}
        routes[f"/repos/o/r/contents/action.yml?ref={SHA_C}"] = {"runs": {"using": "node24"}}
        self.m.gh = fake_api(routes)
        rc, out, _ = run(self.m, ["check", d, "--min-age-hours", "0"])
        self.assertEqual(rc, 0)
        self.assertIn("0h gate", out)
        self.assertIn(f"pin as       o/r@{SHA_B} # v2.0.0", out)
        rc, out, _ = run(self.m, ["check", d])  # default 72 h
        self.assertIn("72h gate     FAIL - only 1h old", out)
        self.assertIn(f"pin as       o/r@{SHA_C} # v1.9.0", out)

    def test_a_fresh_commit_behind_an_old_release_date_is_fresh(self):
        # the tag was re-pointed to a new commit after the release was published
        self.assertAlmostEqual(self.m.age_hours(at(10), at(400)), 10, places=3)
        self.assertAlmostEqual(self.m.age_hours(at(400), at(10)), 10, places=3)
        self.assertAlmostEqual(self.m.age_hours(at(30), None), 30, places=3)  # tag-only: commit decides
        routes = self.releases(release("v2.0.0", 400), release("v1.9.0", 500))
        lightweight(routes, "v2.0.0", SHA_B, 10)
        lightweight(routes, "v1.9.0", SHA_C, 600)
        self.m.gh = fake_api(routes)
        newest, chosen = self.m.pick("o/r", 72)
        self.assertEqual((newest["tag"], round(newest["age"])), ("v2.0.0", 10))
        self.assertEqual(chosen["tag"], "v1.9.0")

    def test_tag_only_repos_are_gated_on_the_commit_date(self):
        routes = {"/repos/o/r/releases?per_page=100": [],
                  "/repos/o/r/tags?per_page=100": [{"name": "v1.1.0"}, {"name": "v1.0.0"}]}
        lightweight(routes, "v1.1.0", SHA_B, 5)
        lightweight(routes, "v1.0.0", SHA_C, 300)
        self.m.gh = fake_api(routes)
        newest, chosen = self.m.pick("o/r", 72)
        self.assertEqual((newest["tag"], newest["published"]), ("v1.1.0", None))
        self.assertEqual(chosen["tag"], "v1.0.0")

    def test_falls_back_to_the_newest_old_enough_release_without_resolving_fresh_ones(self):
        routes = self.releases(release("v3.0.0", 2), release("v2.1.0", 20), release("v2.0.0", 50),
                               release("v1.0.0", 900))
        lightweight(routes, "v3.0.0", SHA_A, 3)
        lightweight(routes, "v1.0.0", SHA_C, 901)  # v2.x are never resolved: no routes for them
        self.m.gh = fake_api(routes)
        newest, chosen = self.m.pick("o/r", 72)
        self.assertEqual((newest["tag"], chosen["tag"]), ("v3.0.0", "v1.0.0"))

    def test_nothing_old_enough_says_wait(self):
        rels = [release(f"v1.{i}.0", 1 + i) for i in range(12, -1, -1)]  # 13 releases, all < 72 h
        routes = self.releases(*rels)
        lightweight(routes, "v1.12.0", SHA_A, 2)
        self.m.gh = fake_api(routes)
        self.assertIsNone(self.m.pick("o/r", 72)[1])
        d = self.workflow("jobs:\n  a:\n    steps:\n      - uses: o/r@v1\n")
        rc, out, _ = run(self.m, ["check", d])
        self.assertEqual(rc, 0)
        self.assertIn("nothing in the last 11 releases passes the gate - wait", out)


class PinTest(Base):
    def check_pin(self, line):
        d = self.workflow(f"jobs:\n  a:\n    steps:\n      {line}\n")
        routes = self.releases(release("v1.0.0", 400))
        lightweight(routes, "v1.0.0", SHA_A, 401)
        routes[f"/repos/o/r/contents/action.yml?ref={SHA_A}"] = {"runs": {"using": "node24"}}
        self.m.gh = fake_api(routes)
        return run(self.m, ["check", d])[1]

    def test_mutable_refs_are_flagged(self):
        for ref in ("v1", "v1.0.0", "main", "abc1234", "a" * 39):
            with self.subTest(ref=ref):
                self.assertIn("<- mutable ref, not SHA-pinned", self.check_pin(f"- uses: o/r@{ref}"))

    def test_full_sha_with_matching_comment_passes(self):
        out = self.check_pin(f"- uses: o/r@{SHA_A} # v1.0.0")
        self.assertIn(f"current pin  {SHA_A}   (v1.0.0)", out)
        self.assertNotIn("MISMATCH", out)
        self.assertNotIn("mutable", out)
        self.assertIn("already on (or past)", out)

    def test_full_sha_without_a_version_comment(self):
        out = self.check_pin(f"- uses: o/r@{SHA_A}")
        self.assertIn("1 pin(s) have no # vX.Y.Z comment", out)
        self.assertIn("majors       unknown", out)
        out = self.check_pin(f"- uses: o/r@{SHA_A} # pinned")  # a comment that is not a version
        self.assertIn("1 pin(s) have no # vX.Y.Z comment", out)

    def test_comment_naming_another_version_is_caught(self):
        out = self.check_pin(f"- uses: o/r@{SHA_B} # v1.0.0")
        self.assertIn(f"MISMATCH     {SHA_B[:12]} is commented v1.0.0, but v1.0.0 is {SHA_A[:12]}", out)
        out = self.check_pin(f"- uses: o/r@{SHA_A} # v0.9.0")
        self.assertIn("MISMATCH     comment v0.9.0: no such tag upstream", out)

    def test_lightweight_and_annotated_tags_resolve_to_the_commit(self):
        routes = lightweight({}, "v1.0.0", SHA_A, 10)
        routes["/repos/o/r/git/ref/tags/v2.0.0"] = {"object": {"type": "tag", "sha": TAGOBJ}}
        routes[f"/repos/o/r/git/tags/{TAGOBJ}"] = {"object": {"type": "commit", "sha": SHA_B}}
        routes[f"/repos/o/r/commits/{SHA_B}"] = {"commit": {"committer": {"date": at(20)}}}
        self.m.gh = fake_api(routes)
        self.assertEqual(self.m.resolve("o/r", "v1.0.0"), (SHA_A, at(10)))
        self.assertEqual(self.m.resolve("o/r", "v2.0.0"), (SHA_B, at(20)))  # never the tag object
        rc, out, _ = run(self.m, ["resolve", "o/r", "v2.0.0"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, f"o/r@{SHA_B} # v2.0.0\ncommit {at(20)} (20h ago)\n")


class MajorsTest(Base):
    def majors(self, pin, newest="v6.1.0"):
        d = self.workflow(f"jobs:\n  a:\n    steps:\n      - uses: o/r@{pin}\n")
        routes = self.releases(release(newest, 400))
        lightweight(routes, newest, SHA_A, 401)
        routes[f"/repos/o/r/contents/action.yml?ref={SHA_A}"] = {"runs": {"using": "node24"}}
        self.m.gh = fake_api(routes)
        return [l for l in run(self.m, ["check", d])[1].splitlines() if "majors" in l or "status" in l][0]

    def test_major_only_and_partial_pins(self):
        self.assertIn("crosses v5, v6 - read the release notes for EACH", self.majors("v4"))
        self.assertIn("crosses v5, v6", self.majors("v4.2"))
        self.assertIn("none - minor/patch bump only", self.majors("v6"))
        self.assertIn("none - minor/patch bump only", self.majors("v6.0.0"))
        self.assertIn("already on (or past)", self.majors("v6.1.0"))
        self.assertIn("unknown", self.majors("main"))

    def test_semver_filters(self):
        self.assertEqual(self.m.semver("v1.2.3"), (1, 2, 3))
        self.assertEqual(self.m.semver("1.2.3"), (1, 2, 3))  # v-less release tags are real releases
        for tag in ("v1.2.3-rc.1", "v1.2.3-beta", "v3.2.2-node20", "v1.2", "v1", "latest", "release-2026", None):
            self.assertIsNone(self.m.semver(tag), tag)
        self.assertEqual([self.m.pin_major(p) for p in ("v4", "v4.2", "4.2.1", "main", SHA_A)], [4, 4, 4, None, None])

    def test_candidates_skip_prereleases_drafts_and_non_semver_tags(self):
        self.m.gh = fake_api(self.releases(
            release("v5.0.0-rc.1", 1), release("v4.1.0", 10, prerelease=True), release("v4.0.0", 20, draft=True),
            release("v3.2.2-node20", 30), release("nightly", 40), release("3.1.0", 50), release("v3.0.0", 60)))
        self.assertEqual([t for t, _ in self.m.candidates("o/r")], ["3.1.0", "v3.0.0"])
        self.m.gh = fake_api({"/repos/o/r/releases?per_page=100": [],
                              "/repos/o/r/tags?per_page=100": [{"name": "v2.0.0-alpha"}, {"name": "main-2026"}]})
        self.assertEqual(self.m.candidates("o/r"), [])


class CallSiteTest(Base):
    def report(self, spec, passed, sub="", path=None):
        path = path or ((sub + "/" if sub else "") + "action.yml")
        self.m.gh = fake_api({f"/repos/o/r/contents/{path}?ref={SHA_A}": spec})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.m.report_inputs("o/r", {"subs": {sub: set(passed)}}, SHA_A)
        return out.getvalue()

    def test_removed_and_newly_required_inputs(self):
        spec = {"inputs": {"token": {"required": False}, "path": {"required": True},
                           "mode": {"required": True, "default": "x"}}, "runs": {"using": "node24", "main": "i.js"}}
        out = self.report(spec, {"token", "fetch-depth"})
        self.assertIn("you pass     fetch-depth, token", out)
        self.assertIn("removed      fetch-depth", out)
        self.assertIn("now required path  <- you do not pass these", out)
        self.assertNotIn("mode", out.split("now required")[1])  # required with a default is not "required"
        out = self.report(spec, {"token", "path"})
        self.assertIn("removed      none - every input you pass still exists", out)
        self.assertNotIn("now required", out)

    def test_composite_action_in_a_sub_path(self):
        spec = {"inputs": {"languages": {}}, "runs": {"using": "composite", "steps": [
            {"uses": "actions/setup-python@v5"}, {"uses": f"actions/cache@{SHA_B}"}, {"run": "echo"}]}}
        out = self.report(spec, {"languages"}, sub="init")
        self.assertIn("[init]", out)
        self.assertIn("unpinned     actions/setup-python@v5  <- not frozen by your SHA pin", out)
        self.assertNotIn("actions/cache", out)

    def test_docker_actions(self):
        out = self.report({"inputs": {"a": {}}, "runs": {"using": "docker", "image": "Dockerfile"}}, {"a"})
        self.assertIn("unpinned     Dockerfile (built at run time; check its FROM lines)", out)
        out = self.report({"runs": {"using": "docker", "image": "docker://alpine:3.22"}}, set())
        self.assertIn("unpinned     docker://alpine:3.22", out)
        out = self.report({"runs": {"using": "docker", "image": "docker://alpine@sha256:" + "0" * 64}}, set())
        self.assertNotIn("unpinned", out)

    def test_action_yaml_fallback_and_missing_spec(self):
        out = self.report({"inputs": {"x": {}}, "runs": {"using": "node24"}}, {"x"}, path="action.yaml")
        self.assertIn("removed      none", out)
        self.m.gh = fake_api({})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.m.report_inputs("o/r", {"subs": {"": {"x"}}}, SHA_A)
        self.assertIn("inputs       o/r: could not read the spec (no action.yml at o/r@", out.getvalue())

    def test_reusable_workflow(self):
        wf = {"on": {"workflow_call": {"inputs": {"env": {"required": True, "type": "string"},
                                                  "dry": {"required": False, "type": "boolean"}}}},
              "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"uses": "actions/checkout@v4"},
                                                                       {"uses": f"actions/cache@{SHA_B}"}]},
                       "deploy": {"uses": "o/other/.github/workflows/deploy.yml@main"},
                       "local": {"uses": "./.github/workflows/local.yml"}}}
        out = self.report(wf, {"dry", "old"}, sub=".github/workflows/release.yml", path=".github/workflows/release.yml")
        self.assertIn("removed      old", out)
        self.assertIn("now required env", out)
        self.assertIn("unpinned     actions/checkout@v4, o/other/.github/workflows/deploy.yml@main", out)
        # PyYAML reads a bare `on:` key as True
        self.assertEqual(self.m.declared_inputs("workflow", yaml.safe_load(
            "on:\n  workflow_call:\n    inputs:\n      a: {required: false}\n")), ({"a"}, set()))
        self.assertEqual(self.m.declared_inputs("workflow", {"on": "push"}), (set(), set()))

    def test_unfrozen(self):
        self.assertFalse(self.m.unfrozen("./local"))
        self.assertFalse(self.m.unfrozen(f"o/r@{SHA_A}"))
        self.assertFalse(self.m.unfrozen("docker://x@sha256:" + "0" * 64))
        for ref in ("o/r@v1", "o/r/sub@main", "docker://x:1", "o/r"):
            self.assertTrue(self.m.unfrozen(ref), ref)

    def test_inputs_command(self):
        self.m.gh = fake_api({f"/repos/o/r/contents/sub/action.yml?ref=v2": {
            "inputs": {"a": {"required": True}, "b": {}}, "runs": {"using": "composite", "steps": [{"uses": "x/y@v1"}]}}})
        rc, out, _ = run(self.m, ["inputs", "o/r/sub", "v2"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "inputs at o/r/sub@v2:\n  a  (required)\n  b\nunpinned dependency: x/y@v1\n")


class UsageTest(Base):
    def test_reference_forms(self):
        d = self.workflow(f"""
jobs:
  a:
    steps:
      - uses: ./local-action
      - uses: docker://alpine:3.22
      - uses: "o/quoted@v1"
      - uses: 'o/single@v2'
      - uses: o/r/sub/dir@{SHA_A}  #v1.0.0
      # - uses: o/commented-out@v1
      - name: x
        uses: o/named@v3   # tag=v3.0.0
      - run: echo "uses: o/in-a-script@v1"
  b:
    uses: o/r/.github/workflows/x.yml@v4
""", name="ci.yaml")
        u = self.m.find_usages([d])
        self.assertEqual(set(u), {"o/quoted", "o/single", "o/r", "o/named"})
        self.assertEqual(u["o/r"]["subs"].keys(), {"sub/dir", ".github/workflows/x.yml"})
        self.assertEqual(u["o/r"]["commented"], {"v1.0.0": {SHA_A}})
        self.assertEqual(u["o/r"]["pins"], {SHA_A, "v4"})
        self.assertEqual(u["o/quoted"]["pins"], {"v1"})
        f = os.path.join(d, "ci.yaml")
        self.assertEqual(u["o/named"]["locs"], {f: [12]})

    def test_files_and_line_numbers_across_a_directory(self):
        d = self.workflow("jobs:\n  a:\n    steps:\n      - uses: o/r@v1\n", name="a.yml")
        with open(os.path.join(d, "b.yaml"), "w", encoding="utf-8") as f:
            f.write("jobs:\n  b:\n    steps:\n      - run: x\n      - uses: o/r@v2\n")
        with open(os.path.join(d, "broken.yml"), "w", encoding="utf-8") as f:
            f.write("jobs: [\n  - uses: o/s@v1\n")  # invalid YAML: the line scan still finds it
        u = self.m.find_usages([d])
        self.assertEqual(u["o/r"]["locs"], {os.path.join(d, "a.yml"): [4], os.path.join(d, "b.yaml"): [5]})
        self.assertEqual(u["o/r"]["pins"], {"v1", "v2"})
        self.assertIn("o/s", u)


class CliTest(Base):
    def test_exit_codes(self):
        rc, out, _ = run(self.m, ["check", self.workflow("jobs:\n  a:\n    steps:\n      - run: x\n")])
        self.assertEqual((rc, out.strip()), (0, "No third-party actions found."))

    def test_gh_missing_is_a_clean_error(self):
        m = load()
        d = self.workflow("jobs:\n  a:\n    steps:\n      - uses: o/r@v1\n      - uses: o/s@v1\n")
        with mock.patch.object(m.subprocess, "run", side_effect=FileNotFoundError(2, "No such file", "gh")):
            for argv in (["check", d], ["resolve", "o/r", "v1"], ["inputs", "o/r", "v1"]):
                with self.subTest(argv=argv[0]):
                    rc, out, err = run(m, argv)
                    self.assertEqual(rc, 2)
                    self.assertIn("gh CLI not found", err)
                    self.assertNotIn("Traceback", err)
                    self.assertEqual(out.count("ERROR"), 0)  # one message, not one per action

    def test_gh_unauthenticated_is_a_clean_error(self):
        m = load()
        d = self.workflow("jobs:\n  a:\n    steps:\n      - uses: o/r@v1\n      - uses: o/s@v1\n")
        failed = mock.Mock(returncode=4, stdout="", stderr="To get started with GitHub CLI, please run:  gh auth login")
        with mock.patch.object(m.subprocess, "run", return_value=failed):
            for argv in (["check", d], ["resolve", "o/r", "v1"]):
                with self.subTest(argv=argv[0]):
                    rc, out, err = run(m, argv)
                    self.assertEqual(rc, 2)
                    self.assertIn("gh auth login", err)
                    self.assertEqual(out.count("ERROR"), 0)

    def test_other_api_errors_stay_per_action(self):
        d = self.workflow("jobs:\n  a:\n    steps:\n      - uses: gone/away@v1\n")
        self.m.gh = fake_api({})
        rc, out, _ = run(self.m, ["check", d])
        self.assertEqual(rc, 1)
        self.assertIn("ERROR        gh api /repos/gone/away/releases?per_page=100 failed: HTTP 404", out)
        rc, _, err = run(self.m, ["resolve", "gone/away", "v1"])
        self.assertEqual(rc, 1)
        self.assertIn("HTTP 404", err)
        self.assertNotIn("Traceback", err)

if __name__ == "__main__":
    unittest.main()
