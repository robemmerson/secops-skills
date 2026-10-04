"""Tests for tools/validate.py and tools/release.py, run against a throwaway git repo.

  python3 -m unittest discover -s tools/tests
"""
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
SKILL = """---
name: {name}
description: {desc}
---

# {name}
"""


class RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(TOOLS, self.tmp / "tools", ignore=shutil.ignore_patterns("tests", "__pycache__"))
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "t")
        (self.tmp / ".claude-plugin").mkdir()
        self.write_json(".claude-plugin/marketplace.json", {
            "name": "test", "owner": {"name": "t", "url": "https://github.com/someone"},
            "plugins": [{"name": "alpha", "source": "./plugins/alpha", "description": "d"}]})
        self.make_plugin("alpha", "1.0.0")
        self.commit("feat: initial")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.tmp, capture_output=True, text=True, check=True).stdout

    def write_json(self, rel, data):
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2) + "\n")

    def make_plugin(self, name, version, desc="A test skill."):
        self.write_json(f"plugins/{name}/.claude-plugin/plugin.json",
                        {"name": name, "version": version, "description": "d"})
        sd = self.tmp / "plugins" / name / "skills" / name
        (sd / "scripts").mkdir(parents=True, exist_ok=True)
        (sd / "SKILL.md").write_text(SKILL.format(name=name, desc=desc))
        (sd / "scripts" / "run.py").write_text("print('hi')\n")
        (self.tmp / "plugins" / name / "README.md").write_text(f"# {name}\n")

    def commit(self, msg, body=""):
        self.git("add", "-A")
        args = ["commit", "-q", "--allow-empty", "-m", msg] + (["-m", body] if body else [])
        self.git(*args)

    def touch(self, name="alpha", fname="notes.md"):
        p = self.tmp / "plugins" / name / "skills" / name / fname
        p.write_text(p.read_text() + "x\n" if p.exists() else "x\n")

    def run_tool(self, *args, check=True):
        r = subprocess.run(["python3", *args], cwd=self.tmp, capture_output=True, text=True)
        if check and r.returncode != 0:
            raise AssertionError(r.stdout + r.stderr)
        return r

    def plan(self):
        return json.loads(self.run_tool("tools/release.py", "plan").stdout)


class ReleaseTests(RepoCase):
    def test_initial_release_uses_manifest_version(self):
        [r] = self.plan()
        self.assertEqual((r["version"], r["bump"], r["tag"]), ("1.0.0", "initial", "alpha-v1.0.0"))

    def test_no_changes_no_release(self):
        self.git("tag", "alpha-v1.0.0")
        self.assertEqual(self.plan(), [])

    def test_bumps(self):
        self.git("tag", "alpha-v1.0.0")
        self.touch(); self.commit("fix: typo")
        self.assertEqual(self.plan()[0]["version"], "1.0.1")
        self.touch(); self.commit("feat(alpha): new command")
        self.assertEqual(self.plan()[0]["version"], "1.1.0")
        self.touch(); self.commit("refactor!: drop old flag")
        self.assertEqual(self.plan()[0]["version"], "2.0.0")

    def test_breaking_change_footer_and_non_conventional(self):
        self.git("tag", "alpha-v1.2.3")
        self.touch(); self.commit("Update the docs")
        self.assertEqual(self.plan()[0]["version"], "1.2.4")
        self.touch(); self.commit("fix: x", "BREAKING CHANGE: removed y")
        self.assertEqual(self.plan()[0]["version"], "2.0.0")

    def test_other_paths_and_release_commits_ignored(self):
        self.git("tag", "alpha-v1.0.0")
        (self.tmp / "README.md").write_text("x\n"); self.commit("feat: repo readme")
        self.touch(); self.commit("chore(release): alpha v1.0.1 [skip ci]")
        self.assertEqual(self.plan(), [])

    def test_highest_tag_by_semver(self):
        self.git("tag", "alpha-v1.9.0")
        self.git("tag", "alpha-v1.10.0")
        self.touch(); self.commit("fix: y")
        self.assertEqual(self.plan()[0]["version"], "1.10.1")

    def test_apply_writes_version(self):
        self.git("tag", "alpha-v1.0.0")
        self.touch(); self.commit("feat: z")
        self.run_tool("tools/release.py", "apply")
        m = json.loads((self.tmp / "plugins/alpha/.claude-plugin/plugin.json").read_text())
        self.assertEqual(m["version"], "1.1.0")

    def test_zip_layout(self):
        (self.tmp / "plugins/alpha/skills/alpha/__pycache__").mkdir()
        (self.tmp / "plugins/alpha/skills/alpha/__pycache__/x.pyc").write_text("junk")
        out = self.tmp / "dist"
        path = self.run_tool("tools/release.py", "zip", "alpha", str(out)).stdout.strip()
        self.assertTrue(path.endswith("alpha-v1.0.0.zip"))
        names = zipfile.ZipFile(path).namelist()
        self.assertIn("alpha/SKILL.md", names)
        self.assertIn("alpha/scripts/run.py", names)
        self.assertFalse(any("__pycache__" in n or n.endswith(".pyc") for n in names))

    def test_notes(self):
        self.git("tag", "alpha-v1.0.0")
        self.touch(); self.commit("feat: shiny")
        n = self.run_tool("tools/release.py", "notes", "alpha").stdout
        self.assertIn("## alpha v1.1.0", n)
        self.assertIn("- feat: shiny", n)
        self.assertIn("claude plugin install alpha@test", n)
        self.assertIn("claude plugin marketplace add someone/test", n)


class ValidateTests(RepoCase):
    def test_valid(self):
        self.assertEqual(self.run_tool("tools/validate.py").returncode, 0)

    def expect_error(self, fragment):
        r = self.run_tool("tools/validate.py", check=False)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(fragment, r.stdout)

    def test_unlisted_plugin(self):
        self.make_plugin("beta", "1.0.0")
        self.expect_error("plugins/beta: not listed")

    def test_marketplace_version_rejected(self):
        mk = json.loads((self.tmp / ".claude-plugin/marketplace.json").read_text())
        mk["plugins"][0]["version"] = "1.0.0"
        self.write_json(".claude-plugin/marketplace.json", mk)
        self.expect_error("remove 'version'")

    def test_bad_semver(self):
        self.write_json("plugins/alpha/.claude-plugin/plugin.json", {"name": "alpha", "version": "1.0", "description": "d"})
        self.expect_error("is not X.Y.Z")

    def test_long_description(self):
        self.make_plugin("alpha", "1.0.0", desc="x" * 1025)
        self.expect_error("description must be 1..1024")

    def test_env_file_rejected(self):
        (self.tmp / "plugins/alpha/skills/alpha/.env").write_text("DEVO_TOKEN=x\n")
        self.expect_error(".env: must not be committed")


if __name__ == "__main__":
    unittest.main()
