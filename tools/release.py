#!/usr/bin/env python3
"""Per-plugin automatic versioning and release packaging. Stdlib only.

Each plugin is versioned on its own and tagged `<plugin>-v<X.Y.Z>`. The next version comes from
the Conventional Commits that touched `plugins/<plugin>/` since that plugin's last tag:

  feat: ...                      -> minor      (fix:, docs:, chore:, anything else -> patch)
  feat!: ... / BREAKING CHANGE:  -> major

A plugin with no tag yet is released at the version already in its plugin.json.

  python3 tools/release.py plan               # JSON list of plugins that need a release
  python3 tools/release.py apply              # write the planned versions into plugin.json
  python3 tools/release.py zip  <plugin> <outdir>   # Claude Desktop zips, one per skill
  python3 tools/release.py notes <plugin>     # markdown release notes for the planned release
"""
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

from skills import (ROOT, marketplace, plugin_dir, plugin_manifest, plugin_manifest_path, plugin_names, semver,
                    skill_dirs, write_json)

CONVENTIONAL = re.compile(r"^(?P<type>\w+)(?:\([^)]*\))?(?P<bang>!)?:\s*(?P<subject>.+)$")
RELEASE_COMMIT = re.compile(r"^chore\(release\):")
SKIP_IN_ZIP = ("__pycache__", ".DS_Store")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def last_tag(plugin):
    """Highest `<plugin>-vX.Y.Z` tag, by semver."""
    tags = [t for t in git("tag", "--list", f"{plugin}-v*").split() if semver(t.split("-v")[-1])]
    return max(tags, key=lambda t: semver(t.split("-v")[-1])) if tags else None


def commits_since(plugin, tag):
    """[(sha, subject, body)] touching plugins/<plugin>/ since tag (all history if no tag)."""
    rng = [f"{tag}..HEAD"] if tag else ["HEAD"]
    out = git("log", *rng, "--format=%H%x1f%s%x1f%b%x1e", "--", f"plugins/{plugin}/")
    commits = []
    for rec in out.split("\x1e"):
        if rec.strip():
            sha, subject, body = (rec.strip("\n").split("\x1f") + ["", ""])[:3]
            if not RELEASE_COMMIT.match(subject):
                commits.append((sha, subject, body))
    return commits


def bump_kind(commits):
    kind = None
    for _, subject, body in commits:
        m = CONVENTIONAL.match(subject)
        if (m and m.group("bang")) or "BREAKING CHANGE" in body:
            return "major"
        if m and m.group("type") == "feat":
            kind = "minor"
        elif kind is None:
            kind = "patch"
    return kind


def bump(version, kind):
    major, minor, patch = semver(version)
    if kind == "major":
        return f"{major + 1}.0.0"
    if kind == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def plan():
    releases = []
    for name in plugin_names():
        current = plugin_manifest(name)["version"]
        tag = last_tag(name)
        commits = commits_since(name, tag)
        if tag is None:
            nxt, kind = current, "initial"
        else:
            if not commits:
                continue
            kind = bump_kind(commits)
            nxt = bump(tag.split("-v")[-1], kind)
        releases.append({"plugin": name, "previous_tag": tag, "version": nxt, "bump": kind,
                         "tag": f"{name}-v{nxt}",
                         "commits": [{"sha": s[:7], "subject": subj} for s, subj, _ in commits]})
    return releases


def apply(releases):
    for r in releases:
        path = plugin_manifest_path(r["plugin"])
        m = json.loads(path.read_text())
        m["version"] = r["version"]
        write_json(path, m)


def build_zips(plugin, outdir):
    """One zip per skill, `<skill>-v<version>.zip`, containing the `<skill>/` folder with SKILL.md
    at its top - the layout Claude Desktop / claude.ai expect for an uploaded skill."""
    version = plugin_manifest(plugin)["version"]
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    made = []
    for sd in skill_dirs(plugin):
        target = outdir / f"{sd.name}-v{version}.zip"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(sd.rglob("*")):
                if f.is_file() and not any(s in f.parts or f.name == s for s in SKIP_IN_ZIP) \
                        and f.suffix != ".pyc":
                    z.write(f, Path(sd.name) / f.relative_to(sd))
        made.append(str(target))
    return made


def marketplace_source():
    """(marketplace name, `owner/repo` to add it from): the repo is named after the marketplace and
    belongs to the owner's GitHub account (owner.url), so it works from any fork."""
    mk = marketplace()
    owner = (mk.get("owner", {}).get("url") or "").rstrip("/").rsplit("/", 1)[-1]
    return mk["name"], f"{owner}/{mk['name']}" if owner else mk["name"]


def notes(release):
    name, source = marketplace_source()
    lines = [f"## {release['plugin']} v{release['version']}", ""]
    if release["bump"] == "initial":
        lines.append(f"First release of this plugin in the {name} marketplace.")
    else:
        lines.append(f"{release['bump'].capitalize()} release since `{release['previous_tag']}`.")
    if release["commits"]:
        lines += ["", "### Changes", ""]
        lines += [f"- {c['subject']} ({c['sha']})" for c in release["commits"]]
    skills = ", ".join(sd.name for sd in skill_dirs(release["plugin"]))
    lines += ["", "### Install", "",
              "Claude Code:",
              "```",
              f"claude plugin marketplace add {source}   # once",
              f"claude plugin install {release['plugin']}@{name}     # or: claude plugin update {release['plugin']}@{name}",
              "```",
              f"Claude Desktop / claude.ai: download the attached zip ({skills}) and upload it under "
              "Settings > Capabilities > Skills."]
    return "\n".join(lines) + "\n"


def main(argv):
    if not argv or argv[0] not in ("plan", "apply", "zip", "notes"):
        print(__doc__)
        return 1
    cmd = argv[0]
    if cmd == "plan":
        print(json.dumps(plan(), indent=1))
    elif cmd == "apply":
        releases = plan()
        apply(releases)
        print(json.dumps([{k: r[k] for k in ("plugin", "version", "tag")} for r in releases]))
    elif cmd == "zip":
        print("\n".join(build_zips(argv[1], argv[2])))
    elif cmd == "notes":
        match = [r for r in plan() if r["plugin"] == argv[1]]
        if not match:
            print(f"{argv[1]}: nothing to release", file=sys.stderr)
            return 1
        sys.stdout.write(notes(match[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
