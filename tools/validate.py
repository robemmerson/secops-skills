#!/usr/bin/env python3
"""Validate the marketplace, plugin manifests and skills. Exit 1 on any error.

  python3 tools/validate.py
"""
import subprocess
import sys
from pathlib import Path

from skills import (MARKETPLACE, MAX_DESCRIPTION, MAX_NAME, NAME, ROOT, frontmatter, load_json,
                    marketplace, plugin_dir, plugin_manifest_path, semver, skill_dirs)

MAX_SKILL_BYTES = 30 * 1024 * 1024  # keep Desktop zips comfortably small


def forbidden(path):
    """Files that must never ship in a skill: caches, OS junk, env/credential files."""
    n = path.name
    return (n in ("__pycache__", ".DS_Store", ".env") or n.startswith(".env.")
            or n.endswith((".pyc", ".pem", ".key")))


def committable(directory):
    """Files git would commit under directory (tracked + untracked, minus .gitignore'd);
    falls back to every file when not in a git work tree."""
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--",
                              str(directory)], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        return [ROOT / f for f in out.split("\0") if f]
    except (OSError, subprocess.CalledProcessError):
        return [f for f in Path(directory).rglob("*") if f.is_file()]


def check():
    errors = []
    err = errors.append
    try:
        mk = marketplace()
    except (OSError, ValueError) as e:
        return [f"{MARKETPLACE}: {e}"]
    for field in ("name", "owner", "plugins"):
        if field not in mk:
            err(f"marketplace.json: missing {field!r}")
    listed = []
    for p in mk.get("plugins", []):
        name = p.get("name", "?")
        listed.append(name)
        if p.get("source") != f"./plugins/{name}":
            err(f"marketplace entry {name}: source must be './plugins/{name}'")
        if "version" in p:
            err(f"marketplace entry {name}: remove 'version' (plugin.json is the single source)")
        if not p.get("description"):
            err(f"marketplace entry {name}: missing description")
    on_disk = sorted(d.name for d in (ROOT / "plugins").iterdir() if d.is_dir())
    for extra in sorted(set(on_disk) - set(listed)):
        err(f"plugins/{extra}: not listed in marketplace.json")
    if len(set(listed)) != len(listed):
        err("marketplace.json: duplicate plugin names")

    for name in listed:
        mpath = plugin_manifest_path(name)
        if not mpath.exists():
            err(f"{mpath.relative_to(ROOT)}: missing")
            continue
        m = load_json(mpath)
        if m.get("name") != name:
            err(f"{mpath.relative_to(ROOT)}: name {m.get('name')!r} != directory {name!r}")
        if not semver(m.get("version")):
            err(f"{mpath.relative_to(ROOT)}: version {m.get('version')!r} is not X.Y.Z")
        if not m.get("description"):
            err(f"{mpath.relative_to(ROOT)}: missing description")
        skills = skill_dirs(name)
        if not skills:
            err(f"plugins/{name}: no skills/<name>/SKILL.md")
        for sd in skills:
            rel = sd.relative_to(ROOT)
            fm = frontmatter(sd / "SKILL.md")
            if fm is None:
                err(f"{rel}/SKILL.md: missing --- frontmatter ---")
                continue
            sname, desc = fm.get("name", ""), fm.get("description", "")
            if sname != sd.name:
                err(f"{rel}/SKILL.md: name {sname!r} != directory {sd.name!r}")
            if not NAME.match(sname) or len(sname) > MAX_NAME:
                err(f"{rel}/SKILL.md: name must be lowercase letters/digits/hyphens, <= {MAX_NAME}")
            if not desc or len(desc) > MAX_DESCRIPTION:
                err(f"{rel}/SKILL.md: description must be 1..{MAX_DESCRIPTION} chars (is {len(desc)})")
            size = 0
            for f in committable(sd):
                if forbidden(f) or any(forbidden(Path(part)) for part in f.relative_to(sd).parts):
                    err(f"{f.relative_to(ROOT)}: must not be committed")
                if f.is_file():
                    size += f.stat().st_size
            if size > MAX_SKILL_BYTES:
                err(f"{rel}: {size / 1e6:.1f} MB exceeds {MAX_SKILL_BYTES / 1e6:.0f} MB")
        if not (plugin_dir(name) / "README.md").exists():
            err(f"plugins/{name}: missing README.md")
    return errors


def main():
    errors = check()
    for e in errors:
        print(f"ERROR: {e}")
    print(f"{len(errors)} error(s)" if errors else "marketplace, plugins and skills are valid")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
