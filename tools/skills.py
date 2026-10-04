"""Shared helpers: find plugins and skills in this repo and read their metadata. Stdlib only."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
# Agent Skills limits (also what Claude Desktop / claude.ai upload enforces)
NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_NAME, MAX_DESCRIPTION = 64, 1024


def load_json(path):
    with open(path) as f:
        return json.load(f)


def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def marketplace():
    return load_json(MARKETPLACE)


def plugin_dir(name):
    return ROOT / "plugins" / name


def plugin_manifest_path(name):
    return plugin_dir(name) / ".claude-plugin" / "plugin.json"


def plugin_manifest(name):
    return load_json(plugin_manifest_path(name))


def plugin_names():
    """Plugins listed in the marketplace, in marketplace order."""
    return [p["name"] for p in marketplace()["plugins"]]


def skill_dirs(name):
    """Skill directories of a plugin: plugins/<name>/skills/<skill>/SKILL.md."""
    base = plugin_dir(name) / "skills"
    return sorted(p.parent for p in base.glob("*/SKILL.md")) if base.is_dir() else []


def frontmatter(skill_md):
    """Parse the simple `key: value` YAML frontmatter of a SKILL.md (no nesting needed here)."""
    text = Path(skill_md).read_text()
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    out = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith((" ", "\t", "#")):
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def semver(v):
    m = SEMVER.match(v or "")
    return tuple(int(x) for x in m.groups()) if m else None
