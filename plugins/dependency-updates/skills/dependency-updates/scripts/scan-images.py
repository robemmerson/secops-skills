#!/usr/bin/env python3
"""Inventory the container images a repo references, bucketed by pin tightness.

Reads compose files, Dockerfiles/Containerfiles, and (with --all-yaml) every
YAML file's `image:` keys - Kubernetes manifests, Helm values, CI configs. It
reads the text rather than `docker compose config` so that commented-out
services and ${VAR} defaults stay visible. Stdlib only.

  python3 scan-images.py [--all-yaml] [--exclude GLOB ...] [paths...]
"""

import argparse
import fnmatch
import re
import sys
from collections import defaultdict
from pathlib import Path

IMAGE = re.compile(r"^(\s*)(#\s*)?-?\s*image:\s*[\"']?([^\"'\s#]+)")
# FROM [--platform=...] image [AS name]
FROM = re.compile(r"^\s*(#\s*)?FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I)

COMPOSE = ("compose.yaml", "compose.yml", "docker-compose*.yaml", "docker-compose*.yml",
           "compose.*.yaml", "compose.*.yml")
DOCKERFILE = ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "*.dockerfile",
              "Containerfile", "Containerfile.*")
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", ".terraform"}

# Tags that name a moving target rather than a release. These are the ones that
# make a deployment non-reproducible: the same file yields a different image
# tomorrow, and there is no record of what ran yesterday.
FLOATING = {"latest", "stable", "edge", "main", "master", "dev", "develop",
            "nightly", "rolling", "beta", "testing", "release", "lts", "current"}


def classify(ref):
    if "@sha256:" in ref:
        return "digest"
    if "${" in ref or ref.startswith("$"):
        return "variable"
    # The tag is whatever follows the last colon after the last slash, so a
    # registry port (localhost:5000/app) is not mistaken for one.
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last:
        return "untagged"
    tag = last.rsplit(":", 1)[1]
    base = tag.split("-")[0]
    if tag in FLOATING or base in FLOATING:
        return "floating"
    # A partial version (postgres:16, golang:1.25, node:22-alpine) still moves
    # with every minor or patch, which is usually intended - but it is not a pin.
    if re.fullmatch(r"v?\d+(\.\d+)?(-.+)?", tag):
        return "partial"
    if re.search(r"\d", tag):
        return "version"
    return "floating"


ORDER = ["untagged", "floating", "variable", "partial", "version", "digest"]
BLURB = {
    "untagged":   "no tag at all - resolves to :latest on every pull",
    "floating":   "moving tag - the image changes under you with no commit",
    "variable":   "version comes from a variable; check the .env / ARG default",
    "partial":    "partial version (16, 1.25) - picks up newer minors/patches on pull",
    "version":    "release tag - readable, but tags can be re-pushed",
    "digest":     "pinned to a digest - immutable",
}


def matches(path, patterns):
    return any(fnmatch.fnmatch(path.name, p) for p in patterns)


def walk(root):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and not SKIP_DIRS.intersection(p.relative_to(root).parts):
            yield p


def scan_file(f, all_yaml):
    """Yield (ref, lineno, commented) for every image reference in one file."""
    text = f.read_text(errors="replace").splitlines()
    if matches(f, DOCKERFILE):
        stages = set()
        for n, line in enumerate(text, 1):
            m = FROM.match(line)
            if not m:
                continue
            ref, alias = m.group(2), m.group(3)
            if alias:
                stages.add(alias.lower())
            # `FROM scratch` and `FROM <earlier stage>` are not images to pin.
            if ref.lower() == "scratch" or ref.lower() in stages - {(alias or "").lower()}:
                continue
            yield ref, n, bool(m.group(1))
    elif matches(f, COMPOSE) or (all_yaml and f.suffix in (".yml", ".yaml")):
        for n, line in enumerate(text, 1):
            m = IMAGE.match(line)
            if m:
                yield m.group(3), n, bool(m.group(2))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--all-yaml", action="store_true",
                    help="also read `image:` from every YAML file (k8s, Helm values, CI)")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="skip paths matching this glob (repeatable), e.g. 'test*/*'")
    args = ap.parse_args(argv)

    buckets, commented, files = defaultdict(list), 0, 0
    for root in map(Path, args.paths or ["."]):
        for f in walk(root):
            if any(fnmatch.fnmatch(str(f), g) for g in args.exclude):
                continue
            hits = list(scan_file(f, args.all_yaml))
            files += bool(hits)
            for ref, n, is_comment in hits:
                if is_comment:
                    commented += 1
                else:
                    buckets[classify(ref)].append(f"{ref:<70} {f}:{n}")

    total = sum(len(v) for v in buckets.values())
    for kind in ORDER:
        if not buckets[kind]:
            continue
        print(f"\n{kind.upper()}  ({len(buckets[kind])}/{total})  - {BLURB[kind]}")
        for row in sorted(buckets[kind]):
            print(f"  {row}")

    print(f"\n{total} active image references in {files} files, {commented} commented out.")
    moving = sum(len(buckets[k]) for k in ("untagged", "floating", "partial"))
    if moving:
        print(f"{moving} are on a moving reference: the repo does not record what actually runs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
