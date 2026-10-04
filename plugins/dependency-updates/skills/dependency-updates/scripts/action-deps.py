#!/usr/bin/env python3
"""Audit the GitHub Actions and reusable workflows pinned in a repo's workflows.

For every `uses:` it reports the current pin, the newest stable release, the
newest release that passes the minimum-age gate (the one to pin), the commit
SHA that tag actually dereferences to, which major versions an upgrade would
cross, whether the inputs the workflow passes still exist in that version, and
whether the action itself pulls in unpinned dependencies. Existing SHA pins are
checked against their `# vX.Y.Z` comment.

Needs `gh` (authenticated) and PyYAML.

  python3 action-deps.py check [--min-age-hours 72] [paths...]
  python3 action-deps.py resolve OWNER/REPO TAG
  python3 action-deps.py inputs  OWNER/REPO[/PATH] REF

Exit codes: 0 done, 1 an action or tag could not be read (check reports the
rest), 2 gh is missing or not authenticated.
"""

import argparse
import base64
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

# Tags like v1.2.3 only. Deliberately excludes v3.2.2-node20 style backports and
# prereleases, which sort high but are not what you want to move onto.
STABLE_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*[\"']?([^\s#\"']+)[\"']?\s*(?:#\s*(?:tag=)?(\S+))?")
SHA = re.compile(r"^[0-9a-f]{40}$")
# v4 and v4.2 are legitimate pins even though they are not full semver, so the
# major is read with a looser pattern than the one used to pick a release.
PIN_MAJOR = re.compile(r"^v?(\d+)(?:\.\d+){0,2}$")
# How many gate-failing releases to step past looking for one old enough.
MAX_FALLBACK = 10
NOT_LOGGED_IN = re.compile(r"gh auth login|not logged in|HTTP 401|Bad credentials", re.I)


class GhUnavailable(Exception):
    """gh is missing or not authenticated: every call would fail, so stop at the first."""


def gh(path, jq=None):
    cmd = ["gh", "api", path]
    if jq:
        cmd += ["--jq", jq]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise GhUnavailable("gh CLI not found: install it (https://cli.github.com) and run `gh auth login`")
    if out.returncode != 0:
        if NOT_LOGGED_IN.search(out.stderr):
            raise GhUnavailable(f"gh is not authenticated ({out.stderr.strip()}); run `gh auth login`")
        raise RuntimeError(f"gh api {path} failed: {out.stderr.strip()}")
    return out.stdout.strip()


def hours_since(iso):
    if not iso:
        return None
    t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - t).total_seconds() / 3600


def pin_major(pin):
    m = PIN_MAJOR.match(pin)
    return int(m.group(1)) if m else None


def semver(tag):
    m = STABLE_TAG.match(tag or "")
    return tuple(int(x) for x in m.groups()) if m else None


def split_uses(ref):
    """'owner/repo/sub/dir@v1' -> ('owner/repo', 'sub/dir', 'v1')."""
    target, _, pin = ref.partition("@")
    parts = target.split("/")
    return "/".join(parts[:2]), "/".join(parts[2:]), pin or "(no ref)"


def candidates(repo):
    """Stable versions, newest first by semver, as (tag, published_at or None).

    Publish order lies: maintainers backport to old majors, so v3.1.0 can be
    published after v8.0.1. Sorting by version is the only correct read. Repos
    that tag without cutting GitHub releases fall back to their tags, which
    carry no publication date, so only the commit date can gate them.
    """
    rels = json.loads(gh(f"/repos/{repo}/releases?per_page=100"))
    out = [(r["tag_name"], r.get("published_at")) for r in rels
           if not r["draft"] and not r["prerelease"] and semver(r["tag_name"])]
    if not out:
        tags = json.loads(gh(f"/repos/{repo}/tags?per_page=100"))
        out = [(t["name"], None) for t in tags if semver(t["name"])]
    return sorted(out, key=lambda p: semver(p[0]), reverse=True)


def resolve(repo, tag):
    """Dereference a tag to the commit SHA it points at.

    Annotated tags return object.type == "tag" and their SHA is the tag object,
    not a commit. Pinning a workflow to a tag-object SHA fails at runtime, so
    the second hop is not optional.
    """
    obj = json.loads(gh(f"/repos/{repo}/git/ref/tags/{tag}"))["object"]
    sha = obj["sha"]
    if obj["type"] == "tag":
        sha = json.loads(gh(f"/repos/{repo}/git/tags/{sha}"))["object"]["sha"]
    commit = json.loads(gh(f"/repos/{repo}/commits/{sha}"))
    return sha, commit["commit"]["committer"]["date"]


def age_hours(commit_date, published):
    """Age is governed by whichever is newer. An old commit freshly released is
    still a fresh artifact, and a fresh commit is obviously fresh."""
    return min(h for h in (hours_since(commit_date), hours_since(published)) if h is not None)


def pick(repo, min_age):
    """Return (newest, chosen): dicts with tag, sha, commit, published, age.

    `chosen` is the newest release that passes the age gate, or None if none of
    the first MAX_FALLBACK do. Publication dates are checked before resolving,
    so stepping past fresh releases costs no extra API calls.
    """
    cands = candidates(repo)
    if not cands:
        return None, None
    newest = chosen = None
    for i, (tag, pub) in enumerate(cands[:MAX_FALLBACK + 1]):
        if i and pub and hours_since(pub) < min_age:
            continue
        sha, commit = resolve(repo, tag)
        info = {"tag": tag, "sha": sha, "commit": commit, "published": pub,
                "age": age_hours(commit, pub)}
        if i == 0:
            newest = info
        if info["age"] >= min_age:
            chosen = info
            break
    return newest, chosen


def fetch_yaml(repo, path, ref):
    raw = gh(f"/repos/{repo}/contents/{path}?ref={ref}", ".content")
    return yaml.safe_load(base64.b64decode(raw)) or {}


def action_spec(repo, sub, ref):
    """Load action.yml (or a reusable workflow) for owner/repo[/sub] at ref.

    Returns (kind, spec): kind is "workflow" for a reusable workflow file and
    "action" otherwise.
    """
    if sub.endswith((".yml", ".yaml")):
        return "workflow", fetch_yaml(repo, sub, ref)
    base = f"{sub}/" if sub else ""
    for name in ("action.yml", "action.yaml"):
        try:
            return "action", fetch_yaml(repo, base + name, ref)
        except RuntimeError:
            continue
    raise RuntimeError(f"no action.yml at {repo}/{sub}@{ref}".replace("/@", "@"))


def declared_inputs(kind, spec):
    if kind == "workflow":
        # PyYAML reads the bare key `on` as boolean True.
        on = spec.get("on", spec.get(True)) or {}
        call = on.get("workflow_call") if isinstance(on, dict) else None
        declared = (call or {}).get("inputs") or {}
    else:
        declared = spec.get("inputs") or {}
    required = {k for k, v in declared.items()
                if (v or {}).get("required") and "default" not in (v or {})}
    return set(declared), required


def unfrozen(ref):
    """True for a `uses:` value that can change without its caller changing."""
    if ref.startswith("./"):
        return False
    if ref.startswith("docker://"):
        return "@sha256:" not in ref
    return not SHA.match(split_uses(ref)[2])


def transitive(kind, spec):
    """Dependencies the action pulls in that the caller's SHA pin does not freeze.

    A composite action that `uses:` another action by tag, or a container action
    that runs `docker://image:tag`, can change underneath an immutable pin.
    """
    if kind != "action":
        if kind == "workflow":
            jobs = spec.get("jobs") or {}
            refs = [s.get("uses", "") for j in jobs.values() if isinstance(j, dict)
                    for s in (j.get("steps") or []) if isinstance(s, dict)]
            refs += [j.get("uses", "") for j in jobs.values() if isinstance(j, dict)]
            return [r for r in refs if r and unfrozen(r)]
        return []
    runs = spec.get("runs") or {}
    using = str(runs.get("using", ""))
    if using == "composite":
        refs = [s.get("uses", "") for s in (runs.get("steps") or []) if isinstance(s, dict)]
        return [r for r in refs if r and unfrozen(r)]
    if using == "docker":
        image = str(runs.get("image", ""))
        if image.startswith("docker://") and "@sha256:" not in image:
            return [image]
        if image and not image.startswith("docker://"):
            return [f"{image} (built at run time; check its FROM lines)"]
    return []


def workflow_files(paths):
    files = []
    for p in paths:
        p = Path(p)
        files += sorted(p.rglob("*.y*ml")) if p.is_dir() else [p]
    return files


def find_usages(paths):
    """Map owner/repo -> pins, locations, version comments, and per-sub-path inputs."""
    found = {}
    for f in workflow_files(paths):
        text = f.read_text()
        for lineno, line in enumerate(text.splitlines(), 1):
            m = USES.match(line)
            if not m or m.group(1).startswith((".", "docker://")):
                continue
            ref, comment = m.group(1), m.group(2)
            repo, sub, pin = split_uses(ref)
            e = found.setdefault(repo, {"pins": set(), "locs": {}, "subs": {},
                                        "commented": {}, "uncommented": 0})
            e["pins"].add(pin)
            e["locs"].setdefault(str(f), []).append(lineno)
            e["subs"].setdefault(sub, set())
            # The version comment beside a SHA is the only way to know which
            # release a 40-hex pin corresponds to, so read it rather than
            # trying to parse a version out of the hex.
            if SHA.match(pin):
                if comment and semver(comment):
                    e["commented"].setdefault(comment, set()).add(pin)
                else:
                    e["uncommented"] += 1

        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        for job in (doc.get("jobs") or {}).values():
            if not isinstance(job, dict):
                continue
            # A job-level `uses:` is a reusable workflow; its `with:` sits on the job.
            users = [job] + [s for s in (job.get("steps") or []) if isinstance(s, dict)]
            for u in users:
                if not isinstance(u.get("uses"), str):
                    continue
                repo, sub, _ = split_uses(u["uses"])
                if repo in found:
                    found[repo]["subs"].setdefault(sub, set()).update((u.get("with") or {}).keys())
    return found


def check_comment_pins(repo, commented):
    """Each `<sha> # vX.Y.Z` pin should be exactly what vX.Y.Z resolves to.

    A mismatch means a stale comment, a re-pointed tag, or a SHA that only
    exists in a fork of the repo (GitHub resolves those through the parent).
    """
    problems = []
    for tag, shas in sorted(commented.items()):
        try:
            real, _ = resolve(repo, tag)
        except RuntimeError:
            problems.append(f"comment {tag}: no such tag upstream")
            continue
        for sha in sorted(shas - {real}):
            problems.append(f"{sha[:12]} is commented {tag}, but {tag} is {real[:12]}")
    return problems


def report_inputs(repo, use, sha):
    for sub, passed in sorted(use["subs"].items()):
        label = f"{repo}/{sub}" if sub else repo
        try:
            kind, spec = action_spec(repo, sub, sha)
        except RuntimeError as e:
            print(f"  inputs       {label}: could not read the spec ({e})")
            continue
        declared, required = declared_inputs(kind, spec)
        head = f"  [{sub}]\n" if len(use["subs"]) > 1 or sub else ""
        print(f"{head}  you pass     {', '.join(sorted(passed)) or '(none)'}")
        gone = sorted(passed - declared)
        print(f"  removed      {', '.join(gone) if gone else 'none - every input you pass still exists'}")
        newly = sorted(required - passed)
        if newly:
            print(f"  now required {', '.join(newly)}  <- you do not pass these")
        loose = transitive(kind, spec)
        if loose:
            print(f"  unpinned     {', '.join(loose)}  <- not frozen by your SHA pin")


def check_one(repo, use, min_age):
    """Print one block. Returns True when the newest release failed the age gate."""
    locs = ", ".join(f"{f}:{','.join(str(n) for n in ns)}"
                     for f, ns in sorted(use["locs"].items()))
    print(f"  used at      {locs}")
    pins = ", ".join(sorted(use["pins"]))
    note = ""
    if any(not SHA.match(p) for p in use["pins"]):
        note = "   <- mutable ref, not SHA-pinned"
    elif use["uncommented"]:
        note = f"   <- {use['uncommented']} pin(s) have no # vX.Y.Z comment"
    elif use["commented"]:
        note = f"   ({', '.join(sorted(use['commented']))})"
    print(f"  current pin  {pins}{note}")
    for problem in check_comment_pins(repo, use["commented"]):
        print(f"  MISMATCH     {problem}")

    newest, chosen = pick(repo, min_age)
    if not newest:
        print("  latest       no stable semver release or tag found - check the repo by hand")
        return False
    gate = f"{min_age:g}h gate"
    fresh = newest["age"] < min_age
    print(f"  newest       {newest['tag']}  (commit {newest['commit']},"
          f" released {newest['published'] or 'n/a - tag only'})")
    verdict = "PASS" if not fresh else f"FAIL - only {newest['age']:.0f}h old"
    print(f"  {gate:<12} {verdict}")
    if not chosen:
        print(f"  pin as       nothing in the last {MAX_FALLBACK + 1} releases passes the gate - wait")
        return fresh
    if fresh:
        print(f"  use instead  {chosen['tag']}  ({chosen['age']:.0f}h old) - newest release that passes")

    # Current version comes from the tag pin, or from the comment beside a
    # SHA pin. A SHA with no comment is opaque - that is the cost of
    # omitting it, and the audit says so rather than guessing.
    readable = [p for p in use["pins"] if not SHA.match(p)] + sorted(use["commented"])
    majors = [m for m in (pin_major(p) for p in readable) if m is not None]
    exact = [semver(p) for p in readable if semver(p)]
    target = semver(chosen["tag"])

    if not majors:
        print("  majors       unknown - no readable version on the current pin;"
              " add a # vX.Y.Z comment")
    elif exact and max(exact) >= target:
        print("  status       already on (or past) the newest release that passes the gate")
    elif target[0] > min(majors):
        crossed = range(min(majors) + 1, target[0] + 1)
        print(f"  majors       crosses v{', v'.join(str(c) for c in crossed)}"
              f" - read the release notes for EACH, not just v{target[0]}")
    else:
        print("  majors       none - minor/patch bump only")

    report_inputs(repo, use, chosen["sha"])
    print(f"  pin as       {repo}@{chosen['sha']} # {chosen['tag']}")
    return fresh


def cmd_check(args):
    usages = find_usages(args.paths)
    if not usages:
        print("No third-party actions found.")
        return 0

    fresh = failed = False
    for repo, use in sorted(usages.items()):
        print(f"\n{repo}")
        try:
            fresh |= check_one(repo, use, args.min_age_hours)
        except RuntimeError as e:
            # One unreachable repo (deleted, private, renamed) must not hide the rest.
            print(f"  ERROR        {e}")
            failed = True

    if fresh:
        print(f"\nSome newest releases are under {args.min_age_hours:g}h old; the `pin as` "
              "lines already point at the newest release that passes.")
    return 1 if failed else 0


def cmd_resolve(args):
    sha, date = resolve(args.repo, args.tag)
    print(f"{args.repo}@{sha} # {args.tag}")
    print(f"commit {date} ({hours_since(date):.0f}h ago)")
    return 0


def cmd_inputs(args):
    repo, sub, _ = split_uses(args.repo)
    kind, spec = action_spec(repo, sub, args.ref)
    declared, required = declared_inputs(kind, spec)
    print(f"inputs at {args.repo}@{args.ref}:")
    for i in sorted(declared):
        print(f"  {i}{'  (required)' if i in required else ''}")
    for r in transitive(kind, spec):
        print(f"unpinned dependency: {r}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="audit every action used in the given paths")
    c.add_argument("paths", nargs="*", default=[".github/workflows"])
    c.add_argument("--min-age-hours", type=float, default=72)
    c.set_defaults(func=cmd_check)

    r = sub.add_parser("resolve", help="tag -> commit SHA, with age")
    r.add_argument("repo")
    r.add_argument("tag")
    r.set_defaults(func=cmd_resolve)

    i = sub.add_parser("inputs", help="inputs declared by an action or reusable workflow at a ref")
    i.add_argument("repo", help="OWNER/REPO, OWNER/REPO/SUBDIR or OWNER/REPO/.github/workflows/X.yml")
    i.add_argument("ref")
    i.set_defaults(func=cmd_inputs)

    args = ap.parse_args(argv)
    if getattr(args, "paths", None) == []:
        args.paths = [".github/workflows"]
    try:
        return args.func(args)
    except GhUnavailable as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:  # resolve / inputs on a missing repo, tag or file
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
