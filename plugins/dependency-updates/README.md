# dependency-updates

Audit, update and harden a project's third-party dependencies under the same rules everywhere:
pin to something immutable with a readable version beside it, adopt only releases at least
72 hours old, read the notes for every major version crossed, and check each change against how
the project actually uses it.

- **GitHub Actions and reusable workflows**: commit-SHA pins with a `# vX.Y.Z` comment. A
  bundled script resolves tags (including annotated tags) to commits, picks the newest release
  that passes the age gate, checks existing pins against their comments, diffs inputs against
  each call site, and flags unpinned actions or images that an action pulls in itself.
- **Container images**: an inventory of every image reference (Dockerfile `FROM`, compose,
  optionally any YAML `image:`) by how tightly it is pinned, plus guidance on index digests,
  `tag@digest` pins and deployments that rely on floating tags.
- **Language packages**: lockfile, integrity, locked-install, audit and native cooldown settings
  for npm, pnpm, Yarn, Bun, pip, uv, Poetry, Go, Cargo, Bundler, Composer, Maven, Gradle, NuGet,
  Terraform, Helm and pre-commit, plus Dependabot and Renovate configuration.

Files:

- `skills/dependency-updates/SKILL.md`: the rules and the workflow.
- `skills/dependency-updates/references/`: per-ecosystem detail (`ecosystems.md`), GitHub
  Actions hardening (`github-actions.md`) and update-bot configuration (`automation.md`).
- `skills/dependency-updates/scripts/action-deps.py`: `check`, `resolve`, `inputs`. Needs an
  authenticated `gh` CLI and PyYAML.
- `skills/dependency-updates/scripts/scan-images.py`: image pin inventory (standard library only).
- `tests/`: offline tests for both scripts, plus a check that the eval suite is in sync with its
  generator and that every fixture builds (`python3 -m unittest discover -s plugins/dependency-updates/tests`).
- `evals/`: behaviour evals for `claude plugin eval`, one case per ecosystem (below).

## Evals

The language-package rules live in `SKILL.md` rather than a script, so they are tested as
plugin evals. Each case in `evals/<ecosystem>/` scaffolds a small project (manifest, lockfile,
code, and a Dependabot or Renovate config) with two fictional dependencies, and asks Claude to
update it:

- `fastqueue`'s newest release is about 20 hours old: the update must stop at the previous
  release (72-hour gate).
- `datekit` 3.0.0 renames an API the project calls: the agent must find the call site and adapt
  it or set out the options.

Graders check the manifest, that the lockfile was not hand-edited and which tool regenerates it,
the age gate, the call-site check, that hashes, integrity values, digests or SHA pins survive, and
that the update bot's config was noticed and left alone. `npm-advisory-fresh-fix` covers the case
where the only security fix is younger than 72 hours (set out the trade-off). The sandbox has no
registry access, so each fixture carries a `REGISTRY_SNAPSHOT.md` (publish times are computed when
the scaffold runs), and the lockfile graders accept the exact command the agent proposes when the
tool cannot reach the registry. Maven, pre-commit, GitHub Actions and container images have no
lockfile, so their pins are graded instead.

Run from the repository root (the scaffolds and Bash need explicit grants; Bash runs in Claude
Code's sandbox, which needs `bubblewrap` and `socat` on Linux):

```sh
claude plugin eval plugins/dependency-updates --scaffold --allow-tools Edit Write Bash
claude plugin eval plugins/dependency-updates --case npm --runs 1 --ablation none --scaffold \
  --allow-tools Edit Write Bash            # one case, one run, no baseline: a cheap smoke test
```

A full run is 22 cases × 3 runs, with and without the plugin, so it takes a while and uses model
quota. Results go to `evals/results/` (ignored by git). The cases are generated: edit the
`ECOSYSTEMS` table in `evals/build.py` and run `python3 plugins/dependency-updates/evals/build.py`;
the unit tests fail if the generated files are out of date.

For unattended updates, pair the skill with Dependabot or Renovate (see
`references/automation.md`) rather than running an agent with write access on a schedule.
