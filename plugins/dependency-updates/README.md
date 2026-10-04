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
- `tests/`: offline tests for both scripts (`python3 -m unittest discover -s plugins/dependency-updates/tests`).

For unattended updates, pair the skill with Dependabot or Renovate (see
`references/automation.md`) rather than running an agent with write access on a schedule.
