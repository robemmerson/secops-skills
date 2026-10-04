# secops-skills

Rob Emmerson's security operations (SecOps) skills for Claude. This repo is the source of truth for them. It is a
**Claude Code plugin marketplace** (one plugin per skill), and every release also attaches the
skills as zips for **Claude Desktop / claude.ai**.

| Plugin | Skill | What it does |
|---|---|---|
| [`devo`](plugins/devo/) | `devo:devo` | Query Devo SIEM data with LINQ, investigate entities, triage Devo alerts (read-only, plus approved alert comments) |
| [`dependency-updates`](plugins/dependency-updates/) | `dependency-updates:dependency-updates` | Audit, update and harden dependencies: SHA-pinned GitHub Actions, container images and language packages (72-hour age gate, call-site checks) |

## Install

### Claude Code

```sh
claude plugin marketplace add robemmerson/secops-skills
claude plugin install devo@secops-skills
claude plugin install dependency-updates@secops-skills
```

(or `/plugin marketplace add robemmerson/secops-skills` and `/plugin install …` inside a session).

Update later with `claude plugin marketplace update secops-skills` and then
`claude plugin update <plugin>@secops-skills`. Claude Code sees an update when the plugin's
`version` changes, which the release workflow does automatically.

If you previously copied a skill into `~/.claude/skills/<name>`, remove that copy, or both will
load.

### Claude Desktop / claude.ai

Download `<skill>-vX.Y.Z.zip` from the [latest releases](../../releases) and upload it under
**Settings > Capabilities > Skills**. Each zip contains one folder with `SKILL.md` at its top.
Skills whose scripts call external services (e.g. Devo) also need the code-execution sandbox to
be allowed to reach them; see each plugin's README.

## Repository layout

```
.claude-plugin/marketplace.json     marketplace: one entry per plugin (no versions here)
plugins/<plugin>/
  .claude-plugin/plugin.json        name, version (single source of truth), description
  skills/<skill>/SKILL.md           the skill that ships (plus scripts/, references/)
  tests/                            offline tests, not shipped
  README.md
tools/
  validate.py                       manifests, frontmatter limits, no caches/.env in skills
  release.py                        next version from Conventional Commits, zips, release notes
.github/workflows/
  ci.yml                            validate, unit tests, zip dry-run, gitleaks
  release.yml                       auto-version, tag, GitHub release with zips
.github/dependabot.yml              weekly SHA-pinned Actions bumps, 3-day cooldown
```

## Versioning and releases (automatic)

Each plugin is versioned on its own with semver and tagged `<plugin>-vX.Y.Z`. On every push
to `main` that touches `plugins/`, the Release workflow reads the
[Conventional Commits](https://www.conventionalcommits.org/) that changed each plugin since
its last tag:

| Commit | Bump |
|---|---|
| `feat: …` / `feat(devo): …` | minor |
| `fix: …`, `docs: …`, `chore: …`, anything else | patch |
| `feat!: …` or a `BREAKING CHANGE:` footer | major |

It writes the new version into `plugin.json`, commits `chore(release): … [skip ci]`, tags, and
publishes a GitHub release with the Desktop zip(s) attached. Plugins with no changes are left
alone. To preview: `python3 tools/release.py plan`.

## Dependencies

- **Dependabot** (weekly) keeps the workflows' GitHub Actions SHA-pinned with a `# vX.Y.Z`
  comment, with a 3-day cooldown matching the skill's 72-hour age rule. Nothing else in the repo
  has third-party dependencies to update.
- The skills themselves avoid third-party packages (the Devo helper is standard-library only).

## Adding a skill

1. `plugins/<name>/.claude-plugin/plugin.json` with `name`, `version` (`1.0.0`),
   `description`, `author`.
2. `plugins/<name>/skills/<name>/SKILL.md` with `name` (lowercase, hyphens, ≤ 64 chars) and
   `description` (≤ 1024 chars) frontmatter, plus any `scripts/` and `references/`.
3. `plugins/<name>/README.md`, and `tests/` if it has code.
4. An entry in `.claude-plugin/marketplace.json` (`name`, `source: ./plugins/<name>`,
   `description`, no `version`).
5. `python3 tools/validate.py`, then commit `feat(<name>): add <name> skill`. The first push
   releases it at 1.0.0.

Scripts inside a skill must not assume where it's installed: refer to them relative to the
skill's base directory, which Claude sees when the skill loads.

## Security

- No credentials in this repo. Skills read tokens from the environment or user config files
  (e.g. `~/.config/devo/env`). `gitleaks` runs on every push and PR, and `validate.py` rejects
  `.env`, key and cache files inside skills.
- Workflows use least-privilege `permissions`, and every action is pinned to a commit SHA.
- No environment data either: skills ship generic knowledge only. The Devo skill learns each
  domain at runtime and caches what it learns on the user's machine (see
  [`plugins/devo`](plugins/devo/)).
