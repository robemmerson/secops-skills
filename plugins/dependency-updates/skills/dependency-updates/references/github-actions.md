# GitHub Actions: pinning detail and hardening

Read this when the audit needs more than `action-deps.py check`: resolving by hand, policy
enforcement, or hardening findings to report alongside the version bumps.

## Resolving a pin by hand

```bash
# 1. tag -> object; if object.type is "tag" it is an annotated tag, so hop once more
gh api /repos/OWNER/REPO/git/ref/tags/vX.Y.Z --jq '.object | .type + " " + .sha'
gh api /repos/OWNER/REPO/git/tags/<tag-object-sha> --jq '.object.sha'
# 2. commit date, for the age gate (compare with the release's published_at)
gh api /repos/OWNER/REPO/commits/<commit-sha> --jq '.commit.committer.date'
gh api /repos/OWNER/REPO/releases --paginate --jq '.[] | select(.tag_name=="vX.Y.Z") | .published_at'
# 3. is a pinned SHA really on the upstream tag (not a fork-only commit)?
gh api /repos/OWNER/REPO/compare/vX.Y.Z...<sha> --jq .status   # "identical" is what you want
```

`git ls-remote --tags https://github.com/OWNER/REPO 'vX.Y.Z*'` works without the API: the
`^{}` line is the peeled commit of an annotated tag.

## What a SHA pin does and doesn't freeze

A full commit SHA freezes the action's own code. It doesn't freeze:

- **Actions a composite action calls by tag.** Check its `action.yml` `runs.steps[].uses`.
- **Container actions** whose `runs.image` is `docker://name:tag`, or a `Dockerfile` whose
  `FROM` floats. The image is fetched at run time.
- **Whatever the action downloads at run time**: tool installers such as `setup-*` actions
  fetch a toolchain version you ask for, and some actions `npm install` or `curl` binaries
  when they start.
- **Reusable workflows' own `uses:` lines**: pinning `owner/repo/.github/workflows/x.yml@sha`
  freezes that file, including any tags it uses.

`action-deps.py check` reports the first, second and fourth as `unpinned`. For anything
security-critical with unpinned internals, say so in the report. Forking or vendoring the
action is the user's call, not a default.

Immutable releases (where a repository enables them) stop a published release's tag and
assets from being changed. That helps, but a SHA pin is still the reference the runner
actually checks out, and it works regardless of the publisher's settings. Keep pinning SHAs.

## Enforcing the policy

- **Repository, organisation or enterprise Actions settings** can restrict which actions
  are allowed and can require that every action is pinned to a full-length commit SHA. A
  workflow that uses a tag then fails before it runs. Recommend it once a repo is fully
  pinned, and leave turning it on to the user, since it affects every workflow.
- **Dependabot** (`package-ecosystem: github-actions`) and **Renovate**
  (`helpers:pinGitHubActionDigests`) keep `@<sha> # vX.Y.Z` pins current. See
  `automation.md`.
- **Tools that convert tags to SHAs**: `pinact run`, `ratchet pin`, or Renovate's preset.
  They save typing, but review their output, because they resolve whatever the tag points at
  *now*, with no age gate.
- **Static analysis**: `zizmor .github/workflows` finds unpinned uses, template injection,
  excessive permissions, `pull_request_target` misuse and credential persistence. It is worth
  running whenever you touch workflows.

## Hardening findings to report

Report these separately from version bumps, and only fix them when the user asks. Each
changes behaviour.

| Finding | Why it matters | Usual fix |
|---|---|---|
| No top-level `permissions:` | The `GITHUB_TOKEN` gets the repo or org default, which may be read-write | `permissions: {}` or `contents: read` at the top, with grants per job |
| `actions/checkout` without `persist-credentials: false` | The token stays readable on disk for every later step, including third-party ones (in `.git/config` before v6, under `$RUNNER_TEMP` from v6) | Set it to `false` unless a later step pushes |
| `pull_request_target` or `workflow_run` that checks out the PR head | Runs untrusted code with secrets and a write token | Split the jobs, or don't check out PR code in a privileged context |
| `${{ github.event.* }}`, `${{ github.head_ref }}` or `${{ inputs.* }}` inside `run:` | Script injection through PR titles, branch names and similar fields | Pass the value through `env:` and quote `"$VAR"` |
| Secrets passed to third-party actions that don't need them | Widens what a compromised action can steal | Pass secrets only to the step that uses them |
| Self-hosted runners on public repos | Fork PRs can run code on your hardware | Use GitHub-hosted runners for untrusted triggers |
| Long-lived cloud keys in secrets | A leak lasts until someone rotates the key | OIDC (`id-token: write`) with a short-lived, narrowly scoped role |

Network egress monitoring or blocking (for example StepSecurity `harden-runner`) is a further
layer for sensitive pipelines. Mention it, but don't add it unasked.
