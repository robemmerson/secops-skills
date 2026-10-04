# Update bots: Dependabot and Renovate

Read this when a repo has a bot configured, when the user wants one set up, or when you are
reviewing a bot's PR. A bot makes the age gate and the pin format permanent instead of
depending on someone running an audit. It doesn't read release notes against your call sites,
so review its PRs with the same rules as a manual update.

## Dependabot (`.github/dependabot.yml`)

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
    cooldown:
      default-days: 3            # the 72-hour gate
    groups:
      actions: { patterns: ["*"] }

  - package-ecosystem: npm       # also pip, uv, gomod, cargo, bundler, composer, maven,
    directory: /                 # gradle, nuget, docker, docker-compose, helm, terraform,
    schedule: { interval: weekly } # pre-commit, ...
    cooldown:
      default-days: 3
      semver-major-days: 14      # optional: let majors settle longer
    groups:
      minor-and-patch:
        update-types: [minor, patch]
```

- `cooldown` keys: `default-days`, `semver-major-days`, `semver-minor-days`,
  `semver-patch-days`, `include`, `exclude`. Some ecosystems, including docker, github-actions,
  helm and terraform, only honour `default-days`.
- **Cooldown doesn't apply to security updates.** Dependabot opens those as soon as a fix
  exists. Review them against the age gate yourself, and set out the trade-off when the fix is
  very new.
- For SHA-pinned actions and digest-pinned images, Dependabot keeps the pin form and updates
  the `# vX.Y.Z` comment or tag.
- Version updates (this file) and security updates (repository settings) are separate
  switches. Check both.

## Renovate (`renovate.json`, `.github/renovate.json5`)

```json5
{
  $schema: "https://docs.renovatebot.com/renovate-schema.json",
  extends: [
    "config:recommended",
    "helpers:pinGitHubActionDigests",   // uses: owner/repo@<sha> # vX.Y.Z
    ":pinDevDependencies"
  ],
  minimumReleaseAge: "3 days",          // the 72-hour gate
  internalChecksFilter: "strict",       // don't open PRs until the age has passed
  pinDigests: true,                     // container images: tag@sha256 (review the policy first)
  lockFileMaintenance: { enabled: true, schedule: ["before 6am on monday"] },
  packageRules: [
    { matchUpdateTypes: ["major"], minimumReleaseAge: "14 days" }
  ]
}
```

- `minimumReleaseAge` needs a release timestamp from the datasource. Under the default
  `minimumReleaseAgeBehaviour: "timestamp-required"`, an update without a timestamp is never
  considered old enough. That is safe, but it can stall updates from registries that don't
  provide timestamps.
- Without `internalChecksFilter: "strict"`, Renovate can open the PR early and show a pending
  status check until the age passes. Either way works, as long as nobody merges on red.
- `pinDigests: true` changes how images get updated. Only enable it after the image strategy
  discussion in `SKILL.md`.

## Native gate or bot gate?

Use both where you can. The bot's cooldown governs which PRs get opened. A native setting
(`min-release-age`, `minimumReleaseAge`, `exclude-newer`, `cooldown` and so on; see
`ecosystems.md`) also covers what a developer resolves locally, including fresh transitive
dependencies that the bot never looks at individually. Renovate's `minimumReleaseAgeBuffer`
exists to stop the two from fighting when both are set.

## Reviewing a bot PR

1. Read the diff, not just the title. Grouped PRs often hide a major bump among patches.
2. Check the age of each new version, and check for a lockfile with unrelated churn.
3. Read the notes for every major crossed, then do the call-site check from `SKILL.md`.
4. For Actions, run `action-deps.py check` on the PR branch. It also confirms that each new
   SHA matches its comment.
5. CI passing is necessary but not sufficient. Name what CI doesn't exercise (steps gated to
   `main`, deploy jobs, runtime-only code paths).
