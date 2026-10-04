# Ecosystem reference

Per ecosystem: where the immutable pin lives, how to install without re-resolving, how to
audit, and how to make the tool enforce the release-age gate itself. Version numbers are the
first release with the feature. Check the installed tool version (`npm -v`, `uv --version` …)
before relying on a setting, and treat anything marked *upcoming* as unavailable until the
tool says otherwise.

Rules of thumb that hold everywhere:

- Update through the package manager. Never hand-edit a lockfile.
- Commit the lockfile for applications. Published libraries keep ranges in their manifest.
- Pin the package manager's own version too (`packageManager` in `package.json`,
  `toolchain` in `go.mod`, `rust-toolchain.toml`, the Gradle wrapper, a `.tool-versions` or
  mise file), or different contributors will produce different lockfiles.
- CI installs from the lockfile in a mode that fails when the lockfile is out of date.
- Most release-age settings need a publication timestamp from the registry. Private
  registries and mirrors don't always provide one, so check what the tool does without it.

## JavaScript / TypeScript

| | npm | pnpm | Yarn (Berry, v2+) | Bun |
|---|---|---|---|---|
| Lockfile (integrity) | `package-lock.json` (`integrity` sha512) | `pnpm-lock.yaml` | `yarn.lock` (`checksum`) | `bun.lock` |
| Locked install | `npm ci` | `pnpm install --frozen-lockfile` | `yarn install --immutable` | `bun install --frozen-lockfile` |
| Outdated | `npm outdated` | `pnpm outdated` | `yarn upgrade-interactive` | `bun outdated` |
| Audit | `npm audit`, `npm audit signatures` | `pnpm audit` | `yarn npm audit` | `bun audit` |
| Why is X here | `npm explain X` | `pnpm why X` | `yarn why X` | `bun why X` |
| Release-age gate | `min-release-age=3` in `.npmrc`, in **days** (npm 11.10) | `minimumReleaseAge: 4320` in `pnpm-workspace.yaml`, in **minutes** (pnpm 10.16; default 1440 from pnpm 11); bypass list `minimumReleaseAgeExclude` | `npmMinimalAgeGate: "3d"` in `.yarnrc.yml` (4.10; duration strings from 4.11, bare numbers are minutes; default `1d` from 4.15); bypass list `npmPreapprovedPackages` | `[install] minimumReleaseAge = 259200` in `bunfig.toml`, in **seconds** (Bun 1.3); bypass list `minimumReleaseAgeExcludes` |
| Install scripts | `ignore-scripts=true` in `.npmrc` | v10+ runs dependency build scripts only for packages listed in `onlyBuiltDependencies` | `enableScripts: false` | runs scripts only for `trustedDependencies` |

Notes:

- The units differ between tools (days, minutes, a duration string, seconds). Convert 72 hours
  correctly for each one.
- npm's older `before=<date>` setting is absolute and wins over `min-release-age` if both are
  set in the same config source.
- `npm audit signatures` checks registry signatures and, where packages publish them,
  provenance attestations. A package that used to ship provenance and suddenly doesn't is a
  red flag. pnpm's `trustPolicy: no-downgrade` (10.21) refuses that downgrade.
- `overrides` (npm, Bun), `pnpm.overrides` and `resolutions` (Yarn) force a transitive version.
  Treat them as a last resort with a comment, and remove them when the parent catches up.
- Lifecycle scripts (`preinstall`/`postinstall`) are the usual way a malicious package
  executes. Disabling them by default and allow-listing the few that need them is the strongest
  single control in this ecosystem.

## Python

| | pip + requirements | uv | Poetry |
|---|---|---|---|
| Pin with hashes | `pip-compile --generate-hashes` or `uv pip compile --generate-hashes`, then `pip install --require-hashes -r requirements.txt` | `uv.lock` (hashes included) | `poetry.lock` (hashes included) |
| Locked install | `pip install --require-hashes --no-deps -r …` | `uv sync --locked` (fails if out of date) or `--frozen` (doesn't check) | `poetry sync` (Poetry 2), or `poetry install` after `poetry check --lock` |
| Outdated | `pip list --outdated` | `uv tree --outdated`, `uv lock --upgrade-package X` | `poetry show --outdated` |
| Audit | `pip-audit -r requirements.txt` | `uv export --format requirements-txt \| pip-audit -r /dev/stdin`, or `pip-audit` in the env | `pip-audit` in the env |
| Release-age gate | `--uploaded-prior-to` (pip 26.0, absolute ISO 8601 timestamp; pip 26.1 also accepts `P3D`) | `exclude-newer = "3 days"` in `[tool.uv]` or `uv.toml` (relative durations from uv 0.9.17; also RFC 3339 or `P3D`); per package `exclude-newer-package = { pkg = false }` | none native: resolve with uv or pip and the gate, or use the bot's cooldown |

Notes:

- With `--require-hashes`, every package needs every hash for every file you might install:
  all wheels for every platform you deploy on, plus the sdist. A hash list generated on one
  OS can fail on another.
- `--only-binary :all:` refuses sdists. Building an sdist runs arbitrary code from the
  package, so this closes the main install-time execution path, at the cost of failing for
  packages that ship no wheel.
- `pylock.toml` (PEP 751) is the standard lockfile format. `pip lock` (pip 25.1+) and
  `uv export --format pylock.toml` write it.
- Hash-pinning a single tool that CI installs (a `requirements-ci.txt` with `--hash` lines)
  is cheap and worth doing even in repos that don't otherwise lock.
- PyPI serves PEP 740 attestations, but pip doesn't verify them at install time yet. Use
  `pypi-attestations` to check one by hand if provenance matters.
- With a relative `exclude-newer`, recent uv records the duration in `uv.lock`
  (`exclude-newer-span = "P3D"`), so the cut-off moves each time you re-lock. What a locked
  install reproduces is the set of pinned versions in the lockfile, not the gate.

## Go

- `go.sum` holds the hashes. The checksum database (`GOSUMDB`, `sum.golang.org` by default)
  catches a module version that changed after first publication. Keep it on, and set
  `GONOSUMDB`/`GOPRIVATE` only for genuinely private module paths.
- Check: `go mod verify`. In CI, `-mod=readonly` (the default for most commands) fails
  rather than editing `go.mod`.
- Outdated: `go list -m -u all`. Update one module: `go get example.com/mod@vX.Y.Z`, then
  `go mod tidy`. Why: `go mod why -m example.com/mod`.
- Audit: `govulncheck ./...` reports only vulnerabilities in code paths you actually call, so
  it is the most precise of these tools. Use its reachability result in the call-site verdict.
- Minimal version selection means `go get` only moves what you ask it to, plus what that
  requires.
- Release-age gate: none native (a `GOCOOLDOWN` proposal is on hold). Check the module
  version's time with `go list -m -json example.com/mod@vX.Y.Z` (the `Time` field), or use the
  bot's cooldown.
- Major versions v2+ are different import paths (`/v2`). Upgrading is a code change, not a
  version bump.

## Rust

- `Cargo.lock` holds checksums. Commit it. Cargo's guidance now recommends this for
  libraries too.
- Locked build: `cargo build --locked` (fails if the lockfile would change). `--frozen` also
  forbids network access.
- Outdated: `cargo update --dry-run --verbose`, or `cargo outdated` (a plugin). Update one:
  `cargo update -p crate --precise X.Y.Z`. Why: `cargo tree -i crate`.
- Audit: `cargo audit` (RustSec), and `cargo deny check` for advisories, licences, bans and
  sources. `cargo vet` records human audits of crates.
- Release-age gate: `[registry] global-min-publish-age = "3 days"` in `.cargo/config.toml`,
  *upcoming* in stable Cargo 1.100 (due 2026-11-12; nightly before that). It doesn't apply
  to `cargo install`.

## Ruby

- `Gemfile.lock`. Bundler 2.6+ can record a `CHECKSUMS` section: `bundle lock --add-checksums`,
  or `bundle config lockfile_checksums true`. Bundler 4 adds it to new lockfiles by default.
  Existing lockfiles still need the command.
- Locked install: `bundle config set frozen true` (or `BUNDLE_FROZEN=true`), then
  `bundle install`.
- Outdated: `bundle outdated`. Update one: `bundle update --conservative gem`.
- Audit: `bundle-audit check --update`.
- Release-age gate: `bundle config set cooldown 3` (whole days; Bundler 4.0.13), or
  `--cooldown 3`, or per source `source "https://rubygems.org", cooldown: 3`.

## PHP

- `composer.lock`. Locked install: `composer install` (installs exactly what is locked). In CI
  add `composer validate --strict` to catch a lockfile out of sync with `composer.json`.
- Outdated: `composer outdated --direct`. Update one: `composer update vendor/pkg --with-dependencies`.
- Audit: `composer audit`. Composer 2.9+ blocks `update`/`require` from picking versions with
  known advisories (`audit.block-insecure`, default on; from 2.10 configured as
  `config.policy.advisories.block`). It doesn't block installing an already-locked version.
- Release-age gate: `config.policy.cooldown.period` (e.g. `"3 days"`), *upcoming* in
  Composer 2.11.

## Java / JVM

**Gradle**

- Dependency verification: `./gradlew --write-verification-metadata sha256 help` writes
  `gradle/verification-metadata.xml`, and builds then fail on any artifact whose checksum
  doesn't match. Add `pgp` for signature checks where publishers sign.
- Locking: `dependencyLocking { lockAllConfigurations() }`, then
  `./gradlew dependencies --write-locks`. Version catalogs (`gradle/libs.versions.toml`) give
  one place to read versions from, but they don't lock transitive ones.
- Wrapper: set `distributionSha256Sum` in `gradle/wrapper/gradle-wrapper.properties`, and
  validate `gradle-wrapper.jar` in CI with `gradle/actions/wrapper-validation` (the old
  `gradle/wrapper-validation-action` is archived).
- Why: `./gradlew dependencyInsight --dependency name`.

**Maven**

- There is no lockfile. Pin exact versions (no ranges, no `LATEST`/`RELEASE`), pin plugin
  versions, and use `maven-enforcer-plugin` (`requireUpperBoundDeps`, `banDynamicVersions`).
- Outdated: `mvn versions:display-dependency-updates` and `versions:display-plugin-updates`.
- Why: `mvn dependency:tree -Dincludes=group:artifact`.
- Wrapper: `distributionSha256Sum` in `.mvn/wrapper/maven-wrapper.properties`.

For both, audit with OWASP `dependency-check`, `osv-scanner`, or the platform's dependency
graph. Neither tool has a native release-age gate, so use the bot's cooldown.

## .NET / NuGet

- Lockfile: `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` writes
  `packages.lock.json`. Locked restore: `dotnet restore --locked-mode` (or
  `RestoreLockedMode=true` in CI).
- Central versions: `Directory.Packages.props` with `ManagePackageVersionsCentrally`.
- Package source mapping (`<packageSourceMapping>` in `nuget.config`) pins each package ID
  pattern to one feed, which stops dependency confusion between public and private feeds.
- Outdated: `dotnet list package --outdated`. Audit: `dotnet list package --vulnerable
  --include-transitive`. NuGet audit also runs during restore (`NuGetAudit`).
- Release-age gate: *upcoming* in NuGet. Until it ships, use the bot's cooldown.

## Terraform / OpenTofu

- `.terraform.lock.hcl` locks **providers only**, with hashes. Commit it.
- Pre-fill hashes for every platform that runs `init` (CI, developer laptops):
  `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64 -platform=windows_amd64`.
  Without this, installs from a mirror or cache can record only the current platform's
  `h1:` hash, and `init` then fails elsewhere.
- Upgrade providers with `terraform init -upgrade` after changing the constraint in
  `required_providers`.
- **Modules are not locked.** Pin registry modules to an exact `version`, and git modules to a
  commit: `source = "git::https://example.com/org/mod.git?ref=<40-hex-sha>"` with the version
  in a comment.
- Audit: `trivy config` or `checkov` cover misconfiguration rather than versions. Check
  provider changelogs for every major crossed, because provider majors routinely remove
  arguments, and `terraform plan` is the call-site check.

## Helm

- `Chart.lock` (from `helm dependency update`) records exact dependency versions and a digest.
  `helm dependency build` installs from it.
- OCI charts can be pinned by digest: `oci://registry.example.com/charts/app@sha256:…`.
- Charts from classic repos can be signed: `helm pull --verify` or `helm install --verify`
  with the publisher's key.
- The images a chart deploys are a separate layer, usually set in `values.yaml`. Scan them with
  `scan-images.py --all-yaml`, or render with `helm template` and scan the output.

## pre-commit

- `pre-commit autoupdate --freeze` writes `rev: <sha>  # frozen: vX.Y.Z`, which is the same
  SHA-plus-comment pattern as Actions. Without `--freeze`, `rev:` is a tag that can move.
- Apply the age gate by hand, by reviewing what autoupdate picked, or with the bot's
  `pre-commit` ecosystem cooldown (Dependabot) or Renovate's `pre-commit` manager.
- Hooks with `language: node`/`python` install their own dependencies when they first run, so
  a pinned hook can still pull unpinned packages.

## Cross-ecosystem tools

- `osv-scanner scan -r .` reads most lockfiles above and checks them against OSV.dev. It is
  the quickest single vulnerability pass across a polyglot repo.
- `trivy fs .` and `grype dir:.` do the same, and also cover container images.
- `syft` generates an SBOM if the user wants an inventory to keep.
