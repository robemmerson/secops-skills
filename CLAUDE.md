# secops-skills: working in this repo

Public source of Rob's SecOps skills for Claude, published as a Claude Code plugin marketplace
(`secops-skills`) plus Claude Desktop zips. See README.md for the layout.

- **This repo is public: nothing specific to anyone's environment goes in.** No table
  inventories or volumes, field maps or profiles, account or host naming conventions, collection
  gaps or lag figures, custom alert definition names or status codes, MDR/vendor relationships,
  dated observations, or anything taken from query results. Domain data belongs in the Devo
  skill's local cache (`devo.py cache ...`), which lives on the user's machine. Placeholders use
  `example.com`, documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and names
  like `jsmith` / `HOST01`.
- `plugins/devo/skills/devo/references/hints/` holds generic seeds for Devo's standard parsers
  only; the helper validates them against each domain at runtime.
- **Commits drive versions.** Use Conventional Commits, and scope them to the plugin they
  change: `feat(devo): …` (minor), `fix(devo): …` (patch), `feat(devo)!: …` or a
  `BREAKING CHANGE:` footer (major). Keep one plugin per commit when you can, so each release
  note is accurate. Never edit `version` in `plugin.json` by hand: the Release workflow owns it.
  Never add `version` to `marketplace.json`.
- **Before committing:** `python3 tools/validate.py`, `python3 -m unittest discover -s tools/tests`,
  and each `plugins/*/tests` that exists (the Devo tests include a no-private-data check). Also
  `claude plugin validate .` if the CLI is available.
- **Skills must be location-independent.** Refer to bundled scripts relative to the skill's base
  directory, never to `~/.claude/skills/...`, because plugin installs live in Claude Code's
  plugin cache and Desktop uploads live elsewhere.
- **No secrets or tenant data beyond what a skill needs.** Never commit tokens, `.env` files or
  customer data such as real user names, emails or hostnames from query results.
- **Dependencies:** follow `plugins/dependency-updates/skills/dependency-updates/SKILL.md`: SHA
  pins with a `# vX.Y.Z` comment, a 72-hour minimum age, read the notes for every major crossed,
  and diff inputs against the call sites.
- Don't add AI or assistant attribution to commits, PRs, code comments or skill text.
- The Devo reference material is edited here directly. Keep it generic: if a fact was learned in
  one domain, phrase it as "in some deployments ...; check with `devo.py fields`" or leave it out.
