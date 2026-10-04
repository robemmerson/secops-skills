# devo

Query and investigate security data in a Devo domain, and triage Devo alerts.

- `skills/devo/SKILL.md`: setup and safety rules, the command synopsis, workflow, the most common
  LINQ traps, triage steps, and how the domain cache is used. Loaded whenever the skill triggers, so
  detail lives in references loaded on demand.
- `skills/devo/scripts/devo.py`: helper with commands `check`, `query`, `schema`, `tables`,
  `alerts`, `alert`, `alert-defs`, `coverage` (is a host logging?), `activity` (everything a user,
  IP or host did), `timeline` (merge an activity sweep into one event list), `teams` (Teams
  conversations, meetings and calls), `lag` (ingestion lag per table), `batch` (many queries from a
  JSON spec), `fields` and `profile` (field profiles), `cache` (the local domain cache) (all
  read-only against Devo) and `comment` (preview by default; posts only with `--confirm`).
- `skills/devo/references/`: generic material only. The Query and Alerts APIs, LINQ syntax and
  functions, the full list of LINQ traps (`linq-traps.md`), command details (`commands.md`), the
  question playbooks (`playbooks.md`), Devo's table catalogue, per-family guides to Devo's standard
  tables (`table-guide/`), the investigation playbook, and Devo's public SecOps detection library.
- `skills/devo/references/hints/`: seeds for Devo's standard parsers. `activity-sources.json` holds
  the sweep recipes (including which fields name the actor and the target, for `timeline`), `event-time.json` the event-time expressions and dedupe ids, and
  `field-roles.json` the curated field roles. The helper validates them against each domain.
- `tests/`: offline unit tests (`python3 -m unittest discover -s plugins/devo/tests`).

## Domain data: fetched on first use, cached locally

Nothing about a particular Devo domain ships with the skill. The first time it needs something it
fetches it from the domain and caches it under `~/.cache/devo-skill/<domain key>/`: the table
list, schemas, field profiles, the event-time expressions verified against real rows, and the
sweep sources that hold up against the live schema. The directory is `0700` and the files `0600`.
The token itself is never written: the directory is named after a hash of it, or after
`DEVO_CACHE_KEY`. Profiles keep data shapes only (types, fill rates, value patterns, and enum
values of categorical fields), never identities.

| Entry | Expires | Refetched early when |
|---|---|---|
| table list | 7 days | a query says a cached table doesn't exist; `tables --live`; `cache refresh tables` |
| schemas, field profiles | 30 days | a query says a cached field doesn't exist; `fields <t> --refresh`; `cache refresh fields [t…]` |
| verified event time | 30 days | the table list changes; `cache refresh event-time` |
| sweep sources | 7 days | the table list or a schema changes; `cache refresh sources` |
| notes, naming templates | never (flagged after 90 days for re-verification) | `cache note rm`, `cache clear --include-notes` |

- `devo.py cache status` shows what is there and how old it is.
- `cache build` fills everything; run it once in the background, since it takes minutes on a large
  domain.
- `cache verify` compares the cache with the live domain and refetches whatever differs.
- `cache clear` drops all the data but keeps the notes.
- `DEVO_CACHE_MAX_AGE_DAYS=N` caps every expiry, and `DEVO_CACHE_DIR` moves the cache.

## Setup

Put the Devo API token in `~/.config/devo/env` (`chmod 600`):

```
DEVO_TOKEN=...
DEVO_REGION=eu            # eu (default), us, ca, apac or us3
DEVO_CACHE_KEY=my-domain  # optional: names the cache, so it survives token rotation
```

The `DEVO_TOKEN`/`DEVO_REGION`/`DEVO_CACHE_KEY` environment variables, or `DEVO_ENV_FILE=<path>`,
take precedence.

## Where it works

- **Claude Code** (primary): needs Python 3.8+ and HTTPS access to `*.devo.com`.
- **Claude Desktop / claude.ai** (zip upload): the scripts run in Claude's code-execution sandbox,
  which must be allowed to reach your region's API hosts (e.g. `apiv2-eu.devo.com` and
  `api-eu.devo.com`). There's no `~/.config/devo/env` there, so the token has to be provided
  another way, and the cache lasts only as long as the sandbox. The reference material is useful
  there on its own.
