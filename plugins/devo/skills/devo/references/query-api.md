# Devo Query API reference

`scripts/devo.py query` wraps this API and already handles every trap below. Read this file
when you need something the helper doesn't expose, want to understand an error, or have to
call the API directly (e.g. with curl).

Facts marked **[verified]** were confirmed against a real Devo domain; the rest comes from the
Devo docs.

## Contents
1. Endpoints and authentication
2. POST /search/query — request body
3. Time ranges (`from` / `to`)
4. Response modes
5. Errors
6. Other endpoints
7. Raw curl example

## 1. Endpoints and authentication

| Region | Query API base | Alerts API base |
|---|---|---|
| EU | `https://apiv2-eu.devo.com/search` | `https://api-eu.devo.com/alerts/v1` |
| US | `https://apiv2-us.devo.com/search` | `https://api-us.devo.com/alerts/v1` |
| CA | `https://apiv2-ca.devo.com/search` | `https://api-ca.devo.com/alerts/v1` |
| APAC | `https://api-apac.devo.com/search` | `https://api-apac.devo.com/alerts/v1` |
| US3 | `https://api-us3.devo.com/search` | `https://api-us3.devo.com/alerts/v1` |

- Header `Authorization: Bearer <token>`. Tokens are created in Devo under
  Administration → Credentials → Tokens and can be restricted to target tables (`*` = any
  characters within one name level, `**` = across levels, e.g. `firewall.fortinet.**`) and
  given an expiry date. A token only sees its target tables.
- **[verified]** Send a `User-Agent` header. Cloudflare blocks Python's default
  `Python-urllib/x` UA with `403` and body `error code: 1010`.
- **[verified]** A token from another region gets `403 {"code":5,"msg":"Token invalid or expired"}`.
  No auth header: `401`.
- Swagger UI: `<base>/swagger/`.

## 2. POST /search/query — request body

| Field | Notes |
|---|---|
| `query` | LINQ text (or `queryId` of a saved query). |
| `from` | **Required.** Start of range, see §3. |
| `to` | End of range. **Omitting it starts a continuous (never-ending) live query**, so always send it. |
| `limit` | Max rows returned. Always set one (the helper defaults to 200). |
| `offset` / `skip` | Skip the first N rows (pagination). |
| `mode.type` | Response format, see §4. Default `json`. |
| `ipAsString` | `true` → IPs as dotted strings; otherwise IPv4 comes back as integers. |
| `timeUnit` | `SECONDS` (default) or `MILLISECONDS` for numeric `from`/`to`. |
| `dateFormat` | For non-JSON modes: `default`/`sql` (`yyyy-MM-dd HH:mm:ss.SSS`) or `iso`. |
| `timeZone` | For non-JSON modes, e.g. `GMT+1`. Output timestamps are otherwise UTC. |
| `progressInfo` | `true` adds progress entries (`p`) to the stream. |
| `keepAlive` | Keep-alive settings for CSV/TSV/XLS live queries. |
| `destination` | Forward results elsewhere (S3, etc.). Not used by this skill. |

Query priority (Minimum/Normal/Urgent) is a per-role UI setting, not an API field.

## 3. Time ranges (`from` / `to`)

All **[verified]**:

| Form | Example | Notes |
|---|---|---|
| Epoch seconds | `1790607781` | Default unit. |
| Epoch ms + `"timeUnit":"MILLISECONDS"` | `1790000000000` | **Trap:** ms *without* `timeUnit` is read as seconds (far future), so the query hangs for minutes and returns 0 rows. |
| Relative date language | `"now() - 1h"`, `"now()-1h"`, `"now() @ 1d"`, `"(now() - 1d) @ 1d"` | Preferred by Devo. `@ 1d` snaps to the start of the day (UTC). Operators: `-`/`+` offset, `@` snap (1m/1h/1d/1w/1W/1M/1y), `^` replace part, `>>`/`<<` shift. |
| Deprecated words | `"1h"`, `"1d"`, `"today"`, `"now"` | Still work. In `from`, `"1d"` means 1 day ago. **`"1s"` means the last one second**, not "since 1s". |
| ISO strings | `"2026-09-28T12:00:00Z"` | **Rejected**: `400 ["406 : Date from not valid format"]`. Convert to epoch first (the helper does). |

Other range errors: `405` missing `from`; `408` `from` later than `to`.

Rules of thumb for speed: an hour of a busy source table usually returns quickly, while
long ranges of `siem.logtrust.collector.counter` and union tables such as `auth.all` can take
minutes even for short windows. Start narrow and widen.

## 4. Response modes

All **[verified]** with `select *` on a small table:

| `mode.type` | Shape | Use |
|---|---|---|
| `json` | `{"msg","timestamp","cid","status":0,"object":[{col:val,...}]}` | Readable, repeats keys. |
| `json/compact` | `{"object":{"m":{col:{type,index}},"metadata":[...],"d":[[...],...]}}` | One document, arrays of values. |
| `json/simple` | One `{col:val}` object per line | Streamable. |
| `json/simple/compact` | First line `{"m":{...},"metadata":[{"name","type"}]}`, then one `{"d":[...]}` per row | **What the helper uses**: streamable and compact. |
| `csv` / `tsv` | Header + rows, timestamps `yyyy-MM-dd HH:mm:ss.SSS` UTC | Spreadsheets. |
| `msgpack`, `xls` | Binary | Not used. |

In JSON modes timestamps are epoch **milliseconds**. Long queries send whitespace padding
(keep-alive) before rows arrive, so skip blank lines. `ipAsString` affects `ip4` columns.

## 5. Errors

LINQ problems come back as HTTP **500** with the reason in `object[1]` **[verified]**:

```json
{"msg":"Error Launching Query","status":500,
 "object":["Error Launching Query","Unknown table `no.such.table`","2086000","MISSING_RESOURCE","MANUAL"]}
```

| Message | Code | Meaning / fix |
|---|---|---|
| ``Unknown table `x` `` | 2086000 MISSING_RESOURCE | Table doesn't exist in the domain (check `devo.py tables`). |
| ``Unknown identifier `f` `` | 1101001 QUERY_PARSING_ERROR | No such field: `devo.py schema <table>`. |
| ``No function named `fn` `` | 1101002 QUERY_PARSING_ERROR | See linq-functions.md. |
| `Unable to Start Task: Query parsing error` | — | Syntax error; Devo gives **no position**. Simplify and rebuild the query clause by clause. |

Silent failures **[verified]**:
- Comparing a field to a literal of the wrong type (`where events = "abc"` on an int)
  returns **200 with 0 rows**, not an error.
- `GET /table/{name}` answers `403 "Access not allowed for table"` for tables that simply
  don't exist, and `404` for some `my.app.*` tables that are queryable.

Parameter errors are HTTP 400 `{"error":"Bad parameters","object":["<code> : <text>"]}`
(405/406/408 above). A task-status page lists further codes for async jobs
(`task-statuses-and-error-codes`); they rarely matter for synchronous queries.

## 6. Other endpoints

- `GET /search/table/{table}` → `{"object":[{"fieldName","type"}]}`: the table schema
  (`devo.py schema`, which falls back to a 1-row query when this endpoint refuses).
- Jobs (`GET /search/job/{id}`, `/jobs`, `/job/stop|start|remove/{id}`) manage queries
  sent with a `destination`; not needed for normal synchronous use.
- Data types seen: `timestamp`, `str`, `int4`, `int8`, `float8`, `bool`, `ip4`, `ip6`,
  plus composite types from functions.

## 7. Raw curl example

```sh
curl -sS -X POST 'https://apiv2-us.devo.com/search/query' \
  -H "Authorization: Bearer $DEVO_TOKEN" -H 'Content-Type: application/json' \
  -H 'User-Agent: devo-skill/1.0' \
  -d '{"query":"from auth.all where result = \"FAIL\" group by user select count() as n",
       "from":"now() - 1h","to":"now()","limit":50,"ipAsString":true,
       "mode":{"type":"json/simple/compact"}}'
```

Don't paste the token into commands you show the user. Rely on the environment variable
or the helper.
