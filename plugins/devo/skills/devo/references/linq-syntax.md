# LINQ syntax reference (Devo Query API)

LINQ as sent in the `query` field of a Query API request. Function-by-function details
(arguments, return types) are in [linq-functions.md](linq-functions.md); this file covers
query structure, operators, grouping, time, performance and worked patterns.

Items marked **[verified]** were confirmed against the live API. Everything else comes from the
Devo docs. Where the docs are unclear, this file says so.

## Contents

1. [Query skeleton and clause order](#1-query-skeleton-and-clause-order)
2. [Table names, fields, literals, comments](#2-table-names-fields-literals-comments)
3. [Filtering (`where`)](#3-filtering-where)
4. [Creating fields (`select ... as`)](#4-creating-fields-select--as)
5. [Grouping and aggregation](#5-grouping-and-aggregation)
6. [Time: API range vs `eventdate`](#6-time-api-range-vs-eventdate)
7. [Subqueries](#7-subqueries)
8. [Union tables, joins, lookups, free text](#8-union-tables-joins-lookups-free-text)
9. [Errors and silent failures](#9-errors-and-silent-failures)
10. [Performance checklist](#10-performance-checklist)
11. [API vs search-window differences](#11-api-vs-search-window-differences)
12. [Worked investigation patterns](#12-worked-investigation-patterns)

---

## 1. Query skeleton and clause order

```
from <table>
where <filter1>, <filter2>            // comma = AND; repeatable
select <expr> as <name>, ...          // create fields; repeatable
group every <period> by <f1>, <f2>    // or: group by <f1>, <f2>
every <client period>                 // optional; see section 5
select <aggregation>(<field>) as <name>, ...
where <filter on aggregated fields>   // post-aggregation filter
```

- Clauses are a pipeline: each one works on the output of the one above it. `where` and
  `select` can appear several times, before and after `group`.
- A field created with `select ... as x` can be used by later `where`/`group`/`select` clauses.
  For example, you can compute `mmlatitude(ip) as latitude` and then `group every 30m by latitude`.
- After `group`, only the grouping keys (plus the time bucket, if you used `every`) and the
  aggregations you `select` exist. Use `first`, `last`, `nnfirst`, `nnlast` or `collectdistinct`
  to carry other columns through a group.
- Clause keywords are shown in lower case. One docs example uses `Group`, but always write them
  in lower case.
- **`let`**: not documented in any source. Do not use it.
- **Sorting**: no `order by`/`sort by` clause is documented (`sort()` is an array function).
  Sort the rows on the client side after the API returns them.
- **Row limits**: the Query API request body takes `limit` and `skip`/`offset` parameters.
  One API docs example also puts `limit` inside the LINQ itself:
  `from siem.logtrust.collector.counter select tag limit 1`. Prefer the request parameter.
  Note that `limit` caps the rows returned, not the rows scanned.

## 2. Table names, fields, literals, comments

- **Table names** are dotted: `firewall.all.traffic`, `box.win_nxlog.security`.
- **[verified]** A table name that contains a hyphen must be backtick-quoted:
  ``from `web.iis.access-w3c-all` ``. Quoting it with `"` or `'` is a parse error.
- **Field names** are case-sensitive identifiers. Backtick-quote a name that starts with a digit
  or symbol, or that contains operators or spaces: `` `2my_field` ``, `` `timeTaken>200` ``.
  The docs use backticks for aliases such as ``select timeTaken > 200 as `timeTaken>200` ``.
- **String literals**: most examples use double quotes (`"GET"`). Single quotes also appear
  (`'2024-09-10 07:21:35' < eventdate`, `'siem.logtrust' as x`). Use double quotes by default.
- **Numbers** are unquoted: `statusCode = 404`.
- **IP literals** are unquoted: `clientIpAddress = 203.0.113.21`, and CIDR too:
  `clientIpAddress <- 198.51.100.0/24`. You can also build them with functions: `ip4("...")`,
  `net4("192.0.2.0/24")`, `net6("...")`.
- **Sets**: `x in {a, b, c}` (from the best-practices doc).
- **Comments**: `// comment` to the end of the line.
- **Whitespace/newlines** are not significant. A whole query can be on one line in the JSON
  body.

## 3. Filtering (`where`)

`where` keeps the rows where the boolean expression is true. `where a, b` is the same as
`where a and b`.
Consecutive `where` clauses also AND together.

| Purpose | Operator / function | Case | Notes |
|---|---|---|---|
| Equal | `f = v`, `eq(f, v)` | sensitive | Uses the index. Match the literal's type to the field's type. |
| Equal, ignore case | `eqic(f, "v")` | insensitive | Uses the index. |
| Not equal | `f /= v`, `f != v`, `ne(f, v)` | sensitive | The docs show `/=`; **[verified]** `!=` works too. |
| Compare | `>`, `>=`, `<`, `<=` (`gt`, `ge`, `lt`, `le`) | n/a | Chains work: `a <= eventdate < b`. |
| Substring | `f -> "v"`, `has(f, "v1", "v2", ...)` | sensitive | `has` with several values = any of them. |
| Substring, ignore case | `f ->> "v"`, `weakhas(f, "v")` | insensitive | |
| Token contains | `toktains(f, "v")` | sensitive | Recommended over `->`/`contains` for performance. Optional booleans `toktains(f, "v", left, right)` control partial-token matching (see functions file). |
| Token contains, ignore case | `weaktoktains(f, "v")` | insensitive | The same speed as `toktains`. |
| Value in string / set / net | `"v" <- f`, `` `in`(v1, v2, ..., f) ``, `x in {a, b}` | sensitive | Note the argument order: the needle comes first and the haystack last. |
| In, ignore case | `weakin("v", f)` | insensitive | |
| IP in CIDR | `ip <- 10.0.0.0/8`, `` `in`(ip, 10.0.0.0/8) `` | n/a | |
| Prefix / suffix | `startswith(f, "p")`, `endswith(f, "s")` | sensitive | Uses the index. |
| Regex | `f ~ re("pat")`, `matches(f, re("pat"))` | per regex | **`re()` is required in LINQ.** Expensive, so put it last. |
| Null / empty | `isnull(f)`, `isnotnull(f)`, `isempty(f)` | n/a | For "has a value" use `isnotnull(f)` and `not isempty(f)`. |
| Private / public IP | `isprivate(ip)`, `ispublic(ip)` | n/a | |
| Boolean logic | `and`, `or`, `not` | n/a | Use parentheses to be explicit: `false and false or true and true` is not the same as `false and (false or true) and true`. |

**[verified]** against the API: `->`, `->>`, `has`, `weakhas`, `toktains`, `weaktoktains`,
`weakin`, `eqic`, `startswith`, `~ re()`, `matches(.., re())`, `!=`, `not isnull()`, and for
`ip4` fields `ip = 10.1.2.3`, `ip = "10.1.2.3"` (string literals are converted), `ip in {a, b}`,
`ip <- 10.0.0.0/8` and `isprivate(ip)` all behave as described. `toktains` matches whole tokens,
so it returns fewer rows than `->` for the same text.

More **[verified]** behaviour:
- `->` is case-sensitive: `host -> "HOST01"` returned 0 rows where `host -> "host01"` matched.
  Use `weakhas`/`eqic` for names, which change case between sources.
- `not <filter>` is false when the field is null, so the row is dropped:
  `where app = "MS-PIM", not weakhas(user, "x")` (field names shortened) returned 0 rows where the first clause alone
  returned rows. Write `isnull(user) or not weakhas(user, "x")` to keep them.
- JSON-typed fields: `weakhas(stringify(f), "x")` matches; `weakhas(str(f), "x")` silently
  returns 0 rows. Extract with `jqeval(jqcompile(".[0].displayName"), f)`; the value comes back
  JSON-quoted (`"\"Directory Writers\""`).
- Values stored with quote marks (Microsoft Graph `properties__user_id` holds `"<guid>"`
  *including the quotes*): `= "<guid>"` never matches; `-> "<guid>"` does.
- `peek(Message, re("Source Network Address:\\s*([^\\r\\n\\t]+)"), 1)` extracts a capture group
  from free text (backslashes doubled inside the double-quoted string).
- There is no `replace(re(...), field, "x")` (`No function named replace … re, str, str`).
  Normalise client-side.
- IP literals in `{...}` are ip4-typed: on a string field (e.g. `properties_ipAddress`)
  `f in {203.0.113.10}` fails with ``No function named `in` … str, set(ip4)``; quote them
  (`{"203.0.113.10"}`). Timestamp subtraction gives a duration that `avg()`/`round()` reject: use
  `epoch(a) - epoch(b)` (ms). The integer cast is `int(...)`; there is no `toint`
  (linq-functions.md).

Notes:
- `in` is a reserved word, so as a function call it needs backticks: `` `in`(...) ``. The infix
  form `x in {..}` or `x in (subquery)` needs no backticks.
- `x in {a, b, c}` and `x = a or x = b or x = c` perform the same. Prefer `in` because it reads
  better.
- `not` does not use the index. It is fine when you know it removes most rows.
- The raw event string is in `rawMessage`, `rawSource` or `raw`, depending on the table. To do
  a keyword search over the whole event, use `where weaktoktains(raw, "value")` or
  `toktains(raw, ...)` with the right column name.
- Typing: `eq(string, "123")` is faster than `eq(string, 123)`, and `eq(int, 123)` is faster
  than `eq(int, "123")`. **[verified]** A type mismatch in `where` can silently return zero
  rows (see section 9).

## 4. Creating fields (`select ... as`)

```
from demo.ecommerce.data
select mmlatitude(clientIpAddress) as latitude,
       mmlongitude(clientIpAddress) as longitude
select decode(statusCode, 200, "OK", 401, "Bad credentials") as statusText
select statusCode = 200 as is_ok          // boolean column
```

- Without `as`, the new column's name is the expression text (for example `operation(field)`).
- Every filter function also works as a boolean column: `select weakhas(ua, "curl") as is_curl`.
- `select field1 as name` projects or renames a field. In the API only the fields you name, plus
  the columns the query produces, are returned. The docs' "Select all fields" checkbox is a
  search-window setting. Its exact API equivalent is not documented, so name the fields you
  need.
- Conditional: `ifthenelse(cond, a, b)`. Null fallback: `nvl(f, default)`. See
  linq-functions.md for these and for the string/IP/URL/geo/time functions.

## 5. Grouping and aggregation

| Form | Meaning |
|---|---|
| `group every 10m by a, b` | One row per (10-minute bucket, a, b). |
| `group every 30m by a every 3h` | Server period 30m, client period 3h. |
| `group by a, b` / `group every - by a, b` | No time buckets; one row per distinct (a, b) over the whole range. |
| `group every 5m` | Time buckets only, with no keys. |
| `group` (no `by`, no `every`) | **[verified]** One row for the whole range, for example `from T group select count() as n`. |
| `... every -` / `... every 0` | No client period. |

- **Server vs client period**: the second `every` comes from the web UI, where the browser
  re-buckets server chunks. For API use, a single `group every 1h by ...` is enough. If you do
  write both, make the server period no larger than the client period.
- **Aggregations** go in the `select` right after `group`:
  `select count() as n, sum(bytes) as total, avg(x) as avgx, min(eventdate) as firstSeen,
  max(eventdate) as lastSeen, collectdistinct(port) as ports, nnfirst(user) as user`.
  - `count()` counts rows. `count(f)` counts the rows where `f` is not null.
  - Distinct counts: no `countdistinct` is documented. Your options are:
    `hllppcount(f)`, an estimate that returns a float; `sizedistinct(f)`, the number of
    distinct values in the group; or an exact count done with two groups:
    `group by f group select count() as distinct_f`.
  - Percentiles, stddev, first/last and the full list are in linq-functions.md.
- **Filtering on aggregates**: add a `where` after the aggregation `select`:
  `select count() as n where n > 200`.
- **Chained grouping**: grouping twice is allowed. The second `group` works on the output of
  the first. This is how the docs count distinct values and cardinality.
- **`eventdate` after grouping**: with `group every P`, each row is a bucket of P, and the
  time column holds the bucket's time. The docs do not say whether it is the start or the end.
  Treat it as the bucket label. With `group by` or a bare `group`, there are no time buckets.
  To get real event times, aggregate them yourself: `min(eventdate)`, `max(eventdate)`.
- **Cost**: grouping by high-cardinality fields (IPs in traffic logs, long strings, URLs) is
  expensive. Filter first, and consider grouping by a derived range or prefix instead.

## 6. Time: API range vs `eventdate`

- The API request's `from`/`to` sets the time window that is searched. Always send both:
  leaving out `to` starts a continuous query. Accepted forms, such as epoch values or
  `now() - 1h`, are covered in query-api.md.
- `eventdate` is the ingestion timestamp. It is indexed, so filters on it are cheap. Tables
  with the time-control feature also have `creationdate`, the time the event was generated at
  its source.
- Inside the query you can narrow further, but never beyond the API range:
  ```
  where "2024-09-10 07:21:35" < eventdate < "2024-09-12 12:21:35"
  where today() - 5d < eventdate
  where timestamp("2023-11-06 07:30:00") <= eventdate < timestamp("2023-11-06 13:30:00")
  ```
- Time helpers (see linq-functions.md): `today()`, `today("tz")`, `yesterday()`,
  `period(eventdate, 15m)`, `hour(eventdate)`, `dayofweek(eventdate)`, `formatdate(...)`.
- The date-language operators `now() - 3h`, `@ 1d` (snap), `^`, `>>`/`<<` are documented for
  the date picker and for the API's `from`/`to`. Inside LINQ, the docs only show
  `today() - 5d`-style arithmetic and literal timestamps.
- Duration literals seen in the docs: `15s`, `5m`, `10m`, `1h`, `3h`, `1d`, `5d`.

## 7. Subqueries

A subquery is a complete LINQ query in parentheses, used as a value set or as a keyed table.
It must be valid on its own. No fields pass between the outer query and the subquery in
either direction.

**`in`**: filter the outer rows by the values from another table.
```
from siem.logtrust.web.activity
where username in (
    from siem.logtrust.web.navigation
    where "2024-09-10 07:21:35" < eventdate < "2024-09-12 12:21:35"
    group every - by userEmail)
group every 10m by username
select count()
```
- Put a single key column last in the subquery (here `group ... by userEmail`).
- Tuples: `select (srcPort, serverPort) as tuple where tuple in (from T2 ... group by srcPort, serverPort)`.
- Several subqueries are allowed at the same level. In the search window only one nesting
  level is allowed; the docs do not state a separate limit for the API.
- **Negation**: no `not in` example exists in the docs. `where not (x in (subquery))` follows from
  the documented `not` and `in` operators, but it is untested. Verify it before relying on it.
- Limit: **32,000 events** from subqueries. The results are truncated beyond that, with a
  warning, so aggregate or filter inside the subquery.
- Time bounds: the docs require subqueries to be "time-bounded in the past" and show an
  explicit `eventdate` filter in them. Alert definitions (each-type) are the opposite: they
  forbid a fixed time range or a temporal group inside the subquery. When you use the API, add
  an explicit `eventdate` bound to the subquery.
- Subqueries are not allowed inside union/custom tables, aggregation tasks or OData requests.

**`has`** is `in` with the arguments reversed: `has((subquery), field)`.
```
from siem.logtrust.web.activity
select has((from siem.logtrust.web.navigation select srcPort, userEmail
            where eventdate > "2024-09-01"), srcPort) as c1
where c1 = true
```

**`->` with a subquery**: keep the rows where a subquery value is contained in the field:
`where (from T2 where today()-5d < eventdate select referer) -> url`.

**`at` / `[key]`**: use the subquery as a lookup table. All columns except the last are the
key, and the last column is the value.
```
from siem.logtrust.web.activity
group by username
select (from siem.logtrust.web.navigation group by userEmail, level)[username] as userLevel
select (from siem.logtrust.web.navigation group by userEmail, level
        select userEmail, count())[username, level] as match
```

## 8. Union tables, joins, lookups, free text

**Union tables** are normal tables that combine several vendor sources. Examples:
`auth.all`, `box.all.win`, `firewall.all.traffic`, `proxy.all.access`, `web.all.access`,
`domains.all`, `network.dns`, `edr.all.threats`, `netstat.netflow.all`. Query them with
`from auth.all ...`. They are the best first stop in a cross-vendor investigation. Once you
know which source matters, switch to the specific table, because it is faster and has more
fields. You cannot use subqueries inside union tables. The table list is in tables.md.

**Cross-search table join**: this is a web-UI widget that merges the results of two grouped
queries on a shared column. **LINQ has no documented `join` clause.** To correlate two tables
in the API, you can:
- filter one table by the other with a subquery (`in`, `has`, `[key]`, see section 7);
- run two grouped queries with the same key and join the results on the client side.

**Lookups (`lu`)**: enrich rows from an uploaded or query lookup.
```
select lu("Lookup_name", "Lookup_field", key_field) as new_field
```
- The key field's type must match the lookup key's type. No match returns `null`. A type
  mismatch is an error.
- A lookup is expensive, so apply it after filtering or grouping:
  ```
  from siem.logtrust.web.activity
  where isnotnull(city), not isempty(city), result = "OK"
  group every 1h by city, result
  select lu("Company_offices", "Office_type", city) as OfficeType
  ```
- A short list of CIDRs performs better than a long list of individual IPs.
- For other lookup functions (`hlut`, `hlurjson`), see linq-functions.md.

**Free-text search**: "free text query" in the docs just means a typed LINQ query. It is not
a keyword search mode. To search for a keyword, filter the raw column:
```
from box.unix where weaktoktains(raw, "sudo")
```
When the term is rare, putting the raw-column filter first can skip parsing. With
`toktains`, the input is decoded and matched against the encoded tokens, so non-ASCII input
can behave in unexpected ways.

## 9. Errors and silent failures

- **[verified]** A plain syntax error returns only `Query parsing error`, with no position.
  Bisect by removing clauses from the end until the query parses.
- **[verified]** An unknown table, field or function gives a specific message
  (``Unknown table `x` ``, ``Unknown identifier `f` ``, ``No function named `fn` ``).
- **[verified]** A type mismatch in `where` (for example, comparing an int field to a string
  literal) does **not** error. It returns zero rows. Before you conclude "no results", check the
  field types with the table schema or with a `limit 1` sample.
- **[verified]** Other silent zero-row causes: case-sensitive `->`/`=` on a name; a negated
  filter on a nullable field (`not f…` drops nulls); `str()` instead of `stringify()` on a JSON
  field; comparing with `=` to a value stored with quote marks; and a time window that ends
  before the data starts, or before late-arriving data (Microsoft 365 lags an hour or more).
- Common causes of parse errors (`!=` is fine, **[verified]**): quoting a table name with `"`/`'`;
  a missing `re()` around a regex; a hyphenated table name without backticks; calling `in` as a
  function without backticks; a trailing comma.
- Also check the docs' own examples, which contain typos: `clientIpAddressevery 10m`,
  `countwhere`, `mlevamodel`/`lenght`. Do not copy them verbatim.

**Error index** (every message reproduced against the API):

| Error | Cause | Fix |
|---|---|---|
| ``Unknown identifier `org` `` / `` `message` `` on `vcs.github.*.audit` | the GitHub audit tables have neither: the org is `organization` / `organization_id` (`business` for enterprise events), and no raw-record field is kept | `select *` with `--limit 1`, or `devo.py fields <table>` / `schema` |
| ``Unknown identifier `userEmail` `` on `siem.logtrust.web.activity` | the user's email is only in `siem.logtrust.web.navigation` | query `siem.logtrust.web.navigation` |
| ``Identifier `client` is used more than once`` (QUERY_PARSING_ERROR 1101003) | the alias (`… as client`) collides with a field of that name, compared case-insensitively, including names `schema` doesn't list: `client` and `raw` failed on `box.win_nxlog.security`, which has neither, and `client`/`Client` on SharePoint (which has `Client`) | pick another alias: `client_ip`, `src`, `raw_text` |
| ``Maximum number of elements surpassed for operation `collectcompact` (configured maximum: 100000)`` (QUERY_LIMIT) | `percentile()` (and other collect-based aggregates) over more than 100 k distinct values in one group, e.g. lag in seconds over a back-fill hour | coarsen the value (`floor(x / 60000)` minutes) or narrow the group/window; `devo.py lag` does this automatically |
| `Cannot run: query has errors` (Devo **web UI** only) | the UI editor rejects some identifiers the API accepts, e.g. `timestamp` | see §11, "Queries for the user to paste into the web UI" |

## 10. Performance checklist

1. Test with a short API time range first, then widen it.
2. Use the most specific table. Use union tables only for discovery.
3. Put the most restrictive filter first, especially one on an indexed operator (`=`, `eqic`,
   `startswith`, `endswith`, `has`, `in`, `weakhas`, `weakin`, `toktains`, `weaktoktains`).
4. Prefer `toktains`/`weaktoktains` over `->`/`contains`.
5. Filter before you group. Never group first and filter afterwards on data you could have
   filtered earlier.
6. Put expensive operations last: regex, `peek`, lookups, geolocation, percentiles,
   `jsonparse`.
7. Avoid grouping by high-cardinality fields or long strings. To check cardinality first, use
   `group by f group select count()`.
8. Match literal types to field types. This avoids auto-conversion and the silent
   zero-row trap.
9. `not` does not use the index.
10. Select only the fields you need, and aggregate on the server instead of pulling raw rows.
11. Heavy aggregations such as `percentileX`, `collectdistinct` and regex `peek` need a narrow
    scope.

## 11. API vs search-window differences

- The docs warn that a query copied from the search window into the API (or the other way
  round) "might not work". The only concrete difference they document is `mlevalmodel(...)`,
  which scores events with an uploaded ML model and exists only in the APIs.
- Alerts API exception: alert definitions use **search-window** LINQ syntax, not API syntax.
- Web-UI concepts that do not apply to the API: the Select all fields checkbox, Server mode,
  Partial results, real-time flow, "Go to query", and the client-period re-bucketing. The
  second `every` is still parsed but has no benefit in the API.
- Beyond `mlevalmodel`, the docs do not list other syntax differences. If a query from the
  web UI fails in the API, simplify it one clause at a time.

### Queries for the user to paste into the web UI

The analyst often re-runs a query in the Devo web UI. The UI can refuse queries that the API has
just run, with **"Cannot run: query has errors"**, when they use `timestamp` as a field name, which
the UI's editor treats as reserved (the API accepts `timestamp` [verified]). For anything you hand over to paste:
- don't use `timestamp` as a field (`devo.py query --ui-safe` warns about it; the `timestamp(...)`
  function is fine);
- for Microsoft 365 event time use
  `parsedate(str(jsonparse(message)["CreationTime"]), "YYYY-MM-DD[T]HH:mm:ss", "UTC") as created`, and
  for the event date `substring(str(jsonparse(message)["CreationTime"]), 0, 10) as created_day`
  [both verified in the API]; elsewhere use `eventdate` or the family's event-time field
  (table-guide.md, "Event time per family");
- give it as one block with the time range stated separately (the UI's range picker replaces
  `--from`/`--to`).

## 12. Worked investigation patterns

All the table and field names below are examples. Check the real schema before running a
query, because field names differ per table. Values are placeholders.

**P1: All events for a user (case-insensitive)**
```
from auth.all
where eqic(user, "alice")
select eventdate, user, srcIp, action, result
```

**P2: Everything touching an IP (as source or destination)**
```
from firewall.all.traffic
where srcIp = 203.0.113.10 or dstIp = 203.0.113.10
```

**P3: Traffic from a CIDR range, bucketed hourly**
```
from firewall.all.traffic
where srcIp <- 203.0.113.0/24
group every 1h by srcIp, dstPort
select count() as n, sum(bytes) as bytes
```

**P4: Top talkers (top-N)**. Aggregate on the server, sort on the client, and cut to N.
```
from firewall.all.traffic
where not isprivate(dstIp)
group by srcIp, dstIp
select count() as n, sum(bytes) as bytes
where n > 100
```

**P5: Failed logins per user, brute-force threshold**
```
from auth.all
where weakhas(result, "fail")
group every 10m by user, srcIp
select count() as failures
where failures >= 20
```

**P6: Distinct values of a field (enumerate)**
```
from box.win_nxlog.security
where eventID = 4625
group by targetUserName
select count() as n
```

**P7: How many distinct users an IP tried (spray detection)**
```
from auth.all
where srcIp = 203.0.113.10
group by srcIp
select hllppcount(user) as approxUsers, collectdistinct(user) as users,
       min(eventdate) as firstSeen, max(eventdate) as lastSeen
```

**P8: Exact distinct count and cardinality check (group twice)**
```
from firewall.all.traffic
group by dstIp
group select count() as distinctDestinations
```

**P9: Keyword hunt in the raw event**
```
from box.unix
where weaktoktains(raw, "authorized_keys")
select eventdate, hostname, raw
```

**P10: Regex match, placed after the cheap filters**
```
from proxy.all.access
where eqic(user, "alice"),
      url ~ re("\\.(zip|iso|js)$")
select eventdate, url, srcIp
```
**[verified]** Escaping: in a double-quoted LINQ string, write the backslash twice
(`re("\\.(zip|iso|js)$")`, as above). A single `\.` there is a lexical error. Single-quoted
strings take it literally (`re('\.(zip|iso|js)$')`), and `[.]` works in both.

**P11: Subquery pivot: IPs that failed auth, and their firewall traffic**
```
from firewall.all.traffic
where srcIp in (
    from auth.all
    where today() - 1d < eventdate
    where weakhas(result, "fail")
    group by srcIp)
group every 1h by srcIp, dstIp, dstPort
select count() as n
```
Remember the 32,000-event subquery cap. Group inside the subquery so it returns keys, not
raw events.

**P12: First and last seen per host for an indicator**
```
from network.dns
where weakhas(query, "example-bad.test")
group by clientIp
select count() as n, min(eventdate) as firstSeen, max(eventdate) as lastSeen,
       collectdistinct(query) as queries
```

**P13: Activity timeline for an account (time bucketing)**
```
from box.all.win
where eqic(user, "alice")
group every 15m by eventID
select count() as n
```

**P14: Enrich with a lookup after grouping**
```
from firewall.all.traffic
where dstPort = 3389
group by srcIp
select count() as n,
       lu("Known_admin_hosts", "owner", srcIp) as owner
where isnull(owner)
```

**P15: Carry non-key columns through a group**
```
from auth.all
where eqic(user, "alice")
group by srcIp
select count() as n, last(action) as lastAction, nnfirst(userAgent) as ua
```
