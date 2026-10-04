# LINQ essentials and traps

The rules and pitfalls that most often make a Devo query fail or silently return wrong or empty
results. Syntax in depth: linq-syntax.md; functions: linq-functions.md.


Contents:
- IP literals
- Time arithmetic
- `->` and `=` are case-sensitive
- Zero rows is not proof of absence.
- Before saying a host or source sends no data
- `not <filter>` drops rows where the field is null
- JSON-typed fields
- Graph activity logs store user ids with quote marks
- Duplicates.
- Entra string timestamps
- "Today" questions
- `eventdate` is ingestion time, not event time, and the lag is variable and batch-driven.
- Use the complete table
- Collection gaps happen.
- Queries the user will paste into the Devo web UI
- Upload / file-sharing questions
- Don't infer identities from timing.

- Clause order: `from` → `where` → `select … as` → `group [every 1h] by …` →
  `select <aggregations>` → optional `where` on aggregates. There is no `order by` (sort
  client-side) and no `countdistinct` (use `hllppcount(f)` or group twice).
- **IP literals:** an unquoted IP (`10.1.2.3`, also inside `{...}`) is an ip4 value. On a string
  field it fails (`No function named in … str, set(ip4)`): quote it. `devo.py fields <table>` shows
  which IP fields are `ip4` and which are strings.
- **Time arithmetic:** a timestamp difference is a duration that `avg()`/`round()` reject; use
  `epoch(a) - epoch(b)` (milliseconds). The integer cast is `int(...)` (there is no `toint`).
  `hllppcount()` is an approximate distinct count (the helper rounds it).
- Matching: `=` exact; `->` contains; `weakhas(f, "x")` / `->>` case-insensitive contains;
  `has(f, "a", "b")` any of; `toktains` whole token; `~ re("regex")`; `f in {a, b}`;
  `ip <- 10.0.0.0/8`; `isprivate(ip)`; not-equal is `!=` or `/=`; combine with `,` / `and` /
  `or` / `not`.
- **`->` and `=` are case-sensitive** [verified]: `host -> "HOST01"` returns 0 rows where
  `host -> "host01"` matches. Names change case between sources: Windows `host` is typically a
  lowercase FQDN, `rawMessage` carries the uppercase hostname, computer accounts look like
  `HOST01$`, and Linux `machine` is often the short name. Use `weakhas`/`eqic` on the shortest
  distinctive substring (`devo.py fields <table>` shows each field's case).
- **Zero rows is not proof of absence.** The usual causes are:
  - exact, case-sensitive `=`/`->` on a string (use `weakhas`/`eqic`)
  - the wrong field, or the wrong table family (Linux hosts are in `box.unix` (`machine`), not
    `box.win_nxlog.*` (`host`))
  - values stored differently from how you typed them (Graph logs keep user ids *with quote
    marks*)
  - a negated filter on a field that can be null (below)
  - a time range that's too short, or one that ends before the data starts or before late data
    arrives
  - a stale cache: the field or table changed (refresh it: SKILL.md, "Domain cache")
  Numeric-looking literals are converted (`EventID = "4624"` and `dstPort = 443` both work), but a
  literal that can't be converted (`events = "abc"` on an int) silently matches nothing. Check
  with `schema` and a looser filter before concluding "nothing happened".
- **Before saying a host or source sends no data**, search the Windows *and* Linux tables,
  case-insensitively, over 7–30 days up to `now` (investigations.md, "Is this host sending logs
  to Devo?"). A short window can miss a host whose agent restarted just after it ended.
- **`not <filter>` drops rows where the field is null** [verified]: adding
  `not weakhas(properties_initiatedBy_user_userPrincipalName, "x")` to a filter on
  `properties_initiatedBy_app_displayName` removes the rows where the UPN is null. Write
  `isnull(f) or not weakhas(f, "x")`.
- **JSON-typed fields** (e.g. `properties_targetResources`, `properties_additionalDetails` in
  `cloud.azure.ad.audit`) [verified]: `weakhas(stringify(f), "x")` works, while
  `weakhas(str(f), "x")` silently returns 0 rows. Extract one value with
  `jqeval(jqcompile(".[0].displayName"), f)`, which comes back JSON-quoted
  (`"\"Directory Writers\""`). For several values, pull rows with `--format jsonl` and parse
  them in Python.
- **Graph activity logs store user ids with quote marks** [verified]:
  `properties__user_id = "<guid>"` never matches; use `properties__user_id -> "<guid>"`.
- `replace(re(...), field, "x")` isn't a function (`No function named replace … re, str, str`).
  Normalise values (GUIDs in URIs, etc.) client-side.
- `peek` pulls a value out of free text: `peek(Message, re("Source Network Address:\\s*([^\\r\\n\\t]+)"), 1)`
  (backslashes doubled inside a double-quoted LINQ string).
- **Duplicates.** Some sources arrive through two collectors or are re-delivered (Entra
  sign-ins and audit, SharePoint/OneDrive back-fills, Defender). Count distinct ids, not rows:
  Entra (`properties_id`), SharePoint/OneDrive (`Id`), Defender (`device_id`, `report_id`,
  `timestamp`); for Entra audit, a copy with `tenantId` null or `-` is the duplicate. Detections
  on a doubly-ingested table fire in pairs. Union tables and their members repeat records too:
  query one source table, not both.
- **Entra string timestamps** (`properties_createdDateTime`) come in two formats from the two
  collectors (`…+00:00` and `…Z`): `min`/`max` on the strings and grouping by them mix the copies.
  Use `eventdate`, or the cached event-time expression (entra-graph.md).
- **"Today" questions:** use `--from today --to now`. A `--to` in the future is clamped to now
  (Devo would otherwise wait until then).
- **`eventdate` is ingestion time, not event time, and the lag is variable and batch-driven.**
  Run `devo.py lag` before relying on a time window rather than assuming a figure. For event
  time, widen the window and filter on the family's event-time field (table-guide.md, "Event time
  per family": `CreationTime`, a key inside the M365 `message` JSON (`jsonparse(message)["CreationTime"]`), Windows `timestamp`, Fortinet `serverdatetime`,
  Entra `properties_createdDateTime`; Linux has none). `cache status` says which families were
  verified in this domain.
- **Use the complete table:** a parent with many children (`from cloud.aws.cloudtrail`) or a
  union table is slow or times out; query the service tables in parallel. Where a product
  lands in several tables (e.g. Entra interactive sign-ins in both `signin` and
  `interactive_user_signin`), compare their volumes with `tables` and use the complete one.
- **Collection gaps happen.** If a busy source has a run of missing hours or days, check
  `devo.py coverage`/`lag` and say so when a question covers those days; record a confirmed gap
  as a cache note.
- `group every 1h` **omits empty buckets**. Fill the missing hours with 0 yourself, and treat a
  run of missing hours on a busy table as a possible log-collection gap, not a quiet period.
- Regex: inside a double-quoted string write `re("microsoft\\.com")` (backslash doubled), or
  use a single-quoted string `re('microsoft\.com')` or `[.]`. A single `\.` in double quotes is
  a lexical error.
- Hyphenated table names need backticks. The helper adds them after `from`.
- A syntax error only says "Query parsing error" with no position. Rebuild the query clause by
  clause. linq-syntax.md §9 has an error → cause → fix index (`Unknown identifier`, `Identifier …
  is used more than once`, the `collectcompact` limit, the web UI's "Cannot run: query has errors").
- **Queries the user will paste into the Devo web UI**: don't use `timestamp` as a field (the UI
  rejects it; the API doesn't); run them through `query --ui-safe` (linq-syntax.md §11).
- **Upload / file-sharing questions** need a proxy, CASB or DLP feed; check `tables` for one.
  Without it, combine EDR data with SharePoint/OneDrive download bursts
  (`references/cross-tool-sentinelone.md`).
- `dns.windows`: filter on `question_dot` (dotted name; `question_name` is in wire format), and
  count client queries with `context = "PACKET", send_receive = "Rcv", query_response != "R"`,
  because each query is logged several times. The query type is `question_type`.
- `siem.logtrust.alert.info.status` is always 0. Use the Alerts API for live status.
- Speed: union tables (`auth.all`, `firewall.all.traffic`, `network.dns`, …) and parent-prefix
  queries (`from cloud.aws.cloudtrail`) take minutes per hour of data. Specific source tables
  usually take seconds for short windows, but timings vary a lot with server load and table
  volume, and a day of the busiest tables (Windows security, DNS, firewalls) takes minutes.
  Filtering on non-indexed text fields adds tens of seconds.
- Parsed fields can be blank or wrong. The raw event text is usually in `Message`,
  `message` or `rawMessage`, so check key facts there when a parsed field looks odd. Null or
  empty group keys show as empty cells: call them "(blank)". Common cases:
  - blank `TargetUserName` on many 4625s
  - Windows `IpAddress` / `IpAddress_ip4`: **in some deployments the NxLog config overwrites it
    with the reporting server's own IP** (check a few rows against `Message` before trusting
    it). The other party's address (the client of a logon, ticket or share access) is in
    `Message`, as "Source Network Address", "Client Address", "Source Address" or "Network
    Address": extract it with `peek` (investigations.md, "True source of a Windows logon").
  - Linux sshd/sudo: parsed `user`/`srcIp` are often blank, and the account and IP are only in
    `message` (a relay may prepend its own tag to each line).
  - Sysmon DNS (EventID 22): `Query` can be empty.
- **Don't infer identities from timing.** Two events lining up in time doesn't make an IP a
  particular host or an account a particular person. Resolve IP↔host through ZTNA/proxy logs,
  a vulnerability scanner, the EDR inventory or the host's own events, and account↔person through
  naming conventions and sessions (investigations.md). Say which link is inferred and which is
  shown in the data.
