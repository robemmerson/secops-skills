# Investigations and alert triage

How to go from an alert (or an indicator) to a defensible verdict using Devo data.
Table and field choices below use Devo's standard parsers; confirm what the domain actually
collects with `devo.py tables` (cached live table list) and `devo.py cache notes` (domain notes
recorded earlier), and check fields with `devo.py fields <table>`. Every query in this file has
been run against a real domain to confirm it parses. Values like `alice`, `203.0.113.10` and
`HOST01` are placeholders.

## Contents
1. Triage workflow
2. Reading an alert
3. Pivot recipes by entity (user, IP incl. "classify an external IP", host, hash/process, domain,
   AWS principal), plus "everything a user did" (multi-source sweep), "is this host sending logs?"
   (coverage check), "who logged into which servers?" and "health of the whole domain"
4. Recipes by alert type (incl. privileged grants in Entra/Azure/AD, brute force / password spray
   playbook with the credential-attack spec, file malware in SharePoint/OneDrive)
5. Time windows and volume control
6. Verdict and drafted actions (report template)

## 1. Triage workflow

1. **Collect.** `devo.py alerts --from 24h` (every status, newest first; `--open` hides
   Closed and False-positive alerts). Pick the alert, then `devo.py alert <id>`.
2. **Understand the detection.** The `alert` output shows the definition's description,
   `sourceTable` and **the LINQ query that fired**. Read it. It tells you exactly which
   condition matched and which table holds the raw events. (The `alerts` table shows the
   same `source` and the `event_utc` next to `created_utc`.)
   - **Native or forwarded?** Definitions reading another product's table (e.g.
     `edr.sentinelone.*`) relay that product's detection; they may be parked at 800
     Suppressed because another case tool ingests them directly (the comments usually say so).
     `SecOps*` definitions on log tables are Devo's own detections, and the detection logic is
     yours to judge.
   - **Event time vs alert time.** Alerts can be created minutes to hours after the event. Work
     from `eventdate` in the extra data and
     mention the delay in the report. For grouped rules `eventdate` is the start of the time
     bucket; the exact time is in fields like `first_seen` or in the raw events.
3. **Reproduce.** Re-run the detection query (or a simplified version) over a window around
   the alert time. The `eventdate` in extra data is the event time. Use ±30 min for a single
   event, and the definition's look-back (`backperiod` in extra data, in ms) for threshold
   alerts. Confirm you see the same events.
4. **Scope.** Pivot on each entity in the alert (user, source/destination IP, host, hash,
   domain): what else did it do before and after, and is it new or normal (compare with the
   previous 7 days)?
5. **Check for related alerts.** Look for the same entity in other alerts:
   `devo.py alerts --from 7d --format json` and search, or the `siem.logtrust.alert.info` query below.
6. **Decide and report.** Give a verdict, confidence, evidence (query + result counts) and
   recommended actions, including the Devo status/comment you *would* set (section 6). You can
   post the comment with `devo.py comment` once the user has approved its exact text (preview
   first, then `--confirm`). Status, priority and tag changes are not implemented.

Triage lessons:
- **Collapse repeats first.** Rolling detections re-fire for the same underlying event (e.g.
  a relay rule can re-fire on each status change in the source product, several alerts per threat). Group the
  alert list by entity/hash/threat before treating them as separate incidents, and list the
  duplicate alert ids in your report.
- **Check what happened after the alert.** Query the source table up to *now*, not just around
  the alert time. The source system's own later verdict (e.g. `threatInfo__analystVerdict`,
  `threatInfo__incidentStatus`, `mitigationStatus`) often settles the case.
- **Mapped alert fields can mislead.** `username`, `srcIp` etc. on the alert are whatever the
  definition mapped, sometimes a static value (e.g. a fixed value rather than the
  actor). Trust the entities in the extra data and in the raw events.
- **Pairs of alerts for one event.** Rules on `cloud.azure.ad.audit` can fire twice per event
  when the table ingests each event twice (see §4, Entra role assignment).
- **Don't infer identities from timing.** An IP on a DC logon that lines up in time with a
  server's activity is not thereby that server (in some NxLog deployments Windows `IpAddress`
  is the reporting server's own IP; check), and an account used on a Linux box is not thereby a
  particular person (it may be a shared local account). Tie IP↔host through ZTNA/VPN
  logs, a vulnerability scanner or the EDR inventory (e.g. Zscaler ZPA `Host`/`ServerIP`, Qualys,
  SentinelOne) or the host's own events, and account↔person through the domain's naming
  conventions and ZTNA/VPN sessions (§3). In the report, say which links the data
  shows and which you inferred.
- **Status in practice:** 800 Suppressed and custom codes are often set by automation (e.g. when
  an alert is forwarded to an external case tool). Read the comments before assuming nobody
  looked at it, and record what a custom code means with `devo.py cache note add '...'`.
- **Per definition first.** `devo.py alerts --from 30d --by-def` prints one row per definition
  with counts per status. "Not closed" includes 800 Suppressed and custom codes, so separate
  native (`SecOps*` on log tables) from forwarded definitions before counting what is really open.
- **Check the definition's source table against its siblings.** A rule on one table misses the
  others: e.g. OneDrive vs SharePoint, interactive vs non-interactive sign-ins, `signin` vs
  `interactive_user_signin`. When the alert's activity could also land in a sibling table, query
  that too and say in the report whether the rule covers it.

Keep a running list of the queries you ran and their row counts. The user needs them to
check your reasoning.

## 2. Reading an alert

- `priority`: 1 very low, 2–3 low, 4–5 medium, 6–7 high, 8–10 very high.
- `status` (Alerts API only): 0 Unread, 1 Updated, 2 False positive, 100 Watched, 300 Closed,
  800 Suppressed. Other codes are custom workflow states, not documented by Devo: read the
  alert's comments to learn what they mean. Report the raw code with what the comments say.
- `context` = `my.alert.<domain>.<DefinitionName>`. The helper prints the definition name.
- `extraData`: the columns the detection query selected, as a JSON string with URL-encoded
  values. The helper decodes it. `__devo_when`, `ticktime`, `backperiod` and `client` are
  Devo bookkeeping; the rest is evidence.
- Fields like `srcIp`, `username` and `dstHost` are only filled if the definition mapped them.
  Often the entities live only in extra data.
- `commentsList` (shown by `alert`) has previous analyst notes. Read them before duplicating
  work.

Alert history through LINQ (fast, and filterable by anything in `extraData`):

```linq
from siem.logtrust.alert.info
where context -> "SentinelOne"
select eventdate, alertId, context, priority, username, srcIp, extraData
```

Count alerts per definition over a period:

```linq
from siem.logtrust.alert.info
group by context
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

## 3. Pivot recipes by entity

### User
Windows logons for a user (4624 success, 4625 failure), by server and client address
(the client address is always in `Message`; in some deployments `IpAddress` is the reporting
server's own IP, so check):
```linq
from box.win_nxlog.security
where EventID in {4624, 4625}, weakhas(TargetUserName, "alice")
select peek(Message, re("(?:Source Network Address|Client Address|Source Address|Network Address):\\s*(?:::ffff:)?([^\\r\\n\\t]+)"), 1) as src
group by EventID, host, src, LogonType
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Entra ID sign-ins for a user. Prefer `cloud.azure.ad.signin` when it has data;
`interactive_user_signin` can hold only a fraction of interactive sign-ins (compare the two over
the same window). Repeat with `cloud.azure.ad.noninteractive_user_signin`. Rows can be duplicated
(e.g. two collectors), so count distinct `properties_id` when you need numbers (entra-graph.md):
```linq
from cloud.azure.ad.signin
where weakhas(properties_userPrincipalName, "alice")
group by properties_ipAddress, properties_location_countryOrRegion, properties_status_errorCode, properties_appDisplayName
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Zscaler private access by user:
```linq
from vpn.zscaler.access
where weakhas(Username, "alice")
group by ClientPublicIp, ClientCountryCode, Application, ConnectionStatus
select count() as n
```

Microsoft 365 activity by user (`eventdate` is ingestion time and the lag is batch-driven: run
`devo.py lag --tables office365`, widen the window to cover it, and filter on `CreationTime`; see
m365.md). For Teams (conversations, other parties, who sent/edited/reacted when, meeting joins and
leaves, shared files and links; message text is never logged) run
`devo.py teams <upn> --from … --to … --tz <Area/City> --out <scratchpad>/teams.json`:
```linq
from cloud.office365.management.azureactivedirectory
where weakhas(UserId, "alice")
group by Operation, ResultStatus, ClientIP
select count() as n
```

### IP address
Firewall traffic totals for an IP, one row per destination (`srcIp`/`dstIp` are ip4; a plain
dotted literal works). Each connection writes start, interim and final rows with **cumulative**
bytes, so sum the final rows only (`logID = "0000000013"`) or take `max()` per `devID, session`
(network-linux.md):
```linq
from firewall.fortinet.traffic.forward
where srcIp = 10.1.2.3, logID = "0000000013"
group by devName, dstIp, dstPort, action
select count() as sessions, sum(bytesSent) as bytes_out, sum(bytesRecv) as bytes_in, sum(duration) as total_s
```

Which Windows server has an IP (where the NxLog config sets `IpAddress` to the reporting
server's own address; check that it does):
```linq
from box.win_nxlog.system
where IpAddress = "10.1.2.3"
group by host, IpAddress
select count() as n, max(eventdate) as last_seen
```

Who logged on to Windows servers *from* an IP (the client address is in `Message`; the
`weakhas` pre-filter keeps it fast, the `src` check makes it exact):
```linq
from box.win_nxlog.security
where EventID in {4624, 4625, 4648, 4768, 4769, 5140, 5145}, weakhas(Message, "10.1.2.3")
select peek(Message, re("(?:Source Network Address|Client Address|Source Address|Network Address):\\s*(?:::ffff:)?([^\\r\\n\\t]+)"), 1) as src
where src = "10.1.2.3"
group by EventID, host, TargetUserName, LogonType
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Linux / SSH from an IP: the parsed `srcIp`/`user` are blank on sshd lines, so parse `message`
("Accepted … for <account> from <ip> port <port>"). Newer OpenSSH logs as `sshd-session`, not
`sshd`. Use the SSH session recipes in `table-guide/network-linux.md`.

Entra ID sign-ins from an IP (prefer `cloud.azure.ad.signin` when it has data):
```linq
from cloud.azure.ad.signin
where properties_ipAddress = "203.0.113.10"
group by properties_userPrincipalName, properties_status_errorCode
select count() as n
```

Public vs internal: `where ispublic(dstIp)`, or `isprivate(srcIp)`, or CIDR
`where srcIp <- 10.0.0.0/8`.

Enrich an external IP inline (GeoIP, ASN and Devo reputation; check they return values in the domain):
```linq
from firewall.fortinet.traffic.forward
where dstIp = 203.0.113.10
group by dstIp
select count() as n, countrycode(dstIp) as cc, asn(dstIp) as asn, asorg(dstIp) as org,
  reputation(dstIp) as rep, reputationscore(dstIp) as rep_score
```

### Classify an external IP
GeoIP and ASN functions take an `ip` value. On a string field such as Entra's
`properties_ipAddress`, convert with `ip4()` and drop rows where that is null (IPv6 or malformed):
`asorg()`/`asn()` on a null fail the whole query with a bare "General error", while `countrycode()`
returns null:
```linq
from cloud.azure.ad.signin
where isnotnull(ip4(properties_ipAddress))
group by properties_ipAddress
select count() as n, countrycode(ip4(properties_ipAddress)) as cc, asn(ip4(properties_ipAddress)) as asn,
  asorg(ip4(properties_ipAddress)) as org
```
For a single literal, use any small table with data in the window and group on the converted value
(run it with `--limit 5`, not `--limit 1`: LINQ has no `limit` keyword, and a grouped query that
returns exactly `--limit` rows prints a "limit reached" note even though the answer is complete). `asorg(ip4("…"))` applied directly per row fails with
"General error"; after a `group by` it works:
```linq
from siem.logtrust.alert.info
select ip4("203.0.113.10") as ip
group by ip
select countrycode(ip) as cc, asn(ip) as asn, asorg(ip) as org,
  reputation(ip) as rep, reputationscore(ip) as rep_score
```
Reading the answer:
- **GeoIP/ASN data can be stale or coarse**, especially for cloud ranges, mobile carriers and
  scanners; a country from a cloud provider's range is where the range is registered, not where
  the person is. Confirm with other evidence (the IP's history in sign-ins, ZTNA, firewall).
- **Cloud-hosted desktops** (VDI, Cloud PC) egress through the provider's ranges, shared by many
  users of the same tenant: many successful users from one cloud IP is usually that, not an attack.
- **ZTNA client public IPs** (`vpn.zscaler.access` `ClientPublicIp`) that many users share reveal a
  corporate office NAT; the organisation's own egress shows as many successful sign-ins.
- **Vulnerability-scanner ranges** (e.g. the scanning vendor's published ranges, or an ASN owned by
  a scanning service) hit many hosts and ports on a schedule; compare with the scanner's
  documentation and the same window on previous days. GeoIP/ASN for a scanner's range can
  disagree with the vendor's published ranges (the ASN may be a hosting provider's, the country
  the registrant's), so confirm against the vendor's own list. If the domain collects the
  scanner's activity log (e.g. `vuln.qualys.useractivitylog`; `devo.py tables --grep vuln`), look
  for an external scan launched around that time: that turns "unknown scanner" into "our scan".
- **Scanner fingerprints in sshd logs.** An "Invalid user NoSuchUser"-style probe (a deliberately
  non-existent account, to see how the server answers) followed by a run of random or dictionary
  usernames from the same IP is a vulnerability scanner or a mass scanner, not a targeted guess
  at real accounts. Check whether any of the usernames exist and whether any login was accepted.
- **Reputation** (`reputation()`, `reputationscore()`, see the firewall example above) is one input,
  not a verdict. A blank `reputation()` (an empty string, not null) with `reputationscore()` 0 means
  the IP is on none of Devo's reputation lists: no reputation data, **not "clean"**. Well-known
  benign IPs (a public DNS resolver, for example) come back exactly like that, and so does any
  fresh attacker IP.

### Who is this internal IP?
Qualys asset inventory (hostname, OS, tags):
```linq
from vuln.qualys.hosts
where ip = 10.1.2.3
select eventdate, dns_fqdn, netbios, os, tag_names
```
SentinelOne agent inventory (computer and last user):
```linq
from edr.sentinelone.agent.agents
where lastIpToMgmt = 10.1.2.3
group by computerName, lastLoggedInUserName, groupName
select max(eventdate) as last_seen
```
Firewall device identification (Fortinet's `srcHost`, MAC and OS guess; only right on directly
attached LANs: on routed subnets many source IPs can share one device and user):
```linq
from firewall.fortinet.traffic.forward
where srcIp = 10.1.2.3
group by srcHost, srcmac, osname
select count() as n
```
What it resolves (a host's DNS lookups often give away its role):
```linq
from dns.windows
where context = "PACKET", send_receive = "Rcv", query_response != "R", remote_ip = 10.1.2.3
group by question_dot
select count() as n
```
ZTNA connector: an internal address that shows up as the source of many logons on servers can be a
ZTNA app connector, which proxies every remote user's session (`Connector` is its name,
`ConnectorIP` the address servers see, `ConnectorPort` the source port; check the names with
`devo.py fields vpn.zscaler.access`). Each session ties back to the user and device:
```linq
from vpn.zscaler.access
where ConnectorIP = "10.1.2.3"
group by Connector, ConnectorIP, Username, ServerIP, ServerPort
select count() as n, min(eventdate) as first, max(eventdate) as last
```
To pin one server-side event to one user, match `ConnectorIP` + `ConnectorPort` to the event's
source address and port at the same time (brute force playbook, step 7).
Also check Windows logons from the IP (client address in `Message`, see above), which Windows
server it is (`IpAddress`, see above), and Zscaler (`ClientPrivateIp`).
Without DHCP data, IP-to-host mappings can be stale: prefer the most recent.

### Is this host sending logs to Devo? (host coverage check)
`devo.py coverage <name>` runs steps 1–3 and the Windows half of step 5 below in one go (Windows
30 days, Linux and Zscaler 7 days; `--no-linux` for a quick Windows answer) and flags missing and
low days. The steps are here so you can read its output and go further by hand.

Before saying a host (or any source) sends no data, run this. Two common mistakes: concluding
"not logging" from a short window that ended just before the agent restarted, and searching a
**Linux** server only in the Windows tables. Search case-insensitively (`weakhas`) on the shortest
distinctive part of the name, over 7–30 days up to `now`, in both families. Record the domain's
host naming conventions as cache notes (`devo.py cache note add '...'`) once you learn them, and
read them with `devo.py cache notes`.

1. **Windows** (30 days, `--chunk 5d --parallel 6`). Repeat for `.security`, `.sysmon`,
   `.powershell` and `.application` with `--from today --chunk 2h` to see when each table's
   data starts today.
   ```linq
   from box.win_nxlog.system
   where weakhas(host, "HOST01")
   group every 1d by host
   select count() as n, min(eventdate) as first, max(eventdate) as last
   ```
2. **Linux** (7 days, `--chunk 1d --parallel 7`; `box.unix` can be slow, so run it in the background).
   ```linq
   from box.unix
   where weakhas(machine, "HOST01")
   group every 1d by machine
   select count() as n, min(eventdate) as first, max(eventdate) as last
   ```
   Look for **low** days as well as missing ones (a handful of events, all just after midnight).
   `group every` omits empty days, so list the missing dates yourself.
3. **Resolve the host's real IP and who connected.** `ServerIP` is the host's internal IP, and
   `ServerPort` 22/3389 tells you SSH vs RDP. `ConnectorIP` is the source address the server
   itself records (e.g. sshd "Accepted publickey for <account> from <ConnectorIP>"), so it
   links the server's own login lines to a Zscaler user.
   ```linq
   from vpn.zscaler.access
   where weakhas(Host, "HOST01")
   group by Username, Host, ServerIP, ServerPort, ConnectorIP, ConnectionStatus
   select count() as n, min(eventdate) as first, max(eventdate) as last
   ```
4. **Other inventories:** Qualys `vuln.qualys.hosts` and SentinelOne
   `edr.sentinelone.agent.agents` (the "Who is this internal IP?" recipes above).
5. **Signatures of logging resuming, or of a reboot:**
   - **Windows:** `box.win_nxlog.system` EventID 7036 "The nxlog service entered the stopped
     state" followed by "running". The first event after a gap is the restart. All nxlog
     service changes per host:
     ```linq
     from box.win_nxlog.system
     where EventID = 7036, weakhas(Message, "nxlog")
     group by host
     select count() as n, min(eventdate) as first, max(eventdate) as last
     ```
   - **Linux:** a burst of `kernel`, `cloud-init`, `dhclient`, `systemd-fsck` and `rsyslogd`
     start lines, plus sshd "Received signal 15; terminating" just before.

Collection gaps happen: hosts can go silent for weeks until the agent restarts. Report
coverage (first/last seen per table, gaps) alongside any "no activity" conclusion.

### Who logged into which servers?
Start with the helper; it covers Windows 4624 (LogonType 2/7/10/11) and Linux sshd "Accepted",
one row per server and account with first/last, sources and a person/service/system label:
```
devo.py logons --from 7d --out <scratchpad>/logons.json
devo.py logons --from 30d --host HOST01            # one server
devo.py logons --from 30d --user jsmith --tz Europe/London
devo.py logons --from 7d --people-only             # hide service-like accounts too
```
- **LogonType cheat-sheet:** 2 console, 7 unlock (repeats for the same session and inflates
  counts), 10 RDP (RemoteInteractive), 11 cached credentials. 3 network and 4/5 batch/service
  are not interactive logons; leave them out of "who logged in" questions (`logons` already
  excludes type 3 network logons).
- **Built-in accounts are never people:** `DWM-n` ("Window Manager"), `UMFD-n` ("Font Driver
  Host") and computer accounts `NAME$` are session/system accounts (`--all-accounts` shows them).
- **People vs service/shared accounts.** Hints: naming patterns (`svc-`, `sa_`, app names),
  very high counts on one host, Linux shared accounts (`ec2-user`, `root`, `git`, `ubuntu`) and
  SFTP partner accounts. The label is a heuristic: confirm, then record the domain's service
  accounts with `devo.py cache service set 'svc-*,sa_*,...'` (`add` appends, `show` lists) so
  later runs label them.
- **Sources:** RDP sources are often `0.0.0.0` or `-` (the client address isn't recorded), or a
  jump host / ZTNA connector IP. Resolve a connector IP to the user and device through the ZTNA
  logs (e.g. `vpn.zscaler.access` `ConnectorIP`, `ServerIP`, `Username`; host coverage check,
  step 3). A shared Linux account ties to a person only that way.
- **Times:** Windows first/last are event times; Linux has only ingestion time.
- **Absence is silent.** A server that stopped logging simply doesn't appear. Before saying
  nobody logged in, check it with `devo.py coverage HOST01` (or `devo.py health` for the whole
  domain).

### Health of the whole domain
`devo.py health` first (`--recent 7d --baseline 21d` by default; `--out` for the full JSON,
`--no-hosts` to skip the slow sender check). It compares collector-counter volumes per table
(recent vs baseline, unqueryable tables excluded and reported apart) and re-counts
stopped/dropped tables on the tables themselves, lists quiet Windows/Linux senders (cloud
autoscaling churn collapsed), normalises `collectors.out` warnings/errors, lists silent
collectors and puts collectors with credential/permission errors first (`AUTH`: 401/403, expired
token; such a collector may be pulling nothing for some services), and measures lag with
clock/time-zone offset detection.
- **Big movers are re-counted on the tables** (`--no-verify` skips it): the median day of the
  last 7 full days vs the 7 before (`← REAL` when that moves too), plus the last 2 days vs the
  same weekdays a week earlier (`← RECENT SHIFT`: a change too new to move the weekly median).
  A mover the table doesn't confirm is a counter artefact or a weekday mix.
- **Volume numbers are from the counter (unverified)** unless the line says re-counted; quote
  them as approximate, and count the table before stating a figure.
- **Lag for one table:** `devo.py lag --table X` works on its own (no `--tables` needed). For a
  table without an event-time family in `hints/event-time.json`, it falls back to the best-filled time field
  of the table's cached field profile (run `devo.py fields X` first if it has none) and prints
  which field it used: check that field really is the event time.

Traps when reading it or going further by hand:
- **The collector counter is not the data.** `siem.logtrust.collector.counter` can under-report
  or miss whole hours or days during platform incidents while the source tables are complete.
  Always confirm a gap by counting the table itself (`group every 1h select count()`).
- **Compare whole weeks.** Weekends and holidays are quiet; a 7-day window against a 21-day
  baseline avoids false "drops".
- **Autoscaling churn.** Cloud instances with auto-generated names (e.g. `ip-10-1-2-3`,
  `vmss…000001`) come and go; a missing one is usually scaled in, not broken. Group by name
  pattern before flagging.
- **Counter-listed tables can be unqueryable** (the counter lists them, a query errors or
  returns nothing). Report them separately rather than as stopped.
- **Whole-hour lag is a clock, not a delay.** A lag that sits on a whole number of hours, every
  hour, is a sender putting local time in a UTC field (time-zone misconfiguration), not
  ingestion delay. Say which.
- **`devo.collector.metric.input_stat` can read 0 for inputs that are flowing.** Confirm on the
  destination table before calling an input dead.
- **`collectors.out` is noisy.** Some warnings are benign and very frequent; normalise the
  messages (strip ids, numbers, timestamps), group them, and look at errors and at collectors
  that went silent.
- **Batchy sources** (Microsoft 365, some cloud APIs) arrive in bursts; check `devo.py lag` before
  calling a recent hour missing.

### Everything a user did in a period (multi-source sweep)
`devo.py activity <surname> --out-dir <dir>` runs the whole sweep in parallel (sources in
`references/hints/activity-sources.json`; sweep recipes, validated against the domain on first
use), writes `<source>.jsonl` plus `summary.json`, re-aggregates
chunked results, and prints rows, events, entities seen, first/last and notes per source. Grouped
rows carry `first_event`/`last_event` (the event-time field per family, table-guide.md) next to
`first`/`last` (ingestion). Then run it again with `--graph-ids <object ids>` (it suggests them) for
the Graph pass.

**Account naming: discover it, then record it.** Account formats differ per organisation
(daily vs admin accounts, on-prem AD vs Entra, GitHub logins, shared local Linux accounts), so
find them before sweeping:
- Entra sign-ins (`properties_userPrincipalName`) and M365 `UserId` show the daily UPN format;
  PIM, Azure portal sign-ins and Graph show any separate cloud admin accounts.
- Windows logons (`TargetUserName`/`SubjectUserName`) and Sysmon `User` (`DOMAIN\user`) show
  on-prem accounts, including admin accounts that may have no Entra activity at all.
- GitHub audit (`actor`, `external_identity_username`) shows how GitHub logins map to UPNs.
- `box.unix` `message` shows Linux accounts; shared local accounts tie to a person only through
  the Zscaler session (host coverage check, step 3).

Confirm the patterns on more than one person, then record them so later sweeps use them:
`devo.py cache naming set '<templates>'`, with templates built from the placeholders `{upn}`
(the full UPN), `{local}` (the part before `@`), `{first}`, `{last}` and `{f}` (first initial),
e.g. `'{upn},{local},adm-{f}{last},{first}-{last}'`. Add anything the templates can't express
(where each form appears, exceptions, shared accounts) with `devo.py cache note add '...'`.

**One person, many identifiers.** A sweep on one form misses the others: a Windows filter on an
admin-account form misses every event of the person's daily account. Give every variant at once:
- `--terms <variant1>,<variant2>,<variant3>` (or repeat `--term`): all terms are OR'd in every
  source, and the summary has a "matched term (events)" column per source plus a list of terms
  that matched nothing;
- `--expand` with the UPN derives the variants from the recorded naming templates; check the
  "matched term" column to see which forms matched in which sources;
- the bare surname (positional term) is the broad net; it also catches other people with that surname.
Sweep with the bare surname **and** the UPN: admin accounts often don't contain the full UPN, so a
UPN-only sweep misses them.
Entra object ids aren't derived: the sweep prints them for `--graph-ids`. To add the Graph pass
to an existing out-dir without re-running the sweep, use `--graph-only --graph-ids <ids>`.

The sources are in `references/hints/activity-sources.json` (sweep recipes, validated against the
domain on first use): `devo.py activity <surname>` runs the user sources, `--by ip <address>` the
IP sources, `--by host <name>` the host sources. They cover Entra sign-ins (`cloud.azure.ad.signin`,
non-interactive, service principal, risk, audit), Graph (second pass with `--graph-ids`), Microsoft
365 (Teams, SharePoint, OneDrive, Exchange, Copilot, …), Windows (security with the client address
from `Message`, Sysmon, PowerShell incl. `.invalid`), Defender, Zscaler, Fortinet, Linux SSH, AWS
(SSO identities and the main service tables), GitHub, 1Password, SentinelOne, Qualys and Devo
alerts. Sources whose tables have no data in the domain return nothing; read a source's `note`
for its caveats. To change one, edit the JSON (check fields with `devo.py fields <table>` first)
and re-run it.

**Timeline.** `devo.py timeline <dir> --tz <Area/City>` merges the sweep into one sorted list
(`timeline.json`: `t_utc`, `t_local`, source, table, actor, action, target, detail, ip, host) plus a
per-day text summary (`timeline.txt`), using each family's event-time field
(`references/hints/event-time.json`) and dropping repeated records (SharePoint/OneDrive `Id`,
Entra `properties_id` and the audit `tenantId` copy, Defender `device_id`+`report_id`+`timestamp`).
It is the input for an HTML timeline report. From a normal sweep each grouped row becomes one event
(with a count and first..last); run the sweep with `--rows` for one event per record (slower and
much larger). Times whose source has no event-time field (Linux, Devo's own tables) are ingestion
times; the timeline says which. Back-filled events whose event time falls before the window are
dropped (`--keep-outside` keeps them), and sources flagged as copies of another source count once.

**Variants and other queries.** For queries the sweep doesn't cover, write a `batch` spec (JSON
list or JSON Lines, one job per query) instead of a shell script: `devo.py batch spec.jsonl --out-dir
<scratchpad>/sweep --vars user=jsmith,from=7d`. A job can hold its query inline (`query`) or in a `.linq` file next to the spec (`query_file`), which
avoids JSON-escaping quotes and regexes. Each job writes `<name>.jsonl` and `<name>.log`, and a
table of rows / limit reached / error / duration closes the run (exit 2 if any job failed).
`{user}`-style placeholders in any field come from `--vars`; LINQ sets such as `{4624, 4625}` are
left alone:
```json
[
 {"name": "signins", "query": "from cloud.azure.ad.signin where weakhas(properties_userPrincipalName, \"{user}\") group by properties_ipAddress, properties_appDisplayName select count() as n", "from": "{from}"},
 {"name": "sysmon", "query": "from box.win_nxlog.sysmon where weakhas(User, \"{user}\") group by host, User, EventID, Image select count() as n", "from": "{from}", "chunk": "3h"},
 {"name": "teams_rows", "query": "from cloud.office365.management.microsoftteams where weakhas(UserId, \"{user}\") select eventdate, Operation, message", "from": "{from}", "limit": 10000}
]
```
This avoids the shell traps hit by hand-written sweeps: zsh not splitting `$FLAGS`, macOS `xargs -I`
("command line cannot be assembled"), and backticks in an unquoted heredoc being run as commands.
Summarise the outputs with Python (or `devo.py query … --stats` for one query), and list the jobs that
returned 0 rows.

Chunked or split `group by` results are merged automatically by `query` and `batch` (counts and
sums added, min/max combined, `hllppcount` = the largest per-window value, so a lower bound;
`--no-merge` keeps the per-window rows). Both pre-check field names against the cached schema, so
a misspelt field fails fast, and warn about reserved words used as aliases (`count() as by` fails
with a bare "Query parsing error" that doesn't name the alias).

Reading the results:
- **Your own calls show up.** If the API token belongs to the subject, their Devo API/console
  usage (`siem.logtrust.web.*`, SecOps/API audit tables) includes the investigation's own
  queries. Exclude those rows (by time and user agent) before describing what the person did.
- **Sanity-check generated sources.** Sweep recipes built on first use can match too broadly
  (a short term inside unrelated fields) or too narrowly; read a few raw rows from any source
  whose counts look surprising. `devo.py activity <term> --no-auto` skips the generated sources and
  runs only the curated ones.
- **PowerShell script blocks (4104) can match a name, not a person.** A person's name in a script
  header or author comment (`# Author: …`) matches on every host that runs the script, fleet-wide.
  Read the matched `ScriptBlockText` before calling it their activity; their own sessions show
  their account in the host's logons and Sysmon `User`.
- **EDR management activity under a person can be an integration.** A SOAR, MDR or ticketing
  integration that uses an API token generated by that person logs its actions under their name.
  Check the activity's description and source (API vs console) and its shape (steady polling,
  out-of-hours, bulk identical actions) before describing it as interactive work
  (table-guide/cloud-tools.md, SentinelOne).
- **GitHub:** `workflows.created_workflow_run` / `completed_workflow_run` with `event = schedule`
  and `actor_ip = 127.0.0.6` are **scheduled workflows attributed to their owner**, not
  interactive activity.
- **Microsoft service sign-ins:** non-interactive sign-ins by Microsoft first-party services
  (e.g. Teams back-end apps) can come from Microsoft-owned IPs that no other account uses.
  Baseline them over 7 days before flagging them.
- **Exchange:** `cloud.office365.management.exchange` can arrive in batches, days behind at times
  and minutes behind at others; run `devo.py lag --tables exchange` and say how recent its newest
  record is before concluding anything about email.
- **Group-membership enumeration** (e.g. a 4798 on an admin host) with the machine account as
  the subject is the system enumerating groups, not a logon.
- **Microsoft 365 lag varies** from minutes to days (`devo.py lag`); for "today" questions, quote
  the table's newest event time and say what may still be missing.

### Is something scanning?
Internal sources touching many hosts or ports per 10 minutes:
```linq
from firewall.fortinet.traffic.forward
where isprivate(srcIp)
group every 10m by srcIp
select count() as n, hllppcount(dstIp) as dst_hosts, hllppcount(dstPort) as dst_ports
where dst_hosts > 100 or dst_ports > 50
```
Before calling it hostile, check whether the source is a known scanner (Qualys appliance, IT
tooling): scheduled scans repeat at the same time every day, so compare the same window on
previous days.

### Host
Process creation on a host (Sysmon event 1), rare parents or command lines first:
```linq
from box.win_nxlog.sysmon
where EventID = 1, weakhas(host, "HOST01")
group by ParentImage, Image, User
select count() as n, min(eventdate) as first_seen
```

Network connections from a host (Sysmon event 3):
```linq
from box.win_nxlog.sysmon
where EventID = 3, weakhas(host, "HOST01")
group by Image, DestinationIp, DestinationPort, DestinationHostname
select count() as n
```

PowerShell script blocks on a host:
```linq
from box.win_nxlog.powershell
where EventID = 4104, weakhas(host, "HOST01")
select eventdate, host, ScriptBlockText
```

### Host activity details
True source of a Windows logon. The client address always comes from `Message` (in some NxLog
deployments `IpAddress` is the reporting server's own IP; check):
```linq
from box.win_nxlog.security
where EventID = 4624, weakhas(TargetUserName, "jsmith")
select peek(Message, re("Source Network Address:\\s*([^\\r\\n\\t]+)"), 1) as src,
  peek(Message, re("Workstation Name:\\s*([^\\r\\n\\t]+)"), 1) as wks,
  peek(Message, re("Logon Type:\\s*(\\d+)"), 1) as lt
group by host, src, wks, lt, AuthenticationPackageName
select count() as n, min(eventdate) as first, max(eventdate) as last
```

Linux logins, sudo and su on a host. Summarise first with
`group by application, appName, type select count() as n` (`appName` is the clean program name;
`application` includes the PID):
```linq
from box.unix
where weakhas(machine, "HOST01"), has(appName, "sshd", "sshd-session", "sudo", "su", "bash", "systemd-logind", "CRON")
select eventdate, appName, user, srcUser, srcIp, cmd, message
```
Only logins and sudo are logged; commands run as root aren't. `su -l … on none` is a
non-interactive su from a root process. The account and source IP are in `message`.

Scheduled task created or updated. `TaskContent` is HTML-escaped (`&lt;`); `Message` has the
readable XML, including `<Command>`, `<Arguments>`, `<UserId>` (S-1-5-18 = SYSTEM),
`<Description>` and `<StartBoundary>`. 4698 means registered and can't tell new from
re-registered:
```linq
from box.win_nxlog.security
where weakhas(host, "HOST01"), EventID in {4698, 4702}
select eventdate, timestamp, EventID, SubjectUserName, TaskName, Message
```

One user's processes, files and network on a host (Sysmon `User` is `DOMAIN\user`):
```linq
from box.win_nxlog.sysmon
where weakhas(host, "HOST01"), weakhas(User, "jsmith")
select eventdate, EventID, Image, CommandLine, ParentImage, ParentCommandLine,
  DestinationIp, DestinationPort, DestinationHostname, TargetFilename
```

PowerShell 4104: most blocks are module auto-load boilerplate. Drop blocks containing
`__cmdletization` or `Export-ModuleMember` client-side before reading. Depending on the
logging policy, only module loads may be captured, not the commands typed.

### File hash / process
```linq
from box.win_nxlog.sysmon
where weakhas(Hashes, "d41d8cd98f00b204e9800998ecf8427e")
group by host, Image, User
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

SentinelOne threats (host, user, classification, verdict):
```linq
from edr.sentinelone.agent.threats
select eventdate, agentRealtimeInfo__agentComputerName, agentDetectionInfo__agentLastLoggedInUserName,
  threatInfo__threatName, threatInfo__classification, threatInfo__confidenceLevel,
  threatInfo__mitigationStatus, threatInfo__analystVerdict, threatInfo__incidentStatus,
  threatInfo__filePath, threatInfo__sha1
```

### Domain name
DNS lookups of a domain and who asked (`question_dot` is the dotted name). The filter on
`context`/`send_receive`/`query_response` keeps one row per client query. Without it each query
is counted several times:
```linq
from dns.windows
where context = "PACKET", send_receive = "Rcv", query_response != "R", weakhas(question_dot, "example.com")
group by remote_ip, question_dot, question_type
select count() as n, min(eventdate) as first_seen
```

Fortinet `url`, `dstHost` and `user` are empty unless the firewall does web filtering (check
with `devo.py fields firewall.fortinet.traffic.forward`). If they are, a domain can't be matched
in firewall logs directly: resolve it to IPs with Sysmon EventID 22 (`QueryName`/`QueryResults`
are parsed from `Message`; `dns.windows` records no answers) and match those IPs as `dstIp`
(`table-guide/windows-dns.md`). Where a secure web gateway such as Zscaler carries web traffic,
search its tables too.

### AWS principal
```linq
from cloud.aws.cloudtrail.iam
where weakhas(userIdentity_arn, "alice")
group by eventName, sourceIPAddress, errorCode
select count() as n
```
IAM changes (write operations) across all accounts. Tables differ per service, so check the
schema: `readOnly` exists in some CloudTrail tables but not in `cloud.aws.cloudtrail.iam`:
```linq
from cloud.aws.cloudtrail.iam
where eventName ~ re("^(Create|Delete|Attach|Detach|Put|Update|Add|Remove|Tag|Untag)")
group by ACCID, userIdentity_arn, eventName
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
New access keys and users only: `where eventName in {"CreateAccessKey", "CreateUser", "CreateLoginProfile"}`.
Failed calls across a service: add `where isnotnull(errorCode)`. Only use
`from cloud.aws.cloudtrail` (all services) with a short window, because it is slow.

### Baseline: is this new?
Run the same pivot over the previous 7 days (`--from 7d --to 1d`) and compare. First-seen
checks are the strongest signal. Example, the first time a user logged on from each client address:
```linq
from box.win_nxlog.security
where EventID = 4624, weakhas(TargetUserName, "alice")
select peek(Message, re("(?:Source Network Address|Client Address|Source Address|Network Address):\\s*(?:::ffff:)?([^\\r\\n\\t]+)"), 1) as src
group by src
select min(eventdate) as first_seen, count() as n
```

## 4. Recipes by alert type

- **EDR / SentinelOne threat.** Read `threatInfo__*` in extra data (classification, threat
  name, mitigation status, analyst verdict, incident status). Check the threats table for other
  hosts with the same hash or threat name. Run the host process and network pivots (Sysmon)
  around the detection time. Check the logged-in user's sign-ins. Mitigated plus a known PUA
  or benign tool usually means FP/benign; unmitigated or spreading means escalate.
- **Risky / suspicious sign-in (Entra ID).** Compare country, IP, app, client and user agent
  with the user's 7-day baseline. Check `properties_status_errorCode` (int, 0 = success; `resultType` is often blank), conditional access and MFA
  details. Look for impossible travel (two countries within a short window) and for M365
  activity from the same IP afterwards.
- **Entra ID sign-in failures: separate interrupts from real failures.** Most non-zero
  error codes (`properties_status_errorCode`, int4, 0 = success; don't use `resultType`, which is
  often blank) are normal interrupts, not attacks. The bulk are typically:
  50074/50076/50079 (MFA required), 50078, 50097 (device auth), 50140 (keep-me-signed-in
  prompt), 50058 and 70043/70044/700082 (session/token expired), and 53000/530003/53003/53005
  (conditional access / device compliance blocks: policy, not credentials). The ones that point
  to credential attacks are 50126 (bad username or password), 50053 (account locked, including
  smart lockout), 50057/500571 (account disabled), 50034/50059 (user or tenant not found) and
  50055 (password expired). Report the two groups separately.
- **"Unusual country" needs a baseline.** Build one from successes over the previous ~30 days
  (`--from 33d --to 3d`): per user where volume allows, otherwise across the tenant. Group by
  `properties_location_countryOrRegion` with `select count() as n, hllppcount(properties_userPrincipalName) as users`
  and flag countries that are new for that user or rare for the tenant. Several days of
  `cloud.azure.ad.noninteractive_user_signin` can take minutes (so set the Bash timeout or run it
  in the background); the interactive table is much faster.
- **Entra role assignment / PIM (e.g. `SecOpsAzureUserAddedToRoleNonPIM`).** See the
  subsection below: this rule false-positives on every PIM activation of a non-Administrator role.
- **Privileged grant (who was made admin?).** See "Privileged grants (Entra, Azure RBAC, AD)"
  below: Entra role and PIM operations, Azure role assignments, AD privileged-group changes.
- **Brute force / password spray.** See the playbook subsection below. In short: count
  failures per source and per user (`EventID = 4625`, or `properties_status_errorCode in {50126, 50053}`
  for Entra). Many users from one IP is a spray; many IPs against one user is a brute force.
  Most important: check whether any success follows from the same source.
- **File malware in SharePoint/OneDrive.** See the subsection below.
- **Suspicious PowerShell / process.** Decode the command line (look for `-enc`), check the
  parent process, and check network connections and file writes from the same process GUID
  or host. Search other hosts for the same command line or hash.
- **AWS API anomaly.** Identify the principal (`userIdentity_arn`, access key), the source
  IP and user agent, and whether the calls were read-only. Look for privilege changes
  (`iam` `Attach*Policy`, `CreateAccessKey`), for disabled logging (`cloudtrail`
  `StopLogging`) and for errors (`AccessDenied` bursts).
- **Firewall / network.** Check the destination's reputation context (country, port,
  `appCat`), bytes out vs in, whether the traffic was allowed (`action`), and which internal
  host initiated it. Then pivot to that host.

### Entra role assignment / PIM (e.g. `SecOpsAzureUserAddedToRoleNonPIM`)
**The false-positive mechanism.** When a user self-activates an eligible role in PIM, the audit
log gets three kinds of row:
- `Add member to role requested (PIM activation)` and `… completed (PIM activation)`: logged by
  service `PIM`, with `initiatedBy_user` = the user.
- A plain `Add member to role`: logged by service `Core Directory`, with
  `initiatedBy_app_displayName` = `MS-PIM` and `initiatedBy_user` **null**.

The detection only excludes `endswith(operationName, "PIM activation)")`, so the MS-PIM write
fires it for every PIM activation of a non-Administrator role. That's also why the alert's "initiated by" fields are blank. Draft a tuning suggestion for
the user (the skill can't edit definitions), minding the null trap:
`isnull(properties_initiatedBy_app_displayName) or properties_initiatedBy_app_displayName != "MS-PIM"`
(the rule edit itself wasn't tested). Rules on this table also fire **in pairs**: each audit
event is ingested twice (one copy with `tenantId`/`region` set, one with them null or `-`, which
also lacks `properties_id`) where two collectors feed it; check whether the domain's table
does. Count on the `tenantId` copy (`isnotnull(tenantId), tenantId != "-"`). A few correlation
ids can appear only in the other copy, so for a single event check both.

Checklist:
1. **Reproduce** around `eventdate`:
   ```linq
   from cloud.azure.ad.audit
   where startswith(operationName, "Add member to role")
   select eventdate, operationName, tenantId, region, correlationId, properties_loggedByService, properties_result,
     properties_initiatedBy_user_userPrincipalName, properties_initiatedBy_app_displayName,
     properties_targetResources, properties_additionalDetails
   ```
2. **Parse `properties_additionalDetails` client-side** (pull rows with `--format jsonl`). It's a
   JSON list of `{key, value}`. Useful keys:
   - `AuditType` (`CreateRequestRoleActivation` / `ActivateRole`)
   - `Justification`
   - `StartTime` / `ExpirationTime` (the activation window)
   - `IsAuthenticatedWithMfa`, `IsActivationRequireApproval`
   - `ipaddr`, `UserAgent`
   - `oid` (the user's object id, for Graph)
   - `RoleAssignmentRequestId`

   The role name: on PIM rows it's `targetResources[0]` (type Role). On Core Directory rows
   `targetResources[0]` is the *user*, and the role is in its `modifiedProperties`
   (`Role.DisplayName`).
3. **Baseline the user's PIM activations.** `jqeval` values come back JSON-quoted
   (`"\"Directory Writers\""`):
   ```linq
   from cloud.azure.ad.audit
   where weakhas(properties_initiatedBy_user_userPrincipalName, "jsmith"), properties_loggedByService = "PIM"
   select jqeval(jqcompile(".[0].displayName"), properties_targetResources) as role
   group by operationName, role
   select count() as n, min(eventdate) as first, max(eventdate) as last
   ```
   Earlier alerts for the same rule (`extraData` is URL-encoded, e.g. `Directory+Writers`):
   ```linq
   from siem.logtrust.alert.info
   where context -> "SecOpsAzureUserAddedToRoleNonPIM"
   select eventdate, alertId, extraData
   ```
4. **What did the user do with the role?**
   - Directory writes:
     ```linq
     from cloud.azure.ad.audit
     where weakhas(properties_initiatedBy_user_userPrincipalName, "jsmith")
     select eventdate, properties_initiatedBy_user_userPrincipalName as upn, operationName,
       properties_loggedByService as svc, properties_result as result,
       jqeval(jqcompile(".[0].displayName"), properties_targetResources) as target0
     ```
   - Changes that mention the user, by anyone (`stringify`, not `str`, for JSON fields):
     ```linq
     from cloud.azure.ad.audit
     where weakhas(stringify(properties_targetResources), "jsmith")
     group by operationName
     select count() as n
     ```
   - Graph API calls, with `--chunk 1h`. The object id comes from sign-in `properties_userId`
     or `oid` in `additionalDetails`; user ids are stored **with quote marks**, so use `->`:
     ```linq
     from cloud.azure.ad.microsoft_graph_activity_logs
     where properties__user_id -> "<object-id>"
     group by properties__request_method, properties__request_uri, properties__response_status_code,
       properties__app_id, properties__ip_address_str
     select count() as n, min(eventdate) as first, max(eventdate) as last
     ```
     Portal use shows GETs, `$batch` POSTs, `estimateAccess`/`checkAccess` POSTs (read-only) and a
     `roleAssignmentScheduleRequests` POST (the activation itself). Some calls come from
     Microsoft-side IPs acting for the portal. `$batch` bodies aren't visible, so confirm "no
     writes" from the audit log. Normalise GUIDs in URIs client-side before grouping.
5. **Sign-ins around the activation** (interactive and non-interactive) against a 30-day IP and
   country baseline (User pivots above).

### Privileged grants (Entra, Azure RBAC, AD)
"Who was given admin rights?" needs three sources: Entra roles (audit log), Azure resource roles
(Activity Log, or PIM when it went through PIM) and on-prem AD groups (Windows security log).
Say in the answer which of them the domain collects.

**Start with the spec and `grants`** (`<base>` is the skill's base directory):
```
devo.py batch <base>/references/specs/privileged-grants.jsonl --vars from=30d --out-dir <scratchpad>/grants
devo.py grants <scratchpad>/grants
```
`grants` reads that directory offline: Entra and PIM role changes classified (activation,
permanent active via PIM, eligible, direct non-PIM, removals, failures), permanent grants paired
with their removal, flags (privileged role, self-grant, service account, no approval), and AD
privileged-group changes with policy re-adds and domain joins collapsed and SIDs resolved. The
sections below are what it does, and how to go further by hand.

**Entra roles.** `cloud.azure.ad.audit`, on one copy (`isnotnull(tenantId), tenantId != "-"`, then
de-duplicate on `properties_id`; entra-graph.md). Filter on `properties_category`, not the top-level
`category` (that reads `AuditLogs` on the Event Hub copy). `RoleManagement` holds directory roles;
`ResourceManagement` holds PIM for Azure resources and groups. First list what exists:
```linq
from cloud.azure.ad.audit
where isnotnull(tenantId), tenantId != "-", properties_category in {"RoleManagement", "ResourceManagement"}
group by properties_category, properties_loggedByService, operationName, properties_result, properties_resultReason
select count() as n, min(eventdate) as first, max(eventdate) as last
```
The PIM operation names (service `PIM`; each has a `requested` row and a `completed` row):

| `operationName` | Meaning |
|---|---|
| `Add member to role requested/completed (PIM activation)` | A user activated an eligible role (self-service, time-limited). The normal path |
| `Add member to role in PIM completed (timebound)` | An admin made a time-bound **active** assignment |
| `Add member to role in PIM completed (permanent)` | An admin made a **permanent active** assignment through PIM: no activation, approval or expiry from then on. Always worth a look |
| `Add eligible member to role in PIM completed (permanent)` / `(timebound)` | An admin made someone eligible (they still have to activate); `requested (renew)` is a renewal |
| `Add member to role outside of PIM (permanent)` | PIM recording an assignment made directly in the directory, not through PIM |
| `Remove member from role (PIM activation expired)`, `Remove member from role requested/completed (PIM deactivate)` | An activation ended (expiry or the user deactivated) |
| `Remove member from role in PIM completed (permanent/timebound)`, `Remove eligible member from role in PIM completed (…)`, `Remove permanent direct role assignment` | An admin removed an assignment or eligibility |
| `Process role removal request` | A removal request was processed (it can fail, e.g. `ActiveDurationTooShort`) |

- **Failures** carry the reason in `properties_resultReason`: `RoleAssignmentExists` (already
  assigned), `RoleAssignmentRequestPolicyValidationFailed` (the request broke the role's policy,
  e.g. missing justification or MFA), or "Attempted to perform an unauthorized operation."
  **On PIM success rows `properties_resultReason` is not empty either**: it carries the
  requester's justification text, so read it as the reason given, not as an error.
- **Approval and justification** are in `properties_additionalDetails` (a `{key, value}` list;
  parse client-side): `Justification`, `IsActivationRequireApproval`, `IsAuthenticatedWithMfa`,
  `StartTime`/`ExpirationTime`, `ipaddr`, `UserAgent`, `RoleAssignmentRequestId`. A permanent
  assignment has no expiry.
- **`IsAuthenticatedWithMfa` can be missing or null**, notably on PIM-for-Azure-resources rows.
  Null means "not recorded", not "no MFA": check the activator's sign-ins around that time
  (`properties_mfaDetail_authMethod`, `properties_mfaDetail_authDetail`) before flagging it.
- **Entra role or Azure RBAC?** Both go through PIM and look alike. A role on an Azure resource
  has a scope path in the target ids or `displayName` of `properties_targetResources`
  (`/subscriptions/<id>/…`, or `/providers/Microsoft.Management/managementGroups/<name>`);
  an Entra directory role does not (its scope is `/` or an administrative unit). Classify on that
  before counting "Global Administrator"-style grants.
- **Who and what.** The actor is `properties_initiatedBy_user_userPrincipalName` (or `…_app_…`). On
  PIM rows `properties_targetResources` is a list: the `Role` entry first (`.[0].displayName`), and
  the member is the entry of type `User` (or `Group`/`ServicePrincipal`); pull it with
  `stringify(properties_targetResources)` and parse client-side.
- **Direct (non-PIM) grants** are `Core Directory` rows (`Add member to role`, `Add eligible member
  to role`) whose initiator is a user or app **other than `MS-PIM`** (MS-PIM writes the Core
  Directory copy of every PIM change; see the PIM section above for the null trap):
  ```linq
  from cloud.azure.ad.audit
  where isnotnull(tenantId), tenantId != "-", properties_loggedByService = "Core Directory",
    operationName in {"Add member to role", "Add eligible member to role"}
  where isnull(properties_initiatedBy_app_displayName) or properties_initiatedBy_app_displayName != "MS-PIM"
  select stringify(properties_targetResources) as targets
  group by operationName, properties_initiatedBy_user_userPrincipalName, properties_initiatedBy_app_displayName, targets
  select count() as n, min(eventdate) as first, max(eventdate) as last
  ```

**Azure RBAC (subscriptions, resource groups, resources).** Direct role assignments are in the
Azure Activity Log (table-catalogue.md: `cloud.azure.activity.events`; check `devo.py tables
--grep azure` for the domain's name and `devo.py fields` for its operation field), operation
`Microsoft.Authorization/roleAssignments/write` (and `/delete`). Defender XDR `CloudAuditEvents`
streamed into a catch-all table (e.g. `cloud.azure.others.events`, category
`AdvancedHunting-CloudAuditEvents`) can carry the same operations when the subscription is
connected. There the top-level `operationName` is the Event Hub verb (`Publish`), not the
operation: the real operation and its source are inside the `properties` JSON
(`.OperationName`, `.DataSource`). **Check `DataSource` first**, over the whole window: it may
cover only some services (e.g. only one resource provider), in which case role assignments are
simply not there, and a substring filter over a large catch-all table is slow:
```linq
from cloud.azure.others.events
where category = "AdvancedHunting-CloudAuditEvents"
select str(jqeval(jqcompile(".DataSource"), properties)) as data_source,
  str(jqeval(jqcompile(".OperationName"), properties)) as op
group by data_source
select count() as n, sizedistinct(op) as operations
```
(`str()` gives the bare value; `stringify()` keeps the JSON quotes.) Only when an ARM source is
listed, filter on `op` (`weakhas(op, "roleAssignments")`), with `--chunk 1d` over long windows.
If the domain has neither, **RBAC changes are visible only when
they go through PIM** (`properties_category = "ResourceManagement"` above): say so explicitly in the
answer rather than reporting "no changes".

**On-prem AD.** Group membership events in `box.win_nxlog.security` (table-guide/windows-dns.md):
4728/4729 global groups, 4732/4733 local and domain-local groups, 4756/4757 universal groups,
against the privileged groups:
```linq
from box.win_nxlog.security
where EventID in {4728, 4729, 4732, 4733, 4756, 4757},
  lower(TargetUserName) in {"domain admins", "enterprise admins", "schema admins", "administrators", "account operators", "backup operators", "server operators", "dnsadmins", "group policy creator owners"}
group by host, EventID, TargetUserName, SubjectUserName, MemberName, MemberSid
select count() as n, min(eventdate) as first, max(eventdate) as last
```
- `MemberName` is often `-` with only `MemberSid`. Resolve the SID through 4624 `TargetUserSid`
  (`group by TargetUserSid, TargetDomainName, TargetUserName`) or 4720/4738 `TargetSid`.
- **Recurring re-adds by the machine account** (`SubjectUserName` ending in `$`, the same member
  added and removed again and again on many hosts) are Restricted Groups / GPO / MDM local-group
  policy re-applying, not a person granting rights. Look for the exceptions: a person as the
  subject, or a member that is not in the policy.
- **A domain join** adds Domain Admins (SID ending `-512`) to the computer's local Administrators
  group (4732 by the machine account at join time): expected once per host.
- Server-local groups are logged by each member server; check that the server forwards security
  logs (`devo.py coverage HOST01`) before saying nothing changed there.
- **Local accounts on a server.** A 4720 (account created) on a member server whose
  `SubjectDomainName` is the server itself (not the domain), followed by a 4732 adding that new
  account to the local Administrators group, is a local admin account being made outside AD:
  worth flagging even when it is an installer or an admin's shortcut. Match the 4732 `MemberSid`
  to the 4720 `TargetSid`.
- **Renamed built-in Administrator.** A subject whose SID (`SubjectUserSid`) ends in `-500` is the built-in
  Administrator (RID 500), whatever its `SubjectUserName` says after a rename. That account acting
  as subject (creating accounts, changing groups) is worth flagging: it bypasses per-person
  accountability and is often excluded from lockout.

### Brute force / password spray (playbook)
**Start with the spec and `creds`.** Stage 1 is a ready-made batch spec; stage 2 is generated from
its results:
```
devo.py batch <base>/references/specs/credential-attacks.jsonl --vars from=3d --out-dir <scratchpad>/cred
devo.py creds <scratchpad>/cred --exclude 198.51.100.4,198.51.100.5     # own egress / ZTNA / NAT IPs
devo.py batch <scratchpad>/cred/stage2.jsonl --out-dir <scratchpad>/cred/stage2
devo.py creds <scratchpad>/cred --stage2-dir <scratchpad>/cred/stage2   # interpret the successes
devo.py batch <scratchpad>/cred/stage2/stage3.jsonl --out-dir <scratchpad>/cred/stage2/stage3   # when written
devo.py creds <scratchpad>/cred --stage2-dir <scratchpad>/cred/stage2   # again, now with those baselines
```
- Stage 1 (`<base>` is the skill's base directory) collects Entra credential failures (interactive
  and non-interactive), Identity Protection risk detections, Windows 4625, Windows 4771/4776 and
  Linux sshd failures. Every job groups by IP + account (+ code), so the summary is exact.
- `creds` reads that directory offline and prints: a **top public IPs by failures** table (with a
  marker on IPs that are the organisation's own egress), spray candidates (one IP, many accounts;
  `--min-users`), distributed brute force (one account, many IPs and countries; `--min-ips`),
  50057 (disabled accounts) separately, and Windows/Linux failure sources split public/private,
  with anonymous NTLM noise (blank account, `WORKSTATION`, user-does-not-exist; step 7) counted
  apart from password guessing.
- **Shared egress is detected for you**: IPs that many accounts sign in from *successfully* (the
  spec's `entra_success_ip_users` job; `--egress-users`, default 10) are treated as own egress /
  NAT and left out of the spray list. `--keep-egress` keeps them; `--exclude` adds IPs it can't
  see (ZTNA, on-prem NAT that never reaches Entra).
- It writes `stage2.jsonl`: successes from the failing IPs **and** from the Identity Protection
  risk-detection IPs, in Entra interactive and non-interactive sign-ins, Linux sshd "Accepted" and
  Windows 4624 (`--window`, default 7d), plus a 30-day baseline of the targeted accounts when
  there are any.
- `creds <dir> --stage2-dir <dir>/stage2` interprets that output: for each success, the **same
  account** that failed from that IP or a **different** one, and whether the IP or range appears
  in the account's history **before the attack window** or is new. It writes `stage3.jsonl` (in the
  stage-2 directory) with the 30-day baselines of the *other* accounts that succeeded from
  attacking IPs; run it into `<stage2-dir>/stage3` and rerun the same command to read those hits
  against them (step 9).

The steps below are what the spec and `creds` do, and how to go further by hand.

1. **Exclude your own addresses first.** The organisation's egress, ZTNA and NAT IPs carry
   everyone's typos and expired passwords, so they top the per-IP list and look like a spray.
   Find them as public IPs with many *successful* users in Entra sign-ins, or as ZTNA client public
   IPs (`vpn.zscaler.access` `ClientPublicIp`). `creds` does the first automatically
   (`--egress-users`); pass the rest to `creds --exclude` (scale the threshold to the tenant's
   size):
   ```linq
   from cloud.azure.ad.signin
   where properties_status_errorCode = 0
   group by properties_ipAddress
   select hllppcount(properties_userPrincipalName) as users, hllppcount(properties_id) as signins
   where users > 20
   ```
2. **Entra failures.** Count distinct sign-in ids (`hllppcount(properties_id)` or `sizedistinct`,
   since rows can be duplicated) per user and per IP, on `cloud.azure.ad.signin` **and**
   `noninteractive_user_signin`, credential codes only:
   - 50126 bad username or password; 50053 locked (smart lockout). The correct password can be
     hidden behind a lockout: a 50053 after the right password still shows as a failure, so a
     lockout at the end of a run is not proof the attacker never had it.
   - 50057 (disabled account) is usually a leaver's devices or cached tokens retrying, not an
     attack; report it separately.
   - Non-interactive failures are dominated by codes that are not attacks: token expiry, MFA and
     other interrupts, device state (50078, 50173, 700082, 70043, 70008, 50074, 50076, 50097,
     50140, 500133). Leave them out; counting "all non-zero codes" turns every tenant into a spray.
   ```linq
   from cloud.azure.ad.signin
   where properties_status_errorCode in {50126, 50053}
   group by properties_ipAddress
   select hllppcount(properties_id) as fails, hllppcount(properties_userPrincipalName) as users,
     min(eventdate) as first, max(eventdate) as last
   ```
3. **Identity Protection detections** are a source in themselves:
   `cloud.azure.ad.user_risk_events` (risk event type `passwordSpray`, plus unfamiliar features,
   anonymous IP etc.) and the Entra/Defender alert tables (`devo.py tables | grep -i alert`).
4. **Shapes.**
   - Many users from one IP = spray.
   - Many IPs against one user = distributed brute force: count distinct IPs **per user**;
     per-IP thresholds miss it because each IP tries only a few times.
   - One attempt per IP from many countries, through scripted clients (PowerShell, CLI tools,
     legacy "Other clients" in `properties_clientAppUsed`, generic user agents), is the signature
     of distributed spray tooling rotating through proxies.
   - Low and slow: a few attempts per hour over days. Widen the window (`--from 7d`) and group
     `every 1d`.
5. **Distinct counts over chunks are lower bounds, except event ids.** A chunked or split query
   cannot merge distinct counts exactly. `hllppcount` of an event id field (e.g. `properties_id`,
   `Id`, `…RecordId`) is summed across chunks, which is exact because an event falls in one chunk
   only (a duplicate copy ingested in another chunk counts again); any
   other `hllppcount` field (users, IPs) is merged by taking the largest per-window value, so
   "distinct IPs per user" over a long window comes out too low. Group by user + IP (as the spec
   does) and count client-side:
   ```python
   import json, collections
   ips = collections.defaultdict(set)
   for f in ("entra_failures.jsonl", "entra_failures_noninteractive.jsonl"):
       for line in open(f"<scratchpad>/cred/{f}"):
           r = json.loads(line)
           ips[r["properties_userPrincipalName"].lower()].add(r["properties_ipAddress"])
   for user, s in sorted(ips.items(), key=lambda kv: -len(kv[1]))[:20]:
       print(len(s), user)
   ```
6. **Known false positives.**
   - ROPC/legacy-auth flows from shared cloud services (cloud print, scan-to-mail, older mail
     clients) can trigger `passwordSpray` detections: many users through the same provider IPs
     with stale passwords. Compare the user agent and app (`properties_appDisplayName`,
     `properties_clientAppUsed`) with a known service account on the same IPs before calling it an
     attack.
   - Firewall VPN "failure" rows from IKE/IPsec negotiation (e.g. Fortinet
     `firewall.fortinet.event.vpn` `action = "negotiate"` with `status` `negotiate_error`/`failure`
     and a `reason` such as "peer SA proposal not match local policy") are tunnel or proposal
     mismatches between two gateways, not user authentication. Leave them out of credential
     counts.
7. **Windows 4625** by true source (the client address `peek`ed from `Message`, §3 User), with
   `Status`/`SubStatus` and `AuthenticationPackageName`. A blank `TargetUserName` with
   `WorkstationName` "WORKSTATION", NTLM and SubStatus `0xc0000064` (user does not exist) is
   typically an anonymous NTLM client retry or a probe, not password guessing. Internal sources
   that are ZTNA connector IPs resolve to the client device through the ZTNA logs: match
   `ConnectorIP`/`ConnectorPort` in `vpn.zscaler.access` against the event's source IP and port
   (`Source Port` in `Message`), around the same time.
   - **Kerberos and NTLM on DCs:** 4771 (pre-auth failed) and 4776 (credential validation) may
     not be collected; check with a `group by EventID` on the DC before relying on their absence.
   - **Linux:** sshd "Failed password" / "Invalid user" lines in `box.unix` `message`
     (table-guide/network-linux.md).
8. **Is it already covered?** `devo.py alerts --by-def --from 7d` lists alert definitions with
   counts per status; check whether an existing detection fired on the same sources or accounts
   (and whether it was closed) before reporting it as new.
9. **Did any attempt succeed?** `stage2.jsonl` does this; by hand, build a second spec from the
   failing IPs and users with `field in {"203.0.113.10", "203.0.113.11"}` (quote IPs for string
   fields such as `properties_ipAddress`; unquoted they are ip4 literals and the query errors) and
   look for errorCode 0, 4624 or sshd "Accepted" from those sources or for those users. Then:
   - Compare any success with the user's baseline of countries and IPs over the previous 30 days
     (§3 Baseline).
   - A success from the same /24 as attacker traffic (but not the same IP) is not compromise by
     itself: VPN providers, mobile carriers and cloud ranges are shared. It counts only if that
     user's 30-day history doesn't already show the range, device and app.
   - A success from the exact attacking IP, after failures for the same user, is the finding:
     escalate it, with the sign-ins and activity that followed (§3 "Everything a user did").

### File malware in SharePoint/OneDrive
**Start with the spec:** `devo.py batch <base>/references/specs/file-malware.jsonl --vars
'file=<distinctive part of the file name>,sha256=<hex SHA-256 or none>,from=14d' --out-dir DIR`. It
lists `FileMalwareDetected` on both tables (whatever the file), the file's trail on each table by
`CreationTime`, Defender for Office detections, Teams and Exchange records mentioning the file,
endpoint file events by name or hash and EDR threats, each grouped (one `.jsonl` per job). Then
work through the steps below on those files.

0. **Sequence on `CreationTime`, not `eventdate`.** Microsoft 365 data can arrive in back-filled
   batches, hours or days late and out of order, so `eventdate` (ingestion) says nothing about
   whether the upload came before the share or the download. Build the upload / share / download
   trail on the record's own time,
   `parsedate(str(jsonparse(message)["CreationTime"]), "YYYY-MM-DD[T]HH:mm:ss", "UTC")` (UTC, no
   `Z`; table-guide.md "Event time per family"), and use `eventdate` only for "when it arrived in
   Devo" (and to size the query window: widen `--to` past the creation times you need). The same
   applies to the m365.md recipes that show `min(eventdate) as first_ingested`: those are ingestion
   times by design, not when the action happened.
1. **Detections on both tables.** `FileMalwareDetected` appears in
   `cloud.office365.management.sharepoint` **and** `cloud.office365.management.onedrive`; query
   both. Check whether the alert rule's source table covers its sibling: a rule on one misses the
   other.
2. **Defender for Office detections** in `cloud.office365.management.threatintelligence`
   (`AtpDetection` records, `DetectionMethod` such as Reputation, Safe Attachments, AntiMalware).
3. **Upload trail:** `FileUploaded` / `FileSyncUploadedFull` for the file (`ObjectId`,
   `SourceFileName`), with `ClientIP`, `UserAgent` and the device (`MachineId`/device name for
   sync uploads).
4. **Sharing and downloads:** `SharingSet`, `AddedToSecureLink`, `AnonymousLinkCreated`, then
   `FileDownloaded`, `FileSyncDownloadedFull`, `FileAccessed` by anyone other than the uploader.
5. **Endpoints:** check the EDR state (threats, agent present and healthy) of the uploader's and
   every downloader's device. With Defender Advanced Hunting (table-guide/defender.md, "File
   origin, hashes and alerts"):
   - `cloud.azure.ah.device_file_event` holds the file landing on the device: `file_name`,
     `folder_path`, `sha1`, `md5`, `sh_a256` (SHA-256), and for downloads the Mark-of-the-Web origin
     `file_origin_url` / `file_origin_referrer_url` (filled on a small fraction of `FileCreated` /
     `FileRenamed` rows only; `file_origin_ip` is usually empty). Match on `sh_a256` when the
     detection gives a SHA-256 (convert a base64 one to lowercase hex first). If you only have a
     SHA-1 or MD5, or the row has no hash, match on file name + device + a window around the
     `CreationTime` of the sync download, and say the match is weaker.
   - `device_process_event` (was it executed: `file_name`/`sh_a256` of the process, or as
     `init_process_*`) and `device_network_event` (what that process connected to, by
     `init_process_unique_id`) follow from there.
   - `alert_info` has no device field; devices and files of a Defender alert are in
     `alert_evidence` (`properties__device_name`, `properties__device_id`, `properties__sha256`),
     joined on `properties__alert_id`. Check the evidence fields are actually filled in the domain.
   - These tables are large: filter by device (`weakhas(device_name, "host01")`) and a short window
     around the event, then widen.
6. **Hashes differ between tables** (e.g. a base64 SHA-256 in `AtpDetection` vs hex in
   SharePoint/OneDrive); convert before joining (m365.md).

### Running union-table library detections on source tables
Many library detections (e.g. `SecOpsAuthPasswordSprayIp`) query `auth.all`, which is usually
far too slow for real windows (minutes for a few minutes of data). Keep the detection's logic and
thresholds and swap in the source tables. `auth.all` field → source field:

| `auth.all` | Windows `box.win_nxlog.security` | Entra `cloud.azure.ad.signin` / `noninteractive_user_signin` | Linux `box.unix` |
|---|---|---|---|
| failure (`result`) | `EventID = 4625` (success 4624) | `properties_status_errorCode in {50126, 50053}` (0 = success) | `action`/`message` (check values) |
| `user` / `username` | `TargetUserName` | `properties_userPrincipalName` | `user` |
| `source_ip` | client address `peek`ed from `Message` (`IpAddress` may be the reporting server) | `properties_ipAddress` | `srcIp` |
| `machine` / `hostname` | `host` / `WorkstationName` | `properties_deviceDetail_displayName` | `machine` |
| `application` | `LogonType`, `AuthenticationPackageName` | `properties_appDisplayName` | `application` |

Normalise user names before counting distinct users (the same person can appear as
`DOMAIN\user`, `user` and `user@domain`, for example via `lower()` and stripping the domain),
and drop MFA/interrupt codes, or they inflate "failures". Say in your report which adaptations you
made.

## 5. Time windows and volume control

- Start with ±30 min around the event, or the last 1 h. Widen to 24 h, then 7 d, only when
  the query is correct and cheap. Always aggregate (`group by … select count()`) before
  listing raw rows on busy tables.
- Prefer specific tables over union tables (`auth.all` is slow).
- For a precise window around an alert, use ISO times: `--from 2025-03-04T14:00Z --to 2025-03-04T15:00Z`.
- If a query hits the helper's timeout, first narrow the time range or filter earlier. When the
  question really needs a long range (e.g. 24 h on a busy Windows security table), raise
  `--timeout` and the Bash tool timeout together, or run it in the background with `--out`.

## 6. Verdict and drafted actions (report template)

Status, priority and tag changes are not implemented: present what you *would* set and let the
user act. The drafted comment can be posted with `devo.py comment <id> --title … --msg …`: preview
it, get the user's explicit approval of that exact text, then re-run with `--confirm`.

```
## Alert <id>: <definition name>
**Verdict:** True positive | Benign true positive | False positive | Inconclusive (confidence: high/medium/low)
**Severity assessment:** <your view vs the alert priority, and why>
**What happened:** 2–4 sentences, with times in UTC.
**Entities:** user(s), host(s), IP(s), hash(es), with the role of each.
**Evidence:**
- <query summary> (<table>, <window>) → <result / row count>
- ...
**Sources checked with no data:** <table (field, window)>, … (and any source that isn't collected at all)
**Scope:** other hosts/users/alerts affected, or "none found in <window>".
**Recommended actions:** containment / follow-up for the user or SOC.
**Drafted Devo update (not sent; the comment can be posted on approval):**
- Status: <100 Watched | 2 False positive | 300 Closed> (reason)
- Comment: "<one-paragraph analyst note>"
**Open questions / data gaps:** e.g. missing mail logs, need the EDR console.
```
