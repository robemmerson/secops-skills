# Table guide: what each table holds and how records link

Generic parser knowledge. Your domain may differ: confirm fields with `devo.py fields <table>` before relying on a detail.

Deep dives into the standard Devo table families. For each family: what a row is, the entity
fields (user / host / IP / time) with their format and case, action and outcome values, join keys,
quirks, speed, and linking recipes. Load only the family file you need:

| File | Tables | Read it for |
|---|---|---|
| `table-guide/windows-dns.md` | `box.win_nxlog.*` (security, sysmon, powershell, system, application, invalid), `dns.windows`, `box.all.win` | EventID field maps, logon sessions (`LogonId`), Sysmon process trees (`ProcessGuid`), PowerShell reassembly, Kerberos/NTLM, DNS → IP → traffic |
| `table-guide/entra-graph.md` | `cloud.azure.ad.*`, `cloud.azure.aadiam.*`, `cloud.azure.others.events` | which sign-in table is complete, sign-in ↔ session ↔ Graph ↔ risk ↔ audit joins, PIM, devices, impossible travel |
| `table-guide/m365.md` | `cloud.office365.management.*` (Teams, SharePoint, OneDrive, Exchange, Copilot, …), `cloud.office365.security.*` | **Teams conversation reconstruction**, file trails and sharing, Copilot resources, Exchange, ingestion lag and duplicates |
| `table-guide/defender.md` | `cloud.azure.ah.*` (Defender Advanced Hunting) | fields per table, process trees (`process_unique_id`), device ↔ IP, links to Sysmon and SentinelOne |
| `table-guide/network-linux.md` | `firewall.fortinet.*`, `vpn.zscaler.*`, `box.unix`, `box.stat.*`, `syslog.*` | Fortinet sessions and bytes, Zscaler user ↔ server, SSH session reconstruction, relay health |
| `table-guide/cloud-tools.md` | `cloud.aws.cloudtrail.*`, `vcs.github.*`, 1Password, `edr.sentinelone.*`, `vuln.qualys.*`, Devo platform tables | AWS SSO identity, per-service field differences, GitHub automation vs people, SentinelOne verdicts, Qualys host → detections, who touched a Devo alert |

Which tables exist in your domain: `devo.py tables` (cached live list); domain-specific notes:
`devo.py cache notes`. Field-level lookups without reading a file: `devo.py fields <table>`
(live-profiled and cached locally: populated fields, type, fill rate, pattern, case, role, enum
values) and `devo.py fields --role ip|user|host|join-id|… [--grep <tables>]` (every table/field
with that role).

## Entity resolution cheat-sheet

**Person ↔ accounts.** Search a distinctive part of the name (such as the surname) to catch every
account variant, or give `activity` every variant with `--terms` / `--expand`. **Confirm identity
by UPN domain or object id, never by display name**: a tenant can span several UPN domains, and
the same display name can belong to different people. `devo.py teams` refuses a term that matches
more than one account for this reason. Bridges between account forms:
- Entra object id (`properties_userId` in sign-ins) = Graph `properties__user_id` (stored with
  quote marks: use `->`) = M365 `UserKey`/object-GUID `UserId` forms.
- AWS SSO: the person's UPN is the session name in `userIdentity_arn`
  (`…/AWSReservedSSO_<set>_<hash>/<upn>`); `SAMLUser`/`IdentityCenterUser` rows have it in other
  fields (cloud-tools.md).
- GitHub: `external_identity_username` = the UPN (quoted in the enterprise table); `actor` =
  the GitHub login.
- 1Password `client__platform_name` = the device hostname, matching SentinelOne `computerName`.

**Person ↔ device ↔ IP.**
- Zscaler `vpn.zscaler.access`: `Username` (UPN) ↔ `ClientPrivateIp` (the client device's own IP,
  which can also appear as Fortinet `srcIp` when the device is on a LAN behind the firewall) ↔
  `ServerIP`/`ServerPort` (servers reached). `ConnectorIP` + `ConnectorPort` equal the
  "from <ip> port <port>" in the target server's sshd log, which ties a shared Linux account to the
  person. Other Zscaler tables may repeat the same records; check before counting across them.
- Windows: in some deployments the NxLog config overwrites `IpAddress` with the reporting host's
  own IP; check against `Message` before trusting it. A logon's client address is in `Message`
  (`peek`; windows-dns.md).
- Defender: `device_name` (not `machine`, the collector) ↔ `device_network_info` IPs ↔
  `device_info` logged-on users; only onboarded devices report.
- SentinelOne agents (`computerName`, `lastLoggedInUserName`, `lastIpToMgmt`), Qualys
  `vuln.qualys.hosts` (`ip`, `dns_fqdn`, `netbios`).

**Session and event chains.**
- Entra: `properties_sessionId` links an interactive sign-in to the non-interactive sign-ins
  after it; Graph `properties__sign_in_activity_id` = the sign-in's token id (its `properties_id`
  in another encoding); risk event `properties__requestId` = sign-in `properties_id`;
  `alerts.id` = risk event id. M365 `AppAccessContext.AADSessionId` = Entra `properties_sessionId`,
  which follows one session across Exchange, SharePoint and Teams.
- Windows: `TargetLogonId` (4624) = `SubjectLogonId`/`TargetLogonId` on later events on the same
  host = Sysmon `LogonId`; Sysmon `ProcessGuid` ↔ `ParentProcessGuid`; PowerShell 4104 PID (from
  `rawMessage`) → Sysmon process.
- Defender: `device_id` + `process_unique_id` ↔ `init_process_unique_id` across all `ah` tables.
- Fortinet: `devID` + `session` groups one connection's start / interim / final rows (bytes are
  cumulative: use the final row or `max()`).
- Linux: sshd pid groups one SSH session; auditd `ses` groups a login session, `msg2` ties the
  records of one event.
- Teams: conversation ids live in the raw `message` JSON (m365.md has the recipe and a Python
  timeline parser); a Teams file URL, URL-decoded, matches SharePoint/OneDrive `ObjectId`; Copilot
  `listItemUniqueId` = SharePoint `ListItemUniqueId`.

## Event time per family

`eventdate` is when Devo ingested the row. The record's own time is in a different field per family
(below). `devo.py lag` and `devo.py timeline` read the same table from
`references/hints/event-time.json`, and `activity` adds `first_event`/`last_event` from it.

| Family (tables) | Event-time field | Notes |
|---|---|---|
| Microsoft 365 (`cloud.office365.management.*`) | `CreationTime` inside `message` (`rawMessage` in `powerplatform`): `parsedate(str(jsonparse(message)["CreationTime"]), "YYYY-MM-DD[T]HH:mm:ss", "UTC")` | UTC without `Z`. Teams meetings/calls: `JoinTime`/`LeaveTime`, `StartTime`/`EndTime` (records are created hours later). Dedupe on `Id` |
| Windows (`box.win_nxlog.*`) | `timestamp` | = the host's `EventTime` converted to UTC (`EventTime` in `rawMessage` is the host's local time) |
| Windows DNS (`dns.windows`) | `serverdate` | can be blank on some rows |
| Fortinet (`firewall.fortinet.*`) | `serverdatetime` | `eventtime` is the same instant in ns |
| Entra sign-ins (`cloud.azure.ad.signin`, `*_user_signin`, `service_principal_signin`, `managed_identity_signin`) | `properties_createdDateTime` (string; `signin` also has `properties_createdDateTime_timestamp`) | **not `timestamp`**, which is minutes later. Dedupe on `properties_id` |
| Entra audit (`cloud.azure.ad.audit`) | `properties_activityDateTime_timestamp` | drop the `tenantId` null/`-` copy, then dedupe on `properties_id` |
| Graph activity (`cloud.azure.ad.microsoft_graph_activity_logs`) | `timestamp` (= `time`) | |
| Defender (`cloud.azure.ah.*`) | `timestamp` | **not `time`** (the Event Hub time). Dedupe on `device_id` + `report_id` + `timestamp` |
| GitHub (`vcs.github.*`) | `at_timestamp` | `created_at` is blank on `git.*` events |
| Zscaler ZPA (`vpn.zscaler.*`) | `LogTimestamp` | |
| 1Password (`auth.agilebits.onepassword.*`) | `timestamp` (string, ns) | |
| Linux (`box.unix`) | **none** | `srceventdate` and `json_time` are empty: only `eventdate` |

## Cross-cutting facts
- **Collection gaps happen** and are not always backfilled. Check `devo.py lag` / per-day counts
  before concluding that something did not happen, and say so if a question covers a gap.
- **`eventdate` is ingestion time, and the lag is variable and batch-driven.** Run `devo.py lag`
  before relying on a recent window: some Microsoft 365 workloads can fall days behind and then
  catch up. Filter on the event-time field (table above) for event time.
- **Duplicates:** count distinct ids, not rows, in Entra sign-ins (`properties_id`), Entra audit
  (`tenantId` copy, then `properties_id`), SharePoint/OneDrive (`Id`), Defender (`device_id`,
  `report_id`, `timestamp`).
- **Speed:** specific-table queries are usually fast; a wildcard parent such as `from
  cloud.aws.cloudtrail` (all services) can be very slow or time out, while querying the individual
  tables separately in parallel is quick.
