# Windows (NXLog) and Windows DNS

Generic parser knowledge. Your domain may differ: confirm fields with `devo.py fields <table>` before relying on a detail.

Contents:

  - Fields every `box.win_nxlog.*` table shares
  - `box.win_nxlog.security`
  - `box.win_nxlog.sysmon`
  - `box.win_nxlog.powershell`
  - `box.win_nxlog.invalid`
  - `box.win_nxlog.system` and `.application`
  - `dns.windows`
  - `box.all.win` (union)
  - Speed
  - Linking recipes (values are placeholders)

Tables: `box.win_nxlog.security`, `.sysmon`, `.powershell`, `.system`, `.application`, `.invalid`,
`dns.windows`, and the union `box.all.win`. Every `box.win_nxlog.*` row is one Windows event log
record shipped by NXLog (`im_msvistalog`); the full record is in `rawMessage` as a JSON object,
and the rendered text in `Message`.

### Fields every `box.win_nxlog.*` table shares

| Field | Format | Notes |
|---|---|---|
| `host` | lowercase FQDN `host01.<ad-domain>`, or a bare lowercase name `host01` for workgroup/cloud builds | lowercased; `rawMessage` `Hostname` keeps the original case |
| `eventdate` / `timestamp` | epoch ms UTC | `timestamp` = event time on the host, `eventdate` = ingestion (usually a few seconds later) |
| `EventID` | int4 | the main discriminator; fields that are filled depend on it (tables below) |
| **`IpAddress` / `IpAddress_ip4`** | dotted IPv4 | In some deployments the NxLog config overwrites `IpAddress` with the reporting host's own IP, in every table and EventID; check against `Message` before trusting it. If it is the reporting host's IP, it gives a reliable server ↔ IP map, and the other party's address (a logon's client, a Kerberos or share client) is only in `Message` |
| `Message` | rendered event text, `\r\n` separated, `Label: value` lines | the only place for the real client IP and several fields NXLog drops (below) |
| `rawMessage` | JSON object (string) | has fields that are not parsed into columns: Sysmon `OriginalFileName`, `ParentUser`, `QueryName`/`QueryStatus`/`QueryResults`; PowerShell `AccountName`/`Domain`/`UserID`/`ProcessID`; Kerberos `ResponseTicket`, encryption-type lists; scheduled-task `ClientProcessId`. Extract with `peek(rawMessage, re("\"AccountName\":\"([^\"]*)\""), 1)` |
| `EventType` | `AUDIT_SUCCESS` / `AUDIT_FAILURE` (security), `INFO`/`WARNING`/`ERROR`/`VERBOSE` | NXLog's severity; in Sysmon it **overwrites** the registry operation (see Sysmon) |
| `ProcessID`, `ThreadID`, `ExecutionProcessID` | ints | the PID of the *logging* process (LSASS, Sysmon service), not of the subject process |

Placeholders render literally: an unset value is the string `-` (e.g. `SubjectUserName = "-"` on
most network 4624s), not null. `not`/`!=` filters keep `-` rows; filter them out explicitly.

### `box.win_nxlog.security`

Common EventIDs, by purpose:
- Logon/session: 4624, 4625, 4627, 4634, 4647, 4648, 4672.
- Credential validation and Kerberos: 4768, 4769, 4776 (on DCs whose logs are collected).
- Process, service and task: 4688, 4697, 4698, 4702.
- Privilege use and object access: 4662, 4673, 4907, 4985, 5140, 5145 (file-share access, on file
  servers), 5156.
- Account and group management/enumeration: 4720–4738, 4756/4757 (universal groups), 4798, 4799.
Which IDs exist depends on the audit policy and which hosts forward logs: check the EventID mix
(recipe at the end) before concluding an event didn't happen.

Which entity fields are filled, by EventID (`-` counted as empty):

| EventID | Meaning | User fields | Session / join fields | Other filled fields |
|---|---|---|---|---|
| 4624 | logon success | `TargetUserName`, `TargetDomainName`, `TargetUserSid`; `SubjectUserName` is `-` on network logons and `HOST01$` otherwise | `TargetLogonId`, `TargetLinkedLogonId` (admin split-token pair), `LogonGuid`, `SubjectLogonId` (`0x3e7` when SYSTEM/winlogon created it) | `LogonType` (str: `"3"` network, `"4"` batch, `"5"` service, `"2"`, `"8"`, `"10"` RDP, `"7"` unlock), `AuthenticationPackageName`, `LogonProcessName`, `WorkstationName` (uppercase NetBIOS or `-`), `IpPort`, `ElevatedToken` (`%%1842` yes / `%%1843` no) |
| 4625 | logon failure | `TargetUserName` (**can be blank** when the account name is empty in the event itself, e.g. scanner/null-session NTLM failures) | `SubjectLogonId` `0x0` | `Status`, `SubStatus` (`0xc0000064` no such user, `0xc000006a` bad password, `0xc0000072` disabled, `0xc000006d`), `FailureReason` (`%%2313`), `WorkstationName`, `LogonType` |
| 4634 | logoff | `TargetUserName`, `TargetDomainName` | `TargetLogonId` (no Subject fields) | `LogonType` |
| 4647 | user-initiated logoff | `TargetUserName` | `TargetLogonId` | no `LogonType` |
| 4648 | explicit credentials (runas, `net use /user`) | `SubjectUserName` (the caller, often `HOST01$`), `TargetUserName` (the credentials used) | `SubjectLogonId`, `LogonGuid`, `TargetLogonGuid` | `TargetServerName`, `TargetInfo`, `ProcessName`; IP only in `Message` "Network Address" (often `-`) |
| 4672 | special privileges at logon | **`SubjectUserName`** (`TargetUserName` is empty) | `SubjectLogonId` = the 4624 `TargetLogonId` (the elevated half of a split token) | `PrivilegeList` |
| 4688 | process created | `SubjectUserName` (creator; `HOST01$` for SYSTEM-spawned), `TargetUserName` (`-` unless created in another session) | `SubjectLogonId`, `TargetLogonId` (the session the process runs in) | `NewProcessName`, `NewProcessId`, `ParentProcessName`, `CommandLine` (empty on hosts without command-line auditing), `TokenElevationType`, `MandatoryLabel` |
| 4662, 4663, 4907, 4985, 4673 | object access, SD change, transaction, privileged service | `SubjectUserName` | `SubjectLogonId`, `HandleId` | `ObjectServer`, `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4697 / 4698, 4702 | service installed / scheduled task created, updated | `SubjectUserName` | `SubjectLogonId` | `ServiceName`, `ServiceFileName`, `ServiceAccount` / `TaskName`, `TaskContent` (HTML-escaped; readable XML in `Message`) |
| 4720–4738, 4742 | account / group changes (4722 enabled, 4724 password reset, 4725 disabled, group membership in the rows below, 4735 group changed, 4738 user changed, 4742 computer changed) | `SubjectUserName` (actor), `TargetUserName` (the account or **group**), `TargetSid`, `MemberSid` (4732/4733: the member, SID only) | `SubjectLogonId` | 4738: `SamAccountName`, `UserPrincipalName`, `OldUacValue`/`NewUacValue`, `PasswordLastSet` |
| 4728 / 4729 | member added to / removed from a **global** security group (e.g. Domain Admins) | `SubjectUserName` (actor), `TargetUserName` (the **group**), `TargetSid` (the group's SID), `MemberName`, `MemberSid` (the member) | `SubjectLogonId` | `MemberName` is the member's DN when filled, but is **often `-`** with only `MemberSid`; resolve the SID through 4624 `TargetUserSid` or 4720/4738 `TargetSid` |
| 4732 / 4733 | member added to / removed from a **local or domain-local** group (e.g. Administrators, Server Operators, DnsAdmins) | as 4728 | `SubjectLogonId` | as 4728 (`MemberName` usually `-`). Logged by the member server for its local groups and by DCs for domain-local groups |
| 4756 / 4757 | member added to / removed from a **universal** group (e.g. Enterprise Admins, Schema Admins) | as 4728 | `SubjectLogonId` | as 4728 |
| 4768 / 4769 | Kerberos TGT / service ticket (on DCs) | `TargetUserName` (4768 `user`; 4769 **`user@REALM`** uppercase realm), `TargetDomainName` | 4769 `LogonGuid` (does **not** reliably match the 4624 `LogonGuid`; see recipes) | `ServiceName` (`krbtgt` or `HOST01$` / service account), `Status` (`0x0`), `TicketEncryptionType` (`0x12` AES256, `0x17` RC4), `TicketOptions`, `PreAuthType`; client IP only in `Message` "Client Address: ::ffff:a.b.c.d" |
| 4776 | NTLM credential validation | `TargetUserName` | none | **`Workstation`** (uppercase NetBIOS client name; not `WorkstationName`), `PackageName`, `Status`; no client IP anywhere |
| 4798 / 4799 | local user's / group's membership enumerated | `SubjectUserName` (often `HOST01$`), `TargetUserName` | `SubjectLogonId` | `CallerProcessName` |
| 5140 / 5145 | share accessed / share object checked | `SubjectUserName` (5145 is often dominated by service/backup accounts on file servers) | `SubjectLogonId` | `ShareName` (`\\*\SHARE`), `ShareLocalPath`, `RelativeTargetName` (5145), `AccessMask`, `IpPort`; client IP only in `Message` "Source Address" |
| 5156 | WFP connection allowed | none | none | `Application` (device path, lowercase), `SourceAddress`/`DestAddress` (ip4), `SourcePort`/`DestPort`, `Direction` (`%%14592` in / `%%14593` out); only on hosts auditing Filtering Platform Connection |

Name formats: `TargetUserName`/`SubjectUserName` are sAMAccountNames as typed (case varies),
computer accounts `HOST01$` uppercase; `TargetDomainName` is uppercase NetBIOS (`CORP`) or
uppercase DNS domain (`CORP.EXAMPLE`, on Kerberos 4624s), sometimes the local host name for local
accounts; SIDs `S-1-5-21-…` uppercase; logon ids lowercase hex `0x1a2b3c4d`; `LogonGuid` `{…}`
lowercase on most hosts, uppercase on some (compare with `eqic` or `weakhas`). `0x3e7` = SYSTEM,
`0x3e4` = NETWORK SERVICE, `0x3e5` = LOCAL SERVICE.

**True source IP** of a security event is only in `Message`, under a label that depends on the
EventID: 4624/4625 "Source Network Address", 4768/4769 "Client Address" (prefixed `::ffff:`),
5140/5145 "Source Address", 4648 "Network Address". On 4624 expect IPv4, `-` (local/service
logons), `::1` and IPv6 link-local values; RDP (type 10) logons often show `0.0.0.0` (take the
source from the type-3 NLA logon a second earlier, or Zscaler `ConnectorIP`).

### `box.win_nxlog.sysmon`

EventIDs depend on the Sysmon config: typically 1 process create, 11 file create, 22 DNS query,
3 network connection, 13 registry value set, 12 registry key create/delete, 2 file time changed,
17/18 pipe created/connected, 8 CreateRemoteThread, 5 process terminated, 6 driver loaded, 15, 4,
16, 255 (Sysmon errors). Many configs **exclude 7 image load and 10 process access**; check the
EventID mix before relying on them.

| EventID | Filled fields |
|---|---|
| 1 | `ProcessGuid`, `ParentProcessGuid`, `Image`, `CommandLine`, `CurrentDirectory`, `ParentImage`, `ParentCommandLine`, `User`, `LogonGuid`, `LogonId`, `TerminalSessionId`, `IntegrityLevel`, `Hashes`, `MD5`, `SHA256`, `ImpHash`, `FileVersion`, `Description`, `Product`, `Company`, `ParentProcessId` |
| 3 | `ProcessGuid`, `Image`, `User`, `Protocol`, `Initiated` (`"true"` = outbound), `SourceIp`, `SourcePort`, `SourceHostname`, `DestinationIp`, `DestinationPort`, `DestinationHostname` (reverse DNS, **not** the name queried), `DestinationPortName` |
| 11 | `ProcessGuid`, `Image`, `User`, `TargetFilename`, `CreationUtcTime` |
| 12 / 13 | `ProcessGuid`, `Image`, `User`, `TargetObject` (`HKLM\…`, `HKU\<sid>\…`), `Details` (13: the value written) |
| 22 | `ProcessGuid`, `Image`, `User` only; **the query name and answers are not parsed** |
| 8 | `SourceProcessGuid`, `SourceImage`, `TargetProcessGuid`, `TargetImage`, `StartAddress` |

Field traps:
- **DNS (22): `Query` is a WMI field and is always empty.** The name, status and answers are in
  `Message`: `peek(Message, re("QueryName:\\s*([^\\r\\n]+)"), 1)`, `QueryStatus:` (0 = answered;
  9003 = NXDOMAIN; 9501 no records; 9560 and other codes = no answer to that caller, results `-`),
  `QueryResults:` = `type:  5 cname.example;` for CNAMEs then `::ffff:a.b.c.d;` per IPv4 answer.
  Sysmon logs every resolver call, including cache hits, so it sees far more than the DNS servers.
- **`ProcessId` is never filled** (NXLog's own `ProcessID` collides with it): the process's PID is
  only in `Message` (`peek(Message, re("\\nProcessId:\\s*(\\d+)"), 1)`; the `\n` keeps it from
  matching `ParentProcessId`). `ExecutionProcessID` is the Sysmon service. Join on `ProcessGuid`.
- **`EventType` is `INFO`, not the registry operation**: on 12/13 the operation (`CreateKey`,
  `DeleteKey`, `DeleteValue`, `SetValue`) is `peek(Message, re("EventType:\\s*(\\w+)"), 1)`.
- `AccountName`/`Domain`/`UserID` are always SYSTEM / `S-1-5-18` (the Sysmon service). The actor
  is **`User`**: `DOMAIN\user` (domain uppercase NetBIOS, or the uppercase host name for local
  accounts, `NT AUTHORITY\SYSTEM`, `DOMAIN\HOST01$`).
- `OriginalFileName` (renamed-binary detection) and `ParentUser` exist only in `Message`/`rawMessage`.
- `Image` case varies between events of the same process (`powershell.exe` vs `Powershell.exe`):
  use `weakhas`. GUIDs are `{…}`, usually lowercase; one process keeps one form.
- `LogonId` uses the same lowercase hex as the security log's `TargetLogonId` and joins to it.
  Sysmon's `LogonGuid` is Sysmon's own (it embeds the logon id) and does not match the security
  log's `LogonGuid`.
- Sysmon 3 is filtered by the Sysmon config, often heavily: absence in Sysmon 3 is not absence
  of traffic.

### `box.win_nxlog.powershell`

EventIDs: 4104 script block, 53504, 40961/40962 (console start), 4103 module/pipeline execution
(only where module logging is on), 4100 error, 8193–8197/12039 (remoting). Fields:
- 4104: `ScriptBlockId` (lowercase GUID, no braces), `MessageNumber`, `MessageTotal` (strings),
  `ScriptBlockText`, `Path` (script file, empty for interactive/encoded commands). `EventType`
  `WARNING` = PowerShell flagged the block as suspicious. Most blocks are module boilerplate
  (`__cmdletization`, `Export-ModuleMember`).
- 4103 / 4100: `ContextInfo` (multi-line `Key = value`: `User = DOMAIN\user`, `Host Application =
  <full command line>`, `Script Name`, `Command Name`, `Host Name`), `Payload`
  (`CommandInvocation(...)`, `ParameterBinding(...)`).
- **No parsed user or PID on 4104.** The running account and the powershell.exe PID are only in
  `rawMessage`: `"AccountName"`, `"Domain"`, `"UserID"` (SID), `"ProcessID"`.
- Long blocks are split into parts of roughly 10 KB, cut mid-token: sort by `int(MessageNumber)`
  and join with no separator. Parts normally arrive together, but check that all `MessageTotal`
  parts are present.
- **Very large 4104 events can fail to parse and never reach this table**: they land truncated
  in `box.win_nxlog.invalid` (below), with no `ScriptBlockId`.

### `box.win_nxlog.invalid`

Only `eventdate`, `host`, `rawMessage`. Typically low volume. Rows here are usually **PowerShell
4104 events whose JSON was cut off** (unterminated string) so NXLog/Devo could not parse it; the
same `RecordNumber` is then missing from `box.win_nxlog.powershell`. Some are `EventType`
`WARNING` (suspicious-block flag). Header keys survive (`Hostname`, `EventID`, `RecordNumber`,
`AccountName`, `Domain`, `UserID`, start of `Message`); `ScriptBlockId`/`MessageNumber`/`Path`
are lost. **Include it in PowerShell hunts and host sweeps** (`weakhas(rawMessage, "<text>")`):
the biggest, most obfuscated scripts are exactly the ones that end up here.

### `box.win_nxlog.system` and `.application`

- system: 7036 service state change (`param1` service display name, `param2`
  `running`/`stopped`), 7040 start type changed, 7045 service installed (`ServiceName`,
  `ImagePath`, `ServiceType`, `StartType`; `AccountName`/`UserID` = **the account that installed
  it**, usually SYSTEM), 7031/7034 crashed, 6005/6006 event log start/stop (boot), 1074 shutdown
  initiated (`param1` process, `param2` host), 16/98 hive/volume. `AccountName`/`UserID` are filled
  only on events that carry a user SID. NXLog's own stop/start shows as 7036.
- application: whatever the installed software logs, often dominated by a few noisy sources.
  Common: MSSQL (18453/18456 logins, 17137…), 1000/1002 app crash/hang (details in `rawMessage`:
  `AppName`, `ModuleName`, `ExceptionCode`), 1033/1035 MSI installs, 16384/16394 licensing.
  `AccountName` as in system. Read `SourceName` + `Message`; there is no common entity schema.

### `dns.windows`

One row per **line of the Windows DNS debug log**, not per query. Usually very high volume.
`hostname` = the DNS server (lowercase FQDN). `rawMessage` = the raw line. Only `PACKET` lines
parse cleanly; continuation lines (`Domain name:`, `Total cache time`, `node`,
`to answer section of packet`) and `RECURSE`/`DSPOLL` lines are split into columns at fixed
offsets, so on those rows `send_receive`, `protocol`, `op_code`, `question_type`,
`response_code` hold word fragments (e.g. `ect`, `alr`, `: g`). Always filter
`context = "PACKET"` first.

| Row (context, send_receive, query_response) | Meaning |
|---|---|
| `PACKET`, `Rcv`, ` ` (a space) | **query received from a client**: count these |
| `PACKET`, `Snd`, `R` | response sent back to that client; **its `response_code` is the client's answer** (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`) |
| `PACKET`, `Snd`, ` ` / `Rcv`, `R` | the server's own recursive query to a forwarder (`remote_ip` = the forwarder, e.g. public resolvers) and its answer |
| `LOOKUP` / `RECURSE` / `DSPOLL` / blank | internal lookups and continuation lines |

- `question_dot` = dotted lowercase name (use it); `question_name` = wire format
  `(3)www(7)example(3)com(0)`; `question_type` `A`/`AAAA`/`SRV`/`PTR`…; `record_type` is only on
  non-PACKET lines.
- `remote_ip` (ip4) = the client on `Rcv`/` ` rows. Null when the client is IPv6 or `::1` (the
  server itself). Clients may be other resolvers or servers rather than end-user devices,
  depending on the DNS design.
- `x_id` (DNS transaction id, 4 hex) + `int_packed_id` (packet buffer address) tie a client query
  to its `Snd`/`R` response row.
- **No answer data** unless the debug log is in detailed mode: resolved IPs are then not in this
  table at all. For name ↔ IP use Sysmon 22 `QueryResults` (recipes).
- "Each query is logged 2–4 times" is the PACKET rows above plus continuation lines.

### `box.all.win` (union)

A normalised union over Windows sources (for NXLog: channels Security, Sysmon, PowerShell,
System, Application) with snake_case fields (`machine`, `event_id` (str), `target_username`,
`subject_username`, `logon_type`, `target_logon_id`, `process_guid`, `parent_process_guid`,
`original_file_name`, `query_name`, …). It adds traps: `source_ip` on 4624 can be the reporting
host's IP (same `IpAddress` overwrite), `machine_ip` can be a relay/collector address shared by
several hosts, `query_name`/`query_results` can be null for Sysmon 22, and `pid` is the Sysmon
service PID. Its one gain is `original_file_name` as a column. Prefer the source tables. Check
what it holds with the recipe at the end.

### Speed
- Short `group by` windows on any `box.win_nxlog.*` table are fast, including `peek(Message, …)`
  per row.
- A day of a user filter on `.security`, or `weakhas(question_dot, …)` on `dns.windows`, can be
  slow: chunk it (`--chunk 1h --parallel 6`).
- **A `--to` in the future makes the query wait until that time**, and can hit the timeout. Use
  `--to now` for open-ended windows.

### Linking recipes (values are placeholders)

**Which Windows server has IP 10.1.2.3** (and the reverse, by `host`), where `IpAddress` is the
reporting server's own IP (confirm against `Message` first). Multi-homed or re-addressed hosts
can report two addresses, so group by both.
```linq
from box.win_nxlog.system
where IpAddress = "10.1.2.3"
group by host, IpAddress
select count() as n, max(eventdate) as last_seen
```

**True source of a user's network logons, tickets and share access**, with one regex for all the
labels:
```linq
from box.win_nxlog.security
where EventID in {4624, 4625, 4648, 4768, 4769, 5140, 5145}, weakhas(TargetUserName, "jsmith") or weakhas(SubjectUserName, "jsmith")
select peek(Message, re("(?:Source Network Address|Client Address|Source Address|Network Address):\\s*(?:::ffff:)?([^\\r\\n\\t]+)"), 1) as src
group by EventID, host, src, LogonType
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Failed logons by true source (expect a blank `TargetUserName` bucket; report it separately):
```linq
from box.win_nxlog.security
where EventID = 4625
select peek(Message, re("Source Network Address:\\s*([^\\r\\n\\t]+)"), 1) as src
group by host, src, TargetUserName, WorkstationName, Status, SubStatus, LogonType
select count() as n
```

**Logon session: start → activity → end.** 1) Find the session ids. An admin RDP/console logon
writes two 4624s at the same instant, linked through `TargetLinkedLogonId`: the elevated one
(`ElevatedToken` `%%1842`, followed by 4672) and the filtered one where the user's processes run.
```linq
from box.win_nxlog.security
where EventID = 4624, weakhas(host, "HOST01"), weakhas(TargetUserName, "jsmith")
select eventdate, host, TargetUserName, LogonType, TargetLogonId, TargetLinkedLogonId, ElevatedToken, LogonGuid,
  peek(Message, re("Source Network Address:\\s*([^\\r\\n\\t]+)"), 1) as src
```
2) Everything in that session on that host. Logon ids are only unique per host and boot, so always
filter the host too. Match **both** `SubjectLogonId` and `TargetLogonId`: 4688s for the session's
processes are often written with `SubjectLogonId` `0x3e7` (SYSTEM created them) and
`TargetLogonId` = the session. An RDP session usually opens with a 4624 and may end
with a 4647; in between you may see events such as 4688 (processes), 4673 (privileged service
calls), 4698–4701 (scheduled tasks), 4799 (group enumeration), 5061 (cryptographic operations) and
5379 (credential manager reads), depending on the audit policy.
```linq
from box.win_nxlog.security
where weakhas(host, "HOST01"), SubjectLogonId = "0x1a2b3c4d" or TargetLogonId = "0x1a2b3c4d"
group by EventID, SubjectLogonId, TargetLogonId
select count() as n, min(eventdate) as first, max(eventdate) as last
```
The session's processes from the security log:
```linq
from box.win_nxlog.security
where EventID = 4688, weakhas(host, "HOST01"), SubjectLogonId = "0x1a2b3c4d" or TargetLogonId = "0x1a2b3c4d"
select eventdate, SubjectUserName, TargetUserName, NewProcessName, ParentProcessName, CommandLine, TokenElevationType
```
End of session: 4647 (user logoff, carries `TargetLogonId`) is the more reliable marker on RDS
hosts; 4634 is often missing for type-10 sessions. A missing end means the session was still
open, disconnected, or the logoff wasn't logged.

3) The same session in Sysmon: `LogonId` = the security `TargetLogonId` (use the non-elevated id
for normal user processes, the elevated one for "Run as administrator"):
```linq
from box.win_nxlog.sysmon
where weakhas(host, "HOST01"), LogonId = "0x1a2b3c4d"
group by EventID, User, Image
select count() as n, min(eventdate) as first, max(eventdate) as last
```

**Kerberos and NTLM to logons.** The 4769 `LogonGuid` generally does not match the 4624
`LogonGuid`, so don't join on it. Join on (service host, client IP, user, time) instead: look for
a 4624 on the service host from the 4769's client address within about a minute.
```linq
from box.win_nxlog.security
where EventID = 4769, weakhas(ServiceName, "HOST01"), weakhas(TargetUserName, "jsmith")
select eventdate, host, TargetUserName, ServiceName, Status, TicketEncryptionType,
  peek(Message, re("Client Address:\\s*(?:::ffff:)?([^\\r\\n\\t]+)"), 1) as client_ip
```
then, on the target host, the logon from that client (filter on a computed field with `select … where`):
```linq
from box.win_nxlog.security
where EventID = 4624, weakhas(host, "HOST01"), weakhas(TargetUserName, "jsmith")
select peek(Message, re("Source Network Address:\\s*([^\\r\\n\\t]+)"), 1) as src
where src = "10.1.2.3"
select eventdate, host, TargetUserName, LogonType, TargetLogonId, AuthenticationPackageName, src
```
A user's tickets (4768 TGT, 4769 service tickets), with the client address. Kerberos events only
exist for DCs whose security logs are collected, so an empty result does not mean no Kerberos
activity:
```linq
from box.win_nxlog.security
where EventID in {4768, 4769, 4771}, weakhas(TargetUserName, "jsmith")
select peek(Message, re("Client Address:\\s*(?:::ffff:)?([^\\r\\n\\t]+)"), 1) as client_ip
group by EventID, host, TargetUserName, ServiceName, client_ip, Status, TicketEncryptionType
select count() as n
```
NTLM validation (4776) names the client only by NetBIOS `Workstation`; pair it with the NTLM 4624
(`AuthenticationPackageName = "NTLM"`, `WorkstationName`) on the target server:
```linq
from box.win_nxlog.security
where EventID = 4776
group by host, TargetUserName, Workstation, Status
select count() as n
```

**Sysmon process tree.** A process, its children (`ParentProcessGuid`), and everything it did
(3 network, 11 file, 12/13 registry, 22 DNS share its `ProcessGuid`). `self` separates the
process's own events from its children's:
```linq
from box.win_nxlog.sysmon
where weakhas(host, "HOST01"), ProcessGuid = "{a1b2c3d4-0000-0000-0000-000000000000}" or ParentProcessGuid = "{a1b2c3d4-0000-0000-0000-000000000000}"
select ProcessGuid = "{a1b2c3d4-0000-0000-0000-000000000000}" as self
group by self, EventID, Image, ProcessGuid
select count() as n, min(eventdate) as first, max(eventdate) as last
```
Walk up one level (repeat with the returned `ParentProcessGuid`; `LogonId` links to the session):
```linq
from box.win_nxlog.sysmon
where EventID = 1, weakhas(host, "HOST01"), ProcessGuid = "{a1b2c3d4-0000-0000-0000-000000000000}"
select eventdate, User, LogonId, Image, CommandLine, ParentProcessGuid, ParentImage, ParentCommandLine
```
The process's activity, with the fields Sysmon leaves in `Message`:
```linq
from box.win_nxlog.sysmon
where weakhas(host, "HOST01"), ProcessGuid = "{a1b2c3d4-0000-0000-0000-000000000000}", EventID in {3, 11, 12, 13, 22}
select eventdate, EventID, DestinationIp, DestinationPort, DestinationHostname, TargetFilename, TargetObject, Details,
  peek(Message, re("EventType:\\s*(\\w+)"), 1) as reg_op,
  peek(Message, re("QueryName:\\s*([^\\r\\n]+)"), 1) as qname,
  peek(Message, re("QueryResults:\\s*([^\\r\\n]+)"), 1) as qresults
```
Within one process, a Sysmon 3 `DestinationIp` normally appears in the `QueryResults` of a
preceding 22, which gives the name the connection was for. `DestinationHostname` is reverse DNS
(e.g. a cloud provider's PTR), not that name.

**DNS: names, answers and traffic.**
Names a host resolved (Sysmon 22, with status):
```linq
from box.win_nxlog.sysmon
where EventID = 22, weakhas(host, "HOST01")
select peek(Message, re("QueryName:\\s*([^\\r\\n]+)"), 1) as qname,
  peek(Message, re("QueryStatus:\\s*(\\d+)"), 1) as qstatus
group by qname, qstatus, Image
select count() as n
```
Name → the IPs it resolved to (across Sysmon hosts):
```linq
from box.win_nxlog.sysmon
where EventID = 22, weakhas(Message, "QueryName: example.com")
select peek(Message, re("QueryResults:\\s*([^\\r\\n]+)"), 1) as qresults
group by host, qresults
select count() as n
```
IP → the names that resolved to it (the trailing `;` stops `10.1.2.3` matching `10.1.2.30`):
```linq
from box.win_nxlog.sysmon
where EventID = 22, weakhas(Message, "::ffff:203.0.113.10;")
select peek(Message, re("QueryName:\\s*([^\\r\\n]+)"), 1) as qname
group by host, qname
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
Then the firewall traffic from that host to that address:
```linq
from firewall.fortinet.traffic.forward
where srcIp = 10.1.2.3, dstIp = 203.0.113.10
group by srcIp, dstIp, dstPort, action, policyName
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
If web traffic leaves through a proxy or Zscaler, the firewall sees the proxy's addresses, not
the resolved IP, so expect matches mainly for direct traffic (OCSP/CRL, cloud APIs, internal
services).

Names a client IP asked the Windows DNS servers (one row per client query):
```linq
from dns.windows
where context = "PACKET", send_receive = "Rcv", query_response != "R", remote_ip = 10.1.2.3
group by hostname, question_dot, question_type, response_code
select count() as n
```
Who asked for a name:
```linq
from dns.windows
where context = "PACKET", send_receive = "Rcv", query_response != "R", weakhas(question_dot, "example.com")
group by remote_ip, hostname, question_dot
select count() as n, min(eventdate) as first_seen
```
NXDOMAIN answers by client (the answer code is on the response row, not the query row):
```linq
from dns.windows
where context = "PACKET", send_receive = "Snd", query_response = "R", response_code = "NXDOMAIN", isnotnull(remote_ip)
group by hostname
select count() as n, hllppcount(remote_ip) as clients
```
Server-side DNS and Sysmon 22 overlap only partly: the DNS servers see processes no Sysmon rule
covers, and Sysmon sees cache hits the servers never get. Check both.

**PowerShell.** Reassemble a script block: pull the parts and join them client-side in
`int(MessageNumber)` order with no separator (`--format jsonl`, then Python):
```linq
from box.win_nxlog.powershell
where EventID = 4104, ScriptBlockId = "<script-block-id>"
select eventdate, host, MessageNumber, MessageTotal, Path, ScriptBlockText
```
Who ran it and which powershell.exe (from `rawMessage`):
```linq
from box.win_nxlog.powershell
where weakhas(host, "HOST01"), EventID in {4103, 4104}
select peek(rawMessage, re("\"ProcessID\":(\\d+)"), 1) as ps_pid,
  peek(rawMessage, re("\"Domain\":\"([^\"]*)\""), 1) as dom,
  peek(rawMessage, re("\"AccountName\":\"([^\"]*)\""), 1) as account
group by EventID, ps_pid, dom, account
select count() as n, min(eventdate) as first, max(eventdate) as last
```
That PID → the Sysmon process (then the tree recipes above). PIDs are reused within minutes, so
keep the window tight around the 4104:
```linq
from box.win_nxlog.sysmon
where EventID = 1, weakhas(host, "HOST01")
select peek(Message, re("\\nProcessId:\\s*(\\d+)"), 1) as pid
where pid = "1234"
select eventdate, ProcessGuid, User, Image, CommandLine, ParentImage
```
4103 carries the user and the full command line of the host process:
```linq
from box.win_nxlog.powershell
where EventID = 4103
select peek(ContextInfo, re("User = ([^\\r\\n]+)"), 1) as ps_user,
  peek(ContextInfo, re("Host Application = ([^\\r\\n]+)"), 1) as host_app
group by host, ps_user
select count() as n
```
Oversized script blocks (search them too):
```linq
from box.win_nxlog.invalid
where weakhas(rawMessage, "Get-Process")
select eventdate, host,
  peek(rawMessage, re("\"EventID\":(\\d+)"), 1) as eid,
  peek(rawMessage, re("\"AccountName\":\"([^\"]*)\""), 1) as account
```

**Services** (installer account in `AccountName`/`UserID`; 4697 in security has the same with
`SubjectUserName`):
```linq
from box.win_nxlog.system
where EventID = 7045
select eventdate, host, ServiceName, ImagePath, ServiceType, StartType, AccountName, UserID
```
```linq
from box.win_nxlog.security
where EventID = 4697
group by host, SubjectUserName, ServiceName, ServiceFileName, ServiceAccount
select count() as n
```

Registry operations (Sysmon 12/13, operation from `Message`):
```linq
from box.win_nxlog.sysmon
where EventID in {12, 13, 14}
select peek(Message, re("EventType:\\s*(\\w+)"), 1) as reg_op
group by EventID, EventType, reg_op
select count() as n
```

EventID mix of a table (swap the table):
```linq
from box.win_nxlog.security
group by EventID
select count() as n, hllppcount(host) as hosts
```

What the union holds:
```linq
from box.all.win
group by source, channel
select count() as n
```
