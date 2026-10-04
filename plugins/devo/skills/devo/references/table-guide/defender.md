# Microsoft Defender for Endpoint (Advanced Hunting stream): `cloud.azure.ah.*`

Generic parser knowledge. Your domain may differ: confirm fields with `devo.py fields <table>` before relying on a detail.

Values in the recipes are placeholders: device `HOST01` (`host01.corp.example`), account `jsmith`
(`john.smith`), `10.1.2.3`, `203.0.113.10`, `<device_id>`, `<process_unique_id>`, `<sha1>`.
Contents:

  - The schema: wide, generic, already parsed
  - Time fields and lag
  - Coverage: which devices report
  - Duplicates
  - Entity fields
  - Action and outcome values
  - File origin, hashes and alerts
  - Join keys
  - Speed
  - Linking recipes
  - Quirks (summary)

One Devo table per Advanced Hunting (AH) table streamed from Defender for Endpoint:

| Devo table | AH table | One row is |
|---|---|---|
| `device_process_event` | DeviceProcessEvents | one process creation (`action_type` always `ProcessCreated`) |
| `device_network_event` | DeviceNetworkEvents | one connection or inspected network event (usually the busiest) |
| `device_file_event` | DeviceFileEvents | one file create/modify/rename/delete |
| `device_registry_event` | DeviceRegistryEvents | one registry key/value change |
| `device_event` | DeviceEvents | one miscellaneous sensor event (many `action_type`s) |
| `device_image_load_event` | DeviceImageLoadEvents | one DLL load (`ImageLoaded`) |
| `device_file_certificate_info` | DeviceFileCertificateInfo | the signing certificate of one file (by `sha1`) seen on a device |
| `device_network_info` | DeviceNetworkInfo | a periodic snapshot of **one network adapter** of a device |
| `device_logon_event` | DeviceLogonEvents | one logon attempt/success/failure on the device |
| `device_info` | DeviceInfo | a periodic inventory snapshot of one device (several per day per device) |
| `alert_info` | AlertInfo | one Defender alert (title, category, severity, detection source); **no device** |
| `alert_evidence` | AlertEvidence | one entity (device, file, IP, account…) attached to an alert |

### The schema: wide, generic, already parsed
- **All the tables share one wide schema.** It is a superset of every AH table (email, identity,
  cloud-app fields too), so most columns are always empty in any one table. Run
  `devo.py fields cloud.azure.ah.<table>` for the populated ones.
- Field names are **snake_case versions of the AH column names**, with these renames:
  `InitiatingProcess*` → `init_process_*`, `SHA256` → `sh_a256` (and `init_process_sh_a256`),
  `AccountUpn` → `account_upn`, `MachineGroup` → `machine_group`. Examples: `DeviceName` →
  `device_name`, `ProcessCommandLine` → `process_command_line`, `InitiatingProcessAccountUpn`
  → `init_process_account_upn`, `RemoteIP` → `remote_ip`.
- **The record is already flattened; there is no raw/`properties` JSON column to extract.**
  The catch is the opposite: **`AdditionalFields` is not ingested** (no such column). So the
  detail AH keeps there is gone: `PowerShellCommand` rows have no command text, `LdapSearch` no
  filter, `DnsQueryResponse` / `DnsConnectionInspected` no query name, `ScheduledTaskCreated` no
  task name, `PnpDeviceConnected` no device, `HttpConnectionInspected` no URL. Only the
  initiating process (and for some types `file_name`/`folder_path`/`sha1`, `remote_url`,
  `registry_*`, `account_sid`, `process_command_line`) is filled. Use Sysmon (EventID 22 DNS) or
  PowerShell 4104 (`box.win_nxlog.powershell`) for those details where you collect them.
- JSON *text* columns (type `str`, holding a JSON array): `device_info.logged_on_users`
  (`[{"UserName","DomainName","Sid"}]`), `merged_device_ids`, `cloud_platforms`;
  `device_network_info.ip_addresses` (`[{"IPAddress","SubnetPrefix","AddressType"}]`),
  `dns_addresses`, `default_gateways`, `connected_networks`; certificate
  `crl_distribution_point_urls`. `weakhas()` works on them directly (no `stringify` needed,
  they are strings). Extract with `jqeval(jqcompile("[.[].IPAddress]"), jsonparse(ip_addresses))`
  wrapped in `stringify()`. The jq engine is limited: `join(",")` is rejected
  ("Invalid filter"). An empty array is stored as the text `[]`, which the field profiler counts
  as "filled".
- Hostname columns: **`machine` is the Devo collector pod name** (`collector-<hash>-<pod>`),
  not the device. Use `device_name`. `operation_name` is always `Publish`, `category` is
  `AdvancedHunting-<AH table name>`, `tenant` is a constant.

### Time fields and lag
- `timestamp`: when the event happened on the device (AH `Timestamp`). Use this for event times.
- `time_received_by_svc`: when Defender's cloud received it. `time`: when it was published to
  the stream. `eventdate`: Devo ingestion (what `--from/--to` filter on).
- **Lag `eventdate - timestamp` is usually a few minutes.** Devices that were offline report
  hours or days later. So when hunting an event at time T, run the window a little past T, and
  widen `--to` if the device was off-network. `devo.py lag` measures it in your domain.
- `process_creation_time` is empty; for a created process use `timestamp`.
  `init_process_creation_time` (the parent's start) is filled.

### Coverage: which devices report
- Event tables (process/network/file/registry/event/image-load/logon/certificate) come only from
  devices onboarded to Defender for Endpoint. Check `device_info` (`os_platform`, `device_type`,
  `onboarding_status`) to see which devices that covers before treating a missing event as
  meaningful.
- Devices that are discovered or inventoried but not sending events appear only in
  `device_info` and `device_network_info`. Use Windows/Sysmon tables for hosts without events.
- `device_info` also lists discovered, unmanaged devices (`onboarding_status` = `Can be
  onboarded` / `Unsupported` / `Insufficient info`; `device_type` `NetworkDevice`, `Printer`,
  `AudioAndVideo`, `Mobile`…; `os_platform` Linux/Android/macOS or blank).
- **Sampling, not full accounting.** Defender caps and de-noises what it reports, so a host that
  also runs Sysmon shows far more process creations there than here. A missing process here is
  not proof it didn't run.
- Collection gaps in the stream are not backfilled. Check hourly counts (recipe below) before
  concluding something didn't happen.

### Duplicates
A small fraction of rows arrive twice (same `device_id` + `report_id` + `timestamp`, different
`time`, `machine` and Devo offset: the stream is at-least-once). De-duplicate on
`device_id, report_id, timestamp` before counting.

### Entity fields

| Entity | Fields | Format / case |
|---|---|---|
| Device | `device_name` | **lowercase**. Domain-joined: FQDN `<host>.<ad-domain>` (`host01.corp.example`). Entra-only devices, Cloud PCs and Azure VMs: often a **short name with no domain** (Cloud PCs `cpc-<user>-<suffix>`). Can differ from `box.win_nxlog.*` `host` for Azure VMs (Windows `host` may carry an Azure-internal DNS suffix where AH has the short name) |
| | `device_id` | 40-hex lowercase (Defender machine id). **Not stable per name**: a re-onboarded device gets a new id (see `merged_device_ids` / `merged_to_device_id`), so pivot by `weakhas(device_name, …)` and use `device_id` only within one device's events |
| | `aad_device_id`, `hardware_uuid` (`device_info`) | GUID lowercase; `aad_device_id` = Entra device object id |
| Account (subject of the event) | `account_name`, `account_domain`, `account_sid`, `account_upn`, `account_object_id` | `account_name` lowercase sAMAccountName (`john.smith`, `host01$` for machine accounts, `system`, `local service`, `umfd-0`/`dwm-1`); `account_domain` lowercase NetBIOS (`corp`), sometimes the lowercase DNS domain, `nt authority`, `font driver host`, `window manager`; SID uppercase `S-1-5-21-…`; `account_upn` mixed case, **often empty** on process events |
| Account (initiating process) | `init_process_account_name/_domain/_sid/_upn/_object_id` | same formats; UPN fill varies by table (empty on logon events) |
| Logon | `device_logon_event.account_name/_domain/_sid`, `logon_id`, `logon_type`, `remote_ip`, `remote_port`, `is_local_admin` (`true`/`false` text) | `account_sid`/`logon_id` only on `LogonSuccess` |
| IP | `local_ip`, `remote_ip` (str, v4 or v6), `local_ipv4/remote_ipv4` (ip4), `local_ipv6/remote_ipv6`; `remote_ip_type`/`local_ip_type` (`Public`, `Private`, `Loopback`, `FourToSixMapping`, `CarrierGradeNat`); `device_info.public_ip`/`public_ipv4` (the device's egress IP); `device_network_info.ip_addresses` (JSON text) | `remote_ip = "203.0.113.10"` (string compare) works. IPv6 in `remote_ip` is compressed, in `remote_ipv6` expanded |
| Domain | `remote_url` (network events: partly filled, a host name; `device_event` `BrowserLaunchedToOpenUrl`: a full URL) | lowercase |
| Process | `file_name` (original case, `Updater.exe`), `folder_path` (original case, full path), `process_command_line`, `process_id`, `process_unique_id`, `process_integrity_level`, `process_token_elevation`, `process_version_*` | `init_process_file_name` / `init_process_folder_path` are **lowercased**; `init_process_command_line` keeps case. Compare names with `weakhas`/`eqic` or lowercase values |
| Parent | `init_process_*` (the process that did the action), `init_process_parent_file_name`, `init_process_parent_id` (its parent) | |
| Hash | `sha1`, `md5`, `sh_a256` (the target file/process), `init_process_sha1/_md5/_sh_a256` | lowercase hex |

### Action and outcome values
- `device_process_event`: `ProcessCreated` only.
- `device_network_event`: `ConnectionSuccess`, `ConnectionFailed`, `ConnectionAcknowledged`,
  `ConnectionAttempt`, `InboundConnectionAccepted`, `ListeningConnectionCreated`,
  `DnsConnectionInspected`, `SslConnectionInspected`, `HttpConnectionInspected`,
  `IcmpConnectionInspected`, `SshConnectionInspected`, `NtlmAuthenticationInspected`,
  `KerberosConnectionInspected`, `NetworkSignatureInspected`, `ConnectionFound`. `protocol`:
  `Tcp`, `TcpV4`, `Udp`, `Icmp`. The `*Inspected` rows have `init_process_id = 0` and no
  initiating process.
- `device_file_event`: `FileCreated` (usually the bulk), `FileRenamed` (`previous_file_name`,
  `previous_folder_path`), `FileDeleted`, `FileModified`; `request_protocol` (e.g. `Local`,
  `Unknown`) and `request_account_*` say who asked over the network.
- `device_registry_event`: `RegistryValueSet`, `RegistryKeyCreated`, `RegistryKeyDeleted`,
  `RegistryValueDeleted`; `registry_key`, `registry_value_name`, `registry_value_data`,
  `registry_value_type`, `previous_registry_*`.
- `device_logon_event`: `LogonSuccess`, `LogonFailed` (`failure_reason` e.g.
  `InvalidUserNameOrPassword`, `LogonServerUnavailable`), `LogonAttempted` (often the largest
  group, `logon_type` `Unknown`, mostly machine accounts and task-host noise). `logon_type`:
  `Interactive`, `Unlock`, `CachedInteractive`, `RemoteInteractive` (RDP), `Network`, `Batch`,
  `Service`, `NewCredentials`. `protocol`: `Negotiate`, `NTLM`, `Kerberos`,
  `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`. Many `remote_ip` values are `127.0.0.1`/loopback.
- `device_event` (examples): `NamedPipeEvent`, `DpapiAccessed`, `ProcessCreatedUsingWmiQuery`,
  `AppControlExecutableAudited`, `PowerShellCommand`, `Nt*VirtualMemory*ApiCall`,
  `BrowserLaunchedToOpenUrl` (`remote_url`), `ClrUnbackedModuleLoaded`,
  `AuditPolicyModification`, `LdapSearch`, `CreateRemoteThreadApiCall`, `SensitiveFileRead`
  (`file_name`, `folder_path`), `ShellLinkCreateFileEvent`, `UserAccountAddedToLocalGroup` /
  `…RemovedFromLocalGroup` (member in `account_sid`; group name lost with AdditionalFields),
  `PnpDeviceConnected`, `DriverLoad` (`file_name`, `sha1`), `ServiceInstalled` (`file_name`,
  `folder_path`, `process_command_line`), `ScheduledTaskCreated/Updated/Deleted`,
  `TamperingAttempt` (`registry_*`), `AntivirusReport`, `UsbDriveMounted`,
  `AsrLsassCredentialTheftBlocked`, `WriteToLsassProcessMemory`, `ExploitGuard*`,
  `UserAccountCreated/Deleted/Modified/PasswordResetAttempt`, `WmiBindEventFilterToConsumer`.
- `device_info`: `onboarding_status`, `sensor_health_state` (`Active`, …), `exposure_level`,
  `os_platform` (`Windows11`, `Windows11WVD`, `WindowsServer20xx`, `Linux`, `Android`, `macOS`),
  `os_version`/`os_build`, `join_type` (`Hybrid Azure AD Join`, `AAD Joined`, `Domain Joined`),
  `device_type`, `is_excluded`, `public_ip`, `logged_on_users`, `client_version` (sensor).
- `device_network_info`: `network_adapter_status` (`Up`, `Down`, `Present`, `Unknown`; many rows
  are `Down` adapters), `network_adapter_type` (`Ethernet`, `Wireless80211`), `mac_address`
  (uppercase, dash-separated), `ip_addresses` (`[]` unless the adapter is up).
- `device_file_certificate_info`: `sha1`, `signer`, `issuer`, `is_signed`, `is_trusted`,
  `is_root_signer_microsoft`, `signature_type` (`Embedded`, `Catalog`), `certificate_serial_number`.

### File origin, hashes and alerts
- **SHA-256 exists**: `sh_a256` (and `init_process_sh_a256`), lowercase hex, filled wherever
  `sha1`/`md5` are on file, process and network (initiating process) rows; some rows have no hash
  at all. Prefer it for matching a SHA-256 from another source (a base64 SHA-256 must be converted
  to hex first). With only a SHA-1 or MD5, or no hash on the row, match on file name + device +
  time, and say that match is weaker.
- **File origin** on `device_file_event`: `file_origin_url`, `file_origin_referrer_url` (from the
  Mark-of-the-Web zone identifier, so browser and some app downloads only: a small fraction of
  `FileCreated`/`FileRenamed` rows), `file_origin_ip`/`file_origin_ipv4` (usually empty). Files
  that arrive another way (sync clients, archive extraction, SMB) usually have none; writes over
  the network have `request_protocol`,
  `share_name`, `request_source_ip`, `request_account_*` instead. Check live with
  `devo.py schema cloud.azure.ah.device_file_event --grep 'origin|sha|folder|file_name|initiat'`.
- **Alerts**: these two tables use a different naming, `properties__<snake_case>`
  (`properties__alert_id`, `properties__title`, `properties__severity`, `properties__category`,
  `properties__detection_source`). `alert_info` has **no device field** (`hostname` is the
  collector; `properties__machine_group` is a device group, often empty). The devices, files,
  IPs and accounts are in `alert_evidence` (`properties__entity_type`, `properties__device_name`,
  `properties__device_id`, `properties__sha1`/`properties__sha256`, `properties__remote_ip`,
  `properties__account_*`), joined on `properties__alert_id`. Check those fields are filled in the
  domain before relying on them: when they are empty, find the device from the alert's time and
  file in the event tables, or from the Defender portal.
- **Size**: file, process and network events are among the largest tables in a domain. Filter by
  device (`weakhas(device_name, "host01")`) and a short window first, then widen.

### Join keys
- **Process identity = `device_id` + `process_unique_id`** (AH `ProcessUniqueId`; unique per
  device, unlike a PID). An action by that process in any other table has
  `init_process_unique_id` = that value (child processes, connections, file writes,
  `device_event` rows, registry changes). A child row's `init_process_unique_id` equals the
  parent row's `process_unique_id`, and `init_process_id` its `process_id`. PIDs alone
  (`process_id` / `init_process_id` / `init_process_parent_id`) repeat.
- The parent's own creation row often isn't there (long-running services started at boot,
  sampling), but each row already carries the parent (`init_process_*`) and grandparent
  name and PID (`init_process_parent_file_name`, `init_process_parent_id`).
- `report_id` is only unique per device (and repeats on the duplicates above).
- `logon_id` (process events) = `logon_id` of a `LogonSuccess` in `device_logon_event` on the
  same `device_id`. This works for some sessions only (UAC split tokens and sampling mean
  processes are often logged under the other session id).
- `sha1` links process/file/image-load rows to `device_file_certificate_info` (signer) and to
  SentinelOne `threatInfo__sha1` (both lowercase). Sysmon `Hashes` holds whichever algorithms the
  Sysmon config selects (uppercase, e.g. `MD5=…,SHA256=…,IMPHASH=…`); if SHA1 is not among them,
  match `sh_a256` against it case-insensitively.
- `account_object_id` / `init_process_account_object_id` = Entra user object id
  (`properties_userId` in sign-ins, `properties__user_id` in Graph).
- Device ↔ other sources (by **short host name**, case-insensitive):
  - Sysmon/Windows `host`: lowercase FQDN; equal to `device_name` for domain-joined devices,
    possibly a different domain suffix for Azure VMs. Only hosts that both run the Defender
    sensor and forward Windows logs appear in both.
  - SentinelOne `edr.sentinelone.agent.agents.computerName` and threats
    `agentRealtimeInfo__agentComputerName`: **short name, uppercase or mixed case**
    (`HOST01`, `CPC-Jsmit-AB12C`).

### Speed
Fast compared with the Windows tables: most queries return in seconds.
- Short windows grouped by `device_id`, and `weakhas` filters (user, host, command line, domain)
  over a day, are quick. Multi-day `weakhas` hunts on process/network events usually work
  unchunked; for hash lookups over a week, `--chunk 1d` keeps each query small.
- `device_info`, `device_network_info`, `device_logon_event` are small and fast even over long
  ranges.
- Many queries at once can produce transient `General error` / `Connection error` responses
  (HTTP 500); re-running them alone works. Keep `--parallel` modest (around 4).

### Linking recipes

**A process and its parent** (from a row you already have: `device_id`, `process_unique_id`):
```linq
from cloud.azure.ah.device_process_event
where device_id = "<device_id>", process_unique_id = "<process_unique_id>"
select timestamp, device_name, account_name, file_name, process_id, process_command_line, sha1, init_process_file_name, init_process_id, init_process_unique_id, init_process_command_line, init_process_parent_file_name
```
Walk up by re-running it with `process_unique_id = "<that row's init_process_unique_id>"`.
0 rows usually means the parent started before the window (or was not reported); its name, PID
and command line are already in the child's `init_process_*`.

**Its child processes**:
```linq
from cloud.azure.ah.device_process_event
where device_id = "<device_id>", init_process_unique_id = "<process_unique_id>"
select timestamp, file_name, process_id, process_unique_id, process_command_line
```

**What that process did on the network, on disk and elsewhere** (same key in each table):
```linq
from cloud.azure.ah.device_network_event
where device_id = "<device_id>", init_process_unique_id = "<process_unique_id>"
select timestamp, action_type, local_ip, remote_ip, remote_port, remote_url, protocol
```
```linq
from cloud.azure.ah.device_file_event
where device_id = "<device_id>", init_process_unique_id = "<process_unique_id>"
select timestamp, action_type, folder_path, file_name, sha1
```
```linq
from cloud.azure.ah.device_event
where device_id = "<device_id>", init_process_unique_id = "<process_unique_id>"
group by action_type select count() as n
```
Registry changes per initiating process on a device:
```linq
from cloud.azure.ah.device_registry_event
where weakhas(device_name, "host01"), init_process_file_name in {"powershell.exe", "svchost.exe"}
group by init_process_unique_id, action_type, registry_key
select count() as n, min(timestamp) as first
```

**Logons on a device**:
```linq
from cloud.azure.ah.device_logon_event
where weakhas(device_name, "host01")
group by action_type, logon_type, account_domain, account_name, remote_ip
select count() as n, min(timestamp) as first, max(timestamp) as last
```
**From an interactive logon to the processes in that session** (works for some sessions, see
Join keys):
```linq
from cloud.azure.ah.device_process_event
where device_id = "<device_id>", logon_id = "<logon_id>"
group by account_name, file_name
select count() as n, min(timestamp) as first, max(timestamp) as last
```

**Device inventory: OS, join type, egress IP, sensor health**:
```linq
from cloud.azure.ah.device_info
where weakhas(device_name, "host01")
group by device_id, device_name, os_platform, os_version, os_build, device_type, join_type, onboarding_status, sensor_health_state, public_ip
select count() as n, max(timestamp) as last_seen
```
Who was logged on (from the JSON text column):
```linq
from cloud.azure.ah.device_info
where weakhas(device_name, "host01")
select stringify(jqeval(jqcompile("[.[].UserName]"), jsonparse(logged_on_users))) as users
group by device_name, users
select count() as n, max(timestamp) as last_seen
```
**The device's internal IPs and MACs** (adapters that are up):
```linq
from cloud.azure.ah.device_network_info
where weakhas(device_name, "host01"), network_adapter_status = "Up"
select stringify(jqeval(jqcompile("[.[].IPAddress]"), jsonparse(ip_addresses))) as ips
group by device_name, network_adapter_type, mac_address, ips
select count() as n, max(timestamp) as last_seen
```
**Which device had internal IP 10.1.2.3** (include the JSON quotes so `10.1.2.3` doesn't
also match `10.1.2.30`):
```linq
from cloud.azure.ah.device_network_info
where weakhas(ip_addresses, "\"10.1.2.3\"")
group by device_name, device_id, network_adapter_status
select count() as n, min(timestamp) as first, max(timestamp) as last
```
**Which devices egress through public IP 203.0.113.10**:
```linq
from cloud.azure.ah.device_info
where public_ip = "203.0.113.10"
group by device_name, os_platform
select count() as n, max(timestamp) as last_seen
```

**Who talked to remote IP 203.0.113.10, and with which program**:
```linq
from cloud.azure.ah.device_network_event
where remote_ip = "203.0.113.10"
group by device_name, init_process_file_name, remote_port, remote_url, action_type
select count() as n, min(timestamp) as first, max(timestamp) as last
```
**Devices that reached a domain** (`remote_url` is a host name):
```linq
from cloud.azure.ah.device_network_event
where weakhas(remote_url, "example.com")
group by remote_url, remote_ip
select count() as n, hllppcount(device_id) as devices
```
**Command-line hunt**:
```linq
from cloud.azure.ah.device_process_event
where weakhas(process_command_line, "encodedcommand")
group by device_name, file_name, account_name
select count() as n, min(timestamp) as first, max(timestamp) as last
```
**A user's processes** (`account_upn` is often empty, so search `account_name` too):
```linq
from cloud.azure.ah.device_process_event
where weakhas(account_name, "jsmith") or weakhas(account_upn, "jsmith")
group by device_name, account_domain, account_name, account_upn, file_name
select count() as n, min(timestamp) as first, max(timestamp) as last
```

**Hash: where it ran / was written / was loaded, and who signed it** (from e.g. a SentinelOne
`threatInfo__sha1`; use `--chunk 1d` over long ranges):
```linq
from cloud.azure.ah.device_process_event
where sha1 = "<sha1>"
group by device_name, action_type, file_name, folder_path
select count() as n, min(timestamp) as first, max(timestamp) as last
```
(same query on `device_file_event` and `device_image_load_event`)
```linq
from cloud.azure.ah.device_file_certificate_info
where sha1 = "<sha1>"
group by signer, issuer, is_trusted, is_signed
select count() as n
```

**Same process in Sysmon** (only for hosts in both). If Sysmon `ProcessId` is empty, match on
host, image name, time (within milliseconds), `init_process_id` = `ParentProcessId`, and
`sh_a256` in `Hashes` (uppercase there):
```linq
from cloud.azure.ah.device_process_event
where weakhas(device_name, "host01"), file_name = "Updater.exe"
select timestamp, device_name, file_name, process_id, init_process_id, init_process_file_name, sh_a256, account_name
```
```linq
from box.win_nxlog.sysmon
where weakhas(host, "host01"), EventID = 1, weakhas(Image, "Updater.exe")
select UtcTime, host, Image, ParentProcessId, ParentImage, User, Hashes, ProcessGuid
```
Sysmon `User` is `CORP\john.smith` (uppercase domain) where AH has `account_domain` `corp`,
`account_name` `john.smith`.

**Same device in SentinelOne** (short name, any case):
```linq
from edr.sentinelone.agent.agents
where weakhas(computerName, "host01")
group by computerName, lastLoggedInUserName, lastIpToMgmt, externalIp, osName
select count() as n, max(eventdate) as last_seen
```

**Is the stream flowing? (hourly rows and devices)** (shows collection gaps):
```linq
from cloud.azure.ah.device_info
group every 1h select count() as n, hllppcount(device_id) as devices
```
**Late or missing data by device day vs ingestion day**:
```linq
from cloud.azure.ah.device_logon_event
select formatdate(timestamp, "YYYY-MM-DD") as evday, formatdate(eventdate, "YYYY-MM-DD") as ingday
group by evday, ingday select count() as n
```
**De-duplicated counts** (group on the identity, then count groups):
```linq
from cloud.azure.ah.device_process_event
where weakhas(device_name, "host01")
group by device_id, report_id, timestamp, file_name, process_command_line
select count() as copies
```

### Quirks (summary)
- `machine` is the collector, not the host. Use `device_name`.
- No `AdditionalFields`: DNS names, PowerShell text, LDAP filters, task names are not here.
- Events only from onboarded devices; discovered/inventoried devices only in `device_info` /
  `device_network_info`.
- `init_process_file_name`/`folder_path` are lowercase; `file_name`/`folder_path` keep case:
  an exact `file_name =` must match the original case. Use `eqic`/`weakhas` when unsure.
- `init_process_id = 0` and an empty initiating process on `*Inspected` network rows,
  `UserAccount*` and some `device_event` rows.
- `account_upn` / `init_process_account_upn` often empty: search `account_name` (sAM) too.
- `is_local_admin` is text `true`/`false`, not a boolean.
- A small fraction of duplicate rows; collection gaps are not backfilled.
