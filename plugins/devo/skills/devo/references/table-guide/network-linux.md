# Network and Linux: Fortinet, Zscaler ZPA, `box.unix`, relay health

Generic parser knowledge. Your domain may differ: confirm fields with `devo.py fields <table>` before relying on a detail.

Contents:

  - Fortinet FortiGate (`firewall.fortinet.*`)
  - Zscaler ZPA (`vpn.zscaler.*`)
  - Linux syslog (`box.unix`)
  - Relay and collector health (`syslog.*`, `box.stat.unix.diskstat`)
  - Linking recipes (values are placeholders)
  - Cross-source summary

Placeholders: `jsmith` / `jsmith@example.com` (person), `HOST01` (server), `10.1.2.3` (internal
IP), `203.0.113.10` (public IP), `198.51.100.4` (an App Connector), `FGXXXXXXXXXXXXXX`
(firewall serial). Short windows (an hour or less) on these tables are usually fast; chunk a day
or more (`--chunk 3h --parallel 8`) on high-volume tables such as `traffic.forward`.

### Fortinet FortiGate (`firewall.fortinet.*`)

When several FortiGates log through one FortiAnalyzer-style collector, **`machine` can be a
constant**: identify the firewall by `devName` or `devID` (serial,
uppercase `FG<model><digits>`). Time fields: `eventdate` is ingestion time; **`serverdatetime` /
`timestamp` are the firewall's event time in UTC**, usually a little earlier; `servertime` is the
firewall's local clock (see `tz`), don't mix it with UTC. Use `serverdatetime` when you line
Fortinet up with other sources to the second.

| Table | One row is |
|---|---|
| `traffic.forward` | one session log line for traffic *through* the firewall (see lifecycle below); by far the largest table |
| `traffic.local` | traffic *to/from the firewall itself*: DNS/ping to the box, routing, management, HA and IKE traffic between firewalls, local-in denies |
| `event.vpn` | IPsec tunnel events: phase 1/2 negotiation, SA install/delete, DPD, tunnel up/down, periodic `tunnel-stats`; SSL-VPN/dial-up events too where those are configured |
| `event.system` | admin logins/logouts and config edits, FortiGuard updates, DHCP ack/stats, NTP, FortiAnalyzer link, HA, `perf-stats` (cpu/mem/sessions every few min) |
| `event.sdwan` | SD-WAN health-check / SLA state (`healthcheck`, `member`, `oldvalue`/`newvalue`) |
| `event.ha` | HA config sync (`sync_type`, `sync_status` = `in-sync`/`out-of-sync`) |
| `event.router` | routing events, e.g. dynamic-routing neighbour up/down (`message` has the neighbour IP) |
| `event.connector` | dynamic address object updates (`address`) |
| `event.user` | firewall user-authentication events where firewall auth/FSSO is used; otherwise may hold only `Seeding from entropy source` (PRNG reseed, `user` = `system`) |

**`traffic.forward` session lifecycle.** The firewall writes several rows per connection, linked
by **`devID` + `session`** (an int8 counter per firewall; not unique across firewalls, and ids
can recur within minutes):

| `logID` | `action` | Meaning | Bytes / `duration` |
|---|---|---|---|
| `0000000015` | `start` | session start | 0 |
| `0000000020` | `accept` | interim "long-lived session" update, every few minutes | **cumulative** so far; `sentdelta`/`rcvddelta` = since the last update |
| `0000000013` | `close`, `client-rst`, `server-rst`, `timeout`, `accept` (non-TCP end), `deny` | the final row (deny = blocked, no other rows) | **final totals** |
| `0000000011` | `dns`, `ip-conn` | DNS-filter / ip-conn events; `message` set, no bytes | - |

Whether start and interim rows exist depends on the firewall's logging settings. So **don't
`sum(bytesSent)` over all rows**: interim rows repeat cumulative counts, so summing them
over-counts long sessions. Either sum final rows only (`logID = "0000000013"`) or take `max()`
per `devID, session` (recipes below). Counting rows overstates connections the same way.

Entity fields (`traffic.forward`):
- `srcIp` / `dstIp` (ip4, unquoted literal or `<-` CIDR), `srcIp_str`/`dstIp_str` strings; `srcPort`,
  `dstPort` (int4); `natIp`/`natPort` (SNAT'd source on egress); `tranip`/`tranport` (DNAT target).
- `srcIface`/`dstIface` with `srcintfrole`/`dstintfrole` (`lan`/`wan`/`undefined`), `policyName`,
  `policyID`, `poluuid`, `service` (e.g. `HTTPS`, `DNS`, `tcp/8443`), `appCat` (`unscanned`
  when application control is off), `srcCountry`/`dstCountry` (`Reserved` for private).
- **`url`, `dstHost`, `user` are only filled when web filtering / user identification is
  enabled on the policy.** Without web filtering, a domain can't be matched in firewall logs
  directly: resolve it first (`dns.windows`, Sysmon 22) and then match `dstIp` here.
- `unauthuser` with `unauthusersource` (e.g. `kerberos`): a passively learned user name, set
  only where the firewall identifies users that way.
- `srcHost` (device name from FortiGate device detection, sometimes with a trailing space),
  `srcmac`, `osname`, `devtype`, `srchwvendor`.
- **Device identity (`srcHost`, `srcmac`, `unauthuser`) is only right on directly attached LANs.**
  For routed traffic the firewall sees the next-hop router's MAC and can pin every source behind
  it to one device. Check how many `srcIp`s share the value before trusting it. Resolve IPs
  through Zscaler, SentinelOne or Qualys instead (cross-source below).

`traffic.local`: same field family minus `policyName` (uses `policyType` =
`local-in-policy`/`local-in-policy6`/`policy`, and `appType`). Mostly monitoring noise; useful for
"who tried to reach the firewall's admin interface" (`action = "deny"`).

`event.vpn`: for site-to-site IPsec, `xauthUser`, `xauthGroup`, `assignIp`, `useralt`,
`server_group` are `N/A` and `user` is the **remote gateway's IP** (or `N/A`), not a person.
Remote-access VPN (SSL-VPN or dial-up IPsec with XAUTH), where present, fills the user and
assigned-IP fields; check `tunnelType` values to see which you have. Key fields: `vpnTunnel`
(tunnel name), `remoteIP`/`localIP` (ip4, gateway ends), `action` (`negotiate` / `install_sa` /
`delete_phase1_sa` / `phase2-up|down` / `tunnel-up|down` / `tunnel-stats` / `dpd` / `error`),
`status` (`success` / `failure` / `negotiate_error` / `dpd_failure` / `esp_error`), `logdesc`,
`reason`, `tunnelID` (joins a tunnel's `tunnel-stats` rows; `bytesSent`/`bytesRecv`/`duration`
are filled only on those). If remote users come in through Zscaler ZPA instead, there is no
user → VPN tunnel IP → traffic chain on the firewall: use the Zscaler `ClientPrivateIp` chain
below. A `fortinet_vpn` sweep source in `references/hints/activity-sources.json` only matches a
person where remote-access VPN exists.

`event.system` admin activity: `user` = the admin account (local, remote/LDAP, built-in
`admin`, or API/service accounts), `ui` = the channel and source, `https(<ip>)` / `ssh(<ip>)` /
`GUI(<ip>)` / `jsconsole` / `ha_daemon`, `srcIp` (filled on login/logout), `action` (`login`,
`logout`, `Edit`), `status` (`success`/`failed`), `logdesc` (`Admin login successful`,
`Admin login failed`, `Attribute configured`, `Configuration changed`, …), `message` (readable
sentence; config edits name the changed object). Without firewall user authentication, this is
the main per-person data in the Fortinet family.

### Zscaler ZPA (`vpn.zscaler.*`)

**The `access`, `activity`, `status_user` and `status_connector` tables can hold the same
records**: when one ZPA user-activity LSS feed is parsed into all four, the same
`ConnectionID`+`ConnectionStatus`+`LogTimestamp` keys appear in each. In that case **query only
`vpn.zscaler.access`**, and never add counts across the tables (check by comparing key counts
for the same minute). The copies differ only in parsing: `access` has
`ClientPublicIp`/`ClientPrivateIp` and a string `Host`; the other three spell them
`ClientPublicIP`/`ClientPrivateIP`, put the target in `Host_str` (`Host` is an ip4 there, filled
only when the target is an IP), and `activity` keeps some of its `Timestamp*` fields as strings.

One row = one ZPA connection status record. Some rows can be empty shells (only `eventdate` and
`hostname`); `hostname` is the log receiver's IP, not the client. A connection
(`ConnectionID`) logs `open` → `active` every few minutes while it lasts → `close`; long sessions
started before your window show only `active` rows. Count connections with
`ConnectionStatus = "open"` or `hllppcount(ConnectionID)`, not rows.

| Field | Meaning / format |
|---|---|
| `Username` | the person: usually the IdP UPN (case may vary, so use `weakhas`). `ZPA LSS Client` = the log-streaming service itself (ignore) |
| `SessionID` | one ZPA client session (20 chars, base64-like, case-sensitive, contains `/` and `+`): one user, one device, many connections; lasts hours |
| `ConnectionID` | `<SessionID>,<20-char id>`: one TCP/UDP flow; prefix = `SessionID` |
| `Hostname` | **the client device name** (Windows/Mac hostname, mixed case, normally the same as SentinelOne `computerName`) |
| `Platform` | `windows` / `mac` / … (blank for LSS) |
| `ClientPrivateIp` | the device's own IP on whatever network it is on: a home router range, or an **office LAN IP that can also appear as a firewall `srcIp`** (string) |
| `ClientPublicIp` | the device's internet egress IP (ip4); `ClientCountryCode`, `ClientCity`, `ClientLatitude`/`Longitude` geolocate it |
| `Host` | the target the user asked for: FQDN (lowercase; DNS aliases of one server show up as different `Host`s) or an IP |
| `ServerIP`, `ServerPort` | the target's real internal IP and port (22 SSH, 3389 RDP, 445 SMB, 389/88/135 AD) |
| `ConnectorIP`, `ConnectorPort` | the App Connector's address and **source port for this flow**: what the target server records as the client |
| `Connector`, `ConnectorZEN`, `ClientZEN` | connector name, Zscaler edge nodes |
| `Application`, `AppGroup`, `Policy` | ZPA app segment / group / access policy names (`0` when blocked before policy) |
| `ConnectionStatus` | `open`, `active`, `close` |
| `InternalReason` | `OPEN_OR_ACTIVE_CONNECTION`, `BRK_MT_TERMINATED` (normal close), `MT_CLOSED_TLS_CONN_GONE_CLIENT_CLOSED`, `BRK_MT_SETUP_FAIL_SAML_EXPIRED`, `APP_NOT_REACHABLE`, `BRK_MT_TERMINATED_IDLE_TIMEOUT`, … |
| `TimestampConnectionStart` / `TimestampConnectionEnd` | flow start/end (End only on `close`) |
| `ZENTotalBytesRxClient` / `ZENTotalBytesTxClient` | cumulative bytes from / to the client (take `max()` per `ConnectionID`) |

**`ConnectorIP` + `ConnectorPort` is an exact join to the server's own login record**: sshd's
`Accepted … from <ConnectorIP> port <ConnectorPort>` on the target matches the Zscaler `open` row
of that connection, a second or two earlier, and the sshd "session closed" line matches the
Zscaler `close` closely. Expect the odd miss from empty rows. Windows RDP logons (4624 type 10)
show `ConnectorIP` as "Source Network Address" but **Source Port 0**, so for RDP join on
`ConnectorIP` + `ServerIP` + time only. Local accounts don't always match the UPN, so the port
join is what ties them together.

### Linux syslog (`box.unix`)

One row = one syslog line from a Linux server, typically via rsyslog. Often high volume.

- `machine`: the hostname as the server reports it (often short, or the AWS default
  `ip-10-1-2-3`). **Not unique**: two servers can share a name.
- `machineIp` (ip4): the address the syslog arrived from. Behind NAT or a relay it can be
  **shared by many servers**, so check how many `machine`s share it before using it as the
  host's IP.
- **`message` prefix**: some syslog relays or rsyslog templates prepend a tag to each line
  (for example `[<TAG>|<ip>] `, with the sender's own IP). If your `message` values start with
  one, it is often the most reliable host IP; check a sample of `message` first. The recipes
  below treat any `[...]` prefix as optional.
- `appName`: clean program name, use it to filter (indexed-fast): `sshd` and, on newer OpenSSH,
  **`sshd-session`** (the per-connection process; filter both), `sudo`, `su`, `systemd-logind`,
  `(systemd)`, `CRON`/`CROND`/`cron`, `audit` (auditd via journald), `audispd` (auditd dispatcher
  format), `useradd`/`groupadd`/`usermod`, `postfix/*`, `sm-mta`, `kernel`, `amazon-ssm-agent`.
- `application`: `appName[pid]`; `processId`: the pid as a string (`processId = "1234"`).
- `facility` (`authpriv`, `security`, `daemon`, `cron`, `user`, `mail`, …), `level`.
- Parsed fields are unreliable: `user`, `srcIp` (ip4) and `srcUser` are **blank on sshd lines**.
  `srcIp` is filled only on auditd records (`addr=`); `user` is the auditd `acct=` or sudo's run-as
  user; `srcUser` on sudo is the invoking user, with any message prefix glued on;
  `auditType` can hold a prefix rather than an audit type; `type` mixes PAM ops (`setcred`,
  `session_open`, …) with SSH key fingerprints. Parse `message` instead (recipes below).

Noise: `systemd`, `audispd`, `sm-mta`, `audit` and cron usually dominate; auth-relevant programs
(`sshd*`, `sudo`, `su`, `systemd-logind`) are a small share of lines, so always filter on
`appName` first.

**SSH session reconstruction.** One sshd process (`processId`) handles one connection:
- `pam_sss(sshd:auth): authentication success; … rhost=<ip> user=<account>` (SSSD/AD-joined hosts only)
- `Accepted <method> for <account> from <ip> port <port> ssh2[: <keytype> SHA256:<fp>]`
  (`method` = `publickey` / `password` / `keyboard-interactive/pam`)
- `pam_unix(sshd:session): session opened for user <account>(uid=N) by (uid=0)`
- `systemd-logind`: `New session <N> of user <account>.` (different pid; `<N>` is the logind
  session id, the same number as auditd `ses`)
- `pam_unix(sshd:session): session closed for user <account>`, plus
  `Received disconnect from <ip> port <port>` / `Disconnected from user <account> <ip> port <port>`
- SFTP-only accounts on `sshd-session` log `session opened for local user <account> from [<ip>]`
  and `opendir`/`closedir` lines.
- Failures: `Invalid user <name> from <ip>`, `Failed password for [invalid user ]<account> from
  <ip>`, `pam_unix(sshd:auth): authentication failure; … rhost=<ip> user=<account>`,
  `maximum authentication attempts exceeded`.

Account names: often shared service/admin accounts (`ec2-user`, `git`, app accounts) and, on
directory-joined hosts, the person's directory name (no domain). When remote users reach servers
through Zscaler ZPA, the source IP is a **Zscaler App Connector IP**, never the laptop, so join
to Zscaler on `ConnectorIP`+`ConnectorPort`. Many logins are server-to-server automation from
internal IPs.

sudo: `<invoker> : [TTY=pts/N ; ]PWD=<dir> ; USER=<runas> ; [GROUP=… ; ]COMMAND=<cmd>`, `<invoker>
: command not allowed ; …` (denied), and `pam_unix(sudo:session): session opened/closed for user
<runas>`. su: `pam_unix(su[-l]:session): session opened for user <target> by (uid=N)`,
`Successful su for <target> by <invoker>`, `(to <target>) <invoker> on <tty>|none`
(`on none` = non-interactive su from a root process). Commands typed in a shell are **not** logged
except where auditd `EXECVE` is on.

auditd: hosts that forward through `audispd` send full auditd records
(`node=<host> type=<TYPE> msg=audit(<epoch>.<ms>:<serial>): …`); others send PAM-level records
via `audit` (`<TYPE> pid=… uid=… auid=… ses=… msg='op=… acct="<user>" exe="…" addr=<ip> …'`).
Types: `USER_AUTH`, `USER_ACCT`, `CRED_ACQ`/`CRED_DISP`, `USER_START`/`USER_END`, `LOGIN`,
`USER_LOGIN`/`USER_LOGOUT`, `USER_CMD` (sudo), `ADD_USER`/`ADD_GROUP`/`USER_MGMT`, `SERVICE_START`
/`STOP`, `SYSCALL`, `EXECVE`, `PROCTITLE`, `PATH`, `CWD`, `BPF`, `AVC`, `ANOM_PROMISCUOUS`,
`SYSTEM_BOOT`. Parsed: `auid` (login uid, `4294967295` = unset), `ses` (login session,
`4294967295` = none), `pid`, `uid`, `cmd` (the `exe`), `op`, `srcIp` (`addr`), `user` (`acct`),
`msg2`. **`msg2` = `audit(<epoch>:<serial>):`, the record id that ties one event's `SYSCALL`
(has `auid`/`ses`/`exe`) to its `EXECVE` (has `a0`, `a1`, … arguments) and `PROCTITLE`**
(hex-encoded command line). Cron jobs open `ses` sessions too (`exe="/usr/sbin/cron"`).

Host ↔ IP: a message-prefix IP (if present), Zscaler `ServerIP` (`Host` = FQDN aliases), Qualys
`vuln.qualys.hosts`, or an `ip-a-b-c-d` name itself.

### Relay and collector health (`syslog.*`, `box.stat.unix.diskstat`)

These describe **the Devo relay** (the on-prem/cloud syslog relay that forwards firewall,
Zscaler and other syslog), not the monitored servers:
- `syslog.scoja.stats`: every few minutes, per relay input (`kind = "source"`, `subkind` `udp` /
  `stream-rfc5424`, `parameters` = `0.0.0.0:<port>`) and output (`kind = "target"`, file or
  `syslog:ssl>nbtcp` to Devo): `partialEvents`, `partialBytes`, `partialDroppedLogs` and buffer
  counters. **Best collection-gap signal for relayed network sources**: a source port dropping to
  0 events/hour while others continue means that feed stopped at the sender. Map ports to feeds
  from your relay configuration (or infer them from volumes, and say it is inferred).
- `syslog.scoja.target`: relay file rotation (`info`/`debug`/`notice`) and `error`/`critical`
  "Error while sending … Disabling [a syslog sender …]" = relay → Devo send failures.
- `syslog.scoja.source`: `error` lines "While processing data from a client(/<ip>:<port>) …
  IOException" (a sender dropped its TCP connection; routine).
- `syslog.relay.out` (`operation` = `health-checker` / `config-updater` / `purge-logs`) and
  `syslog.relay.monitor` / `syslog.relay.conf`: relay self-checks every few minutes; look for
  `Relay health check failed. Retrying (N)`, `Response from Search API: {"status":503 …}`,
  `We cannot confirm if the events are being stored in Devo.`, `The relay has been recovered`.
- `box.stat.unix.diskstat`: the relay's own disk counters per device (`fsSize`, `freeBlocks`,
  `freeInodes`, I/O counters). Only for "did the relay fill its disk".

Sources that don't pass through a relay you can see stats for (for example Linux servers sending
straight to Devo) are gap-checked with `devo.py coverage` / the per-host daily count instead.

### Linking recipes (values replaced with placeholders)

**Fortinet: traffic totals for an IP, one row per destination** (final rows only):
```linq
from firewall.fortinet.traffic.forward
where srcIp = 10.1.2.3, logID = "0000000013"
group by devName, dstIp, dstPort, action
select count() as sessions, sum(bytesSent) as bytes_out, sum(bytesRecv) as bytes_in, sum(duration) as total_s
```

**Fortinet: one row per connection** (`max()` copes with windows that cut a session):
```linq
from firewall.fortinet.traffic.forward
where srcIp = 10.1.2.3
group by devName, session, srcIp, dstIp, dstPort, service, policyName
select min(serverdatetime) as first, max(serverdatetime) as last, max(duration) as duration_s,
  max(bytesSent) as bytes_sent, max(bytesRecv) as bytes_recv, count() as rows
```

**Fortinet: every row of one session** (start / interim / end). Filtering on `session` alone is
slow even with `devID`, so keep the window tight:
```linq
from firewall.fortinet.traffic.forward
where devID = "FGXXXXXXXXXXXXXX", session in {123456789, 123456790}
select serverdatetime, devID, session, logID, action, duration, bytesSent, bytesRecv, sentdelta, rcvddelta, srcIp, dstIp, dstPort, policyName
```

**Fortinet: passively identified user on the firewall** (only where the firewall learns users;
check the `srcIp` count before believing it; chunk a day with `--chunk 3h --parallel 8`):
```linq
from firewall.fortinet.traffic.forward
where weakhas(unauthuser, "smith")
group by devName, unauthuser, unauthusersource, srcIp
select count() as n, min(eventdate) as first, max(eventdate) as last
```

**Fortinet: admin logins and config changes by a person**:
```linq
from firewall.fortinet.event.system
where weakhas(user, "smith")
group by devName, user, ui, logdesc, action, status
select count() as n, min(eventdate) as first, max(eventdate) as last
```

**Fortinet: what the system log contains / anything odd today**:
```linq
from firewall.fortinet.event.system
group by logdesc, action, status, ui
select count() as n
```

**Fortinet: IPsec tunnel health over a week**:
```linq
from firewall.fortinet.event.vpn
group by tunnelType, action
select count() as n
```

**Fortinet: traffic to the firewall itself**:
```linq
from firewall.fortinet.traffic.local
group by devName, action, policyType, service, dstPort
select count() as n
where n > 100
```

**Who was on internal IP X (office LAN or home)?** Zscaler reports every enrolled device's own
IP (chunk a day with `--chunk 3h --parallel 8`):
```linq
from vpn.zscaler.access
where ClientPrivateIp = "10.1.2.3"
group by Username, Hostname, Platform, ClientPublicIp
select count() as n, min(eventdate) as first, max(eventdate) as last
```
The same device then shows in SentinelOne by IP (`lastIpToMgmt` is ip4; quoted and unquoted
literals both match):
```linq
from edr.sentinelone.agent.agents
where lastIpToMgmt = 10.1.2.3
group by computerName, lastLoggedInUserName
select max(eventdate) as last_seen
```
and by name in Zscaler (`Hostname` = S1 `computerName`):
```linq
from vpn.zscaler.access
where weakhas(Hostname, "LAPTOP01")
group by Username, Hostname, ClientPrivateIp, Platform
select count() as n, min(eventdate) as first, max(eventdate) as last
```
The chain is firewall `srcIp` → S1 `computerName` + last user → Zscaler `Hostname`, `Username`
and the same `ClientPrivateIp` for the same hours. DHCP leases move (a laptop can have several
office IPs and a home IP in one day), so always bound by time.

**Servers a user reached through Zscaler**:
```linq
from vpn.zscaler.access
where weakhas(Username, "jsmith")
group by Username, Hostname, Application, Host, ServerIP, ServerPort, ConnectionStatus
select count() as n, min(eventdate) as first, max(eventdate) as last
```

**Who connected to a server through Zscaler** (by name or IP; DNS aliases differ, the IP doesn't):
```linq
from vpn.zscaler.access
where weakhas(Host, "host01") or ServerIP = "10.1.2.3"
group by Username, Hostname, Host, ServerIP, ServerPort, ConnectorIP
select count() as n, min(eventdate) as first, max(eventdate) as last
```

**Each Zscaler connection of a user: start, end, bytes, connector port**:
```linq
from vpn.zscaler.access
where weakhas(Username, "jsmith"), ServerPort = 22
group by SessionID, ConnectionID, Hostname, ClientPublicIp, Host, ServerIP, ConnectorIP, ConnectorPort
select min(TimestampConnectionStart) as started, max(TimestampConnectionEnd) as ended,
  max(ZENTotalBytesRxClient) as bytes_from_client, max(ZENTotalBytesTxClient) as bytes_to_client, count() as n
```

**Linux: parse sshd logins** (account, method, source; plus the prefix IP if your relay adds one):
```linq
from box.unix
where appName in {"sshd", "sshd-session"}, message -> "Accepted "
select peek(message, re("^\\[[^|\\]]*\\|([0-9.]+)\\]"), 1) as hostip,
  peek(message, re("Accepted (\\S+) for "), 1) as method,
  peek(message, re("Accepted \\S+ for (\\S+) from"), 1) as account,
  peek(message, re(" from ([0-9a-fA-F:.]+) port"), 1) as src
group by machine, hostip, method, account, src
select count() as n, min(eventdate) as first, max(eventdate) as last
```
Don't name a computed column `tag` or `comm`: they clash with existing identifiers ("Identifier
`tag` is used more than once").

**Linux: SSH session table** (one row per sshd pid: account, source, port, opened, closed).
`closed` is null when the session outlives the window:
```linq
from box.unix
where machine = "host01", appName in {"sshd", "sshd-session"}
select peek(message, re("Accepted \\S+ for (\\S+) from"), 1) as account,
  peek(message, re("Accepted (\\S+) for "), 1) as method,
  peek(message, re("Accepted \\S+ for \\S+ from ([0-9a-fA-F:.]+) port"), 1) as src,
  peek(message, re("Accepted \\S+ for \\S+ from \\S+ port (\\d+)"), 1) as srcport,
  ifthenelse(message -> "session closed for", eventdate, null) as closed_at
group by machine, processId
select nnfirst(account) as account, nnfirst(method) as method, nnfirst(src) as src, nnfirst(srcport) as srcport,
  min(eventdate) as opened, nnlast(closed_at) as closed
where isnotnull(account)
```

**Linux → person: sshd logins that came through Zscaler.** Step 1, logins from the App Connector
IPs (list them first from `vpn.zscaler.access` `ConnectorIP`; chunk long ranges):
```linq
from box.unix
where appName in {"sshd", "sshd-session"}, message -> "Accepted "
select peek(message, re("Accepted (\\S+) for "), 1) as method,
  peek(message, re("Accepted \\S+ for (\\S+) from"), 1) as account,
  peek(message, re(" from ([0-9a-fA-F:.]+) port"), 1) as src,
  peek(message, re(" port (\\d+)"), 1) as srcport
where src in {"198.51.100.4", "198.51.100.6"}
select eventdate, machine, method, account, src, srcport, processId
```
Step 2, the Zscaler `open` row with that connector IP **and port** names the person and laptop:
```linq
from vpn.zscaler.access
where ServerPort = 22, ConnectorIP in {"198.51.100.4", "198.51.100.6"}, ConnectorPort in {40001, 40002}
select eventdate, Username, Hostname, ClientPrivateIp, ClientPublicIp, SessionID, ConnectionID, ConnectionStatus, Host, ServerIP, ConnectorIP, ConnectorPort, TimestampConnectionStart, TimestampConnectionEnd
```

**Linux: everything one login did on a host** (pid lines plus logind; then add the logind
session number or sudo lines):
```linq
from box.unix
where machine = "host01"
where processId in {"1234567", "1234568"} or weakhas(message, "jsmith")
select eventdate, appName, processId, user, srcUser, cmd, type, ses, auid, message
```
(`where a, b or c` isn't allowed: `(x, y)` is a tuple. Use a second `where` or `and`.)

**Linux: sudo commands** (invoker, run-as, command, denied; any `[...]` prefix skipped):
```linq
from box.unix
where appName = "sudo", message -> "COMMAND="
select peek(message, re("^(?:\\[[^\\]]*\\]\\s+)?(\\S+) : "), 1) as invoker,
  peek(message, re("USER=(\\S+)"), 1) as runas,
  peek(message, re("COMMAND=(.*)$"), 1) as command,
  message -> "command not allowed" as denied
group by machine, invoker, runas, command, denied
select count() as n, min(eventdate) as first, max(eventdate) as last
```

**Linux: SSH failures and invalid users** (chunk a day with `--chunk 6h`):
```linq
from box.unix
where appName in {"sshd", "sshd-session"}, has(message, "Failed password", "Invalid user", "authentication failure", "Failed publickey", "maximum authentication attempts")
select peek(message, re("(Failed \\S+|Invalid user|authentication failure|maximum authentication attempts)"), 1) as what,
  peek(message, re("(?:for invalid user |for |Invalid user |user=)(\\S+)"), 1) as account,
  peek(message, re("(?:from |rhost=)([0-9a-fA-F:.]+)"), 1) as src
group by machine, what, account, src
select count() as n
```

**Linux: machine ↔ sending IP ↔ prefix IP** (does a prefix exist, and is `machineIp` shared?):
```linq
from box.unix
select peek(message, re("^\\[[^|\\]]*\\|([0-9.]+)\\]"), 1) as hostip
group by machine, hostip, machineIp
select count() as n
```

**Linux: which programs dominate** (find the noise before a broad search):
```linq
from box.unix
group by appName
select count() as n
where n > 1000
```

**Linux auditd: what one login session did** (`ses` from the logind "New session N" line or a
`LOGIN` record), and the record-id join that attaches `EXECVE` arguments to a `SYSCALL`:
```linq
from box.unix
where machine = "host01", appName = "audispd", ses = "12345"
select peek(message, re("type=([A-Z_]+) "), 1) as atype,
  peek(message, re(" comm=\"([^\"]*)\""), 1) as procname
group by auid, ses, atype, procname, cmd
select count() as n, min(eventdate) as first, max(eventdate) as last
```
```linq
from box.unix
where machine = "host01", appName = "audispd", msg2 = "audit(1790000000.000:123456):"
select eventdate, auid, ses, cmd, message
```
Record types per hour, to see whether a host has full auditd:
```linq
from box.unix
where appName in {"audit", "audispd"}
select peek(message, re("(?:^\\[[^\\]]*\\]\\s+|^|type=)([A-Z_]+) "), 1) as atype
group by appName, atype
select count() as n, hllppcount(machine) as hosts
```

**Windows RDP through Zscaler** (Source Port is 0, so join on IP and time): logons whose source
is an App Connector:
```linq
from box.win_nxlog.security
where EventID in {4624, 4625}, weakhas(host, "host01")
select peek(Message, re("Source Network Address:\\s*([^\\r\\n\\t]+)"), 1) as src,
  peek(Message, re("Source Port:\\s*([^\\r\\n\\t]+)"), 1) as srcport
where src -> "198.51.100."
group by host, EventID, TargetUserName, LogonType, src, srcport
select count() as n, min(eventdate) as first
```

**Relay: events per input per hour** (gaps in one feed):
```linq
from syslog.scoja.stats
group every 1h by kind, subkind, parameters
select sum(partialEvents) as events, sum(partialDroppedLogs) as dropped
```
**Relay: send failures and health-check failures**:
```linq
from syslog.scoja.target
where level in {"critical", "error"}
group every 1h by level
select count() as n, min(eventdate) as first, max(eventdate) as last
```
```linq
from syslog.relay.out
where operation = "health-checker"
group every 1d by machine, message
select count() as n
```

### Cross-source summary

| From | To | Link | Strength |
|---|---|---|---|
| Linux sshd login (`box.unix`) | person | `from <ip> port <p>` = Zscaler `ConnectorIP` + `ConnectorPort` → `Username`, `Hostname` | exact |
| Linux host | its IP | message-prefix IP (if present) = Zscaler `ServerIP` | exact where the prefix exists |
| Windows RDP logon | person | Source Network Address = `ConnectorIP`, plus `ServerIP` and time (port is 0) | inferred by time |
| Firewall `srcIp` (office LAN) | laptop + person | Zscaler `ClientPrivateIp` (same hours) → `Hostname`, `Username`; S1 `lastIpToMgmt` → `computerName` | exact for the time window |
| Fortinet `srcIp` | device name | `srcHost`/`srcmac` | only on directly attached LANs; wrong for routed subnets |
| Fortinet VPN | person | remote-access VPN user fields, where configured; none for site-to-site | - |
| Zscaler `SessionID` | all of one client session's connections | `ConnectionID` prefix | exact |
| Fortinet session | its start / interim / end rows | `devID` + `session` | exact |
