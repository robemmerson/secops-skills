# Devo tables: naming, choosing a table, union tables

Use this file to decide which table to put after `from` and which fields it has. For the full list
of source table names by category, grep `table-catalogue.md` (one line per product).

## Contents

1. [How table names work](#1-how-table-names-work)
2. [Finding the right table](#2-finding-the-right-table)
3. [Union table or source table?](#3-union-table-or-source-table)
4. [Quick pick for investigations](#4-quick-pick-for-investigations)
5. [Extra (hidden) fields](#5-extra-hidden-fields)
6. [DCDM: Devo Cyber Data Model](#6-dcdm-devo-cyber-data-model)
7. [Platform tables (siem.logtrust.*)](#7-platform-tables-siemlogtrust)
8. [Union table reference](#8-union-table-reference) (43 tables: purpose, sources, fields)

## 1. How table names work

- Each event arrives with a Devo **tag**. A **parser** splits the raw events stored under a tag into
  columns and shows them as a **table**. In most cases the tag and the table name are the same.
- Names are dot-separated levels, read left to right from general to specific:
  `technology.vendor.product.subtype...`, for example `firewall.paloalto.traffic`,
  `cloud.azure.ad.signin`, `box.win_nxlog.security`, `firewall.fortinet.event.vpn`.
  - Level 1 is the technology category (`auth`, `firewall`, `box` = operating systems, `cloud`,
    `edr`, `web`, `proxy`, `mail`, `dns`, ...). There are about 100 of them; each is a heading in
    `table-catalogue.md`.
  - Level 2 is usually the vendor or platform (`firewall.cisco`, `cloud.aws`, `auth.okta`).
    Some products put the collection method in level 2 instead (`box.win_nxlog`, `box.win_snare`,
    `box.unix`).
  - Further levels are the product, then the log type (`cloud.aws.cloudtrail.signin`,
    `edr.crowdstrike.falconstreaming.detection_summary`). Depth varies: `auth.okta` and
    `auth.okta.events` are both tables.
- Names are case-sensitive and some use camelCase (`web.apache.accessCombined`,
  `firewall.fortinet.utm.appCtrl`). Names containing a hyphen must be quoted with backticks in
  LINQ: ``from `firewall.huawei.ngfw.fw-log` ``.
- `cef0.*` tables hold events received in CEF format (for example `cef0.paloAltoNetworks.panOs`,
  `cef0.zscaler.nssweblog`). They are not listed on the category pages but feed several union tables.
- `*.all*` names (`auth.all`, `firewall.all.traffic`, `edr.all.threats`, `firewall.paloalto.all`)
  are almost always union tables. Section 8 lists every documented one.
- Namespaces outside the technology categories:
  - `my.` is the domain's own tables: `my.app.*` (custom application data, for example
    `my.app.log.log`), `my.upload.*` (files uploaded to the domain), and `my.lookuplist` lookups.
    `my.app.*` tables can be queried even when the table-metadata endpoint returns 404 for them;
    use `select * ... limit 1` to see their columns.
  - `siem.logtrust.*` is the Devo platform's own data: alerts, event counters, web activity. See section 7.
- Wildcards: Devo documents `?` (one character), `*` (any characters within one level) and `**`
  (one or more whole levels) for API token target tables, for example `firewall.fortinet.**` or
  `siem.logtrust.alert.*`. LINQ's `nameglob()` inside `anymatches()` uses the same `*`/`**` syntax
  on name fields. Wildcards in a `from` clause are not documented.
- **[verified] Prefix tables:** `from cloud.aws.cloudtrail` (a parent name, no wildcard) queries
  every table under it, and many library detections rely on this. It is slow like a union, even
  for a few minutes of data. Prefer the specific sub-table (e.g.
  `cloud.aws.cloudtrail.iam`) when you know the service.

## 2. Finding the right table

1. **Pick the category.** Map the question to level 1: sign-ins go to `auth`, `cloud.azure.ad`
   and `cloud.office365`; Windows/Linux hosts to `box`; firewalls to `firewall`; EDR to `edr` or
   `xdr`; DNS to `dns`/`ddi`; web servers to `web`; proxies to `proxy`/`swg`/`sig`; email to
   `mail`/`seg`; VPN to `vpn`; cloud control planes to `cloud`.
2. **Find the vendor.** Grep the catalogue by vendor or product, then by prefix:
   `grep -i 'okta' table-catalogue.md`, `grep 'firewall.fortinet' table-catalogue.md`.
   Vendors often spread over several categories (Fortinet appears under `firewall`, `iam`,
   `mail` and `waf`), so grep the vendor name rather than one category.
3. **Check what has data.** The catalogue lists every table Devo *can* parse, not what the domain
   receives. Check `devo.py tables --grep '<table>'` (the domain's cached live table list) and
   `devo.py cache notes`, or confirm with `siem.logtrust.collector.counter` (section 7) or a small
   `select * ... limit 1` over a short window, before building a query on a table.
4. **Get the columns.** Section 8 gives the fields of union tables. For a source table, run
   `devo.py fields <table>` (live-profiled, cached locally), `devo.py schema <table>`, or
   `select * ... limit 1`.

## 3. Union table or source table?

Union tables (common union tables) are created by Devo and available in every domain. They merge
events from many source tables of the same kind into one table with shared, normalised column
names (`source_ip`, `destination_port`, `user`, `action`...). Each row usually has a `source`
column that holds the originating table name. Domains can also have proprietary union tables,
created by users and visible only inside that domain.

**Performance:** union tables are slow. Counting even an hour of `auth.all`,
`firewall.all.traffic` or `network.dns` can take minutes, while the same work on a source table
usually returns in seconds.

Rules:

- **Default to the specific source table** (for example `cloud.azure.ad.signin`,
  `firewall.fortinet.traffic.forward`, `box.win_nxlog.security`). It is fast and has all the vendor's
  fields, not only the normalised subset.
- **Use a union table for cross-vendor pivots**: "has this IP, user or domain appeared anywhere in
  firewall/auth/DNS data?" Keep the window short (minutes to a few hours), filter early, and add
  `limit`.
- Use union tables to discover which sources carry an entity, then switch to the source tables it
  names (the `source` column) for the detailed work.
- Many union tables are empty in a given domain because none of their sources are sent. Check
  the source tables in the collector counter first.
- Many union tables carry an IP twice: `source_ip:str` and `source_ipv4:ip4` (same for
  destination). Filter IPs on the typed `*_ipv4` column, or compare strings on `*_ip`.

## 4. Quick pick for investigations

| Question | Union table (cross-vendor, slow) | Typical fast source tables |
| --- | --- | --- |
| Who signed in, from where, success/failure | `auth.all`, `cloud.azure.ad.signin_all` | `cloud.azure.ad.signin`, `cloud.azure.ad.noninteractive_user_signin`, `auth.okta.events`, `cloud.aws.cloudtrail.signin`, `cloud.gsuite.reports.login` |
| Windows host activity (logons, processes, PowerShell) | `box.all.win` | `box.win_nxlog.*`, `box.win_snare.*`, `box.win_winlogbeat.*`, `box.win_sysmon` |
| Linux host activity | `auth.unix`, `box.audit.unix` | `box.unix`, `box.audit.unix.auditd` |
| Network flows allowed/denied | `firewall.all.traffic`, `netstat.netflow.all` | `firewall.paloalto.traffic`, `firewall.fortinet.traffic.*`, `firewall.cisco.asa`, `cloud.aws.vpc.flow` |
| DNS lookups of a domain | `network.dns`, `domains.all` | `dns.windows`, `dns.infoblox.response`, `ids.bro.dns` |
| Web / proxy requests | `web.all.access`, `proxy.all.access` | `web.iis.accessW3c`, `web.nginx.accessCombined`, `proxy.zscaler.*`, `proxy.squid.*` |
| EDR detections and process trees | `edr.all.threats`, `edr.all.processes`, `edr.all.netconns` | `edr.crowdstrike.falconstreaming.detection_summary`, `edr.sentinelone.agent.threats`, `edr.microsoft_defender.*` |
| Email threats and message trace | `mail.all.threats`, `mail.all.messages` | `mail.proofpoint.tapsiem`, `mail.mimecast.*`, `mail.exchange.messagetracking` |
| Microsoft 365 audit (Exchange, SharePoint, Teams) | `cloud.office365.management` | `cloud.office365.management.exchange`, `.sharepoint`, `.azureactivedirectory` |
| IPS / IDS alerts | `ips.all.alerts`, `firewall.all.ips` | `firewall.paloalto.threat`, `firewall.fortinet.utm.ips` |
| VPN sessions | `firewall.all.vpn.auth`, `vpn.cisco.anyconnect.all` | `firewall.paloalto.globalprotect`, `firewall.fortinet.event.vpn` |
| Devo alerts that fired | - | `siem.logtrust.alert.info` |

## 5. Extra (hidden) fields

Union tables mark some fields as *Extra*: they are not returned by default and must be named
explicitly in `select`. In almost every union table these are `hostchain`, `tag` and usually
`rawMessage`/`rawSource` (sometimes `message`). If you need the raw event, select it by name.
Other extra fields are noted per table in section 8.

## 6. DCDM: Devo Cyber Data Model

The DCDM is Devo's semantic model for normalising data from many log sources into tables with the
same field names for the same data. So far it has been applied only to union tables; parsers are to
follow. What it means for queries:

- New field names are full words in snake_case with no vendor abbreviations: `srcIp` became
  `source_ip`; the vague `domain` in `auth.all` became `user_domain` (as opposed to a web domain).
- Old column names are hidden but kept as **aliases** of the new ones, so old queries and alerts
  keep working. Write new queries with the new names only: Devo warns that a query using both names
  for the same column will have problems.
- Existing union tables and parsers are being converted over time, so older tables (for example
  `network.dns`, with `srcIp`, `dstIp`) may still show the old style. Check the columns before you rely
  on a name.

## 7. Platform tables (siem.logtrust.*)

- `siem.logtrust.alert.info`: triggered Devo alerts, queryable with LINQ (for example
  `from siem.logtrust.alert.info select alertId`). `extraData` is a JSON string with the event
  context.
- `siem.logtrust.collector.counter`: event and byte counts per table. Fields: `eventdate`,
  `collector`, `engine`, `kind`, `object`, `events`, `bytes`. Rows with `kind = "table"` have the
  full table name in `object`. The inventory of tables with data is
  `from siem.logtrust.collector.counter where kind = "table" group by object select sum(events) as events`.
  A full day can take minutes, so use a short window when you can (`devo.py tables` caches
  the result).
  - `kind` values: `table` (object = full table name), `host` (object = the sending host) and
    `technology` (object = the technology part of the tag).
  - `collector` holds Devo-side ingestion nodes, not the customer's collectors or relays.
  - `kind = "host"` objects are hostchain strings or collector pod names; pod names churn
    (a new suffix after each restart or scale event), so group pods by deployment (strip the
    generated suffix) before calling a sender new or gone.
  - The counter can under-report, or miss whole hours or days, during platform incidents while
    the tables themselves are complete: confirm any gap by counting the table directly
    (`devo.py health` does this for stopped/dropped tables).
- `siem.logtrust.web.activity`, `siem.logtrust.web.navigation`, `siem.logtrust.web.connection`:
  activity, navigation and connections of users of the Devo web application. The Devo docs use
  `web.activity` as their standard example table, and `web.connection` feeds `auth.all`.
- `devo.*` tables (category `devo`) hold Devo collector metrics and Devo Endpoint Agent data.
  `devo.collectors.out` is the collectors' own log: credential or permission errors there
  (401/403, forbidden, expired token, invalid client secret) mean a collector may be pulling
  nothing for some services while the rest keeps flowing. `devo.py health` lists those collectors
  first (`AUTH`); see table-guide/cloud-tools.md.

Sending data into Devo (relay rules, collectors) is configured outside the Query API and is not
covered here.

## 8. Union table reference

Per table: purpose; source tables (count and names; abbreviated for per-log-type unions); normalised fields as `name:type`,
deduplicated across all sources; fields beyond the 45th are summarised. Types: `str`, `ip4`, `ip6`,
`int4`, `int8`, `float8`, `bool`, `timestamp`, `json`. A slash (`str/ip4`) means sources disagree.
Almost every table also has `source` (originating table) and the extra fields `hostchain` and `tag`.

### auth.all
Authentication events across IdPs, VPNs, databases, firewalls, ADCs and cloud sign-ins. Credential-access hunting across vendors.
- Sources (41): adn.f5.bigip.apm, adn.f5.bigip.audit, app.lastpass.events, auth.cisco.ise, auth.duo.administrator.login, auth.duo.authentication.events, auth.jumpcloud.all.events, auth.okta.events, auth.okta.system, auth.onelogin.events, auth.ping.federate.audit, auth.ping.federate.security_audit, auth.ping.id.mfa, auth.rsa.secureid.runtime, auth.securenvoy, auth.thycotic.secretserver, auth.unix, box.all.win, cef0.microsoft.microsoftWindows, cloud.aws.cloudtrail.events, cloud.aws.cloudtrail.signin, cloud.azure.ad.signin_all, cloud.azure.sql.audit, cloud.gsuite.reports.login, cloud.office365.management, crm.salesforceobjects.loginhistory, db.mssql.events, db.oracle.audit_trail, ddi.infoblox.audit, firewall.all.vpn.auth, firewall.cisco.asa, firewall.fortinet.event.system, firewall.juniper.srx.system, firewall.paloalto.globalprotect, firewall.paloalto.system, helpdesk.zendesk.audit.logs, network.cisco.switch, network.citrix.adc.sslvpn, siem.logtrust.web.connection, vpn.aws.client, vpn.cisco.asa.anyconnect
- Fields: eventdate:timestamp, source:str, action:str, machine:str, hostname:str, application:str, domain:str, user:str, source_ip:ip4, source_ipv4:ip4, source_hostname:str, source_user:str, username:str, user_identity_username:str, result:str, message:str, hostchain:str, tag:str

### auth.jumpcloud.all.events
All JumpCloud event tables (directory, LDAP, MDM, RADIUS, software, SSO, systems).
- Sources (7): auth.jumpcloud.directory.events, auth.jumpcloud.ldap.events, auth.jumpcloud.mdm.events, auth.jumpcloud.radius.events, auth.jumpcloud.software.events, auth.jumpcloud.sso.events, auth.jumpcloud.systems.events
- Fields: eventdate:timestamp, source:str, hostname:str, initiated_by__id:str, initiated_by__type:str, initiated_by__email:str, initiated_by__username:str, geoip__country_code:str, geoip__timezone:str, geoip__latitude:float8, geoip__continent_code:str, geoip__region_name:str, geoip__region_code:str, geoip__longitude:float8, resource__id:str, resource__type:str, resource__username:str, changes:str, auth_method:str, event_type:str, provider:str, service:str, organization:str, at_version:str, client_ipv4:ip4, client_ipv6:ip6, id:str, user_agent__patch:str, user_agent__minor:str, user_agent__os:str, user_agent__major:str, user_agent__build:str, user_agent__name:str, user_agent__os_name:str, user_agent__device:str, timestamp:timestamp, err:str, error_message:str, start_tls:bool, tls_established:bool, dn:str, mech:str, connection_id:str, port:str, success:bool ... (+34 more; 79 fields in total)

### auth.unix
UNIX/Linux authentication and system events (syslog, auditd, Devo endpoint agent, ESXi, Azure VM).
- Sources (6): box.audit.unix, box.devo_ea.events_linux, box.unix, box.unix_cloudwatch, box.vmware.esx, cloud.azure.vm.unix
- Fields: eventdate:timestamp, source:str, action:str, machine:str, application:str, appName:str, user:str, source_ip:ip4, source_hostname:str, source_user:str, message:str, hostchain:str, tag:str, application_name:str

### av.all.threats
Antivirus threat detections (McAfee ePO, Sophos, Symantec SEP).
- Sources (3): av.mcafee.epo.threat, av.sophos.threats, av.symantec.sepc.events
- Fields: eventdate:timestamp, machine:str, source:str, source_name:str, username:str, threat_name:str, hostname:str, action:str, message:str, hostchain:str, tag:str

### box.all.win
Windows event logs from all Windows collection methods (NXLog, Snare, Winlogbeat, Kinesis, CloudWatch, Azure VM, Devo agents...). The source page lists no field table.
- Sources (16): box.devo_ea.events_windows, box.devo_ua.events_windows, box.win, box.win_classic, box.win_cloudwatch, box.win_hf, box.win_kinesis, box.win_nxlog, box.win_quest.change_auditor.leef, box.win_snare, box.win_solarwinds, box.win_winlogbeat, box.winNxlog, cloud.azure.vm.applicationevent, cloud.azure.vm.securityevent, cloud.azure.vm.systemevent
- Fields: (none listed on the source page)

### box.audit.unix
Linux auditd/audispd records (the page also lists box.unix).
- Sources (3): box.audit.unix.audispd, box.audit.unix.auditd, box.unix
- Fields: eventdate:timestamp, source:str, machine:str, node:str, type:str, audit_timestamp:str, audit_id:str, pid:str, uid:str, gid:str, auid:str, ses:str, old_auid:str, old_ses:str, op:str, opType:str, acct:str, id:str, exe:str, hostname:str, addr:str, terminal:str, res:str, comm:str, reason:str, sig:str, dev:str, prom:str, old_prom:str, fver:str, fp:str, fi:str, fe:str, old_pp:str, old_pi:str, old_pe:str, old_pa:str, pp:str, pi:str, pe:str, pa:str, grantors:str, kind:str, direction:str, spid:str ... (+63 more; 108 fields in total)

### cdn.all.access
CDN access logs (Akamai, Triton).
- Sources (2): cdn.akamai.access, cdn.triton.access
- Fields: eventdate:timestamp, source:str, timestamp:str, hits:str, fecha:str, titulo:str, autor:str, programa:str, seccion:str, emisora:str, tema:str, id_ref:str, duracion:str, horas:str, url_audio:str, url_source:str, tipo:str, fuente:str, hostchain:str, tag:str

### cef0.fortinet.fortigateAll
FortiGate events received in CEF format, all models.
- Sources (6): cef0.fortinet.fortigate, cef0.fortinet.fortigate200e, cef0.fortinet.fortigate300d, cef0.fortinet.fortigate400e, cef0.fortinet.fortigate600e, cef0.fortinet.fortigate60e
- Fields: eventdate:timestamp, source:str, _cefVer:str, act:str, app:str, cat:str, c6a4Label:str, deviceExternalid:str, deviceInboundInterface:str, deviceOutboundInterface:str, dst:ip4, dpt:int4, dvchost:str, in:int8, out:int8, proto:str, rt:timestamp, src:ip4, agt:str, atz:str, categoryBehavior:str, categoryDeviceGroup:str, categoryObject:str, categoryOutcome:str, categorySignificance:str, deviceSeverity:str, dtz:str, eventId:str, rawMessage:str, hostchain:str, tag:str, deviceExternalId:str, in:int8, ahost:str, art:str, rawSource:str

### cloud.azure.ad.signin_all
All Entra ID (Azure AD) sign-in types: interactive, non-interactive, service principal, managed identity.
- Sources (5): cloud.azure.ad.interactive_user_signin, cloud.azure.ad.managed_identity_signin, cloud.azure.ad.noninteractive_user_signin, cloud.azure.ad.service_principal_signin, cloud.azure.ad.signin
- Fields: eventdate:timestamp, machine:str, source:str, region:str, action:str, application:str, user:str, source_ip:str, source_ipv4:ip4, source_ipv6:ip6, id:str, timestamp:timestamp, created_datetime:str, resource_id:str, signin_event_types:str, operation_name:str, operation_version:str, category:str, tenant_id:str, result:str, result_signature:str, result_description:str, duration_ms:int4, correlation_id:str, location:str, error_code:int4, failure_reason:str, user_agent:str, properties:json, message:str, hostchain:str, tag:str

### cloud.office365.management
Microsoft 365 Management Activity API events, one source table per workload (Exchange, SharePoint, OneDrive, Teams, Azure AD, DLP...). Field transformations are split over the five "Tables from N to M" pages.
- Sources (36): cloud.office365.management.aip, cloud.office365.management.airinvestigation, cloud.office365.management.azureactivedirectory, cloud.office365.management.cca, cloud.office365.management.compliance, cloud.office365.management.compliancemanager, cloud.office365.management.corereporting, cloud.office365.management.crm, ... (36 in total)
- Fields: eventdate:timestamp, hostname:str, type:str, Id:str, Workload:str, StatusTime:str, FeatureStatus:str, Status:str, StatusDisplayName:str, IncidentIds:str, WorkloadDisplayName:str, UserType:int4, timestamp:timestamp, Operation:str, Version:int4, LogonType:int4, MailboxOwnerSid:str, ExternalAccess:bool, OrganizationName:str, SessionId:str, ClientAddress:str, ClientIPAddress:str, ClientProcessName:str, ResultStatus:str, UserId:str, LogonUserSid:str, InternalLogonType:int4, OriginatingServer:str, UserKey:str, MailboxGuid:str, OrganizationId:str, RecordType:int4, ClientInfoString:str, MailboxOwnerUPN:str, CrossMailboxOperation:bool, AffectedItems:str, Folder_Id:str, Folder_Path:str, FoldersItemsStr:str, ForwardTo:str, Parameters_Raw:str, Item_Subject:str, Item_Attachments:str, Item_ParentFolder_Id:str, Item_ParentFolder_Path:str ... (+223 more; 268 fields in total)

### ddi.infoblox.dns.queries_responses
Infoblox DNS queries, responses and query errors.
- Sources (3): ddi.infoblox.dns.infobloxResponses, ddi.infoblox.dns.queries, ddi.infoblox.dns.queryErrors
- Fields: eventdate:timestamp, hostname:str, server:str, pid:int4, ib_category:str, message:str, client_object:str, client_ip:str, port:int4, dns_client_signer:str, query_name:str, query:str, class:str, type:str, flags:str, recursion_desired:bool, query_signed:bool, edns:bool, edns_version:int4, tcp:bool, dnssec:bool, checking_disabled:bool, valid_dns_server_cookie_rcv:bool, dns_cookie_without_valid_server_cookie:bool, dnsServer:ip4, info_error:str, error:str, action:str, serverdate:timestamp, protocol:str, dns_view:str, response_info:str, rcode:str, recursion:bool, authoritative_answer:bool, truncated_response:bool, edns_opt_record:bool, dnssec_records_validated:bool, dtc_synthetic_record:bool, rr_text:str, hostchain:str, tag:str, rawMessage:str

### dhcp.all
DHCP lease events (Infoblox, BlueCat, Microsoft, ISC/UNIX, Palo Alto, NXLog).
- Sources (9): box.win_nxlog.dhcp, ddi.infoblox.dhcp.dhcpd, dhcp.bluecat.dhcpd, dhcp.infoblox.stdout, dhcp.isc.stdout, dhcp.microsoft.ip4, dhcp.microsoft.ip6, dhcp.unix.stdout, firewall.paloalto.system
- Fields: eventdate:timestamp, source:str, signature:str, source_ip:str, source_ipv4:ip4, source_hostname:str, source_mac:str, destination_mac:str, description:str, lease_ip:str, lease_mac:str, message:str, rawTagged:str, rawMessage:str, hostchain:str, tag:str, rawSource:str

### domains.all
Domain names seen across DNS, proxy and web logs; pivot on a domain across vendors.
- Sources (14): ddi.infoblox.dns.queries, dns.bind.query, dns.bluecat.named, dns.bluecat.stats, dns.infoblox.response, dns.windows, edr.crowdstrike.cannon.dnsrequest, firewall.fortinet.event.dns, ids.bro.dns, ids.bro.http, proxy.all.access, proxy.zscaler.zia.dns, sig.cisco.umbrella.dns, web.all.access
- Fields: eventdate:timestamp, domain:str, url:str, user_agent:str, source:str, source_ip:ip4, method:str, user:str, hostchain:str, tag:str

### edr.all.netconns
EDR network-connection events (Carbon Black Cloud, CrowdStrike, SentinelOne).
- Sources (3): edr.cbef.endpoint_event.netconn, edr.crowdstrike.cannon.networkconnectip4, edr.sentinelone.dv.events
- Fields: eventdate:timestamp, source:str, event_id:str, pid:str, agent_id:str, domain:str, protocol:str, source_ip:ip4, source_port:str, destination_ip:ip4, destination_port:str, inbound:str, url:str, rawMessage:str, hostchain:str, tag:str, rawSource:str

### edr.all.processes
EDR process-execution events (Carbon Black Cloud, Cisco AMP, CrowdStrike, Defender Advanced Hunting, SentinelOne, Tanium).
- Sources (6): edr.crowdstrike.cannon.processrollup2, edr.cbef.endpoint_event.procstart, edr.cisco.amp.events, edr.microsoft_defender.advanced_hunting.device_process_events, edr.tanium.events, edr.sentinelone.dv.events
- Fields: eventdate:timestamp, source:str, agent_id:str, event_id:str, source_ip:ip4, source_hostname:str, source_username:str, command_line:str, file_path:str, folder_path:str, file_name:str, md5:str, ppid:str, pid:str, raw_pid:str, platform:str, sha1:str, sha256:str, parent_path:str, rawMessage:str, hostchain:str, tag:str, rawSource:str, md5_hash_data:str, sha1_hash_data:str, sha256_hash_data:str

### edr.all.threats
EDR/XDR threat detections and alerts across vendors.
- Sources (27): av.sentinelone.rfc_5424, cef0.bit9CarbonblackJson.cbResponse, cef0.paloAltoNetworks.cortexXdr, cef0.paloAltoNetworks.cortexXdrAgent, cloud.sophos.central.alerts, cloud.sophos.central.events, edr.carbonblack.alert, edr.carbonblack.protect, edr.cbef.alert.cb_analytics, edr.cbef.alert.watchlist, edr.cortex_xdr.alerts, edr.cortex_xdr.incident_alert, edr.crowdstrike.cannon, edr.crowdstrike.falcon, edr.crowdstrike.falconstreaming.detection_summary, edr.crowdstrike.falconstreaming.epp_detection_summary, edr.cylance.device, edr.cylance.threats, edr.fireeye.alerts, edr.microsoft_defender.endpoint.alerts, edr.minervalabs.events, edr.sentinelone.agent.threats, edr.symantec.events, edr.tanium.events, edr.tanium.threats, endpoint.carbonblack.protection, xdr.cynet.alerts.events
- Fields: eventdate:timestamp, source:str, ip:ip4, mac:str, sha256:str, sha1:str, md5:str, file_name:str, file_path:str, message:str, status:str, rule:str, hostname:str, threat_name:str, severity:str, user:str, threat_type:str, pid:str, parent_pid:str, rawMessage:str, hostchain:str, tag:str

### edr.carbonblack.all
All Carbon Black tables.
- Sources (7): cef0.bit9CarbonblackJson.cbResponse, edr.carbonblack.alert, edr.carbonblack.binary, edr.carbonblack.feed, edr.carbonblack.ingress, edr.carbonblack.protect, edr.carbonblack.watchlist
- Fields: eventdate:timestamp, source:str, ip:str, mac:str, sha256:str, sha1:str, md5:str, file_name:str, file_path:str, message:str, status:str, rule:str, hostname:str, threat:str, severity:str, user:str, type:str, pid:str, rawMessage:str, hostchain:str, tag:str, rawSource:str

### edr.crowdstrike.falconstreaming.user_activity_all
CrowdStrike Falcon Streaming user-activity audit events.
- Sources (9): edr.crowdstrike.falconstreaming.user_activity_detections, edr.crowdstrike.falconstreaming.user_activity_device_control_policy, edr.crowdstrike.falconstreaming.user_activity_devices, edr.crowdstrike.falconstreaming.user_activity_groups, edr.crowdstrike.falconstreaming.user_activity_ip_whitelist, edr.crowdstrike.falconstreaming.user_activity_other, edr.crowdstrike.falconstreaming.user_activity_prevention_policy, edr.crowdstrike.falconstreaming.user_activity_quarantined_files, edr.crowdstrike.falconstreaming.user_activity_sensor_update_policy
- Fields: eventdate:timestamp, source:str, customerIDString:str, offset:int8, eventCreationTime:timestamp, version:str, eventType:str, ServiceName:str, OperationName:str, UTCTimestamp:timestamp, UserId:str, UserIp:ip4, AuditKeyValues:json, jsonEvent:json, rawMessage:str, hostchain:str, tag:str

### firewall.all.cpu
Firewall CPU usage (Fortinet, Sophos XG).
- Sources (2): firewall.fortinet.event.system, firewall.sophos.xgfirewall.systemhealth
- Fields: eventdate:timestamp, source:str, firewall_name:str, firewall_cluster:str, firewall_cpu:int8, rawMessage:str, hostchain:str, tag:str, rawSource:str

### firewall.all.ips
Firewall IPS events (Fortinet, SonicWall, Check Point).
- Sources (3): firewall.checkpoint.log_exporter, firewall.fortinet.utm.ips, firewall.sonicwall.genv58
- Fields: eventdate:timestamp, source:str, firewall_name:str, firewall_cluster:str, source_ip:str, source_ipv4:ip4, source_port:str, destination_ip:str, destination_ipv4:ip4, destination_port:str, action:str, severity:str, attack_name:str, attack_id:str, rawMessage:str, hostchain:str, tag:str, rawSource:str

### firewall.all.mem
Firewall memory usage (Fortinet, Sophos XG).
- Sources (2): firewall.fortinet.event.system, firewall.sophos.xgfirewall.systemhealth
- Fields: eventdate:timestamp, source:str, firewall_name:str, firewall_cluster:str, firewall_memory:int8, rawMessage:str, hostchain:str, tag:str, rawSource:str

### firewall.all.traffic
Firewall allow/deny traffic events from most firewall vendors (Check Point, Cisco, Fortinet, Juniper, Palo Alto, Meraki, pfSense, Azure Firewall, CEF feeds...).
- Sources (49): adn.f5.bigip.afm, adn.f5.bigip.asm, box.iptables, cef0.checkPoint.vpn1Firewall1, cef0.cisco.asa, cef0.cisco.firepower, cef0.forcepoint.firewall, cef0.fortinet.fortigateAll, cef0.paloAltoNetworks.lf, cef0.paloAltoNetworks.panOs, cef0.stonesoft.firewall, cef0.stonesoft.stonegate, cef0.zscaler.nssfwlog, cloud.azure.firewall.application_rule, cloud.azure.firewall.network_rule, cloud.cloudflare.logpush.http, edr.crowdstrike.falconstreaming.firewall_match, firewall.checkpoint.fw, firewall.checkpoint.gaia, firewall.checkpoint.lea, firewall.checkpoint.log_exporter, firewall.cisco.asa, firewall.cisco.fmc, firewall.cisco.fmc_estreamer, firewall.cisco.ftd, firewall.cisco.fwsm, firewall.cisco.pix, firewall.fortinet.traffic, firewall.juniper.isg.traffic, firewall.juniper.nsm.traffic, firewall.juniper.srx.traffic, firewall.juniper.ssg.traffic, firewall.meraki.flows, firewall.paloalto.traffic, firewall.pfsense.filterlog, firewall.pfsense.firewall, firewall.sangfor.app_control.event, firewall.sonicwall.genv58, firewall.sophos.securenet.packetfilter, firewall.sophos.xgfirewall.firewall, firewall.stonegate.leef, firewall.stonegate.xml, firewall.velocloud.traffic, firewall.vyatta.traffic, firewall.watchguard.traffic, network.meraki.firewall, network.meraki.l7_firewall, proxy.zscaler.nss_firewall, proxy.zscaler.zia.firewall
- Fields: eventdate:timestamp, source:str, hostname:str, firewall_name:str, firewall_cluster:str, action:str, reason:str, source_ipv4:ip4, source_ip:str, destination_ipv4:ip4, destination_ip:str, source_port:str, destination_port:str, source_zone:str, destination_zone:str, application:str, protocol:str, rule:str, source_interface:str, destination_interface:str, source_service:str, destination_service:str, packets_total:int8, packets_sent:int8, packets_received:int8, bytes_total:int8, bytes_sent:int8, bytes_received:int8, source_username:str, x_forwarded_for_ip:str, firewall_ip:str, rawSource:str, rawMessage:str, hostchain:str, tag:str

### firewall.all.virus
Firewall antivirus detections (Fortinet, SonicWall).
- Sources (2): firewall.fortinet.utm.virus, firewall.sonicwall.genv58
- Fields: eventdate:timestamp, source:str, firewall_name:str, firewall_cluster:str, severity:str, source_ip:str, source_ipv4:ip4, source_port:str, destination_ip:str, destination_ipv4:ip4, destination_port:str, user:str, virus_name:str, virus_subtype:str, hostchain:str, tag:str, rawMessage:str, rawSource:str

### firewall.all.vpn.auth
Firewall VPN authentication events (Fortinet, SonicWall).
- Sources (2): firewall.fortinet.event.vpn, firewall.sonicwall.genv58
- Fields: eventdate:timestamp, source:str, firewall_name:str, firewall_cluster:str, source_ip:str, source_ipv4:ip4, source_port:str, destination_ip:str, destination_ipv4:ip4, destination_port:str, user:str, action:str, reason:str, message:str, type:str, rawMessage:str, hostchain:str, tag:str, rawSource:str

### firewall.all.vpn.traffic
Firewall VPN tunnel traffic (Fortinet, SonicWall).
- Sources (2): firewall.fortinet.event.vpn, firewall.sonicwall.genv58
- Fields: eventdate:timestamp, source:str, firewall_name:str, firewall_cluster:str, source_ip:str, source_ipv4:ip4, source_port:str, destination_ip:str, destination_ipv4:ip4, destination_port:str, bytes_sent:int8, bytes_received:int8, user:str, tunnel_type:str, tunnel_name:str, duration:int8, rawMessage:str, hostchain:str, tag:str, rawSource:str

### firewall.all.webfilter
Firewall web-filter events (Fortinet, SonicWall, Sophos XG).
- Sources (3): firewall.fortinet.utm.webfilter, firewall.sonicwall.genv58, firewall.sophos.xgfirewall.contentfiltering
- Fields: eventdate:timestamp, source:str, firewall_name:str, firewall_cluster:str, level:str, source_ip:str, source_ipv4:ip4, source_port:str, destination_ip:str, destination_ipv4:ip4, destination_port:str, bytes_sent:int8, bytes_received:int8, action:str, user:str, category:str, hostname:str, rawMessage:str, hostchain:str, tag:str, rawSource:str

### firewall.paloalto.all
All Palo Alto firewall log types (traffic, threat, URL, system, config, GlobalProtect, User-ID...).
- Sources (12): firewall.paloalto.auth, firewall.paloalto.config, firewall.paloalto.correlation, firewall.paloalto.decryption, firewall.paloalto.globalprotect, firewall.paloalto.hipmatch, firewall.paloalto.iptag, firewall.paloalto.system, firewall.paloalto.threat, firewall.paloalto.traffic, firewall.paloalto.url, firewall.paloalto.userid
- Fields: eventdate:timestamp, timestamp:timestamp, received_date:timestamp, machine:str, log_type:str, subtype:str, serial:str, source_ip:str, source_ipv4:ip4, destination_ip:str, destination_ipv4:ip4, source_nat_ip:str, source_nat_ipv4:ip4, destination_nat_ip:str, destination_nat_ipv4:ip4, rule:str, session:str, source_username:str, destination_username:str, application:str, virtual_system:str, source_zone:str, destination_zone:str, source_interface:str, destination_interface:str, log_action:str, repeat_count:int4, source_port:str, destination_port:str, source_nat_port:str, destination_nat_port:str, flags:str, protocol:str, action:str, category:str, sequence_number:int8, action_flags:str, device_name:str, bytes_total:int8, bytes_sent:int8, bytes_received:int8, packets_total:int4, source_geo_country_name:str, destination_geo_country_name:str, session_end_reason:str ... (+8 more; 53 fields in total)

### ftp.all.access
FTP access logs (IIS FTP).
- Sources (1): ftp.iis.accessW3cAll
- Fields: eventdate:timestamp, source:str, environment:str, site:str, clon:str, date:str, time:str, client_ip:str, client_ipv4:ip4, client_port:str, client_username:str, server_site:str, server_name:str, server_hostname:str, server_ip:str, server_ipv4:ip4, server_port:str, method:str, file_requested:str, status_code:str, bytes_sent:int8, bytes_received:int8, duration:int8, session:str, file_path:str, info:str, rawMessage:str, hostchain:str, tag:str

### ids.bricata.alerts.all
Bricata IDS alerts.
- Sources (2): ids.bricata.brocata, ids.bricata.burocata
- Fields: eventdate:timestamp, originator:str, host:str, destination_ip:str, destination_ipv4:ip4, destination_port:str, event_type:str, protocol:str, source_ip:str, source_ipv4:ip4, source_port:str, timestamp:str, alert_category:str, alert_revision:int8, alert_severity:int8, alert_signature:str, alert_signature_id:int8, event_format:str, event_source:str, event_uuid:str, sensor_ipv4:ip4, sensor_uuid:str, source_geo_city_name:str, source_geo_country_name:str, source_geo_latitude:float8, source_geo_longitude:float8, destination_geo_city_name:str, destination_geo_country_name:str, destination_geo_latitude:float8, destination_geo_longitude:float8, bytes_analyzed:str, connection_uids:str, download:bool, file_id:str, file_description:str, file_name:str, md5:str, mime_type:str, bro_protocol:str, recipient_destination_ip:str, recipient_destination_ipv4:ip4, recipient_destination_port:str, sha1:str, stored_as:str, transfer_protocol:str ... (+25 more; 70 fields in total)

### ips.all.alerts
IPS alerts from dedicated IPS and firewall IPS modules.
- Sources (15): cef0.cisco.asa, cef0.cisco.firepower, firewall.checkpoint.log_exporter, firewall.fortinet.ips.anomaly, firewall.fortinet.utm.anomaly, firewall.fortinet.utm.ips, firewall.paloalto.threat, firewall.sonicwall.genv58, firewall.sophos.securenet.ips, firewall.stonegate.ips, ips.cisco.sdee.alerts, ips.corero.common, ips.mcafee.nsm.events, ips.proventia.siteprotector.leef, ips.toplayer.common
- Fields: eventdate:timestamp, source_tag:str, sensor:str, source_ip:str, source_ipv4:ip4, destination_ip:str, destination_ipv4:ip4, source_port:str, destination_port:str, protocol:str, rule:str, rule_id:str, status:str, severity:str, source_interface:str, destination_interface:str, source_service:str, destination_service:str, action:str, message:str, hostchain:str, tag:str

### mail.all.messages
Mail message tracking (Mimecast, Proofpoint TAP, Trend Micro).
- Sources (4): mail.mimecast.siem, mail.proofpoint.tapsiem, mail.proofpoint.tapsiem_v2, mail.trend_micro.email_security.mail_tracking
- Fields: eventdate:timestamp, source:str, sender:str, source_ip:str, recipient:str, mail_id:str, subject:str, size:int8, hostchain:str, tag:str

### mail.all.threats
Mail threats, spam and phishing (Abnormal, Agari, Egress, Exchange, Mimecast, Proofpoint...).
- Sources (9): mail.abnormalsecurity.threats, mail.agari.phishing_defense.messages, mail.egress.defend.phishing_events, mail.exchange.messagetracking, mail.mimecast.siem.spameventthread, mail.mimecast.threat.feed, mail.proofpoint.tapsiem, mail.proofpoint.tapsiem_v2, mail.proofpoint.trap
- Fields: eventdate:timestamp, machine:str, source:str, sender_ip:str, sender_ipv4:ip4, subject:str, msg_id:str, hostname:str, recipient:str, sender:str, receiver:str, cc:str, bcc:str, action:str, spam_score:int4, attack_type:str, attachment_names:str, attachment_size_string:str, attachment_extension:str, rawMessage:str, hostchain:str, tag:str, rawSource:str

### mail.proofpoint.pod
Proofpoint on Demand events, maillog, message and isolation tables.
- Sources (4): mail.proofpoint.pod.events, mail.proofpoint.pod.isolation, mail.proofpoint.pod.maillog, mail.proofpoint.pod.message
- Fields: eventdate:timestamp, connection__ip:ip4, connection__country:str, connection__resolveStatus:str, connection__helo:str, connection__sid:str, connection__protocol:str, connection__host:str, connection__tls__inbound__cipherBits:int4, connection__tls__inbound__version:str, connection__tls__inbound__cipher:str, metadata__origin__data__agent:str, metadata__origin__data__version:str, metadata__origin__data__cid:str, ts:str, msgParts:str, filter__qid:str, filter__actions:str, filter__durationSecs:float8, filter__suborgs__sender:str, filter__suborgs__rcpts:str, filter__startTime:str, filter__isMsgReinjected:bool, filter__modules__pdr__v2__rscore:int4, filter__modules__pdr__v2__response:str, filter__modules__urldefense__counts__unique:int4, filter__modules__urldefense__counts__rewritten:int4, filter__modules__urldefense__counts__total:int4, filter__modules__urldefense__counts__noRewriteIsExcludedDomain:int4, filter__modules__urldefense__counts__noRewriteIsEmail:int4, filter__modules__urldefense__counts__noRewriteIsSchemeless:int4, filter__modules__urldefense__counts__noRewriteIsUnsupportedScheme:int4, filter__modules__urldefense__version__engine:str, filter__modules__spf__domain:str, filter__modules__spf__result:str, filter__modules__zerohour__score:str, filter__modules__spam__charsets:str, filter__modules__spam__langs:str, filter__modules__spam__version__definitions:str, filter__modules__spam__version__engine:str, filter__modules__spam__scores__engine:int4, filter__modules__spam__scores__classifiers__mlx:int4, filter__modules__spam__scores__classifiers__suspect:int4, filter__modules__spam__scores__classifiers__lowpriority:int4, filter__modules__spam__scores__classifiers__adult:int4 ... (+145 more; 190 fields in total)

### nac.aruba.sessions
Aruba ClearPass NAC sessions, failed authentications and RADIUS.
- Sources (3): nac.aruba.sessions.common, nac.aruba.sessions.failed_authentications, nac.aruba.sessions.radius
- Fields: eventdate:timestamp, host:str, subtype:str, time:str, eventID:str, hostIP:ip4, type:str, id1:str, id2:str, id3:str, Alerts:str, AlertsPresent:int4, AuditPostureToken:str, AuthType:str, ConnectionStatus:str, EnforcementProfiles:str, ErrorCode:str, HostMACAddress:str, LoginStatus:str, MonitorMode:str, NASIPAddress:str, NASPort:str, RequestId:str, RequestTimestamp:timestamp, Roles:str, Service:str, SessionLogTimestamp:timestamp, Source:str, SystemPostureToken:str, Username:str, AcctAuthentic:str, AcctCalledStationId:str, AcctDelayTime:str, AcctStatusType:str, AuthMethod:str, AuthSource:str, AcctTimestamp:timestamp, AcctSessionId:str, AcctFramedIPAddress:ip4, AcctCallingStationId:str, AcctNASPortType:str, AcctNASPort:str, AcctNASIPAddress:ip4, AcctUsername:str, AcctInputOctets:str ... (+5 more; 50 fields in total)

### netstat.netflow.all
Flow records: NetFlow v9, IPFIX, AWS VPC Flow Logs, AWS Network Firewall netflow.
- Sources (6): cloud.aws.firewall.netflow, cloud.aws.vpc.flow, netstat.netflow.ipfix, netstat.netflow.lt, netstat.netflow.v9, vpc.aws.flow
- Fields: eventdate:timestamp, source:str, hostname:str, version:int4, flow_sequence:int8, source_ip:str, source_ipv4:ip4, source_port:str, destination_ip:str, destination_ipv4:ip4, destination_port:str, protocol:str, packets:int4, bytes:int4, header_date:timestamp, start:timestamp, end:timestamp, ingress_interface:int4, egress_interface:int4, tcp_flags:int4, next_hop:ip4, bgp_next_hop:ip4, source_as_number:int4, destination_as_number:int4, source_mask:int4, destination_mask:int4, direction:int4, flow_sampler_id:int4, tos:int4, hostchain:str, tag:str

### network.dns
DNS query/response events from DNS servers, firewalls, EDR and network sensors.
- Sources (13): box.devo_ea.files.dns_windows, cloud.azure.firewall.dns_proxy, ddi.infoblox.dns.queries_responses, dns.bind.query, dns.bluecat.named, dns.bluecat.stats, dns.infoblox.bloxonethreatdefense.threats, dns.infoblox.response, dns.windows, edr.crowdstrike.cannon.dnsrequest, firewall.paloalto.traffic, ids.bro.dns, ids.corelight.dns
- Fields: eventdate:timestamp, requestCount:str, qclass:str, category:str, answers:str, source:str, protocol:str, qr:str, response:str, rawMessage:str, hostchain:str, tag:str, raw:str, serverdate:timestamp, severity:str, srcIp:ip4, dstIp:ip4, name:str, type:str, flags:str, dnsServer:ip4, srcPort:int8, destPort:str, PID:str, TTL:str, client:str, layouterror:str, layout:str
- Also Extra: client, layouterror, layout

### proxy.all.access
Web proxy access logs (Blue Coat, Forcepoint, McAfee, Squid, Zscaler, HAProxy...).
- Sources (23): cef0.zscaler.nssweblog, firewall.sophos.xgfirewall.contentfiltering, proxy.bluecoat.proxysg.bcreportermain_v1, proxy.bluecoat.proxysg.main, proxy.forcepoint.access, proxy.haproxy.all, proxy.ironport.access.squid, proxy.isaserver.accessW3cAb, proxy.mcafee.webgw.accessAb, proxy.mcafee.webgw.default, proxy.squid.accessClf, proxy.squid.accessCombined, proxy.squid.accessLt, proxy.squid.accessSquid, proxy.squid.accessSquidMime, proxy.varnish.accessCombined, proxy.varnish.accessCombinedXff, proxy.zscaler.access, proxy.zscaler.nss, proxy.zscaler.nss_web, proxy.zscaler.zia.web, sig.cisco.umbrella.proxy, utm.cisco.wsa.accessStd
- Fields: eventdate:timestamp, source:str, machine:str, serverdate:timestamp, srcIp:ip4, srcHost:str, srcPort:int4, user:str, method:str, dstHost:str, dstIp:ip4, url:str, protocol:str, statusCode:int4, referer:str, userAgent:str, hitMiss_requestStat:str, requestLength:int8, responseTime:int4, responseLength:int8, contentType:str, categories:str, location:str, hostchain:str, tag:str, rawMessage:str, rawSource:str

### proxy.haproxy.all
HAProxy CLF, HTTP and TCP logs.
- Sources (3): proxy.haproxy.clf, proxy.haproxy.http, proxy.haproxy.tcp
- Fields: eventdate:timestamp, environment:str, application:str, clone:str, source:str, message:str, server_date:str, machine:str, pid:str, source_ip:str, source_ipv4:ip4, source_port:str, accept_date:str, frontend_name:str, backend_name:str, server_name:str, timers:str, bytes_read:str, termination_state:str, actconn_feconn_beconn_srvconn_retries:str, server_queue:str, backend_queue:str, tr:str, status_code:str, method:str, url:str, protocol:str, rawMessage:str, hostchain:str, tag:str, rawSource:str

### syslog.all.stats
Syslog collector statistics.
- Sources (3): syslog.alcohol.stats, syslog.hybrid.stats, syslog.scoja.stats
- Fields: eventdate:timestamp, collector:str, engine:str, kind:str, subkind:str, parameters:str, partial_cpu:int8, partial_cpu_user:int8, partial_packets:int8, partial_bytes:int8, partial_events:int8, partial_event_bytes:int8, rawSource:str, hostchain:str, tag:str

### devo.ea
Devo Endpoint Agent events (agent, extensions, unknown); fields include osquery result columns.
- Sources (3): devo.ea.agent, devo.ea.extensions, devo.ea.unknown
- Fields: eventdate:timestamp, type:str, subtype:str, extensionName:str, action:str, calendarTime:str, columns:json, deamEntryPoint:str, deamHostname:str, deaAgentHostIp:ip4, deaAgentHostUuid:str, deaAgentHostname:str, deaAgentPlatform:str, deaAgentIdentifier:str, deaAgentTags:str, epoch:int8, osqueryName:str, osqueryUnixTime:timestamp, rawMessage:str, hostchain:str, tag:str

### ids.rscope
Reservoir R-Scope Advanced Threat Detection sensor logs; one source table per log type (conn, dns, http, files, ssl, smb...).
- Sources (48): ids.rscope.communication, ids.rscope.conn, ids.rscope.dce_rpc, ids.rscope.dhcp, ids.rscope.dns, ids.rscope.dpd, ids.rscope.files, ids.rscope.ftp, ... (48 in total)
- Fields: eventdate:timestamp, hostname:str, type:str, timestamp:timestamp, uid:str, id_orig_h:ip4, id_orig_p:int4, id_resp_h:ip4, id_resp_p:int4, rawMessage:str, hostchain:str, tag:str, rawSource:str

### vpn.cisco.anyconnect.all
Cisco AnyConnect VPN events from ASA and FTD.
- Sources (2): vpn.cisco.asa.anyconnect, vpn.cisco.ftd.anyconnect
- Fields: eventdate:timestamp, source:str, host:str, logType:str, Severity:int4, EventID:int8, Group:str, User:str, srcIP:ip4, srcIPV6:ip6, srcPort:int4, dstIP:ip4, dstPort:int4, interface:str, clientType:str, ipv4Address:ip4, ipv6Address:str, SessionType:str, Duration:str, BytesXmt:int8, BytesRcv:int8, Reason:str, svcMessage:str, svcMessageCode:str, Type:str, error:str, message:str, hostchain:str, tag:str, rawMessage:str

### web.all.access
Web server and load-balancer access logs (Apache, IIS, Nginx, AWS ALB/ELB/CloudFront/S3, Azure App Gateway, Akamai...).
- Sources (32): cdn.akamai.audit, cdn.akamai.cloudmonitor, cdn.akamai.cloudmonitor2, cdn.akamai.cloudmonitor3, cdn.akamai.monitor, cloud.aws.cloudfront.web_1, cloud.azure.appgateway.access_log, waf.fastly.nextgen_waf.request_feed, web.apache.accessClf, web.apache.accessCombined, web.apache.accessLt, web.apache.accessLtXff, web.apache.accessVhc, web.aws.alb.access, web.aws.cloudfront.accessW3c, web.aws.elb.access, web.aws.s3.access, web.iis.accessNcsa, web.iis.accessW3c, web.iis.accessW3cAll, web.iplanet.accessClf2, web.jboss.accessClf, web.jboss.accessCombined, web.jboss.accessLt, web.nginx.accessCombined, web.nginx.accessLt, web.nginx.accessLtXff, web.nginx.accessMain, web.tomcat.accessClf, web.tomcat.accessCombined, web.tomcat.accessLt, web.webseal.accessCombined
- Fields: eventdate:timestamp, source:str, environment:str, site:str, clon:str, server_date:timestamp, source_hostname:str, source_ip:str, source_ipv4:ip4, method:str, url:str, protocol:str, status_code:int4, referrer:str, user_agent:str, user:str, server_name:str, server_port:str, cookies:str, request_bytes:int4, response_bytes:int4, response_time:int4, response_time_millis:float8, hostchain:str, tag:str
