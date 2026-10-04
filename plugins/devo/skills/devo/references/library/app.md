# Detection library: APP

SaaS application audit detections (Slack). Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (2):

- SecOpsSlackMassDownloadEvents
- SecOpsSlackPossibleSessionHijacking

## SecOpsSlackMassDownloadEvents

**Summary:** Detects users downloading many files in a short amount of time via Slack.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Web Service (T1567)

**Tables:** app.slack.audit

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from app.slack.audit
where weaktoktains(action, "file_downloaded")
group every 30m by actor_email, action, context_location_type, context_location_domain, context_ip_address, client
select count() as count
where count > 10
select int(hllppcount(entity_file_id)) as num_files, first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select str(context_ip_address) as entity_sourceIP
select actor_email as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str",str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country",entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city",entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type",entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsSlackMassDownloadEvents") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSlackMassDownloadEvents") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques","SecOpsSlackMassDownloadEvents") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSlackMassDownloadEvents") as alertPriority
```

## SecOpsSlackPossibleSessionHijacking

**Summary:** Detects the same session ID used from a new IP for the same user in a short period of time.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Service Session Hijacking (T1563)

**Tables:** app.slack.audit

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from app.slack.audit
group every 5m by context_session_id, actor_email, context_location_type, context_location_domain, client
select int(hllppcount(context_ip_address)) as ip_count
where ip_count > 1
select first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select actor_email as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select `lu/SecOpsAssetRole/class`(entity_sourceAccount) as entity_sourceAccount_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsSlackPossibleSessionHijacking") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSlackPossibleSessionHijacking") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques","SecOpsSlackPossibleSessionHijacking") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSlackPossibleSessionHijacking") as alertPriority
```
