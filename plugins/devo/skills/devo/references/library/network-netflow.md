# Detection library: NETWORK/NETFLOW

NetFlow / Zeek (bro) network detections. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (1):

- SecOpsPossiblePortKnocking

## SecOpsPossiblePortKnocking

**Summary:** Possible port knocking has been detected from an IP outside of the organization.

**Description:** Actions observed as blocked to send large amounts of data from AWS out to the internet.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Traffic Signaling (T1205)

**Tables:** netstat.netflow.all

**Lookups:** SecOpsAssetRole, SecOpsPortAssignment, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from netstat.netflow.all
//where not srcIp <- x.x.x.x/24 //This IP and range need to be substituted for whatever is the customers public IP space
select source_ipv4 as attacker
select destination_ipv4 as victim
// The next two statements are saying not to watch for those ports because they are considered known ports.  Remove this is needed
where not `in`("80","53","22","443","21","25","445","5900","8080","3306","143","110",str(destination_port)) // Don't watch these ports for the destination
where not `in`("80","53","22","443","21","25","445","5900","8080","3306","143","110",str(source_port)) // Don't watch these ports for the source
group every 1m by header_date,attacker,source_port,victim,destination_port // Do a check every 4s.  This number should be modified to match the expected behaviour of the adversary, client
select str(attacker) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select nvl(`lu/SecOpsPortAssignment/Description`(int(source_port)), "Unknown") as enrichStream_entity_destPort_Purpose // If we don't have a value for that port than mark it as unknown
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPossiblePortKnocking") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPossiblePortKnocking") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPossiblePortKnocking") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPossiblePortKnocking") as alertPriority
```
