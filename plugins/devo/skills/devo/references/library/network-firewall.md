# Detection library: NETWORK/FIREWALL

Firewall traffic/system detections (firewall.all.traffic, Palo Alto, Fortinet). Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (33):

- SecOpsAnonymousConnection
- SecOpsCDFWSrcIpIsPossibleIoc
- SecOpsCDHuntFWdstIpIsPossibleIoc
- SecOpsFortinetCriticalAppUse
- SecOpsFortinetHighRiskAppUse
- SecOpsFWEmbargoedCountryInboundTrafficDetected
- SecOpsFWEmbargoedCountryOutboundTrafficDetected
- SecOpsFWExcessFirewallDenies
- SecOpsFWExcessFirewallDeniesOutbound
- SecOpsFWExternalSMBTrafficDetectedFirewall
- SecOpsFWIcmpExcessivePackets
- SecOpsFWIpScanExternal
- SecOpsFWIpScanInternal
- SecOpsFWIrcTrafficExternalDestination
- SecOpsFWPortScanExternalSource
- SecOpsFWPortScanInternalSource
- SecOpsFWPortSweepInternalSource
- SecOpsFWRDPExternalAccess
- SecOpsFWSigred
- SecOpsFWSMBInboundScanningDetected
- SecOpsFWSMBInternalScanningDetected
- SecOpsFWSMBTrafficOutbound
- SecOpsFwTftpOutboundTraffic
- SecOpsFWTrafficForeignDestination
- SecOpsFWTrafficOnUnassignedLowPort
- SecOpsHAFNIUMNetworkActivityTargetingExchangeServers
- SecOpsLog4ShellVulnOverFirewallTrafficConnections
- SecOpsPanAuthExcessiveFailedLoginIP
- SecOpsPanAuthExcessiveFailedLoginUser
- SecOpsPanAuthFailMultipleUserSingleIP
- SecOpsPossibleTrafficMirroring
- SecOpsRevilKaseyaNetworkActivity
- SecOpsVNCPortOpen

## SecOpsAnonymousConnection

**Summary:** Control over the navigation of the users and systems of the networks is considered essential to avoid risks. Access to anonymous navigation networks must be monitored.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Proxy (T1090)

**Tables:** firewall.all.traffic

**Lookups:** mispIndicator, SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.all.traffic
group every 15m by source_ipv4, destination_ipv4, destination_port, firewall_name, client
every 15m
where ispublic(destination_ipv4)
where toktains(lu("mispIndicator", "eventtags_name_str", str(destination_ipv4)), "TOR")
select str(source_ipv4) as entity_sourceIP
select str(destination_ipv4) as entity_destinationIP
select count() as hits
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAnonymousConnection") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAnonymousConnection") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAnonymousConnection") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAnonymousConnection") as alertPriority
```

## SecOpsCDFWSrcIpIsPossibleIoc

**Summary:** This search looks for Collective Defense matches in firewall data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(source_ipv4)
group every 15m by source_ipv4, source, destination_ipv4, client
select str(source_ipv4) as entity_sourceIP
select hlurjson("CollectiveDefense", entity_sourceIP, eventdate) as cd_hit
where isnotnull(cd_hit)
// The below lines separate each json object.  This is unecessary for this alert
select str(jqeval(jqcompile(".sectors"), cd_hit)) as sectors,
str(jqeval(jqcompile(".entity"), cd_hit)) as entity,
str(jqeval(jqcompile(".ueba_alerts"), cd_hit)) as ueba_alerts,
str(jqeval(jqcompile(".alerts"), cd_hit)) as alerts,
str(jqeval(jqcompile(".misp"), cd_hit)) as misp,
str(jqeval(jqcompile(".techniques"), cd_hit)) as techniques,
str(jqeval(jqcompile(".critical_alerts"), cd_hit)) as critical_alerts,
str(jqeval(jqcompile(".domain_c"), cd_hit)) as domain_c,
str(jqeval(jqcompile(".whois"), cd_hit)) as whois,
str(jqeval(jqcompile(".otx"), cd_hit)) as otx,
str(jqeval(jqcompile(".secops_alerts"), cd_hit)) as secops_alerts,
str(jqeval(jqcompile(".high_alerts"), cd_hit)) as high_alerts,
str(jqeval(jqcompile(".technique_c"), cd_hit)) as technique_c,
str(jqeval(jqcompile(".sector_c"), cd_hit)) as sector_c
//Entity Mapping Section
select str(destination_ipv4) as entity_destinationIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDFWSrcIpIsPossibleIoc") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDFWSrcIpIsPossibleIoc") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDFWSrcIpIsPossibleIoc") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDFWSrcIpIsPossibleIoc") as alertPriority
```

## SecOpsCDHuntFWdstIpIsPossibleIoc

**Summary:** This search looks for Collective Defense matches in firewall data.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Valid Accounts (T1078)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(destination_ipv4)
group every 15m by destination_ipv4, source, source_ipv4, client
select str(destination_ipv4) as entity_destinationIP
select str(source_ipv4) as entity_sourceIP
select hlurjson("CollectiveDefense", entity_destinationIP, eventdate) as cd_hit
where isnotnull(cd_hit)
// The below lines separate each json object.  This is unecessary for this alert
select str(jqeval(jqcompile(".sectors"), cd_hit)) as sectors,
str(jqeval(jqcompile(".entity"), cd_hit)) as entity,
str(jqeval(jqcompile(".ueba_alerts"), cd_hit)) as ueba_alerts,
str(jqeval(jqcompile(".alerts"), cd_hit)) as alerts,
str(jqeval(jqcompile(".misp"), cd_hit)) as misp,
str(jqeval(jqcompile(".techniques"), cd_hit)) as techniques,
str(jqeval(jqcompile(".critical_alerts"), cd_hit)) as critical_alerts,
str(jqeval(jqcompile(".domain_c"), cd_hit)) as domain_c,
str(jqeval(jqcompile(".whois"), cd_hit)) as whois,
str(jqeval(jqcompile(".otx"), cd_hit)) as otx,
str(jqeval(jqcompile(".secops_alerts"), cd_hit)) as secops_alerts,
str(jqeval(jqcompile(".high_alerts"), cd_hit)) as high_alerts,
str(jqeval(jqcompile(".technique_c"), cd_hit)) as technique_c,
str(jqeval(jqcompile(".sector_c"), cd_hit)) as sector_c
//Entity Mapping Section
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDHuntFWdstIpIsPossibleIoc") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDHuntFWdstIpIsPossibleIoc") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDHuntFWdstIpIsPossibleIoc") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDHuntFWdstIpIsPossibleIoc") as alertPriority
```

## SecOpsFortinetCriticalAppUse

**Summary:** Fortinet Firewall detected a critical risk application within the environment.

**MITRE:** Tactics: Resource Development (TA0042) | Techniques: Obtain Capabilities (T1588)

**Tables:** firewall.fortinet.traffic.forward

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.fortinet.traffic.forward
where `or`(appRisk="critical", appRisk="Critical", appRisk="5")
group every 5m by srcHost, srcIp, srcPort, dstIp, dstPort, proto, appType, appID, appRisk, appCat, action, client
select count() as count, first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select srcIp as entity_sourceIP
select dstIp as entity_destinationIP
select srcHost as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFortinetCriticalAppUse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFortinetCriticalAppUse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFortinetCriticalAppUse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFortinetCriticalAppUse") as alertPriority
```

## SecOpsFortinetHighRiskAppUse

**Summary:** Alerts when Fortinet Firewall detects a high risk application within the environment.

**MITRE:** Tactics: Resource Development (TA0042) | Techniques: Obtain Capabilities (T1588)

**Tables:** firewall.fortinet.traffic.forward

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.fortinet.traffic.forward
where `or`(appRisk="High", appRisk="high", appRisk="4")
group every 5m by srcIp, srcPort, dstIp, dstPort, proto, appType, appID, appRisk, appCat, action, srcHost, client
select count() as count, first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select srcIp as entity_sourceIP
select dstIp as entity_destinationIP
select srcHost as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFortinetHighRiskAppUse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFortinetHighRiskAppUse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFortinetHighRiskAppUse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFortinetHighRiskAppUse") as alertPriority
```

## SecOpsFWEmbargoedCountryInboundTrafficDetected

**Summary:** Detects inbound traffic sent to an embargoed country. The lookup table SecOpsEmbargoCountries should be modified to fit the organizations needs.

**Description:** An embargoed country is any country or geographic region subject to comprehensive economic sanctions or embargoes administered by OFAC or the European Union. This detection identifies inbound traffic sent to an embargoed country.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Remote Access Software (T1219)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsEmbargoCountries, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(destination_ipv4)
where not action -> "drop"
where not action -> "deny"
where not action -> "Reset"
select countrycode(destination_ipv4) as country
select `lu/SecOpsEmbargoCountries/Country`(country) as src_embargo_country
where isnotnull(src_embargo_country)
group every 1h by source, source_ipv4, destination_ipv4, action, source_username, src_embargo_country, client
every 1h
select count() as event_count
, first(eventdate) as first_seen
, last(eventdate) as last_seen
//Entity Mapping Section
select destination_ipv4 as entity_destinationIP
, source_ipv4 as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
, `lu/SecOpsAssetRole/class`(str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(entity_sourceIP) as enrichStream_entity_sourceIP_ASN
, isp(entity_sourceIP) as enrichStream_entity_sourceIP_ISP
select countrycode(entity_sourceIP) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
, `lu/SecOpsLocation/country`(entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
, `lu/SecOpsLocation/city`(entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
, `lu/SecOpsLocation/state`(entity_sourceIP) as enrichStream_entity_sourceIP_locationState
, `lu/SecOpsLocation/lat`(entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
, `lu/SecOpsLocation/lon`(entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", str(entity_sourceIP)) as indicator
, `lu/mispIndicator/type`(str(entity_sourceIP)) as misp_indicator_type
, `lu/mispIndicator/event_id`(str(entity_sourceIP)) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWEmbargoedCountryInboundTrafficDetected") as alertType
, `lu/SecOpsAlertDescription/alertMitreTactics`("SecOpsFWEmbargoedCountryInboundTrafficDetected") as alertMitreTactics
, `lu/SecOpsAlertDescription/alertMitreTechniques`("SecOpsFWEmbargoedCountryInboundTrafficDetected") as alertMitreTechniques
, `lu/SecOpsAlertDescription/alertPriority`("SecOpsFWEmbargoedCountryInboundTrafficDetected") as alertPriority
```

## SecOpsFWEmbargoedCountryOutboundTrafficDetected

**Summary:** Detects outbound traffic sent to an embargoed country. A lookup table should be populated with a list of embargoed country codes.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Remote Access Software (T1219)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsEmbargoCountries, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where isprivate(source_ipv4)
group every 1h by source, source_ipv4, destination_ipv4, action, source_username, client
select countrycode(destination_ipv4) as country
select `lu/SecOpsEmbargoCountries/Country`(country) as dst_embargo_country
where isnotnull(dst_embargo_country)
select count() as event_count, first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select destination_ipv4 as entity_destinationIP
select source_ipv4 as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ASN
select isp(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ISP
select countrycode(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_destinationIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWEmbargoedCountryOutboundTrafficDetected") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWEmbargoedCountryOutboundTrafficDetected") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWEmbargoedCountryOutboundTrafficDetected") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWEmbargoedCountryOutboundTrafficDetected") as alertPriority
```

## SecOpsFWExcessFirewallDenies

**Summary:** Detects excessive firewall blocks within a short time frame. The threshold should be adjusted in accordance with normal traffic patterns in an organization's environment.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Active Scanning (T1595)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where action = "deny" or action = "drop"
group every 5m by source, firewall_name, action, source_ipv4, client
//TUNE TIMEFRAME: exceeds THRESHOLD in 5 min period
every 5m
select count() as totalConnections
select int(hllppcount(destination_ipv4)) as dstIpCount
select int(hllppcount(destination_port)) as dstPortCount
select first(eventdate) as first_seen
select last(eventdate) as last_seen
//TUNE THRESHOLD: more than 25 denies in TIMEFRAME
where totalConnections > 25
where dstIpCount > 1 or dstPortCount > 1
//Entity Mapping Section
select str(source_ipv4) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWExcessFirewallDenies") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWExcessFirewallDenies") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWExcessFirewallDenies") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWExcessFirewallDenies") as alertPriority
```

## SecOpsFWExcessFirewallDeniesOutbound

**Summary:** Detects excessive firewall blocks for outbound traffic from a single IP in a short period. This activity may be indicative of C2 traffic and should be reviewed.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where action = "deny"
where isprivate(source_ipv4) and ispublic(destination_ipv4)
group every 5m by source, firewall_name, action, source_ipv4, client
//TUNE TIMEFRAME: exceeds THRESHOLD in 5 min period
every 5m
select count() as totalConnections, first(eventdate) as first_seen, last(eventdate) as last_seen
select int(hllppcount(destination_ipv4)) as dstIpCount
select int(hllppcount(destination_port)) as dstPortCount
//TUNE THRESHOLD: more than 25 denies in TIMEFRAME
where totalConnections > 25
//Entity Mapping Section
select str(source_ipv4) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWExcessFirewallDeniesOutbound") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWExcessFirewallDeniesOutbound") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWExcessFirewallDeniesOutbound") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWExcessFirewallDeniesOutbound") as alertPriority
```

## SecOpsFWExternalSMBTrafficDetectedFirewall

**Summary:** Identifies SMB traffic from external sources allowed through the firewall. Due to known vulnerabilities/insecurities with the SMB protocol, this type of external traffic falls outside best practices.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(source_ipv4) and isprivate(destination_ipv4)
where destination_port=139 or destination_port=445
where action = "accept"
group every 5m by source_ipv4, source_port, source_hostname, destination_ipv4, destination_port, protocol, application, action, source, client
every 5m
select count() as count, first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select destination_ipv4 as entity_destinationIP
select source_ipv4 as entity_sourceIP
select source_hostname as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWExternalSMBTrafficDetectedFirewall") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWExternalSMBTrafficDetectedFirewall") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWExternalSMBTrafficDetectedFirewall") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWExternalSMBTrafficDetectedFirewall") as alertPriority
```

## SecOpsFWIcmpExcessivePackets

**Summary:** Since ICMP packets are typically very small, this alert will detect ICMP packets that are larger than expected. A large amount of data sent over ICMP may indicate the presence of command and control traffic or data exfiltration.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Non-Application Layer Protocol (T1095)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
select ifthenelse(eq(lower(protocol),"1"),decode(lower(protocol), "1", "icmp"),lower(protocol)) as protocol_processed
where protocol_processed = "icmp"
where isprivate(source_ipv4) and ispublic(destination_ipv4)
group every 1h by source_ipv4, destination_ipv4, action, protocol_processed, client
select sum(bytes_sent) as totalBytesSent, first(eventdate) as first_seen, last(eventdate) as last_seen
where totalBytesSent > 84 // Tune bytes_total sent threshold as necessary
//Entity Mapping Section
select destination_ipv4 as entity_destinationIP
select source_ipv4 as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ASN
select isp(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ISP
select countrycode(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_destinationIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWIcmpExcessivePackets") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWIcmpExcessivePackets") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWIcmpExcessivePackets") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWIcmpExcessivePackets") as alertPriority
```

## SecOpsFWIpScanExternal

**Summary:** Detects when a single external IP is scanning an internal IPs using different ports for each scan attempt. This is a low and slow technique intended to avoid triggering traditional port scan and port sweep alerts.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Active Scanning (T1595)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(source_ipv4) and isnotnull(destination_port)
group every 5m by source_ipv4, client
//TUNE TIMEFRAME: exceeds THRESHOLD in 1 hr period
every 1h
select int(hllppcount(destination_ipv4)) as dstIpCount
select int(hllppcount(destination_port)) as dstPortCount
//TUNE THRESHOLD: more than 10 dstIp and more than 10 dstPort in TIMEFRAME
where dstIpCount > 10 and dstPortCount > 10
//Entity Mapping Section
select source_ipv4 as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWIpScanExternal") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWIpScanExternal") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWIpScanExternal") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWIpScanExternal") as alertPriority
```

## SecOpsFWIpScanInternal

**Summary:** Detects when a single internal IP is scanning other internal IPs using different ports for each scan attempt. This is a low and slow technique intended to avoid triggering traditional port scan and port sweep alerts.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where isprivate(source_ipv4) and isprivate(destination_ipv4) and isnotnull(destination_port)
group every 5m by source_ipv4, source_hostname, client
//TUNE TIMEFRAME: exceeds THRESHOLD in 1 hr period
every 1h
select int(hllppcount(destination_ipv4)) as dstIpCount
select int(hllppcount(destination_port)) as dstPortCount
//TUNE THRESHOLD: more than 10 dstIp and more than 10 dstPort in TIMEFRAME
where dstIpCount > 10 and dstPortCount > 10
//Entity Mapping Section
select str(source_ipv4) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWIpScanInternal") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWIpScanInternal") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWIpScanInternal") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWIpScanInternal") as alertPriority
```

## SecOpsFWIrcTrafficExternalDestination

**Summary:** Detects outbound traffic over IRC (TCP on ports 194 or 6697). Compromised hosts can utilize IRC for command and control operations.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Application Layer Protocol (T1071)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where (destination_port = 194 or destination_port = 6697) and ispublic(destination_ipv4)
group every 5m by source, source_hostname, firewall_name, source_ipv4, source_port, destination_ipv4, destination_port, protocol, application, action, client
every 5m
select count() as count
//Entity Mapping Section
select destination_ipv4 as entity_destinationIP
select source_ipv4 as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ASN
select isp(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ISP
select countrycode(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_destinationIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWIrcTrafficExternalDestination") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWIrcTrafficExternalDestination") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWIrcTrafficExternalDestination") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWIrcTrafficExternalDestination") as alertPriority
```

## SecOpsFWPortScanExternalSource

**Summary:** Identifies a host external to the monitored network showing behavior consistent with a scan for a port on multiple destination addresses in a short time.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Active Scanning (T1595)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(source_ipv4)
where isprivate(destination_ipv4)
group every 5m by action, source_hostname, source_ipv4, destination_ipv4, client
//TUNE TIMEFRAME: exceeds THRESHOLD in a 1 hr period
every 1h
select int(hllppcount(destination_port)) as dstPortScanCount
//TUNE THRESHOLD: more than 100 ports in TIMEFRAME
where dstPortScanCount >= 100
select first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select destination_ipv4 as entity_destinationIP
select source_ipv4 as entity_sourceIP
select source_hostname as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWPortScanExternalSource") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWPortScanExternalSource") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWPortScanExternalSource") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWPortScanExternalSource") as alertPriority
```

## SecOpsFWPortScanInternalSource

**Summary:** Detects scanning activity from an internal IP address to multiple ports on other internal IP addresses. The time threshold and a number of destination ports threshold should be tuned to fit organizational needs.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.all.traffic
where isprivate(source_ipv4)
where ispublic(destination_ipv4)
group every 5m by action, source_hostname, source_ipv4, destination_ipv4, client
//TUNE TIMEFRAME: exceeds THRESHOLD in a 1 hr period
every 1h
select int(hllppcount(destination_port)) as dstPortScanCount
//TUNE THRESHOLD: more than 100 ports in TIMEFRAME
where dstPortScanCount >= 100
select first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select destination_ipv4 as entity_destinationIP
select source_ipv4 as entity_sourceIP
select source_hostname as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWPortScanInternalSource") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWPortScanInternalSource") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWPortScanInternalSource") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWPortScanInternalSource") as alertPriority
```

## SecOpsFWPortSweepInternalSource

**Summary:** Detects port scanning activity from an internal IP address to multiple other internal IP addresses on the same destination port which may indicate an attacker enumerating the network for lateral movement.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.all.traffic
where isprivate(source_ipv4) and isprivate(destination_ipv4) and isnotnull(destination_port)
group every 5m by source, firewall_name, source_hostname, source_ipv4, destination_port, client
//TUNE TIMEFRAME: exceeds THRESHOLD in 5 min period
every 5m
select int(hllppcount(destination_ipv4)) as dstIpCount
//TUNE THRESHOLD: more than 10 in TIMEFRAME
where dstIpCount > 10
select first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select source_ipv4 as entity_sourceIP
select source_hostname as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWPortSweepInternalSource") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWPortSweepInternalSource") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWPortSweepInternalSource") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWPortSweepInternalSource") as alertPriority
```

## SecOpsFWRDPExternalAccess

**Summary:** Identifies RDP traffic from external sources allowed through the firewall. This type of traffic may indicate an adversary is in possession of valid accounts and is accessing a host from outside the network.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where destination_port = 3389 and action = "accept" and ispublic(source_ipv4)
group every 5m by source_hostname, source_ipv4, source_port, destination_ipv4, destination_port, protocol, application, action, source, client
//Entity Mapping Section
select str(destination_ipv4) as entity_destinationIP
select str(source_ipv4) as entity_sourceIP
select source_hostname as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWRDPExternalAccess") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWRDPExternalAccess") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWRDPExternalAccess") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWRDPExternalAccess") as alertPriority
```

## SecOpsFWSigred

**Summary:** Detects exploitation of DNS RCE bug reported in CVE-2020-1350 by monitoring for suspicious outbound DNS traffic over TCP. The destination name server should be examined for legitimacy.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Application Layer Protocol (T1071)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(destination_ipv4)
where destination_port = 53, (protocol = "6" or lower(protocol) = "tcp")
where bytes_received > 65280
group every 5m by source, source_ipv4, destination_ipv4, protocol, destination_port, application, bytes_received, client
//Entity Mapping Section
select source_ipv4 as entity_sourceIP
select destination_ipv4 as entity_destinationIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ASN
select isp(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ISP
select countrycode(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_destinationIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWSigred") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWSigred") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWSigred") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWSigred") as alertPriority
```

## SecOpsFWSMBInboundScanningDetected

**Summary:** Detects inbound SMB scanning from a single external source IP.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where destination_port=139 or destination_port=445
where ispublic(source_ipv4)
group every 5m by source_ipv4, client
//TUNE TIMEFRAME: exceeds THRESHOLD in 5 min period
every 5m
select int(hllppcount(destination_ipv4)) as dstIpCount
//TUNE THRESHOLD: more than 25 dstIp in TIMEFRAME
where dstIpCount > 25
select first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select source_ipv4 as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWSMBInboundScanningDetected") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWSMBInboundScanningDetected") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWSMBInboundScanningDetected") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWSMBInboundScanningDetected") as alertPriority
```

## SecOpsFWSMBInternalScanningDetected

**Summary:** Identifies a host scanning other hosts for open SMB shares. Triggers when a single source IP connects to more than 25 destinations using SMB.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.all.traffic
where destination_port=139 or destination_port=445
where isprivate(destination_ipv4)
group every 5m by source_ipv4, client
//TUNE TIMEFRAME: exceeds THRESHOLD in 5 min period
every 5m
select int(hllppcount(destination_ipv4)) as dstIpCount
//TUNE THRESHOLD: more than 25 in TIMEFRAME
where dstIpCount > 25
select first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select source_ipv4 as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWSMBInternalScanningDetected") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWSMBInternalScanningDetected") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWSMBInternalScanningDetected") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWSMBInternalScanningDetected") as alertPriority
```

## SecOpsFWSMBTrafficOutbound

**Summary:** This alert detects SMB traffic from internal to external sources allowed through the firewall.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where action = "accept", (destination_port = 139 or destination_port = 445), ispublic(destination_ipv4)
group every 5m by source_hostname, source_ipv4, source_port, destination_ipv4, destination_port, protocol, application, action, source, client
select count() as count, first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select destination_ipv4 as entity_destinationIP
select source_ipv4 as entity_sourceIP
select source_hostname as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ASN
select isp(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ISP
select countrycode(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_destinationIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWSMBTrafficOutbound") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWSMBTrafficOutbound") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWSMBTrafficOutbound") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWSMBTrafficOutbound") as alertPriority
```

## SecOpsFwTftpOutboundTraffic

**Summary:** Detects TFTP to an external network address. TFTP is rared used externally and has been observed as a means to stage data remotely for exfiltration.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Data Staged (T1074)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.all.traffic
where (weaktoktains(rawMessage,"tftp") and isprivate(source_ipv4) and ispublic(destination_ipv4)) or (isprivate(source_ipv4) and ispublic(destination_ipv4) and destination_port = 69 and (protocol = "17" or lower(protocol) = "udp"))
group every 5m by source_hostname, source_ipv4, source_port, destination_ipv4, destination_port, protocol, application, action, source, client
every 5m
select count() as count, first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select str(source_ipv4) as entity_sourceIP
select str(destination_ipv4) as entity_destinationIP
select source_hostname as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFwTftpOutboundTraffic") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFwTftpOutboundTraffic") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFwTftpOutboundTraffic") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFwTftpOutboundTraffic") as alertPriority
```

## SecOpsFWTrafficForeignDestination

**Summary:** Detects outbound traffic destined for unexpected countries. Users must populate a lookup table containing home/domestic/expected country codes.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Automated Exfiltration (T1020)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsDomesticCountries, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(destination_ipv4) and action = "accept"
select countrycode(destination_ipv4) as country
where isnotnull(country)
select `lu/SecOpsDomesticCountries/country`(country) as domesticCountry,
        `lu/SecOpsDomesticCountries/authorized`(country) as authDomesticCountry
where authDomesticCountry = "FALSE"
// Example grouping options:
// Use this grouping if you want to see the srcIp, srcPort,
// dstIp, dstPort, proto, app, action
group every 5m by source_ipv4, source_port, destination_ipv4, destination_port, protocol, application, action, client
  
// Use this grouping if you only want to see what country
// has attempted access and how many times
//group every 5m by domesticCountry, client

select count() as count, first(eventdate) as first_seen, last(eventdate) as last_seen
//Entity Mapping Section
select str(destination_ipv4) as entity_destinationIP
select str(source_ipv4) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ASN
select isp(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_ISP
select countrycode(ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_destinationIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", ip4(entity_destinationIP)) as enrichStream_entity_destinationIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWTrafficForeignDestination") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWTrafficForeignDestination") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWTrafficForeignDestination") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWTrafficForeignDestination") as alertPriority
```

## SecOpsFWTrafficOnUnassignedLowPort

**Summary:** Identifies traffic across a port lower than 1024 that is unassigned by IANA. These ports are rarely used by legitimate services and may indicate malicious activity or traffic.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Non-Standard Port (T1571)

**Tables:** firewall.all.traffic

**Lookups:** IANAPortAssignment, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where isnotnull(destination_port)
where int(destination_port) < 1024
select `lu/IANAPortAssignment/description`(int(destination_port)) as known_ports,
int(destination_port) as int_destination_port
where known_ports = "Unassigned"
group every 5m by destination_port, known_ports, source_ipv4, destination_ipv4, client
every 5m
select count() as count
//add to the below filter exclude ports that you know will be too noisy
//where `or`(destination_port /= "897", destination_port /= "32", <<filter out more ports>>)
//Entity Mapping Section
select str(destination_ipv4) as entity_destinationIP
select str(source_ipv4) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsFWTrafficOnUnassignedLowPort") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFWTrafficOnUnassignedLowPort") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFWTrafficOnUnassignedLowPort") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFWTrafficOnUnassignedLowPort") as alertPriority
```

## SecOpsHAFNIUMNetworkActivityTargetingExchangeServers

**Summary:** Microsoft has detected multiple 0-day exploits being used to attack on-premises versions of Microsoft Exchange Server in limited and targeted attacks.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** firewall.all.traffic

**Lookups:** msfhafnium0day, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(source_ipv4)
select `lu/msfhafnium0day/threat`(str(source_ipv4)) as ismsfhafnium0day
where isnotnull(ismsfhafnium0day)
group every 5m by source_ipv4, destination_ipv4, destination_port, client
every 5m
select str(source_ipv4) as entity_sourceIP
select str(destination_ipv4) as entity_destinationIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsHAFNIUMNetworkActivityTargetingExchangeServers") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHAFNIUMNetworkActivityTargetingExchangeServers") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHAFNIUMNetworkActivityTargetingExchangeServers") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHAFNIUMNetworkActivityTargetingExchangeServers") as alertPriority
```

## SecOpsLog4ShellVulnOverFirewallTrafficConnections

**Summary:** Alert that checks traffic logs on firewalls if a connection against a server related to recent CVE-2021-4428 (Log4Shell) attacks has been performed. It makes use of a lookup table containing the IP of servers related to these malicious activities.

**Description:** Alert that checks traffic logs on firewalls if a connection against a server related to late CVE-2021-4428 (Log4Shell) attacks has been performed.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsLocation, mispIndicator, SecOpsAlertDescription

```linq
from firewall.all.traffic
where action = "accept"
select hlurjson("log4shell", str(source_ipv4), eventdate) as source_ipv4_log4shell
select hlurjson("log4shell", str(destination_ipv4), eventdate) as destination_ipv4_log4shell
where isnotnull(source_ipv4_log4shell) or isnotnull(destination_ipv4_log4shell)
group every 5m by source_ipv4,destination_ipv4,firewall_name,firewall_cluster,destination_port,source_port,tag,source, client
every 5m
select source_ipv4 as entity_sourceIP
select destination_ipv4 as entity_destinationIP
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_destinationIP) as indicator
select lu("mispIndicator", "type", entity_destinationIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnOverFirewallTrafficConnections") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnOverFirewallTrafficConnections") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnOverFirewallTrafficConnections") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnOverFirewallTrafficConnections") as alertPriority
```

## SecOpsPanAuthExcessiveFailedLoginIP

**Summary:** Detects excessive Palo Alto firewall authentication failures for a single IP within a short period of time.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** firewall.paloalto.system

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.paloalto.system
where toktains(rawMessage, "auth-fail")
select user_name as user
select reason
select client_ip as srcIp as srcIp
where isnotnull(srcIp)
group every 10m by srcIp, client
every 10m // Tune failure window
select count() as count
where count > 5 // Tune failure criteria
select int(hllppcount(user)) as userCount, int(hllppcount(reason)) as reasonCount
, first(eventdate) as first_seen, last(eventdate) as last_seen
, collectdistinct(user) as usernames
//Entity Mapping Section
select srcIp as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsPanAuthExcessiveFailedLoginIP") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPanAuthExcessiveFailedLoginIP") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPanAuthExcessiveFailedLoginIP") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPanAuthExcessiveFailedLoginIP") as alertPriority
```

## SecOpsPanAuthExcessiveFailedLoginUser

**Summary:** Detects excessive Palo Alto firewall authentication failures for a single user account within a short period of time.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** firewall.paloalto.system

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.paloalto.system
where toktains(rawMessage, "auth-fail")
select user_name as user
select reason
select client_ip as srcIp
where isnotnull(user)
// Tune failure window
group every 10m by user, client
select count() as count
where count > 5 // Tune excess failure criteria
select int(hllppcount(srcIp)) as srcIpCount
, int(hllppcount(reason)) as reasonCount
, first(eventdate) as first_seen
, last(eventdate) as last_seen
//Entity Mapping Section
select user as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsPanAuthExcessiveFailedLoginUser") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPanAuthExcessiveFailedLoginUser") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPanAuthExcessiveFailedLoginUser") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPanAuthExcessiveFailedLoginUser") as alertPriority
```

## SecOpsPanAuthFailMultipleUserSingleIP

**Summary:** Detects brute force attacks via the Palo Alto firewalls. A source IP address attempted and failed to authenticate multiple times while providing multiple usernames.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** firewall.paloalto.system

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from firewall.paloalto.system
where toktains(rawMessage, "auth-fail")
select peek(description, re("From:\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)"),1) as srcIp
where isnotnull(auth_username) and isnotnull(srcIp)
group every 10m by srcIp, client
every 10m // Tune failure window
select count() as count, int(hllppcount(auth_username)) as userCount
where userCount > 5 // Tune distinct account failures
select int(hllppcount(auth_status)) as reasonCount
, first(eventdate) as first_seen
, last(eventdate) as last_seen
, collectdistinct(user_name) as usernames
//Entity Mapping Section
select str(srcIp) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsPanAuthFailMultipleUserSingleIP") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPanAuthFailMultipleUserSingleIP") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPanAuthFailMultipleUserSingleIP") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPanAuthFailMultipleUserSingleIP") as alertPriority
```

## SecOpsPossibleTrafficMirroring

**Summary:** This alert is meant to be used to tune and utilize as a supplement to helping to identify potentially mirrored traffic

**Description:** Detects potentially duplicate traffic as a potential for traffic mirroring

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Automated Exfiltration (T1020)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where isnotnull(source_ipv4) and isnotnull(destination_ipv4)
select epoch(eventdate) as eventdate_epoch,
source_ipv4 as entity_sourceIP,
destination_ipv4 as entity_dst_IP,
source_interface as entity_source_interface,
bytes_total as entity_bytes
group every 5m by eventdate_epoch, entity_sourceIP, entity_dst_IP, action, client
every 5m
select count(entity_sourceIP) as conn_counter
select ifthenelse(int(conn_counter) > 10, conn_counter, 0) as more_than_10
where more_than_10 > 0
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPossibleTrafficMirroring") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPossibleTrafficMirroring") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPossibleTrafficMirroring") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPossibleTrafficMirroring") as alertPriority
```

## SecOpsRevilKaseyaNetworkActivity

**Summary:** The REvil Ransomware has hit 40 service providers globally due to multiple Kaseya VSA Zero-days. the attack was pushed out via a infected IT Management update from Kaseya.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** firewall.all.traffic

**Lookups:** revilKaseya, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where ispublic(source_ipv4)
select `lu/revilKaseya/type`(str(source_ipv4)) as isrevilKaseya
where isnotnull(isrevilKaseya)
group every 5m by source_ipv4, destination_ipv4, destination_port, client
every 5m
select str(source_ipv4) as entity_sourceIP
select str(destination_ipv4) as entity_destinationIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsRevilKaseyaNetworkActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRevilKaseyaNetworkActivity") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRevilKaseyaNetworkActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRevilKaseyaNetworkActivity") as alertPriority
```

## SecOpsVNCPortOpen

**Summary:** Used to identify the default port for VNC connections

**Description:** Possible VNC Connections

**MITRE:** Tactics: Lateral Movement (TA0008), Initial Access (TA0001) | Techniques: Remote Services (T1021), External Remote Services (T1133)

**Tables:** firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from firewall.all.traffic
where `or`(destination_port = 5900, destination_port = 5800)
group every 5m by source_ipv4, destination_ipv4, protocol, destination_port, source_username, client
select str(source_ipv4) as entity_sourceIP
select str(destination_ipv4) as entity_destinationIP
select destination_port as entity_destinationPort
select source_username as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select count(source_ipv4) as vnc_source
where vnc_source > 1
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsVNCPortOpen") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsVNCPortOpen") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsVNCPortOpen") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsVNCPortOpen") as alertPriority
```
