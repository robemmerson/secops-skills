# Detection library: THREATSYS/IDS

IDS / Zeek detections. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (9):

- SecOpsBroHttpRequestSingleHeader
- SecOpsBroRdpBruteForceSuccessHydraNcrack
- SecOpsBroSelfSignedCert
- SecOpsBroSmbFirstSeenShare
- SecOpsBroSshInteresingHostNameLogin
- SecOpsBroWinDceRpceServiceCall
- SecOpsBroWinDceRpcSamrEnumeration
- SecOpsBroWinLsatUserEnumeration
- SecOpsRemoteDesktopProtocolScan

## SecOpsBroHttpRequestSingleHeader

**Summary:** Detects HTTP requests that contain only a single header.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** ids.bro.http

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from ids.bro.http
where statusCode > 0
where `or`(
ispublic(ip4(destHost))
, ispublic(ip4(origHost))
, weakhas(lu("SecOpsAssetRole", "class", destHost), "proxy"))
group every 5m by origHost, destHost, uri, host, userAgent, referrer, version, client
select ifthenelse(isnull(host), 0, 1) as header_host
, ifthenelse(isnull(userAgent), 0, 1) as header_userAgent
, ifthenelse(isnull(referrer), 0, 1) as header_referrer
, ifthenelse(isnull(version), 0, 1) as header_version
select header_host + header_userAgent + header_referrer + header_version as header_count
where header_count = 1
//Entity Mapping Section
select str(destHost) as entity_destinationIP
select str(origHost) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsBroHttpRequestSingleHeader") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBroHttpRequestSingleHeader") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBroHttpRequestSingleHeader") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBroHttpRequestSingleHeader") as alertPriority
```

## SecOpsBroRdpBruteForceSuccessHydraNcrack

**Summary:** Detects a successful RDP connection via Hydra or Ncrack hacking tools.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** ids.bro.rdp

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from ids.bro.rdp
where weaktoktains(result, "success")
where isnotnull(cookie) and `or`(weaktoktains(clientName, "hydra"), weaktoktains(clientName, "ncrack"))
group every 5m by origHost, destHost, cookie, clientName, client
//Entity Mapping Section
select str(destHost) as entity_destinationIP
select str(origHost) as entity_sourceIP
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsBroRdpBruteForceSuccessHydraNcrack") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBroRdpBruteForceSuccessHydraNcrack") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBroRdpBruteForceSuccessHydraNcrack") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBroRdpBruteForceSuccessHydraNcrack") as alertPriority
```

## SecOpsBroSelfSignedCert

**Summary:** Detects servers responding via SSL or TLS services using self-signed certificates.

**MITRE:** Tactics: Resource Development (TA0042) | Techniques: Develop Capabilities (T1587)

**Tables:** ids.bro.ssl

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from ids.bro.ssl
where isnotnull(issuer), issuer = subject
select lu("SecOpsAssetRole", "class", destHost) as serverType
where ispublic(ip4(destHost)) or weakhas(serverType, "proxy")
group every 5m by origHost, destHost, subject, issuer, client
//Entity Mapping Section
select str(destHost) as entity_destinationIP
select str(origHost) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsBroSelfSignedCert") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBroSelfSignedCert") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBroSelfSignedCert") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBroSelfSignedCert") as alertPriority
```

## SecOpsBroSmbFirstSeenShare

**Summary:** Detects the first seen SMB share for an entity. Adversaries may utilize SMB shares to transport files; while not inherently malicious, this event should be reviewed for legitimacy.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** ids.bro.notice

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from ids.bro.notice
where toktains(raw, "SmbShareAccess:New")
group every 5m by origHost, destHost, note, msg, actions, client
//Entity Mapping Section
select str(destHost) as entity_destinationIP
select str(origHost) as entity_sourceIP
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsBroSmbFirstSeenShare") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBroSmbFirstSeenShare") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBroSmbFirstSeenShare") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBroSmbFirstSeenShare") as alertPriority
```

## SecOpsBroSshInteresingHostNameLogin

**Summary:** Detects interesting host name login events. See Bro/Zeek reference for context around interesting hostnames.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Application Layer Protocol (T1071)

**Tables:** ids.bro.notice

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from ids.bro.notice
where toktains(raw, "SSH::Interesting_Hostname_Login")
group every 5m by origHost, destHost, note, msg, actions, client
//Entity Mapping Section
select str(destHost) as entity_destinationIP
select str(origHost) as entity_sourceIP
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsBroSshInteresingHostNameLogin") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBroSshInteresingHostNameLogin") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBroSshInteresingHostNameLogin") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBroSshInteresingHostNameLogin") as alertPriority
```

## SecOpsBroWinDceRpceServiceCall

**Summary:** Detects the creation or deletion of services via RPC remote administration. Actors may create/delete services to establish a greater foothold once inside a network.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** ids.bro.dce_rpc

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from ids.bro.dce_rpc
where `or`(
toktains(operation, "CreateServiceW")
, toktains(operation, "DeleteService"))
group every 5m by origHost, destHost, namedPipe, endpoint, operation, client
//Entity Mapping Section
select str(destHost) as entity_destinationIP
select str(origHost) as entity_sourceIP
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsBroWinDceRpceServiceCall") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBroWinDceRpceServiceCall") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBroWinDceRpceServiceCall") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBroWinDceRpceServiceCall") as alertPriority
```

## SecOpsBroWinDceRpcSamrEnumeration

**Summary:** Detects actors enumerating user accounts in Active Directory via Security Account Manager Remote Protocol (SAMR).

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** ids.bro.dce_rpc

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from ids.bro.dce_rpc
where toktains(operation, "SamrEnumerateUsersInDomain")
group every 5m by origHost, destHost, namedPipe, endpoint, operation, client
//Entity Mapping Section
select str(destHost) as entity_destinationIP
select str(origHost) as entity_sourceIP
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsBroWinDceRpcSamrEnumeration") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBroWinDceRpcSamrEnumeration") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBroWinDceRpcSamrEnumeration") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBroWinDceRpcSamrEnumeration") as alertPriority
```

## SecOpsBroWinLsatUserEnumeration

**Summary:** Detects actors utilizing MS-LSAT Remote protocol to map security SIDs to user accounts.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** ids.bro.dce_rpc

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from ids.bro.dce_rpc
where `or`(
toktains(operation, "LsaLookupSids")
, toktains(operation, "LsaLookupSids2")
, toktains(operation, "LsaLookupSids3")
, toktains(operation, "LsarLookupSids")
, toktains(operation, "LsarLookupSids2")
, toktains(operation, "LsarLookupSids3"))
group every 5m by origHost, destHost, namedPipe, endpoint, operation, client
//Entity Mapping Section
select str(destHost) as entity_destinationIP
select str(origHost) as entity_sourceIP
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsBroWinLsatUserEnumeration") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBroWinLsatUserEnumeration") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBroWinLsatUserEnumeration") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBroWinLsatUserEnumeration") as alertPriority
```

## SecOpsRemoteDesktopProtocolScan

**Summary:** Remote Desktop Services Scan from one Entity to Multiple Destinations.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** ids.bro.rdp

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from ids.bro.rdp
group every 5m by origHost, destHost, securityProtocol, destPort, keyboardLayout, client
every 1h
select origHost as entity_sourceIP
select destHost as entity_destinationIP
select count(destHost) as rdp_destination
where rdp_destination > 1
where isnotnull(origHost)
where destPort = 3389
where securityProtocol = "RDP"
where keyboardLayout = "rdpdr,cliprdr,rdpsnd"
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsRemoteDesktopProtocolScan") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRemoteDesktopProtocolScan") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRemoteDesktopProtocolScan") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRemoteDesktopProtocolScan") as alertPriority
```
