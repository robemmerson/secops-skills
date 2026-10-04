# Detection library: PROXY

Web proxy detections (proxy.all.access). Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (20):

- SecOpsCDIocUrlSuspiciousProxyData
- SecOpsCDProxyDstIp
- SecOpsCDProxySrcIp
- SecOpsDynamicDNSDetected
- SecOpsIPInsteadADomainInURL
- SecOpsLog4ShellVulnerabilityCloudAzure
- SecOpsLog4ShellVulnerabilityOverProxyConnections
- SecOpsMoveitPotentialNetworkActivityExploitation
- SecOpsMultipleHTTPMethodsUsed
- SecOpsNonStandardHTTPMethod
- SecOpsOutboundTrafficToDeviceFlaggedAsThreat
- SecOpsOutcomingUnauthenticatedArbitraryFileReadInVMwareVCenter
- SecOpsPortIntoURL
- SecOpsPotentialThreatConnectionRansomBehaviour
- SecOpsProxyDataExfiltrationDetection
- SecOpsProxyHighRiskFileExtension
- SecOpsProxyHttpSingleCharacterFileNameRequest
- SecOpsRevilKaseyaWebShellsUploadConn
- SecOpsSeveralAccessByProxy
- SecOpsUserBlockedbyProxy

## SecOpsCDIocUrlSuspiciousProxyData

**Summary:** This search looks for Collective Defense matches in proxy data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from proxy.all.access
where ispublic(destination_ipv4)
select url as entity_destinationUrl
group every 15m by entity_destinationUrl, source, user, machine, client
select hlurjson("CollectiveDefense", entity_destinationUrl, eventdate) as cd_hit
where isnotnull(cd_hit)
select lu("SecOpsAssetRole", "class", entity_destinationUrl) as entity_destinationUrl_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDIocUrlSuspiciousProxyData") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDIocUrlSuspiciousProxyData") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDIocUrlSuspiciousProxyData") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDIocUrlSuspiciousProxyData") as alertPriority
```

## SecOpsCDProxyDstIp

**Summary:** This search looks for Collective Defense matches in proxy data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from proxy.all.access
where ispublic(destination_ipv4)
group every 15m by destination_ipv4, source_ipv4, source, user, machine, client
select str(destination_ipv4) as entity_destinationIP,
str(source_ipv4) as entity_sourceIP,
`lu/CollectiveDefense`(entity_destinationIP) as cd_hit,
count(destination_ipv4) as ip_destination_count
where isnotnull(cd_hit)
// The below lines separate each json object and are unecessary for this alert
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
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDProxySrcIp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDProxySrcIp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDProxySrcIp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDProxySrcIp") as alertPriority
```

## SecOpsCDProxySrcIp

**Summary:** This search looks for Collective Defense matches in proxy data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from proxy.all.access
where ispublic(source_ipv4)
group every 15m by source_ipv4, destination_ipv4, source, user, machine, client
select str(source_ipv4) as entity_sourceIP,
str(destination_ipv4) as entity_dstIP,
`lu/CollectiveDefense`(entity_sourceIP) as cd_hit,
count(source_ipv4) as ip_source_count
where isnotnull(cd_hit)
// The below lines separate each json object and are unecessary for this alert
select jqeval(jqcompile(".sectors"), cd_hit) as sectors,
jqeval(jqcompile(".entity"), cd_hit) as entity,
jqeval(jqcompile(".ueba_alerts"), cd_hit) as ueba_alerts,
jqeval(jqcompile(".alerts"), cd_hit) as alerts,
jqeval(jqcompile(".misp"), cd_hit) as misp,
jqeval(jqcompile(".techniques"), cd_hit) as techniques,
jqeval(jqcompile(".critical_alerts"), cd_hit) as critical_alerts,
jqeval(jqcompile(".domain_c"), cd_hit) as domain_c,
jqeval(jqcompile(".whois"), cd_hit) as whois,
jqeval(jqcompile(".otx"), cd_hit) as otx,
jqeval(jqcompile(".secops_alerts"), cd_hit) as secops_alerts,
jqeval(jqcompile(".high_alerts"), cd_hit) as high_alerts,
jqeval(jqcompile(".technique_c"), cd_hit) as technique_c,
jqeval(jqcompile(".sector_c"), cd_hit) as sector_c
//Entity Mapping Section
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_dstIP) as entity_destinationIP_AssetRole
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDProxySrcIp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDProxySrcIp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDProxySrcIp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDProxySrcIp") as alertPriority
```

## SecOpsDynamicDNSDetected

**Summary:** Dynamic DNS services should be associated in several cases with malware and fraud campaigns. Even could be part of a content filter bypass technique used by internal systems.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Dynamic Resolution (T1568)

**Tables:** proxy.all.access

**Lookups:** DynamicDNS, SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from proxy.all.access
group every 5m by source_ipv4, user, url, machine, client
every 15m
select url as entity_destinationUrl
select user as entity_sourceName
select source_ipv4 as entity_sourceIP
select isnotnull(urihost(url)) ? urihost(url) : urihost("http://" + url) as entity_destinationHostname
where isnotnull(entity_destinationHostname)
select rootdomain(entity_destinationHostname)+"."+topleveldomain(entity_destinationHostname) as FLD
select `lu/DynamicDNS/provider`(FLD) as enrichStream_entity_destinationHostname_isDynamicDNS
where isnotnull(enrichStream_entity_destinationHostname_isDynamicDNS)
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationUrl) as entity_destinationUrl_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select shannonentropy(entity_destinationHostname) as enrichStream_entity_destinationHostname_shannonEntropy
select shannonentropy(entity_destinationUrl) as enrichStream_entity_destinationUrl_shannonEntropy
select lu("mispIndicator", "category", str(entity_sourceIP)) as indicator
select lu("mispIndicator", "type", str(entity_sourceIP)) as misp_indicator_type
select lu("mispIndicator", "event_id", str(entity_sourceIP)) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsDynamicDNSDetected") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsDynamicDNSDetected") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsDynamicDNSDetected") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsDynamicDNSDetected") as alertPriority
```

## SecOpsIPInsteadADomainInURL

**Summary:** Regular navigation uses domains instead of server IP addresses. Using IP in URL is suspicious behavior and it is closely related to the behavior of the malware.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Proxy (T1090)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
where isnotnull(destination_hostname)
where isnull(ip4(url)) //Filter logs where URL is just an IP
group every 5m by url, source_ipv4, machine, client
every 15m
select isnotnull(urihost(url)) ? urihost(url) : urihost("http://" + url) as entity_destinationHostname
select ip4(entity_destinationHostname) as entity_destinationIP
where isnotnull(entity_destinationIP)
select url as entity_destinationUrl
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", str(entity_destinationIP)) as indicator
select lu("mispIndicator", "type", str(entity_destinationIP)) as misp_indicator_type
select lu("mispIndicator", "event_id", str(entity_destinationIP)) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsIPInsteadADomainInURL") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsIPInsteadADomainInURL") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsIPInsteadADomainInURL") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsIPInsteadADomainInURL") as alertPriority
```

## SecOpsLog4ShellVulnerabilityCloudAzure

**Summary:** Alert that checks attempts of exploiting CVE-2021-44228 known as Log4shell. The query looks for payload patterns associated with this vulnerability on the log raw message. This would include payloads included in the url, user-agent header, referer header or POST and PUT HTTP bodies. [WARNING] This alert detects attack patterns and can generate a high volume of events due to the number of scanners currently testing systems on the Internet. It is therefore likely to need some kind of tunning.

**Description:** Checks for attempts of exploiting CVE-2021-44228. Alert that checks attempts of exploiting CVE-2021-44228 known as Log4shell.

**MITRE:** Tactics: Initial Access (TA0001), Discovery (TA0007), Impact (TA0040) | Techniques: Exploit Public-Facing Application (T1190), Network Service Discovery (T1046), Remote System Discovery (T1018), Resource Hijacking (T1496)

**Tables:** cloud.azure

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from cloud.azure
where `in`("/$%7bjndi:","%24%7bjndi:","%24%7Bjndi:","%2524%257Bjndi","%2F%252524%25257Bjndi%3A","${::-j}${","${::-l}${::-d}${::-a}${::-p}","${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}:/","${${::-j}ndi:rmi:/","${${env:","${${lower:${lower:jndi}}:${lower:rmi}:/","${${lower:j}${lower:n}${lower:d}i:${lower:rmi}:","${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}:/","${${lower:jndi}:${lower:rmi}:/","${base64:JHtqbmRp","${jndi:${lower:","${jndi:${lower:l}${lower:d}a${lower:p}://","${jndi:corba","${jndi:dns:/","${jndi:http:/","${jndi:iiop","${jndi:ldap://","${jndi:ldap://${env:","${jndi:ldap:/","${jndi:ldaps:/","${jndi:nds","${jndi:nis","${jndi:rmi:/","$%7Bjndi:","$%7blower:","$%7Blower:","$%7bupper:","$%7Bupper:","${${::-${::-$${::-j}}}",raw)
group every 5m by hostname, region, product, type, raw, client
every 5m
select hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceHostname) as indicator
select lu("mispIndicator", "type", entity_sourceHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnerabilityCloudAzure") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnerabilityCloudAzure") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnerabilityCloudAzure") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnerabilityCloudAzure") as alertPriority
```

## SecOpsLog4ShellVulnerabilityOverProxyConnections

**Summary:** Alert that checks attempts to exploit CVE-2021-44228 known as Log4shell. The query looks for payload patterns associated with this vulnerability in the log raw message. This would include payloads included in the URL, user-agent header, referrer header, or POST and PUT HTTP bodies. [WARNING] This alert detects attack patterns and can generate a high volume of events due to the number of scanners currently testing systems on the Internet. It is therefore likely to need some kind of tunning.

**Description:** Detect CVE-2021-44228 attempts as known as Log4shell. The query contained in this alert can generate high volumes of events due to the nature of the attack pattern. Tunning the alert to your environment is recommended.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
where `in`("/$%7bjndi:","%24%7bjndi:","%24%7Bjndi:","%2524%257Bjndi","%2F%252524%25257Bjndi%3A","${::-j}${","${::-l}${::-d}${::-a}${::-p}","${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}:/","${${::-j}ndi:rmi:/","${${env:","${${lower:${lower:jndi}}:${lower:rmi}:/","${${lower:j}${lower:n}${lower:d}i:${lower:rmi}:","${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}:/","${${lower:jndi}:${lower:rmi}:/","${base64:JHtqbmRp","${jndi:${lower:","${jndi:${lower:l}${lower:d}a${lower:p}://","${jndi:corba","${jndi:dns:/","${jndi:http:/","${jndi:iiop","${jndi:ldap://","${jndi:ldap://${env:","${jndi:ldap:/","${jndi:ldaps:/","${jndi:nds","${jndi:nis","${jndi:rmi:/","$%7Bjndi:","$%7blower:","$%7Blower:","$%7bupper:","$%7Bupper:","${${::-${::-$${::-j}}}",raw)
group every 5m by machine,source_hostname,user,destination_hostname,url,referrer,user_agent,raw,source,tag, client
every 5m
select machine as entity_destinationHostname
select source_hostname as entity_sourceIP
select user as entity_sourceAccount
select destination_hostname as entity_destinationDomain
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationDomain) as entity_destinationDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnerabilityOverProxyConnections") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnerabilityOverProxyConnections") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnerabilityOverProxyConnections") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnerabilityOverProxyConnections") as alertPriority
```

## SecOpsMoveitPotentialNetworkActivityExploitation

**Summary:** Detects file indicators of potential exploitation of MOVEit CVE-2023-34362.

**Description:** Detects file indicators of potential exploitation of MOVEit CVE-2023-34362. Connection: $source_ip to $destination_ip with $source_hostname to $destination_hostname by $user

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** proxy.all.access

**Lookups:** none

```linq
from proxy.all.access
where method in ["GET", "POST", "PUT"]
and status_code in [200, 404, 500]
and ( (method = "GET" and (toktains (url,"/api/v1/folders") or toktains(url, "human2.aspx"))) or
(method = "POST" and (toktains (url,"guestaccess.aspx") or toktains (url,"/api/v1/token") or toktains (url,"api/v1/folders") or toktains (url,"machine2.aspx") or toktains (url,"moveitisapi/moveitisapi.dll"))) or
(method = "PUT" and toktains (url,"uploadType=resumable")))
group every 10m by source_ip,destination_ip,source_hostname,destination_hostname,user,client
select round(hllppcount(url)) as numUrl
select round(hllppcount(method)) as numMethod
select ifthenelse(numMethod>1,ifthenelse(numUrl>1,"pattern_found",null), null) as responseTimeFrame
where responseTimeFrame = "pattern_found"
select source_ip as entity_sourceIP
select destination_ip as entity_destinationIP
select source_hostname as entity_sourceHostname
select destination_hostname as entity_destinationHostname
select user as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Initial Access" as alertMitreTactics
select "Exploit Public-Facing Application" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsMultipleHTTPMethodsUsed

**Summary:** There are more than ten HTTP Methods but usually clients use a few only. If a client uses all of them or a large number of methods, this could be recon, probing, or enumeration.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: System Information Discovery (T1082)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
group every 30m by user, source_ipv4, machine, client
every 1h
select hllppcount(method) as method
where round(method) > 10
select user as entity_sourceName
select source_ipv4 as entity_sourceIP
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select lu("mispIndicator", "category", str(entity_sourceIP)) as indicator
select lu("mispIndicator", "type", str(entity_sourceIP)) as misp_indicator_type
select lu("mispIndicator", "event_id", str(entity_sourceIP)) as misp_indicator_event_id
select lu("SecOpsLocation", "country", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMultipleHTTPMethodsUsed") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMultipleHTTPMethodsUsed") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMultipleHTTPMethodsUsed") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMultipleHTTPMethodsUsed") as alertPriority
```

## SecOpsNonStandardHTTPMethod

**Summary:** HTTP defines a set of request methods to indicate the desired action to be performed for a given resource. It is necessary monitor the non standard methods used into web servers queries because could be an indicator of an attack.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** proxy.all.access

**Lookups:** HTTPMethods, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
where isnotnull(source_ipv4),
isnotnull(method)
group every 30m by method, source_ipv4, user, machine, client
every 1h
select `lu/HTTPMethods/known`(method) as KnownMethod
where isnull(KnownMethod)
select method as HTTPMethod
select user as entity_sourceName
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsNonStandardHTTPMethod") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsNonStandardHTTPMethod") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsNonStandardHTTPMethod") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsNonStandardHTTPMethod") as alertPriority
```

## SecOpsOutboundTrafficToDeviceFlaggedAsThreat

**Summary:** A record flagged a destination host from a threat intelligence match list.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Application Layer Protocol (T1071)

**Tables:** proxy.all.access

**Lookups:** mispIndicator, SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
where isnotnull(`lu/mispIndicator/category`(destination_hostname))
group every 5m by source, source_ipv4, source_hostname, user, destination_ipv4, destination_hostname, url, method, status_code, categories, user_agent, machine, client
every 5m
//Entity Mapping Section
select user as entity_sourceAccount
select str(source_ipv4) as entity_sourceIP
select str(destination_ipv4) as entity_destinationIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
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
select lu("mispIndicator", "category", entity_destinationIP) as indicator
select lu("mispIndicator", "type", entity_destinationIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsOutboundTrafficToDeviceFlaggedAsThreat") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsOutboundTrafficToDeviceFlaggedAsThreat") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsOutboundTrafficToDeviceFlaggedAsThreat") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsOutboundTrafficToDeviceFlaggedAsThreat") as alertPriority
```

## SecOpsOutcomingUnauthenticatedArbitraryFileReadInVMwareVCenter

**Summary:** [Internal connection] Unauthenticated Arbitrary File Read in VMware vCenter before version 6.5u1.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
where (toktains(url, "/eam/vib"))
and (toktains(url, "vCenterServer") or toktains(url, "vmware-vpx") or toktains(url, "vcdb.properties") or toktains(url, "etc/passwd"))
group every 5m by source_ipv4, url, destination_ipv4, machine, client
every 5m
select str(destination_ipv4) as entity_destinationIP
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(destination_ipv4) as enrichStream_entity_destinationIP_ASN
select isp(destination_ipv4) as enrichStream_entity_destinationIP_ISP
select countrycode(destination_ipv4) as enrichStream_entity_destinationIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_destinationIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_destinationIP) as indicator
select lu("mispIndicator", "type", entity_destinationIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsOutcomingUnauthenticatedArbitraryFileReadInVMwareVCenter") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsOutcomingUnauthenticatedArbitraryFileReadInVMwareVCenter") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsOutcomingUnauthenticatedArbitraryFileReadInVMwareVCenter") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsOutcomingUnauthenticatedArbitraryFileReadInVMwareVCenter") as alertPriority
```

## SecOpsPortIntoURL

**Summary:** During the normal navigation of a user or system, the URLs do not include the destination port. The use of the port can become suspicious behavior in combination with other factors.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Non-Standard Port (T1571)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
group every 5m by source_ipv4, url, destination_hostname, machine, client
every 5m
where isnotnull(destination_hostname)
select isnotnull(uriport(url)) ? uriport(url) : uriport("http://" + url) as uriPort
where isnotnull(uriPort)
where uriPort /= 443 and uriPort /= 80
select str(source_ipv4) as entity_sourceIP
select url as entity_destinationUrl
select lu("SecOpsAssetRole", "class", entity_destinationUrl) as entity_destinationUrl_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", url) as indicator
select lu("mispIndicator", "type", url) as misp_indicator_type
select lu("mispIndicator", "event_id", url) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPortIntoURL") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPortIntoURL") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPortIntoURL") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPortIntoURL") as alertPriority
```

## SecOpsPotentialThreatConnectionRansomBehaviour

**Summary:** Detects host downloading high risk files from host flagged as suspicious.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Remote Access Software (T1219)

**Tables:** proxy.all.access

**Lookups:** TA505CL0pMOVEitIOCs

```linq
from proxy.all.access
where toktains(url, "ZoomInstaller")
group every 5m by source_ip,source_hostname,destination_hostname,destination_ip,url,client
select `lu/TA505CL0pMOVEitIOCs/type`(destination_hostname) as pthreat
where isnotnull(`lu/TA505CL0pMOVEitIOCs/type`(destination_hostname))
select source_ip as entity_sourceIP
select destination_ip as entity_destinationIP
select destination_hostname as entity_destinationHostname
select source_hostname as entity_sourceHostname
select url as entity_sourceUrl
//<filtering_section>
select "Detection" as alertType
select "Command and Control" as alertMitreTactics
select "Remote Access Software" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsProxyDataExfiltrationDetection

**Summary:** Monitor proxy logs for connections from internal IPs to parsing or content aggregation sites known for data parsing and content extraction functionalities (Also Known As Paste sites).

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over C2 Channel (T1041)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from proxy.all.access
where has(destination_hostname, "gist.github.com","paste.mozilla.org","ide.geeksforgeeks.org","codepen.io","pastebin.com","gitlab.com","repl.it","paste.ubuntu.com","justpaste.it","jsfiddle.net","paste.centos.org","justpaste.it","jsbin.com","pastelink.net","codebeautify.org","controlc.com","controlc.com","invent.kde.org","ideone.com","paste.rohitab.com","codeshare.io","paste.opensuse.org","dotnetfiddle.net","notes.io","snipplr.com","paste2.org","hastebin.com","ivpaste.com","phpfiddle.org","codepad.org","justpaste.me","pastebin.osuosl.org","geany.org","bpa.st","paste.ofcode.org","paste.ee","dpaste.org","friendpaste.com","defuse.ca","dpaste.com","pastebin.icoder.uz","cl1p.net","pastie.org","pastecode.io","ghostbin.com","heypasteit.com","pastebin.fr","pasteall.org","jsitor.com","termbin.com","p.ip.fi","cutapaste.net","paste.lisp.org","paste.sh","dumpz.org","paste.jp","paste-bin.xyz","paste.xinu.at","paste.debian.net","vpaste.net","paste.pound-python.org","paste.org.ru","apaste.info","quickhighlighter.com","sprunge.us","commie.io","everfall.com","paste.strictfp.com","kpaste.net","fferen.kpaste.net","eilios.kpaste.net","rathena.kpaste.net","paste.frubar.net","pst.klgrth.io","pastebin.pt","nopaste.me","99paste.com","n0paste.tk","pastecode.fr","pastecode.ru","paste.lv","pastesqf.com","tutpaste.com","paste.scratchbook.ch","bitbin.it","pastebin.fi","nekobin.com","pastebin.osuosl.org","bitbin.it","pastefs.com","slexy.org","pasteio.com","paste4btc.com","nzxj65x32vh2fkhk.onion","zerobinqmdqd236y.onion","4m6omb3gmrmnwzxi.onion")
group every 10m by url,destination_ip,destination_hostname,user,source_port,source_hostname, machine, client
every 10m
select count(request_bytes) as datasent_bytes
select destination_ip as entity_destinationIP
select destination_hostname as entity_destinationDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_destinationDomain) as entity_destinationDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
select lu("mispIndicator", "category", entity_destinationIP) as indicator
select lu("mispIndicator", "type", entity_destinationIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsProxyDataExfiltrationDetection") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsProxyDataExfiltrationDetection") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsProxyDataExfiltrationDetection") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsProxyDataExfiltrationDetection") as alertPriority
```

## SecOpsProxyHighRiskFileExtension

**Summary:** Detects users downloading high risk files via requests without hostnames or referrers. Most legitimate downloads will have a valid hostname and referrer.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Ingress Tool Transfer (T1105)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
where weaktoktains(method, "GET")
where `or`(weaktoktains(url, ".exe"), weaktoktains(url, ".ps1"), weaktoktains(url, ".sys"), weaktoktains(url, ".bat"), weaktoktains(url, ".scr"), weaktoktains(url, ".vbs"), weaktoktains(url, ".vba"), weaktoktains(url, ".dll"))
where `or`(endswith(url, ".exe"), endswith(url, ".ps1"), endswith(url, ".sys"), endswith(url, ".bat"), endswith(url, ".scr"), endswith(url, ".vbs"), endswith(url, ".vba"), endswith(url, ".dll"))
where isnotnull(net4(destination_hostname)), isnull(referrer)
group every 5m by user, source_ipv4, destination_ipv4, url, content_type, categories, machine, client
select str(source_ipv4) as entity_sourceIP, str(destination_ipv4) as entity_destinationIP, user as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsProxyHighRiskFileExtension") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsProxyHighRiskFileExtension") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsProxyHighRiskFileExtension") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsProxyHighRiskFileExtension") as alertPriority
```

## SecOpsProxyHttpSingleCharacterFileNameRequest

**Summary:** Detects the download of a file with a single character filename.

**MITRE:** Tactics: Defense Evasion (TA0005), Command and Control (TA0011) | Techniques: Masquerading (T1036), Ingress Tool Transfer (T1105)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
group every 5m by source, source_ip, source_hostname, user, destination_ip, destination_hostname, url, method, status_code, categories, user_agent, machine, client
every 5m
select peek(url, re("\\/([\\S]{1}\\.[\\w]+)$"), 1) as file
where isnotnull(file)
// Uncomment the following line (and modify the regex as necessary) to target specific filetypes
where matches(file, re("(exe|dll|bat|ps1|vbs|vba|sh|rar|zip|tgz|tar|gz|7z)$"))
select count() as count
//Entity Mapping Section
select user as entity_sourceAccount
select source_ip as entity_sourceIP
select destination_ip as entity_destinationIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
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
select lu("mispIndicator", "category", ip4(entity_sourceIP)) as indicator
select lu("mispIndicator", "type", ip4(entity_sourceIP)) as misp_indicator_type
select lu("mispIndicator", "event_id", ip4(entity_sourceIP)) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsProxyHttpSingleCharacterFileNameRequest") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsProxyHttpSingleCharacterFileNameRequest") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsProxyHttpSingleCharacterFileNameRequest") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsProxyHttpSingleCharacterFileNameRequest") as alertPriority
```

## SecOpsRevilKaseyaWebShellsUploadConn

**Summary:** The REvil Ransomware has hit 40 service providers globally due to multiple Kaseya VSA Zero-days. the attack was pushed out via a infected IT Management update from Kaseya.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Server Software Component (T1505)

**Tables:** proxy.all.access

**Lookups:** SecOpsAssetRole, revilKaseya, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
group every 5m by source_ipv4, url, destination_hostname, machine, client
every 5m
select str(source_ipv4) as entity_sourceIP
select destination_hostname as entity_destinationHostname
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select peek(uripath(url), re("/.*/([^/?#]+)"), 1) as resource
where isnotnull(resource)
select `lu/revilKaseya/type`(resource) as isrevilKaseya
where isnotnull(isrevilKaseya)
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsRevilKaseyaWebShellsUploadConn") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRevilKaseyaWebShellsUploadConn") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRevilKaseyaWebShellsUploadConn") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRevilKaseyaWebShellsUploadConn") as alertPriority
```

## SecOpsSeveralAccessByProxy

**Summary:** Access to a several distinct hosts (domains) in a short period of time could be a suspicious behavior that It is important to monitor an control.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** proxy.all.access

**Lookups:** OpenRankTop10M, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from proxy.all.access
where not proxy_action = "TCP_DENIED",
not user = "-",
isnotnull(user)
where purpose(destination_ipv4) = "public" // Filter: Only public IP connections
where isnull(ip4(destination_hostname)) // Filter: Only connections to domains
group every 5m by source_ipv4, user, destination_hostname, machine, client
every 30m
where `lu/OpenRankTop10M/position`(rootdomain(destination_hostname)+"."+topleveldomain(destination_hostname)) < "1000000" // Filter: Not domains in the top 1M Openrank
select round(hllppcount(destination_hostname)) as dstHostRound
where dstHostRound >= 60
select user as entity_sourceName
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSeveralAccessByProxy") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSeveralAccessByProxy") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSeveralAccessByProxy") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSeveralAccessByProxy") as alertPriority
```

## SecOpsUserBlockedbyProxy

**Summary:** It is considered a suspicious behavior that a user is blocked by a proxy server on many occasions in a short period of time.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** proxy.all.access

**Lookups:** OpenRankTop10M, SecOpsAssetRole, SecOpsAlertDescription

```linq
from proxy.all.access
where proxy_action = "TCP_DENIED" or proxy_action = "Blocked"
where purpose(destination_ipv4) = "public" // Filter: Only public IP connections
where isnull(ip4(destination_hostname)) // Filter: Only connections to domains
where `lu/OpenRankTop10M/position`(rootdomain(destination_hostname)+"."+topleveldomain(destination_hostname)) < "1000000" // Filter: Not domains in the top 1M Openrank
group every 5m by user, machine, client
every 10m
select count() as count
where count >= 150
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsUserBlockedbyProxy") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsUserBlockedbyProxy") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsUserBlockedbyProxy") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsUserBlockedbyProxy") as alertPriority
```
