# Detection library: NETWORK/DNS

DNS detections: tunnelling, DGA, suspicious domains. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (13):

- SecOpsDNSQueryToExternalSrvcInteractionDomains
- SecOpsHAFNIUMUserAgentsTargetingExchangeServers
- SecOpsHostDNSBasedCovertChannelIpv6Record
- SecOpsHostNameSubdomainLength
- SecOpsLog4ShellVulnOverDomainsUnionTableConnections
- SecOpsLog4ShellVulnOverDomainsUnionTableConnectionsWithLookup
- SecOpsPossibleDnsEncodingQuery
- SecOpsRevilKaseyaDomainConnection
- SecOpsSuspiciousConnectionToCoinminerDomain
- SecOpsTLDFromDomainNotInMozillaTLD
- SecOpsTooLongDNSResponse
- SecOpsUnusualUseragentLength
- SecOpsWinDnsExcessiveEmptyOrRefusedQueries

## SecOpsDNSQueryToExternalSrvcInteractionDomains

**Summary:** Detects suspicious DNS queries to external service interaction domains often used for out-of-band interactions after successful RCE.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Active Scanning (T1595)

**Tables:** network.dns

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from network.dns
where (weakhas(name, ".interact.sh") or  weakhas(name, ".oast.pro") or  weakhas(name, ".oast.live") or  weakhas(name, ".oast.site") or  weakhas(name, ".oast.online") or  weakhas(name, ".oast.fun") or  weakhas(name, ".oast.me") or  weakhas(name, ".burpcollaborator.net") or  weakhas(name, ".oastify.com") or  weakhas(name, ".canarytokens.com") or  weakhas(name, ".requestbin.net") or  weakhas(name, ".dnslog.cn"))
select str(srcIp) as entity_sourceIP
select name as entity_destinationHostname
group every 5m by entity_sourceIP, entity_destinationHostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsDNSQueryToExternalSrvcInteractionDomains") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsDNSQueryToExternalSrvcInteractionDomains") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsDNSQueryToExternalSrvcInteractionDomains") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsDNSQueryToExternalSrvcInteractionDomains") as alertPriority
```

## SecOpsHAFNIUMUserAgentsTargetingExchangeServers

**Summary:** Microsoft has detected multiple 0-day exploits being used to attack on-premises versions of Microsoft Exchange Server in limited and targeted attacks.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** domains.all

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from domains.all
where isnotnull(user_agent)
group every 5m by user_agent, domain, url, source, client
every 5m
select domain as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
where toktains(user_agent,"antSword/v2.1") or
toktains(user_agent,"Googlebot/2.1+(+http://www.googlebot.com/bot.html)") or
toktains(user_agent,"Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html)") or
toktains(user_agent,"DuckDuckBot/1.0;+(+http://duckduckgo.com/duckduckbot.html)") or
toktains(user_agent,"facebookexternalhit/1.1+(+http://www.facebook.com/externalhit_uatext.php)") or
toktains(user_agent,"Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html)") or
toktains(user_agent,"Mozilla/5.0+(compatible;+Bingbot/2.0;++http://www.bing.com/bingbot.htm)") or
toktains(user_agent,"Mozilla/5.0+(compatible;+Googlebot/2.1;++http://www.google.com/bot.html") or
toktains(user_agent,"Mozilla/5.0+(compatible;+Konqueror/3.5;+Linux)+KHTML/3.5.5+(like+Gecko)+(Exabot-Thumbnails)") or
toktains(user_agent,"Mozilla/5.0+(compatible;+Yahoo!+Slurp;+http://help.yahoo.com/help/us/ysearch/slurp)") or
toktains(user_agent,"Mozilla/5.0+(compatible;+YandexBot/3.0;++http://yandex.com/bots)") or
toktains(user_agent,"ExchangeServicesClient/0.0.0.0") or
toktains(user_agent,"python-requests/2.19.1") or
toktains(user_agent,"python-requests/2.25.1") or
toktains(user_agent,"Mozilla/5.0+(X11;+Linux+x86_64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/51.0.2704.103+Safari/537.36")
select lu("SecOpsAlertDescription", "alertType", "SecOpsHAFNIUMUserAgentsTargetingExchangeServers") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHAFNIUMUserAgentsTargetingExchangeServers") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHAFNIUMUserAgentsTargetingExchangeServers") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHAFNIUMUserAgentsTargetingExchangeServers") as alertPriority
```

## SecOpsHostDNSBasedCovertChannelIpv6Record

**Summary:** Detects if a tripe A DNS response contains or not an IP announced. In case the response contains a non-announced IPv6, we can think there is a kind of cover-channel communication attempt.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Application Layer Protocol (T1071)

**Tables:** network.dns

**Lookups:** SecOpsAssetRole, mispIndicator, MozillaTLDList, AlexaTop1M, UmbrellaTop1M, SecOpsLocation, SecOpsAlertDescription

```linq
from network.dns
where isnotnull(response)
group every 5m by srcIp,name,response, client
every 5m
select ip6(response) as ip6
select ifthenelse(isnotnull(ip6),ifthenelse(isnull(countrycode(ip6)),"notAnnouncedIPv6","announcedIPv6"),"notIPv6") as announcedIP
where not announcedIP = "notIPv6" or not announcedIP = "announcedIPv6" // Detect not announced IPv6
select str(srcIp) as entity_sourceIP
select name as entity_destinationHostname
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select subdomain(name) as HostnameSubdomains
select rootdomain(name) as HostnameRootDomain
select topleveldomain(name) as HostnameTLD
select rootprefix(name) as HostnameRootPrefix
select rootsuffix(name) as HostnameRootSuffix
select length(HostnameSubdomains) as HostnameSubdomainsCount
where not HostnameTLD = "" // Filtering empty TLD
where not HostnameTLD = "arpa" // Filtering PTR records
where HostnameSubdomainsCount > 126 // Half of maximun nomber of characteres for a domain
select isp(srcIp) as enrichStream_entity_sourceIP_ISP
select countrycode(srcIp) as enrichStream_entity_sourceIP_country
select asn(srcIp) as enrichStream_entity_sourceIP_ASN
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select topleveldomain(entity_destinationHostname) as TLD
select rootdomain(entity_destinationHostname) as fqdn
select `lu/MozillaTLDList/status`(TLD) as enrichStream_entity_destinationHostname_isInMozillaTLD
select `lu/AlexaTop1M/position`(fqdn) as enrichStream_entity_destinationHostname_positionInAlexaTop1M
select `lu/UmbrellaTop1M/position`(fqdn) as enrichStream_entity_destinationHostname_positionInUmbrellaTop1M
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsHostDNSBasedCovertChannelIpv6Record") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHostDNSBasedCovertChannelIpv6Record") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHostDNSBasedCovertChannelIpv6Record") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHostDNSBasedCovertChannelIpv6Record") as alertPriority
```

## SecOpsHostNameSubdomainLength

**Summary:** Too long subdomains could be part of Application Layer Protocols.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Application Layer Protocol (T1071)

**Tables:** network.dns

**Lookups:** SecOpsAssetRole, MozillaTLDList, AlexaTop1M, UmbrellaTop1M, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from network.dns
group every 5m by srcIp,name, client
every 5m
select srcIp as entity_sourceIP
select name as entity_destinationHostname
select subdomain(name) as HostnameSubdomains
select length(HostnameSubdomains) as HostnameSubdomainsCount
where HostnameSubdomainsCount > 126
select isp(entity_sourceIP) as enrichStream_entity_sourceIP_ISP
select topleveldomain(entity_destinationHostname) as TLD
select rootdomain(entity_destinationHostname) as fqdn
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select `lu/MozillaTLDList/status`(TLD) as enrichStream_entity_destinationHostname_isInMozillaTLD
select `lu/AlexaTop1M/position`(fqdn) as enrichStream_entity_destinationHostname_positionInAlexaTop1M
select `lu/UmbrellaTop1M/position`(fqdn) as enrichStream_entity_destinationHostname_positionInUmbrellaTop1M
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsHostNameSubdomainLength") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHostNameSubdomainLength") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHostNameSubdomainLength") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHostNameSubdomainLength") as alertPriority
```

## SecOpsLog4ShellVulnOverDomainsUnionTableConnections

**Summary:** Alert that checks attempts of exploiting CVE-2021-44228 known as Log4shell. The query looks for payload patterns associated with this vulnerability in the log raw message. This would include payloads included in the URL, user-agent header, referrer header, or POST and PUT HTTP bodies. [WARNING] This alert detects attack patterns and can generate a high volume of events due to the number of scanners currently testing systems on the Internet. It is therefore likely to need some kind of tunning.

**Description:** Checks for attempts of exploiting CVE-2021-44228 as known as Log4shell.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** domains.all

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from domains.all
where `in`("/$%7bjndi:","%24%7bjndi:","%24%7Bjndi:","%2524%257Bjndi","%2F%252524%25257Bjndi%3A","${::-j}${","${::-l}${::-d}${::-a}${::-p}","${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}:/","${${::-j}ndi:rmi:/","${${env:","${${lower:${lower:jndi}}:${lower:rmi}:/","${${lower:j}${lower:n}${lower:d}i:${lower:rmi}:","${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}:/","${${lower:jndi}:${lower:rmi}:/","${base64:JHtqbmRp","${jndi:${lower:","${jndi:${lower:l}${lower:d}a${lower:p}://","${jndi:corba","${jndi:dns:/","${jndi:http:/","${jndi:iiop","${jndi:ldap://","${jndi:ldap://${env:","${jndi:ldap:/","${jndi:ldaps:/","${jndi:nds","${jndi:nis","${jndi:rmi:/","$%7Bjndi:","$%7blower:","$%7Blower:","$%7bupper:","$%7Bupper:","${${::-${::-$${::-j}}}",raw)
group every 5m by domain,url,user_agent,source,tag,raw, client
every 5m
select domain as entity_destinationDomain
select domain as entity_destinationIP
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationDomain) as entity_destinationDomain_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_destinationIP) as indicator
select lu("mispIndicator", "type", entity_destinationIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnOverDomainsUnionTableConnections") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnOverDomainsUnionTableConnections") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnOverDomainsUnionTableConnections") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnOverDomainsUnionTableConnections") as alertPriority
```

## SecOpsLog4ShellVulnOverDomainsUnionTableConnectionsWithLookup

**Summary:** Alert that checks attempts of exploiting CVE-2021-44228 known as Log4shell. The query looks for payload patterns associated with this vulnerability on the log raw message. This would include payloads included in the url, user-agent header, referer header or POST and PUT HTTP bodies. [WARNING] This alert detects attack patterns and can generate a high volume of events due to the number of scanners currently testing systems on the Internet. It is therefore likely to need some kind of tunning.

**Description:** Checks for attempts of exploiting CVE-2021-44228. Alert that checks attempts of exploiting CVE-2021-44228 known as Log4shell.

**MITRE:** Tactics: Initial Access (TA0001), Discovery (TA0007), Impact (TA0040) | Techniques: Exploit Public-Facing Application (T1190), Network Service Discovery (T1046), Remote System Discovery (T1018), Resource Hijacking (T1496)

**Tables:** domains.all

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from domains.all
where isnotnull(`lu/log4shell`(domain)) or isnotnull(`lu/log4shell`(rootsuffix(domain)))
group every 15m by domain,url,source,tag,raw, client
every 15m
select domain as entity_destinationDomain
select domain as entity_destinationIP
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationDomain) as entity_destinationDomain_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_destinationIP) as indicator
select lu("mispIndicator", "type", entity_destinationIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_destinationIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_destinationIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_destinationIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_destinationIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_destinationIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnOverDomainsUnionTableConnectionsWithLookup") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnOverDomainsUnionTableConnectionsWithLookup") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnOverDomainsUnionTableConnectionsWithLookup") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnOverDomainsUnionTableConnectionsWithLookup") as alertPriority
```

## SecOpsPossibleDnsEncodingQuery

**Summary:** Possible DNS exfiltration detected.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** network.dns

**Lookups:** SecOpsAssetRole, AlexaTop1M, UmbrellaTop1M, mispIndicator, SecOpsAlertDescription

```linq
from network.dns
group every 5m by name, client
every 1h
select name as entity_destinationHostname
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select subdomain(name) as HostnameSubdomains,
rootdomain(name) as HostnameRootDomain,
topleveldomain(name) as HostnameTLD,
rootprefix(name) as HostnameRootPrefix,
rootsuffix(name) as HostnameRootSuffix
where not name -> "-",
not name  -> " ",
not name -> "_",
not HostnameRootDomain = ""
select peek(HostnameTLD, re("([0-9]{1,4})")) as validTLD
where isnull(validTLD)
select peek(HostnameSubdomains, re("([A-Fa-f0-9]{8,})"), 1) as isBASE
select peek(HostnameSubdomains, re("([F-Zf-z]{1,})")) as notBASE
select peek(HostnameSubdomains, re("([A-Fa-f0-9]{8,})"), 1) as ishex
select shannonentropy(HostnameSubdomains) as HostnameSubdomainsEntropy
where not HostnameTLD = ""
where (isnotnull(ishex) and HostnameSubdomainsEntropy > 3.9) or (HostnameSubdomainsEntropy > 3.9 and weakhas(HostnameSubdomains, "=="))
select `lu/AlexaTop1M/position`(HostnameRootSuffix) as enrichStream_entity_destinationHostname_positionInAlexaTop1M
select `lu/UmbrellaTop1M/position`(HostnameRootSuffix) as enrichStream_entity_destinationHostname_positionInUmbrellaTop1M
select lu("mispIndicator", "category", name) as indicator
select lu("mispIndicator", "type", name) as misp_indicator_type
select lu("mispIndicator", "event_id", name) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsPossibleDnsEncodingQuery") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPossibleDnsEncodingQuery") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPossibleDnsEncodingQuery") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPossibleDnsEncodingQuery") as alertPriority
select length(subsall(HostnameSubdomains, re("[^\\.]"), template(""))) + 1 as enrichStream_entity_destinationHostname_numberOfSudomains
select length(HostnameSubdomains) as enrichStream_entity_destinationHostname_subdomainLength
select length(entity_destinationHostname) as enrichStream_entity_destinationHostname_domainLength
```

## SecOpsRevilKaseyaDomainConnection

**Summary:** The REvil Ransomware has hit 40 service providers globally due to multiple Kaseya VSA Zero-days. the attack was pushed out via a infected IT Management update from Kaseya.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Application Layer Protocol (T1071)

**Tables:** domains.all

**Lookups:** revilKaseya, SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from domains.all
where isnotnull(domain)
group every 5m by domain, client
every 30m
// Check domain is not an IP
select ip4(domain) as ip
where isnull(ip)
select domain as entity_destinationHostname
where not isnull(`lu/revilKaseya/type`(entity_destinationHostname))
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsRevilKaseyaDomainConnection") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRevilKaseyaDomainConnection") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRevilKaseyaDomainConnection") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRevilKaseyaDomainConnection") as alertPriority
```

## SecOpsSuspiciousConnectionToCoinminerDomain

**Summary:** Detect connections to domain flagged as possible coin minner.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Resource Hijacking (T1496)

**Tables:** network.dns

**Lookups:** SecOpsAssetRole

```linq
from network.dns
select str(srcIp) as entity_sourceIP
select name as entity_destinationHostname
group every 10m by entity_sourceIP, entity_destinationHostname, client
every 10m
where isnotnull(`lu/mispIndicator`(entity_destinationHostname))
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Impact" as alertMitreTactics
select "Resource Hijacking" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsTLDFromDomainNotInMozillaTLD

**Summary:** Detect a domain with a TLD, not in Mozilla TLD List.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Dynamic Resolution (T1568)

**Tables:** domains.all

**Lookups:** SecOpsAssetRole, MozillaTLDList, AlexaTop1M, UmbrellaTop1M, SecOpsAlertDescription, mispIndicator

```linq
from domains.all
where isnotnull(domain)
group every 5m by domain, client
every 30m
// Check domain is not an IP
select ip4(domain) as ip
where isnull(ip)
select domain as entity_destinationHostname
where toktains(domain, ".")
and not toktains(domain, "/")
and not toktains(domain," ")
and not endswith(domain,".")
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select topleveldomain(entity_destinationHostname) as top_level_domain
where not top_level_domain = ""
select subdomain(entity_destinationHostname) as subdomains
where not subdomains = ""
select rootdomain(entity_destinationHostname) as fqdn
select `lu/MozillaTLDList/status`(lower(top_level_domain)) as enrichStream_entity_destinationHostname_isInMozillaTLD
select `lu/AlexaTop1M/position`(fqdn) as enrichStream_entity_destinationHostname_positionInAlexaTop1M
select `lu/UmbrellaTop1M/position`(fqdn) as enrichStream_entity_destinationHostname_positionInUmbrellaTop1M
where isnull(enrichStream_entity_destinationHostname_isInMozillaTLD)
select lu("SecOpsAlertDescription", "alertType", "SecOpsTLDFromDomainNotInMozillaTLD") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsTLDFromDomainNotInMozillaTLD") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsTLDFromDomainNotInMozillaTLD") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsTLDFromDomainNotInMozillaTLD") as alertPriority
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
```

## SecOpsTooLongDNSResponse

**Summary:** Monitor TXT and ANY responses to detect infiltrations or possible reflection attacks.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Obfuscated Files or Information (T1027)

**Tables:** network.dns

**Lookups:** SecOpsAssetRole, MozillaTLDList, AlexaTop1M, UmbrellaTop1M, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from network.dns
group every 5m by srcIp, name, answers, qclass, type, client
every 10m
where qclass -> "TXT" or qclass ->"ANY"
where not type = "query"
where not type = "update"
select length(answers) as answerslen
where answerslen >= 150
select str(srcIp) as entity_sourceIP
select name as entity_destinationHostname
select topleveldomain(entity_destinationHostname) as TLD
select rootdomain(entity_destinationHostname) as fqdn
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select `lu/MozillaTLDList/status`(TLD) as enrichStream_entity_destinationHostname_isInMozillaTLD
select `lu/AlexaTop1M/position`(fqdn) as enrichStream_entity_destinationHostname_positionInAlexaTop1M
select `lu/UmbrellaTop1M/position`(fqdn) as enrichStream_entity_destinationHostname_positionInUmbrellaTop1M
select asn(srcIp) as enrichStream_entity_sourceIP_ASN
select isp(srcIp) as enrichStream_entity_sourceIP_ISP
select countrycode(srcIp) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsTooLongDNSResponse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsTooLongDNSResponse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsTooLongDNSResponse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsTooLongDNSResponse") as alertPriority
```

## SecOpsUnusualUseragentLength

**Summary:** Unusual User Agent length detected. It can be associated with some type of attack or vulnerability.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** domains.all

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription, AlexaTop1M, UmbrellaTop1M, MozillaTLDList

```linq
from domains.all
group every 5m by domain, url, user_agent, client
every 10m
select domain as entity_destinationHostname
select url as entity_destinationUrl
select nnlast(source) as source
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select rootdomain(domain) as FQDN
select topleveldomain(domain) as tld
select length(user_agent) as useragentLength
where useragentLength > 300
select lu("mispIndicator", "category", domain) as indicator
select lu("mispIndicator", "type", domain) as miss_indicator_type
select lu("mispIndicator", "event_id", domain) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsUnusualUseragentLength") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsUnusualUseragentLength") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsUnusualUseragentLength") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsUnusualUseragentLength") as alertPriority
select `lu/AlexaTop1M/position`(FQDN) as enrichStream_entity_sourceHostname_positionInAlexaTop1M
select `lu/UmbrellaTop1M/position`(FQDN) as enrichStream_entity_sourceHostname_positionInUmbrellaTop1M
select `lu/MozillaTLDList/status`(tld) as enrichStream_entity_destinationHostname_isInMozillaTLD
```

## SecOpsWinDnsExcessiveEmptyOrRefusedQueries

**Summary:** Detects excessive empty or refused Windows DNS queries which may be a sign of DNS tunneling. The threshold for excessive query count should be modified to suit organizational needs.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Protocol Tunneling (T1572)

**Tables:** dns.windows

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from dns.windows
where `or`(toktains(response_code, "REFUSED"), toktains(response_code, "5"), isnull(response_code))
group every 5m by hostname, remote_ip, client
select remote_ip as entity_sourceIP
select count() as n_requests
where n_requests > 50 // Adjust threshold as necessary
select first(eventdate) as first_seen, last(eventdate) as last_seen,
hostname as entity_destinationHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinDnsExcessiveEmptyOrRefusedQueries") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinDnsExcessiveEmptyOrRefusedQueries") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinDnsExcessiveEmptyOrRefusedQueries") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinDnsExcessiveEmptyOrRefusedQueries") as alertPriority
```
