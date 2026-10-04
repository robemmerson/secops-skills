# Detection library: WEB

Web server access-log detections (web.all.access): scanners, webshells, exploits. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (26):

- SecOpsBackupFileAccessAttempt
- SecOpsCDIocIpSuspiciousWebData
- SecOpsCollectiveDefenseWebSrcIp
- SecOpsConfigurationFileAccessAttempt
- SecOpsCredentialsFileAccessAttempt
- SecOpsDatabaseFileAccessAttempt
- SecOpsDiscoveringPasswordFiles
- SecOpsExplotationAttemptF5BigIp
- SecOpsHAFNIUMHttpPostTargetingExchangeServers
- SecOpsHAFNIUMWebShellsTargetingExchangeServers
- SecOpsHTTPQueryNonStandardMethod
- SecOpsHTTPQueryUserAgentLengthOutsize
- SecOpsIncomingUnauthenticatedArbitraryFileReadInVMwareVCenter
- SecOpsLog4ShellVulnerabilityOverWebServerConnections
- SecOpsLogRelatedFileAccessAttempt
- SecOpsMalwareFileAccessAttempt
- SecOpsMoveitWebShell
- SecOpsPossibleFuzzingAttack
- SecOpsPossibleInjectionUserAgent
- SecOpsPossiblePathTrasversalInjection
- SecOpsPossiblePhishingKitByReferer
- SecOpsRevilKaseyaWebShells
- SecOpsRobotFileAskingByNoRobot
- SecOpsSeveralError4xx
- SecOpsSoftwareInfoAccessAttempt
- SecOpsWebShellFileSuspicious

## SecOpsBackupFileAccessAttempt

**Summary:** A backup file is stored in a directory or archive that is made accessible to unauthorized actors.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, SuspiciousWebPath, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where status_code = 200
group every 5m by source_ipv4, url, client
every 15m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select ifthenelse(startswith(url, "/"), substring(url, 1, length(url)), url) as webpath
select lu("SuspiciousWebPath", "type", webpath) as badwebpaths
where isnotnull(badwebpaths),
not webpath = "",
badwebpaths = "backup" // Avoid admin panels - customer has to filter based on customer tech.
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsBackupFileAccessAttempt") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBackupFileAccessAttempt") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBackupFileAccessAttempt") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBackupFileAccessAttempt") as alertPriority
```

## SecOpsCDIocIpSuspiciousWebData

**Summary:** This search looks for Collective Defense matches in web data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from web.all.access
where ispublic(source_ipv4)
select str(source_ipv4) as entity_sourceIP
group every 15m by entity_sourceIP, source, user, client
select hlurjson("CollectiveDefense", entity_sourceIP, eventdate) as cd_hit
where isnotnull(cd_hit)
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDIocIpSuspiciousWebData") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDIocIpSuspiciousWebData") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDIocIpSuspiciousWebData") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDIocIpSuspiciousWebData") as alertPriority
```

## SecOpsCollectiveDefenseWebSrcIp

**Summary:** This search looks for Collective Defense matches in web data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from web.all.access
where ispublic(source_ipv4)
group every 15m by source_ipv4, source, user, client
select str(source_ipv4) as entity_sourceIP
select hlurjson("CollectiveDefense", entity_sourceIP, eventdate) as cd_hit
where isnotnull(cd_hit)
// The below lines separate each json object.  This is unecessary for this alert
select jqeval(jqcompile(".sectors"), cd_hit) as sectors,
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
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCollectiveDefenseWebSrcIp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCollectiveDefenseWebSrcIp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCollectiveDefenseWebSrcIp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCollectiveDefenseWebSrcIp") as alertPriority
```

## SecOpsConfigurationFileAccessAttempt

**Summary:** A configuration file is stored in a directory or archive that is made accessible to unauthorized actors.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, SuspiciousWebPath, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where status_code = 200
group every 5m by source_ipv4, url, client
every 15m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select ifthenelse( startswith(url, "/"), substring(url, 1, length(url)), url) as webpath
select lu("SuspiciousWebPath", "type", webpath) as badwebpaths
where isnotnull(badwebpaths),
not webpath = "",
badwebpaths = "configfile" // Avoid admin panels - customer has to filter based on its tech.
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsConfigurationFileAccessAttempt") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsConfigurationFileAccessAttempt") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsConfigurationFileAccessAttempt") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsConfigurationFileAccessAttempt") as alertPriority
```

## SecOpsCredentialsFileAccessAttempt

**Summary:** A credential file is stored in a directory or archive that is made accessible to unauthorized actors.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, SuspiciousWebPath, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where status_code = 200
group every 5m by source_ipv4, url, client
every 15m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select ifthenelse( startswith(url, "/"), substring(url, 1, length(url)), url) as webpath
select lu("SuspiciousWebPath", "type", webpath) as badwebpaths
where isnotnull(badwebpaths),
not webpath = "",
badwebpaths = "credential" // Avoid admin panels - customer has to filter based on its tech.
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsCredentialsFileAccessAttempt") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCredentialsFileAccessAttempt") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCredentialsFileAccessAttempt") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCredentialsFileAccessAttempt") as alertPriority
```

## SecOpsDatabaseFileAccessAttempt

**Summary:** A Database file is stored in a directory or archive that is made accessible to unauthorized actors.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, SuspiciousWebPath, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where status_code = 200
group every 5m by source_ipv4, url, client
every 15m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select ifthenelse( startswith(url, "/"), substring(url, 1, length(url)), url) as webpath
select lu("SuspiciousWebPath", "type", webpath) as badwebpaths
where isnotnull(badwebpaths),
not webpath = "",
badwebpaths = "database" // Avoid admin panels - customer has to filter based on its tech.
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsDatabaseFileAccessAttempt") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsDatabaseFileAccessAttempt") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsDatabaseFileAccessAttempt") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsDatabaseFileAccessAttempt") as alertPriority
```

## SecOpsDiscoveringPasswordFiles

**Summary:** Based on a list of names related to files susceptible to contain sensitive information, in this case passwords, possible attempts to access this type of files are monitored.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
group every 5m by source_ipv4, url, client
every 15m
where url -> {"/etc/passwd" ,"/secring.skr" ,"/secring.pgp" ,"/secring.bak" ,"/passwd" ,"/passwd.bak" ,"/master.passwd" ,"/pwd.db" ,"/htpasswd" ,"/htpasswd.bak" ,"/htgroup" ,"/spwd.db" ,"/htpasswd/htpasswd.bak" ,"/config.php" ,"/phpinfo.php" ,"/passlist" ,"/passlist.txt" ,"/auth_user_file" ,"/administrators.pwd" ,"/admin.mdb" ,"/connect.inc" ,"/globals.inc" ,"/vtund.conf" ,"/password.log" ,"/slapd.conf" ,"/wvdial.conf" ,"/.netrc" ,"/wand.dat" ,"/mrtg.cfg" ,"/zebra.conf" ,"/ospfd.conf" ,"/ccbill.log" ,"/users.mdb" ,"/lilo.conf" ,"/wwwboard/passwd.txt" ,"/db/main.mdb" ,"/sites.ini" ,"/wcx_ftp.ini" ,"/ws_ftp.ini" ,"/flashFXP.ini" ,"/serv-u.ini" ,"/eudora.ini" ,"/unattend.txt" ,"/passwd.txt" ,"/server.cfg" ,"/pass.dat" ,"/phpinfo.php" ,"/admin.dat"}
select str(source_ipv4) as entity_sourceIP
select url as entity_destinationUrl
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select url as entity_sourceUrl
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicat
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsDiscoveringPasswordFiles") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsDiscoveringPasswordFiles") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsDiscoveringPasswordFiles") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsDiscoveringPasswordFiles") as alertPriority
```

## SecOpsExplotationAttemptF5BigIp

**Summary:** Detects the exploitation attempt of the vulnerability found in F5 BIG-IP and described in CVE-2020-5902

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from web.all.access
where weaktoktains(url, "/tmui/login") and ( weaktoktains(url, "..;/") or weaktoktains(url, ".jsp/.."))
group every 5m by source_ipv4, site, user_agent, client
every 10m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsExplotationAttemptF5BigIp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsExplotationAttemptF5BigIp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsExplotationAttemptF5BigIp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsExplotationAttemptF5BigIp") as alertPriority
```

## SecOpsHAFNIUMHttpPostTargetingExchangeServers

**Summary:** Microsoft has detected multiple 0-day exploits being used to attack on-premises versions of Microsoft Exchange Server in limited and targeted attacks. In the attacks observed, the threat actor used these vulnerabilities to access on-premises Exchange servers which enabled access to email accounts, and allowed installation of additional malware to facilitate long-term access to victim environments.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** web.all.access

**Lookups:** msfhafnium0day, SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from web.all.access
select uripath(url) as uripath
select lu("msfhafnium0day", "threat", uripath) as msfhafnium0day
select length(split(peek(uripath, re("/.*/([^/?#]+)"), 1), ".", 0)) as onecharacter
where isnotnull(msfhafnium0day) or (onecharacter = 1 and endswith(uripath,"js"))
group every 5m by source_ipv4, url, user_agent, client
every 5m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsHAFNIUMHttpPostTargetingExchangeServers") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHAFNIUMHttpPostTargetingExchangeServers") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHAFNIUMHttpPostTargetingExchangeServers") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHAFNIUMHttpPostTargetingExchangeServers") as alertPriority
```

## SecOpsHAFNIUMWebShellsTargetingExchangeServers

**Summary:** Microsoft has detected multiple 0-day exploits being used to attack on-premises versions of Microsoft Exchange Server in limited and targeted attacks.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: External Remote Services (T1133)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, msfhafnium0day, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
group every 5m by source_ipv4, url, client
every 5m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select peek(uripath(url), re("/.*/([^/?#]+)"), 1) as resource
where isnotnull(resource)
select lu("msfhafnium0day", "threat", resource) as listedmsfhafnium0day
where isnotnull(listedmsfhafnium0day)
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsHAFNIUMWebShellsTargetingExchangeServers") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHAFNIUMWebShellsTargetingExchangeServers") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHAFNIUMWebShellsTargetingExchangeServers") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHAFNIUMWebShellsTargetingExchangeServers") as alertPriority
```

## SecOpsHTTPQueryNonStandardMethod

**Summary:** HTTP defines a set of request methods to indicate the desired action to be performed for a given resource. It is necessary to monitor the non standard methods used in web server queries because they could be an indicator of an attack.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** web.all.access

**Lookups:** HTTPMethods, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where isnotnull(source_ipv4), isnotnull(method)
group every 30m by source_ipv4, method, client
every 1h
select lu("HTTPMethods", "known", method) as KnownMethod
where not KnownMethod = "known"
select str(source_ipv4) as entity_sourceIP
select method as HTTPMethod
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsHTTPQueryNonStandardMethod") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHTTPQueryNonStandardMethod") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHTTPQueryNonStandardMethod") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHTTPQueryNonStandardMethod") as alertPriority
```

## SecOpsHTTPQueryUserAgentLengthOutsize

**Summary:** One of the most dangerous attacks against a web server is an injection, either SQL, XPath, etc. These types of attacks do not affect only the forms or parameters of the server applications but can be done in the HTTP headers. It is necessary to monitor this type of attack in the headers.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from web.all.access
where isnotnull(source_ipv4)
where isnotnull(user_agent)
group every 5m by user_agent, source_ipv4, client
every 15m
select length(user_agent) as UserAgentLen
where UserAgentLen > 342 // This is 20% more than the 98th percentile of the length value calculated with a sample of more than 42 million User Agents
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsHTTPQueryUserAgentLengthOutsize") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHTTPQueryUserAgentLengthOutsize") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHTTPQueryUserAgentLengthOutsize") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHTTPQueryUserAgentLengthOutsize") as alertPriority
```

## SecOpsIncomingUnauthenticatedArbitraryFileReadInVMwareVCenter

**Summary:** [External connection] Unauthenticated Arbitrary File Read in VMware vCenter before version 6.5u1.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where (toktains(url, "/eam/vib"))
and (toktains(url, "vCenterServer") or toktains(url, "vmware-vpx") or toktains(url, "vcdb.properties") or toktains(url, "etc/passwd"))
group every 5m by source_ipv4, url, client
every 5m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsIncomingUnauthenticatedArbitraryFileReadInVMwareVCenter") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsIncomingUnauthenticatedArbitraryFileReadInVMwareVCenter") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsIncomingUnauthenticatedArbitraryFileReadInVMwareVCenter") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsIncomingUnauthenticatedArbitraryFileReadInVMwareVCenter") as alertPriority
```

## SecOpsLog4ShellVulnerabilityOverWebServerConnections

**Summary:** Alert that checks attempts to exploit CVE-2021-44228 known as Log4shell. The query looks for payload patterns associated with this vulnerability in the log raw message. This would include payloads included in the url, user-agent header, referrer header, or POST and PUT HTTP bodies. [WARNING] This alert detects attack patterns and can generate a high volume of events due to the number of scanners currently testing systems on the Internet. It is therefore likely to need some kind of tunning.

**Description:** Detects CVE-2021-44228 exploiting known as Log4shell. The query contained in this alert can generate high volumes of events due to the nature of the attack pattern. Tunning the alert to your environment is recommended.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where `in`("/$%7bjndi:","%24%7bjndi:","%24%7Bjndi:","%2524%257Bjndi","%2F%252524%25257Bjndi%3A","${::-j}${","${::-l}${::-d}${::-a}${::-p}","${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}:/","${${::-j}ndi:rmi:/","${${env:","${${lower:${lower:jndi}}:${lower:rmi}:/","${${lower:j}${lower:n}${lower:d}i:${lower:rmi}:","${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}:/","${${lower:jndi}:${lower:rmi}:/","${base64:JHtqbmRp","${jndi:${lower:","${jndi:${lower:l}${lower:d}a${lower:p}://","${jndi:corba","${jndi:dns:/","${jndi:http:/","${jndi:iiop","${jndi:ldap://","${jndi:ldap://${env:","${jndi:ldap:/","${jndi:ldaps:/","${jndi:nds","${jndi:nis","${jndi:rmi:/","$%7Bjndi:","$%7blower:","$%7Blower:","$%7bupper:","$%7Bupper:","${${::-${::-$${::-j}}}",raw)
group every 5m by source_ipv4,url,user_agent,tag,raw,referrer,cookies,hostchain,server_name,user, client
every 5m
select server_name as entity_destinationHostname
select str(source_ipv4) as entity_sourceIP
select user as entity_destinationAccount
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnerabilityOverWebServerConnections") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnerabilityOverWebServerConnections") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnerabilityOverWebServerConnections") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnerabilityOverWebServerConnections") as alertPriority
```

## SecOpsLogRelatedFileAccessAttempt

**Summary:** A log related file is stored in a directory or archive that is made accessible to unauthorized actors.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, SuspiciousWebPath, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where status_code = 200
group every 5m by source_ipv4, url, client
every 1h
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select ifthenelse( startswith(url, "/"), substring(url, 1, length(url)), url) as webpath
select lu("SuspiciousWebPath", "type", webpath) as badwebpaths
where isnotnull(badwebpaths),
not webpath = "",
badwebpaths = "logrelated" // Avoid admin panels - customer has to filter based on its tech.
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsLogRelatedFileAccessAttempt") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLogRelatedFileAccessAttempt") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLogRelatedFileAccessAttempt") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLogRelatedFileAccessAttempt") as alertPriority
```

## SecOpsMalwareFileAccessAttempt

**Summary:** A Malware related file is stored in a directory or archive that is made accessible to unauthorized actors.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, SuspiciousWebPath, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where status_code = 200
group every 5m by source_ipv4, url, client
every 15m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select ifthenelse( startswith(url, "/"), substring(url, 1, length(url)), url) as webpath
select lu("SuspiciousWebPath", "type", webpath) as badwebpaths
where isnotnull(badwebpaths),
not webpath = "",
badwebpaths = "malware" // Avoid admin panels - customer has to filter based on its tech.
select url as entity_sourceUrl
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMalwareFileAccessAttempt") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMalwareFileAccessAttempt") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMalwareFileAccessAttempt") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMalwareFileAccessAttempt") as alertPriority
```

## SecOpsMoveitWebShell

**Summary:** Detects attempts to exploit the MOVEit vulnerability CVE-2023-34362

**Description:** This detection catches CVE-2023-34362, which is an attempt to gain remote code execution on a MOVEit instance.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where `or`(toktains(url,"action=m2"), toktains(url, "guestaccess.aspx"))
group every 5m by source_ip, method, url, client
every 5m
select source_ip as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select ifthenelse(startswith(url, "/"), substring(url, 1, length(url)), url) as webpath
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMoveitWebShell") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMoveitWebShell") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMoveitWebShell") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMoveitWebShell") as alertPriority
```

## SecOpsPossibleFuzzingAttack

**Summary:** In order to detect attacks focused on URL parameters control the amount of parameters it should be a sign of an attack. Attacks like HTTP Parameter pollution are based on duplicate and send multiple parameters on URL to bypass control or Web Application Firewalls (WAF).

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where isnotnull(source_ipv4)
where isnotnull(url)
group every 30m by source_ipv4, url, client
every 1h
select str(source_ipv4) as entity_sourceIP
select uriquery(url) as entity_destinationUrl
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select length(subsall(entity_destinationUrl, re("[^&]"), template("")))+1 as paramsCount
where paramsCount > 50
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_destinationUrl) as indicator
select lu("mispIndicator", "type", entity_destinationUrl) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationUrl) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPossibleFuzzingAttack") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPossibleFuzzingAttack") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPossibleFuzzingAttack") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPossibleFuzzingAttack") as alertPriority
```

## SecOpsPossibleInjectionUserAgent

**Summary:** One of the most dangerous attack against a web server is injection, either SQL, XPath, etc.. These types of attacks do not affect only the forms or parameters of the server applications, but can be done in the HTTP headers. It is necessary to monitor this type of attacks in the headers.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where isnotnull(user_agent)
where user_agent -> "\\x"
or user_agent -> "$"
where isnotnull(source_ipv4)
group every 30m by source_ipv4, user_agent, client
every 1h
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPossibleInjectionUserAgent") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPossibleInjectionUserAgent") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPossibleInjectionUserAgent") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPossibleInjectionUserAgent") as alertPriority
```

## SecOpsPossiblePathTrasversalInjection

**Summary:** A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder. One of the ways to detect this kind of attacks ir to monitor the number of slash included in URL.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from web.all.access
group every 5m by source_ipv4,url,status_code, client
every 15m
select ((length(url)-length(replaceall(url, "/", "")))) as slashCount
select ((length(url)-length(replaceall(url, "..", "")))) as dotCount
select ((length(url)-length(replaceall(url, "%2e", "")))/3) as dotCountEncoded
select dotCount + dotCountEncoded as totalDotCount
where (slashCount > 10 and totalDotCount > 10) or (dotCountEncoded > 0 and slashCount + totalDotCount > 10)
where status_code >= 200 and status_code < 400
select url as entity_destinationUrl
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsPossiblePathTrasversalInjection") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPossiblePathTrasversalInjection") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPossiblePathTrasversalInjection") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPossiblePathTrasversalInjection") as alertPriority
```

## SecOpsPossiblePhishingKitByReferer

**Summary:** Detected referer domain suspected of being part of a the Phishing Kit.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Phishing (T1566)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from web.all.access
where not eqic(referrer, "-")
group every 5m by source_ipv4, referrer, client
every 15m
select str(source_ipv4) as entity_sourceIP
select urihost(referrer) as referer_domain
where isnotnull(`lu/mispIndicator`(referer_domain))
select urihost(referrer) as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select shannonentropy(entity_sourceHostname) as refererHostnameShannonEntropy
select subdomain(entity_sourceHostname) as refererHostnamesubdomains
select topleveldomain(entity_sourceHostname) as TLD
select length(subsall(refererHostnamesubdomains, re("[^\\.]"), template(""))) as subdomainsCount
select lu("mispIndicator", "category", entity_sourceHostname) as indicator
select lu("mispIndicator", "type", entity_sourceHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsPossiblePhishingKitByReferer") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPossiblePhishingKitByReferer") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPossiblePhishingKitByReferer") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPossiblePhishingKitByReferer") as alertPriority
```

## SecOpsRevilKaseyaWebShells

**Summary:** The REvil Ransomware has hit 40 service providers globally due to multiple Kaseya VSA Zero-days. the attack was pushed out via a infected IT Management update from Kaseya.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Server Software Component (T1505)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, revilKaseya, mispIndicator, SecOpsAlertDescription

```linq
from web.all.access
group every 5m by source_ipv4, url, client
every 5m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select peek(uripath(url), re("/.*/([^/?#]+)"), 1) as resource
where isnotnull(resource)
select `lu/revilKaseya/type`(resource) as isrevilKaseya
where isnotnull(isrevilKaseya)
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsRevilKaseyaWebShells") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRevilKaseyaWebShells") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRevilKaseyaWebShells") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRevilKaseyaWebShells") as alertPriority
```

## SecOpsRobotFileAskingByNoRobot

**Summary:** Web server request looking for resources related to automatic services (Robots) using different User Agents is considered suspicious behavior.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from web.all.access
where not user_agent = "-" // Avid User Agents not parsed
group every 5m by source_ipv4, user_agent, url, client
every 5m
where not uaisrobot(user_agent), // Not a robot User Agent
((url -> "robot.txt") or (url -> "sitemap.xml")) // Trying to get robot reources
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsRobotFileAskingByNoRobot") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRobotFileAskingByNoRobot") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRobotFileAskingByNoRobot") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRobotFileAskingByNoRobot") as alertPriority
```

## SecOpsSeveralError4xx

**Summary:** Client 4xx Errors in a web server can be an indicator of an attack occurring, authentication bypass, injection, etc.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where isnotnull(source_ipv4)
group every 5m by source_ipv4, server_name, status_code, client
every 15m
select str(status_code) as statusCodeStr
where startswith(statusCodeStr, "4")
select count() as count
where count >= 100
select str(source_ipv4) as entity_sourceIP
select server_name as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSeveralError4xx") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSeveralError4xx") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSeveralError4xx") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSeveralError4xx") as alertPriority
```

## SecOpsSoftwareInfoAccessAttempt

**Summary:** A software related file is stored in a directory or archive that is made accessible to unauthorized actors.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** web.all.access

**Lookups:** SuspiciousWebPath, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from web.all.access
where status_code = 200
group every 5m by source_ipv4, url, client
every 15m
select str(source_ipv4) as entity_sourceIP
select ifthenelse( startswith(url, "/"), substring(url, 1, length(url)), url) as webpath
select lu("SuspiciousWebPath", "type", webpath) as badwebpaths
where isnotnull(badwebpaths),
not webpath = "",
badwebpaths = "softwareinfo" // Avoid admin panels - customer has to filter based on its tech.
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSoftwareInfoAccessAttempt") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSoftwareInfoAccessAttempt") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSoftwareInfoAccessAttempt") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSoftwareInfoAccessAttempt") as alertPriority
```

## SecOpsWebShellFileSuspicious

**Summary:** Access to suspicious resources, such as so-called webshells, must be monitored. This is done using a list of files broadly used by malware to host malicious services on compromised servers.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** web.all.access

**Lookups:** SecOpsAssetRole, isPHPWebshell, mispIndicator, SecOpsAlertDescription

```linq
from web.all.access
group every 5m by url, source_ipv4, client
every 10m
select str(source_ipv4) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select split(url, "/?", 0) as tempURL,
subs(tempURL, re("^.*(\\/)(.*)$"), template("\\2"), "") as entity_destinationUrl
select `lu/isPHPWebshell/webshell`(entity_destinationUrl) as enrichStream_entity_destinationUrl_suspiciousPHPWebshell
where isnotnull(enrichStream_entity_destinationUrl_suspiciousPHPWebshell)
select asn(source_ipv4) as enrichStream_entity_sourceIP_ASN
select isp(source_ipv4) as enrichStream_entity_sourceIP_ISP
select countrycode(source_ipv4) as enrichStream_entity_sourceIP_country
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsWebShellFileSuspicious") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWebShellFileSuspicious") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWebShellFileSuspicious") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWebShellFileSuspicious") as alertPriority
```
