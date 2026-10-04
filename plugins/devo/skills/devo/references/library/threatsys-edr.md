# Detection library: THREATSYS/EDR

EDR detections (edr.all.*, CrowdStrike, Cylance). Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (10):

- SecOpsDomainReconnADEnumerationAndTrustMapping
- SecOpsEDRCrowdStrikeOverwatchNotification
- SecOpsEDRCylanceScoreUnsafe
- SecOpsHAFNIUMHashFoundFileTargetingExchangeServers
- SecOpsLog4ShellVulnerabilityOverCrowdStrike
- SecOpsMoveitWindowsEvtxFileCreation
- SecOpsRansomBehaviorShadowCopyDeletionAndResizing
- SecOpsRevilKaseyaHashFound
- SecOpsStopWindowsServiceViaNet
- SecOpsSuspiciousCmdExecDirChangeUserReconn

## SecOpsDomainReconnADEnumerationAndTrustMapping

**Summary:** This alert detects domain reconnaissance activities by executing commands that enumerate domain controllers, domain computers, and trust relationships. These commands (nltest and net group) are commonly used by attackers to gather information about the network's Active Directory structure, identify key systems, and map potential lateral movement paths. This behavior is indicative of post-compromise reconnaissance efforts.

**Description:** Detects domain reconn activities by executing commands that enumerate domain controllers, domain computers, and trust relationships. nltest and net group are commonly used to gather information.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Remote System Discovery (T1018)

**Tables:** edr.all.processes

**Lookups:** none

```linq
from edr.all.processes
where toktains(command_line, "cmd.exe /C nltest")
or toktains(command_line, "cmd.exe /C net group")
or toktains(command_line, "cmd.exe /C nltest")
or toktains(command_line, "cmd.exe /C time")
//where parent_path = "cmd.exe"
group every 5m by source_ip,source_hostname,source_username,parent_path,client
select collectDistinct(command_line) as commands
where round(hllppcount(command_line)) > 3
select source_ip as entity_sourceIP
select source_hostname as entity_sourceHostname
select source_username as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Subvert Trust Controls" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsEDRCrowdStrikeOverwatchNotification

**Summary:** Falcon Overwatch has identified suspicious activity. This has been raised for your awareness and should be investigated as normal.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Exploitation for Client Execution (T1203)

**Tables:** edr.crowdstrike.falcon

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from edr.crowdstrike.falcon
where eq(event_DetectName,"Overwatch Detection")
select event_ComputerName as entity_sourceHostname
select event_UserName as entity_sourceAccount
group every 5m by entity_sourceHostname, entity_sourceAccount, event_DetectDescription, event_Severity, event_SeverityName, event_FileName, event_FilePath, event_CommandLine, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsEDRCrowdStrikeOverwatchNotification") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsEDRCrowdStrikeOverwatchNotification") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsEDRCrowdStrikeOverwatchNotification") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsEDRCrowdStrikeOverwatchNotification") as alertPriority
```

## SecOpsEDRCylanceScoreUnsafe

**Summary:** An unsafe file is one that has attributes that greatly resemble malware.

**MITRE:** Tactics: Resource Development (TA0042) | Techniques: Stage Capabilities (T1608)

**Tables:** edr.cylance.threats

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from edr.cylance.threats
where cylance_score >= 60
select ip_address as entity_sourceIP
select device_name as entity_sourceHostname
group every 5m by entity_sourceIP,entity_sourceHostname, path, file_name, threat_class, status, cylance_score, sha_256, md5, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsEDRCylanceScoreUnsafe") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsEDRCylanceScoreUnsafe") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsEDRCylanceScoreUnsafe") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsEDRCylanceScoreUnsafe") as alertPriority
```

## SecOpsHAFNIUMHashFoundFileTargetingExchangeServers

**Summary:** Microsoft has detected multiple 0-day exploits being used to attack on-premises versions of Microsoft Exchange Server in limited and targeted attacks.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** edr.all.threats

**Lookups:** msfhafnium0day, SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from edr.all.threats
where isnotnull(sha256)
select lu("msfhafnium0day", "threat", sha256) as ismsfhafnium0day
where isnotnull(ismsfhafnium0day)
group every 5m by ip, sha256, mac, file_name, hostname, threat_name, ismsfhafnium0day, client
where isnotnull(ip)
select str(ip) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip) as enrichStream_entity_sourceIP_ASN
select isp(ip) as enrichStream_entity_sourceIP_ISP
select countrycode(ip) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsHAFNIUMHashFoundFileTargetingExchangeServers") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHAFNIUMHashFoundFileTargetingExchangeServers") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHAFNIUMHashFoundFileTargetingExchangeServers") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHAFNIUMHashFoundFileTargetingExchangeServers") as alertPriority
```

## SecOpsLog4ShellVulnerabilityOverCrowdStrike

**Summary:** Alert that checks attempts of exploiting CVE-2021-44228 known as Log4shell. The alert checks parent java processes spawning suspicious child processes such as sh, bash, dash, ksh, tcsh, zsh, curl, per, python, ruby, php or wget and java processes trying connections against remote host on ports 1389, 389, 1099, 53 or 5353. [WARNING] This alert detects suspicious behaviours that could be completely legitimate. It is therefore likely to need some kind of tunning.

**Description:** Checks for attempts of exploiting CVE-2021-44228 known as Log4shell.

**MITRE:** Tactics: Initial Access (TA0001), Discovery (TA0007), Impact (TA0040) | Techniques: Exploit Public-Facing Application (T1190), Network Service Discovery (T1046), Remote System Discovery (T1018), Resource Hijacking (T1496)

**Tables:** edr.crowdstrike.cannon.processrollup2, firewall.all.traffic

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from edr.crowdstrike.cannon.processrollup2
group every 5m by ParentBaseFileName,ImageFileName,CommandLine,aip,ParentProcessId,ComputerName, client
every 5m
// Execution arbitrary code (Step 5 from GovCert.sh KillChain diagram)
where (ParentBaseFileName -> "java" and {"sh","bash","dash","ksh","tcsh","zsh","curl","perl","python","ruby","php","wget"} in ImageFileName)
// Connecting to malicious LDAP search (Step 3 from GovCert.sh KillChain diagram)
where ParentProcessId in(
  from edr.crowdstrike.cannon.processrollup2
  where {":1389", ":389", ":1099", ":636", "ldap", "dns"} in CommandLine
  //where now()-5m <= eventdate < now()
  group every - by RawProcessId
  select RawProcessId as ParentProcessId)
// Firewall correlation: Connecting to malicious LDAP search (Step 3 from GovCert.sh KillChain diagram)
where aip in (
  from firewall.all.traffic
  where {"1389", "389", "1099", "636"} in dstPort
  where ispublic(dstIp)
  //where now()-5m <= eventdate < now()
  group every - by srcIp
  select srcIp as aip)
select ComputerName as entity_sourceHostname
select str(aip) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select nnlast(rawMessage) as last_rawMessage
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnerabilityOverCrowdStrike") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnerabilityOverCrowdStrike") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnerabilityOverCrowdStrike") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnerabilityOverCrowdStrike") as alertPriority
```

## SecOpsMoveitWindowsEvtxFileCreation

**Summary:** This alert detects the creation of Windows Event (EVTX) log files, which may indicate that an attacker is recording system actions and events to gather information, monitor system behavior, or document their steps during exploitation.

**Description:** Detects the creation of Windows Event (EVTX) log files, which may indicate that an attacker is recording system actions and events to gather information or monitor system behavior.

**MITRE:** Tactics: Execution (TA0002) | Techniques: System Services (T1569)

**Tables:** edr.crowdstrike.cannon.genericfilewritten

**Lookups:** none

```linq
from edr.crowdstrike.cannon.genericfilewritten
where toktains(TargetFileName, "MOVEit.evtx")
group every 5m by aip,hostname,UserName,TargetFileName,client
select str(aip) as entity_sourceIP
select hostname as entity_sourceHostname
select UserName as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Execution" as alertMitreTactics
select "System Services" as alertMitreTechniques
select 2 as alertPriority
```

## SecOpsRansomBehaviorShadowCopyDeletionAndResizing

**Summary:** This alert detects suspicious behavior associated with deleting or resizing Volume Shadow Copy storage, often seen during ransomware execution. Attackers commonly use this tactic to eliminate system backups (shadow copies) and prevent recovery, thus ensuring their ransomware can fully encrypt the system without the victim being able to restore data from previous snapshots.

**Description:** Detects suspicious behavior associated with deleting or resizing Volume Shadow Copy storage, often seen during ransomware execution.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Windows Management Instrumentation (T1047)

**Tables:** edr.all.processes

**Lookups:** none

```linq
from edr.all.processes
where toktains(command_line, "vssadmin.exe Delete Shadows")
or toktains(command_line, "vssadmin.exe resize shadowstorage")
or toktains(command_line, "maxsize=unbounded")
//where parent_path = "cmd.exe"
group every 5m by source_ip,source_hostname,source_username,parent_path,client
select collectDistinct(command_line) as commands
where round(hllppcount(command_line)) > 2
select source_ip as entity_sourceIP
select source_hostname as entity_sourceHostname
select source_username as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Subvert Trust Controls" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsRevilKaseyaHashFound

**Summary:** The REvil Ransomware has hit 40 service providers globally due to multiple Kaseya VSA Zero-days. The attack was pushed out via an infected IT Management update from Kaseya.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** edr.all.threats

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from edr.all.threats
where isnotnull(sha256)
select hlurjson("revilKaseya", sha256, eventdate) as isrevilKaseya
where isnotnull(isrevilKaseya)
group every 5m by ip, sha256, mac, file_name, hostname, threat_name, client
where isnotnull(ip)
select str(ip) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip) as enrichStream_entity_sourceIP_ASN
select isp(ip) as enrichStream_entity_sourceIP_ISP
select countrycode(ip) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsRevilKaseyaHashFound") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRevilKaseyaHashFound") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRevilKaseyaHashFound") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRevilKaseyaHashFound") as alertPriority
```

## SecOpsStopWindowsServiceViaNet

**Summary:** This alert detects the use of the net stop command to halt a Windows service, a technique often exploited by attackers to disable security software, backup services, or other critical processes. Stopping essential services can be indicative of malicious activity, especially in ransomware attacks, where disabling these services enables encryption to proceed without interference.

**Description:** detects the use of the net stop command to halt a Windows service.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Service Stop (T1489)

**Tables:** edr.all.processes

**Lookups:** none

```linq
from edr.all.processes
where toktains(command_line, "net stop")
group every 5m by source_ip,source_hostname,source_username,parent_path,client
select collectDistinct(command_line) as commands
where round(hllppcount(command_line)) > 10
select source_ip as entity_sourceIP
select source_hostname as entity_sourceHostname
select source_username as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Impact" as alertMitreTactics
select "Service Stop" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsSuspiciousCmdExecDirChangeUserReconn

**Summary:** This alert detects the execution of suspicious commands involving cmd.exe, commonly used in attack scenarios. The first command (cmd.exe /Q /c cd \) changes the directory to the root of the drive, often used by attackers to navigate critical system areas or prepare for further exploitation. The second command (cmd.exe /Q /c quser) retrieves a list of currently logged-in users and their session information, typically used for reconnaissance to identify high-privileged accounts or active sessions. These commands are indicative of early-stage reconnaissance or lateral movement efforts in potential attacks.

**Description:** Detects the execution of suspicious commands, commonly used in attack scenarios. First command (cmd.exe /Q /c cd \) changes the directory to the root, used by attackers to navigate critical areas.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Subvert Trust Controls (T1553)

**Tables:** edr.all.processes

**Lookups:** none

```linq
from edr.all.processes
where toktains(command_line, "cmd.exe /Q /c cd")
or toktains(command_line, "cmd.exe /Q /c quser")
//where parent_path = "cmd.exe"
group every 5m by source_ip,source_hostname,source_username,parent_path,client
select collectDistinct(command_line) as commands
where round(hllppcount(command_line)) > 1
select source_ip as entity_sourceIP
select source_hostname as entity_sourceHostname
select source_username as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Subvert Trust Controls" as alertMitreTechniques
select 3 as alertPriority
```
