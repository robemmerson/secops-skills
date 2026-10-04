# Detection library: AUTH

Authentication detections: password spray, failed/simultaneous logins, lockouts, MFA fraud (auth.all, Office 365, Ping). Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (13):

- SecOpsAuthPasswordSprayHost
- SecOpsAuthPasswordSprayIp
- SecOpsCDPossibleIocIpFoundInAuthData
- SecOpsLoginFailAttempts
- SecOpsLoginFailCombinedSuccessed
- SecOpsO365AuthExcessiveFailedLoginsSingleSource
- SecOpsO365AuthExcessiveFailedLoginsUserAuthAll
- SecOpsPingEmailNotificationFraud
- SecOpsPingMFGDeviceJailbrokenOrRooted
- SecOpsPingPushNotificationFraud
- SecOpsSimultaneouslyLoginbyIP
- SecOpsSimultaneouslyLoginbyUser
- SecOpsWinLockoutsEndpoint-AuthAll

## SecOpsAuthPasswordSprayHost

**Summary:** Detects failed login attempts from a single host to two or more accounts in ten minutes. The account number threshold and time threshold should be adjusted to suit organizational needs.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from auth.all
where weaktoktains(action, "FAILED"), isnotnull(source_hostname)
group every 10m by source_hostname, source_ipv4, client
select round(hllppcount(user)) as n_user_accounts, collectdistinct(user) as user_accounts,
count() as n_failed_attempts, first(eventdate) as first_seen, last(eventdate) as last_seen
//Alert Tuning Section
where n_user_accounts >= 2 //Adjust as necessary
select str(source_ipv4) as entity_sourceIP
select str(source_hostname) as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Context Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsAuthPasswordSprayHost") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAuthPasswordSprayHost") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAuthPasswordSprayHost") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAuthPasswordSprayHost") as alertPriority
```

## SecOpsAuthPasswordSprayIp

**Summary:** Detects when a single IP fails to log in to two or more accounts in ten minutes. The account number threshold and time threshold should be adjusted to suit organizational needs.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from auth.all
where weaktoktains(action, "FAILED"), isnotnull(source_ipv4)
group every 10m by source_ipv4, source_hostname, client
select round(hllppcount(user)) as n_user_accounts, collectdistinct(user) as user_accounts,
count() as n_failed_attempts, first(eventdate) as first_seen, last(eventdate) as last_seen
where n_user_accounts >= 2 // Adjust threshold as necessary
select str(source_ipv4) as entity_sourceIP
select source_hostname as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsAuthPasswordSprayIp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAuthPasswordSprayIp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAuthPasswordSprayIp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAuthPasswordSprayIp") as alertPriority
```

## SecOpsCDPossibleIocIpFoundInAuthData

**Summary:** This search looks for Collective Defense matches in authentication data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from auth.all
where ispublic(source_ipv4)
group every 15m by source_ipv4, source, source_hostname, user, client
select `lu/CollectiveDefense`(source_ipv4) as cd_hit
where isnotnull(cd_hit)
select str(source_ipv4) as entity_sourceIP,
user as entity_sourceAccount,
source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCollectiveDefenseHuntAuthSrcIp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCollectiveDefenseHuntAuthSrcIp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCollectiveDefenseHuntAuthSrcIp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCollectiveDefenseHuntAuthSrcIp") as alertPriority
```

## SecOpsLoginFailAttempts

**Summary:** A large number of unsuccessful access attempts in a system must be monitored, it can be part of a brute force attack.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from auth.all
where isnotnull(source_ipv4)
where isnotnull(user)
where weakhas(action, "fail")
where not endswith(user, "$")
group every 30m by source_ipv4, user, client
every 1h
select nnlast(action) as action_nnlast
select nnlast(source) as source_nnlast,
count() as count
where count > 10
select str(source_ipv4) as entity_sourceIP
select user as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsLoginFailAttempts") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLoginFailAttempts") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLoginFailAttempts") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLoginFailAttempts") as alertPriority
```

## SecOpsLoginFailCombinedSuccessed

**Summary:** It could be considered an indicator of compromise when after a raised number of failed access attempts there is a valid access.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from auth.all
where isnotnull(source_ipv4)
select lower(action) as laction
where laction = "login" or laction = "failed"
select decode(laction, "failed", 1) as failed_attempt
group every 5m by source_ipv4, source_hostname, client
every 15m
select hllppcount(laction) as action
select count(failed_attempt) as action_count
where  int(action) > 1 and action_count >= 5
select str(source_ipv4) as entity_sourceIP
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsLoginFailCombinedSuccessed") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLoginFailCombinedSuccessed") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLoginFailCombinedSuccessed") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLoginFailCombinedSuccessed") as alertPriority
```

## SecOpsO365AuthExcessiveFailedLoginsSingleSource

**Summary:** Detects multiple failed authentications from a single IP in Office365.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from auth.all
where source = "office365-management"
select jsonparse(result) as result_json,str(jqeval(jqcompile(".Operation"), result_json) ) as result_Operation
where result_Operation = "UserLoginFailed"
select mm2city(source_ipv4) as city,countrycode(source_ipv4) as country
group every 5m by user, source_hostname, source_ipv4, city, country, client
select count() as failed_attempts
where failed_attempts > 3
select first(eventdate) as firstseen
select last (eventdate) as lastseen
//Entity Mapping Section
select str(source_ipv4) as entity_sourceIP
select user as entity_sourceAccount
select str(source_hostname) as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365AuthExcessiveFailedLoginsSingleSource") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365AuthExcessiveFailedLoginsSingleSource") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365AuthExcessiveFailedLoginsSingleSource") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365AuthExcessiveFailedLoginsSingleSource") as alertPriority
```

## SecOpsO365AuthExcessiveFailedLoginsUserAuthAll

**Summary:** Detects when a user account has multiple failed Office 365 authentication attempts.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from auth.all
where source = "office365-management"
select jsonparse(result) as result_json,str(jqeval(jqcompile(".Operation"), result_json) ) as result_Operation
where result_Operation = "UserLoginFailed"
group every 5m by user, source_hostname, source_ipv4, client
select count() as failed_attempts
where failed_attempts >= 3
select first(eventdate) as firstseen
select last(eventdate) as lastseen
//Entity Mapping Section
select user as entity_sourceAccount
select str(source_ipv4) as entity_sourceIP
select str(source_hostname) as entity_sourceHostname
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365AuthExcessiveFailedLoginsUserAuthAll") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365AuthExcessiveFailedLoginsUserAuthAll") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365AuthExcessiveFailedLoginsUserAuthAll") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365AuthExcessiveFailedLoginsUserAuthAll") as alertPriority
```

## SecOpsPingEmailNotificationFraud

**Summary:** Fraudulent activity detected through email notifications.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1566)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole

```linq
from auth.all
where weakhas(result, "Fraud Reported (email notification)")
group every 15m by source, source_hostname, user, client
select user as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Initial Access" as alertMitreTactics
select "Phishing" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsPingMFGDeviceJailbrokenOrRooted

**Summary:** Device identified as jailbroken or rooted, posing security risks.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Hijack Execution Flow (T1574)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole

```linq
from auth.all
where eq(peek(result, "Device Rooted or Jailbroken: (.+)", 1),"true")
group every 15m by source, user, client
select user as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Privilege Escalation" as alertMitreTactics
select "Hijack Execution Flow" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsPingPushNotificationFraud

**Summary:** Fraudulent activity detected through push notifications.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1566)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole

```linq
from auth.all
where weakhas(result, "SSO Auth Cancel (Report Fraud)")
group every 15m by source, source_hostname, user, client
select user as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Initial Access" as alertMitreTactics
select "Phishing" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsSimultaneouslyLoginbyIP

**Summary:** In order to prevent possible misuse of access credentials, it's important to control simultaneous users used on systems from the same IP addresses.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from auth.all
where isnotnull(source_ipv4)
group every 10m by source_ipv4, client
every 10m
select hllppcount(user) as user
where user >= 2
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsSimultaneouslyLoginbyIP") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSimultaneouslyLoginbyIP") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSimultaneouslyLoginbyIP") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSimultaneouslyLoginbyIP") as alertPriority
```

## SecOpsSimultaneouslyLoginbyUser

**Summary:** In order to prevent possible misuses of access credentials, it is important to control simultaneous access by user from different systems.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from auth.all
where action = "LOGIN"
where not user = "SYSTEM",
not user = "LOCAL SERVICE",
not user = "NETWORK SERVICE",
not user = "SQLTELEMETRY"
select split(split(message, "<Data Name='LogonType'>", 1), "</Data>", 0) as LogonType
where isnotnull(LogonType)
where LogonType = "null" or LogonType ="2" // Filtering Logon type Network when windows
where not endswith(user, "$")
group every 1h by user, client
select int(hllppcount(machine)) as servers
where servers > 2
select nnlast(LogonType) as LastLogonType
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsSimultaneouslyLoginbyUser") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSimultaneouslyLoginbyUser") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSimultaneouslyLoginbyUser") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSimultaneouslyLoginbyUser") as alertPriority
```

## SecOpsWinLockoutsEndpoint-AuthAll

**Summary:** Detects when a single Windows endpoint has multiple Windows account lockouts within a short period.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** auth.all

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from auth.all
where action="LOCKED"
where startswith(source, "box.win")
// Uncomment below line if you wish to exclude local logins from alert criteria
// where not(endswith(user, "$"))
group every 1h by machine, domain, client
select round(hllppcount(user)) as user_count
, collectdistinct(user) as users
, first(eventdate) as first_seen
, last(eventdate) as last_seen
where user_count >= 2
select machine as entity_destinationIP, domain as entity_destinationDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationDomain) as entity_destinationDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinLockoutsEndpoint-AuthAll") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinLockoutsEndpoint-AuthAll") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinLockoutsEndpoint-AuthAll") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinLockoutsEndpoint-AuthAll") as alertPriority
```
