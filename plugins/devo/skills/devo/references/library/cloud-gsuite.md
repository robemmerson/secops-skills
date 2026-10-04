# Detection library: CLOUD/GSUITE

Google Workspace (G Suite) reports and alerts detections. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (11):

- SecOpsCDIocIpSuspiciousGSuiteData
- SecOpsGSuite2SVDisabled
- SecOpsGSuiteAcessTransparencyEvent
- SecOpsGSuiteDriveExternallyShared
- SecOpsGSuiteDriveOpenToPublic
- SecOpsGSuiteDriveSuspiciousSharedFileName
- SecOpsGSuiteExcessiveOAuthPermissionsRequest
- SecOpsGSuiteGovernmentAttackWarning
- SecOpsGSuiteLoginAccountWarning
- SecOpsGSuiteMobileSuspiciousActivity
- SecOpsGSuiteUnauthorizedOAuthApp

## SecOpsCDIocIpSuspiciousGSuiteData

**Summary:** This search looks for Collective Defense matches in GSuite data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** cloud.gsuite.reports

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.gsuite.reports
where ispublic(ip4(ipAddress))
select actor_email as entity_sourceAccount
select ipAddress as entity_sourceIP
group every 15m by entity_sourceAccount, entity_sourceIP, event_name, id_applicationName, client
select hlurjson("CollectiveDefense", entity_sourceIP, eventdate) as cd_hit
where isnotnull(cd_hit)
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDIocIpSuspiciousGSuiteData") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDIocIpSuspiciousGSuiteData") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDIocIpSuspiciousGSuiteData") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDIocIpSuspiciousGSuiteData") as alertPriority
```

## SecOpsGSuite2SVDisabled

**Summary:** An adversary may attempt to disable the second factor authentication in order to weaken an organization’s security controls.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.gsuite.reports.admin

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.gsuite.reports.admin
where eq(event_type, "SECURITY_SETTINGS") and eq(event_name, "ENFORCE_STRONG_AUTHENTICATION") and eq(ev_param_new_value, "false")
select actor_email as entity_destinationAccount
group every 5m by entity_destinationAccount, event_name, client
every 5m
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuite2SVDisabled") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuite2SVDisabled") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuite2SVDisabled") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuite2SVDisabled") as alertPriority
```

## SecOpsGSuiteAcessTransparencyEvent

**Summary:** A Google Access Transparency log event has been generated. Google is accessing your data.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Data from Cloud Storage (T1530)

**Tables:** cloud.gsuite.reports.access_transparency

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.gsuite.reports.access_transparency
where id_applicationName = "access_transparency" and kind = "admin#reports#activity" and event_type = "GSUITE_RESOURCE" and event_name = "ACCESS"
select actor_email as entity_sourceAccount
select ev_param_owner_email as entity_destinationAccount
group every 5m by  entity_sourceAccount, entity_destinationAccount, ev_param_gsuite_product_name, ev_param_resource_name, ev_param_justifications, client
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteAcessTransparencyEvent") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteAcessTransparencyEvent") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteAcessTransparencyEvent") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteAcessTransparencyEvent") as alertPriority
```

## SecOpsGSuiteDriveExternallyShared

**Summary:** Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Web Service (T1567)

**Tables:** cloud.gsuite.reports.drive

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gsuite.reports.drive
where eq(id_applicationName, "drive") and eq(ev_param_visibility, "shared_externally") and eq(event_type, "acl_change")
select actor_email as entity_sourceAccount
select ipAddress as entity_sourceIP
select ev_param_target_user as entity_destinationAccount
group every 5m by entity_sourceAccount, entity_sourceIP, ev_param_visibility, entity_destinationAccount, ev_param_doc_title, event_name, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteDriveExternallyShared") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteDriveExternallyShared") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteDriveExternallyShared") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteDriveExternallyShared") as alertPriority
```

## SecOpsGSuiteDriveOpenToPublic

**Summary:** An attacker may access data objects from improperly secured cloud storage.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Data from Cloud Storage (T1530)

**Tables:** cloud.gsuite.audit.drive

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gsuite.audit.drive
where eq(id_applicationName, "drive") and eq(event_type, "acl_change") and eq(ev_param_visibility, "public_on_the_web")
select actor_email as entity_sourceAccount
select ipAddress as entity_sourceIP
group every 5m by id_applicationName, event_type,event_name, ev_param_visibility, ev_param_doc_title, ev_param_owner, entity_sourceAccount, entity_sourceIP, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteDriveOpenToPublic") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteDriveOpenToPublic") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteDriveOpenToPublic") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteDriveOpenToPublic") as alertPriority
```

## SecOpsGSuiteDriveSuspiciousSharedFileName

**Summary:** Adversaries may send Spear Phishing emails with a malicious attachment or share malicious files by cloud storage services in an attempt to gain access to victim systems.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Phishing (T1566)

**Tables:** cloud.gsuite.reports.drive

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gsuite.reports.drive
select actor_email as entity_sourceAccount
select ipAddress as entity_sourceIP
where eq(id_applicationName, "drive") and eq(ev_param_owner_is_shared_drive, true) and (eq(ev_param_doc_type, "document") or eq(ev_param_doc_type, "pdf") or eq(ev_param_doc_type, "msexcel") or eq(ev_param_doc_type, "msword") or eq(ev_param_doc_type, "spreadsheet") or eq(ev_param_doc_type, "presentation")) and eq(ev_param_owner_is_team_drive, false) and (weaktoktains(ev_param_doc_title, "invoice") or weaktoktains(ev_param_doc_title, "payment") or weaktoktains(ev_param_doc_title, "delivery") or weaktoktains(ev_param_doc_title, "tax") or weaktoktains(ev_param_doc_title, "banking") or weaktoktains(ev_param_doc_title, "irs") or weaktoktains(ev_param_doc_title, "dhl") or weaktoktains(ev_param_doc_title, "past due") or weaktoktains(ev_param_doc_title, "usps") or weaktoktains(ev_param_doc_title, "ups") or weaktoktains(ev_param_doc_title, "fedex") or weaktoktains(ev_param_doc_title, "emergency"))
group every 5m by entity_sourceAccount, entity_sourceIP, event_type, event_name, ev_param_doc_title, ev_param_doc_type, ev_param_owner, ev_param_owner_is_shared_drive, ev_param_visibility, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteDriveSuspiciousSharedFileName") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteDriveSuspiciousSharedFileName") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteDriveSuspiciousSharedFileName") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteDriveSuspiciousSharedFileName") as alertPriority
```

## SecOpsGSuiteExcessiveOAuthPermissionsRequest

**Summary:** An adversary may steal application access tokens as a means of acquiring credentials to access remote systems and resources.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Steal Application Access Token (T1528)

**Tables:** cloud.gsuite.reports.token

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.gsuite.reports.token
where eq(event_name, "authorize")
select event_parameters
select ev_param_app_name as entity_sourceName
select length(split(stringify(jqeval(jqcompile(".event_parameters[4].multiValue"), jsonparse(rawMessage))), "\",\"")) as scopes
where scopes > 15
group every 5m by event_name,entity_sourceName,scopes,event_parameters, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteExcessiveOAuthPermissionsRequest") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteExcessiveOAuthPermissionsRequest") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteExcessiveOAuthPermissionsRequest") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteExcessiveOAuthPermissionsRequest") as alertPriority
```

## SecOpsGSuiteGovernmentAttackWarning

**Summary:** A government-backed attacker could try to steal a password or other personal information of one of your users by sending an email containing a harmful attachment, links to malicious software or to fake websites.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.gsuite.alerts

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.gsuite.alerts
where eq(devo_source_type, "state_sponsored_attack") and eq(type, "Government attack warning")
select str(jqeval(jqcompile(".email"), jsonparse(data))) as entity_sourceAccount
group every 5m by entity_sourceAccount, securityInvestigationToolLink, metadata_severity, metadata_status, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteGovernmentAttackWarning") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteGovernmentAttackWarning") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteGovernmentAttackWarning") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteGovernmentAttackWarning") as alertPriority
```

## SecOpsGSuiteLoginAccountWarning

**Summary:** An attacker could steal the credentials of one of your users.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.gsuite.reports.login

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gsuite.reports.login
where eq(event_type, "account_warning")
select event_type
select event_name
select ipAddress as entity_sourceIP
select ev_param_affected_email_address as entity_sourceAccount
group every 5m by event_type, event_name, entity_sourceIP, entity_sourceAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteLoginAccountWarning") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteLoginAccountWarning") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteLoginAccountWarning") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteLoginAccountWarning") as alertPriority
```

## SecOpsGSuiteMobileSuspiciousActivity

**Summary:** An attacker could steal the credentials or the mobile device of one of your users.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.gsuite.reports.mobile

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.gsuite.reports.mobile
where eq(event_type, "suspicious_activity") and eq(id_applicationName, "mobile")
select event_type
select event_name
select ev_param_device_id
select ev_param_device_model as deviceModel
select ev_param_device_type
select ev_param_serial_number
select actor_email as entity_sourceAccount
group every 5m by event_type, event_name,ev_param_device_id,ev_param_device_model,ev_param_device_type,ev_param_serial_number,entity_sourceAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteMobileSuspiciousActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteMobileSuspiciousActivity") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteMobileSuspiciousActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteMobileSuspiciousActivity") as alertPriority
```

## SecOpsGSuiteUnauthorizedOAuthApp

**Summary:** Detects authentications from OAuth apps outside of your predefined list of approved OAuth applications.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Drive-by Compromise (T1189)

**Tables:** cloud.gsuite.reports.token

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gsuite.reports.token
select ipAddress as entity_sourceIP
select actor_email as entity_sourceAccount
select ev_param_app_name as entity_sourceName
group every 5m by entity_sourceName, entity_sourceIP, entity_sourceAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGSuiteUnauthorizedOAuthApp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGSuiteUnauthorizedOAuthApp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGSuiteUnauthorizedOAuthApp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGSuiteUnauthorizedOAuthApp") as alertPriority
```
