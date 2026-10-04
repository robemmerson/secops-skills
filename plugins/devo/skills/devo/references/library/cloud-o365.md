# Detection library: CLOUD/O365

Microsoft 365 / Office 365 detections: management activity, SIEM agent events and alerts, Exchange. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (47):

- SecOpsActivityAnonymousIPAddressesO365
- SecOpsActivityFromAnonymousIPO365
- SecOpsActivityInfrequentCountryO365
- SecOpsActivityPerformedByTerminatedUserO365
- SecOpsAdministrativeActivityFromNonCorporateIPO365
- SecOpsAnomalousBehaviorDiscoveredUsersO365
- SecOpsArrowAdminFailedLogonO365
- SecOpsAWSInstancesCreatedOrDeletedO365
- SecOpsAzureADThreatIntelligenceO365
- SecOpsCDIocIpSuspiciousO365Data
- SecOpsCloudDiscoveryAnomalyDetectionO365
- SecOpsDataExfiltrationToUnsanctionedAppsO365
- SecOpsGroupMembershipModifiedO365
- SecOpsImpossibleTravelO365
- SecOpsMaliciousOAuthAppConsentO365
- SecOpsMalwareDetectionO365
- SecOpsMFADisabledAlertO365
- SecOpsMultipleDeleteVMO365
- SecOpsMultipleStorageDeletionActivitiesO365
- SecOpsMultipleVMCreationActivitiesO365
- SecOpsO365AddedServicePrincipal
- SecOpsO365BruteForce
- SecOpsO365BypassMFAviaIP
- SecOpsO365DisableMFA
- SecOpsO365ExcessiveAuthFailureAttempts
- SecOpsO365ExcessiveSSOLoginFailures
- SecOpsO365ImpossibleTravel
- SecOpsO365MailboxAuditBypass
- SecOpsO365NewFederatedDomain
- SecOpsO365OneDriveDownload
- SecOpsO365PhishAttempt
- SecOpsO365PSTExportAlert
- SecOpsO365SusMailboxDelegation
- SecOpsO365SuspiciousAdminEmailForwarding
- SecOpsO365UserPasswordChange
- SecOpsO365UserPasswordReset
- SecOpsPermissionsAddedMailboxFolderO365
- SecOpsPhishingEmailRansomDistributionCampaign
- SecOpsRansomwareActivityO365
- SecOpsSuspiciousEmailDeletionActivityO365
- SecOpsSuspiciousInboxForwardingO365
- SecOpsSuspiciousInboxManipulationRuleO365
- SecOpsSuspiciousOAuthAppFileDownloadO365
- SecOpsUnusualAdministrativeActivityO365
- SecOpsUnusualFileDeletionActivityO365
- SecOpsUnusualFileDownloadO365
- SecOpsUnusualImpersonatedActivityO365

## SecOpsActivityAnonymousIPAddressesO365

**Summary:** This alert shows a anonymous IP detection made by MCAS

**Description:** This alert triggers when MCAS policy "Activity from anonymous IP addresses ". Found here: [https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy#activity-from-anonymous-ip-addresses](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy#activity-from-anonymous-ip-addresses)

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Proxy (T1090)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
select rt as event_time,
hostname as host,
signatureID as signature,
msg as event_details,
name as policy_name,
dvc as destination
where signatureID="ALERT_EXTERNAL_IPC" and
(name="Activity from a Tor IP address" or name="Risky sign-in: Anonymous IP address" or toktains(name,"tor"))
group every 5m by event_time, host, signature, policy_name, severity, suser, event_details, destination, client
select ifthenelse(isnull(str(destination)),"No IP Provided",str(destination)) as entity_destIp,
suser as entity_sourceName,
destination as entity_destinationIP
// Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", str(entity_sourceName)) as entity_source_AssetRole
select lu("SecOpsAssetRole", "class", str(entity_destinationIP)) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsActivityAnonymousIPAddressesO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsActivityAnonymousIPAddressesO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsActivityAnonymousIPAddressesO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsActivityAnonymousIPAddressesO365") as alertPriority
```

## SecOpsActivityFromAnonymousIPO365

**Summary:** This policy profiles your environment and triggers alerts when it identifies activity from an IP address that has been identified as an anonymous proxy IP address.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Proxy (T1090)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
where eqic(name, "Activity from a Tor IP address") or eqic(name, "Risky sign-in: Anonymous IP address")
select suser as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsActivityFromAnonymousIPO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsActivityFromAnonymousIPO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsActivityFromAnonymousIPO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsActivityFromAnonymousIPO365") as alertPriority
```

## SecOpsActivityInfrequentCountryO365

**Summary:** This policy profiles your environment and triggers alerts when activity is detected from a location that was not recently or never visited by the user or by any user in the organization.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
where eqic(name, "Activity from infrequent country")
select suser as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsActivityInfrequentCountryO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsActivityInfrequentCountryO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsActivityInfrequentCountryO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsActivityInfrequentCountryO365") as alertPriority
```

## SecOpsActivityPerformedByTerminatedUserO365

**Summary:** Activity performed by terminated user.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Suspicious OAuth app file download activities")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsActivityPerformedByTerminatedUserO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsActivityPerformedByTerminatedUserO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsActivityPerformedByTerminatedUserO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsActivityPerformedByTerminatedUserO365") as alertPriority
```

## SecOpsAdministrativeActivityFromNonCorporateIPO365

**Summary:** Alert when an admin user performs an administrative activity from an IP address that is not included in the corporate IP address range category.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Administrative activity from a non-corporate IP address")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAdministrativeActivityFromNonCorporateIPO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAdministrativeActivityFromNonCorporateIPO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAdministrativeActivityFromNonCorporateIPO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAdministrativeActivityFromNonCorporateIPO365") as alertPriority
```

## SecOpsAnomalousBehaviorDiscoveredUsersO365

**Summary:** Alert when anomalous behavior is detected in discovered users and apps, such as: large amounts of uploaded data compared to other users, large user transactions compared to the user's history.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Data Transfer Size Limits (T1030)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where eqic(name, "Anomalous behavior in discovered users")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAnomalousBehaviorDiscoveredUsersO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAnomalousBehaviorDiscoveredUsersO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAnomalousBehaviorDiscoveredUsersO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAnomalousBehaviorDiscoveredUsersO365") as alertPriority
```

## SecOpsArrowAdminFailedLogonO365

**Summary:** A member of Arrow Admin has failed to log on.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Arrow Admin Failed Logon")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsArrowAdminFailedLogonO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsArrowAdminFailedLogonO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsArrowAdminFailedLogonO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsArrowAdminFailedLogonO365") as alertPriority
```

## SecOpsAWSInstancesCreatedOrDeletedO365

**Summary:** Alert notification for AWS Instances Created or Deleted..

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Hide Artifacts (T1564)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "AWS Instances Created or Deleted")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSInstancesCreatedOrDeletedO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSInstancesCreatedOrDeletedO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSInstancesCreatedOrDeletedO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSInstancesCreatedOrDeletedO365") as alertPriority
```

## SecOpsAzureADThreatIntelligenceO365

**Summary:** This detection indicates user activity consistent with known attack patterns Azured TI.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
select suser as entity_sourceEmail
where eqic(name, "Azure AD threat intelligence")
select lu("SecOpsAssetRole", "class", entity_sourceEmail) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceEmail) as indicator
select lu("mispIndicator", "type", entity_sourceEmail) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceEmail) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureADThreatIntelligenceO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureADThreatIntelligenceO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureADThreatIntelligenceO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureADThreatIntelligenceO365") as alertPriority
```

## SecOpsCDIocIpSuspiciousO365Data

**Summary:** This search looks for Collective Defense matches in o365 data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** cloud.office365.management

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management
where ispublic(ip4(ClientIP))
select ClientIP as entity_sourceIP
select UserId as entity_sourceAccount
group every 15m by entity_sourceIP, entity_sourceAccount, Workload, Operation, client
select hlurjson("CollectiveDefense", entity_sourceIP, eventdate) as cd_hit
where isnotnull(cd_hit)
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDIocIpSuspiciousO365Data") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDIocIpSuspiciousO365Data") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDIocIpSuspiciousO365Data") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDIocIpSuspiciousO365Data") as alertPriority
```

## SecOpsCloudDiscoveryAnomalyDetectionO365

**Summary:** This policy is automatically enabled to alert you when anomalous behavior is detected in discovered users, IP addresses and services, such as: large amounts of uploaded data upload compared to other users, large service transactions compared to the service's history.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Data Transfer Size Limits (T1030)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Cloud Discovery anomaly detection")
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsCloudDiscoveryAnomalyDetectionO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCloudDiscoveryAnomalyDetectionO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCloudDiscoveryAnomalyDetectionO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCloudDiscoveryAnomalyDetectionO365") as alertPriority
```

## SecOpsDataExfiltrationToUnsanctionedAppsO365

**Summary:** This policy is automatically enabled to alert you when a user or IP address is using an app that is not sanctioned to perform an activity that might be an attempt to exfiltrate information from your organization.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Automated Exfiltration (T1020)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Data exfiltration to unsanctioned apps")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsDataExfiltrationToUnsanctionedAppsO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsDataExfiltrationToUnsanctionedAppsO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsDataExfiltrationToUnsanctionedAppsO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsDataExfiltrationToUnsanctionedAppsO365") as alertPriority
```

## SecOpsGroupMembershipModifiedO365

**Summary:** Group Membership Modified.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Group Membership Modified")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGroupMembershipModifiedO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGroupMembershipModifiedO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGroupMembershipModifiedO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGroupMembershipModifiedO365") as alertPriority
```

## SecOpsImpossibleTravelO365

**Summary:** This policy triggers when activities are detected from the same user in different locations within a time period that is shorter than the expected travel time between the two locations. This could indicate that a different user is using the same credentials.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
where eqic(name, "Impossible travel activity")
select suser as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsImpossibleTravelO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsImpossibleTravelO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsImpossibleTravelO365") as alertPriority
select lu("SecOpsAlertDescription", "alertType", "SecOpsImpossibleTravelO365") as alertType
```

## SecOpsMaliciousOAuthAppConsentO365

**Summary:** This policy uses Microsoft Threat Intelligence to scan OAuth apps connected to your environment and triggers an alert when it detects a potentially malicious app that has been authorized.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Abuse Elevation Control Mechanism (T1548)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Malicious OAuth app consent")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMaliciousOAuthAppConsentO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMaliciousOAuthAppConsentO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMaliciousOAuthAppConsentO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMaliciousOAuthAppConsentO365") as alertPriority
```

## SecOpsMalwareDetectionO365

**Summary:** This detection scans files in your cloud apps and runs suspicious files through Microsoft’s threat intelligence engine to determine whether they are associated with known malware.

**MITRE:** Tactics: Execution (TA0002) | Techniques: User Execution (T1204)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weakhas(name, "Malware ")
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMalwareDetectionO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMalwareDetectionO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMalwareDetectionO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMalwareDetectionO365") as alertPriority
```

## SecOpsMFADisabledAlertO365

**Summary:** Alerts when mfa is disabled for an account.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
where eqic(name, "MFA Disabled Alert")
select suser as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsMFADisabledAlertO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMFADisabledAlertO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMFADisabledAlertO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMFADisabledAlertO365") as alertPriority
```

## SecOpsMultipleDeleteVMO365

**Summary:** This policy profiles your environment and triggers alerts when users perform multiple delete VM activities in a single session with respect to the baseline learned, which could indicate an attempted breach.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
where eqic(name, "Multiple delete VM activities")
select suser as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsMultipleDeleteVMO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMultipleDeleteVMO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMultipleDeleteVMO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMultipleDeleteVMO365") as alertPriority
```

## SecOpsMultipleStorageDeletionActivitiesO365

**Summary:** This policy profiles your environment and triggers alerts when users perform multiple storage deletion or DB deletion activities in a single session with respect to the baseline learned, which could indicate an attempted breach.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
where eqic(name, "Multiple VM creation activities")
select suser as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsMultipleStorageDeletionActivitiesO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMultipleStorageDeletionActivitiesO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMultipleStorageDeletionActivitiesO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMultipleStorageDeletionActivitiesO365") as alertPriority
```

## SecOpsMultipleVMCreationActivitiesO365

**Summary:** This policy profiles your environment and triggers alerts when users perform multiple create VM activities in a single session with respect to the baseline learned.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Software Deployment Tools (T1072)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
where eqic(name, "Multiple VM creation activities")
select suser as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsMultipleVMCreationActivitiesO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMultipleVMCreationActivitiesO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMultipleVMCreationActivitiesO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMultipleVMCreationActivitiesO365") as alertPriority
```

## SecOpsO365AddedServicePrincipal

**Summary:** This activity is not necessarily malicious. However, these events need to be followed closely, as they may indicate federated credential abuse or a backdoor via federated identities.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** cloud.office365.management.azureactivedirectory

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management.azureactivedirectory
where eq(Workload, "AzureActiveDirectory") and eq(Operation, "Add service principal credentials.") and eq(ResultStatus, "Success")
select UserId as entity_destinationAccount
group every 5m by Workload, Operation, ResultStatus, entity_destinationAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365AddedServicePrincipal") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365AddedServicePrincipal") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365AddedServicePrincipal") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365AddedServicePrincipal") as alertPriority
```

## SecOpsO365BruteForce

**Summary:** Identifies a password spraying attempt.

**Description:** Detects actions that are similar to successful brute force attacks A user has failed repeatedly, then succeeded in logging in.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** cloud.office365

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator

```linq
from cloud.office365
where (eq(Operation,"UserLoginFailed") and toktains(rawMessage,"InvalidUserNameOrPassword",true,true)) or eq(Operation,"UserLoggedIn")
select ClientIP as initial_entity_sourceIP, countrycode(ip4(initial_entity_sourceIP)) as country,UserId as entity_sourceName,ifthenelse(eq(Operation,"UserLoginFailed"), 1 , 0) as failed_attempt,ifthenelse(eq(Operation,"UserLoggedIn"), 1 , 0) as successful_attempt,ObjectId as entity_destinationAccount
group every 5m by entity_sourceName,country,entity_destinationAccount, client
select sum(failed_attempt) as failed_attempts, sum(successful_attempt) as successful_attempts,last(initial_entity_sourceIP) as entity_sourceIP
where failed_attempts > 3
where successful_attempts > 0
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365BruteForce") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365BruteForce") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365BruteForce") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365BruteForce") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
`lu/mispIndicator/type`(entity_sourceIP) as misp_indicator_type,
`lu/mispIndicator/event_id`(entity_sourceIP) as misp_indicator_event_id
```

## SecOpsO365BypassMFAviaIP

**Summary:** This activity is not necessarily malicious. However, these events need to be followed closely. Attackers are often known to use this technique so that they can bypass the MFA system.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.office365.management

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management
where eq(Workload, "AzureActiveDirectory") and eq(Operation, "Set Company Information.") and eq(ResultStatus, "Success")
select str(jqeval(jqcompile(".ModifiedProperties[0].Name"), jsonparse(rawMessage))) as CustomModifiedProperties
where eq(CustomModifiedProperties, "StrongAuthenticationPolicy")
select str(jqeval(jqcompile(".ModifiedProperties[0].OldValue"), jsonparse(rawMessage))) as oldValue
select str(jqeval(jqcompile(".ModifiedProperties[0].NewValue"), jsonparse(rawMessage))) as newValue
select jqeval(jqcompile(".[0].RelyingPartyStrongAuthenticationPolicies[0].Rules[0].SelectionConditions[0].Values"), jsonparse(oldValue)) as oldAllowedIPlist
select jqeval(jqcompile(".[0].RelyingPartyStrongAuthenticationPolicies[0].Rules[0].SelectionConditions[0].Values"), jsonparse(newValue)) as newAllowedIPlist
select UserId as entity_destinationAccount
select length(split(stringify(oldAllowedIPlist), "\",\"")) as numOldAllowedIPs
select length(split(stringify(newAllowedIPlist), "\",\"")) as numNewAllowedIPs
where numOldAllowedIPs < numNewAllowedIPs
group every 5m by entity_destinationAccount, oldAllowedIPlist, numOldAllowedIPs, newAllowedIPlist, numNewAllowedIPs, client
every 5m
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365BypassMFAviaIP") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365BypassMFAviaIP") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365BypassMFAviaIP") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365BypassMFAviaIP") as alertPriority
```

## SecOpsO365DisableMFA

**Summary:** Adversaries may modify authentication mechanisms and processes to access user credentials, bypass authentication mechanisms or enable otherwise unwarranted access to accounts.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Authentication Process (T1556)

**Tables:** cloud.office365.management.azureactivedirectory

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management.azureactivedirectory
where eq(Operation, "Disable Strong Authentication.")
select UserId as entity_sourceAccount
select ObjectId as entity_destinationAccount
group every 5m by Operation, ResultStatus, entity_sourceAccount, entity_destinationAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365DisableMFA") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365DisableMFA") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365DisableMFA") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365DisableMFA") as alertPriority
```

## SecOpsO365ExcessiveAuthFailureAttempts

**Summary:** Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** cloud.office365.management.azureactivedirectory

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.management.azureactivedirectory
where eq(Operation, "UserLoginFailed")
group every 5m by Operation, UserId, client
every 5m
select count() as failedAttempts
where failedAttempts > 10
select last(ClientIP) as entity_sourceIP
select UserId as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365ExcessiveAuthFailureAttempts") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365ExcessiveAuthFailureAttempts") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365ExcessiveAuthFailureAttempts") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365ExcessiveAuthFailureAttempts") as alertPriority
```

## SecOpsO365ExcessiveSSOLoginFailures

**Summary:** Adversaries may use brute-force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** cloud.office365.management.azureactivedirectory

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.management.azureactivedirectory
where eq(Workload, "AzureActiveDirectory") and eq(LogonError, "SsoArtifactInvalidOrExpired")
group every 5m by Workload, UserId, LogonError, client
every 5m
select last(ClientIP) as entity_sourceIP
select UserId as entity_sourceAccount
select last(UserAgent) as lastUsed_UserAgent
select count() as numSSOLoginFailures
where numSSOLoginFailures > 5
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365ExcessiveSSOLoginFailures") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365ExcessiveSSOLoginFailures") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365ExcessiveSSOLoginFailures") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365ExcessiveSSOLoginFailures") as alertPriority
```

## SecOpsO365ImpossibleTravel

**Summary:** This detection will identify users that have had successful logins in two geographically different locations within an hour.

**Description:** Detects users who have authenticated to O365 from more than 1 country in 1 hour.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: XSL Script Processing (T1220)

**Tables:** cloud.office365

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator

```linq
from cloud.office365
where Operation = "UserLoginFailed" or Operation = "UserLoggedIn"
select ip4(ClientIP) as initial_entity_sourceIP, countrycode(initial_entity_sourceIP) as country, UserId as entity_sourceName
group every 1h by entity_sourceName,Workload, OrganizationId, client
select str(last(initial_entity_sourceIP)) as entity_sourceIP
select int(hllppcount(country)) as location_count
where round(hllppcount(country)) > 1
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365ImpossibleTravel") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365ImpossibleTravel") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365ImpossibleTravel") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365ImpossibleTravel") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsO365MailboxAuditBypass

**Summary:** The mailbox audit is responsible for logging specified mailbox events. Attackers may attempt to bypass this mechanism to conceal actions taken.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.office365.management.exchange

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management.exchange
where eq(Operation, "Set-MailboxAuditBypassAssociation") and eq(Workload, "Exchange")
select UserId as entity_sourceAccount
select Parameters_Identity as entity_destinationAccount
select OriginatingServer as entity_sourceHostname
group every 5m by Workload, entity_sourceHostname, entity_sourceAccount, Operation, entity_destinationAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365MailboxAuditBypass") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365MailboxAuditBypass") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365MailboxAuditBypass") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365MailboxAuditBypass") as alertPriority
```

## SecOpsO365NewFederatedDomain

**Summary:** The addition of a new Federated domain may be a normal activity. However, these events need to be followed closely, as they may indicate federated credential abuse or a backdoor via federated identities.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** cloud.office365.management.exchange

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management.exchange
where eq(Workload, "Exchange") and eq(Operation, "Add-FederatedDomain")
select OriginatingServer as entity_sourceHostname
select UserId as entity_sourceAccount
select str(jqeval(jqcompile(".Parameters[1].Value"), jsonparse(rawMessage))) as newFederatedDomain
group every 5m by Workload, Operation, entity_sourceHostname, OrganizationName, newFederatedDomain, entity_sourceAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365NewFederatedDomain") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365NewFederatedDomain") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365NewFederatedDomain") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365NewFederatedDomain") as alertPriority
```

## SecOpsO365OneDriveDownload

**Summary:** Detects high volume of OneDrive activity

**Description:** Detects user activity in OneDrive

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Unsecured Credentials (T1552)

**Tables:** cloud.office365.management.onedrive

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator

```linq
from cloud.office365.management.onedrive
where UserId != "app@sharepoint"
group every 5m by UserId, FileSizeBytes, Operation, ClientIP, SourceFileName, client
every 5m
select count(UserId) as count_of_entries
select FileSizeBytes \ 1024 as FileSizeKiloBytes
select FileSizeKiloBytes \ 1024 as FileSizeMegaBytes
select FileSizeMegaBytes \ 1024 as FileSizeGigaBytes
//This is an arbitrary number and should be adjusted to whatever
//makes the most sense to your organization
where FileSizeKiloBytes >= 12
select sum(FileSizeBytes) as total_bytes_transferred
select total_bytes_transferred \ 1024 as TransKiloBytes
select TransKiloBytes \ 1024 as TransMegaBytes
select TransMegaBytes \ 1024 as TransGigaBytes
//Entity Creation
select split(UserId,"@",0) as entity_sourceName,
ClientIP as entity_sourceIP,
`lu/SecOpsAssetRole/class`(entity_sourceIP) as entity_sourceIP_AssetRole, // Get asset role from SecOpsRole Lookup
`lu/SecOpsAssetRole/class`(entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365OneDriveDownload") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365OneDriveDownload") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365OneDriveDownload") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365OneDriveDownload") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
`lu/mispIndicator/type`(entity_sourceIP) as misp_indicator_type,
`lu/mispIndicator/event_id`(entity_sourceIP) as misp_indicator_event_id
```

## SecOpsO365PhishAttempt

**Summary:** Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Phishing (T1566)

**Tables:** cloud.office365.management.securitycompliancecenter

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management.securitycompliancecenter
where eq(Operation, "UserSubmission")
select UserId as entity_sourceAccount
group every 5m by entity_sourceAccount, Recipients, P1Sender, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365PhishAttempt") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365PhishAttempt") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365PhishAttempt") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365PhishAttempt") as alertPriority
```

## SecOpsO365PSTExportAlert

**Summary:** This detection is triggered when a user has performed an Ediscovery or exported a pst file with sensitive information.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Email Collection (T1114)

**Tables:** cloud.office365.management

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management
where eq(Name, "eDiscovery search started or exported")
where eq(ResultStatus,"Succeeded")
select ObjectId as entity_destinationAccount
select UserId as entity_sourceName
group every 5m by Operation, entity_sourceName, entity_destinationAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole// Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365PSTExportAlert") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365PSTExportAlert") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365PSTExportAlert") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365PSTExportAlert") as alertPriority
```

## SecOpsO365SusMailboxDelegation

**Summary:** Adversaries may use the compromised account to send messages to other accounts in the network of the target organization while creating inbox rules.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365.management.exchange

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management.exchange
select UserId
select ClientIP as entity_sourceIP
select Parameters_Identity as entity_destinationAccount
select Parameters_User as entity_sourceAccount
select Parameters_AccessRights
where eq(Workload, "Exchange") and eq(Operation, "Add-MailboxPermission") and not eq(UserId, "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)")
group every 5m by UserId, entity_sourceIP, entity_destinationAccount, entity_sourceAccount, Parameters_AccessRights, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365SusMailboxDelegation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365SusMailboxDelegation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365SusMailboxDelegation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365SusMailboxDelegation") as alertPriority
```

## SecOpsO365SuspiciousAdminEmailForwarding

**Summary:** This detection is triggered when a user has configured several forwarding rules to the same email address.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Email Collection (T1114)

**Tables:** cloud.office365.management

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.management
where eq(Operation, "Set-Mailbox")
where toktains(Parameters_Name_str,"ForwardingAddress",true,true)
select UserId as entity_sourceName
select ClientIP as entity_sourceIP
select split(split(split(Parameters_Raw,"ForwardingAddress")[1],": ")[1],"\"")[1] as ForwardingAddress
where not eq(ForwardingAddress,"")
group every 5m by ForwardingAddress,entity_sourceIP,entity_sourceName, client
every 5m
select count(ObjectId) as Identity_count
where Identity_count >1
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole// Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365SuspiciousAdminEmailForwarding") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365SuspiciousAdminEmailForwarding") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365SuspiciousAdminEmailForwarding") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365SuspiciousAdminEmailForwarding") as alertPriority
```

## SecOpsO365UserPasswordChange

**Summary:** Detection based on password changes that occur within an hour.

**Description:** Detects actions to change user passwords in O365.

**MITRE:** Tactics: Credential Access (TA0006), Persistence (TA0003) | Techniques: Steal Application Access Token (T1528), Steal Web Session Cookie (T1539), Valid Accounts (T1078)

**Tables:** cloud.office365

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator

```linq
from cloud.office365
where Operation = "Change user password."
select ip4(ClientIP) as entity_sourceIP, UserId as entity_sourceName
select ObjectId as entity_destinationName
group every 1h by entity_sourceName, entity_sourceIP, Workload, OrganizationId, ResultStatus, entity_destinationName, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365UserPasswordChange") as alertType
//<filtering_section>
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365UserPasswordChange") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365UserPasswordChange") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365UserPasswordChange") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsO365UserPasswordReset

**Summary:** This alert looks for users that have reset their o365 account passwords.

**Description:** Detects actions to reset user passwords in O365.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator

```linq
from cloud.office365
where Operation = "Reset user password."
select ip4(ClientIP) as entity_sourceIP, UserId as entity_sourceName
select ObjectId as entity_destinationName
group every 1h by entity_sourceName, entity_sourceIP, Workload, OrganizationId, ResultStatus, entity_destinationName, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsO365UserPasswordReset") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsO365UserPasswordReset") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsO365UserPasswordReset") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsO365UserPasswordReset") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsPermissionsAddedMailboxFolderO365

**Summary:** Permissions added to Mailbox or Mailbox Folder.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Mailbox Permissions Added")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPermissionsAddedMailboxFolderO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPermissionsAddedMailboxFolderO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPermissionsAddedMailboxFolderO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPermissionsAddedMailboxFolderO365") as alertPriority
```

## SecOpsPhishingEmailRansomDistributionCampaign

**Summary:** This alert detects phishing emails that may be used as part of ransomware distribution campaigns, specifically targeting initial infection vectors for attacks like those orchestrated by the TA505 threat actor group. TA505 is known for using phishing emails to distribute malware, such as the Get2 downloader and SDBbot RAT, which then facilitate the delivery of ransomware payloads.

**Description:** Detects phishing emails potentially linked to ransomware distribution campaigns, such as those by TA505, which leverage malicious links or attachments to gain initial access.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Phishing (T1566)

**Tables:** cloud.office365.messagetracing

**Lookups:** none

```linq
from cloud.office365.messagetracing
group every 5m by Subject, RecipientAddress, FromIP, ToIP, Status, SenderAddress,client
where toktains(Subject, "Urgent") or
toktains(Subject, "Immediate action required") or
toktains(Subject, "Your account will be suspended") or
toktains(Subject, "Payment overdue") or
toktains(Subject, "Final notice") or
toktains(Subject, "Invoice") or
toktains(Subject, "Payment") or
toktains(Subject, "Refund") or
toktains(Subject, "Account locked") or
toktains(Subject, "Verify your account") or
toktains(Subject, "Password reset") or
toktains(Subject, "Unusual login activity") or
toktains(Subject, "Suspicious activity detected") or
toktains(Subject, "Click here to verify") or
toktains(Subject, "Open the attached file") or
toktains(Subject, "Download the attachment") or
toktains(Subject, "Login attempt failed") or
toktains(Subject, "Your account is compromised") or
toktains(Subject, "Security alert") or
toktains(Subject, "Dear customer")
where RecipientAddress not in ["email@company.com"] //Avoid False Positives
select RecipientAddress as entity_destinationEmail
select FromIP as entity_sourceIP
select ToIP as entity_destinationIP
select SenderAddress as entity_sourceEmail
//<filtering_section>
select "Detection" as alertType
select "Initial Access" as alertMitreTactics
select "Exploit Public-Facing Application" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsRansomwareActivityO365

**Summary:** Ransomware Activity Detected - If Cloud App Security identifies, for example, a high rate of file uploads or file deletion activities it may represent an adverse encryption process.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Ransomware activity")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsRansomwareActivityO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRansomwareActivityO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRansomwareActivityO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRansomwareActivityO365") as alertPriority
```

## SecOpsSuspiciousEmailDeletionActivityO365

**Summary:** This policy profiles your environment and triggers alerts when a user performs suspicious email deletion activities in a single session, which could indicate an attempted breach.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** cloud.office365.siem_agent_alert

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_alert
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, client
every 5m
where eqic(name, "Suspicious email deletion activity")
select suser as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousEmailDeletionActivityO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousEmailDeletionActivityO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousEmailDeletionActivityO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousEmailDeletionActivityO365") as alertPriority
```

## SecOpsSuspiciousInboxForwardingO365

**Summary:** Suspicious inbox forwarding.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Automated Exfiltration (T1020)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Suspicious inbox forwarding")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousInboxForwardingO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousInboxForwardingO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousInboxForwardingO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousInboxForwardingO365") as alertPriority
```

## SecOpsSuspiciousInboxManipulationRuleO365

**Summary:** A suspicious inbox rule was set on a user's inbox. This may indicate that the user account is compromised, and that the mailbox is being used to distribute spam and malware in your organization.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Suspicious inbox manipulation rule")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousInboxManipulationRuleO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousInboxManipulationRuleO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousInboxManipulationRuleO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousInboxManipulationRuleO365") as alertPriority
```

## SecOpsSuspiciousOAuthAppFileDownloadO365

**Summary:** This policy scans the OAuth apps connected to your environment and triggers an alert when an app downloads multiple files from Microsoft SharePoint or Microsoft OneDrive in a manner that is uncommon for the user.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Data Transfer Size Limits (T1030)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Suspicious OAuth app file download activities")
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousOAuthAppFileDownloadO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousOAuthAppFileDownloadO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousOAuthAppFileDownloadO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousOAuthAppFileDownloadO365") as alertPriority
```

## SecOpsUnusualAdministrativeActivityO365

**Summary:** This policy profiles your environment and triggers alerts when users perform multiple administrative activities in a single session with respect to the baseline learned.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where eqic(name, "MFA Disabled Alert")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsUnusualAdministrativeActivityO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsUnusualAdministrativeActivityO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsUnusualAdministrativeActivityO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsUnusualAdministrativeActivityO365") as alertPriority
```

## SecOpsUnusualFileDeletionActivityO365

**Summary:** This policy profiles your environment and triggers alerts when users perform multiple file deletion activities in a single session with respect to the baseline learned.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where weaktoktains(signatureID, "ALERT")
where eqic(name, "Unusual file deletion activity (by user)")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsUnusualFileDeletionActivityO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsUnusualFileDeletionActivityO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsUnusualFileDeletionActivityO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsUnusualFileDeletionActivityO365") as alertPriority
```

## SecOpsUnusualFileDownloadO365

**Summary:** This policy profiles your environment and triggers alerts when users perform multiple file download activities in a single session with respect to the baseline learned.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Data Transfer Size Limits (T1030)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where eqic(name, "Unusual file download (by user)")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsUnusualFileDownloadO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsUnusualFileDownloadO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsUnusualFileDownloadO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsUnusualFileDownloadO365") as alertPriority
```

## SecOpsUnusualImpersonatedActivityO365

**Summary:** This policy profiles your environment and triggers alerts when users perform multiple impersonated activities in a single session with respect to the baseline learned.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Automated Exfiltration (T1020)

**Tables:** cloud.office365.siem_agent_event

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.office365.siem_agent_event
group every 5m by rt, hostname, signatureID, name, severity, suser, msg, dvc, client
every 5m
where eqic(name, "Unusual impersonated activity (by user)")
select suser as entity_sourceEmail
select str(dvc) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(dvc) as enrichStream_entity_sourceIP_ASN
select isp(dvc) as enrichStream_entity_sourceIP_ISP
select countrycode(dvc) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsUnusualImpersonatedActivityO365") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsUnusualImpersonatedActivityO365") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsUnusualImpersonatedActivityO365") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsUnusualImpersonatedActivityO365") as alertPriority
```
