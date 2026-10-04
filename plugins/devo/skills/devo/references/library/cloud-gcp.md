# Detection library: CLOUD/GCP

Google Cloud Platform audit detections: IAM, storage buckets, firewall, compute. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (40):

- SecOpsGCPAuditListQueues
- SecOpsGCPAuditUnauthorizedAPICalls
- SecOpsGCPDetectAccountsWithHighRiskRolesByProject
- SecOpsGCPGCEFirewallRuleCreation
- SecOpsGCPGCEFirewallRuleDeletion
- SecOpsGCPGCEFirewallRuleModification
- SecOpsGCPGCPloitExploitationFrameworkActivity
- SecOpsGCPGCSBucketEnumerated
- SecOpsGCPGCSBucketModified
- SecOpsGCPGoogleDriveSharedPublicly
- SecOpsGCPIAMCustomRoleCreation
- SecOpsGCPIAMCustomRoleDeletion
- SecOpsGCPIAMServiceAccountCreated
- SecOpsGCPIAMServiceAccountDeletion
- SecOpsGCPIAMServiceAccountDisabled
- SecOpsGCPIAMServiceAccountKeyCreation
- SecOpsGCPIAMServiceAccountKeyDeletion
- SecOpsGCPKMSKeyDestroy
- SecOpsGCPKMSKeyEnabledOrDisabled
- SecOpsGCPKubernetesClusterPodScanDetection
- SecOpsGCPKubernetesSensitiveObjectAccess
- SecOpsGCPLoggingBucketDeletion
- SecOpsGCPLoggingSinkDeletion
- SecOpsGCPLoggingSinkModification
- SecOpsGCPNewPublicStorageBucket
- SecOpsGCPPortScan
- SecOpsGCPPortSweep
- SecOpsGCPPossibleReconnaissanceActivity
- SecOpsGCPPrivateCloudNetworkDeletion
- SecOpsGCPPrivateCloudRouteCreation
- SecOpsGCPPrivateCloudRouteDeletion
- SecOpsGCPPubSubSubscriptionCreation
- SecOpsGCPPubSubSubscriptionDeletion
- SecOpsGCPPubSubTopicCreation
- SecOpsGCPPubSubTopicDeletion
- SecOpsGCPSecretsManagerHighActivity
- SecOpsGCPSQLDatabaseModification
- SecOpsGCPStorageBucketDeletion
- SecOpsGCPStorageBucketPermissionsModification
- SecOpsLog4ShellVulnerabilityCloudGCP

## SecOpsGCPAuditListQueues

**Summary:** Accessing list queues is one of the first steps taken by an attacker in order to enumerate a Google Cloud Platform project.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Cloud Infrastructure Discovery (T1580), Data from Cloud Storage (T1530)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, mispIndicator, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName -> "ListQueues"
group every 5m by protoPayload_methodName,protoPayload_requestMetadata_callerIp,host2,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id, hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select host2 as entity_destinationHostname
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPAuditListQueues") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPAuditListQueues") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPAuditListQueues") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPAuditListQueues") as alertPriority
```

## SecOpsGCPAuditUnauthorizedAPICalls

**Summary:** An attacker could be performing reconnaissance on a GCP project trying to enumerate permissions.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Cloud Infrastructure Discovery (T1580)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_status_code = 7
select lower(protoPayload_authenticationInfo_principalEmail) as lowerPrincipalEmail
group every 5m by resource_labels_project_id,lowerPrincipalEmail, hostname, client
every 5m
select count() as count
where count > 10
select lowerPrincipalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPAuditUnauthorizedAPICalls") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPAuditUnauthorizedAPICalls") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPAuditUnauthorizedAPICalls") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPAuditUnauthorizedAPICalls") as alertPriority
```

## SecOpsGCPDetectAccountsWithHighRiskRolesByProject

**Summary:** A high risk role have been assigned to a user, this could indicate that a malicious actor could be trying to escalate privileges within project.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "SetIamPolicy"
select jqeval(jqcompile(".policyDelta.bindingDeltas"), jsonparse(protoPayload_serviceData)) as binding_deltas
group every 5m by binding_deltas,protoPayload_methodName,protoPayload_requestMetadata_callerIp,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id, hostname, client
every 5m
select ["roles/owner","roles/editor","roles/iam.serviceAccountUser","roles/iam.serviceAccountAdmin","roles/iam.serviceAccountTokenCreator","roles/dataflow.developer","roles/dataflow.admin","roles/composer.admin","roles/dataproc.admin","roles/dataproc.editor"] as privileged_roles
select "ADD" as add_action
select str(jqeval(jqcompile(".[0].action"),binding_deltas)) as action1
select str(jqeval(jqcompile(".[0].role"),binding_deltas)) as role1
select str(jqeval(jqcompile(".[1].action"),binding_deltas)) as action2
select str(jqeval(jqcompile(".[1].role"),binding_deltas)) as role2
select str(jqeval(jqcompile(".[2].action"),binding_deltas)) as action3
select str(jqeval(jqcompile(".[2].role"),binding_deltas)) as role3
select str(jqeval(jqcompile(".[3].action"),binding_deltas)) as action4
select str(jqeval(jqcompile(".[3].role"),binding_deltas)) as role4
select str(jqeval(jqcompile(".[4].action"),binding_deltas)) as action5
select str(jqeval(jqcompile(".[4].role"),binding_deltas)) as role5
where (role1 in privileged_roles and action1 = add_action) or (role2 in privileged_roles and action2 = add_action) or (role3 in privileged_roles and action3 = add_action) or (role4 in privileged_roles and action4 = add_action) or (role5 in privileged_roles and action5 = add_action)
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPDetectAccountsWithHighRiskRolesByProject") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPDetectAccountsWithHighRiskRolesByProject") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPDetectAccountsWithHighRiskRolesByProject") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPDetectAccountsWithHighRiskRolesByProject") as alertPriority
```

## SecOpsGCPGCEFirewallRuleCreation

**Summary:** An attacker may have tried to bypass perimeter security by creating a firewall rule.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select resource_labels_project_id
select protoPayload_resourceName
select protoPayload_methodName as methodName
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
where resource_type = "gce_firewall_rule" and has(methodName,".compute.firewalls.insert")
group every 5m by resource_type, resource_labels_project_id, protoPayload_resourceName, methodName, entity_sourceIP, entity_sourceAccount, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPGCEFirewallRuleCreation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPGCEFirewallRuleCreation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPGCEFirewallRuleCreation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPGCEFirewallRuleCreation") as alertPriority
```

## SecOpsGCPGCEFirewallRuleDeletion

**Summary:** An attacker may have tried to bypass perimeter security by deleting a firewall rule.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select resource_labels_project_id
select protoPayload_resourceName
select protoPayload_methodName as methodName
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
where resource_type = "gce_firewall_rule" and has(methodName,".compute.firewalls.delete")
group every 5m by resource_type, resource_labels_project_id, protoPayload_resourceName, methodName, entity_sourceIP, entity_sourceAccount, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPGCEFirewallRuleDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPGCEFirewallRuleDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPGCEFirewallRuleDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPGCEFirewallRuleDeletion") as alertPriority
```

## SecOpsGCPGCEFirewallRuleModification

**Summary:** An attacker may have tried to bypass perimeter security by modifying a firewall rule.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select resource_labels_project_id
select protoPayload_resourceName
select protoPayload_methodName as methodName
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
where resource_type = "gce_firewall_rule" and has(methodName,".compute.firewalls.patch")
group every 5m by resource_type, resource_labels_project_id, protoPayload_resourceName, methodName, entity_sourceIP, entity_sourceAccount, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPGCEFirewallRuleModification") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPGCEFirewallRuleModification") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPGCEFirewallRuleModification") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPGCEFirewallRuleModification") as alertPriority
```

## SecOpsGCPGCPloitExploitationFrameworkActivity

**Summary:** GCPPloit is a framework to audit GCP accounts, this could be used by attackers in order to find security issues.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select str(jqeval(jqcompile(".function.timeout"), jsonparse(protoPayload_request))) as requestTimeout
where requestTimeout = "539s"
group every 5m by protoPayload_requestMetadata_callerIp,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id, hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPGCPloitExploitationFrameworkActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPGCPloitExploitationFrameworkActivity") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPGCPloitExploitationFrameworkActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPGCPloitExploitationFrameworkActivity") as alertPriority
```

## SecOpsGCPGCSBucketEnumerated

**Summary:** An attacker could be enumerating GCS buckets to gain more information regarding the Google Cloud project.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Cloud Service Discovery (T1526)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, mispIndicator, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "storage.buckets.list"
where protoPayload_authenticationInfo_principalEmail -> ".iam.gserviceaccount.com"
group every 5m by protoPayload_methodName,protoPayload_requestMetadata_callerIp,host2,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id,hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select host2 as entity_destinationHostname
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPGCSBucketEnumerated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPGCSBucketEnumerated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPGCSBucketEnumerated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPGCSBucketEnumerated") as alertPriority
```

## SecOpsGCPGCSBucketModified

**Summary:** An attacker could be modifying permissions, or accessibility, over a bucket.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, mispIndicator, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "storage.buckets.update"
select str(jqeval(jqcompile(".resource.labels.bucket_name"), jsonparse(rawMessage))) as bucketName
group every 5m by protoPayload_methodName,protoPayload_requestMetadata_callerIp,host2,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id,bucketName, hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select host2 as entity_destinationHostname
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPGCSBucketModified") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPGCSBucketModified") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPGCSBucketModified") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPGCSBucketModified") as alertPriority
```

## SecOpsGCPGoogleDriveSharedPublicly

**Summary:** An attacker could be modifying permissions, or accessibility, over a bucket to make it public, or creating a public one.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Data from Cloud Storage (T1530)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, mispIndicator, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "storage.buckets.create" or protoPayload_methodName = "storage.setIamPermissions"
select str(jqeval(jqcompile(".resource.labels.bucket_name"), jsonparse(rawMessage))) as bucketName
group every 5m by protoPayload_methodName,protoPayload_requestMetadata_callerIp,host2,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id,bucketName,rawMessage, hostname, client
every 5m
select jqeval(jqcompile(".protoPayload.serviceData.policyDelta.bindingDeltas"), jsonparse(rawMessage)) as bindingDeltas
select str(jqeval(jqcompile(".[0].member"),bindingDeltas)) as member1
select str(jqeval(jqcompile(".[1].member"),bindingDeltas)) as member2
select str(jqeval(jqcompile(".[2].member"),bindingDeltas)) as member3
select str(jqeval(jqcompile(".[3].member"),bindingDeltas)) as member4
select str(jqeval(jqcompile(".[4].member"),bindingDeltas)) as member5
select str(jqeval(jqcompile(".[0].action"),bindingDeltas)) as action1
select str(jqeval(jqcompile(".[1].action"),bindingDeltas)) as action2
select str(jqeval(jqcompile(".[2].action"),bindingDeltas)) as action3
select str(jqeval(jqcompile(".[3].action"),bindingDeltas)) as action4
select str(jqeval(jqcompile(".[4].action"),bindingDeltas)) as action5
where (member1 = "allUsers" and action1 = "ADD") or (member2 = "allUsers" and action2 = "ADD") or (member3 = "allUsers" and action3 = "ADD") or (member4 = "allUsers" and action4 = "ADD") or (member5 = "allUsers" and action5 = "ADD")
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select host2 as entity_destinationHostname
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPGoogleDriveSharedPublicly") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPGoogleDriveSharedPublicly") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPGoogleDriveSharedPublicly") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPGoogleDriveSharedPublicly") as alertPriority
```

## SecOpsGCPIAMCustomRoleCreation

**Summary:** An attacker may have created a new Role to gain persistence.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select resource_labels_project_id as project
select protoPayload_resourceName as newRole
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
where resource_type = "iam_role" and matches(methodName, re("google.iam.admin.v[1-9].CreateRole")) and granted = true
group every 5m by resource_type, project, newRole, methodName, entity_sourceIP, entity_sourceAccount, granted, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPIAMCustomRoleCreation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPIAMCustomRoleCreation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPIAMCustomRoleCreation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPIAMCustomRoleCreation") as alertPriority
```

## SecOpsGCPIAMCustomRoleDeletion

**Summary:** An adversary could delete an IAM Custom Role to disrupt the availability of system and network resources by inhibiting access to accounts used by legitimate users.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Account Access Removal (T1531)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select resource_labels_project_id as project
select protoPayload_resourceName as deletedRole
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
where resource_type = "iam_role" and matches(methodName, re("google.iam.admin.v[1-9].DeleteRole")) and granted = true
group every 5m by resource_type, project, deletedRole, methodName, entity_sourceIP, entity_sourceAccount, granted, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPIAMCustomRoleDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPIAMCustomRoleDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPIAMCustomRoleDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPIAMCustomRoleDeletion") as alertPriority
```

## SecOpsGCPIAMServiceAccountCreated

**Summary:** An attacker could be creating a service account to gain persistence on the project.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, mispIndicator, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "google.iam.admin.v1.CreateServiceAccount"
where resource_type = "service_account"
select str(jqeval(jqcompile(".resource.email_id"), jsonparse(rawMessage))) as emailId
select str(jqeval(jqcompile(".description"), jsonparse(protoPayload_response))) as description
group every 5m by protoPayload_methodName,protoPayload_requestMetadata_callerIp,host2,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id,emailId,description, hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select host2 as entity_destinationHostname
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select emailId as entity_destinationAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_destinationHostname) as indicator
select lu("mispIndicator", "type", entity_destinationHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_destinationHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPIAMServiceAccountCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPIAMServiceAccountCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPIAMServiceAccountCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPIAMServiceAccountCreated") as alertPriority
```

## SecOpsGCPIAMServiceAccountDeletion

**Summary:** An attacker could delete a Service Account to interrupt availability of systems and network resources by inhibiting access to accounts utilized by legitimate users.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Account Access Removal (T1531)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as entity_destinationAccount
where resource_type = "service_account" and matches(methodName, re("google.iam.admin.v[1-9].DeleteServiceAccount$")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, entity_destinationAccount, hostname, client
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPIAMServiceAccountDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPIAMServiceAccountDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPIAMServiceAccountDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPIAMServiceAccountDeletion") as alertPriority
```

## SecOpsGCPIAMServiceAccountDisabled

**Summary:** An adversary could disable a IAM Service Account to manipulate the service account and maintain access to the systems.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Account Access Removal (T1531)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as deletedServiceAccount
where resource_type = "service_account" and matches(methodName, re("google.iam.admin.v[1-9].DisableServiceAccount$")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, deletedServiceAccount, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPIAMServiceAccountDisabled") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPIAMServiceAccountDisabled") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPIAMServiceAccountDisabled") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPIAMServiceAccountDisabled") as alertPriority
```

## SecOpsGCPIAMServiceAccountKeyCreation

**Summary:** An adversary could create a IAM Service Account Key to manipulate a service account and maintain access to the systems.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as newServiceKey
where resource_type = "service_account" and matches(methodName, re("google.iam.admin.v[1-9].CreateServiceAccountKey")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, newServiceKey, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPIAMServiceAccountKeyCreation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPIAMServiceAccountKeyCreation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPIAMServiceAccountKeyCreation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPIAMServiceAccountKeyCreation") as alertPriority
```

## SecOpsGCPIAMServiceAccountKeyDeletion

**Summary:** An adversary could delete a IAM Service Account Key to manipulate the service account and maintain access to the systems.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as deletedServiceKey
where resource_type = "service_account" and matches(methodName, re("google.iam.admin.v[1-9].DeleteServiceAccountKey")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, deletedServiceKey, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPIAMServiceAccountKeyDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPIAMServiceAccountKeyDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPIAMServiceAccountKeyDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPIAMServiceAccountKeyDeletion") as alertPriority
```

## SecOpsGCPKMSKeyDestroy

**Summary:** Destroying a crypto key is an unusual event that should be checked and considered in context with other suspicious events occurring at the same GCP project.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "DestroyCryptoKeyVersion"
group every 5m by protoPayload_methodName,protoPayload_requestMetadata_callerIp,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id,resource_labels, hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPKMSKeyDestroy") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPKMSKeyDestroy") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPKMSKeyDestroy") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPKMSKeyDestroy") as alertPriority
```

## SecOpsGCPKMSKeyEnabledOrDisabled

**Summary:** Updating the state of a crypto key is an unusual event that should be checked and considered in context with other suspicious events occurring in the same GCP project.

**Description:** Updating state the of a crypto key is an unusual event that should be checked and considered in context with other suspicious events occurring in the same GCP project.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "UpdateCryptoKeyVersion"
select str(jqeval(jqcompile(".cryptoKeyVersion.state"), jsonparse(protoPayload_request))) as keyState
where keyState in ["ENABLED","DISABLED"]
group every 5m by keyState,protoPayload_methodName,protoPayload_requestMetadata_callerIp,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id,resource_labels, hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPKMSKeyEnabledOrDisabled") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPKMSKeyEnabledOrDisabled") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPKMSKeyEnabledOrDisabled") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPKMSKeyEnabledOrDisabled") as alertPriority
```

## SecOpsGCPKubernetesClusterPodScanDetection

**Summary:** An adversary may attempt to enumerate the cloud services running on GCP Kubernetes cluster’s pods

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Cloud Service Discovery (T1526)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select split(stringify(jqeval(jqcompile(".jsonPayload.request.headers"), jsonparse(rawMessage))),",",10) as entity_sourceIP
select int(jqeval(jqcompile(".jsonPayload.statusCode"), jsonparse(rawMessage))) as response_statusCode
group every 5m by entity_sourceIP, resource_type, response_statusCode, hostname, client
every 5m
where resource_type = "k8s_container" and response_statusCode = 401 and count() > 10
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPKubernetesClusterPodScanDetection") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPKubernetesClusterPodScanDetection") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPKubernetesClusterPodScanDetection") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPKubernetesClusterPodScanDetection") as alertPriority
```

## SecOpsGCPKubernetesSensitiveObjectAccess

**Summary:** An attacker could gain access to a Secret or ConfigMap.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Data from Cloud Storage (T1530)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_resourceName as entity_fileName
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_methodName as methodName
where weakhas(methodName, "secrets.get") or  weakhas(methodName, "configmaps.get")
group every 5m by entity_sourceAccount,entity_fileName,entity_sourceIP,methodName, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPKubernetesSensitiveObjectAccess") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPKubernetesSensitiveObjectAccess") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPKubernetesSensitiveObjectAccess") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPKubernetesSensitiveObjectAccess") as alertPriority
```

## SecOpsGCPLoggingBucketDeletion

**Summary:** An adversary could remove a Google Cloud Logging Bucket to impair event aggregation and analysis mechanisms.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as deletedBucket
where resource_type = "audited_resource" and matches(methodName, re("google.logging.v[1-9].ConfigServiceV[1-9].DeleteBucket")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, deletedBucket, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPLoggingBucketDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPLoggingBucketDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPLoggingBucketDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPLoggingBucketDeletion") as alertPriority
```

## SecOpsGCPLoggingSinkDeletion

**Summary:** An attacker could be deleting a logging sink to avoid detection.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "google.logging.v2.ConfigServiceV2.DeleteSink"
group every 5m by protoPayload_resourceName,protoPayload_requestMetadata_callerIp,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id, hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPLoggingSinkDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPLoggingSinkDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPLoggingSinkDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPLoggingSinkDeletion") as alertPriority
```

## SecOpsGCPLoggingSinkModification

**Summary:** An attacker could be modifying a logging sink to avoid detection, or redirect logs to a different destination.

**Description:** An attacker could be modifying a logging sink in order to avoid detection, or redirect logs to a different destination.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Transfer Data to Cloud Account (T1537)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName = "google.logging.v2.ConfigServiceV2.UpdateSink"
group every 5m by protoPayload_resourceName,protoPayload_requestMetadata_callerIp,severity,protoPayload_authenticationInfo_principalEmail,resource_labels_project_id,protoPayload_request, hostname, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPLoggingSinkModification") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPLoggingSinkModification") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPLoggingSinkModification") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPLoggingSinkModification") as alertPriority
```

## SecOpsGCPNewPublicStorageBucket

**Summary:** An attacker could intend to collect data, making public the data from a GCP Storage Bucket.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Data from Cloud Storage (T1530)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select protoPayload_requestMetadata_requestAttributes_time as eventTime
select resource_type
select protoPayload_resourceName as entity_sourceHostname
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_methodName as methodName
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_resourceLocation_currentLocations as bucketLocations
select str(jqeval(jqcompile(".protoPayload.serviceData.policyDelta.bindingDeltas[0].action"), jsonparse(rawMessage))) as action
select str(jqeval(jqcompile(".protoPayload.serviceData.policyDelta.bindingDeltas[0].role"), jsonparse(rawMessage))) as role
select str(jqeval(jqcompile(".protoPayload.serviceData.policyDelta.bindingDeltas[0].member"), jsonparse(rawMessage))) as member
where resource_type = "gcs_bucket" and methodName = "storage.setIamPermissions" and action = "ADD" and member = "allUsers"
group every 5m by eventTime,resource_type, entity_sourceHostname, entity_sourceIP, methodName, entity_sourceAccount, bucketLocations, action, role, member, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPNewPublicStorageBucket") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPNewPublicStorageBucket") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPNewPublicStorageBucket") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPNewPublicStorageBucket") as alertPriority
```

## SecOpsGCPPortScan

**Summary:** An attacker could be performing reconnaissance against a network.

**MITRE:** Tactics: Reconnaissance (TA0043), Discovery (TA0007) | Techniques: Network Service Discovery (T1046), Cloud Infrastructure Discovery (T1580), Active Scanning (T1595)

**Tables:** cloud.gcp.compute.firewall

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp.compute.firewall
where ispublic(jsonPayload__connection__src_ip) and isprivate(jsonPayload__connection__dest_ip)
group every 5m by jsonPayload__connection__dest_ip,jsonPayload__connection__src_ip,resource__labels__project_id,resource__labels__location, hostname, client
every 5m
select collectDistinct(jsonPayload__connection__dest_port) as destPortList
where length(destPortList) > 5
select jsonPayload__connection__src_ip as entity_sourceIP
select jsonPayload__connection__dest_ip as entity_destinationIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPortScan") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPortScan") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPortScan") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPortScan") as alertPriority
```

## SecOpsGCPPortSweep

**Summary:** An attacker could be performing reconnaissance against a network.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046), Cloud Infrastructure Discovery (T1580)

**Tables:** cloud.gcp.compute.firewall

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp.compute.firewall
where ispublic(jsonPayload__connection__src_ip) and isprivate(jsonPayload__connection__dest_ip)
group every 5m by jsonPayload__connection__dest_port,jsonPayload__connection__src_ip,resource__labels__project_id,resource__labels__location, hostname, client
every 5m
select collectDistinct(jsonPayload__connection__dest_ip) as destIpList
where length(destIpList) > 5
select jsonPayload__connection__src_ip as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPortSweep") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPortSweep") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPortSweep") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPortSweep") as alertPriority
```

## SecOpsGCPPossibleReconnaissanceActivity

**Summary:** An attacker could intend to enumerate the environment.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Cloud Infrastructure Discovery (T1580)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select str(jqeval(jqcompile(".protoPayload.authenticationInfo.principalEmail"), jsonparse(rawMessage))) as entity_sourceAccount
select str(jqeval(jqcompile(".protoPayload.authorizationInfo[0].resourceAttributes.name"), jsonparse(rawMessage))) as entity_resource
select str(jqeval(jqcompile(".protoPayload.serviceName"), jsonparse(rawMessage))) as serviceName
select str(jqeval(jqcompile(".protoPayload.requestMetadata.callerIp"), jsonparse(rawMessage))) as entity_sourceIP
select str(jqeval(jqcompile(".protoPayload.methodName"), jsonparse(rawMessage))) as api_method
select split(api_method, ".", 3) as method
where (weakhas(api_method, ".get") or  weakhas(api_method, ".list")) and weakhas(serviceName,"googleapis.com")
group every 5m by entity_sourceAccount, hostname, client
every 5m
where round(hllppcount(method))>1
select last(entity_resource) as resource, last(api_method) as api_method, last(entity_sourceIP) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPossibleReconnaissanceActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPossibleReconnaissanceActivity") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPossibleReconnaissanceActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPossibleReconnaissanceActivity") as alertPriority
```

## SecOpsGCPPrivateCloudNetworkDeletion

**Summary:** An attacker could delete a Virtual Private Cloud Network (VPC) to interrupt availability of systems and network resources.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Service Stop (T1489)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as deletedVPC
where resource_type = "gce_network" and matches(methodName, re("v[1-9].compute.networks.delete")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, deletedVPC, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPrivateCloudNetworkDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPrivateCloudNetworkDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPrivateCloudNetworkDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPrivateCloudNetworkDeletion") as alertPriority
```

## SecOpsGCPPrivateCloudRouteCreation

**Summary:** An attacker may have created a new Route to bypass restrictions on traffic routing segregating trusted and untrusted networks.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Network Boundary Bridging (T1599)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select protoPayload_resourceName as newRoute
where resource_type = "gce_route" and weakhas(methodName, "compute.routes.insert")
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, newRoute, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPrivateCloudRouteCreation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPrivateCloudRouteCreation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPrivateCloudRouteCreation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPrivateCloudRouteCreation") as alertPriority
```

## SecOpsGCPPrivateCloudRouteDeletion

**Summary:** An attacker may have deleted a VPC Route to interrupt the availability of systems and network resources.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Service Stop (T1489)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as deletedRoute
where resource_type = "gce_route" and granted = true and matches(methodName, re("v[1-9].compute.routes.delete"))
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, deletedRoute, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPrivateCloudRouteDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPrivateCloudRouteDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPrivateCloudRouteDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPrivateCloudRouteDeletion") as alertPriority
```

## SecOpsGCPPubSubSubscriptionCreation

**Summary:** An adversary could create a Google Cloud Pub/Sub Subscription to collect data.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Data from Cloud Storage (T1530)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as newSubscription
where resource_type = "pubsub_subscription" and matches(methodName, re("google.pubsub.v[1-9].Subscriber.CreateSubscription")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, newSubscription, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPubSubSubscriptionCreation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPubSubSubscriptionCreation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPubSubSubscriptionCreation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPubSubSubscriptionCreation") as alertPriority
```

## SecOpsGCPPubSubSubscriptionDeletion

**Summary:** An adversary could delete a Google Cloud Pub/Sub subscription to impair event aggregation and analysis mechanisms.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as deletedSubscription
where resource_type = "pubsub_subscription" and matches(methodName, re("google.pubsub.v[1-9].Subscriber.DeleteSubscription")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, deletedSubscription, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPubSubSubscriptionDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPubSubSubscriptionDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPubSubSubscriptionDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPubSubSubscriptionDeletion") as alertPriority
```

## SecOpsGCPPubSubTopicCreation

**Summary:** An adversary could create a Google Cloud Pub/Sub topic to collect data.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Data from Cloud Storage (T1530)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as newTopic
where resource_type = "pubsub_topic" and matches(methodName, re("google.pubsub.v[1-9].Publisher.CreateTopic")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, newTopic, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPubSubTopicCreation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPubSubTopicCreation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPubSubTopicCreation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPubSubTopicCreation") as alertPriority
```

## SecOpsGCPPubSubTopicDeletion

**Summary:** An adversary could delete a Google Cloud Pub/Sub topic to impair event aggregation and analysis mechanisms.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as deletedTopic
where resource_type = "pubsub_topic" and matches(methodName, re("google.pubsub.v[1-9].Publisher.DeleteTopic")) and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, deletedTopic, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPPubSubTopicDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPPubSubTopicDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPPubSubTopicDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPPubSubTopicDeletion") as alertPriority
```

## SecOpsGCPSecretsManagerHighActivity

**Summary:** An attacker could be attempting to access, or modify, the Secret Manager service

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Unsecured Credentials (T1552)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
where protoPayload_methodName -> "SecretManagerService"
group every 5m by resource_labels_project_id,protoPayload_requestMetadata_callerIp,protoPayload_authenticationInfo_principalEmail, hostname, client
every 5m
select count() as count
where count > 10
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPSecretsManagerHighActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPSecretsManagerHighActivity") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPSecretsManagerHighActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPSecretsManagerHighActivity") as alertPriority
```

## SecOpsGCPSQLDatabaseModification

**Summary:** An attacker could intend to modify, or gain, privileges on a Cloud SQL Database.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Manipulation (T1565)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select str(jqeval(jqcompile(".protoPayload.serviceName"), jsonparse(rawMessage))) as serviceName
select str(jqeval(jqcompile(".protoPayload.resourceName"), jsonparse(rawMessage))) as entity_sourceHostname
select str(jqeval(jqcompile(".protoPayload.request.ip"), jsonparse(rawMessage))) as entity_sourceIP
select ifthenelse(isnull( str(jqeval(jqcompile(".protoPayload.request.cmd"), jsonparse(rawMessage)))),str(jqeval(jqcompile(".protoPayload.request.command"), jsonparse(rawMessage))),str(jqeval(jqcompile(".protoPayload.request.cmd"), jsonparse(rawMessage)))) as command
select ifthenelse(isnull( str(jqeval(jqcompile(".protoPayload.request.query"), jsonparse(rawMessage)))),str(jqeval(jqcompile(".protoPayload.request.statement"), jsonparse(rawMessage))),str(jqeval(jqcompile(".protoPayload.request.query"), jsonparse(rawMessage)))) as complete_query
select ifthenelse(isnull( str(jqeval(jqcompile(".protoPayload.request.privUser"), jsonparse(rawMessage)))),str(jqeval(jqcompile(".protoPayload.request.user"), jsonparse(rawMessage))),str(jqeval(jqcompile(".protoPayload.request.privUser"), jsonparse(rawMessage)))) as entity_sourceAccount
select ifthenelse(isnull( str(jqeval(jqcompile(".protoPayload.request.objects[0].db"), jsonparse(rawMessage)))),str(jqeval(jqcompile(".protoPayload.request.database"), jsonparse(rawMessage))),str(jqeval(jqcompile(".protoPayload.request.objects[0].db"), jsonparse(rawMessage)))) as db_name
where serviceName = "cloudsql.googleapis.com" and (weakhas(command, "create") or weakhas(command, "alter") or weakhas(command, "drop") or weakhas(command, "grant") or weakhas(command, "revoke"))
group every 5m by entity_sourceHostname,entity_sourceIP,command,complete_query,entity_sourceAccount,db_name, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPSQLDatabaseModification") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPSQLDatabaseModification") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPSQLDatabaseModification") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPSQLDatabaseModification") as alertPriority
```

## SecOpsGCPStorageBucketDeletion

**Summary:** An adversary could delete a Google Cloud Storage Bucket to destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as deletedBucket
where resource_type = "gcs_bucket" and methodName = "storage.buckets.delete" and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, deletedBucket, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPStorageBucketDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPStorageBucketDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPStorageBucketDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPStorageBucketDeletion") as alertPriority
```

## SecOpsGCPStorageBucketPermissionsModification

**Summary:** An adversary may modify Storage Bucket Permissions to evade access control lists (ACLs) and access protected files.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: File and Directory Permissions Modification (T1222)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.gcp
select resource_type
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select protoPayload_authenticationInfo_principalEmail as entity_sourceAccount
select protoPayload_methodName as methodName
select bool(jqeval(jqcompile(".protoPayload.authorizationInfo[0].granted"), jsonparse(rawMessage))) as granted
select protoPayload_resourceName as targetBucket
where resource_type = "gcs_bucket" and methodName = "storage.setIamPermissions" and granted = true
group every 5m by resource_type, entity_sourceIP, entity_sourceAccount, methodName, granted, targetBucket, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGCPStorageBucketPermissionsModification") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGCPStorageBucketPermissionsModification") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGCPStorageBucketPermissionsModification") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGCPStorageBucketPermissionsModification") as alertPriority
```

## SecOpsLog4ShellVulnerabilityCloudGCP

**Summary:** Alert that checks attempts to exploit CVE-2021-44228 known as Log4shell. The query looks for payload patterns associated with this vulnerability in the log raw message. This would include payloads included in the URL, user-agent header, referrer header, or POST and PUT HTTP bodies. [WARNING] This alert detects attack patterns and can generate a high volume of events due to the number of scanners currently testing systems on the Internet. It is therefore likely to need some kind of tunning.

**Description:** Checks for attempts of exploiting CVE-2021-44228 as known as Log4shell.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** cloud.gcp

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from cloud.gcp
where `in`("/$%7bjndi:","%24%7bjndi:","%24%7Bjndi:","%2524%257Bjndi","%2F%252524%25257Bjndi%3A","${::-j}${","${::-l}${::-d}${::-a}${::-p}","${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}:/","${${::-j}ndi:rmi:/","${${env:","${${lower:${lower:jndi}}:${lower:rmi}:/","${${lower:j}${lower:n}${lower:d}i:${lower:rmi}:","${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}:/","${${lower:jndi}:${lower:rmi}:/","${base64:JHtqbmRp","${jndi:${lower:","${jndi:${lower:l}${lower:d}a${lower:p}://","${jndi:corba","${jndi:dns:/","${jndi:http:/","${jndi:iiop","${jndi:ldap://","${jndi:ldap://${env:","${jndi:ldap:/","${jndi:ldaps:/","${jndi:nds","${jndi:nis","${jndi:rmi:/","$%7Bjndi:","$%7blower:","$%7Blower:","$%7bupper:","$%7Bupper:","${${::-${::-$${::-j}}}",raw)
group every 5m by raw,protoPayload_requestMetadata_callerSuppliedUserAgent,protoPayload_requestMetadata_callerIp,hostname,protoPayload_methodName,account, client
every 5m
select protoPayload_requestMetadata_callerIp as entity_sourceIP
select hostname as entity_sourceHostname
select account as entity_destinationAccount
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceHostname) as indicator
select lu("mispIndicator", "type", entity_sourceHostname) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceHostname) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnerabilityCloudGCP") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnerabilityCloudGCP") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnerabilityCloudGCP") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnerabilityCloudGCP") as alertPriority
```
