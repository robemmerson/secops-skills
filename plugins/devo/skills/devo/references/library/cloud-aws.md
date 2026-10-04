# Detection library: CLOUD/AWS

AWS CloudTrail / VPC flow detections: IAM, keys, KMS, S3, logging tampering, console logins. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (56):

- SecOpsAwsCloudTrailReconEvent
- SecOpsAWSCreateAccessKey
- SecOpsAWSCreateloginprofile
- SecOpsAWSCreatePolicyVersionToAllowAllResources
- SecOpsAwsDbSnapshotCreated
- SecOpsAWSDetectStsAssumeRoleAbuse
- SecOpsAWSDetectUsersCreatingKeysWithEncryptPolicyWithoutMFA
- SecOpsAwsEc2KeyAction
- SecOpsAwsECRContainerScanningFindingsCritical
- SecOpsAWSECRContainerScanningFindingsLowInformationalUnknown
- SecOpsAwsECRContainerUploadOutsideBusinessHours
- SecOpsAwsEcrImageUpload
- SecOpsAWSExcessiveSecurityScanning
- SecOpsAwsGetSecretFromNonAmazonIp
- SecOpsAWSIAMAssumeRolePolicyBruteForce
- SecOpsAWSIAMCreateUserActionObserved
- SecOpsAWSIAMDeletePolicy
- SecOpsAWSIAMPolicyAppliedToGroup
- SecOpsAWSIAMPolicyAppliedToRole
- SecOpsAWSIAMPolicyAppliedToUser
- SecOpsAWSIamSuccessfulGroupDeletion
- SecOpsAWSIAMUserGeneratingAccessDeniedErrorsAcrossMultipleActions
- SecOpsAwsKmsKeyDeletion
- SecOpsAwsKmsSensitiveActivity
- SecOpsAWSLoggingConfigurationChangeObservedDeleteTrail
- SecOpsAWSLoggingConfigurationChangeObservedRemoveTags
- SecOpsAWSLoggingConfigurationChangeObservedStopLogging
- SecOpsAwsMasterKeyDisabledOrDeletion
- SecOpsAWSMultipleFailedConsoleLogins
- SecOpsAWSMultipleFailedConsoleLoginsFromASourceIP
- SecOpsAWSNetworkAccessControlListDeleted
- SecOpsAWSNewUserPoolClientCreated
- SecOpsAWSOpenNetworkACLs
- SecOpsAWSOpsWorksDescribePermissionsEvent
- SecOpsAwsPermanentKeyCreation
- SecOpsAWSPermissionsBoundaryLiftedtoRole
- SecOpsAWSPermissionsBoundaryLiftedtoUser
- SecOpsAWSPermissionsBoundaryModifiedToRole
- SecOpsAWSPermissionsBoundaryModifiedToUser
- SecOpsAWSPublicS3BucketExposed
- SecOpsAwsRoleCreated
- SecOpsAWSRootLogin
- SecOpsAwsS3EncryptWithKMSKey
- SecOpsAWSSamlAccess
- SecOpsAWSSecretsManagerSensitiveAdminActionObserved
- SecOpsAWSSetdefaultpolicyversion
- SecOpsAwsSqsListQueues
- SecOpsAwsStsPossibleSessionTokenAbuse
- SecOpsAwsUnapprovedUserApiActivity
- SecOpsAWSUpdateloginprofile
- SecOpsAwsUpdateSAMLProvider
- SecOpsAWSUserSuccessfulLoginWithoutMFA
- SecOpsAwsVpcLargeFile
- SecOpsAwsVpcLargeOutboundTrafficBlock
- SecOpsCDIocIpSuspiciousAWSData
- SecOpsLog4ShellVulnerabilityCloudAWS

## SecOpsAwsCloudTrailReconEvent

**Summary:** Analytical detection of a reconnaissance type behavior from AWS CloudTrail logs.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Cloud Infrastructure Discovery (T1580)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator, SecOpsLocation

```linq
from cloud.aws.cloudtrail
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
group every 5m by entity_sourceIP, entity_sourceName,requestParameters, client
select int(hllppcount(eventName)) as unique_eventNames
select int(hllppcount(eventSource)) as unique_eventSource
select int(hllppcount(awsRegion)) as unique_awsRegions
select count() as count
//TUNE
where unique_eventSource > 1
where count > 10
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsCloudTrailReconEvent") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsCloudTrailReconEvent") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsCloudTrailReconEvent") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsCloudTrailReconEvent") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAWSCreateAccessKey

**Summary:** This search looks for AWS CloudTrail events where a user, who already has permission to create access keys, makes an API call to create access keys for a second user.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"CreateAccessKey") and not eq(userAgent,"console.amazonaws.com")
group every 5m by eventName,requestParameters_userName,responseElements_accessKey_status,responseElements_accessKey_createDate,userIdentity_arn,userIdentity_accountId,userIdentity_userName,sourceIPAddress, client
every 5m
select str(sourceIPAddress) as entity_sourceIP
select userIdentity_accountId as entity_sourceAccount
select userIdentity_arn as entity_sourceName
where not eq(entity_sourceName,userIdentity_userName)
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSCreateAccessKey") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSCreateAccessKey") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSCreateAccessKey") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSCreateAccessKey") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSCreateloginprofile

**Summary:** Detects if a login has been performed by a user which has been created in the last 24 hours and checks if the user creation and the login has been performed from the same IP. This behaviour could indicate a privilege escalation attempt.

**Description:** Detects if a login has been performed by a user which has been created in the last 24 hours and checks if the user creation and the login has been performed from the same IP. Possible privilege escalation attempt.

**MITRE:** Tactics: Resource Development (TA0042) | Techniques: Establish Accounts (T1585)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"signin.amazonaws.com")
where eq(eventName,"ConsoleLogin")
group every 15m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress,userName, client
every 15m
where (sourceIPAddress,userName,userIdentity_arn) in (
from cloud.aws.cloudtrail
where eq(eventName,"CreateLoginProfile")
select str(jqeval(jqcompile(".userName"),requestParameters)) as createdUserName
group every - by sourceIPAddress,createdUserName,userIdentity_arn, client
)
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSCreateloginprofile") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSCreateloginprofile") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSCreateloginprofile") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSCreateloginprofile") as alertPriority
```

## SecOpsAWSCreatePolicyVersionToAllowAllResources

**Summary:** This search looks for AWS CloudTrail events where a user has created a policy version that allows the user to access any resource in their account.

**Description:** This search looks for AWS CloudTrail events where a user created a policy version that allows the user to access any resource in their account.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"CreatePolicyVersion")
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress,requestParameters_policyDocument_Statement_Action,requestParameters_policyDocument,client
every 5m
select join(requestParameters_policyDocument_Statement_Action, " ") as policyDocument_Statement_Action
where toktains(policyDocument_Statement_Action,"iam:*")
select sourceIPAddress as entity_sourceIP
select userIdentity_accountId as entity_sourceAccount
select userIdentity_arn as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSCreatePolicyVersionToAllowAllResources") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSCreatePolicyVersionToAllowAllResources") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSCreatePolicyVersionToAllowAllResources") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSCreatePolicyVersionToAllowAllResources") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsDbSnapshotCreated

**Summary:** Creating a snapshot is a common technique utilized by malicious actors to download databases in a stealthy manner. This alert should be considered when other signals could indicate that an account has been compromised.

**MITRE:** Tactics: Discovery (TA0007), Defense Evasion (TA0005), Exfiltration (TA0010) | Techniques: Cloud Storage Object Discovery (T1619), Modify Cloud Compute Infrastructure (T1578), Data from Cloud Storage (T1530), Valid Accounts (T1078)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"rds.amazonaws.com")
where eq(eventName,"CreateDBSnapshot")
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
group every 5m by awsRegion, userIdentity_type, entity_sourceAccount, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsDbSnapshotCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsDbSnapshotCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsDbSnapshotCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsDbSnapshotCreated") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSDetectStsAssumeRoleAbuse

**Summary:** Suspicious use of "AssumedRole". This type of tokens could be used by an attacker in order perform privilege escalation or lateral movements.

**MITRE:** Tactics: Persistence (TA0003), Privilege Escalation (TA0004) | Techniques: Valid Accounts (T1078), Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(userIdentity_type,"AssumedRole")
where userIdentity_sessionContext_sessionIssuer_type = "Role"
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSDetectStsAssumeRoleAbuse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSDetectStsAssumeRoleAbuse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSDetectStsAssumeRoleAbuse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSDetectStsAssumeRoleAbuse") as alertPriority
```

## SecOpsAWSDetectUsersCreatingKeysWithEncryptPolicyWithoutMFA

**Summary:** Creation of a KMS key with action kms:Encrypt is available for everyone. This could be a compromised account indicator.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Service Session Hijacking (T1563)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"kms.amazonaws.com")
where eq(eventName,"CreateKey") or eq(eventName,"PutKeyPolicy")
where ((toktains(requestParameters_policy_Statement_Action[0],"kms:*") or toktains(requestParameters_policy_Statement_Action[0],"kms:Encrypt")) and (eq(requestParameters_policy_Statement_Principal_AWS[0],"*"))) or ((toktains(requestParameters_policy_Statement_Action[1],"kms:*") or toktains(requestParameters_policy_Statement_Action[1],"kms:Encrypt")) and (eq(requestParameters_policy_Statement_Principal_AWS[1],"*"))) or ((toktains(requestParameters_policy_Statement_Action[2],"kms:*") or toktains(requestParameters_policy_Statement_Action[2],"kms:Encrypt")) and (eq(requestParameters_policy_Statement_Principal_AWS[2],"*"))) or ((toktains(requestParameters_policy_Statement_Action[3],"kms:*") or toktains(requestParameters_policy_Statement_Action[3],"kms:Encrypt")) and (eq(requestParameters_policy_Statement_Principal_AWS[3],"*"))) or ((toktains(requestParameters_policy_Statement_Action[4],"kms:*") or toktains(requestParameters_policy_Statement_Action[4],"kms:Encrypt")) and (eq(requestParameters_policy_Statement_Principal_AWS[4],"*")))
group every 5m by eventName, responseElements_keyMetadata, userIdentity_arn, userIdentity_accountId, sourceIPAddress, userName, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSDetectUsersCreatingKeysWithEncryptPolicyWithoutMFA") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSDetectUsersCreatingKeysWithEncryptPolicyWithoutMFA") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSDetectUsersCreatingKeysWithEncryptPolicyWithoutMFA") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSDetectUsersCreatingKeysWithEncryptPolicyWithoutMFA") as alertPriority
```

## SecOpsAwsEc2KeyAction

**Summary:** Detects any actions observed that create, import, or delete access keys to EC2.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"ec2.amazonaws.com")
where endswith(eventName, "KeyPair")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsEc2KeyAction") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsEc2KeyAction") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsEc2KeyAction") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsEc2KeyAction") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsECRContainerScanningFindingsCritical

**Summary:** Scanning from an ECR container detected at least one critical risk finding.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource, "ecr.amazonaws.com")
where eq(eventName, "DescribeImageScanFindings")
where toktains(stringify(responseElements), "CRITICAL")
group every 5m by eventName,requestParameters_imageId_imageDigest,requestParameters_repositoryName,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsECRContainerScanningFindingsCritical") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsECRContainerScanningFindingsCritical") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsECRContainerScanningFindingsCritical") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsECRContainerScanningFindingsCritical") as alertPriority
```

## SecOpsAWSECRContainerScanningFindingsLowInformationalUnknown

**Summary:** Scanning from an ECR container detected at least one LOW or UNDEFINED risk finding.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource, "ecr.amazonaws.com")
where eq(eventName, "DescribeImageScanFindings")
where weakhas(responseElements_imageScanFindings_findings_severity_str, "LOW") or toktains(responseElements_imageScanFindings_findings_severity_str, "UNDEFINED") or  toktains(responseElements_imageScanFindings_findings_severity_str, "INFORMATIONAL")
group every 5m by eventName,requestParameters_imageId_imageDigest,requestParameters_repositoryName,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSECRContainerScanningFindingsLowInformationalUnknown") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSECRContainerScanningFindingsLowInformationalUnknown") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSECRContainerScanningFindingsLowInformationalUnknown") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSECRContainerScanningFindingsLowInformationalUnknown") as alertPriority
```

## SecOpsAwsECRContainerUploadOutsideBusinessHours

**Summary:** Upload of a new ECR container was performed outside normal business hours. This is during weekend or between 20:00 and 8:00

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Cloud Compute Infrastructure (T1578)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"ecr.amazonaws.com")
where eq(eventName,"PutImage")
select hour(eventdate) as eventHour
select dayname(eventdate) as eventDayName
where eventDayName in ["Saturday","Sunday"] or (eventHour >= 20) or (eventHour < 8)
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select str(jqeval(jqcompile(".imageTag"),requestParameters)) as imageTag
select str(jqeval(jqcompile(".registryId"),requestParameters)) as registryId
select str(jqeval(jqcompile(".repositoryName"),requestParameters)) as repositoryName
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsECRContainerUploadOutsideBusinessHours") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsECRContainerUploadOutsideBusinessHours") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsECRContainerUploadOutsideBusinessHours") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsECRContainerUploadOutsideBusinessHours") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsEcrImageUpload

**Summary:** Detects users uploading new images to AWS Elastic Container Registry (ECR).

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Implant Internal Image (T1525)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventName,"PutImage")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 1h by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceAccount, entity_sourceName, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsEcrImageUpload") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsEcrImageUpload") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsEcrImageUpload") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsEcrImageUpload") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSExcessiveSecurityScanning

**Summary:** A large number of actions performed which start with Describe have been performed by a single user. This could indicate this user is trying to enumerate the AWS account.

**Description:** A large ammount of actions performed which start with Describe have been performed by a single user. This could indicate this user is trying to enumerate the AWS account.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Network Service Discovery (T1046)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where startswith(eventName,"Describe") or startswith(eventName,"Get") or startswith(eventName,"List")
group every 30m by sourceIPAddress,userIdentity_arn,userIdentity_accountId, client
every 30m
select collectDistinct(eventName) as eventNames
where length(eventNames) > 50
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSExcessiveSecurityScanning") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSExcessiveSecurityScanning") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSExcessiveSecurityScanning") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSExcessiveSecurityScanning") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsGetSecretFromNonAmazonIp

**Summary:** Detects a GetSecretValue action where the source IP does not belong in an Amazon instance IP space.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Unsecured Credentials (T1552)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"secretsmanager.amazonaws.com") and eq(eventName,"GetSecretValue")
select userIdentity_arn as entity_sourceName
select userIdentity_principalId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select isp(ip4(entity_sourceIP)) as isp
where not weaktoktains(isp, "Amazon")
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, userIdentity_accountId, eventName, requestParameters, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsGetSecretFromNonAmazonIp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsGetSecretFromNonAmazonIp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsGetSecretFromNonAmazonIp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsGetSecretFromNonAmazonIp") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAWSIAMAssumeRolePolicyBruteForce

**Summary:** Detection of events with errorCode "MalformedPolicyDocumentException". A malformed policy document exception occurs in instances where roles are attempted to be assumed, or brute forced.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(errorCode, "MalformedPolicyDocumentException") and not endswith(userAgent, ".amazonaws.com")
select userIdentity_userName as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by eventSource, awsRegion, userIdentity_accountId, userIdentity_principalId, userIdentity_arn, entity_sourceAccount, entity_sourceIP, eventName, requestParameters_policyName, requestParameters_policyDocument, errorCode, userAgent, client
every 5m
select count() as numEvents
where numEvents >= 2
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSIAMAssumeRolePolicyBruteForce") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSIAMAssumeRolePolicyBruteForce") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSIAMAssumeRolePolicyBruteForce") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSIAMAssumeRolePolicyBruteForce") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSIAMCreateUserActionObserved

**Summary:** A new user was created. This actions should be checked since an attacker could have created this user to gain persistence on the AWS account.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098), Create Account (T1136)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"CreateUser") and isnotnull(requestParameters)
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSIAMCreateUserActionObserved") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSIAMCreateUserActionObserved") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSIAMCreateUserActionObserved") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSIAMCreateUserActionObserved") as alertPriority
```

## SecOpsAWSIAMDeletePolicy

**Summary:** An action to delete a policy was performed. This should be checked since it could undermine the security configuration of the AWS environment.

**MITRE:** Tactics: Persistence (TA0003), Impact (TA0040) | Techniques: Account Manipulation (T1098), Account Access Removal (T1531)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"DeletePolicy") and isnotnull(requestParameters)
where not toktains(userAgent,".amazonaws.com")
group every 5m by eventName,requestParameters_policyArn,userIdentity_arn,userIdentity_accountId,sourceIPAddress,errorMessage, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSIAMDeletePolicy") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSIAMDeletePolicy") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSIAMDeletePolicy") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSIAMDeletePolicy") as alertPriority
```

## SecOpsAWSIAMPolicyAppliedToGroup

**Summary:** It was detected that a policy had been attached to a group. These kinds of events should be checked since they could be granting excessive access permissions to AWS services or resources.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Domain Policy Modification (T1484)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"PutGroupPolicy")
group every 5m by eventName,requestParameters_groupName,requestParameters_policyName,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSIAMPolicyAppliedToGroup") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSIAMPolicyAppliedToGroup") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSIAMPolicyAppliedToGroup") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSIAMPolicyAppliedToGroup") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSIAMPolicyAppliedToRole

**Summary:** It was detected that a policy has been attached to a role, these kind of events should be checked since they could be granting excessive access permissions to AWS services or resources.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Domain Policy Modification (T1484)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"PutRolePolicy")
group every 5m by eventName,requestParameters_policyName,requestParameters_roleName,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select userIdentity_arn as entity_sourceName
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSIAMPolicyAppliedToRole") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSIAMPolicyAppliedToRole") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSIAMPolicyAppliedToRole") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSIAMPolicyAppliedToRole") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSIAMPolicyAppliedToUser

**Summary:** It was detected that a policy has been attached to a role, these kind of events should be checked since they could be granting excessive access permissions to AWS services or resources.

**Description:** It was detected that a policy has been attached to a user, these kind of events should be checked since they could be granting excessive access permissions to AWS services or resources.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Domain Policy Modification (T1484)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"PutUserPolicy")
group every 5m by eventName,requestParameters_userName,requestParameters_policyName,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSIAMPolicyAppliedToUser") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSIAMPolicyAppliedToUser") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSIAMPolicyAppliedToUser") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSIAMPolicyAppliedToUser") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSIamSuccessfulGroupDeletion

**Summary:** Deletion of an IAM group is not a dangerous action by itself, but correlated with other events such as recently user or group creations could indicate that a malicious behaviour.

**MITRE:** Tactics: Impact (TA0040), Persistence (TA0003), Defense Evasion (TA0005), Initial Access (TA0001) | Techniques: Valid Accounts (T1078), Account Access Removal (T1531)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"DeleteGroup") and isnotnull(requestParameters) and isnull(errorCode)
//where not userAgent -> ".amazonaws.com" -> filtering removed because matas/mafia is not parsing userAgent correctly
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select str(jqeval(jqcompile(".groupName"),requestParameters)) as groupName
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSIamSuccessfulGroupDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSIamSuccessfulGroupDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSIamSuccessfulGroupDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSIamSuccessfulGroupDeletion") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSIAMUserGeneratingAccessDeniedErrorsAcrossMultipleActions

**Summary:** This alert checks filters by events where the errorCode AccessDenied is present and groups each 5 minutes by user arn and aws account.

**Description:** It was detected that a user has received the errorCode value AccessDenied when trying to perform different actions within a short period of time. This could indicate this user is trying to enumerate their permissions over the AWS account.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Cloud Service Discovery (T1526)

**Tables:** cloud.aws.cloudtrail.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail.events
where eq(errorCode, "AccessDenied")
group every 5m by userName, client
every 5m
select userName as entity_sourceAccount
select hllppcount(eventName) as unique_actions_denied
select count() as total_denies
where unique_actions_denied >= 5
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSIAMUserGeneratingAccessDeniedErrorsAcrossMultipleActions") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSIAMUserGeneratingAccessDeniedErrorsAcrossMultipleActions") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSIAMUserGeneratingAccessDeniedErrorsAcrossMultipleActions") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSIAMUserGeneratingAccessDeniedErrorsAcrossMultipleActions") as alertPriority
```

## SecOpsAwsKmsKeyDeletion

**Summary:** Detects the scheduled deletion of KMS keys.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Account Access Removal (T1531)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"kms.amazonaws.com")
where eq(eventName,"ScheduleKeyDeletion")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsKmsKeyDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsKmsKeyDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsKmsKeyDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsKmsKeyDeletion") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAwsKmsSensitiveActivity

**Summary:** Analytics detection about KMS key enable or disable actions.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"kms.amazonaws.com")
where eq(eventName,"EnableKey") or eq(eventName,"DisableKey")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, eventName, requestParameters, client
select count() as count
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsKmsSensitiveActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsKmsSensitiveActivity") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsKmsSensitiveActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsKmsSensitiveActivity") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAWSLoggingConfigurationChangeObservedDeleteTrail

**Summary:** A trail within the Cloudtrail service has been deleted. This event should be checked since it could indicate that an attacker may be trying to hide suspicious activity within an AWS account.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventName,"DeleteTrail")
group every 5m by eventName,userIdentity_arn,userIdentity_accountId,sourceIPAddress,requestParameters_name, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSLoggingConfigurationChangeObservedDeleteTrail") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSLoggingConfigurationChangeObservedDeleteTrail") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSLoggingConfigurationChangeObservedDeleteTrail") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSLoggingConfigurationChangeObservedDeleteTrail") as alertPriority
```

## SecOpsAWSLoggingConfigurationChangeObservedRemoveTags

**Summary:** This detection filters by cloudtrail events with RemoveTags as eventName.

**Description:** Some tags were removed from the configuration of a logging trail. This event should be checked since it could indicate an attacker may be trying to hide suspicious activity within an AWS account.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eventName = "RemoveTags"
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select jqeval(jqcompile(".tagsList"), requestParameters) as tagsDict
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSLoggingConfigurationChangeObservedRemoveTags") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSLoggingConfigurationChangeObservedRemoveTags") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSLoggingConfigurationChangeObservedRemoveTags") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSLoggingConfigurationChangeObservedRemoveTags") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSLoggingConfigurationChangeObservedStopLogging

**Summary:** A trail within the Cloudtrail service has been stopped. This event should be checked since it could indicate that an attacker may be trying to hide suspicious activity within an AWS account.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventName,"StopLogging")
group every 5m by userIdentity_arn,userIdentity_accountId,sourceIPAddress,requestParameters_name, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSLoggingConfigurationChangeObservedStopLogging") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSLoggingConfigurationChangeObservedStopLogging") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSLoggingConfigurationChangeObservedStopLogging") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSLoggingConfigurationChangeObservedStopLogging") as alertPriority
```

## SecOpsAwsMasterKeyDisabledOrDeletion

**Summary:** Detects when a Customer Master Key (CMK) was disabled or scheduled for deletion.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Account Access Removal (T1531)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"kms.amazonaws.com")
where eq(eventName,"ScheduleKeyDeletion") or eq(eventName,"DisableKey")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceAccount, entity_sourceName, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsMasterKeyDisabledOrDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsMasterKeyDisabledOrDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsMasterKeyDisabledOrDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsMasterKeyDisabledOrDeletion") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAWSMultipleFailedConsoleLogins

**Summary:** Multiple failed login attempts from the same user were detected. This could indicate an attacker could be trying to brute force access to that specific user account.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"signin.amazonaws.com")
where eq(eventName,"ConsoleLogin") and not eq(responseElements_ConsoleLogin,"Success")
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId, client
every 5m
select count() as count
where count > 5
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select collectDistinct(sourceIPAddress) as srcIpList
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSMultipleFailedConsoleLogins") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSMultipleFailedConsoleLogins") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSMultipleFailedConsoleLogins") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSMultipleFailedConsoleLogins") as alertPriority
```

## SecOpsAWSMultipleFailedConsoleLoginsFromASourceIP

**Summary:** The Describe permissions event retrieves a description of permissions for a specified stack. This could be used by an attacker to collect information for further attacks.

**Description:** Multiple failed login attempts were detected from the same source IP. This could indicate that an attacker could be trying to brute force different AWS user accounts.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"signin.amazonaws.com")
where eq(eventName,"ConsoleLogin") and not eq(responseElements_ConsoleLogin,"Success")
group every 5m by sourceIPAddress, client
every 5m
select count() as count
where count > 5
select sourceIPAddress as entity_sourceIP
select str(join(collectDistinct(userIdentity_userName),",")) as userIdentity_userNameList
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSMultipleFailedConsoleLoginsFromASourceIP") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSMultipleFailedConsoleLoginsFromASourceIP") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSMultipleFailedConsoleLoginsFromASourceIP") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSMultipleFailedConsoleLoginsFromASourceIP") as alertPriority
```

## SecOpsAWSNetworkAccessControlListDeleted

**Summary:** Network ACl was deleted, this could indicate that an attacker is downgrading security access of a network instance

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"ec2.amazonaws.com")
where eq(eventName,"DeleteNetworkAclEntry")
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select str(int(jqeval(jqcompile(".ruleNumber"), requestParameters))) as ruleNumber
select str(jqeval(jqcompile(".networkAclId"), requestParameters)) as networkAclId
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSNetworkAccessControlListDeleted") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSNetworkAccessControlListDeleted") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSNetworkAccessControlListDeleted") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSNetworkAccessControlListDeleted") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSNewUserPoolClientCreated

**Summary:** It was detected that a UserPoolClient entity has been created. These type of entities could be used by an attacker to perform unauthenticated API operations.

**MITRE:** Tactics: Persistence (TA0003), Credential Access (TA0006) | Techniques: Account Manipulation (T1098), Create Account (T1136), Use Alternate Authentication Material (T1550)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"cognito-idp.amazonaws.com")
where eq(eventName,"CreateUserPoolClient")
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select str(jqeval(jqcompile(".userPoolId"), requestParameters)) as userPoolId
select str(jqeval(jqcompile(".clientName"), requestParameters)) as clientName
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSNewUserPoolClientCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSNewUserPoolClientCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSNewUserPoolClientCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSNewUserPoolClientCreated") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSOpenNetworkACLs

**Summary:** The search looks for CloudTrail events to detect if any network ACLs were created with all the ports open to a specified CIDR.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where (eq(eventName, "CreateNetworkAclEntry") or eq(eventName, "ReplaceNetworkAclEntry")) and eq(requestParameters_ruleAction, "allow") and eq(requestParameters_egress, false) and eq(requestParameters_aclProtocol, "-1")
select userName as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select str(jqeval(jqcompile(".requestParameters.cidrBlock"), jsonparse(rawMessage))) as CIDR_Block
select int(jqeval(jqcompile(".requestParameters.portRange.from"), jsonparse(rawMessage))) as portRange_from
select int(jqeval(jqcompile(".requestParameters.portRange.to"), jsonparse(rawMessage))) as portRange_to
select (portRange_to - portRange_from) as num_opened_ports
where num_opened_ports > 1024
group every 5m by awsRegion, userIdentity_principalId, eventName, entity_sourceAccount, entity_sourceIP, userAgent, requestParameters_ruleAction, requestParameters_egress, requestParameters_aclProtocol, CIDR_Block, portRange_from, portRange_to, num_opened_ports, client
every 5m
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSOpenNetworkACLs") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSOpenNetworkACLs") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSOpenNetworkACLs") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSOpenNetworkACLs") as alertPriority
```

## SecOpsAWSOpsWorksDescribePermissionsEvent

**Summary:** The DescribePermissions event retrieves a description about permissions for a specified stack. This could be used by an attacker to collect information for further attacks.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Account Discovery (T1087)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"opsworks.amazonaws.com")
where eq(eventName,"DescribePermissions")
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSOpsWorksDescribePermissionsEvent") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSOpsWorksDescribePermissionsEvent") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSOpsWorksDescribePermissionsEvent") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSOpsWorksDescribePermissionsEvent") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsPermanentKeyCreation

**Summary:** Detects actions observed that create, import and delete access keys to EC2.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(userIdentity_type,"IAMUser")
where eq(eventName,"CreateAccessKey")
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsPermanentKeyCreation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsPermanentKeyCreation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsPermanentKeyCreation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsPermanentKeyCreation") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSPermissionsBoundaryLiftedtoRole

**Summary:** It was detected that a permission boundary has been lifted against an IAM role. This action could be used by an attacker to escalate privileges within an AWS account.

**MITRE:** Tactics: Defense Evasion (TA0005), Persistence (TA0003), Privilege Escalation (TA0004) | Techniques: Account Manipulation (T1098), Valid Accounts (T1078)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"DeleteRolePermissionsBoundary") and isnull(errorMessage)
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select str(jqeval(jqcompile(".roleName"), requestParameters)) as roleName
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSPermissionsBoundaryLiftedtoRole") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSPermissionsBoundaryLiftedtoRole") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSPermissionsBoundaryLiftedtoRole") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSPermissionsBoundaryLiftedtoRole") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSPermissionsBoundaryLiftedtoUser

**Summary:** It was detected that a permission boundary has been lifted against an IAM user. This action could be used by an attacker to escalate privileges within an AWS account.

**MITRE:** Tactics: Defense Evasion (TA0005), Persistence (TA0003), Privilege Escalation (TA0004) | Techniques: Account Manipulation (T1098), Valid Accounts (T1078)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"DeleteUserPermissionsBoundary") and isnull(errorMessage)
group every 5m by eventName,requestParameters_userName,requestParameters_roleName,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSPermissionsBoundaryLiftedtoUser") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSPermissionsBoundaryLiftedtoUser") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSPermissionsBoundaryLiftedtoUser") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSPermissionsBoundaryLiftedtoUser") as alertPriority
```

## SecOpsAWSPermissionsBoundaryModifiedToRole

**Summary:** A Permission Boundary has been modified on a role. This could allow to grant all the actions in the permissions of the policies attached to that role.

**MITRE:** Tactics: Persistence (TA0003), Defense Evasion (TA0005), Privelege Escalation (TA0004) | Techniques: Valid Accounts (T1078), Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"PutRolePermissionsBoundary") and isnull(errorMessage)
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select str(jqeval(jqcompile(".roleName"), requestParameters)) as roleName
select str(jqeval(jqcompile(".permissionsBoundary"), requestParameters)) as permissionsBoundaryArn
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSPermissionsBoundaryModifiedToRole") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSPermissionsBoundaryModifiedToRole") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSPermissionsBoundaryModifiedToRole") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSPermissionsBoundaryModifiedToRole") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSPermissionsBoundaryModifiedToUser

**Summary:** A Permission Boundary has been modified for a role. This could allow granting all the actions in the permissions of the policies attached to that role.

**MITRE:** Tactics: Persistence (TA0003), Defense Evasion (TA0005), Privilege Escalation (TA0004) | Techniques: Valid Accounts (T1078), Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"PutUserPermissionsBoundary") and isnull(errorMessage)
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select str(jqeval(jqcompile(".userName"), requestParameters)) as userName
select str(jqeval(jqcompile(".permissionsBoundary"), requestParameters)) as permissionsBoundaryArn
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSPermissionsBoundaryModifiedToUser") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSPermissionsBoundaryModifiedToUser") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSPermissionsBoundaryModifiedToUser") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSPermissionsBoundaryModifiedToUser") as alertPriority
```

## SecOpsAWSPublicS3BucketExposed

**Summary:** This alert filters PutBucketAcl cloudtrail events that come from the S3 service. The alert then extracts each URI and Permission pair from the raw event message. The alert then checks if the URI is equal to [http://acs.amazonaws.com/groups/global/AllUsers](http://acs.amazonaws.com/groups/global/AllUsers) or [http://acs.amazonaws.com/groups/global/AuthenticatedUsers](http://acs.amazonaws.com/groups/global/AuthenticatedUsers) and if the permission is READ, READ_ACP, WRITE, WRITE_ACP, or FULL_CONTROL. The alert will trigger if any of these pairs meet both criteria. This alert will only extract the first five permissions and URIs of a message.

**Description:** A request to set a new ACL to a bucket and to make it public has been detected. Although this could be a legitimate action, It should be reviewed.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Domain Policy Modification (T1484)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"s3.amazonaws.com")
where eq(eventName,"PutBucketAcl")
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Grantee_URI[0] as URI1
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Grantee_URI[1] as URI2
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Grantee_URI[2] as URI3
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Grantee_URI[3] as URI4
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Grantee_URI[4] as URI5
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Permission[0] as Permission1
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Permission[1] as Permission2
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Permission[2] as Permission3
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Permission[3] as Permission4
select requestParameters_AccessControlPolicy_AccessControlList_Grant_Permission[4] as Permission5
select ["http://acs.amazonaws.com/groups/global/AllUsers","http://acs.amazonaws.com/groups/global/AuthenticatedUsers"] as URIs
select ["READ","READ_ACP","WRITE","WRITE_ACP","FULL_CONTROL"] as Permissions
where (URI1 in URIs and Permission1 in Permissions) or (URI2 in URIs and Permission2 in Permissions) or (URI3 in URIs and Permission3 in Permissions) or (URI4 in URIs and Permission4 in Permissions) or (URI5 in URIs and Permission5 in Permissions)
group every 5m by eventName,requestParameters,requestParameters_bucketName,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select last(rawMessage) as lastRawMessage
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSPublicS3BucketExposed") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSPublicS3BucketExposed") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSPublicS3BucketExposed") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSPublicS3BucketExposed") as alertPriority
```

## SecOpsAwsRoleCreated

**Summary:** Detects actions taken to create new IAM roles in AWS

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"CreateRole")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsRoleCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsRoleCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsRoleCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsRoleCreated") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAWSRootLogin

**Summary:** A successful root account login was detected. This account should only be used to create initial IAM users or perform tasks only available to the root user. Using this account is against AWS security best practices.

**MITRE:** Tactics: Privilege Escalation (TA0004), Persistence (TA0003), Initial Access (TA0001) | Techniques: Valid Accounts (T1078), Domain Policy Modification (T1484)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"signin.amazonaws.com")
where eq(eventName,"ConsoleLogin")
where eq(userName,"root")
where eq(responseElements_ConsoleLogin, "Success")
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSRootLogin") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSRootLogin") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSRootLogin") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSRootLogin") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsS3EncryptWithKMSKey

**Summary:** Detects actions taken by users to encrypt S3 buckets using KMS keys.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"s3.amazonaws.com")
where eq(eventName,"CopyObject")
where toktains(rawMessage, "x-amz-server-side-encryption") and toktains(rawMessage, "aws:kms")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 1h by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, userName, eventName, requestParameters, entity_sourceAccount, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsS3EncryptWithKMSKey") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsS3EncryptWithKMSKey") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsS3EncryptWithKMSKey") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsS3EncryptWithKMSKey") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAWSSamlAccess

**Summary:** This search provides specific information to detect abnormal access or potential credential hijack or forgery, specially in federated environments using SAML protocol inside the perimeter or cloud provider

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Forge Web Credentials (T1606), Valid Accounts (T1078)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventName,"AssumeRoleWithSAML")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by entity_sourceIP,entity_sourceName,entity_sourceAccount,REGION,requestParameters_principalArn,requestParameters_roleSessionName,responseElements_issuer, client
select first(eventTime) as firstTime, last(eventTime) as lastTime
select count() as Count
where Count > 3
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSSamlAccess") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSSamlAccess") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSSamlAccess") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSSamlAccess") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAWSSecretsManagerSensitiveAdminActionObserved

**Summary:** Any modification action performed against the AWS Secrets Administrative service should be reviewd. This could be an indicator of suspicious activity being carried out by a hostile entity.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Unsecured Credentials (T1552)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"secretsmanager.amazonaws.com")
where toktains(eventName, "Secret")
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSSecretsManagerSensitiveAdminActionObserved") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSSecretsManagerSensitiveAdminActionObserved") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSSecretsManagerSensitiveAdminActionObserved") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSSecretsManagerSensitiveAdminActionObserved") as alertPriority
```

## SecOpsAWSSetdefaultpolicyversion

**Summary:** This alert filters SetDefaultPolicyVersion cloudtrail events that come from the IAM service. In addition, the errorCode has to be equal to null to avoid false positives.

**Description:** This searches for AWS CloudTrail events where a user has set a default policy version. Attackers are known to use this as a Privilege Escalation if previous policy versions had permissions to access more resources than the current version

**MITRE:** Tactics: Privilege Escalation (TA0004), Persistence (TA0003) | Techniques: Valid Accounts (T1078), Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"SetDefaultPolicyVersion") and isnull(errorMessage)
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress,requestParameters_roleName, client
every 5m
select userIdentity_accountId as entity_sourceAccount
select userIdentity_arn as entity_sourceName
select sourceIPAddress as entity_sourceIP
select jqeval(jqcompile(".policyArn"),requestParameters) as policyArn
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSSetdefaultpolicyversion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSSetdefaultpolicyversion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSSetdefaultpolicyversion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSSetdefaultpolicyversion") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsSqsListQueues

**Summary:** Detects rare ListQueues event from AWS SQS.

**MITRE:** Tactics: Collection (TA0009) | Techniques: Data from Cloud Storage (T1530)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventName,"ListQueues")
where eq(eventSource,"sqs.amazonaws.com")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsSqsListQueues") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsSqsListQueues") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsSqsListQueues") as alertMitreTechniques
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAwsStsPossibleSessionTokenAbuse

**Summary:** Detects STS session tokens, which can be used to move laterally, or escalate, privileges in AWS.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Use Alternate Authentication Material (T1550)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"sts.amazonaws.com")
where eq(eventName,"GetSessionToken")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 5m by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, eventName, requestParameters, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsStsPossibleSessionTokenAbuse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsStsPossibleSessionTokenAbuse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsStsPossibleSessionTokenAbuse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsStsPossibleSessionTokenAbuse") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAwsUnapprovedUserApiActivity

**Summary:** Detects AWS API activity by users who are not explicitly authorized from an allow list.

**Description:** Detects actions from Unapproved users against AWS API.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventType,"AwsApiCall")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 1h by awsRegion, userIdentity_type, userIdentity_invokedBy, entity_sourceIP, entity_sourceName, entity_sourceAccount, userName, eventSource, client
select hlurjson("AwsAuthorizedApiUsers", entity_sourceName, eventdate) as approved_user
where isnull(approved_user)
select count() as count
select hllppcount(eventName) as unique_count_events
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsUnapprovedUserApiActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsUnapprovedUserApiActivty") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsUnapprovedUserApiActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsUnapprovedUserApiActivity") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAWSUpdateloginprofile

**Summary:** A user has updated the login profile of a different user. This could indicate that a privilege escalation is being performed leveraging the user which login profile has been updated.

**MITRE:** Tactics: Privilege Escalation (TA0004), Persistence (TA0003) | Techniques: Valid Accounts (T1078), Account Manipulation (T1098)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"UpdateLoginProfile")
where not eq(userAgent,"console.amazonaws.com") and isnull(errorCode)
group every 5m by eventName,requestParameters_userName,userIdentity_arn,userIdentity_accountId,sourceIPAddress,userIdentity_userName, client
every 5m
where not eq(str(userIdentity_userName),requestParameters_userName)
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select userIdentity_arn as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSUpdateloginprofile") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSUpdateloginprofile") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSUpdateloginprofile") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSUpdateloginprofile") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsUpdateSAMLProvider

**Summary:** Detects actions that update SAML the provider configuration

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Forge Web Credentials (T1606)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eq(eventSource,"iam.amazonaws.com")
where eq(eventName,"UpdateSAMLProvider")
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select jqeval(jqcompile(".principalArn"), requestParameters) as sAMLProviderArn
group every 5m by entity_sourceIP, entity_sourceName, awsRegion, eventName, sAMLProviderArn, entity_sourceAccount, userIdentity_arn, userIdentity_accessKeyId, userIdentity_principalId, client
select first(eventTime) as firstTime, last(eventTime) as lastTime, count() as count
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsUpdateSAMLProvider") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsUpdateSAMLProvider") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsUpdateSAMLProvider") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsUpdateSAMLProvider") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAWSUserSuccessfulLoginWithoutMFA

**Summary:** An AWS console successfully without MFA login was detected. AWS security best practices are recommended to enable this security measure for console access login.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.aws.cloudtrail
where eventSource = "signin.amazonaws.com"
where eventName = "ConsoleLogin"
where str(jqeval(jqcompile(".responseElements.ConsoleLogin"), jsonparse(rawMessage))) = "Success"
where str(jqeval(jqcompile(".additionalEventData.MFAUsed"), jsonparse(rawMessage))) = "No"
group every 5m by eventName,requestParameters,userIdentity_arn,userIdentity_accountId,sourceIPAddress, client
every 5m
select userIdentity_arn as entity_sourceName
select userIdentity_accountId as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAWSUserSuccessfulLoginWithoutMFA") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAWSUserSuccessfulLoginWithoutMFA") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAWSUserSuccessfulLoginWithoutMFA") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAWSUserSuccessfulLoginWithoutMFA") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAwsVpcLargeFile

**Summary:** Detects possible large file being moved via AWS VPC logs.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Data Transfer Size Limits (T1030)

**Tables:** vpc.aws.flow

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from vpc.aws.flow
select str(srcaddr) as entity_sourceIP
select str(dstaddr) as entity_destinationIP
group every 15m by accountId, interface_id, action, entity_sourceIP, entity_destinationIP, dstport, client
select sum(bytes/1000000) as total_mbytes
where total_mbytes > 50
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsVpcLargeFile") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsVpcLargeFile") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsVpcLargeFile") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsVpcLargeFile") as alertPriority
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
```

## SecOpsAwsVpcLargeOutboundTrafficBlock

**Summary:** Actions observed as blocked for sending large amounts of data from AWS out to the internet.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** vpc.aws.flow

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from vpc.aws.flow
where eqic(action, "REJECT")
where isprivate(srcaddr) and ispublic(dstaddr)
select srcaddr as entity_sourceIP
select dstaddr as entity_destinationIP
group every 5m by accountId, action, entity_sourceIP, entity_destinationIP, client
select sum(bytes/1000000) as total_mbytes
where total_mbytes > 200
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAwsVpcLargeOutboundTrafficBlock") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAwsVpcLargeOutboundTrafficBlock") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAwsVpcLargeOutboundTrafficBlock") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAwsVpcLargeOutboundTrafficBlock") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsCDIocIpSuspiciousAWSData

**Summary:** This search looks for Collective Defense matches in AWS data.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Exploitation for Defense Evasion (T1211)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where ispublic(ip4(sourceIPAddress))
select userIdentity_arn as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
group every 15m by entity_sourceIP, entity_sourceAccount, eventSource, eventName, client
select `lu/CollectiveDefense`(entity_sourceIP) as cd_hit
where isnotnull(cd_hit)
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsCDIocIpSuspiciousAWSData") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsCDIocIpSuspiciousAWSData") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsCDIocIpSuspiciousAWSData") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsCDIocIpSuspiciousAWSData") as alertPriority
```

## SecOpsLog4ShellVulnerabilityCloudAWS

**Summary:** This alert checks for the CVE-2021-44228 exploit (Log4shell). The query looks for payload patterns associated with Log4shell including payloads in the url, user-agent header, referer header, or POST and PUT HTTP bodies.

**Description:** Checks for attempts of exploiting CVE-2021-44228 as known as Log4shell. The query contained in this alert can generate high volumes of events due to the nature of the attack pattern. Tunning the alert to your environment is recommended.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** cloud.aws.cloudtrail

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.aws.cloudtrail
where {"/$%7bjndi:","%24%7bjndi:","%24%7Bjndi:","%2524%257Bjndi","%2F%252524%25257Bjndi%3A","${::-j}${","${::-l}${::-d}${::-a}${::-p}","${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}:/","${${::-j}ndi:rmi:/","${${env:","${${lower:${lower:jndi}}:${lower:rmi}:/","${${lower:j}${lower:n}${lower:d}i:${lower:rmi}:","${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}:/","${${lower:jndi}:${lower:rmi}:/","${base64:JHtqbmRp","${jndi:${lower:","${jndi:${lower:l}${lower:d}a${lower:p}://","${jndi:corba","${jndi:dns:/","${jndi:http:/","${jndi:iiop","${jndi:ldap://","${jndi:ldap://${env:","${jndi:ldap:/","${jndi:ldaps:/","${jndi:nds","${jndi:nis","${jndi:rmi:/","$%7Bjndi:","$%7blower:","$%7Blower:","$%7bupper:","$%7Bupper:","${${::-${::-$${::-j}}}"} in raw
group every 5m by sourceIPAddress,eventSource,eventName,userIdentity_userName,awsRegion,userAgent,eventID,eventType,raw, client
every 5m
select userIdentity_userName as entity_sourceAccount
select sourceIPAddress as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
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
select lu("SecOpsAlertDescription", "alertType", "SecOpsLog4ShellVulnerabilityCloudAWS") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLog4ShellVulnerabilityCloudAWS") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLog4ShellVulnerabilityCloudAWS") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLog4ShellVulnerabilityCloudAWS") as alertPriority
```
