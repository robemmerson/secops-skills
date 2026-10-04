# Detection library: CLOUD/AZURE

Azure detections: Azure AD audit/sign-in, activity logs, Event Hub, VMs. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (33):

- SecOpsAzureAutoAccountCreated
- SecOpsAzureAutomationRunbookCreatedOrMofidied
- SecOpsAzureAutomationRunbookDeleted
- SecOpsAzureAutomationWebhookCreated
- SecOpsAzureConditionalAccessPolicyAdded
- SecOpsAzureConditionalAccessPolicyDeleted
- SecOpsAzureConditionalAccessPolicyUpdated
- SecOpsAzureDevOpsAuditDisabled
- SecOpsAzureDevOpsPATMisuse
- SecOpsAzureDevOpsProjectVisibilityChanged
- SecOpsAzureDevOpsPublicUpstreamSourceAdded
- SecOpsAzureDevOpsSecretNotSecured
- SecOpsAzureExternalUserInvitationRedeemed
- SecOpsAzureExternalUserInvited
- SecOpsAzureFrontDoorWafPolicyDeletion
- SecOpsAzureFWPolicyDeletion
- SecOpsAzureGroupInformationDownload
- SecOpsAzureHybridHealthADFSDelete
- SecOpsAzureHybridHealthADFSNewServer
- SecOpsAzureImpossibleTravel
- SecOpsAzureNWDeviceModified
- SecOpsAzureUserAddedNonAdminRole
- SecOpsAzureUserAddedOutsidePIMRole
- SecOpsAzureUserAddedToGlobalAdminRole
- SecOpsAzureUserAddedToRoleNonPIM
- SecOpsAzureUserConfirmedCompromised
- SecOpsAzureUserCreated
- SecOpsAzureUserHighAggregateRiskSignIn
- SecOpsAzureUserHighRiskSignIn
- SecOpsAzureUserInfoDownload
- SecOpsAzureUserInformationDownload
- SecOpsAzureUserLoginSuspiciousRisk
- SecOpsAzureVMCmdEXE

## SecOpsAzureAutoAccountCreated

**Summary:** This alert identifies when a user has created a new Azure automation account, this could be leveraged by an attacker in order to gain persistence in an Azure environment.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.azure.eh.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.eh.events
where eq(operationName,"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE")
where eq(resultType,"Success")
select stringify(jqeval(jqcompile(".identity.claims"), jsonparse(rawMessage))) as claim
select split(split(split(claim, "claims/upn", 1),":",1),",",0) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureAutoAccountCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureAutoAccountCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureAutoAccountCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureAutoAccountCreated") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureAutomationRunbookCreatedOrMofidied

**Summary:** This alert identifies when a user has created or modified an Azure Automation runbook. This could be used by an attacker in order to gain persistence on the Azure environment.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Scheduled Task/Job (T1053)

**Tables:** cloud.azure.activity.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.activity.events
where operationName in ["MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE","MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE","MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION"]
where eq(resultType,"Success")
select callerIpAddress as entity_sourceIP
select stringify(jqeval(jqcompile(".identity.claims"), jsonparse(rawMessage))) as claim
select split(split(split(claim, "claims/upn", 1),":",1),",",0) as entity_sourceAccount
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureAutomationRunbookCreatedOrMofidied") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureAutomationRunbookCreatedOrMofidied") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureAutomationRunbookCreatedOrMofidied") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureAutomationRunbookCreatedOrMofidied") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureAutomationRunbookDeleted

**Summary:** This alert identifies when a user has deleted an Azure Automation runbook. This could be indicative than attacker may be trying to disrupt the normal behaviour of the automated processes within an azure account or deleting a runbook used in order to gain persistence.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Inhibit System Recovery (T1490)

**Tables:** cloud.azure.activity.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.activity.events
where eq(operationName,"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE")
where eq(resultType,"Success")
select callerIpAddress as entity_sourceIP
select stringify(jqeval(jqcompile(".identity.claims"), jsonparse(rawMessage))) as claim
select split(split(split(claim, "claims/upn", 1),":",1),",",0) as entity_sourceAccount
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureAutomationRunbookDeleted") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureAutomationRunbookDeleted") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureAutomationRunbookDeleted") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureAutomationRunbookDeleted") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureAutomationWebhookCreated

**Summary:** This alert identifies when an Azure Automation webhook has been created. This could be leveraged by an attacker in order to execute arbitrary code on the Azure environment.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Scheduled Task/Job (T1053)

**Tables:** cloud.azure.activity.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.activity.events
where operationName in ["MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/ACTION","MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE"]
where eq(resultType,"Success")
select stringify(jqeval(jqcompile(".identity.claims"), jsonparse(rawMessage))) as claim
select split(split(split(claim, "claims/upn", 1),":",1),",",0) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureAutomationWebhookCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureAutomationWebhookCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureAutomationWebhookCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureAutomationWebhookCreated") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureConditionalAccessPolicyAdded

**Summary:** This alert identifies when a user has added a conditional access policy, this should be checked since it could be undermining the security posture of the environment.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Domain Policy Modification (T1484)

**Tables:** cloud.azure.eh.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.eh.events
where eq(operationName,"Add conditional access policy")
where eq(properties_result_str,"success")
select str(jqeval(jqcompile(".properties.initiatedBy.user.id"), jsonparse(rawMessage))) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureConditionalAccessPolicyAdded") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureConditionalAccessPolicyAdded") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureConditionalAccessPolicyAdded") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureConditionalAccessPolicyAdded") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureConditionalAccessPolicyDeleted

**Summary:** This alert identifies when a user deletes a conditional access policy, this should be checked since it could be undermining the security posture of the environment.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Domain Policy Modification (T1484)

**Tables:** cloud.azure.eh.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.eh.events
where eq(operationName,"Delete conditional access policy")
where eq(properties_result_str,"success")
select str(jqeval(jqcompile(".properties.initiatedBy.user.id"), jsonparse(rawMessage))) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureConditionalAccessPolicyDeleted") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureConditionalAccessPolicyDeleted") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureConditionalAccessPolicyDeleted") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureConditionalAccessPolicyDeleted") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureConditionalAccessPolicyUpdated

**Summary:** This alert identifies when a user has modified a conditional access policy, this should be checked since it could be undermining the security posture of the environment.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Domain Policy Modification (T1484)

**Tables:** cloud.azure.eh.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.eh.events
where eq(operationName,"Update conditional access policy")
where eq(properties_result_str,"success")
select str(jqeval(jqcompile(".properties.initiatedBy.user.id"), jsonparse(rawMessage))) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureConditionalAccessPolicyUpdated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureConditionalAccessPolicyUpdated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureConditionalAccessPolicyUpdated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureConditionalAccessPolicyUpdated") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureDevOpsAuditDisabled

**Summary:** This alert identifies when a user has disabled an Azure audit stream within the Azure Devops service. This could indicate that an attacker is trying to hide malicious activity.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.azure.vm.unknown_events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.vm.unknown_events
select str(jqeval(jqcompile(".OperationName"), jsonparse(message))) as operationName
where eq(operationName,"AuditLog.StreamDisabledByUser")
select str(jqeval(jqcompile(".IpAddress"), jsonparse(message))) as entity_sourceIP
select str(jqeval(jqcompile(".ActorUPN"), jsonparse(message))) as entity_sourceAccount
select str(jqeval(jqcompile(".Id"), jsonparse(message))) as streamId
select str(jqeval(jqcompile("._Internal_WorkspaceResourceId"), jsonparse(message))) as workspaceId
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, streamId, workspaceId, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureDevOpsAuditDisabled") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureDevOpsAuditDisabled") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureDevOpsAuditDisabled") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureDevOpsAuditDisabled") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureDevOpsPATMisuse

**Summary:** This alert identifies specific actions that are not usually performed using a PAT.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Resource Hijacking (T1496)

**Tables:** cloud.azure.vm.unknown_events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.vm.unknown_events
select str(jqeval(jqcompile(".OperationName"), jsonparse(message))) as operationName
where toktains(operationName,"Security.",true,true) or toktains(operationName,"Project.",true,true) or toktains(operationName,"AuditLog.",true,true) or toktains(operationName,"Extension.",true,true) or toktains(operationName,"Group.UpdateGroupMembership.Add",true,true) or toktains(operationName,"Library.ServiceConnectionExecuted",true,true) or toktains(operationName,"Pipelines.PipelineModified",true,true) or toktains(operationName,"Release.ReleasePipelineModified",true,true) or toktains(operationName,"Git.RefUpdatePoliciesBypassed",true,true)
select str(jqeval(jqcompile(".AuthenticationMechanism"), jsonparse(message))) as AuthenticationMechanism
where startswith(AuthenticationMechanism, "SessionToken_Unscoped") or startswith(AuthenticationMechanism, "PAT_Unscoped")
select str(jqeval(jqcompile(".IpAddress"), jsonparse(message))) as entity_sourceIP
select str(jqeval(jqcompile(".ActorUPN"), jsonparse(message))) as entity_sourceAccount
select str(jqeval(jqcompile(".Id"), jsonparse(message))) as streamId
select str(jqeval(jqcompile("._Internal_WorkspaceResourceId"), jsonparse(message))) as workspaceId
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, streamId, workspaceId, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureDevOpsPATMisuse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureDevOpsPATMisuse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureDevOpsPATMisuse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureDevOpsPATMisuse") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureDevOpsProjectVisibilityChanged

**Summary:** This alert identifies when an Azure DevOps project visibility has been set to public. This action should be reviewed since it could be undermining the security posture of the company.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Resource Hijacking (T1496)

**Tables:** cloud.azure.vm.unknown_events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.vm.unknown_events
select str(jqeval(jqcompile(".OperationName"), jsonparse(message))) as operationName
where eq(operationName,"Project.UpdateVisibilityCompleted")
select str(jqeval(jqcompile(".Data.ProjectVisibility"), jsonparse(message))) as ProjectVisibility
where eq(ProjectVisibility,"public")
select str(jqeval(jqcompile(".Data.ProjectName"), jsonparse(message))) as ProjectName
select str(jqeval(jqcompile(".IpAddress"), jsonparse(message))) as entity_sourceIP
select str(jqeval(jqcompile(".ActorUPN"), jsonparse(message))) as entity_sourceAccount
select str(jqeval(jqcompile(".Id"), jsonparse(message))) as streamId
select str(jqeval(jqcompile("._Internal_WorkspaceResourceId"), jsonparse(message))) as workspaceId
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, streamId, workspaceId, ProjectName, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureDevOpsProjectVisibilityChanged") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureDevOpsProjectVisibilityChanged") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureDevOpsProjectVisibilityChanged") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureDevOpsProjectVisibilityChanged") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureDevOpsPublicUpstreamSourceAdded

**Summary:** This alert identifies when an external upstream has been added to an Azure DevOps feed. This action should be reviewed since a threat actor could be trying to inject malicious packages into an Azure DevOps pipeline.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Resource Hijacking (T1496)

**Tables:** cloud.azure.vm.unknown_events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.vm.unknown_events
select str(jqeval(jqcompile(".OperationName"), jsonparse(message))) as operationName
where eq(operationName,"Artifacts.Feed.Org.Modify") or eq(operationName,"Artifacts.Feed.Project.Modify")
select str(jqeval(jqcompile(".Details"), jsonparse(message))) as Details
where toktains(Details,"UpstreamSources, added",true,true)
select jqeval(jqcompile(".Data.UpstreamsAdded"), jsonparse(message)) as upstreamsAdded
select str(jqeval(jqcompile(".[0].UpstreamSourceType"), upstreamsAdded)) as upstreamType_1
select str(jqeval(jqcompile(".[1].UpstreamSourceType"), upstreamsAdded)) as upstreamType_2
select str(jqeval(jqcompile(".[2].UpstreamSourceType"), upstreamsAdded)) as upstreamType_3
select str(jqeval(jqcompile(".[3].UpstreamSourceType"), upstreamsAdded)) as upstreamType_4
select str(jqeval(jqcompile(".[4].UpstreamSourceType"), upstreamsAdded)) as upstreamType_5
where eq(upstreamType_1,"public") or eq(upstreamType_2,"public") or eq(upstreamType_3,"public") or eq(upstreamType_4,"public") or eq(upstreamType_5,"public")
select str(jqeval(jqcompile(".IpAddress"), jsonparse(message))) as entity_sourceIP
select str(jqeval(jqcompile(".ActorUPN"), jsonparse(message))) as entity_sourceAccount
select str(jqeval(jqcompile(".Id"), jsonparse(message))) as streamId
select str(jqeval(jqcompile("._Internal_WorkspaceResourceId"), jsonparse(message))) as workspaceId
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, streamId, workspaceId, upstreamsAdded, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureDevOpsPublicUpstreamSourceAdded") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureDevOpsPublicUpstreamSourceAdded") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureDevOpsPublicUpstreamSourceAdded") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureDevOpsPublicUpstreamSourceAdded") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureDevOpsSecretNotSecured

**Summary:** This alert identifies when a user has insecurely stored a new variable in Azure Devops that could be containing credentials.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Unsecured Credentials (T1552)

**Tables:** cloud.azure.vm.unknown_events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.vm.unknown_events
select str(jqeval(jqcompile(".OperationName"), jsonparse(message))) as operationName
where eq(operationName,"Library.VariableGroupModified")
select stringify(jqeval(jqcompile(".Data.Variables"), jsonparse(message))) as Variables
where (weaktoktains(Variables,"secret",true,true) or weaktoktains(Variables,"secrets",true,true) or weaktoktains(Variables,"password",true,true) or toktains(Variables,"PAT",true,true) or weaktoktains(Variables,"passwd",true,true) or weaktoktains(Variables,"pswd",true,true) or weaktoktains(Variables,"pwd",true,true) or weaktoktains(Variables,"cred",true,true) or weaktoktains(Variables,"creds",true,true) or weaktoktains(Variables,"credentials",true,true) or weaktoktains(Variables,"credential",true,true) or weaktoktains(Variables,"key",true,true)) and not weaktoktains(Variables,"IsSecret",true,true)
select str(jqeval(jqcompile(".IpAddress"), jsonparse(message))) as entity_sourceIP
select str(jqeval(jqcompile(".ActorUPN"), jsonparse(message))) as entity_sourceAccount
select str(jqeval(jqcompile(".Id"), jsonparse(message))) as streamId
select str(jqeval(jqcompile("._Internal_WorkspaceResourceId"), jsonparse(message))) as workspaceId
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, streamId, workspaceId, Variables, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureDevOpsSecretNotSecured") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureDevOpsSecretNotSecured") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureDevOpsSecretNotSecured") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureDevOpsSecretNotSecured") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureExternalUserInvitationRedeemed

**Summary:** An adversary can create a new Azure AD account by redeeming an invitation for an external user. This may be a routine activity, but could be used as a vector for an adversary to gain access or persistence.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.azure.ad.audit
select properties_category
select operationName
select properties_result
select properties_initiatedBy_user_userPrincipalName as entity_sourceAccount
where eq(properties_category, "UserManagement") and eq(operationName, "Redeem external user invite") and eq(properties_result, "success") and isnotnull(entity_sourceAccount)
group every 5m by properties_category, operationName, properties_result, entity_sourceAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureExternalUserInvitationRedeemed") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureExternalUserInvitationRedeemed") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureExternalUserInvitationRedeemed") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureExternalUserInvitationRedeemed") as alertPriority
```

## SecOpsAzureExternalUserInvited

**Summary:** An adversary could create an invitation for an external user to create a new account in Azure AD. This may be a routine activity but could be used as a vector for an adversary to gain access or persistence.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.audit
select properties_category
select operationName
select properties_result
select callerIpAddress as entity_sourceIP
select properties_initiatedBy_user_userPrincipalName as entity_sourceAccount
select str(jqeval(jqcompile(".properties.additionalDetails[5].value"), jsonparse(rawMessage))) as entity_destinationAccount
where eq(properties_category, "UserManagement") and eq(operationName, "Invite external user") and eq(properties_result, "success")
group every 5m by properties_category, operationName, properties_result, entity_sourceIP, entity_sourceAccount, entity_destinationAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureExternalUserInvited") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureExternalUserInvited") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureExternalUserInvited") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureExternalUserInvited") as alertPriority
```

## SecOpsAzureFrontDoorWafPolicyDeletion

**Summary:** This alert identifies when a user has deleted a web application firewall policy. Although this is a common operation, it should be checked since it could be undermining the security posture of the Azure account.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.azure.activity.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.activity.events
where eq(operationName,"MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE")
where eq(resultType,"Success")
select callerIpAddress as entity_sourceIP
select stringify(jqeval(jqcompile(".identity.claims"), jsonparse(rawMessage))) as claim
select split(split(split(claim, "claims/upn", 1),":",1),",",0) as entity_sourceAccount
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureFrontDoorWafPolicyDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureFrontDoorWafPolicyDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureFrontDoorWafPolicyDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureFrontDoorWafPolicyDeletion") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureFWPolicyDeletion

**Summary:** This alert identifies when a user has deleted a firewall policy. Although this is a common operation, it should be checked since it could be undermining the security posture of the Azure account.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** cloud.azure.eh.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.eh.events
where eq(operationName,"MICROSOFT.NETWORK/APPLICATIONGATEWAYWEBAPPLICATIONFIREWALLPOLICIES/DELETE")
where eq(resultType,"Success")
select stringify(jqeval(jqcompile(".identity.claims"), jsonparse(rawMessage))) as claim
select split(split(split(claim, "claims/upn", 1),":",1),",",0) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureFWPolicyDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureFWPolicyDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureFWPolicyDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureFWPolicyDeletion") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureGroupInformationDownload

**Summary:** An adversary could download group information to learn about the environment.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Permission Groups Discovery (T1069)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.azure.ad.audit
where weakhas(operationName, "download group") and properties_result = "success"
select properties_initiatedBy_user_userPrincipalName as entity_sourceAccount
group every 5m by region, operationName, properties_result, resultDescription, entity_sourceAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureGroupInformationDownload") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureGroupInformationDownload") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureGroupInformationDownload") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureGroupInformationDownload") as alertPriority
```

## SecOpsAzureHybridHealthADFSDelete

**Summary:** This alert identifies when a user has deleted an Azure AD Hybrid health AD FS service instance. A malicious user could have been using a fake AD FS service to spoof AD FS signing logs and is deleting it since it is no longer needed.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Cloud Compute Infrastructure (T1578)

**Tables:** cloud.azure.others.administrative

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.others.administrative
where eq(category,"Administrative")
where weaktoktains(resourceId,"Microsoft.ADHybridHealthService")
where eqic(operationName,"Microsoft.ADHybridHealthService/services/delete")
where eqic(resultType,"Success")
select str(jqeval(jqcompile(".identity.claims.name"), jsonparse(rawMessage))) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureHybridHealthADFSDelete") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureHybridHealthADFSDelete") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureHybridHealthADFSDelete") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureHybridHealthADFSDelete") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureHybridHealthADFSNewServer

**Summary:** This alert identifies when a user has updated or created a server instance in an Azure AD Hybrid health AD FS service, this should be checked since it could be undermining the security posture of the environment.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Cloud Compute Infrastructure (T1578)

**Tables:** cloud.azure.others.administrative

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.others.administrative
where eq(category,"Administrative")
where weaktoktains(resourceId,"Microsoft.ADHybridHealthService")
where eqic(operationName,"Microsoft.ADHybridHealthService/services/servicemembers/action")
where eqic(resultType,"Success")
select str(jqeval(jqcompile(".identity.claims.name"), jsonparse(rawMessage))) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureHybridHealthADFSNewServer") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureHybridHealthADFSNewServer") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureHybridHealthADFSNewServer") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureHybridHealthADFSNewServer") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureImpossibleTravel

**Summary:** An adversary could obtain and abuse credentials of existing accounts as a means of gaining Initial Access. Compromised credentials may be used to bypass access controls and for persistent access to remote systems and external services.

**Description:** An adversary may compromise credentials to gain initial access and maintain persistence by bypassing controls.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.azure.ad.signin

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.signin
select properties_userPrincipalName
where operationName = "Sign-in activity" and isnotnull(location)
group every 1h by properties_userPrincipalName, hostname, client
every 1h
select int(hllppcount(location)) as distinct_countries
where distinct_countries >= 2
select properties_userPrincipalName as entity_sourceAccount
select last(operationName) as activity_type
select last(properties_resourceDisplayName) as platform
select last(identity) as userName
select last(callerIpAddress) as entity_sourceIP
select last(location) as countryCode
select collect(properties_location_geoCoordinates_latitude) as properties_location_geoCoordinates_latitude_list
select collect(properties_location_geoCoordinates_longitude) as properties_location_geoCoordinates_longitude_list
select collect(location) as countrycode_list
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureImpossibleTravel") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureImpossibleTravel") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureImpossibleTravel") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureImpossibleTravel") as alertPriority
```

## SecOpsAzureNWDeviceModified

**Summary:** This alert identifies when a user has modified network device such as network virtual appliance, virtual hub or virtual router. Although this is a common operation, it should be checked since it could be undermining the security posture of the Azure account.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Service Stop (T1489)

**Tables:** cloud.azure.activity.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.activity.events
where operationName in ["MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE","MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE","MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE","MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION","MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE","MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE","MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE","MICROSOFT.NETWORK/VIRTUALHUBS/DELETE","MICROSOFT.NETWORK/VIRTUALHUBS/WRITE","MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE","MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE"]
where eq(resultType,"Success")
select callerIpAddress as entity_sourceIP
select stringify(jqeval(jqcompile(".identity.claims"), jsonparse(rawMessage))) as claim
select split(split(split(claim, "claims/upn", 1),":",1),",",0) as entity_sourceAccount
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureNWDeviceModified") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureNWDeviceModified") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureNWDeviceModified") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureNWDeviceModified") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureUserAddedNonAdminRole

**Summary:** An adversary could escalate privileges by adding an account to a role.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.audit
select ifthenelse(isnull(callerIpAddress), "Source IP Address not pressent in log", callerIpAddress) as entity_sourceIP
select operationName
select properties_result as result
select properties_initiatedBy_user_userPrincipalName as entity_sourceAccount
select str(jqeval(jqcompile(".[0].displayName"), properties_targetResources)) as roleName
select str(jqeval(jqcompile(".[2].displayName"), properties_targetResources)) as modifiedUser
where startswith(operationName, "Add member to role") and roleName /= "Member" and properties_result = "success" and not has(roleName, "Administrator") and isnotnull(modifiedUser)
group every 5m by entity_sourceIP, entity_sourceAccount, operationName, result, roleName, modifiedUser, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserAddedNonAdminRole") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserAddedNonAdminRole") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserAddedNonAdminRole") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserAddedNonAdminRole") as alertPriority
```

## SecOpsAzureUserAddedOutsidePIMRole

**Summary:** An adversary could escalate privileges or attempt to persist by adding an account to a role outside of Privilege Identity Management (PIM) in Azure AD.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.audit
select callerIpAddress as entity_sourceIP
select identity as entity_sourceAccount
select operationName
select properties_result
select properties_initiatedBy_app_displayName as initiatedByApp
select str(jqeval(jqcompile(".properties.targetResources[0].userPrincipalName"), jsonparse(rawMessage))) as modifiedUser
select str(jqeval(jqcompile(".properties.targetResources[0].modifiedProperties[1].newValue"), jsonparse(rawMessage))) as assignedRole
where startswith(operationName, "Add member to role") and properties_initiatedBy_app_displayName /= "MS-PIM" and not has(operationName, "PIM") and properties_result = "success"
group every 5m by entity_sourceIP, entity_sourceAccount, operationName, properties_result, initiatedByApp, modifiedUser, assignedRole, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserAddedOutsidePIMRole") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserAddedOutsidePIMRole") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserAddedOutsidePIMRole") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserAddedOutsidePIMRole") as alertPriority
```

## SecOpsAzureUserAddedToGlobalAdminRole

**Summary:** An adversary could escalate privileges or attempt to persist by adding an account to a Global Administrator role in Azure AD.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.audit
select properties_initiatedBy_user_userPrincipalName as entity_sourceAccount
select operationName
select properties_result
select str(jqeval(jqcompile(".properties.additionalDetails[9].value"), jsonparse(rawMessage))) as entity_sourceIP
select str(jqeval(jqcompile(".properties.targetResources[2].userPrincipalName"), jsonparse(rawMessage))) as modifiedUser
select str(jqeval(jqcompile(".properties.targetResources[0].displayName"), jsonparse(rawMessage))) as assignedRole
where startswith(operationName, "Add member to role") and properties_result = "success" and assignedRole = "Global Administrator" and isnotnull(modifiedUser)
group every 5m by entity_sourceIP, entity_sourceAccount, operationName, properties_result, modifiedUser, assignedRole, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserAddedToGlobalAdminRole") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserAddedToGlobalAdminRole") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserAddedToGlobalAdminRole") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserAddedToGlobalAdminRole") as alertPriority
```

## SecOpsAzureUserAddedToRoleNonPIM

**Summary:** Detects actions to add new users to roles.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator

```linq
from cloud.azure.ad.audit
where startswith(operationName, "Add member to role") and not endswith(operationName, "PIM activation)")
select callerIpAddress as entity_sourceIP
group every 1h by region, tenantId, operationName, entity_sourceIP, properties_result, properties_resultReason, properties_operationType,  properties_initiatedBy_user_displayName, properties_initiatedBy_user_userPrincipalName, properties_targetResources, client
select jqeval(jqcompile(".[0].modifiedProperties[1].newValue"), properties_targetResources) as roleType
select jqeval(jqcompile(".[0].displayName"), properties_targetResources) as roleName
where not has(stringify(roleType), "Administrator") and not has(stringify(roleName), "Administrator")
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserAddedToRoleNonPIM") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserAddedToRoleNonPIM") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserAddedToRoleNonPIM") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserAddedToRoleNonPIM") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureUserConfirmedCompromised

**Summary:** An adversary could obtain and abuse credentials of existing accounts as a means of gaining Initial Access. Compromised credentials may be used to bypass access controls and for persistent access to remote systems and external services.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.azure.ad.signin

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.signin
select operationName
select identity
select properties_userPrincipalName as entity_sourceAccount
select callerIpAddress as entity_sourceIP
select properties_appDisplayName
select properties_clientAppUsed
select properties_riskLevelDuringSignIn
select properties_riskDetail
select properties_riskState
where eq(operationName, "Sign-in activity") and eq(properties_riskDetail, "adminConfirmedSigninCompromised") and eq(properties_riskState, "confirmedCompromised")
group every 5m by operationName, identity, entity_sourceIP, entity_sourceAccount, properties_appDisplayName, properties_clientAppUsed, properties_riskLevelDuringSignIn, properties_riskDetail, properties_riskState, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserConfirmedCompromised") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserConfirmedCompromised") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserConfirmedCompromised") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserConfirmedCompromised") as alertPriority
```

## SecOpsAzureUserCreated

**Summary:** An adversary could attempt to persist by creating a user account in Azure AD.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.azure.ad.audit
select properties_initiatedBy_user_userPrincipalName as entity_sourceAccount
select properties_category
select operationName
select str(jqeval(jqcompile(".properties.targetResources[0].userPrincipalName"), jsonparse(rawMessage))) as entity_destinationAccount
select properties_result
where properties_category = "UserManagement" and operationName = "Add user" and properties_result = "success"
group every 5m by entity_sourceAccount, properties_category, operationName, entity_destinationAccount, properties_result, client
every 5m
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserCreated") as alertPriority
```

## SecOpsAzureUserHighAggregateRiskSignIn

**Summary:** An adversary could obtain and abuse credentials of existing accounts as a means of gaining Initial Access. Compromised credentials may be used to bypass access controls and for persistent access to remote systems and external services.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.azure.ad.signin

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.signin
select operationName
select callerIpAddress as entity_sourceIP
select properties_userPrincipalName as entity_sourceAccount
select identity
select properties_riskLevelAggregated
where eq(operationName, "Sign-in activity") and eq(properties_riskLevelAggregated, "high")
group every 5m by operationName, entity_sourceIP, entity_sourceAccount, identity, properties_riskLevelAggregated, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserHighAggregateRiskSignIn") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserHighAggregateRiskSignIn") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserHighAggregateRiskSignIn") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserHighAggregateRiskSignIn") as alertPriority
```

## SecOpsAzureUserHighRiskSignIn

**Summary:** An adversary could obtain and abuse credentials of existing accounts as a means of gaining Initial Access. Compromised credentials may be used to bypass access controls and for persistent access to remote systems and externally services.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.azure.ad.signin

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.signin
select operationName
select callerIpAddress as entity_sourceIP
select properties_userPrincipalName as entity_sourceAccount
select identity
select properties_riskDetail
select properties_riskLevelDuringSignIn
where eq(operationName, "Sign-in activity") and eq(properties_riskLevelDuringSignIn, "high")
group every 5m by operationName, entity_sourceIP, entity_sourceAccount, identity, properties_riskDetail, properties_riskLevelDuringSignIn, hostname,  client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserHighRiskSignIn") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserHighRiskSignIn") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserHighRiskSignIn") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserHighRiskSignIn") as alertPriority
```

## SecOpsAzureUserInfoDownload

**Summary:** Detects downloads of user information from the Azure AD Portal.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Account Discovery (T1087)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator

```linq
from cloud.azure.ad.audit
where toktains(operationName, "Download users")
select properties_initiatedBy_user_userPrincipalName as entity_sourceName
select callerIpAddress as entity_sourceIP
group every 1h by region, tenantId, operationName, properties_result, resultDescription, entity_sourceName, entity_sourceIP, client
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserInfoDownload") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserInfoDownload") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserInfoDownload") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserInfoDownload") as alertPriority
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```

## SecOpsAzureUserInformationDownload

**Summary:** An adversary may attempt to get a listing of accounts on a system or within an environment.

**Description:** An adversary may attempt to get a listing and more information about accounts on a system or within an environment.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Account Discovery (T1087)

**Tables:** cloud.azure.ad.audit

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from cloud.azure.ad.audit
where weakhas(operationName, "download user") and properties_result = "success"
select properties_initiatedBy_user_userPrincipalName as entity_sourceAccount
group every 5m by region, operationName, properties_result, resultDescription, entity_sourceAccount, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserInformationDownload") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserInformationDownload") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserInformationDownload") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserInformationDownload") as alertPriority
```

## SecOpsAzureUserLoginSuspiciousRisk

**Summary:** An adversary could obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** cloud.azure.ad.signin

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from cloud.azure.ad.signin
where operationName = "Sign-in activity" and properties_riskState = "atRisk"
select callerIpAddress as entity_sourceIP
select properties_userPrincipalName as entity_sourceAccount
select identity
select properties_clientAppUsed
select properties_userAgent
select operationName
select properties_appDisplayName as destinationApp
select properties_riskState
select Level as riskLevel
select resultDescription
group every 5m by entity_sourceIP, entity_sourceAccount, identity, properties_clientAppUsed, properties_userAgent, operationName, destinationApp, properties_riskState, riskLevel, resultDescription, hostname, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureUserLoginSuspiciousRisk") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureUserLoginSuspiciousRisk") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureUserLoginSuspiciousRisk") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureUserLoginSuspiciousRisk") as alertPriority
```

## SecOpsAzureVMCmdEXE

**Summary:** This alert identifies a command execution on a virtual machine. This should be checked in order to verify that the command is not undermining the security posture of the virtual machine.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** cloud.azure.activity.events

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, SecOpsLocation, mispIndicator

```linq
from cloud.azure.activity.events
where eq(operationName,"MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION")
where eq(resultType,"Success")
select stringify(jqeval(jqcompile(".identity.claims"), jsonparse(rawMessage))) as claim
select split(split(split(claim, "claims/upn", 1),":",1),",",0) as entity_sourceAccount
select callerIpAddress as entity_sourceIP
group every 5m by entity_sourceIP, operationName, entity_sourceAccount, resourceId , client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAzureVMCmdEXE") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAzureVMCmdEXE") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAzureVMCmdEXE") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAzureVMCmdEXE") as alertPriority
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
```
