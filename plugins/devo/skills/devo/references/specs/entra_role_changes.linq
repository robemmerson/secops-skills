from cloud.azure.ad.audit
where properties_category in {"RoleManagement", "ResourceManagement"}
select stringify(properties_targetResources) as targets, stringify(properties_additionalDetails) as details
select eventdate, tenantId, properties_id, properties_category, properties_loggedByService, operationName, properties_result, properties_resultReason, properties_initiatedBy_user_userPrincipalName, properties_initiatedBy_app_displayName, targets, details
