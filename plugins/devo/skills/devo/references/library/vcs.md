# Detection library: VCS

Version control system (GitHub organization audit) detections. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (21):

- SecOpsGithubActionsSecretDeletedForRepo
- SecOpsGithubAdvancedSecurityDisabled
- SecOpsGithubBranchProtectionDisabled
- SecOpsGithubDeleteActionInvoked
- SecOpsGithubHighRiskConfigurationDisabled
- SecOpsGithubNewAppAddedToGitHubEnterpriseOrganization
- SecOpsGithubNewSecretCreated
- SecOpsGithubOrganizationPermissionChange
- SecOpsGithubOrgSensitiveChangeActions
- SecOpsGithubOutdatedDependencyOrVulnerabilityAlertDisabled
- SecOpsGithubOutsideCollaboratorDetected
- SecOpsGithubPreReceiveHookDisabled
- SecOpsGithubRepoDestroy
- SecOpsGithubRepoVisibilityChange
- SecOpsGithubSecretScanning
- SecOpsGithubSecretScanningGeneral
- SecOpsGithubSponsorsCategoryActions
- SecOpsGithubThreeOrMoreRepoDownloadbySameUserWithinOneHour
- SecOpsGithubUserOauthChangePersonalAccessToken
- SecOpsGithubUserPublicKeyChangesSSHKeyManipulation
- SecOpsGithubWorkflowDisabled

## SecOpsGithubActionsSecretDeletedForRepo

**Summary:** A secret used in GitHub Actions has been deleted from a repository.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "repo.remove_actions_secret"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsGithubAdvancedSecurityDisabled

**Summary:** GitHub Advanced Security features have been disabled.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "repo.advanced_security_disabled"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubBranchProtectionDisabled

**Summary:** Branch protection rules have been disabled on a repository.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "protected_branch.destroy"))
group every 5m by action, repository, user, head_branch, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubDeleteActionInvoked

**Summary:** A repository delete action has been performed.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "codespaces.delete")
or eq(action, "environment.delete")
or eq(action, "project.delete")
or eq(action, "repo.destroy"))
group every 5m by user, head_branch, action, repository, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Impact" as alertMitreTactics
select "Data Destruction" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubHighRiskConfigurationDisabled

**Summary:** A high-security risk configuration setting has been disabled.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "pre_receive_hook.enforcement")
or eq(action, "org.advanced_security_policy_selected_member_disabled"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubNewAppAddedToGitHubEnterpriseOrganization

**Summary:** A new GitHub app has been added to the enterprise organization.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Account Discovery (T1087)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "integration_installation.repositories_added"))
group every 5m by user, head_branch, action, repository, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Discovery" as alertMitreTactics
select "Account Discovery" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsGithubNewSecretCreated

**Summary:** A new secret (like an API key or token) has been added to a repository.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Unsecured Credentials (T1552)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "org.create_actions_secret")
or eq(action, "environment.create_actions_secret")
or eq(action, "codespaces.create_an_org_secret")
or eq(action, "repo.create_actions_secret"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Credential Access" as alertMitreTactics
select "Unsecured Credentials" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubOrganizationPermissionChange

**Summary:** Permissions within the GitHub organization have been altered.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "org.update_default_repository_permission"))
group every 5m by user, head_branch, action, repository, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Discovery" as alertMitreTactics
select "Permission Groups Discovery" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubOrgSensitiveChangeActions

**Summary:** Sensitive changes within the organization have been detected.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Domain Policy Modification (T1484)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "org.disable_two_factor_requirement")
or eq(action, "org.enable_member_team_creation_permission")
or eq(action, "org.oauth_app_access_approved")
or eq(action, "members_can_delete_repos.disable")
or eq(action, "org.update_default_repository_permission")
or eq(action, "organization_domain.create")
or eq(action, "oauth_application.create")
or eq(action, "integration_installation.repositories_added")
or eq(action, "org.disable_oauth_app_restrictions")
or eq(action, "org.update_actions_settings")
or eq(action, "org.create_actions_secret")
or eq(action, "dependency_graph.disable")
or eq(action, "dependabot_security_updates_new_repos.disable")
or eq(action, "org.update_actions_settings"))
group every 5m by user, head_branch, action, repository, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Privilege Escalation" as alertMitreTactics
select "Domain or Tenant Policy Modification" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubOutdatedDependencyOrVulnerabilityAlertDisabled

**Summary:** Indicates a dependency is outdated or vulnerable has been disabled.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "dependabot_alerts.disable")
or eq(action, "dependabot_alerts_new_repos.disable")
or eq(action, "dependabot_security_updates.disable")
or eq(action, "dependabot_security_updates_new_repos.disable")
or eq(action, "repository_vulnerability_alerts.disable"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubOutsideCollaboratorDetected

**Summary:** An external collaborator has been added to a repository.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "project.update_user_permission")
or eq(action, "org.remove_outside_collaborator"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Initial Access" as alertMitreTactics
select "Valid Accounts" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsGithubPreReceiveHookDisabled

**Summary:** A pre-receive hook for security policy enforcement has been disabled.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "org.disable_oauth_app_restrictions")
or eq(action, "org.disable_two_factor_requirement")
or eq(action, "repo.advanced_security_disabled")
or eq(action, "org.advanced_security_policy_selected_member_disabled"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubRepoDestroy

**Summary:** A repository has been deleted from the organization.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "repo.destroy"))
group every 5m by user, head_branch, action, repository, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Impact" as alertMitreTactics
select "Data Destruction" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubRepoVisibilityChange

**Summary:** The visibility of a repository has been changed (e.g., private to public).

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "repo.access")
or eq(action, "repo.pages_private")
or eq(action, "repo.pages_public"))
group every 5m by user, head_branch, action, repository, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Discovery" as alertMitreTactics
select "Permission Groups Discovery" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsGithubSecretScanning

**Summary:** Secret scanning has detected exposed secrets..

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "repository_secret_scanning_push_protection.disable")
or eq(action, "repository_secret_scanning_push_protection.enable")
or eq(action, "repository_secret_scanning_custom_pattern_push_protection.enabled")
or eq(action, "repository_secret_scanning_custom_pattern_push_protection.disabled")
or eq(action, "repository_secret_scanning_custom_pattern.create")
or eq(action, "repository_secret_scanning_custom_pattern.delete")
or eq(action, "repository_secret_scanning_custom_pattern.update")
or eq(action, "repository_secret_scanning.disable")
or eq(action, "repository_secret_scanning.enable")
or eq(action, "business_secret_scanning_push_protection_custom_message.disable")
or eq(action, "business_secret_scanning_push_protection_custom_message.enable")
or eq(action, "business_secret_scanning_push_protection_custom_message.update")
or eq(action, "business_secret_scanning_push_protection.disable")
or eq(action, "business_secret_scanning_push_protection.enable")
or eq(action, "business_secret_scanning_push_protection.disabled_for_new_repos")
or eq(action, "business_secret_scanning_push_protection.enabled_for_new_repos")
or eq(action, "business_secret_scanning_custom_pattern_push_protection.enabled")
or eq(action, "business_secret_scanning_custom_pattern_push_protection.disabled")
or eq(action, "business_secret_scanning_custom_pattern.create")
or eq(action, "business_secret_scanning_custom_pattern.delete")
or eq(action, "business_secret_scanning_custom_pattern.update")
or eq(action, "business_secret_scanning.disable")
or eq(action, "business_secret_scanning.enable")
or eq(action, "business_secret_scanning.disabled_for_new_repos")
or eq(action, "business_secret_scanning.enabled_for_new_repos")
or eq(action, "business_secret_scanning_push_protection_custom_message.disable")
or eq(action, "business_secret_scanning_push_protection_custom_message.enable")
or eq(action, "business_secret_scanning_push_protection_custom_message.update")
or eq(action, "business_secret_scanning_push_protection.disable")
or eq(action, "business_secret_scanning_push_protection.enable")
or eq(action, "business_secret_scanning_push_protection.disabled_for_new_repos")
or eq(action, "business_secret_scanning_push_protection.enabled_for_new_repos")
or eq(action, "business_secret_scanning_custom_pattern_push_protection.enabled")
or eq(action, "business_secret_scanning_custom_pattern_push_protection.disabled"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubSecretScanningGeneral

**Summary:** An alert for potential secrets detected in the repository.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "secret_scanning.disable")
or eq(action, "secret_scanning.enable")
or eq(action, "secret_scanning_alert.create")
or eq(action, "secret_scanning_alert.reopen")
or eq(action, "secret_scanning_alert.resolve")
or eq(action, "secret_scanning_new_repos.disable")
or eq(action, "secret_scanning_new_repos.enable")
or eq(action, "bypass"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsGithubSponsorsCategoryActions

**Summary:** Actions related to the GitHub Sponsors feature have been detected.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "sponsors.agreement_sign")
or eq(action, "sponsors.custom_amount_settings_change")
or eq(action, "sponsors.fiscal_host_change")
or eq(action, "sponsors.withdraw_agreement_signature")
or eq(action, "sponsors.repo_funding_links_file_action")
or eq(action, "sponsors.sponsor_sponsorship_cancel")
or eq(action, "sponsors.sponsor_sponsorship_create")
or eq(action, "sponsors.sponsor_sponsorship_payment_complete")
or eq(action, "sponsors.sponsor_sponsorship_preference_change")
or eq(action, "sponsors.sponsor_sponsorship_tier_change")
or eq(action, "sponsors.sponsored_developer_approve")
or eq(action, "sponsors.sponsored_developer_create")
or eq(action, "sponsors.sponsored_developer_disable")
or eq(action, "sponsors.sponsored_developer_profile_update")
or eq(action, "sponsors.sponsored_developer_redraft")
or eq(action, "sponsors.sponsored_developer_request_approval")
or eq(action, "sponsors.sponsored_developer_tier_description_update")
or eq(action, "sponsors.update_tier_welcome_message")
or eq(action, "sponsors.update_tier_repository"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Initial Access" as alertMitreTactics
select "Valid Accounts" as alertMitreTechniques
select 2 as alertPriority
```

## SecOpsGithubThreeOrMoreRepoDownloadbySameUserWithinOneHour

**Summary:** Multiple repositories have been downloaded by the same user in a short time.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "repo.download_zip"))
group every 1h by actor, repository, client
where gt(count(),2)
select actor as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Exfiltration" as alertMitreTactics
select "Exfiltration Over Alternative Protocol" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsGithubUserOauthChangePersonalAccessToken

**Summary:** A user's OAuth or personal access token has been changed.

**MITRE:** Tactics: Lateral Movement (TA0004) | Techniques: Use Alternate Authentication Material (T1550)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "oauth_access.create")
or eq(action, "oauth_authorization.update")
or eq(action, "oauth_authorization.destroy"))
group every 5m by user, head_branch, action, repository, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Lateral Movement" as alertMitreTactics
select "Use Alternate Authentication Material" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsGithubUserPublicKeyChangesSSHKeyManipulation

**Summary:** A user’s public SSH key has been changed or added.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "ssh_certificate_authority.create")
or eq(action, "ssh_certificate_authority.destroy")
or eq(action, "ssh_certificate_requirement.enable")
or eq(action, "ssh_certificate_requirement.disable")
or eq(action, "public_key.create")
or eq(action, "public_key.update"))
group every 5m by action, repository, user, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Initial Access" as alertMitreTactics
select "Valid Accounts" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsGithubWorkflowDisabled

**Summary:** A workflow has been disabled in a repository.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Impair Defenses (T1562)

**Tables:** vcs.github.organization.audit

**Lookups:** SecOpsAssetRole

```linq
from vcs.github.organization.audit
where (eq(action, "workflows.disable_workflow"))
group every 5m by action, repository, user, head_branch, client
select user as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Impair Defenses" as alertMitreTechniques
select 4 as alertPriority
```
