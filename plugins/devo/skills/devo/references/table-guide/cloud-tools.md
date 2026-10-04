# Cloud, developer and security tools

Generic parser knowledge. Your domain may differ: confirm fields with `devo.py fields <table>` before relying on a detail.

Contents:

- AWS CloudTrail (`cloud.aws.cloudtrail.<service>`, one table per service)
- GitHub (`vcs.github.enterprise.audit`, `vcs.github.organization.audit`)
- 1Password (`auth.agilebits.onepassword.signinattempt`, `.audit`, `.itemusage`)
- SentinelOne (`edr.sentinelone.agent.agents`, `.agent.threats`, `.management.activities`)
- Qualys (`vuln.qualys.hosts`, `.hostdetections`, `.vulnerabilities`, `.useractivitylog`)
- Devo platform and other tables

Placeholders: `jsmith@example.com` (a UPN), `smith` (a surname), `HOST01`/`host01`, `10.1.2.3`
(an internal IP), `203.0.113.10` (a public IP), `<THREAT_ID>`, `<HOST_ID>`, `<QID>`, `<ALERT_ID>`.
Use `devo.py tables` to see which of these tables your domain actually has.

Speed: most tables in this family answer quickly over days or weeks. High-volume service tables
(typically `cloud.aws.cloudtrail.s3`) and the `from cloud.aws.cloudtrail` parent prefix are
slow: a parent-prefix query with a filter can fail to finish even over a short window, while the
same filter run on each service table separately (in parallel) returns quickly.

## AWS CloudTrail (`cloud.aws.cloudtrail.<service>`)

**One row = one CloudTrail record** (API call, console sign-in or service event) for one
service. A cross-account call shows up **twice**, once in each account (`ACCID`). The two rows
share `sharedEventID` and `requestID` but have different `eventID`s, so count on `eventID`
within one `ACCID`.

**Fields every table has:** `eventdate`, `ACCID` (12-digit account that logged the event; the
same as `recipientAccountId`), `REGION`/`awsRegion`, `eventSource` (`<svc>.amazonaws.com`),
`eventName`, `eventType` (`AwsApiCall`, `AwsConsoleSignIn`, `AwsServiceEvent`), `eventID`,
`userAgent`, `eventVersion`. Almost all also have `eventTime` (not `events`), `requestID` (not
`signin`), `userIdentity_type/_arn/_principalId/_accountId` and `sourceIPAddress`.

The field sets fall into these groups:

| Group | Tables | What differs |
|---|---|---|
| Rich | s3, kms, lambda, sts, ec2, dynamodb, logs, iam, rds, ssm, cloudtrail, monitoring, secretsmanager, sns, sqs, tagging, elasticloadbalancing, autoscaling, cloudformation, organizations, route53, redshift, kinesis, ecr, ce, cloudfront, health, compute_optimizer, resource_groups, application_insights, signin | Have `rawMessage` (the full JSON record: `weakhas(rawMessage, …)` and `jsonparse(rawMessage)["…"]` reach anything the parser dropped). `userIdentity_sessionContext_sessionIssuer` / `_attributes` are JSON. Service-specific `requestParameters_*` / `responseElements_*` columns. |
| Generic | every other service (xray, states, ecs, codedeploy, elasticache, apigateway, backup, glue, athena, …) | The same small column set everywhere. **No `rawMessage` and no `errorCode`/`errorMessage`**, so failed calls can't be told apart from successful ones. `requestParameters`, `responseElements`, `resources`, `additionalEventData` and `userIdentity_sessionContext` are whole JSON columns (use `stringify()`). Has `readOnly`. |
| Odd names | `eks`, `secretsmanager` | `userIdentity__arn`, `userIdentity__type`, `userIdentity__sessionContext__sessionIssuer__userName` (double underscore). **`userIdentity_arn` is an unknown identifier there.** |
| | `secretsmanager`, `ecr` | `sourceIPAddress_str` instead of `sourceIPAddress` |
| | `events` | no `eventTime` |

- **`errorCode` exists in only some tables:** autoscaling, compute_optimizer, ec2, events, health,
  iam, kms, lambda, logs, organizations, rds, redshift, resource_groups, s3, ses, sqs, ssm,
  tagging. Using it anywhere else fails the query (`Unknown identifier`). Check with
  `devo.py fields <table>`.
  - **`sts` has no `errorCode`, but failed AssumeRole calls are there** (causes include
    `AccessDenied` on the trust policy, expired tokens, or e.g. `RegionDisabledException` when STS
    is called in a disabled region). Get them from `rawMessage` (recipe below).
  - `signin` has `errorMessage` but no `errorCode`. Typical values: `Failed authentication`,
    `No username found in supplied account`, `Failed authorizeOAuth2Access`,
    `Assertion is no longer valid`.
- `readOnly` is missing from a number of tables, including `iam`, `sts`, `signin`, `ec2`,
  `lambda`, `logs`, `rds`, `sns` and `sqs`.

**`userIdentity_type`** (enum): `AssumedRole` (usually most traffic), `AWSService`, `AWSAccount`
(a principal in another account, with no arn), `IAMUser`, `Root`, `SAMLUser`, `WebIdentityUser`,
`IdentityCenterUser` (only in `signin`), `Unknown`.

**`userIdentity_arn` forms:**
- A human through IAM Identity Center (SSO):
  `arn:aws:sts::<acct>:assumed-role/AWSReservedSSO_<permission-set>_<16 hex>/<session>`. With
  a typical IdP setup the **session name is the person's UPN** (`jsmith@example.com`, as typed
  in the IdP). Then `weakhas(userIdentity_arn, "smith")` finds a person's API calls in every
  table. The same person can appear under several accounts and permission sets.
- Workloads: `assumed-role/<role>/<session>`, where the session is an EC2 instance id
  (`i-0…`), a Lambda function name, a tool name, or an SDK default such as `botocore-session-…`.
- IAM users: `arn:aws:iam::<acct>:user/<name>`.
- Root: `arn:aws:iam::<acct>:root`.
- Blank for `AWSService`, `AWSAccount`, `SAMLUser` and `IdentityCenterUser` rows.

`userIdentity_principalId` is `<role id AROA…>:<session name>` for assumed roles (so it also
holds the session name). For `SAMLUser` it is `<idp hash>:<name>`.

**`userIdentity_accessKeyId`**: `ASIA…` for temporary credentials, `AKIA…` for long-lived IAM
user keys. It is a session key, not a user: role it as a join id.

**`sourceIPAddress` forms:**
- the caller's public IPv4: humans, CI runners, servers outside AWS
- a service hostname such as `<svc>.amazonaws.com` or `<bucket-ish>.s3.amazonaws.com`, when an
  AWS service calls on the principal's behalf (often the majority of rows)
- `AWS Internal`

Filter IPs with `=` on the string. Don't put `isprivate()` on this field unchecked: it is a
string column holding hostnames as well as IPs.

**Ids:**
- `eventID`: unique per record per account.
- `requestID`: shared by the copies of one cross-account call. It is in uppercase hex (not a
  GUID) in `s3`.
- `sharedEventID`: set only on cross-account and service-delivered events (common in `sts`,
  and on S3 data events).

**Console and SSO sign-ins (`cloud.aws.cloudtrail.signin`).** One SSO console sign-in writes,
all in the same second:

1. `UserAuthentication` (`IdentityCenterUser`, `eventType` `AwsServiceEvent`), logged in the
   Identity Center account. The arn is blank and the user name is only in `rawMessage`
   (`additionalEventData.UserName`, `CredentialType` = `EXTERNAL_IDP` with an external IdP).
2. `sts` `AssumeRoleWithSAML` (`SAMLUser`) in the member account. `requestParameters_roleSessionName`
   = the session name (usually the UPN), `requestParameters_roleArn` =
   `…/aws-reserved/sso.amazonaws.com/AWSReservedSSO_<set>_<hash>`. `sourceIPAddress` is an
   AWS-owned address, and `userAgent` is the AWS Java SDK (the SSO service), not the user's
   browser.
3. `GetSigninToken` and `ConsoleLogin` (`AssumedRole`, arn ending `/<session>`), with
   `responseElements_ConsoleLogin` = `Success`/`Failure`, `additionalEventData_MFAUsed` (`No`
   when MFA happens at the IdP), and the user's real IP and browser user agent.

`CreateOAuth2Token` / `AuthorizeOAuth2Access` are CLI/SDK SSO logins. `ExternalIdPDirectoryLogin`
(type `Unknown`) is a failed SAML assertion. `Root` and `IAMUser` console logins are usually
rare, so each one is worth a look.

**Linking a session to the person.** For SSO console sessions, the access key does not link:
the key returned by `AssumeRoleWithSAML` generally does not reappear, and the person's console
API calls use many different short-lived `ASIA` keys. **Link on the session name in
`userIdentity_arn` instead.** For SDK/CLI role sessions (`AssumeRole` by `AssumedRole`,
`AWSAccount` or `IAMUser`), the key does chain:
`sts.responseElements_credentials_accessKeyId` = `userIdentity_accessKeyId` on the calls made
with those credentials (a session may make no logged calls at all). Third-party cross-account
principals (`AWSAccount`) and AWS services that assume roles on a user's behalf (`AWSService`)
may use service- or vendor-specific session name formats. No
`sourceIdentity` field is parsed in any table.

Recipes:

A person's sign-ins (console, SSO portal, CLI):
```linq
from cloud.aws.cloudtrail.signin
where weakhas(userIdentity_arn, "smith") or weakhas(rawMessage, "smith")
group by ACCID, eventName, userIdentity_type, responseElements_ConsoleLogin, sourceIPAddress
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

The SSO roles a person took (one row per account and permission set):
```linq
from cloud.aws.cloudtrail.sts
where eventName = "AssumeRoleWithSAML", weakhas(requestParameters_roleSessionName, "smith")
group by ACCID, requestParameters_roleArn, requestParameters_roleSessionName, sourceIPAddress
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
(For a week or more, use `--chunk 1d --parallel 7`.)

What the person then did, per service table. On `secretsmanager`/`eks` use `userIdentity__arn`.
SSO activity is usually spread across many service tables (monitoring, logs, ec2, kms, rds, s3,
iam, lambda, ssm, …), so sweep them in parallel.
```linq
from cloud.aws.cloudtrail.ec2
where weakhas(userIdentity_arn, "smith")
group by ACCID, userIdentity_arn, eventName, sourceIPAddress, errorCode
select count() as n, min(eventdate) as first_seen
```

Failed and root/IAM-user console logins:
```linq
from cloud.aws.cloudtrail.signin
where responseElements_ConsoleLogin = "Failure" or isnotnull(errorMessage)
group by ACCID, eventName, userIdentity_type, errorMessage, sourceIPAddress
select count() as n, min(eventdate) as first_seen
```
```linq
from cloud.aws.cloudtrail.signin
where userIdentity_type in {"Root", "IAMUser"}
group by ACCID, userIdentity_type, eventName, responseElements_ConsoleLogin, additionalEventData_MFAUsed, sourceIPAddress
select count() as n, min(eventdate) as first_seen
```

Who was issued a key, and the calls made with it (SDK sessions). The reverse lookup returns one
row per account for a cross-account AssumeRole:
```linq
from cloud.aws.cloudtrail.sts
where responseElements_credentials_accessKeyId = "ASIAEXAMPLEKEY123456"
select eventdate, ACCID, eventName, userIdentity_type, userIdentity_arn, userIdentity_principalId,
  requestParameters_roleArn, requestParameters_roleSessionName, sourceIPAddress, userAgent
```
```linq
from cloud.aws.cloudtrail.ec2
where userIdentity_accessKeyId = "ASIAEXAMPLEKEY123456"
group by userIdentity_arn, eventName, sourceIPAddress
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
To search every service for a key or arn, run one query per table in parallel (the sweep script
pattern). Don't use `from cloud.aws.cloudtrail`.

STS failures (the error is only in `rawMessage`):
```linq
from cloud.aws.cloudtrail.sts
where weakhas(rawMessage, "errorCode")
select str(jsonparse(rawMessage)["errorCode"]) as err
group by ACCID, eventName, userIdentity_type, requestParameters_roleArn, err
select count() as n
```
Don't call the alias `errorCode`. Use another name, as here.

Denied calls in a table that has `errorCode`:
```linq
from cloud.aws.cloudtrail.iam
where errorCode in {"AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"}
group by ACCID, userIdentity_arn, eventName, errorCode
select count() as n, min(eventdate) as first_seen
```

Logging tampered with (normally returns no rows):
```linq
from cloud.aws.cloudtrail.cloudtrail
where eventName in {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "PutInsightSelectors"}
group by ACCID, userIdentity_arn, eventName, sourceIPAddress
select count() as n
```

Everything from one IP (repeat per table):
```linq
from cloud.aws.cloudtrail.signin
where sourceIPAddress = "203.0.113.10"
group by ACCID, eventName, userIdentity_arn
select count() as n
```

Secrets Manager reads, with its own field names:
```linq
from cloud.aws.cloudtrail.secretsmanager
group by ACCID, userIdentity__type, userIdentity__sessionContext__sessionIssuer__userName, eventName, sourceIPAddress_str
select count() as n
```

## GitHub (`vcs.github.enterprise.audit`, `vcs.github.organization.audit`)

**One row = one audit-log event.** `document_id` is unique per event.
- **`enterprise.audit`** covers every organization in the enterprise. `organization` is blank
  for enterprise-level events (`oauth_access.*`, `business.*`, `user.*`, `enterprise.*`).
- **`organization.audit`** is **one organization's slice of the same stream**, when both
  collectors are configured: its per-action counts track that organization's rows in
  `enterprise.audit` closely. Search `enterprise.audit` first, and treat `organization.audit`
  as a duplicate. It has `actor_ip` instead of `actor_ipv4`, `org` instead of `organization`,
  no `programmatic_access_type`/`user_agent`/`hashed_token`, and `transport_protocol_name`
  (`http`/`ssh`) on `git.*` events.
- If GitHub and other API-pulled sources go quiet at the same time, suspect a collection gap
  rather than inactivity (check `devo.collectors.out`).

**Fields:**
- `eventdate` is the ingest time, usually shortly after `created_at`/`at_timestamp` (the event
  time).
- `machine` / `hostname` is the Devo collector, not a user host.
- `actor` (who did it) is the GitHub login:
  - humans: the login (with Enterprise Managed Users, `<handle>_<enterprise-shortcode>`)
  - bots: `<app-name>[bot]`
  - blank on `workflows.prepared_workflow_job`, `oauth_access.*` and Dependabot alerts
- `user` is the account acted on: the target of a team/member change, a review request, a
  token create/destroy. It is often `""` (empty string) rather than null.
- **`external_identity_username`** is the actor's SSO identity (typically the UPN).
  In `enterprise.audit` it is **stored with double quotes** (`"jsmith@example.com"`), so `=`
  never matches: use `weakhas(…)` or `->`. In `organization.audit` it is stored unquoted. It
  is filled on human events (git, pull requests, workflow runs a human triggered,
  `org_credential_authorization.*`, `business.sso_response`) and blank for bots and app
  tokens. It is only populated when SAML SSO/SCIM is in use.
- `actor_ipv4` (ip4; `actor_ip` in org) and `actor_location__country_code` (ISO-2): blank for
  workflows and apps.
- `repo` (`<org>/<repo>`), `branch` (on `protected_branch.*`), and `head_branch` / `head_sha`
  / `event` / `name` / `workflow_run_id` / `conclusion` on workflow events.
- `programmatic_access_type`:
  - `GitHub App server-to-server token` (automation, often the bulk of `git.clone`)
  - `GitHub App user-to-server token`
  - `OAuth access token`
  - `Personal access token (classic)`
  - `Fine-grained personal access token`
  - `Public Key (User/Deploy)` (SSH key or deploy key)
  - blank (web UI, or a workflow)
- `hashed_token` / `token_id` identify the credential. Group on them to see what one token did.

**Action families** (enterprise table): `workflows`, `git` (`git.clone`, `git.fetch`,
`git.push`), `org` (for example `org.register_self_hosted_runner`), `oauth_access`,
`org_credential_authorization` (SSO authorisations of tokens), `pull_request*`,
`repository_vulnerability_alert`, `issue_comment`, `protected_branch` (`rejected_ref_update`,
`policy_override`), `environment`, `business` (`sso_response`), `repo` (`download_zip`,
`*_actions_secret`, `*_actions_variable`, `change_merge_setting`, `create`), `agent_session`
(Copilot agent), `enterprise`, `user` (`login`, `new_device_used`,
`sign_in_from_unrecognized_device`, `suspend`, `rename`), `user_session.country_change`,
`external_identity` (SCIM provision/deprovision), `team`, `integration_installation`,
`personal_access_token`, `public_key`.

**Interactive or automation:**
- Bots: `actor` ending `[bot]`.
- Apps: `programmatic_access_type = "GitHub App server-to-server token"`. Blank
  `external_identity_username` plus a blank or `[bot]` actor also means automation.
- Workflow runs: `workflows.created_workflow_run` has `event` set to `schedule`, `push`,
  `pull_request`, `dynamic`, `merge_group` or `workflow_dispatch`. Scheduled runs are attributed
  to the workflow's owner with `actor_ip = 127.0.0.6` in the org table, so they are not that
  person acting.
- Humans at a keyboard: a human `actor`, `external_identity_username` set, and
  `programmatic_access_type` blank (web), `OAuth access token` (git client / gh CLI / IDE),
  `Public Key` (ssh git) or a PAT. A PAT can also be a script running as that person, so check
  `user_agent` and the timing.

Recipes:

Find the GitHub login for a person (UPN → `actor`):
```linq
from vcs.github.enterprise.audit
where weakhas(external_identity_username, "jsmith@example.com")
group by actor, external_identity_username
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Everything that login did, and how:
```linq
from vcs.github.enterprise.audit
where weakhas(actor, "jsmith")
group by action, programmatic_access_type, repo, actor_ipv4, actor_location__country_code
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Non-bot, non-app activity (who is active by hand):
```linq
from vcs.github.enterprise.audit
where isnotnull(actor), not actor -> "[bot]",
  isnull(programmatic_access_type) or programmatic_access_type != "GitHub App server-to-server token"
group by actor, action, programmatic_access_type
select count() as n
```

Branch-protection bypasses and rule changes:
```linq
from vcs.github.enterprise.audit
where action in {"protected_branch.policy_override", "protected_branch.rejected_ref_update", "protected_branch.destroy", "protected_branch.update", "repository_ruleset.update", "repository_ruleset.destroy"}
group by action, actor, repo, branch
select count() as n, min(eventdate) as first_seen
```

Bulk cloning or downloads by people (a data-theft check):
```linq
from vcs.github.enterprise.audit
where action in {"git.clone", "repo.download_zip"}, isnotnull(external_identity_username)
group by actor, external_identity_username, action, programmatic_access_type, actor_ipv4
select count() as n, hllppcount(repo) as repos
```

Account sign-in signals:
```linq
from vcs.github.enterprise.audit
where action in {"user.login", "user.new_device_used", "user.sign_in_from_unrecognized_device", "user_session.country_change", "business.sso_response"}
group by action, actor, actor_ipv4, actor_location__country_code
select count() as n
```

Credentials and integrations created or removed:
```linq
from vcs.github.enterprise.audit
where action -> "personal_access_token" or action -> "oauth_authorization" or action -> "public_key" or action -> "integration_installation"
group by action, actor, user
select count() as n
```

Secrets and variables changed:
```linq
from vcs.github.enterprise.audit
where action -> "secret" or action -> "actions_variable"
group by action, actor, repo
select count() as n
```

Scheduled runs (the 127.0.0.6 attribution):
```linq
from vcs.github.organization.audit
where action = "workflows.created_workflow_run"
group by event, actor_ip, actor
select count() as n
```

## 1Password (`auth.agilebits.onepassword.signinattempt`, `.audit`, `.itemusage`)

Usually low volume. `uuid` is the event id. A few events can be ingested more than once with the
same `uuid`, so de-duplicate on `uuid`. `timestamp` is the event time (ISO string with
nanoseconds). `eventdate` is the ingest time, a little later. `hostname` is the collector.

**`signinattempt`**: one row per sign-in to an account (also re-authentications).
- `target_user__email` (UPN; can be mixed case, so use `weakhas`), `target_user__name`,
  `target_user__uuid` (26-char uppercase base32).
- `category` / `type` (outcome): `success` / `credentials_ok`, and
  `credentials_failed` / `password_secret_bad`. Other 1Password values such as `mfa_failed`
  and `sso_failed` are possible.
- `session_uuid` (links to `audit.session__uuid`).
- `client__app_name`: `1Password Browser Extension`, `1Password for Web`, `1Password for Windows`,
  `1Password for Mac`, `1Password CLI`, `1Password SCIM Bridge`.
- **`client__platform_name` depends on the app:**
  - extensions: the browser (`Chrome extension`, `Edge extension`, `Firefox extension`, `Brave extension`)
  - Web: the browser (`Microsoft Edge`, …)
  - Windows/Mac apps: **the device hostname**. This typically matches a SentinelOne
    `computerName` (case-insensitive), a person → device link.
  - CLI: the host or CI runner name
  - SCIM Bridge: its host or pod name
- `client__platform_version`: the browser version, the Mac model (`MacBookPro<N>,<M>`), or the
  architecture.
- `client__os_name`: `Windows`, `MacOSX`, `Linux`, `Android`.
- `client__ip_address` (ip4), `location__country/region/city`.

**`audit`**: one row per account-level action.
- `actor_uuid`, `actor_details__email`, `actor_details__name`, then `action` + `object_type`:
  - `dlgsess`/`dlgdsess` and `ssotknv`/`ssotkn`: session plumbing, most rows; ignore them
  - `patch`/`items`: items edited. `object_uuid` = the **vault** uuid, `aux_info` = per-change counts
  - `share`/`item`: `object_uuid` = the item, `aux_uuid` = its vault
  - `create`/`device`: a new device enrolled. `aux_details__email` = the device's user
  - `create`/`file`
  - `grant`/`revoke`/`update` on `gva`/`uva` (vault access for groups/users)
  - `suspend`, `activate`, `beginr`/`completr` (account recovery), `dealldev` (devices
    deauthorised), `reauth`, `tdvcsso` on `user`
- `session__uuid` = `signinattempt.session_uuid`, `session__ip`, `session__device_uuid`
  (26-char lowercase), `session__login_time` (equal to the sign-in's `timestamp`). `dlgsess`
  rows carry the delegating session's uuid in `aux_uuid`.

**`itemusage`**: one row per item use.
- `user__email` / `user__name` / `user__uuid`.
- `action`: `reveal`, `fill`, `server-fetch`, `secure-copy`, `server-update`,
  `enter-item-edit-mode`, `share`, `server-create`, `export`.
- `vault_uuid`, `item_uuid` (26-char lowercase), `used_version`.
- **No item or vault names, and no session id.** Map the uuids in the 1Password console.
- The `client__*` and `location__*` fields are as in `signinattempt`.
- To tie a use to a sign-in, match on user + `client__ip_address` + `client__platform_name`.
  This is inferred, not a key.
- `1Password CLI` usage is often service accounts and CI runners reading secrets.

Recipes:

A person's sign-ins (devices, apps, IPs):
```linq
from auth.agilebits.onepassword.signinattempt
where weakhas(target_user__email, "jsmith@example.com")
group by category, type, client__app_name, client__platform_name, client__os_name, client__ip_address, location__country
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Failed sign-ins:
```linq
from auth.agilebits.onepassword.signinattempt
where category != "success"
group by target_user__email, category, type, client__app_name, client__ip_address, country
select count() as n
```

What a person revealed, copied or filled:
```linq
from auth.agilebits.onepassword.itemusage
where weakhas(user__email, "jsmith@example.com")
group by action, vault_uuid, item_uuid, client__app_name, client__platform_name, client__ip_address
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Who used one item:
```linq
from auth.agilebits.onepassword.itemusage
where item_uuid = "<ITEM_UUID>"
group by user__email, action, client__app_name, client__platform_name
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

A sign-in and everything done in that session:
```linq
from auth.agilebits.onepassword.signinattempt
where session_uuid = "<SESSION_UUID>"
select eventdate, target_user__email, type, client__app_name, client__platform_name, client__ip_address
```
```linq
from auth.agilebits.onepassword.audit
where session__uuid = "<SESSION_UUID>"
select eventdate, actor_details__email, action, object_type, object_uuid, aux_uuid, aux_info, session__ip
```

Admin and item changes (session noise left out):
```linq
from auth.agilebits.onepassword.audit
where action not in {"dlgsess", "ssotknv"}
group by actor_details__email, action, object_type
select count() as n
```

Hosts and runners using the CLI:
```linq
from auth.agilebits.onepassword.itemusage
where client__app_name = "1Password CLI"
group by user__email, client__platform_name, client__ip_address
select count() as n
```

## SentinelOne (`edr.sentinelone.agent.agents`, `.agent.threats`, `.management.activities`)

`hostname` in all three tables is the Devo collector, not the endpoint.

**`agent.agents`**: one row per agent **each time the agent record changes**, not a full
inventory per poll. A short window shows only a fraction of the fleet, so **use at least 24 h**
to look up a host or IP.
- `id` (numeric agent id = `threats.agentRealtimeInfo__agentId` = `activities.agentId`),
  `uuid`.
- `computerName`: mixed case; AWS servers often look like `ip-10-…`.
- `lastLoggedInUserName`: a bare sAMAccountName, often blank.
  `lastUserDistinguishedName` and `osUsername` are also there.
- `lastIpToMgmt` (ip4, internal), `externalIp` / `externalIpv4` (public egress),
  `networkInterfaces` (JSON).
- `osType` (`windows`, `macos`, `linux`), `osName`, `machineType`, `groupName`, `siteName`,
  `isActive`, `infected`, `activeThreats`, `networkStatus`, `lastActiveDate`.
- `agentVersion` / `rangerVersion` are version strings, not IPs.

**`agent.threats`**: one row per threat **per update**, so one threat has several rows. Only
`eventdate`, `threatInfo__updatedAt`, `indicators` and `whiteningOptions` change between
copies, so take the latest row (`last()`) per threat.
- `threatInfo__threatId` = `id` (numeric). `threatInfo__storyline`: a 16-hex or GUID
  storyline id (SentinelOne's process-tree id; it ties to Deep Visibility, if that is
  collected).
- Endpoint:
  - `agentRealtimeInfo__agentComputerName`, `agentRealtimeInfo__agentId`, `…__agentUuid`
  - `agentDetectionInfo__agentLastLoggedInUserName` (sAMAccountName)
  - `threatInfo__processUser` (`DOMAIN\user`, or a bare name)
  - `agentDetectionInfo__agentIpV4_str`: **a comma-separated list** when the host has several
    interfaces. The ip4 `agentDetectionInfo__agentIpV4` is then null, so match the `_str`
    field with `->`.
  - `agentDetectionInfo__externalIp` (public)
- Verdict and state:
  - `threatInfo__analystVerdict`: `undefined`, `suspicious`, `true_positive`, `false_positive`
  - `threatInfo__incidentStatus`: `unresolved`, `in_progress`, `resolved`
  - `threatInfo__mitigationStatus`: `not_mitigated`, `mitigated`, `marked_as_benign`
  - `threatInfo__confidenceLevel`: `malicious`, `suspicious`
  - `threatInfo__classification`: `Malware`, `Infostealer`, `Ransomware`, `Rootkit`, `General`,
    `Benign`
  - `threatInfo__initiatedBy`: `agent_policy`, `star_active` (a custom rule)
- File and process: `threatInfo__threatName`, `threatInfo__filePath`, `threatInfo__sha1`
  (usually set), `threatInfo__sha256` (often set), `threatInfo__md5` (rarely set),
  `threatInfo__originatorProcess`, `threatInfo__maliciousProcessArguments`,
  `threatInfo__publisherName`, `indicators` (JSON).

**`management.activities`**: one row per console activity.
- `activityType` (int), `primaryDescription` (readable sentence), `secondaryDescription`.
- `rawData`: the activity's `data` object as a JSON string, with old/new values. It is a string
  column, so use `jsonparse()`.
- `threatId` (equal to `threats.threatInfo__threatId`), `agentId`, `userId`.
- `dataComputerName`.
- **`dataUsername`** (who acted) comes in several forms:
  - `First Last (<email>)` (sometimes with two spaces)
  - `<upn> (<upn>)`
  - an API user's name (integrations and service providers acting through the API)
- `dataIpAddress` is **stored with quote marks** (`"203.0.113.10"`), so match it with `->`.
- `dataActoralternateid`, `dataLoginsusername` and `dataSourceprocessusername` may be empty.
  `dataUsername` is the one that matters.

**Activity types.** If your domain has an activity-type lookup uploaded (check
`my.lookup.data`), `lu("<lookup name>", "description", activityType)` maps `activityType` →
description. Common types:

| Type | Meaning |
|---|---|
| 5126 | USB device connected (Device Control); often the noisiest type |
| 3631/3632 | Live update merged / not merged |
| 71/90/91/92 | Full disk scan initiated / started / aborted / completed |
| 17, 47, 48, 5009 | Agent subscribed / decommissioned / recommissioned / moved group |
| 3653 | User attached a tag |
| 19, 18, 4003 | Threat detected (malicious / mitigated / suspicious not mitigated) |
| 2001, 2004 | Agent killed / quarantined a threat |
| 4008 | Threat mitigation status changed (`originalStatus` → `newStatus` in rawData) |
| **2028** | **Incident status changed** (`oldIncidentStatus` → `newIncidentStatus`) |
| **2030** | **Analyst verdict changed** (`oldAnalystVerdict` → `newAnalystVerdict`) |
| 4020/4022 | Threat note added/deleted (`noteDetails`) |
| 85, 86, 203 | Fetch threat file command / agent uploaded it / user downloaded it |
| 61/62, 1001/1002 | Disconnect from / reconnect to network (isolation) command / done |
| 50, 117/118, 120 | Uninstall / disable / enable agent |
| 3200/3201/3203, 3400 | Remote shell started / created / terminated, transcript uploaded |
| 3618, 3616/3622/3623 | Script executed / script library changed |
| 27, 33, 133, 144, 155 | Console login / logout / failed login / locked out / token revoked |
| 112, 138, 3711/3714 | API token generated, protected-actions session, password change |
| 3600/3603, 3608, 4107, 4114 | Custom rule added/changed, alert from custom rule, rule marked threat, alert linked to threat |
| 3776–3793 | Platform library rules created/edited/enabled (vendor) |

**Linking.** Threat → endpoint: `agentRealtimeInfo__agentId` = `agents.id`. Threat → analyst
actions: `activities.threatId`. Endpoint → user/IP: `agents` (≥24 h) or the threat's own
`agentDetectionInfo__*` fields. IP → endpoint: `agents.lastIpToMgmt` (internal) or
`externalIp`. Devo alert definitions built on SentinelOne threats fire on these status changes
(see the platform tables below).

Recipes:

Current state of each threat (one row per threat):
```linq
from edr.sentinelone.agent.threats
group by threatInfo__threatId, agentRealtimeInfo__agentId, agentRealtimeInfo__agentComputerName, threatInfo__threatName, threatInfo__classification
select min(threatInfo__createdAt) as created, max(eventdate) as last_update,
  last(threatInfo__analystVerdict) as verdict, last(threatInfo__incidentStatus) as incident,
  last(threatInfo__mitigationStatus) as mitigation, last(agentDetectionInfo__agentLastLoggedInUserName) as user,
  last(agentDetectionInfo__agentIpV4_str) as ip, last(agentDetectionInfo__externalIp) as ext_ip
```

Timeline of a threat (detection, analyst notes, status and verdict changes, file fetches):
```linq
from edr.sentinelone.management.activities
where threatId = "<THREAT_ID>"
select eventdate, activityType, dataUsername, primaryDescription
```

Who changed verdicts and incident statuses, from what to what:
```linq
from edr.sentinelone.management.activities
where activityType in {2028, 2030}
select eventdate, activityType, threatId, agentId, dataComputerName, dataUsername,
  str(jsonparse(rawData)["oldAnalystVerdict"]) as old_verdict,
  str(jsonparse(rawData)["newAnalystVerdict"]) as new_verdict,
  str(jsonparse(rawData)["oldIncidentStatus"]) as old_status,
  str(jsonparse(rawData)["newIncidentStatus"]) as new_status
```
`jqeval(jqcompile(…), rawData)` fails on this string column. Wrap it in `jsonparse()`, or use
`jsonparse(rawData)["key"]` as above.

Activity types with their names (needs the lookup):
```linq
from edr.sentinelone.management.activities
group by activityType
select count() as n, lu("<lookup name>", "description", activityType) as description
```

Response actions (isolation, uninstall, remote shell, scripts):
```linq
from edr.sentinelone.management.activities
where activityType in {50, 61, 62, 85, 117, 118, 3200, 3201, 3203, 3618}
group by activityType, dataUsername, dataComputerName
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

A console user's logins and failures:
```linq
from edr.sentinelone.management.activities
where activityType in {27, 33, 133, 144, 155}, weakhas(dataUsername, "smith")
select eventdate, activityType, dataUsername, dataIpAddress, primaryDescription
```

Host → agent, last user, IPs (use ≥24 h):
```linq
from edr.sentinelone.agent.agents
where weakhas(computerName, "HOST01")
group by id, uuid, computerName, lastLoggedInUserName, lastIpToMgmt, externalIp, osName, groupName, siteName
select max(eventdate) as last_seen
```
IP → host:
```linq
from edr.sentinelone.agent.agents
where lastIpToMgmt = 10.1.2.3
group by computerName, lastLoggedInUserName, groupName
select max(eventdate) as last_seen
```

Everything the console logged about a host:
```linq
from edr.sentinelone.management.activities
where weakhas(dataComputerName, "HOST01")
group by activityType, agentId, dataUsername
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
Activities from or about an IP (quoted field):
```linq
from edr.sentinelone.management.activities
where dataIpAddress -> "203.0.113.10"
group by activityType, dataComputerName, dataUsername
select count() as n
```

## Qualys (`vuln.qualys.hosts`, `.hostdetections`, `.vulnerabilities`, `.useractivitylog`)

**`hosts`**: one row per asset per inventory pull. Pulls may not happen every day, so use a few
days of data.
- `host_id` (numeric string), `qg_hostid` (GUID; Qualys' global id).
- `ip` (ip4). One IP can map to more than one `host_id` (re-imaged or replaced cloud hosts), so
  take the latest `last_activity`.
- `dns` / `dns_fqdn` / `dns_hostname` (lowercase), `netbios` (uppercase short name).
- `os`, `tracking_method`: `Cloud Agent`, `IP`, `DNS`, `NETBIOS`.
- `cloud_provider` (`AWS`/`Azure`), `ec2_instance_id` / `cloud_resource_id`.
- `agent_status`, `last_activity`, `last_boot`.

**`hostdetections`**: one row per (host, QID) **per pull**, several times a day. Always group:
never count raw rows.
- `host_id` (= `hosts.host_id`), `ip`, `dns_hostname`, `netbios`.
- `detection_qid` (**a string** here, but an int `qid` in `vulnerabilities`).
- `detection_unique_vuln_id`.
- `detection_type`: `Confirmed` or `Potential`. `detection_severity`: `1`–`5` (string).
- `detection_status`: `New`, `Active`, `Re-Opened`. The feed may carry open detections only
  (check whether any `Fixed` rows exist), in which case a QID dropping out of the latest pull is
  the sign it was fixed (`detection_last_fixed_datetime` marks detections that were fixed once
  and came back).
- `detection_first_found_datetime`, `detection_last_found_datetime`.
- `detection_results`: the evidence text (versions, paths).
- **No title.**

**`vulnerabilities` is not the Qualys KnowledgeBase.** It holds **network-scan results**: one
row per (IP, QID) per scan, with `scan_reference`, `title`, `severity`, `type` (`Vuln`,
`Practice`, `Ig` = information gathered), `category`, `port`, `threat` / `impact` / `solution`
/ `results`, and `cve_id` (rarely filled). Only QIDs that appeared in a network scan are there,
so **most agent detection QIDs have no title in Devo**. Look them up in Qualys.

**`useractivitylog`**: Qualys console/API audit. `user_name` (lowercase), `user_role`,
`user_ip`, `module` (`auth`, `scan`, `schedule`, `report`), `action`, `details`. Many rows can
be an integration account's API polling (`auth`/`request` with
`API: /api/…/fo/asset/host/…`), so filter `module != "auth"` for scan and schedule changes.

Recipes:

IP or name → asset:
```linq
from vuln.qualys.hosts
where ip = 10.1.2.3
group by host_id, qg_hostid, dns_fqdn, dns_hostname, netbios, os, tracking_method, ec2_instance_id
select max(eventdate) as last_seen, max(last_activity) as last_activity
```
```linq
from vuln.qualys.hosts
where weakhas(dns_hostname, "host01") or weakhas(netbios, "host01")
group by host_id, ip, dns_fqdn, netbios, os
select max(eventdate) as last_seen
```

A host's open detections (one row each):
```linq
from vuln.qualys.hostdetections
where host_id = "<HOST_ID>", detection_status in {"New", "Active", "Re-Opened"}
group by detection_qid, detection_severity, detection_type, detection_status
select max(detection_last_found_datetime) as last_found, min(detection_first_found_datetime) as first_found
```

With titles where Devo has them. The subquery covers the same time window, so use a long one
(30 days):
```linq
from vuln.qualys.hostdetections
where host_id = "<HOST_ID>"
group by detection_qid
select (from vuln.qualys.vulnerabilities group by str(qid) as q select last(title) as t)[detection_qid] as title
```
(A blank title means the QID was never in a network scan.)

Hosts with a QID, and the most widespread confirmed severity-5 QIDs:
```linq
from vuln.qualys.hostdetections
where detection_qid = "<QID>"
group by host_id, dns_hostname, ip
select max(detection_last_found_datetime) as last_found
```
```linq
from vuln.qualys.hostdetections
where detection_severity = "5", detection_type = "Confirmed", detection_status in {"New", "Active", "Re-Opened"}
group by detection_qid
select hllppcount(host_id) as hosts
```

A QID's title (only for QIDs from network scans):
```linq
from vuln.qualys.vulnerabilities
where qid = 12345   // placeholder QID
group by qid, title, severity, type, category
select count() as n, hllppcount(ip) as ips
```

Changes to Qualys scans and schedules:
```linq
from vuln.qualys.useractivitylog
where module != "auth"
group by user_name, user_role, module, action, user_ip
select count() as n
```

## Devo platform and other tables

| Table | What it is | Use in investigations |
|---|---|---|
| `siem.logtrust.alert.info` | One row per alert fired (`alertId`, `context` = `my.alert.<domain>.<Definition>`, `priority`, `extraData` JSON, `alertcreationdate`). `status` may always be 0. `username` is the definition owner, not the actor. `srcIp`/`dstIp` may be empty. | Alert history and counts. Entities come from `extraData`. |
| `devo.audit.alert.triggered` | **The alert workflow log.** `id` = alertId. `action`: `CREATE`, `EDIT STATUS`, `CREATE COMMENT`, `UPDATE COMMENT`, `DELETE COMMENT`, `EDIT PRIORITY`. `username` (who did it), `name` (definition name), `info` JSON (`statusCode`/`statusName`, `priorityName`, `commentMsg`/`commentTitle`). | **Who looked at or changed an alert, and when.** Best source. |
| `secops.alerts.enriched` | SecOps alert events: `alertId`, `eventType` (`status`, `comment`), `status` (numeric status codes), `commentTitle`/`commentMsg`, `username`. | The same story as the audit table, without definition names. |
| `secops.audit.api` | Alerts API calls (request and response rows, linked by `cid`): `method`, `relativePath` (`v1/alerts/list`, `v1/comments/add`, `v2/alerts/count`, …), `body`, `status`, `username`. | Who used the API (including this skill's token) to read or comment on alerts. |
| `siem.logtrust.web.navigation` | Devo console page views: `userEmail`, `srcHost` (client IP), `section`/`action` (`search`, `table`, `mfa`, `user`, `roles`, …), `isp`, `country`. | Who used the Devo console, and from where. |
| `siem.logtrust.web.activity` | Devo console HTTP requests: `username`, `srcHost`, `url`, `params`, `userAgent`, `country`. Mostly polling (`notification.json`, `alertsGlobe.json`). | Session-level detail behind the navigation rows. |
| `devo.internal.audit.logs` | Devo admin audit (low volume): `username`, `user_ip4`, `service` (`webapp`, `ws-api`, `aggregations`, …), `section`/`subsection` (`credentials`, `security`/`token`), `action` (`list tokens`, `retrieve token`, `certificate.read`, …). | Who viewed or created Devo API tokens, keys and certificates. |
| `my.lookup.control`, `my.lookup.data` | Lookup upload bookkeeping. Data rows are `rawData` CSV lines. | Use lookups through `lu(...)`, not directly. |
| `devo.collectors.out` | Collector logs: `collector_name` (AWS, Azure, Github, MS-Graph, Office-365, …), `input_name`, `service_name`, `level2` (`debug`/`info`/`warning`/`error`), `msg`. Some warnings are benign and very high-volume: group normalised messages (ids, numbers and timestamps stripped) and look at errors and at collectors that went silent. Credential/permission errors (401/403, expired token) mean a collector may be pulling nothing for some services (`health` lists them first, `AUTH`). | Explaining collection gaps: a source going quiet (`devo.py health` summarises it). |
| `devo.collector.metric.*` (`input_stat`, `output_stat`, `process_stat`, `gc_info`) | Collector metrics. `input_stat` has per-input message counts (`msg_enqueued_standard__part_counter`) per pull. The counters can read 0 for inputs that are flowing: confirm on the destination table. | Volume per input over time, a gap check for API-pulled sources. |
| `my.app` | NxLog agents' own messages (`category` `nxlog_internal`: connect/reconnect/SSL closed, config errors) and other custom app data. | Why a Windows host's logs stopped. |
| `unknown.unknown` | Events whose tag has no table (for example a log type sent with a tag Devo has no parser for). The whole log line is in `message`; the tag may not be a separate field (check `devo.py schema unknown.unknown`), in which case it is near the start of `message`. `hostchain` = `<sender>=<ip>`. | Sometimes the only place a source exists: `weakhas(message, "<term>")`. Extract the tag from `message` (`peek`/`substring`, recipe below) and group by it to see what is there. |

Recipes:

Every change and comment on one alert:
```linq
from devo.audit.alert.triggered
where id = "<ALERT_ID>"
select eventdate, actiondate, action, username, name, info
```
```linq
from secops.alerts.enriched
where alertId = "<ALERT_ID>"
select eventdate, eventType, status, username, commentTitle, commentMsg
```

Who works the alerts:
```linq
from devo.audit.alert.triggered
where action in {"EDIT STATUS", "CREATE COMMENT", "EDIT PRIORITY", "UPDATE COMMENT", "DELETE COMMENT"}
group by username, action
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

API use by a person:
```linq
from secops.audit.api
where weakhas(username, "jsmith"), msgType = "request"
group by method, relativePath
select count() as n
```

Devo console use and admin actions:
```linq
from siem.logtrust.web.navigation
group by userEmail, srcHost, section, action
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
```linq
from siem.logtrust.web.activity
group by username, srcHost, country
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
```linq
from devo.internal.audit.logs
group by username, user_ip4, service, section, action, status
select count() as n
```

Alert counts per definition:
```linq
from siem.logtrust.alert.info
where context -> "SentinelOne"
group by context
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

What is in `unknown.unknown`, by tag and by sender. If `schema` shows no `tag` field, take it from
`message` (adjust the regex to the line format after a `limit 5` sample):
```linq
from unknown.unknown
select peek(message, re("^\\S+ \\S+ (\\S+)"), 1) as tag
group by tag
select count() as n
```
```linq
from unknown.unknown
where weakhas(message, "<distinctive string>")
group by hostchain
select count() as n
```

Collector warnings and per-input volume (gap check). Normalise `msg` client-side (replace digits,
GUIDs and quoted values) before grouping by message, or a handful of benign warnings swamp the
list; `input_stat` zeros are not proof an input stopped.

**Credential and permission errors come first.** Messages with HTTP 401/403, "forbidden",
"unauthorized", "access denied", an expired token or an invalid client secret mean the collector
can no longer read that source: it may be pulling **nothing** for some services (one Microsoft 365
content type, one Graph endpoint, one AWS account) while its other inputs keep flowing, so the
table looks merely quiet. Read `service_name`/`input_name` to see which part is affected, then
confirm on the destination table. `devo.py health` lists collectors with such errors first,
marked `AUTH`:
```linq
from devo.collectors.out
where level2 in {"warning", "error"}
group by collector_name, input_name, service_name, level2
select count() as n, max(eventdate) as last_seen
```
```linq
from devo.collector.metric.input_stat
group every 1h by collector_name, input, service
select sum(msg_enqueued_standard__part_counter) as msgs
```
