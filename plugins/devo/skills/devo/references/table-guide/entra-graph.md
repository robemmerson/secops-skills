# Entra ID, Microsoft Graph and other Azure tables

Generic parser knowledge. Your domain may differ: confirm fields with `devo.py fields <table>` before relying on a detail.

Values in the recipes are placeholders (`jsmith`, `203.0.113.10`, `<object-id>`, `<start>`/`<end>`
timestamps). Contents:

  - Two collectors feed the same tables
  - Sign-in tables
  - `cloud.azure.ad.signin_all` (union)
  - `cloud.azure.ad.microsoft_graph_activity_logs`
  - `cloud.azure.ad.audit`
  - `cloud.azure.ad.provisioning`
  - `cloud.azure.ad.user_risk_events` and `cloud.azure.ad.alerts`
  - `cloud.azure.others.events`
  - Device and location fields for impossible travel and new devices
  - Linking recipes

Tables: `cloud.azure.ad.microsoft_graph_activity_logs` and `cloud.azure.others.events` (usually
the largest), `cloud.azure.ad.noninteractive_user_signin` (the bulk of sign-ins),
`cloud.azure.ad.service_principal_signin`, `cloud.azure.aadiam.microsoftserviceprincipalsigninlogs`,
`cloud.azure.ad.audit`, `cloud.azure.ad.provisioning`, `cloud.azure.ad.signin`,
`cloud.azure.ad.managed_identity_signin`, `cloud.azure.ad.interactive_user_signin`,
`cloud.azure.ad.user_risk_events` and `cloud.azure.ad.alerts` (low volume). Union:
`cloud.azure.ad.signin_all` (all five sign-in tables, normalised fields). Defender Advanced Hunting
(`cloud.azure.ah.*`) is covered separately. Run `devo.py tables` to see which of these your domain
has.

Most queries in this family are fast; the Graph table is large, so chunk it (`--chunk 1h`) over
more than a few hours.

### Two collectors feed the same tables

A table here can be written by one or both of two Devo collectors, and the two write **different
field sets into the same table**. Which tables get which path depends on how the collectors are set
up in your domain; the markers below tell them apart.

| | Event Hub (diagnostic settings) | Graph API puller |
|---|---|---|
| `hostname` | `collector-<id>-<pod>` (several pods) | `collector-<other id>-<pod>` |
| Marker fields | `category` (`SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `ManagedIdentitySignInLogs`, `AuditLogs`, `ProvisioningLogs`, …), `tenantId`, `region` (the Azure region), `resultType`, `callerIpAddress`, `at_devo_eh_*` | `category` null (audit: the Graph category such as `GroupManagement`), `tenantId` null, `region` null or `-` |
| Session / token ids | `properties_sessionId`, `properties_uniqueTokenIdentifier` | `sessionId`, `uniqueTokenIdentifier` (no `properties_` prefix) |
| Other fields that move | `properties_clientCredentialType`, `properties_autonomousSystemNumber`, `properties_incomingTokenType`, `properties_isInteractive`, `properties_userType` (`Member`/`Guest`) | `clientCredentialType`, `autonomousSystemNumber`, `incomingTokenType`, `isInteractive`, `properties_userType` (`member`/`guest`, lowercase) |

`hostname` is the collector pod, **never a device**. The fields an analyst usually needs are the same
on both paths: `properties_id`, `correlationId`, `properties_userPrincipalName`, `properties_userId`,
`properties_ipAddress`, `properties_appDisplayName`/`properties_appId`, `properties_resourceDisplayName`,
`properties_status_errorCode`, `properties_location_*`, `properties_deviceDetail_*`. When you group by a
field from the "moves" row, add its twin or the rows of the other path land in a blank bucket.

**What that means per table (typical layout when both collectors run):**
- `cloud.azure.ad.signin` = **all interactive user sign-ins**: Event Hub `SignInLogs` rows plus
  Graph v1.0 API rows (largely a subset of the Event Hub ones).
- `cloud.azure.ad.interactive_user_signin` = Graph beta API rows only, and can hold **only a
  fraction of interactive sign-ins** (accounts, including guests, can be missing entirely).
  Compare distinct `properties_id` counts against `cloud.azure.ad.signin` in your domain; by default
  **use `cloud.azure.ad.signin` for interactive sign-ins**.
- `noninteractive_user_signin`, `service_principal_signin`, `managed_identity_signin`: both paths in one
  table; API rows mostly duplicate Event Hub rows.
- `cloud.azure.ad.audit`: both paths (the "ingested twice" rule; see the audit section).
- `cloud.azure.ad.provisioning`: both paths, but the Event Hub copy is header-only (no `properties_*`).
- `cloud.azure.aadiam.*`, `cloud.azure.others.events`, `microsoft_graph_activity_logs`,
  `user_risk_events`: Event Hub only. `cloud.azure.ad.alerts`: API only.

**Duplicates.** Raw row counts overstate events in every sign-in table: the API copy duplicates Event
Hub rows, and Event Hub redelivers some events (same `properties_id` and
`properties_createdDateTime`, later `eventdate`; sometimes several copies). Count sign-ins with
`hllppcount(properties_id)` or `group by properties_id`, never `count()`.

**Lag.** `eventdate` is ingestion time; the event time is `properties_createdDateTime` (ISO string;
`signin` also has `properties_createdDateTime_timestamp`). Lag is typically minutes, with a long
tail (tens of minutes to over an hour, longest on the Event Hub non-interactive path). Because the API
path is often faster and the Event Hub path more complete, don't filter one path out when looking at
the last hour: query the table and de-duplicate on `properties_id`. A `--to` window ending in the last
hour or so can still be missing non-interactive rows. `devo.py lag` measures it in your domain.

**Two string formats for the same timestamp.** `properties_createdDateTime` (and other ISO string
times in these tables) can arrive as `2026-01-01T09:00:00Z` from one collector and as
`2026-01-01T09:00:00.1234567+00:00` (6–7 fractional digits) from the other, in the same table and
window. `min()`/`max()` on the string compare text, so they mix the two and can return the wrong
first/last; parse before aggregating. Use `properties_createdDateTime_timestamp` where it exists
(`signin`); elsewhere truncate to whole seconds first, because `timestamp()` on the long form reads
the 6–7 fractional digits as milliseconds and lands minutes to hours late:
```linq
from cloud.azure.ad.noninteractive_user_signin
select timestamp(concat(substring(properties_createdDateTime, 0, 19), "Z")) as created
group by properties_userPrincipalName
select min(created) as first, max(created) as last
```
Client-side, normalise both forms (`Z` and `+00:00`, trimmed fraction) before sorting or merging.

### Sign-in tables

One row = one sign-in (token issuance) event, identified by `properties_id` (GUID, lowercase).
- **`cloud.azure.ad.signin`**: interactive user sign-ins (password, MFA, Windows Sign In, browser
  SSO). `properties_isInteractive` true, `properties_signInEventTypes` `["interactiveUser"]`.
- **`cloud.azure.ad.noninteractive_user_signin`**: token refreshes and SSO done by a client on the
  user's behalf (Teams, Outlook, OneDrive sync, Graph-using apps). The bulk of user activity; most
  delegated Graph calls trace back to rows here.
- **`cloud.azure.ad.service_principal_signin`**: app-only (client-credentials) sign-ins by the
  tenant's own app registrations and third-party apps. No user. Identity is
  `properties_servicePrincipalName` / `properties_servicePrincipalId` / `properties_appId`; credential
  is `properties_clientCredentialType` (`clientSecret`, `clientAssertion`, `certificate`,
  `federatedIdentityCredential`; API rows: `clientCredentialType`) and
  `properties_servicePrincipalCredentialKeyId` / `…Thumbprint` (rarely filled). `properties_ipAddress`
  is the app's egress IP (cloud provider ranges for SaaS apps).
- **`cloud.azure.ad.managed_identity_signin`**: Azure managed identities (VMs, Functions, AKS, Logic
  Apps) getting tokens from IMDS. `properties_servicePrincipalName` is the identity name (often the
  resource name, sometimes a hex string), `properties_resourceDisplayName` the target (Azure
  Resource Manager, Key Vault, Azure Monitor…). **No IP address** (`properties_ipAddress` absent;
  location rarely filled, lat/long `0.0`). `managedServiceIdentity_associatedResourceId`
  (`/subscriptions/<sub>/resourcegroups/<rg>/providers/<type>/<name>`) is filled only on some API rows.
- **`cloud.azure.aadiam.microsoftserviceprincipalsigninlogs`**: Microsoft first-party services
  (AADReporting, Microsoft Teams Graph Service, Office licensing, Media Analysis…) getting app-only
  tokens in the tenant. Background noise for most investigations, but it is where a first-party
  app's Graph or Azure AD Graph token is issued. **Field names are snake_case**:
  `properties_service_principal_name`, `properties_app_id`, `properties_ip_address`, `caller_ip`,
  `properties_status_error_code`, `properties_unique_token_identifier`, `properties_session_id`,
  `properties_created_date_time`, `result_type`, `correlation_id`. `properties_user_id` is the
  literal `""`.

**Entity fields (user sign-in tables):**
- User: `properties_userPrincipalName` (the UPN, usually lowercase; guests appear with their home
  address, e.g. `<name>@example.com`, `properties_userType` `Guest`, `properties_crossTenantAccessType`
  `b2bCollaboration`), `properties_userId` (Entra object id, lowercase GUID: the key for Graph and
  audit), `properties_userDisplayName` / Event Hub `identity` (the display name).
- IP: `properties_ipAddress` (IPv4 or IPv6, string; Event Hub `callerIpAddress` is the same value),
  `properties_autonomousSystemNumber` (int; API rows `autonomousSystemNumber`).
- Location (IP geolocation): `properties_location_countryOrRegion` (ISO-2 uppercase),
  `properties_location_state`, `properties_location_city`, `…_geoCoordinates_latitude/longitude`
  (float). Event Hub `location` is the same country code.
- Device: `properties_deviceDetail_deviceId` (Entra device object id; blank for unregistered devices,
  the literal **`{PII Removed}`** for guests), `properties_deviceDetail_displayName` (the device name:
  Windows names uppercase like `HOST01`, Macs/phones free text), `…_operatingSystem` (`Windows10`,
  `Windows`, `MacOs`, `Ios`, `Android`), `…_browser` (`Edge 1xx.0.0`), `…_trustType` (`Hybrid Azure
  AD joined`, `Azure AD joined`, `Azure AD registered`), `…_isCompliant`, `…_isManaged` (bool),
  `properties_userAgent`.
- App / resource: `properties_appDisplayName` + `properties_appId` (the client),
  `properties_resourceDisplayName` + `properties_resourceId` (the API the token is for: Microsoft
  Graph, Office 365 SharePoint Online, Windows Azure Active Directory…; on API rows the top-level
  `resourceId` is the resource app id, on Event Hub rows it is `/tenants/<tid>/providers/Microsoft.aadiam`).
  `properties_clientAppUsed`: `Browser`, `Mobile Apps and Desktop clients`, `Exchange ActiveSync`,
  `Other clients` (legacy auth).
- Session and token: `properties_sessionId` (API: `sessionId`), `properties_uniqueTokenIdentifier`
  (API: `uniqueTokenIdentifier`), `correlationId` (= `properties_correlationId`),
  `properties_originalRequestId` (usually = `properties_id`).

**Outcome fields.** `properties_status_errorCode` (int4, 0 = success) is filled on every row of both
paths and is the field to use. `resultType` (string) exists only on Event Hub rows and matches
`properties_status_errorCode`; it is null on API rows (and absent from `interactive_user_signin`,
which fails the query if you name it). `properties_status_failureReason` is mostly empty on Event
Hub rows and reads "Other." on **successful** API rows, so don't use it to decide success.
`properties_status_additionalDetails` explains interrupts ("MFA requirement satisfied by claim in the
token"). Event Hub `resultSignature`: `SUCCESS` / `FAILURE`. Conditional access:
`properties_conditionalAccessStatus` (`success`, `failure`, `notApplied`) and
`properties_appliedConditionalAccessPolicies` (JSON string: policy `displayName`, `result`). MFA:
`properties_mfaDetail_authMethod` (sparsely filled), `properties_authenticationDetails_*`
(comma-joined lists, API rows of `interactive_user_signin` only). Risk:
`properties_riskLevelDuringSignIn`, `properties_riskState`, `properties_riskDetail` (mostly `none`;
`hidden` when not licensed).

**How the session and token ids relate:**
- `properties_sessionId` is the Entra session (the primary refresh token / browser session). It is
  shared by the interactive sign-in and every non-interactive refresh that follows, normally with one
  user and one device id, a few IPs (IPv4 and IPv6 of the same line, mobile carriers), and usually
  one country. A session that shows a **new ASN or country** is the token-theft signal to chase.
- `correlationId` groups the attempts of one sign-in flow (interrupt + success) but in practice is
  nearly always 1:1 with `properties_id` for interactive rows; it does not follow a session.
- `properties_uniqueTokenIdentifier` (22-char base64url) **is `properties_id` encoded**: base64url-decode
  it and read the 16 bytes as a little-endian GUID (Python
  `str(uuid.UUID(bytes_le=base64.urlsafe_b64decode(t + "==")))`). Graph activity's
  `properties__sign_in_activity_id` uses this token form.

**Error codes.** See investigations.md §4 ("separate interrupts from real failures"). Common
interactive codes besides 0: 50074 (MFA required), 50076, 50203, 50125 (password reset or
registration interrupt). The API path tends to carry few of the interrupt codes, another reason to
use the full table.

### `cloud.azure.ad.signin_all` (union)

The five sign-in tables with normalised fields: `source` (`azure-ad-signin`,
`azure-ad-noninteractive_user_signin`, `azure-ad-interactive_user_signin`,
`azure-ad-service_principal_signin`, `azure-ad-managed_identity_signin`), `username` (**the UPN on every
path**), `user` (UPN on API rows but the display name on Event Hub rows: don't use it), `source_ip`
(+ `source_ipv4`/`source_ipv6`), `error_code` (int), `result`, `action` (`LOGIN` / `FAILED`),
`application`, `id` (= `properties_id`), `machine` (the collector pod). One IP across every sign-in
type in one query. It inherits both paths, so the `interactive_user_signin` subset shows up as a
separate `source` and duplicates `azure-ad-signin`.

### `cloud.azure.ad.microsoft_graph_activity_logs`

One row = one Microsoft Graph API request (`graph.microsoft.com`), Event Hub only, snake_case with
double underscores.
- Caller: `properties__user_id` (object id **stored with quote marks**, `"<guid>"`: match with `->`;
  `=` returns 0 rows), `properties__app_id` (client app id), `properties__service_principal_id`,
  `properties__ip_address_str` (also `_ip4`/`_ip6`; `caller_ip_str` is the same),
  `properties__user_agent`, `properties__client_auth_method` (`0` public client, `1` secret, `2`
  certificate/assertion).
- **Delegated vs app-only:** delegated calls have `properties__user_id` set,
  `properties__service_principal_id` null, `properties__scopes` filled and `properties__roles`
  empty; app-only calls have `properties__user_id` null, a service principal id, `properties__scopes`
  = the literal `""` (two quote characters) and `properties__roles` filled. App-only calls are often
  the majority of volume.
- Request: `properties__request_method` (`GET`, `POST`, `PATCH`, `PUT`, `DELETE`),
  `properties__request_uri` (full URL; user ids or UPNs and object GUIDs inside it: normalise GUIDs
  client-side before grouping), `properties__response_status_code` (int; 200/204/304/404/429…),
  `properties__api_version` (`v1.0`/`beta`), `properties__response_size_bytes`,
  `properties__wids` (directory role template ids in the token), `properties__scopes`, `properties__roles`.
- Join ids: `properties__sign_in_activity_id` = the **token's sign-in**, in uniqueTokenIdentifier form
  (see below); `properties__client_request_id` = the caller's client-request-id, which some Microsoft
  portals reuse as the audit `correlationId`; `properties__request_id` = `properties__operation_id` =
  `correlation_id` (Graph's own id, not seen elsewhere). `properties__token_issued_at` (timestamp) is
  when the token was issued: search sign-ins around it, not around the call. There may be **no
  session id field** in the Graph logs; check `devo.py fields cloud.azure.ad.microsoft_graph_activity_logs`.
- `properties__ip_address_str` can be a Microsoft service IP for delegated calls made on the user's
  behalf (Teams service, Office on-behalf-of flows), so a Graph IP that differs from the user's
  sign-in IP is not by itself suspicious; check the ASN.
- Speed: `--chunk 1h` for anything over a few hours (add `--parallel` for long ranges).

### `cloud.azure.ad.audit`

One row = one Entra directory change or audited action. Fields: `operationName` (=
`properties_activityDisplayName`), `properties_loggedByService` (`Core Directory`, `Account
Provisioning`, `Authentication Methods`, `Self-service Password Management`, `Self-service Group
Management`, `Device Registration Service`, `PIM`, `B2C`, `Access Reviews`, `Azure MFA`),
`properties_category` (`UserManagement`, `GroupManagement`, `RoleManagement`, `ApplicationManagement`,
`Device`, `KeyManagement`, `ProvisioningManagement`, `Policy`…), `properties_operationType` (`Add`,
`Update`, `Delete`, `Assign`, `Read`), `properties_result` (`success`, `failure`, `clientError`),
`properties_resultReason` (text; for security-info changes it names the method),
`properties_activityDateTime_aux` (event time, ISO) / `properties_activityDateTime_timestamp`.
- Actor: `properties_initiatedBy_user_userPrincipalName`, `properties_initiatedBy_user_id` (object
  id), `properties_initiatedBy_user_ipAddress` (= `callerIpAddress`), or for apps
  `properties_initiatedBy_app_displayName` / `…_appId` / `…_servicePrincipalId` (e.g. `MS-PIM`,
  `Azure MFA StrongAuthenticationService`, `Microsoft Approval Management`, the directory-sync
  account `ConnectSyncProvisioning_<server>_<id>`, Intune services). **Self-service Group Management
  writes the acting user's UPN into `properties_initiatedBy_app_displayName`** and leaves the user
  fields null. User-initiated rows are usually a small minority; Account Provisioning and directory
  sync tend to dominate.
- Target: `properties_targetResources` (JSON) and `properties_additionalDetails` (JSON list of
  `{key, value}`). Search them with `weakhas(stringify(f), "x")`; extract with `jqeval(jqcompile(…), f)`.
  `rawJson` holds the whole event.

**Duplicate ingestion.** When both collectors write audit, the Event Hub copy (`tenantId` set,
`region` set, `category` `AuditLogs`, `properties_id` set) is a superset; the API copy (`tenantId`
null, `region` `-`, `category` = the Graph category, **no `properties_id`**) duplicates only part of
it (most Core Directory events, fewer provisioning and PIM-service events). So:
- Count on the Event Hub copy: `isnotnull(tenantId), tenantId != "-"`, **and** de-duplicate on
  `properties_id` (Event Hub also redelivers some rows).
- An alert on this table fires twice only when both copies exist (most Core Directory events, e.g.
  the MS-PIM "Add member to role"); PIM-service and provisioning events mostly fire once.
- For a single event, check both copies (match on `correlationId` + `operationName`).
- `correlationId` is not unique per row: one directory-sync or provisioning run shares it across many
  rows.

**`properties_targetResources` layouts:**

| Operation | `[0]` | `[1]` | Where the detail is |
|---|---|---|---|
| Add/Remove member to/from group, Add owner to group | the member (`type` User, Device or ServicePrincipal; `userPrincipalName` for users) | Group (`displayName` empty) | `.[0].modifiedProperties[1]` is always `Group.DisplayName` (`newValue` on add, `oldValue` on remove); `[0]` is `Group.ObjectID` |
| Add/Remove member to/from role (Core Directory, incl. MS-PIM) | the user | Role | `.[0].modifiedProperties[1]` = `Role.DisplayName`; `[2]` `Role.TemplateId` |
| `… (PIM activation)` (PIM service) | Role (`displayName` = role) | Directory or Subscription | additionalDetails `Justification`, `StartTime`, `ExpirationTime`, `ipaddr`, `oid` |
| Update user | the user | | `modifiedProperties[]`; `Included Updated Properties` lists what changed (`StrongAuthenticationPhoneAppDetail` = Authenticator app re-registration, `LastDirSyncTime`, `ProxyAddresses`, `AccountEnabled`…) |
| Add user | the user | | `modifiedProperties` (`UserType` `["Guest"]`, `CreationType` `["Invitation"]` for B2B invites) |
| Disable account / Delete user | the user | | `AccountEnabled` `[true]` → `[false]`; `Is Hard Deleted` |
| User registered / deleted security info, User started security info registration | the user | | `properties_resultReason` names the method ("User registered Fido2 Authentication Method", "User deleted Microsoft Authenticator Authentication Method"); additionalDetails `InitiatedFrom` |
| Consent to application, Add delegated permission grant, Add app role assignment to service principal | ServicePrincipal (the app) | | `ConsentContext.IsAdminConsent`, `ConsentAction.Permissions`, `DelegatedPermissionGrant.Scope` (old/new scope list) |
| Add service principal credentials, Update application – Certificates and secrets management | ServicePrincipal / Application | | `KeyDescription` (old/new key list: `KeyIdentifier`, `KeyType`, `KeyUsage`) |

`modifiedProperties` values are JSON-encoded strings inside JSON, so `jqeval` returns them doubly
quoted (`"\"Group Name\""`). Devo's `jqcompile` accepts paths, `[]`, pipes and array construction
(`[.[0].modifiedProperties[] | .newValue]`) but **rejects `select(...)`, `map(select(...))` and
`==`** ("Invalid filter"), so address by position (stable, as above) or parse JSONL client-side.
Note `Update application – Certificates and secrets management ` has an en dash and a trailing
space.

**Linking an audit event to the sign-in or API call behind it:**
- There is no session id or token id in the audit log. Link by **user object id + time**:
  `properties_initiatedBy_user_id` = sign-in `properties_userId`; look at sign-ins in both sign-in
  tables in the hour before `properties_activityDateTime_aux` (lag means the sign-in row may arrive
  after the audit row).
- `properties_initiatedBy_user_ipAddress` often does not equal any of the user's sign-in IPs: for
  portal and My Security Info changes it is often a Microsoft service address (Azure ranges, shared
  by several users in the same hour). Treat an IP match as confirmation, a mismatch as normal.
- Audit `correlationId` = Graph `properties__client_request_id` for flows that go through Graph with
  the client's request id: My Security Info (passkey/authenticator registration, `checkAccess`), SSPR,
  LAPS (`Update device local administrator password`), B2C, access reviews. Core Directory changes
  made in the Entra/Azure portals generally do not match.
- PIM rows carry the actor's `ipaddr` and `oid` in additionalDetails.

### `cloud.azure.ad.provisioning`

One row = one provisioning action by the Entra provisioning service to a target system,
e.g. a SaaS app's SCIM endpoint.
**Use the API rows only (`isnotnull(properties_id)`)**: the Event Hub copy (`category`
`ProvisioningLogs`) has only header fields (`resultType` `Success`/`Skipped`) and no
details. Fields: `properties_servicePrincipal_Name` (the target app's enterprise app),
`properties_targetSystem_Name` (`customappsso` for a generic SCIM app, otherwise `<target system>`),
`provisioningAction` (`create`, `update`, `delete`, `disable`, `other`),
`properties_sourceIdentity_identityType` (`User`/`Group`), `sourceIdentityDetailsUserPrincipalName`
(UPN, **mixed case**: use `weakhas`), `properties_sourceIdentity_Name` (display name),
`properties_targetIdentity_Id` (id in the target app), `provisioningStepsStatus` (comma list per step:
`import,matching,scoping,export`; a `failure` at the end means the export failed;
`properties_statusInfo_Status` is empty), `properties_jobId`, `properties_cycleId`,
`properties_changeId`, `properties_modifiedProperties` (JSON string). Many rows can be group
`create` re-evaluations ending in `skipped`. Investigation use: when a leaver was disabled/deleted in
each downstream app, or when an account was created in a downstream app.

### `cloud.azure.ad.user_risk_events` and `cloud.azure.ad.alerts`

`user_risk_events`: one row = an Entra ID Protection risk detection (Event Hub `UserRiskEvents`). A
detection is re-sent when its state changes, so group by `properties__id`. Fields (double
underscore): `properties__userPrincipalName` (mixed case), `properties__userId`,
`properties__ipAddress` (**ip4 type**: compare with an unquoted literal), `properties__location`
(JSON), `properties__riskEventType` (`unfamiliarFeatures`, `anonymizedIPAddress`, `unlikelyTravel`,
`passwordSpray`, `aiCompoundAccountRisk`…), `properties__riskLevel` (`low`/`medium`/`high`),
`properties__riskState` (`atRisk`, `remediated`, `dismissed`), `properties__riskDetail`,
`properties__detectionTimingType` (`realtime`/`offline`), `properties__activity` (`signin` or `user`),
`properties__activityDateTime_str`, `properties__additionalInfo` (JSON: `riskReasons` such as
`UnfamiliarASN`, `UnfamiliarDevice`, `UnfamiliarLocation`). **Link to the sign-in:**
`properties__requestId` = sign-in `properties_id` (look in `cloud.azure.ad.signin` first), and
`properties__correlationId` = sign-in `correlationId`. `properties__id` (64 hex chars, = top-level
`correlationId`) is the detection id.

`cloud.azure.ad.alerts`: one row = an Identity Protection alert from the Graph security API
(`vendorInformation__provider` `IPC`). `id` = the risk event's `properties__id`.
`category` (`UnfamiliarLocation`, `AnonymousLogin`, `ImpossibleTravel`, `PasswordSpray`), `title`,
`severity`, `status` (`newAlert`/`resolved`), `userStates__aadUserId`, `userStates__logonIp`,
`userStates__logonLocation`, `userStates__logonDateTime`. `userStates__userPrincipalName` and other
`userStates__*` fields often hold the **string `"null"`**: use `userStates__aadUserId`. Not every
risk event becomes an alert.

### `cloud.azure.others.events`

Catch-all for Event Hub categories without their own table. Only `category`, `operationName`,
`tenantId`, `timestamp` are columns; everything else is in `properties` (JSON) and `rawMessage`.
Categories you may see (depends on which diagnostic settings are exported):

| `category` | What it is | Useful `properties` keys |
|---|---|---|
| `AdvancedHunting-CloudProcessEvents` | Defender for Cloud container/Kubernetes process events (can be very high volume) | `ProcessCommandLine`, `AzureResourceId`, `KubernetesPodName`… |
| `AdvancedHunting-CloudAuditEvents` | AKS (Kubernetes) API audit | `OperationName` (verb), `RawEventData.RequestURI`, `RawEventData.User`, `IPAddress`, `AzureResourceId` |
| `AzureADGraphActivityLogs` | legacy **Azure AD Graph** (`graph.windows.net`) API calls | `appId`, `servicePrincipalId`, `userId`, `actorType` (`Application`/`User`), `httpMethod`, `requestUri`, `httpStatusCode`, `callerIpAddress`, `signInActivityId`, `sessionId`, `userAgent` |
| `NetworkAccessTrafficLogs`, `NetworkAccessConnectionEvents` | Global Secure Access (Entra Internet/Private Access) client traffic | `UserPrincipalName`, `UserId`, `DeviceId`, `ClientDeviceName`, `SourceIp`, `DestinationFQDN`, `CloudAppName`, `Action`, `InitiatingProcessName` |
| `AdvancedHunting-IdentityInfo` | Defender identity inventory changes | `AccountUpn`, `AccountObjectId`, `IsAccountEnabled` |

Always filter on `category` first (one category can dominate the table). In Azure AD Graph rows
`signInActivityId` is a **plain GUID = sign-in `properties_id`** (not the base64 form), usually found
in `aadiam.microsoftserviceprincipalsigninlogs`, sometimes in non-interactive. `jqeval` values come
back JSON-quoted (`"\"Application\""`).

### Device and location fields for impossible travel and new devices

- Reliable: `properties_location_countryOrRegion`, `properties_autonomousSystemNumber`,
  `properties_deviceDetail_deviceId` (Entra device object id, stable per device; filled for
  registered devices), `…_trustType`, `…_isCompliant`, `…_operatingSystem`.
- City/state/coordinates are IP geolocation: fine for country, rough for city (mobile carrier IPs
  land in odd cities).
- **ASN 8075 (Microsoft) breaks country checks**: Windows Sign In, Office shell and cloud
  proxy/ZTNA sign-ins from Cloud PC or Microsoft egress geolocate to many countries. Exclude or flag
  ASN 8075 (and your proxy's egress ASN) before calling impossible travel. Most real users use one
  country a day.
- `properties_deviceDetail_displayName` is the device name (Windows: uppercase NetBIOS name, the same
  machine as Windows `host` `host01.corp.example`); guests show `{PII Removed}` in both device fields;
  unregistered devices have them blank, so "no device id" is common for personal devices and not proof
  of a new device. Most users use one or two device ids a day.
- Event Hub `location` equals `properties_location_countryOrRegion`; Graph has only
  `properties__location` (the Azure region that served the call), not the caller's.

### Linking recipes

Interactive sign-ins for a user (use `signin`, not `interactive_user_signin`):
```linq
from cloud.azure.ad.signin
where weakhas(properties_userPrincipalName, "jsmith")
group by properties_userPrincipalName, properties_userId, properties_ipAddress, properties_location_countryOrRegion,
  properties_appDisplayName, properties_clientAppUsed, properties_status_errorCode, properties_deviceDetail_displayName
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Count sign-ins, not rows (duplicates; with `--chunk 6h`, sum `rows` but don't add `signins` across
chunks unless the user is quiet):
```linq
from cloud.azure.ad.noninteractive_user_signin
where weakhas(properties_userPrincipalName, "jsmith")
group by properties_userPrincipalName
select count() as rows, hllppcount(properties_id) as signins
```

Follow one session from the interactive sign-in into token refreshes (session id from the
interactive row; both field names because of the two collectors):
```linq
from cloud.azure.ad.noninteractive_user_signin
where properties_sessionId = "<session-guid>" or sessionId = "<session-guid>"
group by properties_userPrincipalName, properties_ipAddress, properties_location_countryOrRegion,
  properties_appDisplayName, properties_deviceDetail_deviceId
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```
```linq
from cloud.azure.ad.signin
where properties_sessionId = "<session-guid>"
group by properties_userPrincipalName, properties_ipAddress, properties_appDisplayName, properties_status_errorCode
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

All sessions of a user's successful interactive sign-ins, expanded into non-interactive use, one row
per session × IP × ASN × country × device (subquery; `--chunk 8h` over long ranges). Look for a
session with a second ASN or country:
```linq
from cloud.azure.ad.noninteractive_user_signin
where properties_sessionId in (from cloud.azure.ad.signin
    where "<start>" < eventdate < "<end>", category = "SignInLogs",
      weakhas(properties_userPrincipalName, "jsmith"), properties_status_errorCode = 0
    group by properties_sessionId)
group by properties_sessionId, properties_userPrincipalName, properties_ipAddress, properties_autonomousSystemNumber,
  properties_location_countryOrRegion, properties_deviceDetail_deviceId
select count() as n, hllppcount(properties_appDisplayName) as apps, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Sign-in → the Graph calls made with its tokens (subquery). The token id joins
`properties__sign_in_activity_id`; delegated Graph tokens come from **non-interactive** sign-ins,
app-only ones from `service_principal_signin` (or the first-party `aadiam` table). The subquery only
sees Event Hub rows (`properties_uniqueTokenIdentifier`), which is usually nearly all of them. Keep
`--to` in the past (see the trap below):
```linq
from cloud.azure.ad.microsoft_graph_activity_logs
where properties__sign_in_activity_id in (
  from cloud.azure.ad.noninteractive_user_signin
  where "<start>" < eventdate < "<end>",
    weakhas(properties_userPrincipalName, "jsmith"), properties_ipAddress = "203.0.113.10"
  group by properties_uniqueTokenIdentifier)
group by properties__sign_in_activity_id, properties__app_id, properties__ip_address_str, properties__request_method,
  properties__response_status_code
select count() as n, min(eventdate) as first, max(eventdate) as last
```
Two-step alternative: pull `properties_uniqueTokenIdentifier, uniqueTokenIdentifier` from the
sign-in query with `--format jsonl`, then `… where properties__sign_in_activity_id in {"<token-id>", …}`
on the Graph table with `--chunk 1h`. Tokens issued before the window won't be found this way:
search from `properties__token_issued_at`.

Graph call → its sign-in (the token id as stored in Graph):
```linq
from cloud.azure.ad.noninteractive_user_signin
where properties_uniqueTokenIdentifier = "<token-id>" or uniqueTokenIdentifier = "<token-id>"
select eventdate, properties_id, properties_userPrincipalName, properties_ipAddress, properties_appDisplayName,
  properties_resourceDisplayName, properties_sessionId
```
For an app-only call use `cloud.azure.ad.service_principal_signin` with the same filter, or
`cloud.azure.aadiam.microsoftserviceprincipalsigninlogs` with `properties_unique_token_identifier`.
Then follow `properties_sessionId` (recipe above) to the interactive sign-in.

Graph activity for a user (ids are stored quoted; `->`):
```linq
from cloud.azure.ad.microsoft_graph_activity_logs
where properties__user_id -> "<object-id>"
group by properties__user_id
select count() as n
```

Audit event → Graph request (works for My Security Info, SSPR, LAPS, B2C):
```linq
from cloud.azure.ad.microsoft_graph_activity_logs
where properties__client_request_id = "<audit-correlationId>"
select eventdate, properties__request_method, properties__request_uri, properties__response_status_code,
  properties__user_id, properties__app_id, properties__ip_address_str, properties__sign_in_activity_id
```

Audit event → the actor's sign-ins before it (object id from `properties_initiatedBy_user_id`;
window: two hours before `properties_activityDateTime_aux` to ten minutes after; repeat on
`noninteractive_user_signin`):
```linq
from cloud.azure.ad.signin
where properties_userId = "<object-id>"
group by properties_ipAddress, properties_appDisplayName, properties_sessionId, properties_status_errorCode
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Group and role membership changes, with the group or role name:
```linq
from cloud.azure.ad.audit
where isnotnull(tenantId), tenantId != "-",
  operationName in {"Add member to group", "Remove member from group", "Add member to role", "Remove member from role"}
select jqeval(jqcompile(".[0].userPrincipalName"), properties_targetResources) as member,
  jqeval(jqcompile(".[0].type"), properties_targetResources) as member_type,
  jqeval(jqcompile(".[0].modifiedProperties[1].newValue"), properties_targetResources) as added_to,
  jqeval(jqcompile(".[0].modifiedProperties[1].oldValue"), properties_targetResources) as removed_from
group by operationName, member_type, added_to, removed_from, properties_initiatedBy_app_displayName
select count() as n
```
Add `member` to the `group by` to list people; add
`weakhas(stringify(properties_targetResources), "jsmith")` to the `where` for one person.

MFA / authentication-method changes (the method is in `properties_resultReason`):
```linq
from cloud.azure.ad.audit
where isnotnull(tenantId), tenantId != "-", properties_loggedByService = "Authentication Methods"
select jqeval(jqcompile(".[0].userPrincipalName"), properties_targetResources) as target_user
group by operationName, properties_resultReason, properties_result
select count() as n, hllppcount(target_user) as users
```
Authenticator re-registrations by the service show as `Update user` by `Azure MFA
StrongAuthenticationService` with `StrongAuthenticationPhoneAppDetail` in `Included Updated
Properties`. Admin-driven deletions show `properties_initiatedBy_app_displayName` = the automation app.

App consent, permission grants and new credentials:
```linq
from cloud.azure.ad.audit
where isnotnull(tenantId), tenantId != "-",
  operationName in {"Consent to application", "Add delegated permission grant", "Add app role assignment to service principal",
    "Add service principal credentials", "Update application – Certificates and secrets management ",
    "Add service principal", "Add application"}
select jqeval(jqcompile(".[0].displayName"), properties_targetResources) as target,
  jqeval(jqcompile(".[0].type"), properties_targetResources) as target_type
group by operationName, target, target_type, properties_initiatedBy_user_userPrincipalName,
  properties_initiatedBy_app_displayName, properties_result
select count() as n, min(eventdate) as first_seen
```
Pull the matching rows with `--format jsonl` to read `ConsentAction.Permissions`,
`DelegatedPermissionGrant.Scope` and `KeyDescription` from `modifiedProperties`.

Risk detection → the sign-in it flagged:
```linq
from cloud.azure.ad.signin
where category = "SignInLogs",
  properties_id in (from cloud.azure.ad.user_risk_events
    where "<start>" < eventdate < "<end>", properties__activity = "signin"
    group by properties__requestId)
group by properties_userPrincipalName, properties_ipAddress, properties_location_countryOrRegion, properties_appDisplayName,
  properties_status_errorCode, properties_riskLevelDuringSignIn, properties_riskState
select count() as n, min(eventdate) as first_seen
```

Country / ASN per user per hour, for impossible-travel review (post-process: flag users with two
countries within a few hours after dropping ASN 8075 and proxy ASNs; add
`noninteractive_user_signin` with `--chunk 3h` for a full picture):
```linq
from cloud.azure.ad.signin
where category = "SignInLogs", properties_status_errorCode = 0
group every 1h by properties_userPrincipalName, properties_location_countryOrRegion, properties_autonomousSystemNumber
select count() as n, hllppcount(properties_ipAddress) as ips
```

Devices a user signed in from, for a new-device check (`--chunk 5d` over a month):
```linq
from cloud.azure.ad.signin
where weakhas(properties_userPrincipalName, "jsmith"), properties_status_errorCode = 0
group by properties_userPrincipalName, properties_deviceDetail_deviceId, properties_deviceDetail_displayName,
  properties_deviceDetail_operatingSystem, properties_deviceDetail_trustType, properties_deviceDetail_isCompliant
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Credential-attack failures, separated from interrupts:
```linq
from cloud.azure.ad.signin
where category = "SignInLogs", properties_status_errorCode in {50126, 50053, 50057, 50055, 50034}
group by properties_userPrincipalName, properties_ipAddress, properties_status_errorCode, properties_status_failureReason
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Every sign-in type from one IP (union):
```linq
from cloud.azure.ad.signin_all
where source_ip = "203.0.113.10"
group by source, username, error_code
select count() as n
```

Service principal baseline: which apps sign in from where, with which credential (`--chunk 6h`
over a day). A known app from a new IP/country or a new credential type is the signal; group by
`clientCredentialType` too, for API rows:
```linq
from cloud.azure.ad.service_principal_signin
group by properties_appDisplayName, properties_appId, properties_ipAddress, properties_location_countryOrRegion,
  properties_clientCredentialType, properties_resourceDisplayName, properties_status_errorCode
select count() as n, hllppcount(properties_id) as signins
```

Managed identities and what they get tokens for:
```linq
from cloud.azure.ad.managed_identity_signin
group by properties_servicePrincipalName, properties_resourceDisplayName, managedServiceIdentity_associatedResourceId,
  properties_status_errorCode
select count() as n
```

First-party Microsoft service principals (snake_case fields):
```linq
from cloud.azure.aadiam.microsoftserviceprincipalsigninlogs
group by properties_service_principal_name, properties_resource_display_name, properties_status_error_code
select count() as n
```

A user's downstream provisioning (created/disabled/deleted in downstream apps; long ranges can be
slow):
```linq
from cloud.azure.ad.provisioning
where isnotnull(properties_id), weakhas(sourceIdentityDetailsUserPrincipalName, "jsmith")
group by sourceIdentityDetailsUserPrincipalName, properties_servicePrincipal_Name, provisioningAction, provisioningStepsStatus
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

Legacy Azure AD Graph calls (in `others.events`):
```linq
from cloud.azure.others.events
where category = "AzureADGraphActivityLogs"
select jqeval(jqcompile(".appId"), properties) as appId,
  jqeval(jqcompile(".userId"), properties) as userId,
  jqeval(jqcompile(".actorType"), properties) as actorType,
  jqeval(jqcompile(".httpMethod"), properties) as method
group by appId, userId, actorType, method
select count() as n
```

Global Secure Access traffic for a user (UPN, device, source IP; `--chunk 1d` over long ranges):
```linq
from cloud.azure.others.events
where category in {"NetworkAccessTrafficLogs", "NetworkAccessConnectionEvents"}, weakhas(stringify(properties), "jsmith")
select jqeval(jqcompile(".UserPrincipalName"), properties) as upn,
  jqeval(jqcompile(".DeviceId"), properties) as dev,
  jqeval(jqcompile(".SourceIp"), properties) as src
group by category, upn, dev, src
select count() as n, min(eventdate) as first_seen, max(eventdate) as last_seen
```

**Trap: a `--to` in the future hangs.** A query (or a `--chunk` window) whose end is later than now
waits until the query timeout, and returns at once when rerun with `--to now`. Use `now`, or an end
time in the past, never "the end of this hour".
