# Devo Alerts API reference

Load this when working with Devo triggered alerts or alert definitions over HTTP. `scripts/devo.py` wraps the
read endpoints; use this file to interpret fields and statuses, or to call a read endpoint the helper
does not cover.

## Contents

1. [Base URLs](#base-urls)
2. [Authentication and required headers](#authentication-and-required-headers)
3. [Status codes and priority scale](#status-codes-and-priority-scale)
4. [Triggered alert fields](#triggered-alert-fields)
5. [Read endpoints: triggered alerts](#read-endpoints-triggered-alerts)
6. [Read endpoints: alert definitions](#read-endpoints-alert-definitions)
7. [Read endpoint: list comments](#read-endpoint-list-comments)
8. [Querying alerts with LINQ instead](#querying-alerts-with-linq-instead)
9. [Errors](#errors)
10. [Doc inconsistencies to be aware of](#doc-inconsistencies-to-be-aware-of)
11. [Write operations (only comments/add is enabled)](#write-operations-only-commentsadd-is-enabled)

## Base URLs

Choose the base URL for the domain's region and append the endpoint path.

| Region | Base URL |
| --- | --- |
| USA | `https://api-us.devo.com/alerts/v1` |
| EU | `https://api-eu.devo.com/alerts/v1` |
| CA | `https://api-ca.devo.com/alerts/v1` |
| APAC | `https://api-apac.devo.com/alerts/v1` |
| US3 | `https://api-us3.devo.com/alerts/v1` |

The docs sometimes write paths as `/v1/alerts/list`; the `/v1` is already part of the base URL, so the
full URL is e.g. `https://api-us.devo.com/alerts/v1/alerts/list`. A wrong path returns an HTML 404 page, not
JSON (verified live), so treat a non-JSON body as "bad path".

## Authentication and required headers

- `standAloneToken: <token>` is the documented header. `Authorization: Bearer <token>` also works
  (verified live).
- Always send an explicit `User-Agent` header. Cloudflare blocks Python's default UA with HTTP 403 and
  body `error code: 1010` (verified live). This is not a permissions error.
- Tokens are created with type **Alert API**; the token is tied to a user and a set of target tables.
- What a token can do follows the associated user's role permissions:
  - GET requests need *Alert configuration* and *Triggered alerts* at *View* level.
  - POST, PUT and DELETE need the same permissions at *Manage* level.

```bash
curl -H "standAloneToken: $DEVO_TOKEN" -H "User-Agent: devo-skill/1.0" \
  "https://api-us.devo.com/alerts/v1/alerts/get?id=123456"
```

## Status codes and priority scale

Triggered-alert `status` values, exactly as the docs define them (from `updateStatus`):

| Code | Status |
| --- | --- |
| `0` | Unread |
| `1` | Updated |
| `2` | False Positive |
| `100` | Watched |
| `300` | Closed |
| `800` | Suppressed |

The docs say `showAll=false` (the default) excludes False Positive and Closed alerts and
`showAll=true` includes them. **[verified] Live it is the reverse**: omitting `showAll` (or
`false`) returned every status (including Closed, Suppressed and custom codes), while `showAll=true` returned
the same set *minus* the Closed alerts. `devo.py alerts` never sends it and filters client-side
(`--open`).

**[verified]** Domains can also use custom status codes that aren't in the docs. They are
domain-specific workflow states (e.g. set by automation that forwards alerts to an external case
tool): read the alert's comments to learn what a code means, and report the raw code alongside
that.

Triggered-alert `priority` scale (from `PUT /alerts/{alertID}/priority`; values 1-10):

| Label | Values |
| --- | --- |
| Very low | `1` |
| Low | `2`, `3` |
| Medium | `4`, `5` |
| High | `6`, `7` |
| Very high | `8`, `9`, `10` |

The alert-definition docs give a slightly different scale for `alertCorrelationContext.priority`:
Very low `0`, `1`; Low `2`, `3`; Normal `4`, `5`; High `6`, `7`; Very high `8`, `9`, `10` (while also
saying values 1-10 are allowed). Treat 0 and 1 both as Very low.

## Triggered alert fields

A triggered alert as returned by `alerts/get` (and each element of `alerts/list`). Many fields are
usually `null`.

| Field | Meaning |
| --- | --- |
| `id` | Triggered alert ID (integer). Use with `alerts/get?id=`, comments, status updates. |
| `domain` | Devo domain name. |
| `priority` | Numeric priority, see scale above. |
| `status` | Numeric status code, see table above. |
| `context` | Alert rule identifier, `my.alert.<domain>.<AlertName>`. The last segment matches the alert definition's `name` (verified live); in the docs' examples the whole string has the same form as the definition's `alertCorrelationContext.nameId`. |
| `category` | Category string, e.g. `my.context`. |
| `srcIp`, `srcPort`, `srcHost` | Source network fields, if the alert query produced them. |
| `dstIp`, `dstPort`, `dstHost` | Destination network fields. |
| `protocol`, `application` | Protocol and application, if available. |
| `username` | User associated with the alert (e.g. `alice@example.com`). |
| `engine` | Engine/pipeline that produced the alert. |
| `extraData` | JSON **string** with the alert query's columns. Values are URL-encoded (see below). Can hold up to 65 KB. |
| `createDate` | When the alert was triggered. Epoch milliseconds in `alerts/get` responses. |
| `updateDate` | Last update (e.g. after status change), epoch ms or `null`. |
| `alertDate`, `ack_status_date` | Additional dates; often `null`. |
| `scaled` | Boolean. |
| `digest`, `uniquedigest` | Hash identifiers of the alert. |
| `contextLabel`, `contextSubscription`, `alertOwner`, `alertType`, `alertPriority`, `alertMitreTactics`, `alertMitreTechniques`, `postAlertAction`, `shouldSend` | Metadata; often `null`/`false`. |
| `fullExtraData`, `allExtraDataFields` | Extended extra data (map of field -> value in the list schema). |
| `alertDefinition` | Embedded definition object (same shape as in `alertDefinitions`, including `alertCorrelationContext.querySourceCode`), or `null`. |
| `tags` | Array of tag strings, or `null`. |
| `entities` | Array of entities (hostname, ip, email, account, hash, `entityType`...), or `null`. |
| `commentsList` | Array of comments (`msg`, `title`, `author`, `creationDate`...). |
| `integrations`, `contexto` | Integration info and the context/category/subcategory object. |

### Decoding `extraData`

`extraData` must be parsed twice: `json.loads` the string, then URL-decode each value with
`urllib.parse.unquote_plus`. Example: `"2026-09-21+20%3A15%3A00.000"` decodes to
`"2026-09-21 20:15:00.000"`, and `"%2F192.0.2.10"` decodes to `"/192.0.2.10"`.

```python
import json
from urllib.parse import unquote_plus
extra = {k: unquote_plus(v) if isinstance(v, str) else v
         for k, v in json.loads(alert["extraData"] or "{}").items()}
```

## Read endpoints: triggered alerts

**[verified] Paging quirks of `alerts/list`:** results come **oldest first**, and a page often
holds *fewer* items than `limit` even when more exist. A short page
therefore does not mean the end: keep increasing `offset` until an empty page comes back, then
de-duplicate by `id` and sort by `createDate` yourself. `orderby=createDate` returns newest
first but has the same short-page behaviour. `devo.py alerts` does all of this.

**[verified] `alerts/get` returns `alertDefinition: null`.** Only `alerts/list` embeds the
definition (name, description, `alertCorrelationContext.sourceTable` and `querySourceCode`, the
detection's LINQ). To get it for one alert, list the window `createDate ± 1 min` and match on
`id` (`devo.py alert <id>` does this). Matching `context` to `alertDefinitions?nameFilter=`
is unreliable: the context can carry an internal name (`Example_Vendor_..._Alert`), while
`nameFilter` matches the display name (`Example - Vendor ... Alert`).

**[verified] Comment objects** (in `commentsList`) have `msg`, `title`, `creationDate`,
`elementId`, `ack` and `author.user.username` (an email), plus a large `author`/`domain`
blob you can ignore.

All return 400 (bad request), 401 (unauthorized), 403 (forbidden), 405 (method not allowed) or 500
(server error) on failure.

### GET `/alerts/list`

List triggered alerts in a time range. Limits: at most 100,000 alerts and at most 90 days per request.

| Parameter | Type | Required | Notes |
| --- | --- | --- | --- |
| `from` | string (epoch ms) | yes | Alerts triggered after this time. Omitting it returns 400 code 618 "must not be null" (verified live). |
| `to` | string (epoch ms) | yes | Alerts triggered before this time. Same 618 error if missing. |
| `limit` | integer | yes | Max elements returned. |
| `offset` | integer | yes | Index of first element; `0` for no offset. Use with `limit` to page. |
| `orderby` | string | no | One of `id`, `domain`, `priority`, `context`, `category`, `srcPort`, `srcIp`, `srcHost`, `dstIp`, `dstPort`, `dstHost`, `protocol`, `username`, `application`, `engine`, `extraData`, `status`, `ack_status_date`, `createDate`, `updateDate`. |
| `orderasc` | boolean | no | `true` for ascending order. |
| `showAll` | boolean | no | `true` includes False Positive and Closed alerts. Default `false`. |

Response: JSON array of triggered alert objects (fields above).

```bash
curl -H "standAloneToken: $DEVO_TOKEN" -H "User-Agent: devo-skill/1.0" \
  "https://api-us.devo.com/alerts/v1/alerts/list?limit=50&offset=0&from=1790000000000&to=1790086400000&showAll=true"
```

### GET `/alerts/get`

Get one triggered alert by ID. Works with IDs returned by `listStatus` or `list` (verified live).

| Parameter | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | string | yes | Triggered alert ID. |
| `tags` | boolean | no | Include tags. Default `true`. The docs say using this parameter requires a Query API token (not an Alert API token). |
| `annotations` | boolean | no | Include annotations. Default `true`. |

Response: a single triggered alert object.

### GET `/alerts/listStatus`

Cheap way to find recent alert IDs and their statuses.

| Parameter | Type | Required | Notes |
| --- | --- | --- | --- |
| `from` | string (epoch ms) | no | Default: 24 hours before the request. |

Response: object mapping alert ID (string) to status code, e.g. `{"123456": 0, "123457": 2, "123458": 100}`.

### GET `/alerts/statistics`

Aggregate counts of triggered alerts.

| Parameter | Type | Required | Notes |
| --- | --- | --- | --- |
| `hours` | integer | no | Number of hours back to analyse. |
| `from` | integer (epoch ms) | no | Alerts triggered after this time. |
| `type` | string | no | `raw` (default), `funnel` or `list`. |
| `filterName` | string | no | Filter by alert name. |
| `showAll` | boolean | no | Include False Positive and Closed. Default `false`. |

Example response (`type=funnel`):
`{"total":{"total":30,"enriched":30},"types":{"Model":{"total":0,"enriched":0},"Observation":{"total":0,"enriched":0},"Detection":{"total":20,"enriched":20},"Analytics":{"total":10,"enriched":10}}}` (illustrative counts)

## Read endpoints: alert definitions

### GET `/alertDefinitions`

List alert definitions (the rules that produce triggered alerts).

| Parameter | Type | Notes |
| --- | --- | --- |
| `page` | number | Zero-based page index. |
| `size` | number | Page size. With 12 definitions, `page=2&size=5` returns items 10-11 (groups 0-4, 5-9, 10-11). |
| `nameFilter` | string | Case-insensitive substring match on the definition name. |
| `idFilter` | number | Return only the definition with this ID. Definition IDs are only obtainable through this API. |

Response: JSON array of definitions. Key fields:

| Field | Meaning |
| --- | --- |
| `id` | Definition ID (string), e.g. `"214554"`. Not the same as triggered alert IDs. |
| `name` | Definition name, e.g. `BruteForceLogin`. Matches the last segment of a triggered alert's `context`. |
| `message` | Summary text; may contain `$columnName` variables. |
| `description` | Full description; may contain `$columnName` variables. |
| `categoryId`, `subcategory`, `subcategoryId` | Grouping; user alerts live under **My Alerts** and `subcategory` looks like `lib.my.<domain>.<name>`. |
| `isActive` | Whether the rule is enabled. |
| `isFavorite`, `isAlertChain` | Booleans. |
| `creationDate` | Epoch ms. |
| `alertCorrelationContext.nameId` | `my.alert.<domain>.<name>`; equals the triggered alert's `context`. |
| `alertCorrelationContext.ownerEmail` | Owner of the rule. |
| `alertCorrelationContext.querySourceCode` | **The LINQ query of the alert.** |
| `alertCorrelationContext.priority` | Priority given to triggered alerts. |
| `alertCorrelationContext.correlationTrigger` | `kind` (`each`, `several`, `low`, `inactivity`, `rolling`, `deviation`, `gradient`) plus kind-specific settings (`period`, `threshold`, `keys`, `backPeriod`, `absolute`, `aggregationColumn`, `externalOffset`, `internalPeriod`, `internalOffset`). |
| `actionPolicyId` | Assigned delivery (sending) policy IDs. |

To find the rule behind a triggered alert: take the last segment of `context`, call
`alertDefinitions?nameFilter=<name>`, and pick the entry whose `alertCorrelationContext.nameId` equals
the full `context`. `nameFilter` is a substring match, so several definitions may come back.

## Read endpoint: list comments

### POST `/comments/list`

Despite being a POST, this only reads. Body: JSON array of triggered alert IDs as strings,
e.g. `["123456", "123457"]` (send `Content-Type: application/json`).

Response: array of `{ "idAlert": 123456, "comments": [ ... ] }`. Each comment has `id`, `msg`,
`title`, `creationDate`, `updateDate` (epoch ms), `elementType` (`alert`), `elementId`, `status`, `task`,
`ack` (JSON string with `ackUserList`), and `author` (with `author.user.email`, `author.user.username`).
Responses: 200, 400, 401, 403, 404, 405, 500.

## Querying alerts with LINQ instead

The same triggered alerts are queryable through the Query API from table `siem.logtrust.alert.info`
(verified live). Useful for filtering and aggregation the Alerts API cannot do. Fields include:
`eventdate`, `alertHost`, `domain`, `priority`, `context`, `category`, `status`, `alertId`, `srcIp`,
`srcPort`, `srcHost`, `dstIp`, `dstPort`, `dstHost`, `protocol`, `username`, `application`, `engine`,
`extraData`, `alertContextSubscription`, `alertcreationdate`.

```
from siem.logtrust.alert.info
where context = "my.alert.exampledomain.BruteForceLogin"
select alertId, priority, status, username, srcIp, extraData
```

`alertId` corresponds to the Alerts API `id`.

## Errors

HTTP-level:

| Symptom | Meaning |
| --- | --- |
| 403 with body `error code: 1010` | Cloudflare blocked the User-Agent. Set a custom `User-Agent`. |
| HTML 404 page | Wrong path. |
| 400 with code `618`, "must not be null" | A required parameter is missing (e.g. `from`/`to` on `alerts/list`). Not in the published error table; verified live. |
| 401 / 403 JSON | Token invalid, or the token's user lacks the needed permission level. |

Alerts API error codes (condensed from the docs):

| Range | Group | Codes |
| --- | --- | --- |
| 600-617, 685 | Parameters | 600 subquery missing; 601 subcategory name can't change; 602 invalid keys in Several alert; 603 subquery params missing; 604 external period not configurable; 605 parameter cannot be empty; 606 subcategory too long; 607 priority out of bounds; 608 definition cannot be empty; 609 invalid alert ID; 610 definition with ID not found; 611 name cannot change; 612 context already exists; 613 threshold negative; 614 threshold must be positive; 615 period 1 min-100 days; 616 period 1 s-100 days; 617 rolling period 60 s-100 days; 685 look-back / frequency ratio must be below 120. |
| 630-645 | Query | 630 subquery nested more than one level; 631 `eventdate` in `where`; 632 `client` in `where`; 633 temporal grouping in inner query; 634 pragmas not accepted; 635 expressions in `every`; 636 no aggregation column; 637 parse error; 638 no keys; 639 no time grouping; 640 cannot operate with old alert; 641 no key grouping; 642 temporal grouping found; 643 invalid query; 644 aggregation column must be numeric; 645 aggregation column not found. |
| 650-653 | Alert type | 650 subquery only for Each alerts; 651 query incompatible with alert kind; 652 alert could not be processed; 653 operation unavailable for alerts with subqueries. |
| 660-663 | Permissions | 660/661 unknown table; 662 resource not found; 663 cannot change alert status (not found or not editable). |

## Doc inconsistencies to be aware of

- Priority scale differs between triggered alerts (Very low = 1, "Medium" 4-5) and definitions
  (Very low = 0-1, "Normal" 4-5).
- The `alerts/list` response schema shows dates as ISO strings, while `alerts/get` examples show epoch
  milliseconds for `createDate`/`updateDate`. Handle both.
- `alerts/get`'s `tags` parameter defaults to `true` yet is documented as requiring a Query API token.
- Definition `id` is a string in responses but `idFilter` is documented as a number.
- Permission names vary: "Alert configuration / Triggered alerts (View)" vs "Alerts (view)".
- `from`/`to` on `alerts/list` are documented as required; verified live that omitting them returns 618.

## Write operations (only comments/add is enabled)

**Enabled: `POST /comments/add`, through `devo.py comment` only.** It previews by default and posts
only with `--confirm` after the user has approved the exact text. **[verified]** The
body `{"elementId":"<id>","commentType":"ALERT","commentTitle":"…","commentMsg":"…"}` returned
`true`. The comment appeared in `commentsList` authored by the token's user (display name shown
in the UI). The alert's status and `updateDate` did not change.

**Everything else in this section is not implemented, and the skill must not call it.** If a user
asks for one of these actions, explain what the call would do and draft it for them. All need
*Manage*-level permissions.

Triggered alerts:

- `PUT /alerts/updateStatus?id=<id>&status=<code>` — set one alert's status (codes above). Returns the
  updated alert.
- `PUT /alerts/updateStatusList?status=<code>` — body `["123456","123457"]`; bulk status change.
- `PUT /alerts/{alertID}/priority?priority=<1-10>` — change a triggered alert's priority.
- `PUT /tags` — body `{"alertIds": ["123456"], "tags": ["phishing"]}`; add tags. Returns
  `[{"eventType":"tag","alertId":"123456","tags":[...],"username":...,"deleted":false}]`.

Comments (body fields `commentType` = `ALERT` (new comment) or `REPLY`, `commentTitle`, `commentMsg`):

- `POST /comments/add` — body adds `elementId` (alert ID). Returns `true`.
- `POST /comments/bulk/add` — body adds `elementIds` array. Returns `{"<id>": true, ...}`.
- `PUT /comments/update?commentId=<id>` — body adds `elementId`. Returns `true`.
- `PUT /comments/bulk/update` — body adds `idMap` (map of IDs to comment ID arrays).
- `DELETE /comments/delete` — body is an array of IDs (docs call them alert IDs; the example looks like comment IDs). Returns `true`.

Alert definitions:

- `POST /alertDefinitions` — create. Required: `name`, `subcategory`, `alertCorrelationContext`
  (`querySourceCode`, `priority`, `correlationTrigger.kind` plus kind parameters). Optional: `message`,
  `description`, `isActive` (default `true`), `deliveryPolicy` (`type`: `POLICY_BASED`,
  `NO_NOTIFICATION`, `DEFAULT_POLICY`; `policies`: `[{"id": ...}]`), `timezone` (default `GMT`),
  `locale` (default `en_US`), `withSelectAll`.
- `POST /alertDefinitions/batch` — create several (array body).
- `PUT /alertDefinitions` — update; body must include `id` plus the original `name` and `subcategory`
  (neither can be changed).
- `PUT /alertDefinitions/batch` — update several.
- `PUT /alertDefinitions/{id}/deliveryPolicy` — assign sending policies.
- `PUT /alertDefinitions/status?alertIds=<id>&alertIds=<id>&enable=<true|false>` — enable or disable.
  Returns `{"updated":{"<id>":true}}`.
- `DELETE /alertDefinitions?alertIds=<id>&alertIds=<id>` — delete definitions permanently.
