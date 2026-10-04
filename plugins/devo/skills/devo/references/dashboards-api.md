# Devo dashboards: the Activeboards API

Load this when the user wants to list, read, build, change or delete Devo dashboards. Devo's current
dashboards are **Activeboards**. The older "Dashboards" feature is legacy: it may not be available to
new users, and Devo documents no API for it. `scripts/devo.py` wraps the Activeboards API (`boards`,
`board`, `board-new`, `board-check`, `board-push`, `board-set`, `board-clone`, `board-delete`).

Marks: **[doc]** stated in Devo's public documentation; **[verified]** confirmed against a live
domain; **[inferred]** neither, treat as a lead.

## Contents

1. [Base URLs and authentication](#base-urls-and-authentication)
2. [Endpoints](#endpoints)
3. [The board definition (`settings`)](#the-board-definition-settings)
4. [LINQ inside widgets](#linq-inside-widgets)
5. [Workflow: build or change a board](#workflow-build-or-change-a-board)
6. [Sharing and permissions](#sharing-and-permissions)
7. [Scheduled reports](#scheduled-reports)
8. [Gaps in the documentation](#gaps-in-the-documentation)

## Base URLs and authentication

| Region | Base URL [doc] |
| --- | --- |
| EU | `https://api-eu.devo.com/activeboards/v2` |
| USA | `https://api-us.devo.com/activeboards/v2` |
| CA | `https://api-ca.devo.com/activeboards/v2` |
| APAC | `https://api-apac.devo.com/activeboards/v2` |
| US3 | `https://api-us3.devo.com/activeboards/v2` |

These are the Alerts API hosts (`/alerts/v1`), not the Query API hosts (`apiv2-*`). Each region
also serves a Swagger UI at `https://api-<region>.devo.com/activeboards/#/` [doc].

- Header: `standAloneToken: <token>` [doc]. The helper sends it along with `Authorization: Bearer`, and
  that combination works [verified]. A Query API token works here if its user holds the
  Activeboards permissions [verified].
- Send an explicit `User-Agent`: Devo's Cloudflare blocks Python's default one (see alerts-api.md).
- A token acts as its user: what it can do follows that user's role [doc].
  - `Activeboards (view)`: the GET calls, tags and the scheduled-report endpoints.
  - `Activeboards (manage)`: create, clone, update, privacy, favourite, default, delete.
  - `User resources`: every board in the domain, whoever owns it.
  A token without these returns 401/403 on `boards` even when queries work.

```bash
curl -H "standAloneToken: $DEVO_TOKEN" -H "User-Agent: devo-skill/1.0" \
  "https://api-eu.devo.com/activeboards/v2/activeboards"
```

## Endpoints

Paths are relative to the base URL [doc]. `{id}` is the numeric board id. **The Devo UI doesn't show
board ids**: get them from the list (`devo.py boards`).

| Method | Path | Body | Success | Helper |
| --- | --- | --- | --- | --- |
| GET | `/activeboards` | – | 200, list of summaries (no widgets) [verified] | `boards` |
| GET | `/activeboards/{id}` | – | 200, summary + `settings` [verified]; 404 once deleted [verified] | `board <id>` |
| GET | `/activeboards/default` | – | 200, or 404 when the user has none | `board default` |
| POST | `/activeboards` | `{name, description?, settings}` | 201, the new board with its `id` [verified] | `board-push FILE` |
| PUT | `/activeboards/{id}` | `{name, description?, settings}` | 200 | `board-push FILE --id ID` |
| POST | `/activeboards/{id}/clone` | `{name, description?}` | 201 | `board-clone` |
| PATCH | `/activeboards/{id}/privacy` | `{"privacy": true}` (true = private) | 200 | `board-set --private` |
| PATCH | `/activeboards/{id}/tags` | `{"tags": "a, b"}`: **one comma-separated string** [verified] | 200 | `board-set --tags` |
| PATCH | `/activeboards/{id}/favorite` | `{"favorite": true}` | 200 | `board-set --favorite` |
| PATCH | `/activeboards/{id}/default` | `{"markAsDefault": true}` | 200 | `board-set --default` |
| DELETE | `/activeboards/{id}` | – | 204 [verified] | `board-delete` |

Summary fields [verified]: `id` (integer), `name`, `description`, `creationDate`, `updateDate` (epoch
ms), `isPrivate`, `isDefault`, `favorite`, `editable`, `tags` (a list, or `null` when there are none),
`owner` {`id`, `email`, `username`, `userDomain`}, `version`, `schedules`, `categories`.

- **`editable` is not "this user can edit it"** [verified]. It is `false` even on a board the token's
  user just created and can change. Don't use it to predict a 403.
- `owner.username` can hold the person's display name, not a login [verified].
- A new board is stored exactly as sent. Devo adds `name` to the root of `settings` [verified].
  Changing tags doesn't move `updateDate` [verified].

- **PUT replaces the whole board** [doc; not yet exercised live]. Send the complete `settings`, never a fragment.
  There is no documented optimistic locking. `board-push --id` compares the board's `updateDate` with
  the one recorded at export, and warns when someone edited the board in the meantime.
- No export/import endpoint exists. Export means GET `/{id}` and keeping `name`, `description`,
  `settings` (`board <id> --out FILE`). Import means POST them.
- No pagination, filters or rate limits are documented. Errors: 400, 401, 403, 404, 405, 500 [doc].

## The board definition (`settings`)

`settings` is the same JSON as the UI's **Edit raw configuration** (board menu, in edit mode) [doc],
so a board built in the UI is the best template.

```json
{
  "type": "container", "subtype": "Grid", "datasource": null, "definitions": null,
  "date": {"realTime": false, "from": "now() - 1d", "to": "now()"},
  "settings": {
    "layout": {"Table0": {"x": 0, "y": 0, "w": 6, "h": 10, "i": "Table0", "moved": false, "static": false}},
    "header": false
  },
  "extra": {"favourites": {"widgets": "Line", "inputs": "Input", "containers": "Grid"},
            "autoRefreshPeriod": null, "config": {"theme": {}}},
  "children": {
    "Table0": {
      "name": "Table0", "description": "Requests by method", "type": "widget", "subtype": "Table",
      "datasource": "query(from siem.logtrust.web.activity group by method select count() as n)",
      "definitions": null, "date": {}, "settings": {}, "extra": {"lastMetadata": []},
      "children": null, "version": 3
    }
  },
  "version": 3
}
```

- **Root**: a `container` / `Grid`. Board time range in `date` (Devo date expressions:
  `now() - 1d`, `now()`); `extra.autoRefreshPeriod` (null = off) [doc].
- **Elements** are the root's `children`, keyed by element id (`Table0`, `Line1`, `Select0`: the
  subtype plus a counter). `type` is `widget`, `input` or `container`, and `subtype` is the kind.
  **`name` is the widget's title**, shown on the board ("Requests by method"). It isn't the key
  [verified]; the docs' example just happens to use the key as the title.
- **Layout**: `settings.layout[<id>] = {x, y, w, h, i, moved, static}`, with `i` equal to the id. This is
  react-grid-layout on 12 columns [verified: UI-built boards use x + w ≤ 12, e.g. full width is
  `w: 12`]. Every child needs a layout entry, or it isn't placed.
- **Widget time range**: `date: {}` inherits the board's. A widget can carry its own `{from, to}` [doc].
- **Widget `settings`** depend on the subtype [verified on UI-built boards]:
  - `Table`: `columnDefs` (and optionally `topRowLimits`, sort...)
  - `Line`: `fields`, `series`, `xAxis`, `yAxis`
  - `Pie`: `fields`
  - `SimpleValue`: `field`, `label`, `prefix`, `suffix`, `decimals`, `color`, `conditions`, `size`,
    `weight`, `link`, `patternLink`, `trans`
  The chart settings name the query's columns. A widget created with empty `settings` is accepted
  [verified], but its columns have to be mapped in the UI's widget editor before it shows a chart.
  `extra.lastMetadata` caches the output columns [doc example].
- **Subtypes**: the UI offers Area, Calendar heatmap, Column, Dependency wheel, Donut, Funnel,
  Heatmap, Line, Markers map, Pie, Scatter, Simple value, Stacked area, Stacked column, Table, Time
  lapse, Timeline and Voronoi [doc]. JSON `subtype` strings [verified]: `Table`, `Line`, `Column`,
  `Pie`, `Voronoi`, `DependencyWheel`, `SimpleValue`; inputs `Input`; root container `Grid`. For any
  other chart, build one in the UI, export it (`board <id> --out`) and reuse it
  (`board-new --template`).

## LINQ inside widgets

- The widget's `datasource` holds its LINQ. **Boards built in the UI store plain LINQ**
  (`from t where ... select ...`) [verified]. The docs wrap it in `query(...)` [doc], and the API
  stores that form unchanged too [verified]. `board-new` writes plain LINQ. Limit with `limit 5` or
  `take(query(...), 5)` [doc].
- Devo's docs write widget filters in functional form (`where eq(method, "POST")`, `ge(a, b)`), and
  warn that a query pasted from the search window "might not work". The functional forms also run
  through the Query API [verified], so `board-check --run` tests them as written. In particular, `min()` takes
  exactly two arguments, so chain the calls [doc]. Test every widget query with `board-check --run`
  before publishing.
- **Inputs** [doc]:
  - `$Input0.value` inserts the input's value formatted (a string is quoted).
  - `$*Select0.value` inserts it raw (a table name, a period: `group every $*Select0.value`).
  - `query(Input0.value)` takes the whole query from the input.
  `board-check --run --input Select0=1h` substitutes values so these widgets can be tested.
- Global variables: `$DOMAIN_NAME`, `$USER_NAME`, `$USER_EMAIL`, `$TIMEZONE`... [doc]. Only the board
  can resolve them, so `board-check --run` skips these widgets.
- Each widget query runs when the board opens and again on every refresh. Keep them aggregated
  (`group by` / `group every`), on specific source tables rather than union tables, and over the
  board's range. A raw-row query on a busy table makes a slow board.

## Workflow: build or change a board

1. **Find it**: `devo.py boards --grep <name>` (ids, owner, flags). Read it with `devo.py board <id>`
   (widgets, layout, LINQ).
2. **New board**: write a spec (below), then `devo.py board-new spec.json --out board.json`. `title`
   becomes the widget's `name`. Charts other than Table need their column mapping: pass `--template`
   with an exported board that has the same chart type, or set it in the UI after pushing.
   **Changing a board**: `devo.py board <id> --out board.json`, then edit the JSON.
3. `devo.py board-check board.json --run` checks the structure, then runs every widget query over the
   board's range through the Query API (read-only). Fix the errors, and look into any 0-row widget.
4. `devo.py board-push board.json` (or `--id <id>` to replace) prints what would be sent, plus a
   widget diff for an update. **Show the preview to the user and wait for a clear yes** before
   re-running with `--confirm`. A new board is private to the token's user. Before a PUT or DELETE, the
   helper saves the previous definition under the domain cache (`board-backups/`), and `board-push
   <backup>` restores it.
5. Visibility and tags: `board-set <id> --private false --tags 'soc, web'` (preview, then `--confirm`).
   Sharing with roles is done in the UI.

Spec for `board-new` (12-column grid; widgets fill left to right, 6×10 by default, unless `x`/`y` are given):

```json
{"name": "Web activity", "description": "Requests by method and over time",
 "from": "now() - 1d", "to": "now()",
 "widgets": [
  {"id": "Select0", "type": "Input", "w": 3, "h": 2},
  {"id": "Methods", "type": "Table", "title": "Requests by method",
   "query": "from siem.logtrust.web.activity group by method select count() as n"},
  {"id": "Trend", "type": "Line",
   "query": "from siem.logtrust.web.activity group every $*Select0.value select count() as n"}
 ]}
```

## Sharing and permissions

- A new board is visible to its owner and to `User resources` holders only. To share it, make it
  visible (`privacy: false`), then share it with roles in the UI (board menu → Share with roles, or
  Administration → Roles → Activeboards) [doc]. The API has no role-sharing endpoint.
- `manage` lets a user share with the roles they hold. `User resources` lets them share with any role.
  `manage` doesn't automatically give edit access to other users' boards [doc]; check `editable`
  before a PUT.

## Scheduled reports

`/schedules` [doc]: GET (list), GET/PUT/DELETE `/schedules/{id}`, POST. Body: `startAt` (epoch ms),
`timezone`, `recurrence` {`cronExpression`, `scheduleExpression` {`time` {`hour`, `minute`}, `frequency`
(`Daily`, `Weekly`...)}}, `isEnable`, `customData` {`dateFrom`, `dateTo`, `email` [...]}, `resources`
(board ids as strings). These send email, so the helper doesn't wrap them. Draft the body for the user.

## Gaps in the documentation

- The `subtype` strings of the chart types not listed above, and the full `settings` schema of
  each chart: take them from a UI-built board.
- Whether `Authorization: Bearer` works alone (the helper sends both headers), and limits on
  payload size or request rate.
