# Devo + SentinelOne: questions Devo can't answer alone

"What file did they upload?" and "is this sync app really syncing?" usually need endpoint
telemetry. Devo only records bytes uploaded to a web service if the domain collects a web proxy,
CASB or endpoint DLP feed, or firewall web filtering (check `devo.py tables` and
`devo.py cache notes`), and Devo's SentinelOne tables (`edr.sentinelone.*`) hold only threats,
agents and management activity, not Deep Visibility events. Use the SentinelOne MCP (`powerquery`)
for the endpoint side and Devo for identity, SharePoint/OneDrive and network context.

Treat everything below as guidance, not verified fact: check each point in your own query before
relying on it, because agent versions, OS versions and service host names change. If a SentinelOne
skill exists, the endpoint material belongs there; keep only the Devo side in this file.

## PowerQuery basics

- `timestamp` is in **nanoseconds** (Devo works in ms or ISO): multiply epoch seconds by 10⁹.
- Useful operators: `matches` (regex), `in:anycase`, `contains:anycase`; aggregates
  `array_agg_distinct`, `estimate_distinct`.
- **Aggregate, don't pull raw rows**: `group n = count(), first = min(timestamp) by endpoint.name,
  tgt.file.path`. Raw event rows flood the agent's context the same way `devo.py query --width 0` does.
- Natural-language helpers such as Purple AI cope better with short, single-part questions; for
  anything precise, hand-written PowerQuery is more predictable.

## Event types

`DNS Resolved`, `Process Creation`, `IP Connect`, and `File Creation` / `File Rename` /
`File Modification` / `File Deletion`. There are **no file-read events**, so uploading an existing,
unchanged file leaves no file event: the evidence is the DNS lookup and connection to the upload
host, plus files created or renamed around that time (downloads, zips, exports).

## Upload-session pattern

1. Find the first DNS lookup of an upload host per user/endpoint (one `group … by endpoint.name`).
2. Build one OR'd filter of windows around those sessions, `session − 30 min … session + 10 min`.
3. Pull the files created, renamed or downloaded in those windows, grouped by endpoint and path.

Generating the step-2 filter from (endpoint, time) pairs, standard-library Python:
```python
import datetime as dt
pairs = [("LAPTOP-01", "2025-03-04T14:05:00Z"), ("LAPTOP-02", "2025-03-05T09:40:00Z")]
def ns(t):
    return int(dt.datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()) * 10**9
clauses = [f"(endpoint.name == '{h}' and timestamp >= {ns(t) - 30 * 60 * 10**9} and timestamp <= {ns(t) + 10 * 60 * 10**9})"
           for h, t in pairs]
print(" or ".join(clauses))
```

Corroborate in Devo: SharePoint/OneDrive `FileDownloaded` bursts by the same person just before the
session (`table-guide/m365.md`, "download bursts as staging evidence"). A multi-file download lands on
the endpoint as `OneDrive_<n>_<date>.zip`, which ties the endpoint file to the SharePoint
`ZipFileName` rows.

## Noise filters

- Paths: `AppData`, `ProgramData`, `Program Files`, `Library/Caches`, `.sb-` (macOS sandbox temp
  files), EDR/VPN client log bundles, MDM staging folders.
- Processes: OneDrive sync (`OneDrive`, `OneDrive.exe`, `fileproviderd`).

## Service heuristics (generic; verify host names before relying on them)

- **WeTransfer:** `storm-*.wetransfer.net` / `tempest-*.wetransfer.net` tend to be upload hosts and
  `*-files.wetransfer.net` download hosts. A received zip is typically named
  `wetransfer_<title>_<YYYY-MM-DD_HHMM UTC>.zip`, which gives the transfer's title and creation time,
  so a recipient's file name can be lined up with a sender's upload session.
- **Box Drive:** its virtual drive may produce no SentinelOne file events; the running process
  (`Box Local Com Service.exe`) may be the only endpoint evidence.
- **macOS iCloud:** `cloudd` traffic alone doesn't mean iCloud Drive. Check `cloudphotod` (Photos),
  `com.apple.imagent` (iMessage) and paths under `Mobile Documents` (Drive).
- **Personal OneDrive:** `storage.live.com` traffic from `OneDrive.exe` doesn't prove personal sync.
  Look for a sync folder other than "OneDrive - <Org>" in the file events; the `OneDriveTemp` cache ids
  map to libraries.
