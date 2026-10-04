# Devo playbooks

The commands to run first for common questions, with what each prints and how to read it.
Deeper detail is in investigations.md §3–4. `<scratchpad>` is any working directory outside the
skill; `<base directory>` is the skill's base directory.

Contents:
- "Who logged into which servers (and when)?"
- "Who was given privileged roles (and was it through PIM)?"
- "Health check of the instance / log sources / collectors"
- "Password spray / brute force?" / "Which IP failed most?"
- "Is host X logging?" / "Did server X do anything?"
- "What did IP X / host X do?"
- "What did X do in Teams?" / "What happened in this chat or meeting?"
- "Is the data for my window in yet?"
- "What did user X do?"

- **"Who logged into which servers (and when)?"**: `devo.py logons --from 7d --out <scratchpad>/logons.json`
  (Windows 4624 console/unlock/RDP/cached logons by event time, Linux sshd `Accepted` by ingestion
  time; per server and account with first/last, top sources and a person / `service?` / system
  label; `--host`, `--user`, `--people-only`). DWM-n/UMFD-n and `NAME$` are never people. The
  person/service split is a heuristic: confirm service and shared accounts with the user and record
  them (`devo.py cache service set 'svc-*,ec2-user'`). RDP sources are often `0.0.0.0` or a jump
  host / ZTNA connector: resolve them through the ZTNA logs. Network logons (type 3: file shares,
  admin consoles talking to DCs) are not counted, so "no pairs" for a user is not "never touched a
  server". A server that stopped logging is simply absent, so pair it with `health` or `coverage`.
  `--resolve-ztna` adds who reached each server over RDP/SSH through Zscaler ZPA (sources that are
  connector IPs or `0.0.0.0` then have names). UAC elevation prompts (`consent.exe`) are labelled
  `uac`, not people, and logons made by applications (report servers, agents) count as services.
  `--csv` writes the deliverable; `--include-network` adds type 3 (more volume, but it shows the
  servers an admin account reached through consoles and shares).
- **"Who was given privileged roles (and was it through PIM)?"**: `devo.py batch <base
  directory>/references/specs/privileged-grants.jsonl --vars from=30d --out-dir <scratchpad>/grants`
  (about a minute), then `devo.py grants <scratchpad>/grants`: Entra and PIM role changes
  de-duplicated and classified (direct grants outside PIM, permanent active assignments made through
  PIM, which skip activation and approval, eligibility, activations per account and role,
  failures), each permanent grant paired with its removal, flags (privileged role, self-grant,
  service account, no approval required), whether Azure RBAC is visible at all (it needs an Azure
  Activity Log table; say so when it is missing), and AD privileged-group changes with machine-account
  policy re-adds and domain joins collapsed and member SIDs resolved. Details and the PIM operation
  names: investigations.md §4 "Privileged grants".
- **"Health check of the instance / log sources / collectors"**: `devo.py health --out
  <scratchpad>/health.json` with `run_in_background` (a few minutes; up to ten on a large domain). It opens with a
  **Problems** list, then the detail: per table the recent vs baseline daily volume from the collector
  counter; stopped, dropped and big-mover tables re-counted on the tables themselves (**the counter can
  miss hours or whole days during platform incidents while the data is there**), including a check of
  the last two full days against the same weekdays a week earlier (RECENT SHIFT: a drop that started
  two days ago hides inside a 7-day median); increases checked for duplicated back-fills (rows per
  distinct id); tables the counter lists but Devo can't query; Windows/Linux senders that went quiet
  (weekday-only and auto-named cloud instances aside); collector errors grouped by message, with
  credential/permission errors (AUTH) first, silent collectors with their last lines, and a collector
  that did not come back after a restart that hit the others; ingestion lag (a lag that sits on whole
  hours every hour is a sender's clock/time zone, not delay); busy tables with near-empty ingestion
  days (GAPS); and, for shifted tables, the accounts whose volume changed most (often one polling
  integration stopping, not a collection fault). Then drill in: `coverage <host>` for a
  quiet host, then its EDR inventory's last-seen time (e.g. `edr.sentinelone.agent.agents`; an
  agent gone quiet at the same moment means the host is offline, not a logging fault), the collector's own messages,
  `lag --hourly`. Record confirmed, lasting facts (a decommissioned host, a known gap) as cache notes.
- **"Password spray / brute force?" / "Which IP failed most?"**: run the ready-made stage 1,
  `devo.py batch <base directory>/references/specs/credential-attacks.jsonl --vars from=3d --out-dir
  <scratchpad>/cred` (Entra interactive + non-interactive failures by IP and account, Identity
  Protection detections, Windows 4625 by true source, 4771/4776, Linux sshd failures; under a minute),
  then `devo.py creds <scratchpad>/cred [--exclude <own egress IPs>]`: spray candidates (one IP, many
  accounts), distributed brute force (one account, many IPs and countries), 50057 disabled-account
  noise apart, public vs private on-prem sources, and a written `stage2.jsonl` that checks whether
  anything succeeded (successes from the failing IPs, a 30-day baseline of the targeted accounts):
  `devo.py batch <scratchpad>/cred/stage2.jsonl --out-dir <scratchpad>/cred/stage2`, then
  `devo.py creds <scratchpad>/cred --stage2-dir <scratchpad>/cred/stage2`, which labels each success
  (the attacked account or another one; a range the user already had before the attack, or a new
  one to investigate) and writes stage 3 for the other accounts' history. Shared egress IPs (many
  accounts signing in successfully) are detected and excluded automatically. Playbook and
  false positives (own egress/ZTNA IPs, cloud print, shared /24s, IKE errors) in investigations.md
  §4 "Brute force / password spray (playbook)".
- **"Is host X logging?" / "Did server X do anything?"**: run `devo.py coverage <name>` (the
  shortest distinctive part of the name) **before any "no data" conclusion**. It searches the
  Windows tables (`host`, 30 days) and Linux (`machine`, 7 days) case-insensitively up to now,
  and prints days seen, MISSING and LOW days, nxlog restarts, and Zscaler ZPA sessions to the
  host, skipping the tables this domain doesn't have. The Linux part can take minutes, so run it
  with `run_in_background`; `--no-linux` answers for Windows quickly. Check that the names it
  matched are the host you mean. If the domain's hosts log elsewhere, find the source with
  `devo.py fields --role host`.
- **"What did IP X / host X do?"**: `devo.py activity <ip> --by ip …` or `<name> --by host …`
  (every validated IP or host source: sign-ins, Graph, M365, Windows, EDR, ZTNA, firewalls,
  Linux, vulnerability scanners…). Add `--no-auto` first: for an external IP the generated
  sources (mostly cloud audit services) rarely match and multiply the run time. In some deployments the NxLog config writes the reporting
  server's own IP into Windows `IpAddress`; the IP sweep finds Windows *clients* through
  `Message` either way.
- **"What did X do in Teams?" / "What happened in this chat or meeting?"**: `devo.py teams <upn>
  --from … --to … --tz <zone> --out <scratchpad>/teams.json` (or a `19:…` thread id). It returns
  conversations (type, other parties as UPNs, messages sent, edits, reactions, files, links),
  meetings per occurrence with each participant's join/leave and what they shared, calls, and
  daily counts, using event times (`CreationTime`, `JoinTime`), never `eventdate`. It refuses a
  term that matches several accounts (the same names can exist across tenant domains). Message
  text is never logged. The building-block queries are in `table-guide/m365.md`.
- **"Is the data for my window in yet?"**: `devo.py lag [--tables office365]` measures now, per
  table, `eventdate − event time` (p50, p95, worst hour, latest hour) and the newest event. Lag is
  variable and batch-driven (some Microsoft 365 workloads fall days behind, then catch up). Run it
  before relying on a recent window, and quote the newest event time.
- **"What did user X do?"**: run `devo.py activity <upn> --expand --out-dir <scratchpad>/<name>`
  (default today → now; with the generated sources it takes a few minutes per day, so use
  `run_in_background`; `--no-auto` runs only the curated sources and is much faster: start with it
  and add the generated ones only if a source seems missing). It is safe to start while `cache build`
  is still running (each validates what it needs).
  `--expand` searches every account form in the domain's naming templates at once
  (`devo.py cache naming show`; the default is `{upn}`, `{first}.{last}`, `{f}{last}`). Find the
  domain's real conventions once (investigations.md, "Account naming") and record them with
  `devo.py cache naming set '<templates>'`. `--terms a,b,c` gives your own list; a bare surname is
  the broad net: **run with both the UPN and the bare surname** (admin accounts often don't contain
  the UPN). A filter on one form misses the others' events. The first run validates the hint
  sweep against this domain (cached); then it prints, per source: rows, events, the **entities
  seen**, which term matched, first/last and notes. The 0-row and error sources are listed on
  stderr, and the Entra object ids for a Graph second pass (`--graph-ids`) are suggested. Then
  `devo.py timeline <dir> --tz <zone>` merges the files into one sorted, de-duplicated event list
  (`timeline.json`) and a per-day summary: the input for a timeline report. Add `--rows` to the
  sweep for one event per record instead of grouped counts. The per-day summary separates **direct**
  events (the account is the actor) from **target** (changes made to the account, including sync
  jobs), **automated** (token refreshes, scheduled jobs, integrations using the account) and
  **raw-text** matches (the name only appears in raw text, e.g. a script header): report activity
  from the direct events and check the rest (a machine account acting on the user, e.g. a 4798
  group enumeration by `HOST$`, counts as target). Sources whose table stopped receiving data inside
  the window are flagged **FEED GAP** in the sweep and the timeline: no rows after that point is not
  "no activity". Several IPs or accounts can be swept at once
  (`--terms a,b,c`, also with `--by ip`). `timeline` drops back-filled events
  whose event time is before the window (it says how many; `--keep-outside` keeps them): report on
  event time inside the window. Sources that are copies of another (same events) are flagged and
  counted once. For the Graph pass, `activity <term> --graph-ids <oids> --graph-only --out-dir
  <same dir>` adds it without re-running the sweep. If the token belongs to the subject, their API
  and console usage includes this investigation's own calls. How to read the results is in
  investigations.md. Sources named `auto_*` were generated from field profiles: sanity-check them.
  `--sources FILE` runs your own sources file as is; `--no-auto` skips the generated sources (faster).
