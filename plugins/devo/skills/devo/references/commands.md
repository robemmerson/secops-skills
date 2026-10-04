# Devo helper: command details

Options and behaviour of `devo.py` beyond the synopsis in SKILL.md (`devo.py` = `python3 <skill base
directory>/scripts/devo.py`). Read this before long, chunked, sorted or batched queries.

- **Time (`--from`/`--to`)**: `15m`, `24h`, `7d`, `2w` (= that long ago), `now`, `today`,
  `yesterday` (UTC midnight), ISO `2026-09-28` / `2026-09-28T14:00Z` / `...+01:00`, epoch
  seconds or ms, or Devo expressions containing `now()` such as `"(now() - 1d) @ 1d"`
  (passed through). Default: the last hour. Every summary line prints the resolved UTC range.
  Quote it in your answer so the user knows exactly which period was searched. For "today"
  questions use `--from today --to now`, and check how far behind the source is (`lag`, playbooks.md).
- **`--tz <IANA zone>`** (query, activity, teams, timeline, batch, lag) adds a `<field>_local`
  column (ISO with the offset, e.g. `2026-10-02T14:04:32+01:00`) next to each UTC timestamp. Use it
  for reports in the reader's time zone instead of converting by hand (hand conversion is where
  an hour's error creeps in).
- **Output**: `table` (default) is for reading in the terminal; long cells are cut at
  `--width` (0 = full). Use `csv`/`tsv`/`json`/`jsonl` with `--out file` when the user wants
  data to keep or process. Timestamps become ISO-8601 UTC (`--epoch` keeps epoch ms). IPs come
  back as dotted strings.
- The row count, range, duration, "limit reached", zero-row and `# cache:` hints go to
  **stderr** as `# ...` lines. Read them. "limit reached" means you're seeing a truncated sample.
- **Protect your context: aggregate first.** Large dumps (a `tsv --width 0` dump, per-file
  listings) overflow the context and need another script to summarise. Default pattern for
  anything over ~200 rows: aggregate on the server (`group by … select count()`); when you need
  rows, write them with `--out FILE` (stdout then shows only `--stats`: row count, and per column
  filled/distinct counts and the top 5 values) and summarise the file with Python. `--head N`
  prints the first N rows; `--stats` replaces rows with the summary.
- Exit codes: 0 ok, 1 usage/config, 2 API error (message plus hint), 3 timeout (default
  600 s, `--timeout N`).
- **Long queries and the Bash tool.** Query time grows with the range and the table's volume
  (`tables` shows it), but chunked runs (`--chunk 6h`/`1d`, run in parallel) are usually far faster
  than "1 h × N": for anything past a few hours, chunk from the start rather than extrapolating
  from an unchunked hour. Set the Bash tool's `timeout` (max 600000 ms) and the helper's
  `--timeout` for long runs, or use `run_in_background` with `--out`; you are notified when a
  background command finishes, so don't sleep or poll in a loop (`activity` prints `# [k/N]`
  progress lines on stderr and writes `summary.json` when done). Tell the user when something
  will take minutes.
- **`--chunk 6h`** splits a long range into windows run in parallel (4 at a time) and joins the
  rows. This is the fix for day-plus queries on busy tables. It is exact for raw rows and for
  `group every P` when the chunk is a multiple of P. Plain `group by` results come back once
  per chunk: `query` and `batch` **merge them automatically** when the aggregations are count, sum,
  min, max or hllppcount (the stderr note says so; hllppcount becomes the largest per-window value, a
  lower bound, and a `where` on aggregates ran per window; `--no-merge` keeps the per-window rows).
  Anything else (avg, collect…) is left unmerged with a warning. `--limit` applies per chunk. **Auto-split**: when a chunk returns exactly
  `--limit` rows, the helper halves it and re-runs both halves (down to `--min-split`, 5 min). It is
  on by default for raw-row queries with `--limit` ≥ 1000 (off for samples and `group` queries;
  `--auto-split`/`--no-auto-split` override). A back-fill can land more rows than the limit in one
  minute, which no split separates: if it still warns, raise `--limit`. Run day-plus queries on the
  busiest tables in the background with `--out`.
  **Chunking also pays off for short, text-filtered queries**: a substring filter over a day of a
  busy table can be several times faster as 1–3 h chunks run in parallel than as one query.
- **Many queries: `devo.py batch spec.jsonl --out-dir <scratchpad>/x`.** The spec is a JSON list
  (or JSON Lines) of jobs `{name, query (or query_file: a .linq file next to the spec, no JSON
  escaping), from, to, chunk?, parallel?, limit?, format?}`; jobs run in
  parallel (`--parallel`, default 4), each writing `<name>.jsonl` and `<name>.log`, then a table of
  rows / limit reached / error / duration (exit 2 if a job failed). `--vars user=jsmith,from=7d` fills
  `{user}`/`{from}` in every job, so one spec serves several subjects. No shell scripts: hand-written
  sweeps keep failing on zsh word splitting, macOS `xargs -I` and backticks in heredocs. Use
  `run_in_background` for big specs; investigations.md has an example.
- `query` and `batch` pre-check field names against the cached schema, and reserved words used as
  aliases (`as by` fails with a bare "Query parsing error"), and warn (`# pre-check:`; in `batch`
  also in the summary table).
- LINQ has no ORDER BY: `--sort=-count` (descending) or `--sort=field` sorts the returned
  rows client-side. Rows come back unordered and `--limit` truncates *before* the sort, so for a
  top-N: aggregate, cut the long tail on the server (`select count() as n where n > 100`), and use
  a limit big enough to hold every remaining row (or `--limit 0`). Then `--sort` and take the top.
  The helper warns when a sorted result was truncated.
- Multi-line queries: pass them in single quotes (newlines are fine), or use `-` as the query
  and pipe it on stdin (`devo.py query - --from 1h <<'EOF' … EOF`).
