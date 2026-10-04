#!/usr/bin/env python3
"""Devo Query API and Alerts API helper. Python 3.8+, standard library only.
Read-only except `comment`, which only posts with --confirm.

Commands:
  check                          verify the token and region
  query  "<LINQ>" [options]      run a LINQ query
  schema <table>                 list a table's fields and types
  tables [--grep RE] [--live]    tables that have data in this domain (cached locally)
  alerts [options]               list triggered alerts
  alert  <id> [--json]           one triggered alert, decoded, with its detection query
  alert-defs [--name TEXT]       alert definitions (with --query: their LINQ)
  coverage <name>                is a host sending logs? Windows+Linux daily counts, gaps, restarts
  activity <term> --out-dir DIR  everything a user did: parallel multi-source sweep
  timeline <activity dir>        merge an activity sweep into one sorted timeline (offline)
  teams <upn|19:thread> --out F  Teams conversations, meetings, calls and daily counts as JSON
  lag [--tables RE]              measure ingestion lag per table now
  batch <spec.json> --out-dir D  run many queries in parallel from a JSON/JSONL spec
  comment <id> --title T --msg M  preview a comment on a triggered alert; --confirm posts it
  logons [--from 7d] [--os ...]   who logged into which Windows/Linux servers, per server and account
  health [--baseline 21d]        the whole domain: sources stopped/dropped/new, quiet senders, collector errors
  creds <batch dir>              summarise a credential-attack batch; writes the stage-2 spec (offline)
  grants <batch dir>             summarise a privileged-grants batch: PIM/direct/permanent, AD groups (offline)
  cache status|build|verify|refresh|clear|notes|note|naming|service
                                 the domain data cached on this machine (see below)

Credentials: DEVO_TOKEN (and optional DEVO_REGION, default "eu") from the environment,
otherwise from the env file named by DEVO_ENV_FILE, otherwise ~/.config/devo/env
(KEY=VALUE lines). The token is never printed.

Cache: the domain's table list, schemas, field profiles, verified event-time expressions and validated
sweep sources are fetched on first use and cached under $DEVO_CACHE_DIR, else
$XDG_CACHE_HOME/devo-skill, else ~/.cache/devo-skill (one directory per domain; DEVO_CACHE_KEY
names it, otherwise region + a hash of the token). Entries expire (tables and sources 7 days,
schemas, profiles and event time 30; DEVO_CACHE_MAX_AGE_DAYS caps them), are marked stale when a
query contradicts them, and `cache verify|refresh|clear` refetch or drop them.

Times (--from/--to): 30m, 24h, 7d, 2w (= that long ago); now; today; yesterday;
ISO dates/times (UTC unless an offset is given: 2026-09-28, 2026-09-28T14:00,
2026-09-28 14:00:00+01:00); epoch seconds or milliseconds; or Devo relative-date
expressions containing now() (e.g. "now() - 3h", "(now() - 1d) @ 1d"), passed through.

Exit codes: 0 ok, 1 usage/config error, 2 API error, 3 timeout.
"""
import argparse, csv, datetime as dt, http.client, io, json, os, re, socket, stat, sys, threading, time
import urllib.error, urllib.parse, urllib.request

VERSION = "1.0"
USER_AGENT = f"devo-skill/{VERSION}"  # Devo's Cloudflare blocks Python's default UA (403 "error code: 1010")
REGIONS = {  # region -> (Query API host, Alerts API host)
    "eu": ("apiv2-eu.devo.com", "api-eu.devo.com"),
    "us": ("apiv2-us.devo.com", "api-us.devo.com"),
    "ca": ("apiv2-ca.devo.com", "api-ca.devo.com"),
    "apac": ("api-apac.devo.com", "api-apac.devo.com"),
    "us3": ("api-us3.devo.com", "api-us3.devo.com"),  # gitleaks:allow (public hostname)
}
ALERT_STATUS = {0: "Unread", 1: "Updated", 2: "False positive", 100: "Watched", 300: "Closed",
                800: "Suppressed"}  # other codes are domain-specific workflow states (undocumented)
CLOSED_STATUSES = {2, 300}
SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HINTS = os.path.join(SKILL_DIR, "references", "hints")  # generic seeds; the cache holds the validated copies


class DevoError(Exception):
    def __init__(self, msg, hint="", code=2):
        super().__init__(msg)
        self.hint, self.code = hint, code


# ---------------------------------------------------------------- config

def read_env_file(path):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("export "):
                    line = line[7:]
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


_WARNED = set()


def warn_if_exposed(path):
    """The token file should be private to the user: say so once if not."""
    for p, want in ((path, 0o600),):
        try:
            mode = stat.S_IMODE(os.stat(p).st_mode)
        except OSError:
            continue
        if mode & 0o077 and p not in _WARNED:
            _WARNED.add(p)
            print(f"# warning: {p} is readable by other users (mode {mode:o}); run: chmod {want:o} {p}",
                  file=sys.stderr)


def load_config(environ=None):
    env = os.environ if environ is None else environ
    path = env.get("DEVO_ENV_FILE") or os.path.expanduser("~/.config/devo/env")
    filevals = read_env_file(path)
    if filevals.get("DEVO_TOKEN") and not env.get("DEVO_TOKEN"):
        warn_if_exposed(path)
    token = env.get("DEVO_TOKEN") or filevals.get("DEVO_TOKEN")
    region = (env.get("DEVO_REGION") or filevals.get("DEVO_REGION") or "eu").lower()
    if not token:
        raise DevoError("no Devo token found",
                        f"set DEVO_TOKEN, or put DEVO_TOKEN=... in {path} (or point DEVO_ENV_FILE at a file)",
                        code=1)
    if region not in REGIONS:
        raise DevoError(f"unknown region {region!r}", f"use one of: {', '.join(REGIONS)}", code=1)
    cfg = {"token": token, "region": region}
    key = env.get("DEVO_CACHE_KEY") or filevals.get("DEVO_CACHE_KEY")
    if key:
        cfg["cache_key"] = key
    return cfg


# ---------------------------------------------------------------- time parsing

DUR = re.compile(r"^\s*-?\s*(\d+)\s*(s|m|h|d|w)\s*(?:ago)?\s*$", re.I)
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$", re.I)


def resolve_time(value, now=None):
    """Return (api_value, epoch_seconds_or_None). api_value is an int epoch in seconds,
    or a Devo relative-date string passed through untouched."""
    now = int(time.time()) if now is None else now
    s = str(value).strip()
    low = s.lower()
    if "now()" in low:
        return s, None
    if low == "now":
        return now, now
    if low in ("today", "yesterday"):
        midnight = now - now % 86400
        t = midnight if low == "today" else midnight - 86400
        return t, t
    m = DUR.match(s)
    if m:
        t = now - int(m.group(1)) * UNIT_SECONDS[m.group(2).lower()]
        return t, t
    if re.fullmatch(r"\d{9,16}", s):
        n = int(s)
        t = n // 1000 if n > 10 ** 11 else n  # treat 12+ digit values as milliseconds
        return t, t
    if ISO.match(s):
        iso = s.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} \d", s) else s
        iso = re.sub(r"[zZ]$", "+00:00", iso)
        iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", iso)
        d = dt.datetime.fromisoformat(iso)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        t = int(d.timestamp())
        return t, t
    raise DevoError(f"can't parse time {value!r}",
                    "use e.g. 24h, 7d, now, today, yesterday, 2026-09-28T14:00Z, epoch seconds, "
                    "or a Devo expression like \"now() - 3h\"", code=1)


def fmt_epoch(seconds):
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def fmt_ms(ms):
    if ms is None or ms == "":
        return ""
    try:
        return dt.datetime.fromtimestamp(int(ms) / 1000, dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (ValueError, OverflowError, OSError):
        return str(ms)


# ---------------------------------------------------------------- local time

def get_tz(name):
    """An IANA zone (e.g. Europe/London) for the *_local columns, or None."""
    if not name:
        return None
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        raise DevoError("--tz needs Python 3.9+ (zoneinfo)", code=1)
    try:
        return ZoneInfo(name)
    except Exception:
        raise DevoError(f"--tz {name!r}: unknown time zone", "use an IANA name such as Europe/London or UTC", code=1)


def parse_utc(v):
    """An aware UTC datetime from epoch ms/seconds, ISO with Z/offset, or ISO without a zone (taken as
    UTC, as in Microsoft 365 CreationTime); None if it isn't a time."""
    if v is None or v == "" or isinstance(v, bool):
        return None
    try:
        if isinstance(v, (int, float)):
            return dt.datetime.fromtimestamp(v / 1000 if v > 10 ** 11 else v, dt.timezone.utc)
        s = str(v).strip()
        if not re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", s):
            return None
        s = s.replace(" ", "T", 1)
        s = re.sub(r"(\.\d{1,6})\d*", r"\1", s)  # fromisoformat takes at most microseconds
        s = re.sub(r"[zZ]$", "+00:00", s)
        s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)
        d = dt.datetime.fromisoformat(s)
        return d.replace(tzinfo=dt.timezone.utc) if d.tzinfo is None else d.astimezone(dt.timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def iso_utc(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def to_local(v, tz):
    """'2026-10-02T14:04:32+01:00' (seconds; the offset makes daylight saving explicit), or None."""
    d = parse_utc(v)
    return d.astimezone(tz).isoformat(timespec="seconds") if d and tz else None


def add_local_columns(columns, rows, tz):
    """Insert <name>_local after every timestamp column."""
    idx = [i for i, (_, t) in enumerate(columns) if t == "timestamp"]
    if not idx:
        return columns, rows
    cols = []
    for i, c in enumerate(columns):
        cols.append(c)
        if i in idx:
            cols.append((c[0] + "_local", "str"))
    out = []
    for r in rows:
        nr = []
        for i, v in enumerate(r):
            nr.append(v)
            if i in idx:
                nr.append(to_local(v, tz))
        out.append(nr)
    return cols, out


def add_local_fields(rec, tz, fields=("eventdate", "first", "last", "first_event", "last_event", "event_time")):
    if tz:
        for f in fields:
            if rec.get(f):
                rec[f + "_local"] = to_local(rec[f], tz)
    return rec


# ---------------------------------------------------------------- HTTP

def http_open(method, url, token, body=None, headers=None, timeout=60):
    """Open a request; return the response object or raise DevoError with a readable message."""
    h = {"User-Agent": USER_AGENT, "Accept": "application/json", "Authorization": f"Bearer {token}"}
    if body is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        raise api_error(e.code, e.read().decode("utf-8", "replace"), token)
    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
        raise DevoError(f"network error: {getattr(e, 'reason', e)}", "check connectivity to *.devo.com")


def api_error(status, text, token=""):
    text = text.replace(token, "<token>") if token else text
    msg, detail, hint = "", "", ""
    try:
        j = json.loads(text)
    except ValueError:
        j = None
    if isinstance(j, dict):
        obj = j.get("object")
        if isinstance(obj, list) and len(obj) >= 2 and obj[0] == "Error Launching Query":
            msg = str(obj[1])
            if len(obj) >= 4:
                detail = f"{obj[3]} {obj[2]}"
        elif isinstance(obj, list) and obj:
            msg = f"{j.get('error') or j.get('msg') or 'error'}: " + "; ".join(map(str, obj))
        if not msg:
            e = j.get("error")
            msg = e.get("message") if isinstance(e, dict) else (e or j.get("msg") or "")
        ctx = j.get("context")
        if not msg and j.get("title"):  # Cloudflare JSON error pages
            msg = j["title"] + (f" ({j['detail'][:160]})" if j.get("detail") else "")
        if isinstance(ctx, dict) and ctx.get("fields"):
            msg += " " + "; ".join(f"{f.get('path')}: {', '.join(f.get('errors', []))}" for f in ctx["fields"])
    if not msg:
        if "error code: 1010" in text:
            msg = "blocked by Cloudflare (browser signature)"
        elif text.lstrip().startswith("<"):
            m = re.search(r"<title>(.*?)</title>", text, re.S)
            msg = m.group(1).strip() if m else "HTML error page"
        else:
            msg = text.strip()[:300] or "no response body"
    low = msg.lower()
    if "unknown table" in low:
        hint = ("the table doesn't exist in this domain: check `devo.py tables --grep ...` (the cached list; "
                "`--live` refreshes it) "
                "and references/table-catalogue.md; table names are case-sensitive")
    elif "unknown identifier" in low:
        hint = "no such field in that table: list fields with `devo.py schema <table>`"
    elif "no function named `lu`" in low:
        hint = ("the lookup doesn't exist in this domain, or it has no field with that name: check "
                "lookup and field names (references/library/INDEX.md lists the library's lookups), "
                "or drop the lu(...) enrichment")
    elif "no function named `in`" in low and "set(ip4)" in low:
        hint = ("an unquoted IP in {...} is an ip4 literal, but this field is a string: quote the IPs "
                "(field in {\"10.1.2.3\", ...}) or compare with an ip4 field (`devo.py fields <table>` shows types)")
    elif "no function named" in low:
        hint = ("unknown function, or wrong argument types for it: check "
                "references/linq-functions.md")
    elif "parsing error" in low:
        hint = ("LINQ syntax error (Devo gives no position). Common causes: missing `as name` after a "
                "select expression, a keyword used as an alias (`as by`, `as group`), unbalanced quotes/parentheses, "
                "`where` after `group`, a hyphenated "
                "table name that needs backticks, SQL-only syntax; see references/linq-syntax.md")
    elif "date from" in low or "date to" in low:
        hint = "bad time range: see `devo.py query --help` for accepted --from/--to formats"
    elif "token invalid" in low or status == 401:
        hint = "token invalid/expired, or wrong region: run `devo.py check`"
    elif "access not allowed for table" in low:
        hint = ("usually means the table doesn't exist (Devo answers 403 for unknown tables); "
                "it can also mean the token isn't allowed to read it")
    elif "browser signature" in low:
        hint = "send a custom User-Agent header (devo.py does)"
    elif status in (502, 503, 504, 520, 522, 524):
        hint = "transient Devo/Cloudflare gateway error: wait a few seconds and retry"
    head = f"HTTP {status}" + (f", {detail}" if detail else "")
    return DevoError(f"{head}: {msg}", hint)


def get_json(url, token, headers=None, timeout=60):
    with http_open("GET", url, token, headers=headers, timeout=timeout) as r:
        text = r.read().decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        raise DevoError(f"unexpected non-JSON response: {text[:200]}")


# ---------------------------------------------------------------- query

SAFE_TABLE = re.compile(r"^[A-Za-z0-9_.]+$")


def quote_table(name):
    """Backtick table names with characters LINQ can't parse bare (e.g. hyphens)."""
    return name if SAFE_TABLE.match(name) or name.startswith("`") else f"`{name}`"


class CompactStream:
    """Incremental parser for mode json/simple/compact: a metadata line {"m":..,"metadata":[..]},
    then one {"d":[...]} line per row. Devo pads long-running responses with whitespace."""

    def __init__(self):
        self.buf = ""
        self.columns = None  # [(name, type)]

    def feed(self, text):
        self.buf += text
        rows = []
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            rows.extend(self._line(line))
        return rows

    def close(self):
        line, self.buf = self.buf, ""
        return list(self._line(line))

    def _line(self, line):
        line = line.strip()
        if not line:
            return
        try:
            obj = json.loads(line)
        except ValueError:
            raise DevoError(f"unparseable response line: {line[:200]}")
        if "d" in obj:
            yield obj["d"]
        elif "metadata" in obj or "m" in obj:
            meta = obj.get("metadata")
            if meta:
                self.columns = [(c["name"], c.get("type", "")) for c in meta]
            else:
                self.columns = [(k, v.get("type", "")) for k, v in
                                sorted(obj["m"].items(), key=lambda kv: kv[1].get("index", 0))]
        elif "e" in obj or "error" in obj or obj.get("status", 0) not in (0, None):
            raise api_error(200, line)
        # progress ("p") and other control objects are ignored


def run_query(cfg, linq, frm, to, limit, timeout, ip_as_string=True):
    """Yield (columns, row) pairs; raises DevoError. Always sends `to` (no `to` = endless live query)."""
    body = {"query": linq, "from": frm, "to": to, "mode": {"type": "json/simple/compact"},
            "ipAsString": ip_as_string}
    if limit:
        body["limit"] = limit
    url = f"https://{REGIONS[cfg['region']][0]}/search/query"
    deadline = time.time() + timeout
    parser = CompactStream()
    resp = http_open("POST", url, cfg["token"], body=body, timeout=min(timeout, 120))
    with resp:
        while True:
            if time.time() > deadline:
                raise DevoError(f"query still running after {timeout}s, aborted",
                                "narrow --from/--to, query a specific source table instead of a union "
                                "table, filter earlier, or raise --timeout", code=3)
            try:
                chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
            except socket.timeout:
                continue
            except (http.client.IncompleteRead, ConnectionError, OSError) as e:
                raise DevoError(f"connection dropped mid-response ({type(e).__name__})",
                                "transient: re-run, or use --chunk to split the range")
            if not chunk:
                break
            for row in parser.feed(chunk.decode("utf-8", "replace")):
                yield parser.columns, row
        for row in parser.close():
            yield parser.columns, row
    if parser.columns is None:
        raise DevoError("empty response from Devo (no metadata line)")
    yield parser.columns, None  # sentinel so callers always learn the columns


def convert_value(v, typ, epoch=False):
    if v is None:
        return None
    if typ == "timestamp" and not epoch:
        return fmt_ms(v)
    return v


def cell(v, width):
    if v is None:
        s = ""
    elif isinstance(v, (dict, list)):
        s = json.dumps(v, ensure_ascii=False)
    else:
        s = str(v)
    s = s.replace("\r", "").replace("\n", "⏎").replace("\t", " ")
    if width and len(s) > width:
        s = s[: width - 1] + "…"
    return s


def write_rows(out, fmt, columns, rows, width):
    names = [c[0] for c in columns]
    if fmt == "jsonl":
        for r in rows:
            out.write(json.dumps(dict(zip(names, r)), ensure_ascii=False) + "\n")
    elif fmt == "json":
        json.dump([dict(zip(names, r)) for r in rows], out, ensure_ascii=False, indent=1)
        out.write("\n")
    elif fmt in ("csv", "tsv"):
        w = csv.writer(out, delimiter="," if fmt == "csv" else "\t", lineterminator="\n")
        w.writerow(names)
        for r in rows:
            w.writerow(["" if v is None else (json.dumps(v) if isinstance(v, (dict, list)) else v) for v in r])
    else:  # table
        cells = [[cell(v, width) for v in r] for r in rows]
        widths = [max([len(n)] + [len(c[i]) for c in cells]) for i, n in enumerate(names)]
        out.write("  ".join(n.ljust(w) for n, w in zip(names, widths)).rstrip() + "\n")
        for c in cells:
            out.write("  ".join(v.ljust(w) for v, w in zip(c, widths)).rstrip() + "\n")


NAME_FIELD = r"[A-Za-z_]*(?:host|machine|user|name|User|Name|Host)[A-Za-z_]*"
CASE_SENSITIVE_MATCH = re.compile(rf'\b({NAME_FIELD})\s*(?:->|=(?!=))\s*"|\bhas\(\s*({NAME_FIELD})\s*,')


def case_sensitive_name_matches(linq):
    """Name-like fields compared case-sensitively with a string literal (->, =, has)."""
    found = []
    for m in CASE_SENSITIVE_MATCH.finditer(linq):
        f = m.group(1) or m.group(2)
        if f not in found:
            found.append(f)
    return found


def sort_rows(rows, names, spec):
    """Client-side sort (LINQ has no ORDER BY). spec: 'field' or '-field' (descending),
    comma-separated; nulls always last."""
    for key in reversed([k.strip() for k in spec.split(",") if k.strip()]):
        desc = key.startswith("-")
        name = key.lstrip("-+")
        if name not in names:
            raise DevoError(f"--sort: no column {name!r}", f"columns: {', '.join(names)}", code=1)
        i = names.index(name)
        present = [r for r in rows if r[i] is not None]
        missing = [r for r in rows if r[i] is None]
        numeric = all(isinstance(r[i], (int, float)) for r in present)
        present.sort(key=(lambda r: r[i]) if numeric else (lambda r: str(r[i])), reverse=desc)
        rows = present + missing
    return rows


def collect(cfg, linq, frm, to, limit, timeout, ip_as_string=True):
    columns, rows = None, []
    try:
        for columns, row in run_query(cfg, linq, frm, to, limit, timeout, ip_as_string=ip_as_string):
            if row is not None:
                rows.append(row)
    except DevoError as e:
        cache_mismatch(linq, e, cfg)
        raise
    return columns, rows


def chunk_step(chunk):
    m = DUR.match(chunk or "")
    if not m:
        raise DevoError(f"--chunk {chunk!r}: use a duration like 1h, 6h, 1d", code=1)
    step = int(m.group(1)) * UNIT_SECONDS[m.group(2).lower()]
    if step <= 0:
        raise DevoError("--chunk must be positive", code=1)
    return step


MIN_SPLIT = 300  # seconds: --auto-split stops halving a window below this
MAX_SPLITS = 64  # halvings per fetch(), so a filter that matches everything can't fan out without end
AUTO_SPLIT_MIN_LIMIT = 1000  # below this a --limit is a sample, not a collection: don't split by default


def default_auto_split(linq, limit):
    """On for raw-row queries that collect (limit >= 1000); off for samples and `group` queries."""
    return bool(limit) and limit >= AUTO_SPLIT_MIN_LIMIT and not is_grouped(linq)


def is_grouped(linq):
    return bool(re.search(r"\bgroup\b", linq))


RETRYABLE = re.compile(r"connection dropped|network error|INTERNAL_ERROR|Log file listed but not found|HTTP 50[234]|"
                       r"timed? ?out while|temporarily unavailable", re.I)


def fetch(cfg, linq, frm_s, to_s, limit, timeout, chunk=None, parallel=4, ip_as_string=True, auto_split=False,
          min_split=MIN_SPLIT, partial=False):
    """Run a query over [frm_s, to_s) (epoch seconds), optionally split into --chunk windows run in
    parallel. Returns (columns, rows, info) with info = {windows, retried, full, splits}. Windows start
    on multiples of the chunk size (UTC), so `group every` buckets never straddle two chunks.
    auto_split: a window that returns `limit` rows is halved and both halves re-run, down to
    min_split seconds; `full` then lists only the windows still at the limit."""
    from concurrent.futures import ThreadPoolExecutor
    if frm_s is None or to_s is None:
        raise DevoError("--chunk needs concrete --from/--to (e.g. 7d, yesterday, ISO), not now() expressions",
                        code=1)
    if not chunk:
        windows = [(frm_s, to_s)]
    else:
        step = chunk_step(chunk)
        edges = [frm_s] + list(range((frm_s // step + 1) * step, to_s, step)) + [to_s]
        windows = [(a_, b_) for a_, b_ in zip(edges, edges[1:]) if b_ > a_]
        if len(windows) > 200:
            raise DevoError(f"--chunk {chunk} gives {len(windows)} windows; use a bigger chunk", code=1)
    retried, splits = [], []

    def get(w):
        for attempt in range(3):
            try:
                return collect(cfg, linq, w[0], w[1], limit, timeout, ip_as_string)
            except DevoError as e:
                transient = bool(RETRYABLE.search(str(e)))
                if not transient or attempt == 2:
                    where = f"window {fmt_epoch(w[0])} → {fmt_epoch(w[1])}: " if chunk or splits else ""
                    raise DevoError(f"{where}{e}", e.hint, e.code)
                retried.append(w)
                time.sleep(RETRY_DELAY * (attempt + 1))

    failed = []

    def one(w):
        try:
            columns, rows = get(w)
        except DevoError as e:
            if not partial or len(windows) < 2:
                raise
            failed.append((w, str(e)[:160]))  # keep the other windows' rows; the caller reports the gap
            return None, [], []
        at_limit = bool(limit) and len(rows) >= limit
        if not (at_limit and auto_split and w[1] - w[0] >= 2 * min_split and len(splits) < MAX_SPLITS):
            return columns, rows, [w] if at_limit else []
        splits.append(w)
        mid = w[0] + (w[1] - w[0]) // 2
        out, full = [], []
        for half in ((w[0], mid), (mid, w[1])):
            c, r, f = one(half)
            columns = columns or c
            out.extend(r)
            full.extend(f)
        return columns, out, full

    with ThreadPoolExecutor(max(1, min(parallel, len(windows)))) as pool:
        results = list(pool.map(one, windows))
    columns = next((c for c, _, _ in results if c), [])
    rows = [r for _, rs, _ in results for r in rs]
    full = [fmt_epoch(w[0]) for _, _, fs in results for w in fs]
    if partial and failed and len(failed) == len(windows):
        raise DevoError(f"every window failed: {failed[0][1]}")
    return columns, rows, {"windows": len(windows), "retried": len(retried), "full": full, "splits": len(splits),
                           "failed": [f"{fmt_epoch(w[0])} → {fmt_epoch(w[1])}: {m}" for w, m in failed]}


def limit_note(limit, info, auto_split):
    """stderr lines about --limit for a fetch() result."""
    note = ""
    if info.get("splits"):
        note += (f"\n# auto-split: {info['splits']} window(s) hit --limit {limit} and were halved and re-run "
                 f"(back-fill batches cause this)")
    if info["full"]:
        how = (f"even at the minimum split ({len(info['full'])} window(s), first {info['full'][0]})" if auto_split
               else f"in {len(info['full'])} window(s) (first: {info['full'][0]})")
        note += (f"\n# limit {limit} reached {how}: results incomplete" +
                 ("; a back-fill batch can land more rows than that within one minute, which no time split "
                  "separates: raise --limit (or 0) or narrow the filter" if auto_split
                  else "; --auto-split halves full windows and re-runs them"))
    return note


def run_fetch(cfg, linq, frm_s, to_s, limit, a, auto_split):
    """`query` over concrete times: fetch() plus the stderr notes. Chunks are exact for raw rows and
    for `group every P` when the chunk is a multiple of P; other aggregates come back once per chunk
    and must be re-aggregated by the caller."""
    columns, rows, info = fetch(cfg, linq, frm_s, to_s, limit, a.timeout, a.chunk, a.parallel, not a.raw_ip,
                                auto_split, chunk_step(a.min_split))
    note = ""
    n = info["windows"]
    merged = None
    if is_grouped(linq) and (n > 1 or info["splits"]) and not getattr(a, "no_merge", False):
        merged, why = merge_grouped(linq, columns, rows)
        if merged is not None:
            rows = merged
            note += f"\n# {why}"
        else:
            note += (f"\n# grouped rows come back once per window and were NOT merged ({why}): re-aggregate "
                     "them yourself (sum counts, min/max of min/max; never add distinct counts)")
    if a.chunk:
        note += (f"\n# chunked: {n} windows of {a.chunk} (aligned to UTC multiples of the chunk size), "
                 f"{min(a.parallel, n)} in parallel")
    if info["retried"]:
        note += f"\n# {info['retried']} request(s) retried after a dropped connection"
    note += limit_note(limit, info, auto_split)
    return columns, rows, note, bool(info["full"])


def stats_text(names, rows, top=5, width=50):
    """Row count, then per column: filled, distinct, top values. For results too big to read."""
    out = [f"# stats: {len(rows)} rows, {len(names)} columns (column · filled · distinct · top {top} values)\n"]
    for i, n in enumerate(names):
        counts = {}
        for r in rows:
            v = cell(r[i], 0)
            if v != "":
                counts[v] = counts.get(v, 0) + 1
        filled = sum(counts.values())
        best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
        tops = " | ".join(f"{cell(v, width)} ×{c}" for v, c in best)
        out.append(f"{n} · {filled} · {len(counts)} · {tops}\n")
    return "".join(out)


UI_RESERVED = ("timestamp",)  # identifiers the Devo web UI's query editor rejects (the API accepts them)


def ui_lint(linq):
    """Warnings for a query meant to be pasted into the Devo web UI."""
    text = re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', linq)  # ignore string literals
    out = []
    for word in UI_RESERVED:
        if re.search(rf"\b{word}\b(?!\s*\()", text):  # timestamp(...) is a function and is fine
            out.append(f"`{word}` used as a field: the web UI says \"Cannot run: query has errors\". For Microsoft 365 "
                       f"use parsedate(str(jsonparse(message)[\"CreationTime\"]), \"YYYY-MM-DD[T]HH:mm:ss\", \"UTC\"); "
                       f"elsewhere use eventdate or the family's event-time field (table-guide.md)")
    return out


def as_dicts(columns, rows):
    """Rows as dicts, timestamps as ISO-8601 UTC."""
    names, types = [c[0] for c in columns], [c[1] for c in columns]
    return [dict(zip(names, (convert_value(v, t) for v, t in zip(r, types)))) for r in rows]


AGG_SELECT = "select count() as n, min(eventdate) as first, max(eventdate) as last"


def merge_agg(rows, keys):
    """Re-aggregate `group by keys` + AGG_SELECT rows that came back once per chunk."""
    out = {}
    for r in rows:
        k = tuple(r.get(f) for f in keys)
        if k not in out:
            out[k] = dict(r)
            continue
        m = out[k]
        m["n"] = (m.get("n") or 0) + (r.get("n") or 0)
        for k, pick in (("first", min), ("last", max), ("first_event", min), ("last_event", max)):
            if k in m or k in r:
                vals = [x for x in (m.get(k), r.get(k)) if x]
                m[k] = pick(vals) if vals else None
    return list(out.values())


# ---- grouped results across windows, approximate counts, field pre-checks

MERGE_FUNCS = {"count": "sum", "sum": "sum", "min": "min", "max": "max", "hllppcount": "max", "hllppcount_id": "sum"}
UNIQUE_ID = re.compile(r"(\w+_)?(id|Id|ID)|properties_id|\w*RecordId|\w*EventId|\w*_uuid")
_STR = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')


def blank_strings(linq):
    return _STR.sub(lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', linq)


def grouped_aggregates(linq):
    """The aggregations of a query's last `group ... select ...` as [(alias, func)], and whether a
    `where` on the aggregates follows; None when it can't be parsed."""
    text = blank_strings(linq)
    g = [m.end() for m in re.finditer(r"\bgroup\b", text)]
    if not g:
        return None
    rest = text[g[-1]:]
    m = re.search(r"\bselect\b", rest)
    if not m:
        return None
    sel = rest[m.end():]
    w = re.search(r"\bwhere\b", sel)
    having = bool(w)
    if w:
        sel = sel[:w.start()]
    out = []
    for item in split_top(sel):
        im = re.fullmatch(r"\s*(\w+)\s*\((.*)\)\s+as\s+(\w+)\s*", item, re.S)
        if not im:
            return None
        func = im.group(1).lower()
        if func == "hllppcount" and UNIQUE_ID.fullmatch(im.group(2).strip()):
            func = "hllppcount_id"  # distinct event ids: each event falls in one window, so window counts add up
        out.append((im.group(3), func))
    return out, having


def merge_grouped(linq, columns, rows):
    """Rows of a grouped query that came back once per window (chunks, auto-split halves), merged
    into one row per group: counts and sums added, min/max combined, hllppcount the largest window
    value (a lower bound: distinct counts can't be added). Returns (rows, note) or (None, reason)."""
    parsed = grouped_aggregates(linq)
    if not parsed:
        return None, "couldn't parse the aggregations"
    aggs, having = parsed
    bad = [f"{f}()" for _, f in aggs if f not in MERGE_FUNCS]
    if bad:
        return None, f"{', '.join(sorted(set(bad)))} can't be combined across windows"
    names = [c[0] for c in columns]
    how = {names.index(a): MERGE_FUNCS[f] for a, f in aggs if a in names}
    if len(how) != len(aggs):
        return None, "an aggregation alias is missing from the result"
    keys = [i for i in range(len(names)) if i not in how]
    out = {}
    for r in rows:
        k = tuple(json.dumps(r[i], sort_keys=True, default=str) for i in keys)
        m = out.get(k)
        if m is None:
            out[k] = list(r)
            continue
        for i, op in how.items():
            a, b = m[i], r[i]
            if a is None or b is None:
                m[i] = a if b is None else b
            elif op == "sum":
                m[i] = a + b
            else:
                m[i] = (min if op == "min" else max)(a, b)
    note = f"merged {len(rows)} per-window rows into {len(out)} groups (counts/sums added, min/max combined"
    if any(f == "hllppcount" for _, f in aggs):
        note += "; hllppcount = the largest per-window value, a lower bound"
    if any(f == "hllppcount_id" for _, f in aggs):
        note += "; hllppcount of an event id summed across windows (each event is in one window)"
    note += ")"
    if having:
        note += ("; the `where` on aggregates ran per window before merging, so groups near the threshold "
                 "may be missing: query without it and filter the merged rows")
    return list(out.values()), note


def round_approx(linq, columns, rows):
    """hllppcount() is an approximate distinct count that comes back as a float: show it as an int."""
    aliases = set(re.findall(r"\bhllppcount\s*\([^)]*\)\s+as\s+(\w+)", blank_strings(linq)))
    idx = [i for i, c in enumerate(columns) if c[0] in aliases]
    if idx:
        for r in rows:
            for i in idx:
                if isinstance(r[i], float):
                    r[i] = int(round(r[i]))
    return rows


RESERVED_ALIASES = {"by", "from", "where", "select", "group", "every", "as", "and", "or", "not", "in", "tag", "comm"}


def empty_columns(columns, rows, min_rows=5):
    """Columns that are null/empty in every returned row: often a parser that doesn't fill them (the data
    is then only in rawMessage/message), not real absence."""
    if len(rows) < min_rows:
        return []
    out = []
    for i, (name, _) in enumerate(columns):
        if name in ("eventdate",):
            continue
        if all(r[i] in (None, "", [], {}) for r in rows):
            out.append(name)
    return out


def heal_schema(prechecked, columns):
    """A pre-check named a field missing from the cached schema, yet it came back in the result: the
    cached schema is incomplete, so drop it (refetched on next use)."""
    names = {c[0] for c in columns or []}
    for table, missing in prechecked or []:
        if CACHE and names & set(missing):
            CACHE.drop(f"schema/{table}")


def reserved_aliases(linq):
    """Aliases (`as by`) that are LINQ keywords or clash with built-in identifiers: Devo answers only
    "Query parsing error" or "Identifier ... is used more than once"."""
    return sorted({a for a in re.findall(r"\bas\s+([A-Za-z_]\w*)", blank_strings(linq)) if a.lower() in RESERVED_ALIASES})


def unknown_fields(linq, cfg=None):
    """Field-like names in a query that the cached schema of its table doesn't have: [(table, [names])].
    Advisory (aliases and computed columns are excluded as far as a regex can tell); never fetches."""
    if not CACHE:
        return []
    text = blank_strings(linq)
    m = re.match(r"\s*from\s+`?([A-Za-z0-9_.-]+)`?", text)
    if not m or re.search(r"\b(from|union|join)\b", text[m.end():]):
        return []  # subqueries and joins: too much to guess
    table = m.group(1)
    known = set()
    for n in (f"schema/{table}", f"fields/{table}"):  # the schema API can omit fields a query returns: use both
        known |= known_fields(CACHE.get(n, allow_old=True) or [])
    if not known and cfg and table in (cached_table_set() or set()):
        try:
            known = known_fields(schema_fields(cfg, table))  # one quick GET, then cached
        except DevoError:
            return []
    if not known:
        return []
    body = text[m.end():]
    aliases = set(re.findall(r"\bas\s+([A-Za-z_]\w*)", body))
    words = linq_identifiers(body) - aliases - LINQ_WORDS - {"eventdate", "now"}
    words = {w for w in words if not re.fullmatch(r"\d+[smhdw]?|[smhdw]", w)}
    missing = sorted(w for w in words if w not in known)
    lower = {k.lower(): k for k in known}
    missing = [f"{w} (did you mean {lower[w.lower()]}?)" if w.lower() in lower else w for w in missing]
    return [(table, missing)] if missing else []


SAFE_TERM = re.compile(r"^[A-Za-z0-9_.@$-]+$")


def linq_term(term, what="term"):
    """A user-supplied name/term, validated for safe use inside a LINQ string literal."""
    if not SAFE_TERM.match(term or ""):
        raise DevoError(f"{what} {term!r}: use letters, digits and . _ @ $ - only (a distinctive substring)",
                        code=1)
    return term


def feed_gaps(cfg, tables, frm_s, to_s, timeout=300, slack=6 * 3600):
    """{table: newest eventdate} for tables whose feed stopped more than `slack` before to_s, from one
    collector-counter query (empty when the window is short or the counter fails)."""
    tables = sorted({t for t in tables if t})
    if not tables or to_s - frm_s < 12 * 3600:
        return {}
    q = ('from siem.logtrust.collector.counter where kind = "table", object in {'
         + ", ".join(json.dumps(t) for t in tables[:200]) + '} group by object select max(eventdate) as last')
    try:
        cols, rws, _ = fetch(cfg, q, frm_s, to_s, 0, timeout, "1d", 4)
    except DevoError:
        return {}
    last = {r.get("object"): r.get("last") for r in as_dicts(cols, rws)}
    cut = fmt_epoch(to_s - slack)
    return {t: v for t, v in last.items() if v and v < cut}


def cmd_query(cfg, a):
    linq = a.linq if a.linq != "-" else sys.stdin.read()
    linq = re.sub(r"^(\s*from\s+)(\S+)", lambda m: m.group(1) + quote_table(m.group(2)), linq, count=1)
    frm, frm_s = resolve_time(a.from_)
    to, to_s = resolve_time(a.to)
    clamped = ""
    now_s = int(time.time())
    if to_s is not None and to_s > now_s:  # Devo waits for a future `to` instead of returning
        to, to_s = now_s, now_s
        clamped = "\n# --to is in the future: clamped to now (Devo would otherwise wait until then)"
    if frm_s is not None and to_s is not None and frm_s >= to_s:
        raise DevoError(f"--from ({fmt_epoch(frm_s)}) must be before --to ({fmt_epoch(to_s)})", code=1)
    limit = None if a.limit == 0 else a.limit
    rng = f"{fmt_epoch(frm_s) if frm_s is not None else frm} → {fmt_epoch(to_s) if to_s is not None else to}"
    if a.dry_run:
        print(json.dumps({"query": linq, "from": frm, "to": to, "limit": limit,
                          "mode": {"type": "json/simple/compact"}, "ipAsString": True}, indent=1))
        print(f"# range {rng}", file=sys.stderr)
        return 0
    if a.ui_safe:
        for w in ui_lint(linq):
            print(f"# ui-safe: {w}", file=sys.stderr)
    tz = get_tz(a.tz)
    for bad in reserved_aliases(linq):
        print(f"# pre-check: `as {bad}` uses a reserved word as an alias: rename it (Devo will only say "
              "\"Query parsing error\")", file=sys.stderr)
    prechecked = unknown_fields(linq, cfg)
    for table, missing in prechecked:
        print(f"# pre-check: {', '.join(missing)} not in the cached schema of {table}: the query may fail with "
              f"`Unknown identifier` (the schema API can omit fields, and computed names are fine: if the query "
              f"works, ignore this)", file=sys.stderr)
    auto_split = a.auto_split if a.auto_split is not None else default_auto_split(linq, limit)
    start = time.time()
    full = False
    if frm_s is not None and to_s is not None:
        columns, rows, fetch_note, full = run_fetch(cfg, linq, frm_s, to_s, limit, a, auto_split)
    elif a.chunk:
        raise DevoError("--chunk needs concrete --from/--to (e.g. 7d, yesterday, ISO), not now() expressions",
                        code=1)
    else:
        columns, rows = collect(cfg, linq, frm, to, limit, a.timeout, not a.raw_ip)
        fetch_note = ""
        full = bool(limit) and len(rows) >= limit
    rows = round_approx(linq, columns, rows)
    heal_schema(prechecked, columns)
    blank = empty_columns(columns, rows)
    if blank and len(blank) < len(columns):
        print(f"# note: {', '.join(blank[:8])}{' …' if len(blank) > 8 else ''} empty in all {len(rows)} rows: the parser "
              "may not fill them (look in rawMessage/message) rather than the data being absent", file=sys.stderr)
    types = [c[1] for c in columns]
    rows = [[convert_value(v, t, a.epoch) for v, t in zip(r, types)] for r in rows]
    if tz:
        columns, rows = add_local_columns(columns, rows, tz)
    if a.sort:
        rows = sort_rows(rows, [c[0] for c in columns], a.sort)
    names = [c[0] for c in columns]
    if a.out:
        with open(a.out, "w", newline="") as out:
            write_rows(out, a.format, columns, rows, 0 if a.format != "table" else a.width)
    if a.stats or (a.out and not a.no_summary):
        sys.stdout.write(stats_text(names, rows))
    elif not a.out:
        shown = rows[: a.head] if a.head else rows
        write_rows(sys.stdout, a.format, columns, shown, 0 if a.format != "table" else a.width)
    note = f"# {len(rows)} rows, {len(columns)} columns, range {rng} UTC, {time.time() - start:.1f}s" + clamped
    if a.head and not a.out and not a.stats and len(rows) > a.head:
        note += f"\n# showing the first {a.head} of {len(rows)} rows (--head); use --out FILE for all of them"
    note += fetch_note
    if full and not fetch_note:
        note += f"\n# limit {limit} reached: more rows probably exist (raise --limit, or aggregate with group)"
    if full:
        if a.sort:
            note += ("\n# WARNING: --sort ran on a truncated result, so the top rows may be wrong. For a "
                     "top-N, filter on the aggregate (select count() as n where n > X) and/or use --limit 0")
    if not rows:
        note += ("\n# 0 rows. Check: time range; exact field values (string equality is exact; see "
                 "linq-syntax.md for substring/case-insensitive matching); field types (comparing a number field to a "
                 "string returns 0 rows without an error; see `devo.py schema`); whether the table has "
                 "data (`devo.py tables --grep`)")
        m_t = re.match(r"\s*from\s+`?([A-Za-z0-9_.-]+)", linq)
        if m_t and frm_s is not None and to_s is not None:
            for tname, lt in feed_gaps(cfg, [m_t.group(1)], frm_s, to_s, 60).items():
                note += (f"\n# FEED GAP: {tname} received nothing after {lt[:16]} (collector counter): 0 rows may "
                         "mean the feed is down, not that nothing happened")
        if m_t and event_time_for(m_t.group(1)) and event_time_for(m_t.group(1)).get("linq"):
            note += (f"\n# {m_t.group(1)} is filtered on eventdate (ingestion): its records can arrive hours or days "
                     "after they happened, so extend --to to now and filter on the event-time field instead "
                     "(table-guide.md, Event time per family)")
        fields = case_sensitive_name_matches(linq)
        if fields:
            note += (f"\n# note: {', '.join(fields)} matched case-sensitively (->, =, has). Names change case "
                     "between sources (host FQDN lowercase, rawMessage uppercase, NAME$ accounts); use "
                     "weakhas(field, \"...\") or eqic() on the shortest distinctive part of the name")
    if a.out:
        note += f"\n# written to {a.out}"
    print(note, file=sys.stderr)
    return 0


# ---------------------------------------------------------------- schema / tables

def table_fields(cfg, table):
    """[(field, type)] via GET /table; falls back to a 1-row query (the endpoint 404s for my.app.*)."""
    url = f"https://{REGIONS[cfg['region']][0]}/search/table/{urllib.parse.quote(table, safe='.')}"
    try:
        j = get_json(url, cfg["token"])
        return [(f["fieldName"], f["type"]) for f in j.get("object", [])], "schema API"
    except DevoError as e:
        if not re.search(r"HTTP (403|404)", str(e)):
            raise
    cols = None
    for cols, _ in run_query(cfg, f"from {quote_table(table)} select *", "now() - 1h", "now()", 1, 120):
        pass
    return cols or [], "1-row query"


def cmd_schema(cfg, a):
    fields, how = table_fields(cfg, a.table)
    total = len(fields)
    if a.grep:
        rx = re.compile(a.grep, re.I)
        fields = [(f, t) for f, t in fields if rx.search(f)]
    if a.format == "json":
        print(json.dumps([{"field": f, "type": t} for f, t in fields], indent=1))
    else:
        w = max([len(f) for f, _ in fields] + [5])
        for f, t in fields:
            print(f"{f.ljust(w)}  {t}")
    print(f"# {a.table}: {len(fields)}" + (f" of {total}" if a.grep else "") + f" fields (via {how})", file=sys.stderr)
    return 0


def cmd_tables(cfg, a):
    pat = re.compile(a.grep, re.I) if a.grep else None
    if a.live and a.from_ != TABLES_WINDOW:  # a one-off window: shown, not cached
        rows = [tuple(r) for r in live_tables(cfg, a.from_, a.timeout)]
        src = f"live, events since {a.from_}"
    else:
        state = CACHE.state("tables") if CACHE else "missing"
        rows = domain_tables(cfg, refresh=a.live, timeout=a.timeout)
        e = CACHE.read("tables") if CACHE else None
        age = human_secs(time.time() - e["fetched"]) if e else "0s"
        src = (f"events in the last {TABLES_WINDOW}; " + ("fetched live now, cached" if a.live or state != "fresh"
                                                          else f"cached {age} ago; --live refreshes"))
    shown = [(t, n) for t, n in rows if not pat or pat.search(t)]
    for t, n in shown:
        print(f"{n:>13,}  {t}")
    unq = ((CACHE.read("tables") or {}).get("unqueryable") or []) if CACHE else []
    print(f"# {len(shown)} tables ({src})" + (f"; {len(unq)} more are listed by the collector counter but aren't "
                                               "queryable (hidden)" if unq else ""), file=sys.stderr)
    return 0


# ---------------------------------------------------------------- alerts

def alerts_url(cfg, path):
    return f"https://{REGIONS[cfg['region']][1]}/alerts/v1/{path}"


def decode_extra(alert):
    """extraData is a JSON string with URL-encoded values; return a plain dict."""
    raw = alert.get("extraData")
    try:
        d = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        return {"extraData": raw}
    out = {}
    for k, v in d.items():
        if isinstance(v, str):
            v = urllib.parse.unquote_plus(v)
            t = v.strip()
            if len(t) >= 2 and ((t[0] == t[-1] == '"') or (t[0] in "[{" and t[-1] in "]}")):
                try:  # JSON-quoted strings ("\"JS/Foo\"") and nested JSON (raw_messages) as values
                    v = json.loads(t)
                except ValueError:
                    pass
        out[k] = v
    return out


RAW_TIME_KEYS = ("CreationTime", "creationTime", "createdDateTime", "activityDateTime", "eventTime", "EventTime",
                 "TimeGenerated", "timestamp", "Timestamp", "time", "@timestamp", "created_at")


def raw_event_time(ex):
    """The earliest event time found in the raw records carried in an alert's extra data (e.g. a
    Microsoft 365 record's CreationTime inside raw_messages), and how far it is from the alert's
    eventdate when that is over an hour ("+2.9d")."""
    found = []

    def walk(v, depth=0):
        if depth > 4:
            return
        if isinstance(v, dict):
            for k, x in v.items():
                if k in RAW_TIME_KEYS and isinstance(x, str):
                    d = parse_utc(x)
                    if d:
                        found.append(d)
                else:
                    walk(x, depth + 1)
        elif isinstance(v, list):
            for x in v[:50]:
                walk(x, depth + 1)

    walk({k: v for k, v in ex.items() if k != "eventdate"})
    if not found:
        return None, ""
    t = min(found)
    ev = parse_utc(str(ex.get("eventdate") or "").replace(" ", "T")) if ex.get("eventdate") else None
    gap = ""
    if ev:
        secs = (ev - t).total_seconds()
        if abs(secs) > 3600:
            gap = ("+" if secs > 0 else "-") + human_secs(abs(secs)) + " before the alert's eventdate"
    return iso_utc(t), gap


def alert_name(alert):
    d = alert.get("alertDefinition") or {}
    return d.get("name") or (alert.get("context") or "").rsplit(".", 1)[-1]


def status_label(code):
    return f"{code} {ALERT_STATUS.get(code, 'custom (see comments)')}"


def priority_label(p):
    try:
        p = float(p)
    except (TypeError, ValueError):
        return str(p)
    lab = ("very low" if p <= 1 else "low" if p <= 3 else "medium" if p <= 5 else
           "high" if p <= 7 else "very high")
    return f"{p:g} {lab}"


def to_ms(value):
    _, s = resolve_time(value)
    if s is None:
        raise DevoError(f"the Alerts API needs a concrete time, not {value!r}",
                        "use e.g. 24h, 7d, today, an ISO date or epoch", code=1)
    return s * 1000


PAGE = 100
RETRY_DELAY = 2  # seconds; chunk retries after a dropped connection


def fetch_alerts(cfg, frm, to, max_items):
    """All alerts in [frm, to] (epoch ms), every status, newest first. The list endpoint returns
    pages oldest first and often returns fewer items than `limit` even when more exist, so page
    until an empty page and de-duplicate by id. `showAll` is never sent: live, showAll=true
    *hides* Closed alerts (the docs say the opposite) and omitting it returns everything.
    Returns (alerts, truncated)."""
    seen, offset = {}, 0
    while True:
        q = {"limit": PAGE, "offset": offset, "from": frm, "to": to}
        page = get_json(alerts_url(cfg, "alerts/list?" + urllib.parse.urlencode(q)), cfg["token"])
        if not isinstance(page, list):
            raise DevoError(f"unexpected response: {str(page)[:200]}")
        if not page:
            break
        for x in page:
            seen.setdefault(x.get("id"), x)
        offset += PAGE
        if len(seen) >= max_items:
            break
    items = sorted(seen.values(), key=lambda x: x.get("createDate") or 0, reverse=True)
    return items, len(seen) >= max_items


def cmd_alerts(cfg, a):
    frm, to = to_ms(a.from_), to_ms(a.to)
    items, truncated = fetch_alerts(cfg, frm, to, a.max)
    if a.open:
        items = [x for x in items if x.get("status") not in CLOSED_STATUSES]
    if a.name:  # the definition name only: every context starts with the same my.alert.<domain>. prefix
        before = len(items)
        items = [x for x in items if a.name.lower() in alert_name(x).lower()]
        if before > 1 and len(items) == before:
            print(f"# note: --name {a.name!r} matched every alert in the window", file=sys.stderr)
    total = len(items)
    if a.by_def:
        return print_alerts_by_def(items, frm, to, a)
    if a.group_by:
        return print_alerts_grouped(items, frm, to, a)
    items = items[: a.limit]
    if a.format == "json":
        for x in items:
            x["extraDataDecoded"] = decode_extra(x)
        print(json.dumps(items, indent=1, ensure_ascii=False))
    else:
        rows = []
        for x in items:
            ex = decode_extra(x)
            src = x.get("srcIp") or x.get("srcHost") or ""
            dst = x.get("dstIp") or x.get("dstHost") or ""
            source = ((x.get("alertDefinition") or {}).get("alertCorrelationContext") or {}).get("sourceTable")
            raw_t, gap = raw_event_time(ex)
            rows.append([x.get("id"), fmt_ms(x.get("createDate"))[:19], str(ex.get("eventdate") or "")[:19],
                         (raw_t or "")[:19] + (f" ({gap})" if gap else ""),
                         priority_label(x.get("priority")), status_label(x.get("status")), alert_name(x),
                         source or "", x.get("username") or "", f"{src}→{dst}" if src or dst else "", len(ex)])
        # event_utc: the event time the detection captured; alerts can be created hours later.
        # source: the table the definition reads (edr.sentinelone.* = forwarded from another product).
        # raw_event_utc: the event's own time from the raw record in the extra data (CreationTime etc.),
        # when there is one: back-filled data can alert days after the event. mapped_user: the
        # definition's username mapping, which can be a fixed value or the rule author, not the actor.
        cols = [("id", ""), ("created_utc", ""), ("event_utc", ""), ("raw_event_utc", ""), ("priority", ""),
                ("status", ""), ("alert", ""), ("source", ""), ("mapped_user", ""), ("src→dst", ""),
                ("extra_fields", "")]
        write_rows(sys.stdout, "table" if a.format == "table" else a.format, cols, rows, a.width)
    note = (f"# {total} alerts in {fmt_epoch(frm // 1000)} → {fmt_epoch(to // 1000)} UTC, newest first"
            + (f"; showing {len(items)} (raise --limit)" if total > len(items) else ""))
    if truncated:
        note += f"; stopped fetching at --max {a.max}, older alerts not included"
    note += ("; Closed/False-positive hidden (--open)" if a.open
             else "; all statuses (use --open to hide Closed/False-positive)")
    print(note, file=sys.stderr)
    return 0


GROUP_KEYS = {"file": r"(file|object)_?(name|id)?$|sourcefilename|filename|objectid|filepath|path$",
              "site": r"^siteurl$|siteurl|site$|sitename",
              "user": r"^(user(id|name|principalname)?|upn|actor|account(name)?|targetusername|subjectusername)$",
              "host": r"^(host(name)?|machine|device(name)?|computer(name)?|srchost|dsthost)$",
              "hash": r"sha256|sha1|md5|hash",
              "ip": r"^(src|client|source)_?ip(address)?$|^ipaddress$|clientip"}


def extra_value(ex, rx):
    """The first value under a key matching rx in an alert's decoded extra data (nested records too)."""
    found = []

    def walk(v, depth=0):
        if depth > 4 or found:
            return
        if isinstance(v, dict):
            for k, x in v.items():
                if isinstance(x, (str, int)) and str(x).strip() and re.search(rx, k, re.I):
                    found.append(str(x))
                    return
            for x in v.values():
                walk(x, depth + 1)
        elif isinstance(v, list):
            for x in v[:20]:
                walk(x, depth + 1)

    walk(ex)
    return found[0] if found else None


def print_alerts_grouped(items, frm, to, a):
    """Alerts grouped into incidents by values in their extra data (file, site, user, host, hash, ip, or a
    key regex): several alerts under one definition are often separate incidents."""
    keys = [k.strip() for k in a.group_by.split(",") if k.strip()]
    groups = {}
    for x in items:
        ex = decode_extra(x)
        vals = tuple((extra_value(ex, GROUP_KEYS.get(k, k)) or "-") for k in keys)
        if a.group_by_parent:
            vals = tuple(re.sub(r"[/\\][^/\\]*$", "", v) if v != "-" else v for v in vals)
        g = groups.setdefault((alert_name(x),) + vals, {"ids": [], "status": {}, "first": None, "last": None})
        g["ids"].append(x.get("id"))
        st = status_label(x.get("status"))
        g["status"][st] = g["status"].get(st, 0) + 1
        c = x.get("createDate") or 0
        g["first"] = min(g["first"] or c, c)
        g["last"] = max(g["last"] or c, c)
    rows = [[len(g["ids"]), k[0]] + list(k[1:]) + [", ".join(f"{s_} {n}" for s_, n in g["status"].items()),
                                                    fmt_ms(g["first"])[:16], fmt_ms(g["last"])[:16],
                                                    ", ".join(map(str, g["ids"][:6])) + (" …" if len(g["ids"]) > 6 else "")]
            for k, g in sorted(groups.items(), key=lambda kv: -kv[1]["last"])]
    cols = [("alerts", ""), ("definition", "")] + [(k, "") for k in keys] + [("status", ""), ("first_created", ""),
                                                                              ("last_created", ""), ("ids", "")]
    write_rows(sys.stdout, "table" if a.format == "table" else a.format, cols, rows, a.width)
    print(f"# {len(items)} alerts in {len(groups)} group(s) by {', '.join(keys)} (from the extra data; '-' = no such "
          f"value), {fmt_epoch(frm // 1000)} → {fmt_epoch(to // 1000)} UTC", file=sys.stderr)
    return 0


def print_alerts_by_def(items, frm, to, a):
    """One row per alert definition: counts per status, newest alert, source table, entities seen."""
    groups = {}
    for x in items:
        g = groups.setdefault(alert_name(x), {"n": 0, "status": {}, "newest": None, "newest_id": None,
                                             "priority": x.get("priority"), "source": "", "users": set(), "open": 0})
        g["n"] += 1
        g["users"].add(x.get("username") or "")
        if x.get("status") not in (2, 300, 800):
            g["open"] += 1
        st = status_label(x.get("status"))
        g["status"][st] = g["status"].get(st, 0) + 1
        if g["newest"] is None or (x.get("createDate") or 0) > g["newest"]:
            g["newest"], g["newest_id"] = x.get("createDate") or 0, x.get("id")
        g["source"] = ((x.get("alertDefinition") or {}).get("alertCorrelationContext") or {}).get("sourceTable") or g["source"]
    rows = []
    for name, g in sorted(groups.items(), key=lambda kv: -(kv[1]["newest"] or 0)):
        if getattr(a, "open", False) and not g["open"]:
            continue  # --open: definitions whose alerts are all closed or suppressed are left out
        native = "forwarded" if (g["source"] or "").startswith(("edr.", "siem.")) else "native"
        mu = next(iter(g["users"])) if len(g["users"]) == 1 and g["n"] > 1 else ""
        rows.append([g["n"], g["open"], ", ".join(f"{k} {v}" for k, v in sorted(g["status"].items(), key=lambda kv: -kv[1])),
                     priority_label(g["priority"]), name, g["source"], native, fmt_ms(g["newest"])[:19], g["newest_id"],
                     (mu + " (same on every alert: a fixed value or the author, not the actor)") if mu else ""])
    cols = [("alerts", ""), ("open", ""), ("status", ""), ("priority", ""), ("definition", ""), ("source", ""),
            ("kind", ""), ("newest_utc", ""), ("newest_id", ""), ("mapped_user", "")]
    write_rows(sys.stdout, "table" if a.format == "table" else a.format, cols, rows, a.width)
    print(f"# {len(items)} alerts in {len(groups)} definitions, {fmt_epoch(frm // 1000)} → {fmt_epoch(to // 1000)} UTC"
          "; open = not Closed, False positive or Suppressed (custom codes count as open: read their comments); "
          "kind: forwarded = the definition relays another product's detection (EDR/SIEM table)", file=sys.stderr)
    return 0


def with_definition(cfg, x):
    """alerts/get omits alertDefinition (description, source table, detection query);
    alerts/list embeds it, so fetch the same alert from the list around its createDate."""
    if x.get("alertDefinition") or not x.get("createDate"):
        return x
    t = int(x["createDate"])
    try:
        items, _ = fetch_alerts(cfg, t - 60000, t + 60000, 2000)
    except DevoError:
        return x
    for y in items:
        if str(y.get("id")) == str(x.get("id")) and y.get("alertDefinition"):
            x["alertDefinition"] = y["alertDefinition"]
    return x


def cmd_alert(cfg, a):
    x = get_json(alerts_url(cfg, "alerts/get?" + urllib.parse.urlencode({"id": a.id})), cfg["token"])
    x = with_definition(cfg, x)
    ex = decode_extra(x)
    if a.json:
        x["extraDataDecoded"] = ex
        print(json.dumps(x, indent=1, ensure_ascii=False))
        return 0
    d = x.get("alertDefinition") or {}
    ctx = d.get("alertCorrelationContext") or {}
    p = print
    p(f"Alert {x.get('id')}: {alert_name(x)}")
    p(f"  created    {fmt_ms(x.get('createDate'))}   updated {fmt_ms(x.get('updateDate'))}")
    p(f"  priority   {priority_label(x.get('priority'))}   status {status_label(x.get('status'))}")
    p(f"  context    {x.get('context')}")
    for k in ("category", "username", "srcIp", "srcPort", "srcHost", "dstIp", "dstPort", "dstHost",
              "protocol", "application", "engine", "alertOwner", "alertMitreTactics", "alertMitreTechniques"):
        if x.get(k) not in (None, "", []):
            p(f"  {k:<10} {x.get(k)}")
    if not d:
        p("\n(definition not returned by the API: try `alert-defs --name <part of the name> --query`)")
    if d:
        p("\nDefinition")
        p(f"  name        {d.get('name')}")
        if d.get("description"):
            p(f"  description {d.get('description')}")
        if d.get("message"):
            p(f"  message     {d.get('message')}")
        if ctx.get("sourceTable"):
            p(f"  sourceTable {ctx.get('sourceTable')}")
        trig = ctx.get("correlationTrigger") or {}
        if trig:
            p(f"  trigger     {json.dumps({k: v for k, v in trig.items() if v is not None})}")
        if ctx.get("querySourceCode"):
            p("  query:")
            for line in ctx["querySourceCode"].splitlines():
                p(f"    {line}")
    raw_t, gap = raw_event_time(ex)
    if raw_t:
        p(f"\nEvent time in the raw record: {raw_t}" + (f"  ({gap}: the data arrived late; date the "
                                                         "incident from this, not from eventdate)" if gap else ""))
    p(f"\nExtra data ({len(ex)} fields)")
    w = max([len(k) for k in ex] + [1])
    for k in sorted(ex):
        p(f"  {k.ljust(w)}  {cell(ex[k], 0 if a.full else 300)}")
    comments = x.get("commentsList") or []
    if comments:
        p(f"\nComments ({len(comments)})")
        for c in sorted(comments, key=lambda c: c.get("creationDate") or 0):
            user = (c.get("author") or {}).get("user") or {}
            who = user.get("username") or user.get("name") or user.get("email") or "?"
            when = fmt_ms(c.get("creationDate"))
            title = f"{c['title']}: " if c.get("title") else ""
            text = c.get("msg") or c.get("comment") or c.get("text") or ""
            p(f"  [{when}] {who}: {title}{cell(text, 0 if a.full else 500)}")
    tags = x.get("tags") or []
    if tags:
        p(f"\nTags: {', '.join(str(t.get('name', t)) if isinstance(t, dict) else str(t) for t in tags)}")
    return 0


def cmd_alert_defs(cfg, a):
    q = {"page": a.page, "size": a.size}
    if a.name:
        q["nameFilter"] = a.name
    items = get_json(alerts_url(cfg, "alertDefinitions?" + urllib.parse.urlencode(q)), cfg["token"])
    if a.format == "json":
        print(json.dumps(items, indent=1, ensure_ascii=False))
        return 0
    for d in items:
        ctx = d.get("alertCorrelationContext") or {}
        p = print
        p(f"{d.get('id')}  {'active ' if d.get('isActive') else 'inactive'}  {d.get('name')}"
          f"  [{ctx.get('sourceTable') or '?'}]")
        if a.query and ctx.get("querySourceCode"):
            for line in ctx["querySourceCode"].splitlines():
                p(f"    {line}")
    print(f"# {len(items)} definitions (page {a.page}, size {a.size})", file=sys.stderr)
    return 0


def cmd_comment(cfg, a):
    """Add a comment to a triggered alert. Without --confirm nothing is sent: the exact request is
    printed for the user to approve. With --confirm it posts, then re-reads the alert to verify."""
    if not re.fullmatch(r"\d+", a.id):
        raise DevoError(f"alert id must be numeric, got {a.id!r}", code=1)
    title, msg = a.title.strip(), a.msg.strip()
    if not title or not msg:
        raise DevoError("--title and --msg must not be empty", code=1)
    get_url = alerts_url(cfg, "alerts/get?" + urllib.parse.urlencode({"id": a.id}))
    x = get_json(get_url, cfg["token"])
    body = {"elementId": a.id, "commentType": "ALERT", "commentTitle": title, "commentMsg": msg}
    before = len(x.get("commentsList") or [])
    print(f"Alert {a.id}: {alert_name(x)}  |  status {status_label(x.get('status'))}  |  "
          f"priority {priority_label(x.get('priority'))}  |  {before} existing comment(s)")
    print(f"POST {alerts_url(cfg, 'comments/add')}")
    print(json.dumps(body, indent=1, ensure_ascii=False))
    if not a.confirm:
        print("# NOT SENT (preview). Show this to the user; re-run with --confirm only after they approve it.",
              file=sys.stderr)
        return 0
    with http_open("POST", alerts_url(cfg, "comments/add"), cfg["token"], body=body) as r:
        result = r.read().decode("utf-8", "replace").strip()
    if result != "true":
        raise DevoError(f"unexpected response to comments/add: {result[:200]}")
    after = get_json(get_url, cfg["token"])
    match = [c for c in (after.get("commentsList") or [])
             if (c.get("title") or "").strip() == title and (c.get("msg") or "").strip() == msg]
    if not match:
        raise DevoError("Devo accepted the comment (true) but could not verify it on the alert yet",
                        f"check with `devo.py alert {a.id}` in a moment")
    c = max(match, key=lambda c: c.get("creationDate") or 0)
    who = ((c.get("author") or {}).get("user") or {}).get("username") or "?"
    print(f"# posted and verified: comment {c.get('id', '?')} at {fmt_ms(c.get('creationDate'))} as {who}; "
          f"alert status unchanged ({status_label(after.get('status'))})", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- coverage

WINDOWS_TABLES = ["system", "security", "sysmon", "powershell", "application"]


def day_range(frm_s, to_s):
    """UTC dates (YYYY-MM-DD) touched by [frm_s, to_s)."""
    first, last = frm_s - frm_s % 86400, (to_s - 1) - (to_s - 1) % 86400
    return [fmt_epoch(t)[:10] for t in range(first, last + 1, 86400)]


def day_gaps(per_day, days, low_ratio):
    """per_day: {date: n}. Returns (missing, low) for the window's days; the first and last day
    are partial, so they are never reported as low."""
    missing = [d for d in days if d not in per_day]
    present = sorted(per_day[d] for d in days if d in per_day)
    median = present[len(present) // 2] if present else 0
    inner = days[1:-1]
    low = [(d, per_day[d]) for d in inner if d in per_day and median and per_day[d] < low_ratio * median]
    return missing, low


def daily_coverage(cfg, table, field, name, frm_s, to_s, chunk, parallel, timeout, low_ratio):
    """Daily counts of a host in one table: {entity: {first, last, days: {date: n}, missing, low}}."""
    linq = (f'from {table} where weakhas({field}, "{name}") group every 1d by {field} '
            f'select count() as n, min(eventdate) as first, max(eventdate) as last')
    columns, rows, info = fetch(cfg, linq, frm_s, to_s, 0, timeout, chunk, parallel)
    days = day_range(frm_s, to_s)
    out = {}
    for r in as_dicts(columns, rows):
        e = out.setdefault(r[field], {"days": {}, "first": None, "last": None})
        d = (r.get("eventdate") or r.get("first") or "")[:10]
        e["days"][d] = e["days"].get(d, 0) + (r.get("n") or 0)
        for k, pick in (("first", min), ("last", max)):
            vals = [x for x in (e[k], r.get(k)) if x]
            e[k] = pick(vals) if vals else None
    for e in out.values():
        e["missing"], e["low"] = day_gaps(e["days"], days, low_ratio)
    return {"table": table, "query": linq, "window": [fmt_epoch(frm_s), fmt_epoch(to_s)], "days": len(days),
            "entities": out, "retried": info["retried"]}


def zscaler_sessions(cfg, name, frm_s, to_s, timeout):
    linq = (f'from vpn.zscaler.access where weakhas(Host, "{name}") '
            f'group by Username, Host, ServerIP, ServerPort, ConnectorIP, ConnectionStatus {AGG_SELECT}')
    columns, rows, _ = fetch(cfg, linq, frm_s, to_s, 0, timeout, "1d", 7)
    keys = ["Username", "Host", "ServerIP", "ServerPort", "ConnectorIP", "ConnectionStatus"]
    return {"table": "vpn.zscaler.access", "query": linq, "window": [fmt_epoch(frm_s), fmt_epoch(to_s)],
            "sessions": merge_agg(as_dicts(columns, rows), keys)}


def nxlog_restarts(cfg, name, frm_s, to_s, timeout):
    linq = (f'from box.win_nxlog.system where EventID = 7036, weakhas(host, "{name}"), weakhas(Message, "nxlog") '
            f'select eventdate, host, Message')
    columns, rows, _ = fetch(cfg, linq, frm_s, to_s, 500, timeout, "5d", 6)
    events = []
    for r in as_dicts(columns, rows):
        m = re.search(r"entered the (\w+) state", r.get("Message") or "")
        events.append({"eventdate": r.get("eventdate"), "host": r.get("host"), "state": m.group(1) if m else "?"})
    return {"table": "box.win_nxlog.system", "query": linq, "events": sorted(events, key=lambda e: e["eventdate"] or "")}


def cmd_coverage(cfg, a):
    """Is this host sending logs? Windows tables (host) and Linux (machine), case-insensitive,
    daily counts up to now, with missing and low days; Zscaler sessions to it; nxlog restarts."""
    from concurrent.futures import ThreadPoolExecutor
    name = linq_term(a.name, "host name")
    _, frm_s = resolve_time(a.from_)
    _, to_s = resolve_time(a.to)
    _, lfrm_s = resolve_time(a.linux_from)
    if None in (frm_s, to_s, lfrm_s) or frm_s >= to_s:
        raise DevoError("coverage needs concrete --from/--to (e.g. 30d, today, ISO) with from < to", code=1)
    lfrm_s = max(lfrm_s, frm_s)
    jobs = {f"box.win_nxlog.{t}": (daily_coverage, (cfg, f"box.win_nxlog.{t}", "host", name, frm_s, to_s, "5d", 6,
                                                    a.timeout, a.low_ratio)) for t in WINDOWS_TABLES}
    if not a.no_linux:
        jobs["box.unix"] = (daily_coverage, (cfg, "box.unix", "machine", name, lfrm_s, to_s, "1d", 7,
                                             a.timeout, a.low_ratio))
        jobs["vpn.zscaler.access"] = (zscaler_sessions, (cfg, name, lfrm_s, to_s, a.timeout))
    jobs["nxlog restarts"] = (nxlog_restarts, (cfg, name, frm_s, to_s, a.timeout))
    have = cached_table_set()  # skip the tables this domain doesn't have (never fetches the list)
    absent = []
    if have is not None:
        need = {k: ("box.win_nxlog.system" if k == "nxlog restarts" else k) for k in jobs}
        absent = sorted(k for k, t in need.items() if t not in have)
        jobs = {k: v for k, v in jobs.items() if k not in absent}
        if absent:
            cache_say("not in this domain's table list, skipped: " + ", ".join(absent))
        if not jobs:
            raise DevoError("none of the coverage tables (Windows nxlog, box.unix, Zscaler) are in this domain",
                            "find the host's source with `devo.py fields --role host` and query it directly", code=1)
    start = time.time()

    def run(item):
        key, (fn, args) = item
        try:
            return key, fn(*args), None
        except DevoError as e:
            return key, None, str(e)

    with ThreadPoolExecutor(3) as pool:
        results = list(pool.map(run, jobs.items()))
    report = {"name": name, "window": [fmt_epoch(frm_s), fmt_epoch(to_s)],
              "linux_window": None if a.no_linux else [fmt_epoch(lfrm_s), fmt_epoch(to_s)],
              "results": {k: (r if r is not None else {"error": err}) for k, r, err in results},
              "absent": absent}
    if a.format == "json":
        print(json.dumps(report, indent=1, ensure_ascii=False))
    else:
        print_coverage(report)
    print(f"# coverage for {name!r} in {time.time() - start:.0f}s. Name matching is weakhas (case-insensitive "
          "substring): check the matched names above are the host you mean.", file=sys.stderr)
    return 0


def print_coverage(report):
    p = print
    p(f"Coverage for {report['name']!r}  (Windows {report['window'][0]} → {report['window'][1]} UTC"
      + (f"; Linux/Zscaler {report['linux_window'][0]} → {report['linux_window'][1]}" if report["linux_window"] else
         "; Linux/Zscaler skipped (--no-linux)") + ")")
    for key, r in report["results"].items():
        if "error" in r:
            p(f"\n{key}: ERROR {r['error']}")
            continue
        if "entities" in r:
            if not r["entities"]:
                p(f"\n{key}: 0 rows")
                continue
            for ent, e in sorted(r["entities"].items()):
                seen = len(e["days"])
                p(f"\n{key}  [{ent}]  {seen}/{r['days']} days  first {e['first']}  last {e['last']}")
                if e["missing"]:
                    p(f"  MISSING days: {compress_days(e['missing'])}")
                if e["low"]:
                    p("  LOW days: " + ", ".join(f"{d} ({n} events)" for d, n in e["low"]))
        elif "sessions" in r:
            if not r["sessions"]:
                p(f"\n{key}: 0 sessions")
                continue
            p(f"\n{key}: {len(r['sessions'])} user/target combinations (ServerPort 22 = SSH, 3389 = RDP)")
            for x in sorted(r["sessions"], key=lambda x: x.get("last") or "", reverse=True)[:15]:
                p(f"  {x.get('Username')}  →  {x.get('Host')} {x.get('ServerIP')}:{x.get('ServerPort')}  "
                  f"via {x.get('ConnectorIP')}  {x.get('ConnectionStatus')}  n={x.get('n')}  last {x.get('last')}")
        elif "events" in r:
            ev = r["events"]
            p(f"\n{key}: " + ("none" if not ev else f"{len(ev)} nxlog service state change(s)"))
            gaps = set()
            for other in report["results"].values():
                for e in (other.get("entities") or {}).values():
                    gaps.update(e.get("missing") or [])
            near_days = {(dt.date.fromisoformat(g) + dt.timedelta(days=k)).isoformat() for g in gaps for k in (-1, 0, 1)}
            near = [x for x in ev if (x["eventdate"] or "")[:10] in near_days]
            if near:
                p(f"  around gaps ({len(near)}): the first 'running' after a gap is when logging resumed")
                for x in near[:20]:
                    p(f"    {x['eventdate']}  {x['host']}  {x['state']}")
            rest = [x for x in ev if x not in near]
            if rest:
                p(f"  other ({len(rest)}; restarts on a regular schedule are usually routine), latest:")
                for x in rest[-4:]:
                    p(f"    {x['eventdate']}  {x['host']}  {x['state']}")


def compress_days(days):
    """['2026-09-14','2026-09-15','2026-09-20'] -> '2026-09-14..2026-09-15, 2026-09-20'."""
    out, run = [], []
    for d in days:
        if run and (dt.date.fromisoformat(d) - dt.date.fromisoformat(run[-1])).days == 1:
            run.append(d)
        else:
            if run:
                out.append(run[0] if len(run) == 1 else f"{run[0]}..{run[-1]}")
            run = [d]
    if run:
        out.append(run[0] if len(run) == 1 else f"{run[0]}..{run[-1]}")
    return ", ".join(out)


# ---------------------------------------------------------------- activity

HINT_SOURCES = os.path.join(HINTS, "activity-sources.json")
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def load_activity_sources(path=None):
    with open(path or HINT_SOURCES) as f:
        return json.load(f)


def split_top(s, sep=","):
    """Split on `sep` outside parentheses, braces, brackets and string literals."""
    parts, depth, cur, quote, i = [], 0, [], None, 0
    while i < len(s):
        c = s[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
            cur.append(c)
        elif c in "({[":
            depth += 1
            cur.append(c)
        elif c in ")}]":
            depth -= 1
            cur.append(c)
        elif c == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def term_filter(filt, terms):
    """A source filter with {T} for each term, OR'd: only the conjuncts that mention {T} are
    repeated, so `EventID = 4103, weakhas(f, {T})` keeps its EventID test once."""
    terms = [terms] if isinstance(terms, str) else list(terms)
    out = []
    for part in split_top(filt):
        if "{T}" not in part:
            out.append(part)
        elif len(terms) == 1:
            out.append(part.replace("{T}", f'"{terms[0]}"'))
        else:
            out.append("(" + " or ".join(f'({part.replace("{T}", chr(34) + t + chr(34))})' for t in terms) + ")")
    return ", ".join(out)


def pre_aliases(pre):
    return re.findall(r"\bas\s+([A-Za-z_]\w*)", pre or "")


def event_time_select(src, et):
    """`select <expr> as event_time` for a source, or '' when the family has no event time (or the
    source already defines one)."""
    if not et or not et.get("linq") or "event_time" in pre_aliases(src.get("pre")):
        return ""
    return f'{et["linq"]} as event_time'


def source_query(src, terms, rows=False, et=None, dedupe=None):
    """The LINQ for one sweep source. rows=True turns a grouped source into raw rows (eventdate, the
    group fields, event_time and the dedupe columns) for `timeline`."""
    where = term_filter(src["filter"], terms)
    t = quote_table(src["table"])
    ets = event_time_select(src, et)
    pre = ", ".join(x for x in (src.get("pre"), ets) if x)
    pre = f" select {pre}" if pre else ""
    group = src.get("group")
    if group and len(terms if not isinstance(terms, str) else [terms]) > 1:
        tf = term_fields(src["filter"])  # with several terms, keep the matched field so each row names its term
        have_g = {g.strip() for g in group.split(",")}
        add = [f for f in tf if f not in have_g]
        if add:
            src = dict(src, group=group + ", " + ", ".join(add))
    if src.get("group") and rows:
        derived = set(pre_aliases(src.get("pre")))
        cols = ["eventdate"] + [f.strip() for f in src["group"].split(",") if f.strip() not in derived]
        cols += [d for d in dedupe or [] if d not in cols and d != "event_time"]
        return f"from {t} where {where}{pre} select {', '.join(dict.fromkeys(cols))}"
    if src.get("group"):
        agg = AGG_SELECT + (", min(event_time) as first_event, max(event_time) as last_event" if ets or
                            "event_time" in pre_aliases(src.get("pre")) else "")
        return f"from {t} where {where}{pre} group by {src['group']} {agg}"
    computed = ", ".join(x for x in (src.get("pre"), ets) if x)  # computed columns, then the projection
    if not computed:
        return f"from {t} where {where} select {src.get('select', '*')}"
    return f"from {t} where {where} select {computed} select {src.get('select', '*')}"


def term_fields(filt):
    """The fields a source compares with {T} (weakhas(f, {T}), f = {T}, f -> {T}, has(f, ... {T}))."""
    out = re.findall(r"\b(?:weakhas|has|eqic|toktains|weaktoktains)\(\s*([A-Za-z_]\w*)\s*,\s*\{T\}", filt)
    out += re.findall(r"\b([A-Za-z_]\w*)\s*(?:=|->|->>)\s*\{T\}", filt)
    return list(dict.fromkeys(f for f in out if f not in ("message", "Message", "rawMessage", "rawData")))


def table_has_field(table, field, fm=None):
    if fm is not None:
        t = fm.get("tables", {}).get(table) or {}
        return field in (t.get("fields") or {}) or field in (t.get("empty") or [])
    for n in (f"fields/{table}", f"schema/{table}"):
        d = CACHE.get(n, allow_old=True) if CACHE else None
        if d:
            return field in known_fields(d)
    return False


def fit_chunk(chunk, frm_s, to_s, max_windows=150):
    """A source's chunk, widened (in whole hours) when the range would need more than max_windows."""
    if not chunk:
        return chunk
    step = chunk_step(chunk)
    if (to_s - frm_s) / step <= max_windows:
        return chunk
    hours = -(-(to_s - frm_s) // (max_windows * 3600))
    return f"{hours}h" if hours < 48 else f"{-(-hours // 24)}d"


def run_source(cfg, src, terms, frm_s, to_s, limit, timeout, out_dir, rows=False, tz=None):
    terms = [terms] if isinstance(terms, str) else list(terms)
    et = event_time_for(src["table"])
    dedupe = [d for d in (et or {}).get("dedupe") or [] if rows and table_has_field(src["table"], d)]
    linq = source_query(src, terms, rows, et, dedupe)
    grouped = bool(src.get("group")) and not rows
    columns, rows_, info = fetch(cfg, linq, frm_s, to_s, limit, timeout, fit_chunk(src.get("chunk") or "1d", frm_s, to_s)
                                 if to_s - frm_s > 2 * 86400 or src.get("chunk") else None,
                                 src.get("parallel", 4), auto_split=not grouped, partial=True)
    recs = as_dicts(columns, rows_)
    if grouped and (info["windows"] > 1 or info["splits"]):
        recs = merge_agg(recs, [f.strip() for f in src["group"].split(",")])
    path = os.path.join(out_dir, f"{src['name']}.jsonl")
    with open(path, "w") as f:
        for r in recs:
            f.write(json.dumps(add_local_fields(r, tz), ensure_ascii=False) + "\n")
    # some tables store identities with quote marks ("x@y"); show them bare. Without `accounts`,
    # any field value containing the term counts (IP and host sweeps).
    skip = {"n", "first", "last", "first_event", "last_event", "eventdate", "event_time"}
    fields = src.get("accounts") or sorted({k for r in recs for k in r if k not in skip and not k.endswith("_local")})
    low = [t.lower() for t in terms]
    accounts, matched = set(), {}
    for r in recs:
        hit = set()
        for k in fields:
            v = r.get(k)
            if v in (None, "") or len(str(v)) > 200:
                continue
            sv = str(v).lower()
            for t, tl in zip(terms, low):
                if tl in sv:
                    hit.add(t)
                    accounts.add(str(v).strip('"'))
        for t in hit:
            matched[t] = matched.get(t, 0) + (r.get("n") or 1 if grouped else 1)
    if grouped:
        firsts = [r["first"] for r in recs if r.get("first")]
        lasts = [r["last"] for r in recs if r.get("last")]
        events = sum(r.get("n") or 0 for r in recs)
    else:
        firsts = lasts = [r["eventdate"] for r in recs if r.get("eventdate")]
        events = len(recs)
    return {"source": src["name"], "table": src["table"], "query": linq, "rows": len(recs), "events": events,
            "accounts": sorted(accounts), "matched": matched, "first": min(firsts) if firsts else None,
            "last": max(lasts) if lasts else None, "limit_reached": bool(info["full"]), "retried": info["retried"],
            "splits": info["splits"], "note": src.get("note", ""), "file": path, "mode": "rows" if rows else
            ("grouped" if src.get("group") else "rows"),
            "text_match": bool(re.search(r"\b(message|Message|rawMessage|rawData)\b|stringify\(", src["filter"])),
            "attribution": src.get("attribution") or ("raw-text" if re.search(r"\b(rawMessage|rawData)\b",
                                                                              src["filter"]) else "direct"),
            "partial": info.get("failed") or []}


def expand_terms(upn, naming=None):
    """Account variants from a UPN `first.last@domain`, one per naming template ({upn}, {local}, {first},
    {last}, {f} = first initial, {l} = last initial). The domain's conventions are recorded with
    `devo.py cache naming set ...`; without them the defaults are {upn}, {first}.{last}, {f}{last}."""
    local = upn.split("@", 1)[0].lower()
    parts = [p for p in re.split(r"[._-]", local) if p]
    if "@" not in upn or len(parts) < 2:
        raise DevoError(f"--expand needs a UPN like first.last@domain, got {upn!r}", code=1)
    first, last = parts[0], parts[-1]
    vals = {"upn": upn.lower(), "local": local, "first": first, "last": last, "f": first[0], "l": last[0]}
    out = []
    for tpl in naming or DEFAULT_NAMING:
        try:
            out.append(tpl.format(**vals))
        except (KeyError, IndexError, ValueError):
            raise DevoError(f"naming template {tpl!r}: use {{upn}} {{local}} {{first}} {{last}} {{f}} {{l}}", code=1)
    return list(dict.fromkeys(out))


def cmd_activity(cfg, a):
    """Everything a user did: run the domain's validated sweep sources (cached; seeded from references/hints/activity-sources.json) in parallel, one
    JSONL file per source in --out-dir, and print a per-source summary."""
    from concurrent.futures import ThreadPoolExecutor
    raw_terms = [a.term] if a.term else []
    for t in a.terms or []:
        raw_terms += [x.strip() for x in t.split(",") if x.strip()]
    raw_terms += list(a.term_opt or [])
    if not raw_terms:
        raise DevoError("give a term (positional), --term or --terms", code=1)
    if a.expand:
        if a.by != "user":
            raise DevoError("--expand is for --by user", code=1)
        upns = [t for t in raw_terms if "@" in t]
        if not upns:
            raise DevoError("--expand needs a UPN (first.last@domain) among the terms", code=1)
        naming = naming_templates()
        if not load_notes().get("naming"):
            cache_say(f"--expand with the default naming {', '.join(naming)}; record this domain's account "
                      "conventions with `devo.py cache naming set '<templates>'`")
        raw_terms = [x for u in upns for x in expand_terms(u, naming)] + [t for t in raw_terms if "@" not in t]
    terms = list(dict.fromkeys(linq_term(t) for t in raw_terms))
    if a.by == "ip":
        for t in terms:
            if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*", t):
                raise DevoError(f"--by ip needs an IP address, got {t!r}", code=1)
    tz = get_tz(a.tz)
    _, frm_s = resolve_time(a.from_)
    _, to_s = resolve_time(a.to)
    if None in (frm_s, to_s) or frm_s >= to_s:
        raise DevoError("activity needs concrete --from/--to (e.g. today, 24h, ISO) with from < to", code=1)
    out_dir = os.path.abspath(os.path.expanduser(a.out_dir))
    if os.path.commonpath([out_dir, SKILL_DIR]) == SKILL_DIR:
        raise DevoError("--out-dir must not be inside the skill directory (results hold personal data)", code=1)
    os.makedirs(out_dir, exist_ok=True)
    conf = load_activity_sources(a.sources) if a.sources else domain_sources(cfg)
    sources = list(conf["sources"])
    only = {x.strip() for x in a.only.split(",")} if a.only else None
    skip = {x.strip() for x in a.skip.split(",")} if a.skip else set()
    sources = [x for x in sources if x.get("by", "user") == a.by
               and (only is None or x["name"] in only) and x["name"] not in skip
               and not (a.no_auto and x.get("generated"))]
    if a.graph_only:
        if not a.graph_ids:
            raise DevoError("--graph-only needs --graph-ids", code=1)
        sources = []
    prior = os.path.join(out_dir, "summary.json")
    if a.graph_only and os.path.exists(prior):  # run the Graph pass over the earlier sweep's window
        with open(prior) as f:
            w = [parse_utc(x) for x in json.load(f).get("window") or []]
        if len(w) == 2 and all(w):
            frm_s, to_s = int(w[0].timestamp()), int(w[1].timestamp())
            print(f"# --graph-only: using the earlier sweep's window {fmt_epoch(frm_s)} → {fmt_epoch(to_s)}",
                  file=sys.stderr)
    jobs = [(x, terms) for x in sources]
    for i, oid in enumerate([g.strip() for g in a.graph_ids.split(",")] if a.graph_ids and a.by == "user" else [], 1):
        if not GUID.match(oid):
            raise DevoError(f"--graph-ids: {oid!r} is not an object id (GUID)", code=1)
        if not conf.get("graph"):
            raise DevoError("--graph-ids: this domain has no Microsoft Graph activity table (or its schema "
                            "lacks the fields)", "see `devo.py cache status`", code=1)
        g = dict(conf["graph"], name=f"graph_{i}")
        jobs.append((g, [oid]))
    if not jobs:
        raise DevoError("no sources selected (check --only/--skip names)", code=1)
    if len(terms) > 1 or a.expand:
        print(f"# terms (OR'd in every source): {', '.join(terms)}", file=sys.stderr)
    start = time.time()

    done, lock = [0], threading.Lock()

    def run(job):
        src, t = job
        try:
            r = run_source(cfg, src, t, frm_s, to_s, a.limit, a.timeout, out_dir, a.rows, tz)
        except DevoError as e:
            r = {"source": src["name"], "table": src["table"], "query": source_query(src, t), "error": str(e),
                 "rows": 0, "events": 0, "accounts": [], "matched": {}, "first": None, "last": None,
                 "note": src.get("note", "")}
        r["generated"] = bool(src.get("generated"))
        with lock:
            done[0] += 1
            if r["rows"] or r.get("error") or done[0] % 25 == 0 or done[0] == len(jobs):
                print(f"# [{done[0]}/{len(jobs)}] {src['name']}: " + (f"ERROR {r['error'][:80]}" if r.get("error")
                      else f"{r['rows']} rows"), file=sys.stderr, flush=True)
        return r

    with ThreadPoolExecutor(max(1, a.parallel_sources)) as pool:
        results = list(pool.map(run, jobs))
    mark_duplicates(results)
    feed_gaps = {}
    if to_s - frm_s >= 12 * 3600:  # did any source's table stop receiving data inside the window?
        try:
            q = ('from siem.logtrust.collector.counter where kind = "table" group by object '
                 'select max(eventdate) as last')
            cols, rws, _ = fetch(cfg, q, frm_s, to_s, 0, a.timeout, "1d", 4)
            last = {r.get("object"): r.get("last") for r in as_dicts(cols, rws)}
            cut = fmt_epoch(to_s - 6 * 3600)
            for tname in {r["table"] for r in results}:
                lt = last.get(tname)
                if lt and lt < cut:
                    feed_gaps[tname] = lt
        except DevoError:
            pass
    for r in results:
        if r["table"] in feed_gaps:
            r["feed_gap"] = feed_gaps[r["table"]]
            r["note"] = (f"FEED GAP: {r['table']} received nothing after {feed_gaps[r['table']][:16]}; no rows after that "
                         "is not 'no activity'; " + (r.get("note") or "")).rstrip("; ")
    if feed_gaps:
        print("# feed gaps inside the window (newest data in the collector counter): " + ", ".join(
            f"{t} after {v[:16]}" for t, v in sorted(feed_gaps.items())), file=sys.stderr)
    if a.graph_only and os.path.exists(prior):  # add the Graph pass to the earlier sweep in the same directory
        with open(prior) as f:
            old = json.load(f)
        names = {r["source"] for r in results}
        results = [r for r in old.get("sources", []) if r["source"] not in names] + results
        terms = list(dict.fromkeys((old.get("terms") or []) + terms))
        w = [parse_utc(x) for x in old.get("window") or []]
        if len(w) == 2 and all(w):  # the summary keeps the sweep's window (the Graph pass ran over --from/--to)
            frm_s, to_s = int(w[0].timestamp()), int(w[1].timestamp())
    summary = {"term": terms[0] if len(terms) == 1 else ",".join(terms), "terms": terms, "by": a.by,
               "rows_mode": bool(a.rows), "tz": a.tz, "window": [fmt_epoch(frm_s), fmt_epoch(to_s)],
               "seconds": round(time.time() - start), "sources": results, "feed_gaps": feed_gaps}
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1, ensure_ascii=False)
    print_activity(summary, a.width)
    return 0


def mark_duplicates(results):
    """Sources that report exactly the same events (copies of one record stream in sibling tables, e.g.
    a vendor writing each record to several tables) are marked so the summary and timeline count them once."""
    seen = {}
    for r in sorted(results, key=lambda r: (r.get("generated", False), r["source"])):
        if not r.get("events") or r.get("error"):
            continue
        # the same count in sibling tables is one stream written twice; small counts must also share times
        k = ((r["events"], (r.get("table") or "").rsplit(".", 1)[0]) if r["events"] >= 20
             else (r["events"], r.get("first"), r.get("last"), tuple(sorted(r.get("matched") or {}))))
        if k in seen:
            r["duplicate_of"] = seen[k]
            r["note"] = (f"same events as {seen[k]} (a copy): counted once; " + (r.get("note") or "")).rstrip("; ")
        else:
            seen[k] = r["source"]


def print_activity(summary, width):
    res = summary["sources"]
    multi = len(summary.get("terms") or []) > 1
    rows = []
    for r in sorted(res, key=lambda r: (-(r["events"] or 0), r["source"])):
        if not r["rows"] and not r.get("error") and not r.get("partial"):
            continue  # listed once, collapsed, on stderr
        acc = r["accounts"]
        shown = ", ".join(acc[:3]) + (f" +{len(acc) - 3}" if len(acc) > 3 else "")
        note = "ERROR: " + r["error"] if r.get("error") else r.get("note", "")
        if r.get("limit_reached"):
            note = "LIMIT REACHED (raise --limit); " + note
        if r.get("partial"):
            note = f"PARTIAL: {len(r['partial'])} window(s) failed ({r['partial'][0][:60]}…): rerun; " + note
        row = [r["source"], r["rows"], r["events"], shown, (r["first"] or "")[:16], (r["last"] or "")[:16], note]
        raw_only = r["rows"] and not r.get("matched") and r.get("text_match")
        if multi:
            row.insert(4, ", ".join(f"{t} ({n})" for t, n in sorted((r.get("matched") or {}).items(),
                                                                    key=lambda kv: -kv[1]))
                       or ("(raw text only: check the match)" if raw_only else "-"))
        elif raw_only and not acc:
            row[3] = "(matched in raw text only: check it)"
        rows.append(row)
    cols = [("source", ""), ("rows", ""), ("events", ""), ("entities seen", ""), ("first", ""), ("last", ""),
            ("note", "")]
    if multi:
        cols.insert(4, ("matched term (events)", ""))
    write_rows(sys.stdout, "table", cols, rows, width)
    if multi:
        unmatched = [t for t in summary["terms"] if not any(t in (r.get("matched") or {}) for r in res)]
        unattributed = [r["source"] for r in res if r["rows"] and not r.get("matched")]
        print(f"# terms not matched in any source that names its term: {', '.join(unmatched) or '-'}"
              + (f" (but {len(unattributed)} source(s) with rows can't say which term matched, e.g. raw-text matches: "
                 f"{', '.join(unattributed[:5])}; check them or sweep that term alone)" if unmatched and unattributed else ""),
              file=sys.stderr)
    empty = [r["source"] for r in res if not r.get("error") and not r["rows"]]
    errors = [r["source"] for r in res if r.get("error")]
    limited = [r["source"] for r in res if r.get("limit_reached")]
    print(f"# {summary['term']!r} {summary['window'][0]} → {summary['window'][1]} UTC, {len(res)} sources in "
          f"{summary['seconds']}s; files and summary.json in the --out-dir", file=sys.stderr)
    gen_empty = [x for x in empty if x.startswith("auto_")]
    hint_empty = [x for x in empty if not x.startswith("auto_")]
    print(f"# 0 rows ({len(empty)}): {', '.join(hint_empty) or '-'}"
          + (f"; plus {len(gen_empty)} generated sources" if gen_empty else ""), file=sys.stderr)
    dups = [f"{r['source']}={r['duplicate_of']}" for r in res if r.get("duplicate_of")]
    if dups:
        print(f"# copies (same events, counted once in timeline): {', '.join(dups)}", file=sys.stderr)
    print(f"# errors ({len(errors)}): {', '.join(errors) or '-'}   limit reached: {', '.join(limited) or '-'}",
          file=sys.stderr)
    oids = sorted({r.get("properties_userId") for x in res if x["source"].startswith("entra_") and x.get("file")
                   for r in _read_jsonl(x["file"]) if r.get("properties_userId")})
    if oids and not any(x["source"].startswith("graph_") for x in res):
        print(f"# Graph second pass: --graph-ids {','.join(oids)} (object ids seen in the sign-ins)", file=sys.stderr)


def _read_jsonl(path):
    try:
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]
    except OSError:
        return []


# ---------------------------------------------------------------- profile / field map

PATTERNS = [  # (name, regex) - first match wins; applied to str(value).strip()
    ("guid-quoted", re.compile(r'^"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"$')),
    ("guid", re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")),
    ("email-quoted", re.compile(r'^"[^@\s"]+@[^@\s"]+\.[^@\s"]+"$')),
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("domain\\user", re.compile(r"^[A-Za-z0-9_.-]+\\[^\\\s]+$")),
    ("sid", re.compile(r"^S-1-\d+(-\d+)+$")),
    ("ipv4", re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")),
    ("ipv4:port", re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d+$")),
    ("time-of-day", re.compile(r"^\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?$")),
    ("ipv6", re.compile(r"^(?=[0-9a-fA-F:]*(::|[a-fA-F]))(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")),
    ("mac", re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")),
    ("md5", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("sha1", re.compile(r"^[0-9a-fA-F]{40}$")),
    ("sha256", re.compile(r"^[0-9a-fA-F]{64}$")),
    ("arn", re.compile(r"^arn:aws")),
    ("url", re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")),
    ("iso-time", re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")),
    ("date", re.compile(r"^\d{4}-\d{2}-\d{2}$")),
    ("epoch-ms", re.compile(r"^1[5-9]\d{11}$")),
    ("epoch-s", re.compile(r"^1[5-9]\d{8}$")),
    ("int", re.compile(r"^-?\d+$")),
    ("float", re.compile(r"^-?\d+\.\d+$")),
    ("bool", re.compile(r"^(true|false|True|False)$")),
    ("json-object", re.compile(r"^\{.*\}$", re.S)),
    ("json-array", re.compile(r"^\[.*\]$", re.S)),
    ("win-path", re.compile(r"^[A-Za-z]:\\|^\\\\")),
    ("unix-path", re.compile(r"^/[^ ]*$")),
    ("fqdn", re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\.?$")),
    ("token", re.compile(r"^[A-Za-z0-9_.$-]+$")),
]
# identity-like field names: never keep sample values for these (personal data)
IDENTITY_NAME = re.compile(r"user|name|host|machine|computer|account|mail|upn|actor|owner|principal|subject|target|"
                           r"display|title|message|msg|path|file|url|uri|domain|ip|addr|sid|id$|_id|guid|session|"
                           r"token|key|secret|password|phone|device|workstation|client|server|email|comment|body|"
                           r"text|query|command|cmd|arg|script|subject|recipient|sender|location|city|country|lat|lon",
                           re.I)
# sample values are kept ONLY for fields whose names say they are categorical (allowlist): other
# low-cardinality fields (repo, org, app group, customer, version, tenant…) can hold names.
ENUM_NAME = re.compile(r"(^|_)(operation|action|activity|activitytype|eventid|event_?type|eventname|type|subtype|"
                       r"category|status|result|resulttype|outcome|severity|level|method|protocol|proto|direction|"
                       r"kind|mode|state|verdict|classification|logontype|recordtype|usertype|workload|"
                       r"service|logid|code|reason|channel|keywords|opcode|task|ruletype|confidence)$", re.I)
ROLE_RULES = [  # (role, name regex, patterns that support it or None for name-only)
    ("time", re.compile(r"date|time|timestamp|created|when", re.I),
     {"iso-time", "epoch-ms", "epoch-s", "date", "time-of-day"}),
    ("ip", re.compile(r"ip|addr|address", re.I), {"ipv4", "ipv6", "ipv4:port"}),
    ("user", re.compile(r"user|account|actor|upn|principal|owner|login|initiatedby|email|mail|sender|recipient|"
                        r"identity|member", re.I), {"email", "email-quoted", "domain\\user", "token", "sid", "guid"}),
    ("host", re.compile(r"host|machine|computer|workstation|device|server|fqdn|agent.*name|node", re.I),
     {"fqdn", "token"}),
    ("join-id", re.compile(r"correlation|session|request|conversation|thread|chat|message.?id|logonid|logon_id|"
                           r"processguid|process_guid|guid|storyline|trace|operationid|connectionid|meetingid|"
                           r"(^|_)id$|Id$", re.I), None),  # the name decides: thread ids look like emails
    ("hash", re.compile(r"hash|md5|sha", re.I), {"md5", "sha1", "sha256", "token"}),
    ("url/domain", re.compile(r"url|uri|domain|question|query_?name|site|referer|dns", re.I),
     {"url", "fqdn", "token", "unix-path"}),
    ("process/file", re.compile(r"image|process|file|path|command|cmd|script|exe", re.I),
     {"win-path", "unix-path", "token"}),
    ("action", re.compile(r"operation|action|eventname|eventid|event_?type|activity|category|method|type$|op$", re.I),
     None),
    ("outcome", re.compile(r"result|status|error|code|outcome|success|fail|reason|verdict", re.I), None),
    ("text", re.compile(r"message|msg|raw|payload|description|details|body|text", re.I), None),
]


def keep_values(name):
    """Whether sample values of this field may be stored: categorical names only, never identities."""
    leaf = re.split(r"__|_(?=[A-Z])|\.", name)[-1]
    if ENUM_NAME.fullmatch(leaf) or ENUM_NAME.fullmatch(name):
        return True  # the name itself is categorical (EventID, action, Operation, …)
    return bool(ENUM_NAME.search(name)) and not IDENTITY_NAME.search(leaf)


def classify(v):
    s = str(v).strip()
    if s == "":
        return "empty"
    for name, rx in PATTERNS:
        if rx.match(s):
            return name
    return "text" if " " in s else "other"


def case_of(values):
    letters = [v for v in values if any(c.isalpha() for c in v)]
    if not letters:
        return None
    lo = all(v == v.lower() for v in letters)
    up = all(v == v.upper() for v in letters)
    return "lower" if lo else "upper" if up else "mixed"


def guess_role(name, typ, patterns):
    if typ == "timestamp":
        return "time"
    if typ in ("ip4", "ip6"):
        return "ip"
    for role, rx, pats in ROLE_RULES:
        if rx.search(name) and (pats is None or not patterns or patterns & pats):
            return role
    if patterns & {"ipv4", "ipv6"}:
        return "ip"
    if patterns & {"email", "email-quoted", "domain\\user"}:
        return "user"
    return None


def profile_rows(columns, rows):
    """Field profiles from sample rows: type, fill rate, value patterns, case, distinct count, role, and
    enum values only for non-identity, low-cardinality fields. No other sample values are kept."""
    n = len(rows)
    out = {}
    for i, (name, typ) in enumerate(columns):
        vals = [r[i] for r in rows]
        filled = [v for v in vals if v not in (None, "", "-", [], {}) and str(v).lower() not in ("null", "none")]
        strs = [json.dumps(v) if isinstance(v, (dict, list)) else str(v) for v in filled]
        pats = {}
        for v in strs:
            k = classify(v)
            pats[k] = pats.get(k, 0) + 1
        distinct = len(set(strs))
        f = {"type": typ, "fill": round(len(filled) / n, 3) if n else 0.0, "distinct": distinct}
        if pats:
            f["patterns"] = dict(sorted(pats.items(), key=lambda kv: -kv[1])[:3])
            c = case_of(strs)
            if c:
                f["case"] = c
            f["len"] = round(sum(len(x) for x in strs) / len(strs))
        role = guess_role(name, typ, set(pats))
        if role == "join-id" and distinct <= 1 and len(filled) >= 20:
            role = "constant"  # e.g. tenant/organisation ids: one value everywhere, links nothing
        if role:
            f["role"] = role
        if (strs and distinct <= 12 and keep_values(name)
                and all(classify(x) in ("int", "token", "bool", "text", "other") and len(x) <= 60 for x in set(strs))):
            f["values"] = sorted(set(strs))[:12]
        out[name] = f
    return out


def sample_table(cfg, table, size, timeout, windows=("1h", "24h", "7d", "30d")):
    """Up to `size` rows from the most recent window that has enough data."""
    columns, rows, used = None, [], None
    _, to_s = resolve_time("now")
    for w in windows:
        _, frm_s = resolve_time(w)
        columns, rows, _ = fetch(cfg, f"from {quote_table(table)} select *", frm_s, to_s, size, timeout)
        used = w
        if len(rows) >= min(size, 50):
            break
    return columns or [], rows, used


def cmd_profile(cfg, a):
    """Profile tables from live samples (shapes only), store them in the cache, and print them (or also
    merge them into an exported field-map JSON file with --write)."""
    from concurrent.futures import ThreadPoolExecutor
    tables = a.tables
    if a.from_file:
        with open(a.from_file) as f:
            tables = [l.split()[-1] for l in f if l.strip() and not l.startswith("#")]

    def one(t):
        try:
            return t, table_profile(cfg, t, refresh=True, sample=a.sample, timeout=a.timeout), None
        except DevoError as e:
            return t, None, str(e)

    with ThreadPoolExecutor(max(1, a.parallel)) as pool:
        results = list(pool.map(one, tables))
    if a.write:
        if os.path.exists(a.write):
            with open(a.write) as f:
                fm = json.load(f)  # raw: curated roles stay in field-roles.json
        else:
            fm = {"tables": {}}
        for t, prof, err in results:
            if prof is not None:
                prof["profiled"] = fmt_epoch(int(time.time()))[:10]
                fm["tables"][t] = prof
            elif "Unknown table" in (err or ""):
                fm.setdefault("unqueryable", [])
                if t not in fm["unqueryable"]:
                    fm["unqueryable"].append(t)
        fm["tables"] = dict(sorted(fm["tables"].items()))
        with open(a.write, "w") as f:
            json.dump(fm, f, indent=0, ensure_ascii=False, sort_keys=False)
            f.write("\n")
    if a.format == "json":
        print(json.dumps({t: (p if p else {"error": e}) for t, p, e in results}, indent=1))
    else:
        for t, prof, err in results:
            if err:
                print(f"{t}: ERROR {err}")
                continue
            print_profile(t, prof, a.all)
    ok = sum(1 for _, p, _ in results if p)
    print(f"# profiled {ok}/{len(results)} tables, cached" + (f"; merged into {a.write}" if a.write else ""),
          file=sys.stderr)
    return 0


def compact_profile(prof):
    """Keep full entries only for fields with data; empty ones become a list of names."""
    fields = prof["fields"]
    prof["fields"] = {k: v for k, v in fields.items() if v["fill"] > 0}
    prof["empty"] = [k for k, v in fields.items() if v["fill"] == 0]
    return prof


def print_profile(table, prof, show_empty=False, grep=None):
    fields, empty = prof["fields"], prof.get("empty", [])
    if grep:
        rx = re.compile(grep, re.I)
        fields = {k: v for k, v in fields.items() if rx.search(k)}
        empty = [k for k in empty if rx.search(k)]
    print(f"\n{table}  ({prof['rows']} sample rows from the last {prof['window']}"
          + (f", profiled {prof['profiled']}" if prof.get("profiled") else "")
          + f"; {len(fields)}/{len(fields) + len(empty)} fields had data in the sample: fields only some event types "
            "fill can be missing from it; `schema` lists every field, --all shows the unseen ones)")
    for name, f in fields.items():
        pats = ",".join(f.get("patterns", {}))
        extra = f"  values: {', '.join(f['values'])}" if f.get("values") else ""
        print(f"  {name:<40} {f['type']:<9} fill {f['fill']:>5.0%}  {f.get('role') or '':<12} {pats:<24} "
              f"{f.get('case') or ''}{extra}"[:220])
    if show_empty and empty:
        print(f"  (no data in the sample: {', '.join(empty)})")


FIELD_ROLES = os.path.join(HINTS, "field-roles.json")


def apply_roles(fm, roles_path):
    """Apply curated role corrections on top of profiled roles, so re-profiling never loses them. A
    curated role of null clears a wrong guess."""
    if roles_path and os.path.exists(roles_path):
        with open(roles_path) as f:
            curated = json.load(f)
        everywhere = curated.get("*") or {}  # by field name, for every table; table keys override

        def put(f, role):
            if role:
                f["role"] = role
            else:
                f.pop("role", None)
            f["curated"] = True

        for table, prof in fm.get("tables", {}).items():
            own = curated.get(table) or {}
            for name, f in prof.get("fields", {}).items():
                if name in own:
                    put(f, own[name])
                elif name in everywhere:
                    put(f, everywhere[name])
    return fm


def load_field_map(path=None, roles_path=None):
    """The field map: from a file when given (an export or a test), else the cached profiles of this
    domain, with the curated roles in references/hints/field-roles.json applied on top."""
    if path is None:
        return cached_field_map()
    with open(path) as f:
        fm = json.load(f)
    return apply_roles(fm, roles_path)


def cmd_fields(cfg, a):
    """A table's populated fields (profiled live and cached on first use), or every cached table/field
    with a role."""
    fm = load_field_map(a.map, a.roles)
    tables = fm["tables"]
    if a.table:
        matches = [t for t in tables if t == a.table]
        if not matches and not a.map and cfg and (a.refresh or a.table in (cached_table_set() or {a.table})):
            prof = table_profile(cfg, a.table, refresh=a.refresh)  # first use, or --refresh: profile it live
            tables = cached_field_map()["tables"] or {a.table: prof}
            matches = [a.table]
        elif matches and a.refresh and not a.map and cfg:
            table_profile(cfg, a.table, refresh=True)
            tables = cached_field_map()["tables"]
        matches = matches or [t for t in tables if a.table in t]
        if not matches:
            raise DevoError(f"{a.table!r} is not in this domain's cached table list or field map",
                            "check the name with `devo.py tables --grep ...`", code=1)
        for t in matches:
            prof = tables[t]
            if a.role:
                prof = dict(prof, fields={k: v for k, v in prof["fields"].items() if v.get("role") == a.role}, empty=[])
            print_profile(t, prof, a.all, a.grep)
        return 0
    a.role = a.role or "ip"
    rx = re.compile(a.grep, re.I) if a.grep else None
    count = 0
    for t, prof in tables.items():
        if rx and not rx.search(t):
            continue
        hits = [(n, f) for n, f in prof["fields"].items() if f.get("role") == a.role and f["fill"] >= a.min_fill]
        if hits:
            count += 1
            print(f"{t}: " + ", ".join(f"{n} ({f['fill']:.0%}{', ' + f['case'] if f.get('case') else ''})"
                                         for n, f in hits))
    have = cached_table_set()
    gap = "" if a.map or have is None else f"; {len(tables)}/{len(have)} of the domain's tables are profiled"
    print(f"# {count} tables with populated {a.role!r} fields (from the cached field map{gap})", file=sys.stderr)
    if not a.map and (have is None or len(tables) < len(have)):
        cache_say("for a complete answer profile every table once: `devo.py cache build` (several minutes; run it "
                  "in the background)")
    return 0


# ---------------------------------------------------------------- event time / lag

EVENT_TIME = os.path.join(HINTS, "event-time.json")
_EVENT_TIME_CACHE = {}


def load_event_time(path=None):
    """The event-time families: the domain-verified copy from the cache when there is one, else the
    hints (references/hints/event-time.json) as shipped."""
    if path is None and CACHE:
        d = CACHE.get("event-time", allow_old=True)
        if d:
            return d
    path = path or EVENT_TIME
    if path not in _EVENT_TIME_CACHE:
        with open(path) as f:
            _EVENT_TIME_CACHE[path] = json.load(f)["families"]
    return _EVENT_TIME_CACHE[path]


def event_time_for(table, families=None):
    """The event-time family entry for a table (verified copy in the cache, else references/hints/event-time.json), or None."""
    for fam in families or load_event_time():
        if re.search(fam["tables"], table):
            return fam
    return None


def human_secs(s):
    if s is None:
        return "-"
    s = float(s)
    sign = "-" if s < 0 else ""
    s = abs(s)
    if s < 120:
        return f"{sign}{s:.0f}s"
    if s < 7200:
        return f"{sign}{s / 60:.0f}m"
    if s < 172800:
        return f"{sign}{s / 3600:.1f}h"
    return f"{sign}{s / 86400:.1f}d"


def weighted_pct(pairs, q):
    """q-th percentile (0-100) of values weighted by counts: pairs = [(value, weight)]."""
    pairs = sorted((v, w) for v, w in pairs if v is not None and w)
    total = sum(w for _, w in pairs)
    if not total:
        return None
    acc = 0
    for v, w in pairs:
        acc += w
        if acc >= total * q / 100:
            return v
    return pairs[-1][0]


def lag_query(table, fam, unit=1):
    """Hourly lag stats in `unit` seconds (60 when the per-second values overflow percentile())."""
    if fam and fam.get("linq"):
        return (f"from {quote_table(table)} select {fam['linq']} as event_time "
                f"select floor((epoch(eventdate) - epoch(event_time)) / {unit * 1000}) as lag "
                "where isnotnull(event_time) group every 1h "
                "select count() as n, percentile(lag, 50) as p50, percentile(lag, 95) as p95, "
                "max(event_time) as newest_event, max(eventdate) as newest_ingest")
    return f"from {quote_table(table)} group every 1h select count() as n, max(eventdate) as newest_ingest"


def lag_table(cfg, table, fam, frm_s, to_s, chunk, timeout):
    unit = 1
    linq = lag_query(table, fam, unit)
    try:
        columns, rows, _ = fetch(cfg, linq, frm_s, to_s, 0, timeout, chunk, 4)
    except DevoError as e:
        if "Maximum number of elements" not in str(e):
            raise
        unit = 60  # back-fill hours hold more distinct second values than percentile() accepts
        linq = lag_query(table, fam, unit)
        columns, rows, _ = fetch(cfg, linq, frm_s, to_s, 0, timeout, chunk, 4)
    hours = sorted(as_dicts(columns, rows), key=lambda h: h.get("eventdate") or "")
    for h in hours:
        for k in ("p50", "p95"):
            if h.get(k) is not None:
                h[k] = h[k] * unit
    has_et = bool(fam and fam.get("linq"))
    n = sum(h.get("n") or 0 for h in hours)
    out = {"table": table, "family": fam["family"] if fam else None, "event_time": fam["field"] if fam else None,
           "has_event_time": has_et, "resolution_s": unit, "query": linq, "rows": n, "hours_with_data": len(hours),
           "hours_in_window": (to_s - 1) // 3600 - frm_s // 3600 + 1, "hourly": hours,
           "newest_ingest": max((h["newest_ingest"] for h in hours if h.get("newest_ingest")), default=None)}
    if has_et:
        out["p50_s"] = weighted_pct([(h.get("p50"), h.get("n")) for h in hours], 50)
        out["p95_s"] = weighted_pct([(h.get("p95"), h.get("n")) for h in hours], 95)
        out["worst_hour_p95_s"] = max((h["p95"] for h in hours if h.get("p95") is not None), default=None)
        out["newest_event"] = max((h["newest_event"] for h in hours if h.get("newest_event")), default=None)
        last = hours[-1] if hours else {}
        out["latest_hour_p50_s"] = last.get("p50")
    return out


def profile_time_family(table):
    """An event-time family for a table the hints don't cover, from its cached field profile: the
    best-filled timestamp field (or ISO string) with the time role other than eventdate."""
    prof = CACHE.get(f"fields/{table}", allow_old=True) if CACHE else None
    if not prof:
        return None
    cands = [(k, f) for k, f in (prof.get("fields") or {}).items() if f.get("role") == "time" and k != "eventdate"
             and f.get("fill", 0) >= 0.9 and (f.get("type") == "timestamp" or "iso-time" in (f.get("patterns") or {}))
             and not re.search(r"ingest|received|collect|_local$", k, re.I)]
    if not cands:
        return None
    k, f = sorted(cands, key=lambda kv: (kv[1].get("type") != "timestamp", -kv[1].get("fill", 0)))[0]
    linq = k if f.get("type") == "timestamp" else f'timestamp(concat(substring({k}, 0, 19), "Z"))'
    return {"family": f"profile: {table}", "tables": re.escape(table), "linq": linq,
            "field": f"{k} (from the field profile; check it is the event time)", "dedupe": [], "lag": []}


def lag_sanity(r, fam):
    if fam and str(fam.get("family", "")).startswith("profile:"):
        note = f"time field from the profile: {fam.get('field', '?').split(' ')[0]}"
        if (r.get("p50_s") or 0) > 30 * 86400:
            return note + "; lag over 30 days is implausible: that field is probably not the event time"
        return note
    if (r.get("p50_s") or 0) > 30 * 86400:
        return "lag over 30 days: the event-time field is probably wrong for this table"
    return ""


def offset_note(r):
    """A lag that sits on a whole number of hours, the same every hour, is a sender's clock or time zone
    (local time stored as UTC), not ingestion delay."""
    p50, p95, worst = r.get("p50_s"), r.get("p95_s"), r.get("worst_hour_p95_s")
    for v, who in ((p50, "every sender"), (p95, "some senders")):
        if not v or v < 3000:
            continue
        h = round(v / 3600)
        steady = who == "every sender" or (worst and abs(worst - v) <= max(600, 0.05 * v))
        if h >= 1 and abs(v - h * 3600) <= 600 and steady:
            return (f"{'p50' if v is p50 else 'p95'} sits at ~{h}h every hour: {who} likely send local time as UTC "
                    "(clock/time-zone offset), not ingestion lag")
    return ""


def cmd_lag(cfg, a):
    """Ingestion lag per table, measured now: eventdate − event time, per hour of ingestion."""
    from concurrent.futures import ThreadPoolExecutor
    _, frm_s = resolve_time(a.from_)
    _, to_s = resolve_time(a.to)
    if to_s is not None:
        to_s = min(to_s, int(time.time()))  # Devo waits for a future `to` instead of returning
    if None in (frm_s, to_s) or frm_s >= to_s:
        raise DevoError("lag needs concrete --from/--to with from < to", code=1)
    fams = load_event_time()
    tables = list(dict.fromkeys(t for f in fams for t in f.get("lag", [])))
    have = cached_table_set()
    if have is not None:
        tables = [t for t in tables if t in have]
    if a.tables:
        rx = re.compile(a.tables, re.I)
        extra = [t for t in sorted(have or []) if rx.search(t) and t not in tables
                 and (event_time_for(t, fams) or profile_time_family(t))]
        skipped = [t for t in sorted(have or []) if rx.search(t) and t not in tables and t not in extra]
        if skipped:
            print(f"# lag: {len(skipped)} matching table(s) have no event-time expression and no profiled time field, "
                  f"so only ingestion freshness could be measured: {', '.join(skipped[:8])} (add them with --table to "
                  "see their newest ingest; `devo.py fields <t>` first lets the fallback find a time field)", file=sys.stderr)
        tables = [t for t in tables if rx.search(t)] + extra
    elif a.table:
        tables = []  # --table alone: just those
    if a.table:
        tables += [t for t in a.table if t not in tables]
    if not tables:
        raise DevoError("no tables selected", "the default set is the `lag` lists in references/hints/event-time.json "
                        "that exist in this domain; "
                        "add others with --table", code=1)
    chunk = a.chunk or ("6h" if to_s - frm_s <= 2 * 86400 else "1d")
    start = time.time()

    def one(t):
        try:
            return lag_table(cfg, t, event_time_for(t, fams) or profile_time_family(t), frm_s, to_s, chunk, a.timeout)
        except DevoError as e:
            return {"table": t, "error": str(e)}

    with ThreadPoolExecutor(max(1, a.parallel)) as pool:
        results = list(pool.map(one, tables))
    tz = get_tz(a.tz)
    now = int(time.time())
    if a.out:
        with open(a.out, "w") as f:
            json.dump({"window": [fmt_epoch(frm_s), fmt_epoch(to_s)], "measured": fmt_epoch(now),
                       "tables": results}, f, indent=1, ensure_ascii=False)
    rows = []
    for r in results:
        if r.get("error"):
            rows.append([r["table"], "", "", "", "", "", "", "", "", "ERROR " + r["error"]])
            continue
        loc = (lambda v: to_local(v, tz)[:16] if v and tz else (v or "")[:16])
        et = r.get("has_event_time")
        note = "" if et else "no event-time field: only ingestion is measurable"
        if et and (r.get("worst_hour_p95_s") or 0) > 6 * 3600:
            note = "batchy: some hours arrive much later (--hourly)"
        if et and r.get("latest_hour_p50_s") is not None and r.get("p50_s") is not None and \
                r["latest_hour_p50_s"] > max(3 * r["p50_s"], 1800):
            note = f"behind now: latest hour p50 {human_secs(r['latest_hour_p50_s'])}"
        if et and offset_note(r):
            note = offset_note(r)
        sane = lag_sanity(r, event_time_for(r["table"], fams) or profile_time_family(r["table"]))
        if sane:
            note = sane if "implausible" in sane or "wrong" in sane else (note + "; " + sane).strip("; ")
        if not r["rows"]:
            note = "no rows in the window"
        na = lambda k: human_secs(r.get(k)) if et else "n/a"
        rows.append([r["table"], r["rows"], na("p50_s"), na("p95_s"), na("worst_hour_p95_s"), na("latest_hour_p50_s"),
                     loc(r.get("newest_event")), loc(r.get("newest_ingest")),
                     f"{r['hours_with_data']}/{r['hours_in_window']}", note])
    cols = [("table", ""), ("rows", ""), ("p50 lag", ""), ("p95 lag", ""), ("worst hour p95", ""),
            ("latest hour p50", ""), ("newest event", ""), ("newest ingest", ""), ("hours", ""), ("note", "")]
    write_rows(sys.stdout, "table", cols, rows, a.width)
    if a.hourly:
        for r in results:
            if r.get("error") or not r.get("hourly"):
                continue
            print(f"\n{r['table']} (per hour of ingestion: rows, p50, p95, newest event)")
            for h in r["hourly"]:
                print(f"  {(to_local(h['eventdate'], tz) if tz else h['eventdate'])[:16]}  {h.get('n'):>9}  "
                      f"{human_secs(h.get('p50')):>6}  {human_secs(h.get('p95')):>6}  {(h.get('newest_event') or '')[:16]}")
    print(f"# lag = eventdate (ingestion) − event time, {fmt_epoch(frm_s)} → {fmt_epoch(to_s)} UTC "
          f"(chunks of {chunk}), measured {fmt_epoch(now)}, {time.time() - start:.0f}s. p50/p95 are row-weighted "
          f"percentiles of the hourly p50/p95 values. Times are {a.tz or 'UTC'}." +
          (f" Full detail in {a.out}" if a.out else ""), file=sys.stderr)
    return 0


# ---------------------------------------------------------------- batch

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
EXT = {"jsonl": "jsonl", "json": "json", "csv": "csv", "tsv": "tsv", "table": "txt"}


def load_spec(path):
    """Jobs from a JSON list, {"jobs": [...]}, or JSON Lines."""
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path) as f:
            text = f.read()
    try:
        obj = json.loads(text)
        jobs = (obj["jobs"] if "jobs" in obj else [obj]) if isinstance(obj, dict) else obj
    except ValueError:
        try:
            jobs = [json.loads(line) for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        except ValueError as e:
            raise DevoError(f"{path}: not JSON or JSON Lines ({e})", code=1)
    if not isinstance(jobs, list) or not all(isinstance(j, dict) for j in jobs):
        raise DevoError(f"{path}: expected a list of job objects", code=1)
    base = os.path.dirname(os.path.abspath(path)) if path != "-" else os.getcwd()
    for j in jobs:  # "query_file": a .linq file next to the spec, so LINQ quotes need no JSON escaping
        if "query_file" in j and "query" not in j:
            qp = os.path.join(base, os.path.expanduser(j["query_file"]))
            try:
                with open(qp) as f:
                    j["query"] = f.read()
            except OSError as e:
                raise DevoError(f"job {j.get('name')}: query_file {qp}: {e.strerror}", code=1)
    return jobs


def parse_vars(items):
    out = {}
    for item in items or []:
        for kv in split_top(item):
            if "=" not in kv:
                raise DevoError(f"--vars {kv!r}: use name=value", code=1)
            k, v = kv.split("=", 1)
            k = k.strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", k):
                raise DevoError(f"--vars: bad name {k!r}", code=1)
            if re.search(r'["\\\n]', v):
                raise DevoError(f"--vars {k}: values can't contain quotes, backslashes or newlines", code=1)
            out[k] = v.strip()
    return out


def substitute(value, variables):
    """Replace {name} for the given names only, so LINQ sets like {4624, 4625} are left alone."""
    if isinstance(value, str):
        return re.sub(r"\{([A-Za-z_]\w*)\}", lambda m: variables.get(m.group(1), m.group(0)), value)
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    return value


def run_job(cfg, job, out_dir, tz, defaults):
    """One batch job: query → <out-dir>/<name>.<ext> plus <name>.log. Returns its summary."""
    name = job["name"]
    fmt = job.get("format", "jsonl")
    path = os.path.join(out_dir, f"{name}.{EXT.get(fmt, 'txt')}")
    log = [f"# job {name}", f"# query: {job['query']}"]
    start = time.time()
    res = {"name": name, "rows": 0, "limit_reached": False, "error": None, "file": path}
    try:
        linq = re.sub(r"^(\s*from\s+)(\S+)", lambda m: m.group(1) + quote_table(m.group(2)), job["query"], count=1)
        _, frm_s = resolve_time(job.get("from", defaults["from"]))
        _, to_s = resolve_time(job.get("to", defaults["to"]))
        if None in (frm_s, to_s):
            raise DevoError("batch jobs need concrete from/to (e.g. 7d, today, ISO), not now() expressions", code=1)
        to_s = min(to_s, int(time.time()))
        if frm_s >= to_s:
            raise DevoError(f"from ({fmt_epoch(frm_s)}) must be before to ({fmt_epoch(to_s)})", code=1)
        limit = job.get("limit", defaults["limit"]) or None
        auto = job.get("auto_split")
        auto = default_auto_split(linq, limit) if auto is None else bool(auto)
        for table, missing in unknown_fields(linq, cfg):
            log.append(f"# pre-check: {', '.join(missing)} not in the cached schema of {table} (may fail)")
            res["precheck"] = f"not in {table}'s schema: {', '.join(missing)}"
        bad = reserved_aliases(linq)
        if bad:
            log.append(f"# pre-check: reserved word(s) used as alias: {', '.join(bad)}")
            res["precheck"] = (res.get("precheck", "") + f" reserved alias: {', '.join(bad)}").strip()
        columns, rows, info = fetch(cfg, linq, frm_s, to_s, limit, job.get("timeout", defaults["timeout"]),
                                    job.get("chunk"), int(job.get("parallel", 4)), True, auto,
                                    chunk_step(job.get("min_split", "5m")), partial=True)
        if info.get("failed"):
            res["partial"] = info["failed"]
            log.append(f"# PARTIAL: {len(info['failed'])} window(s) failed after retries: " + "; ".join(info["failed"][:3]))
        merge_note = None
        if is_grouped(linq) and (info["windows"] > 1 or info["splits"]) and job.get("merge", True):
            merged, merge_note = merge_grouped(linq, columns, rows)
            if merged is not None:
                rows = merged
            else:
                merge_note = f"grouped rows come back once per chunk and were NOT merged ({merge_note}): re-aggregate them"
        rows = round_approx(linq, columns, rows)
        heal_schema(unknown_fields(linq) if res.get("precheck") else [], columns)
        blank = empty_columns(columns, rows)
        if blank and len(blank) < len(columns):
            log.append(f"# note: {', '.join(blank[:8])} empty in all {len(rows)} rows (parser gap? check rawMessage)")
            res["precheck"] = (res.get("precheck", "") + f" empty columns: {', '.join(blank[:4])}").strip()
        types = [c[1] for c in columns]
        rows = [[convert_value(v, t) for v, t in zip(r, types)] for r in rows]
        if tz:
            columns, rows = add_local_columns(columns, rows, tz)
        with open(path, "w", newline="") as f:
            write_rows(f, fmt, columns, rows, 0)
        res.update(rows=len(rows), limit_reached=bool(info["full"]), splits=info["splits"],
                   range=[fmt_epoch(frm_s), fmt_epoch(to_s)])
        log.append(f"# {len(rows)} rows, {len(columns)} columns, range {fmt_epoch(frm_s)} → {fmt_epoch(to_s)} UTC"
                   + (f", {info['windows']} chunk(s) of {job['chunk']}" if job.get("chunk") else ""))
        note = limit_note(limit, info, auto)
        if note:
            log.append(note.strip())
        if merge_note:
            log.append(f"# {merge_note}")
    except DevoError as e:
        res["error"] = str(e)
        log.append(f"ERROR: {e}" + (f"\nhint: {e.hint}" if e.hint else ""))
    except (OSError, ValueError, TypeError) as e:  # one bad job must not lose the others' summary
        res["error"] = f"{type(e).__name__}: {e}"
        log.append(f"ERROR: {res['error']}")
    res["seconds"] = round(time.time() - start, 1)
    log.append(f"# {res['seconds']}s")
    with open(os.path.join(out_dir, f"{name}.log"), "w") as f:
        f.write("\n".join(log) + "\n")
    return res


def cmd_batch(cfg, a):
    """Run many queries from a spec file in parallel: one output file and one .log per job."""
    from concurrent.futures import ThreadPoolExecutor
    variables = parse_vars(a.vars)
    jobs = [substitute(j, variables) for j in load_spec(a.spec)]
    seen = set()
    for i, j in enumerate(jobs, 1):
        if not j.get("name") or not j.get("query"):
            raise DevoError(f"job {i}: needs `name` and `query`", code=1)
        if not SAFE_NAME.match(j["name"]):
            raise DevoError(f"job {i}: name {j['name']!r}: letters, digits, . _ - only (it is a file name)", code=1)
        if j["name"] in seen:
            raise DevoError(f"job {i}: duplicate name {j['name']!r}", code=1)
        seen.add(j["name"])
        if j.get("format", "jsonl") not in EXT:
            raise DevoError(f"job {j['name']}: format must be one of {', '.join(EXT)}", code=1)
        for k in ("limit", "parallel", "timeout"):
            if k in j and (not isinstance(j[k], int) or isinstance(j[k], bool) or j[k] < 0):
                raise DevoError(f"job {j['name']}: {k} must be a whole number (JSON number, not a string)", code=1)
        for k in ("query", "from", "to", "chunk", "min_split"):
            if k in j and not isinstance(j[k], str):
                raise DevoError(f"job {j['name']}: {k} must be a string", code=1)
        left = sorted(set(re.findall(r"\{([A-Za-z_]\w*)\}", json.dumps({k: j.get(k) for k in ("query", "from", "to")}))))
        if left:
            print(f"# warning: job {j['name']}: unreplaced placeholder(s) {', '.join(left)} (pass --vars)",
                  file=sys.stderr)
    out_dir = os.path.abspath(os.path.expanduser(a.out_dir))
    if os.path.commonpath([out_dir, SKILL_DIR]) == SKILL_DIR:
        raise DevoError("--out-dir must not be inside the skill directory (results hold personal data)", code=1)
    os.makedirs(out_dir, exist_ok=True)
    tz = get_tz(a.tz)
    defaults = {"from": a.from_, "to": a.to, "limit": a.limit, "timeout": a.timeout}
    start = time.time()
    with ThreadPoolExecutor(max(1, a.parallel)) as pool:
        results = list(pool.map(lambda j: run_job(cfg, j, out_dir, tz, defaults), jobs))
    tbl = {}
    for j, r in zip(jobs, results):
        m_t = re.match(r"\s*from\s+`?([A-Za-z0-9_.-]+)", j.get("query") or "")
        if m_t and r.get("range"):
            tbl.setdefault(m_t.group(1), []).append(r)
    gaps = {}
    if tbl:
        spans = [(parse_utc(r["range"][0]), parse_utc(r["range"][1])) for rs in tbl.values() for r in rs]
        f0 = int(min(x for x, _ in spans).timestamp())
        t0 = int(max(y for _, y in spans).timestamp())
        gaps = feed_gaps(cfg, list(tbl), f0, t0, a.timeout)
        for tname, lt in gaps.items():
            for r in tbl[tname]:
                r["feed_gap"] = lt
    with open(os.path.join(out_dir, "batch-summary.json"), "w") as f:
        json.dump({"spec": os.path.abspath(a.spec) if a.spec != "-" else "-", "vars": variables, "feed_gaps": gaps,
                   "seconds": round(time.time() - start), "jobs": results}, f, indent=1, ensure_ascii=False)
    rows = [[r["name"], r["rows"], "yes" if r["limit_reached"] else "no",
             " → ".join(x[:16] for x in r.get("range") or []),
             (r["error"] or "") + (f"  [pre-check: {r['precheck']}]" if r.get("precheck") else "")
             + (f"  [PARTIAL: {len(r['partial'])} window(s) failed]" if r.get("partial") else "")
             + (f"  [FEED GAP after {r['feed_gap'][:16]}]" if r.get("feed_gap") else ""), f"{r['seconds']}s"]
            for r in results]
    write_rows(sys.stdout, "table", [("name", ""), ("rows", ""), ("limit reached", ""), ("range (UTC)", ""),
                                     ("error", ""), ("duration", "")], rows, a.width)
    bad = [r for r in results if r["error"]]
    print(f"# {len(results)} jobs, {len(bad)} failed, {time.time() - start:.0f}s; outputs, .log files and "
          f"batch-summary.json in {out_dir}", file=sys.stderr)
    return 2 if bad else 0


# ---------------------------------------------------------------- timeline

AGG_KEYS = {"n", "first", "last", "first_event", "last_event"}
NOT_DETAIL = AGG_KEYS | {"eventdate", "event_time", "message", "rawMessage", "Message", "extraData"}


def field_roles(table, fm):
    """{field: role} for a table: the field map's (curated) roles, else a guess from the name."""
    known = {k: v.get("role") for k, v in ((fm.get("tables", {}).get(table) or {}).get("fields") or {}).items()}

    def role(name):
        if name in known:
            return known[name]
        return guess_role(name, "str", set())
    return role


def record_time(rec, fam):
    """(event time, basis) for one activity record: event_time / first_event, the family's field,
    Microsoft 365 CreationTime inside message, else eventdate/first (ingestion)."""
    for k in ("event_time", "first_event"):
        if rec.get(k):
            return parse_utc(rec[k]), "event"
    if fam and fam.get("linq"):
        col = fam["linq"] if re.fullmatch(r"\w+", fam["linq"]) else None
        if col and rec.get(col):
            return parse_utc(rec[col]), "event"
        for raw in ("message", "rawMessage"):
            if isinstance(rec.get(raw), str) and '"CreationTime"' in rec[raw]:
                try:
                    return parse_utc(json.loads(rec[raw]).get("CreationTime")), "event"
                except ValueError:
                    pass
    for k in ("eventdate", "first"):
        if rec.get(k):
            return parse_utc(rec[k]), "ingest"
    return None, None


def normalise(rec, source, table, fam, role):
    t, basis = record_time(rec, fam)
    if not t:
        return None
    ev = {"t_utc": iso_utc(t), "source": source, "table": table, "actor": None, "action": None, "target": None,
          "ip": None, "host": None, "detail": None, "time_basis": basis}
    if "n" in rec:
        ev["count"] = rec.get("n")
        last = parse_utc(rec.get("last_event") or rec.get("last"))
        if last and last != t:
            ev["t_last_utc"] = iso_utc(last)
    slots = {"user": "actor", "action": "action", "ip": "ip", "host": "host", "url/domain": "target",
             "process/file": "target"}
    rest = []
    for k, v in rec.items():
        if k in NOT_DETAIL or k.endswith("_local") or v in (None, "", [], {}):
            continue
        slot = slots.get(role(k))
        sv = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        if slot and ev[slot] is None:
            ev[slot] = sv.strip('"')
        else:
            rest.append(f"{k}={sv}")
    if ev["action"] is None and rec.get("Operation"):
        ev["action"] = rec["Operation"]
    ev["detail"] = cell("; ".join(rest), 300) or None
    return ev


def dedupe_key(rec, fam, table):
    """A record id for raw rows of tables that ingest the same record more than once, else None."""
    keys = (fam or {}).get("dedupe") or []
    if keys and all(rec.get(k) not in (None, "") for k in keys):
        return (table,) + tuple(str(rec[k]) for k in keys)
    if table.startswith("cloud.office365.") and isinstance(rec.get("message"), str):
        m = re.search(r'"Id"\s*:\s*"([^"]+)"', rec["message"])
        if m:
            return (table, m.group(1))
    return None


def build_timeline(act_dir, tz=None, fm=None, families=None):
    """Merge an `activity` --out-dir into one sorted event list. Returns (events, notes, summary)."""
    with open(os.path.join(act_dir, "summary.json")) as f:
        summary = json.load(f)
    try:
        fm = fm if fm is not None else load_field_map()
    except (OSError, ValueError):
        fm = {"tables": {}}
    events, notes, seen, dropped = [], [], set(), {}
    for src in summary["sources"]:
        if src.get("error") or src.get("duplicate_of"):
            continue
        path = src.get("file") or f"{src['source']}.jsonl"
        if not os.path.exists(path):  # the directory was moved or copied: look next to summary.json
            path = os.path.join(act_dir, os.path.basename(path))
        if not os.path.exists(path):
            if src.get("rows"):
                notes.append(f"{src['source']}: {os.path.basename(path)} is missing from {act_dir}")
            continue
        table, fam = src["table"], event_time_for(src["table"], families)
        role = field_roles(table, fm)
        basis = set()
        recs = list(_read_jsonl(path))
        # Where Entra audit is fed by two collectors, one copy has tenantId, the other null or "-". Drop the
        # tenant-less copies only when tenant-filled ones exist (a single-collector domain keeps all).
        two_copies = table == "cloud.azure.ad.audit" and any(r.get("tenantId") not in (None, "", "-") for r in recs)
        for rec in recs:
            if two_copies and "tenantId" in rec and rec.get("tenantId") in (None, "", "-"):
                dropped[src["source"]] = dropped.get(src["source"], 0) + 1  # the second copy of each audit event
                continue
            if "n" not in rec:
                k = dedupe_key(rec, fam, table)
                if k is not None:
                    if k in seen:
                        dropped[src["source"]] = dropped.get(src["source"], 0) + 1
                        continue
                    seen.add(k)
            ev = normalise(rec, src["source"], table, fam, role)
            if ev:
                ev["attribution"] = src.get("attribution") or "direct"
                subj = str(rec.get("SubjectUserName") or "")
                if ev["attribution"] == "direct" and subj.endswith("$"):
                    ev["attribution"] = "target"  # a machine account acting on the user (e.g. 4798 enumeration)
                if tz:
                    ev["t_local"] = to_local(ev["t_utc"], tz)
                basis.add(ev["time_basis"])
                events.append(ev)
        if "ingest" in basis and fam and fam.get("linq"):
            notes.append(f"{src['source']}: some times are ingestion time (eventdate); re-run activity to get "
                         f"event times ({fam['field']})")
        elif "ingest" in basis:
            notes.append(f"{src['source']}: no event-time field in {table}: times are ingestion (eventdate)")
        if src.get("mode") != "rows" and src.get("rows") and table.startswith(("cloud.office365.management.sharepoint",
                                                                               "cloud.office365.management.onedrive")):
            notes.append(f"{src['source']}: grouped counts include SharePoint/OneDrive back-fill duplicates; "
                         "use activity --rows for de-duplicated events")
    for s, n in sorted(dropped.items()):
        notes.append(f"{s}: dropped {n} duplicate record(s)")
    events.sort(key=lambda e: (e["t_utc"], e["source"]))
    return events, notes, summary


def day_summary(events, tz):
    """Compact per-day text: count, first-last, top sources and actions (local days when --tz)."""
    days, spread = {}, 0
    for e in events:
        t = e.get("t_local") or e["t_utc"]
        c = e.get("count") or 1
        t_end = e.get("t_last_utc")
        if t_end and tz:
            t_end = to_local(t_end, tz)
        span = [t[:10]]
        if t_end and t_end[:10] == t[:10]:
            d0 = days.setdefault(t[:10], {"n": 0, "first": t, "last": t, "src": {}, "act": {}, "attr": {}})
            d0["last"] = max(d0["last"], t_end)
        if t_end and t_end[:10] > t[:10]:  # a grouped row covering several days: spread its count over them
            d0, d1 = dt.date.fromisoformat(t[:10]), dt.date.fromisoformat(t_end[:10])
            span = [(d0 + dt.timedelta(days=i)).isoformat() for i in range((d1 - d0).days + 1)]
            spread += 1
        for i, day in enumerate(span):
            share = c // len(span) + (1 if i < c % len(span) else 0)
            stamp = t if i == 0 else (t_end if i == len(span) - 1 else day + "T12:00")
            d = days.setdefault(day, {"n": 0, "first": stamp, "last": stamp, "src": {}, "act": {}, "attr": {}})
            d["n"] += share
            at = e.get("attribution") or "direct"
            d["attr"][at] = d["attr"].get(at, 0) + share
            d["first"], d["last"] = min(d["first"], stamp), max(d["last"], stamp)
            d["src"][e["source"]] = d["src"].get(e["source"], 0) + share
            if e.get("action"):
                d["act"][e["action"]] = d["act"].get(e["action"], 0) + share
    lines = []
    for day in sorted(days):
        d = days[day]
        wd = dt.date.fromisoformat(day).strftime("%a")
        top = lambda m, k: ", ".join(f"{x} {n}" for x, n in sorted(m.items(), key=lambda kv: -kv[1])[:k])
        other = ", ".join(f"{k} {v}" for k, v in sorted(d["attr"].items()) if k != "direct")
        lines.append(f"{day} {wd}: {d['attr'].get('direct', 0)} direct events" + (f" (+ {other})" if other else "")
                     + f" {d['first'][11:16]}–{d['last'][11:16]}"
                     f" | sources: {top(d['src'], 6)} | actions: {top(d['act'], 5)}")
    if any(k != "direct" for d in days.values() for k in d["attr"]):
        lines.append("(direct = the account is the actor in a parsed field; target = changes made to the account by "
                     "others or by sync/automation; automated = token refreshes, scheduled jobs, integrations using the "
                     "account; raw-text = the term only appears in raw text such as a script header: check before "
                     "calling it the person's activity)")
    if spread:
        lines.append(f"(counts of {spread} grouped row(s) spanning several days are spread evenly over their "
                     "first..last day: approximate per-day totals; run the sweep with --rows for exact ones)")
    return "\n".join(lines) + ("\n" if lines else "")


def cmd_timeline(cfg, a):
    """Merge an `activity` output directory into one timeline (JSON) plus a per-day text summary."""
    act_dir = os.path.abspath(os.path.expanduser(a.dir))
    if not os.path.exists(os.path.join(act_dir, "summary.json")):
        raise DevoError(f"{act_dir} has no summary.json", "point it at an `activity --out-dir` directory", code=1)
    tz = get_tz(a.tz)
    events, notes, summary = build_timeline(act_dir, tz)
    for tname, last in sorted((summary.get("feed_gaps") or {}).items()):
        notes.append(f"FEED GAP: {tname} received nothing after {last[:16]}: absence after that is not 'no activity'")
    w0 = (summary.get("window") or [None])[0]
    if w0 and re.match(r"\d{4}-\d\d-\d\d", str(w0)) and not a.keep_outside:  # back-filled records: ingested inside the window, but the event is older
        before = [e for e in events if (e.get("t_utc") or "") < w0[:19]]
        if before:
            events = [e for e in events if e not in before]
            by_src = {}
            for e in before:
                by_src[e["source"]] = by_src.get(e["source"], 0) + 1
            notes.append(f"dropped {len(before)} event(s) whose event time is before the window ({w0}): back-filled "
                         "records ingested inside it (" + ", ".join(f"{k} {v}" for k, v in sorted(by_src.items())) +
                         "); --keep-outside keeps them")
    text = day_summary(events, tz)
    out = a.out or os.path.join(act_dir, "timeline.json")
    with open(out, "w") as f:
        json.dump({"terms": summary.get("terms") or [summary.get("term")], "window": summary.get("window"),
                   "tz": a.tz or "UTC", "events": events, "notes": notes}, f, indent=1, ensure_ascii=False)
    txt = re.sub(r"\.json$", "", out) + ".txt"
    with open(txt, "w") as f:
        f.write(text)
    sys.stdout.write(text)
    for n in notes:
        print(f"# {n}", file=sys.stderr)
    print(f"# {len(events)} events from {len({e['source'] for e in events})} sources → {out} (+ {txt}); "
          f"days are {a.tz or 'UTC'}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- teams

TEAMS_TABLE = "cloud.office365.management.microsoftteams"
TEAMS_APP_OPS = {"MessagesListed", "MessagesExported", "MessageCreatedNotification", "ChatRetrieved",
                 "AppCleanedUpAfterExpiration", "MessageUpdatedNotification"}  # app/backup reads, not people
SENT_OPS = {"MessageSent", "MessageCreatedHasLink"}
EDIT_OPS = {"MessageUpdated", "MessageEditedHasLink"}
MEETING_OPS = {"MeetingDetail", "MeetingParticipantDetail", "CallParticipantDetail"}
THREAD_ID = re.compile(r"^19:[A-Za-z0-9_.@:=+/-]+$")
ONE_ON_ONE = re.compile(r"^19:([0-9a-f-]{36})_([0-9a-f-]{36})@unq\.gbl\.spaces$", re.I)
TEAMS_INTERNAL_HOST = re.compile(r"(^|\.)(skype\.com|teams\.microsoft\.com|office\.net|teams\.cloud\.microsoft)$", re.I)
CONV_TYPES = {"OneOnOne": "1:1", "GroupChat": "group", "Meeting": "meeting", "Channel": "channel"}
TEAMS_SLACK = 86400  # meeting records are created hours after the meeting: search ingestion this much past --to


def linq_set(values):
    return "{" + ", ".join(f'"{v}"' for v in sorted(values)) + "}"


def teams_select(where, extra=""):
    return (f"from {TEAMS_TABLE} where Operation not in {linq_set(TEAMS_APP_OPS)}{extra}, {where} "
            "select eventdate, Operation, UserId, UserKey, message")


def teams_pull(cfg, linq, frm_s, to_s, timeout):
    """Raw Teams records for a query (one dict per record, message parsed)."""
    columns, rows, info = fetch(cfg, linq, frm_s, to_s, 20000, timeout, "1d", 4, auto_split=True)
    out = []
    for r in as_dicts(columns, rows):
        try:
            m = json.loads(r.get("message") or "{}")
        except ValueError:
            continue
        m.setdefault("UserId", r.get("UserId"))
        m.setdefault("Operation", r.get("Operation"))
        m["_eventdate"] = r.get("eventdate")
        out.append(m)
    return out, info


def thread_of(m):
    return m.get("ChatThreadId") or m.get("ChannelGuid") or None


def conv_type(m, tid):
    t = CONV_TYPES.get(m.get("CommunicationType") or "")
    if t:
        return t
    if ONE_ON_ONE.match(tid or ""):
        return "1:1"
    if "meeting_" in (tid or ""):
        return "meeting"
    if (tid or "").endswith("@thread.tacv2"):
        return "channel"
    return "group"


def teams_time(m):
    """The record's own time: JoinTime for participants, StartTime for meetings, else CreationTime."""
    op = m.get("Operation")
    if op in ("MeetingParticipantDetail", "CallParticipantDetail"):
        return parse_utc(m.get("JoinTime")) or parse_utc(m.get("CreationTime"))
    if op == "MeetingDetail":
        return parse_utc(m.get("StartTime")) or parse_utc(m.get("CreationTime"))
    return parse_utc(m.get("CreationTime"))


def msg_links(m):
    """(files, links) of a message: files from MessageFiles (URL-decoded = SharePoint/OneDrive ObjectId);
    links from MessageLinks plus MessageURLs that are neither files nor Teams-internal (images, emoji)."""
    files = [urllib.parse.unquote(f.get("FileUrl") or "") for f in m.get("MessageFiles") or [] if f.get("FileUrl")]
    raw_files = {f.get("FileUrl") for f in m.get("MessageFiles") or []}
    links = [x.get("Url") for x in m.get("MessageLinks") or [] if x.get("Url")]
    for u in m.get("MessageURLs") or []:
        if not isinstance(u, str) or u in raw_files or urllib.parse.unquote(u) in files or u in links:
            continue
        host = urllib.parse.urlparse(u).hostname or ""
        if not TEAMS_INTERNAL_HOST.search(host):
            links.append(u)
    return list(dict.fromkeys(files)), list(dict.fromkeys(links))


def teams_resolve(cfg, term, frm_s, to_s, timeout):
    """[(upn, object id, rows)] of Teams actors whose UserId contains the term."""
    linq = f'from {TEAMS_TABLE} where weakhas(UserId, "{term}") group by UserId, UserKey select count() as n'
    columns, rows, _ = fetch(cfg, linq, frm_s, to_s, 0, timeout, "7d", 4)
    acc = {}
    for r in as_dicts(columns, rows):
        upn, oid = (r.get("UserId") or "").lower(), (r.get("UserKey") or "").lower()
        if "@" not in upn or not GUID.match(oid):
            continue
        if "@" in term and upn != term.lower():
            continue
        acc[(upn, oid)] = acc.get((upn, oid), 0) + (r.get("n") or 0)
    return [(u, o, n) for (u, o), n in sorted(acc.items(), key=lambda kv: -kv[1])]


def teams_oid_names(cfg, oids, to_s, timeout):
    """object id -> UPN through any Teams record the id acted in (30 days before --to)."""
    out = {}
    oids = sorted(o for o in oids if GUID.match(o))[:300]
    for i in range(0, len(oids), 60):
        linq = (f"from {TEAMS_TABLE} where UserKey in {linq_set(oids[i:i + 60])} group by UserKey, UserId "
                "select count() as n")
        columns, rows, _ = fetch(cfg, linq, to_s - 30 * 86400, to_s, 0, timeout, "10d", 3)
        for r in as_dicts(columns, rows):
            if "@" in (r.get("UserId") or ""):
                out[r["UserKey"].lower()] = r["UserId"].lower()
    return out


def build_teams(records, subject_oids, subject_upns, frm_s, to_s, tz, names):
    """Normalised conversations, meetings, calls and daily counts from raw Teams records."""
    me = lambda m: (m.get("UserKey") or "").lower() in subject_oids or (m.get("UserId") or "").lower() in subject_upns
    loc = lambda d: d.astimezone(tz).isoformat(timespec="seconds") if tz and d else None
    name = lambda oid: names.get((oid or "").lower())
    seen, convs, meetings, calls, shares = set(), {}, {}, {}, []
    daily = {}

    def day(d):
        k = (d.astimezone(tz) if tz else d).strftime("%Y-%m-%d")
        return daily.setdefault(k, {"sent": 0, "edits": 0, "reactions": 0, "files": 0, "links": 0,
                                    "meeting_joins": 0, "call_joins": 0, "conversations": set()})

    for m in records:
        rid = m.get("Id")
        if rid in seen:
            continue
        seen.add(rid)
        t = teams_time(m)
        if not t or not (frm_s <= t.timestamp() < to_s):
            continue
        op = m.get("Operation")
        actor = (m.get("UserId") or "").lower() or None
        if op in MEETING_OPS:
            if op == "MeetingDetail":
                mt = meetings.setdefault(m.get("Id"), {"meeting_detail_id": m.get("Id"), "participants": {}})
                org = (m.get("Organizer") or {}).get("UserObjectId")
                mt.update({"thread_id": m.get("ChatThreadId"), "kind": m.get("CommunicationSubType"),
                           "organizer": name(org) or actor or org,
                           "start_utc": iso_utc(parse_utc(m.get("StartTime"))),
                           "end_utc": iso_utc(parse_utc(m.get("EndTime"))),
                           "modalities": m.get("Modalities"),
                           "artifacts": [{"name": x.get("ArtifactSharedName"),
                                          "sessions": [[s.get("StartTimestamp"), s.get("EndTimestamp")]
                                                       for s in x.get("ArtifactShareSessions") or []]}
                                         for x in m.get("ArtifactsShared") or []]})
                if tz:
                    mt["start_local"], mt["end_local"] = loc(parse_utc(m.get("StartTime"))), loc(parse_utc(m.get("EndTime")))
                continue
            att = (m.get("Attendees") or [{}])[0]
            who = (att.get("UPN") or name(att.get("UserObjectId")) or att.get("DisplayName") or
                   att.get("UserObjectId") or "?")
            is_me = (att.get("UserObjectId") or "").lower() in subject_oids or (att.get("UPN") or "").lower() in subject_upns
            key = m.get("MeetingDetailId") if op == "MeetingParticipantDetail" else m.get("CallId")
            box = meetings if op == "MeetingParticipantDetail" else calls
            ent = box.setdefault(key, {("meeting_detail_id" if box is meetings else "call_id"): key, "participants": {}})
            if box is meetings:
                ent.setdefault("thread_id", m.get("ChatThreadId"))
            else:
                ent.setdefault("kind", m.get("ItemName"))
            p = ent["participants"].setdefault(who.lower() if "@" in who else who, {
                "who": who, "role": att.get("Role"), "guest": att.get("IsAADGuest"), "subject": is_me, "sessions": []})
            sess = {"join_utc": iso_utc(parse_utc(m.get("JoinTime"))), "leave_utc": iso_utc(parse_utc(m.get("LeaveTime"))),
                    "device": m.get("DeviceInformation"),
                    "shared": [x.get("ArtifactSharedName") for x in m.get("ArtifactsShared") or []]}
            if tz:
                sess["join_local"], sess["leave_local"] = loc(parse_utc(m.get("JoinTime"))), loc(parse_utc(m.get("LeaveTime")))
            p["sessions"].append(sess)
            if is_me:
                day(t)["meeting_joins" if box is meetings else "call_joins"] += 1
            continue
        tid = thread_of(m)
        if not tid:
            continue
        c = convs.setdefault(tid, {"id": tid, "type": conv_type(m, tid), "name": None, "parties": set(),
                                   "subject": {"sent": set(), "edits": set(), "reactions": 0, "files": [], "links": []},
                                   "others": {"sent": set(), "edits": set(), "reactions": 0, "files": 0, "links": 0},
                                   "members": [], "first": t, "last": t})
        if c["type"] == "group" and m.get("CommunicationType"):
            c["type"] = conv_type(m, tid)
        c["name"] = c["name"] or m.get("ChatName") or (f"{m.get('TeamName')} / {m.get('ChannelName')}"
                                                       if m.get("ChannelName") else None)
        c["first"], c["last"] = min(c["first"], t), max(c["last"], t)
        mine = me(m)
        if actor and not mine:
            c["parties"].add(actor)
        bucket = c["subject"] if mine else c["others"]
        msg = (m.get("MessageId"), m.get("MessageVersion"))
        if op in SENT_OPS:
            new = msg[0] not in bucket["sent"]
            bucket["sent"].add(msg[0])
            if mine and new:
                day(t)["sent"] += 1
        elif op in EDIT_OPS:
            bucket["edits"].add(msg)
            if mine:
                day(t)["edits"] += 1
        elif op == "ReactedToMessage":
            bucket["reactions"] += 1
            if mine:
                day(t)["reactions"] += 1
        elif op in ("MemberAdded", "MemberRemoved", "ChatCreated"):
            ms = [x.get("UPN") or x.get("DisplayName") for x in m.get("Members") or []]
            c["members"].append({"t_utc": iso_utc(t), "op": op, "by": actor, "members": ms})
            c["parties"].update(x.lower() for x in ms if x and "@" in x and x.lower() not in subject_upns)
        files, links = msg_links(m)
        if files or links:
            for kind, urls in (("file", files), ("link", links)):
                for u in urls:
                    shares.append({"t_utc": iso_utc(t), "t_local": loc(t), "by": actor, "kind": kind, "url": u,
                                   "conversation": tid, "op": op})
            if mine:
                bucket["files"].extend(files)
                bucket["links"].extend(links)
                day(t)["files"] += len(files)
                day(t)["links"] += len(links)
            else:
                bucket["files"] += len(files)
                bucket["links"] += len(links)
        if mine:
            day(t)["conversations"].add(tid)
    # 1:1 threads name both parties in the id; an id we can't resolve (a user in another tenant has a
    # different object id there) is left out when the other party is already seen acting in the thread
    for tid, c in convs.items():
        mt = ONE_ON_ONE.match(tid)
        if mt:
            for oid in (x.lower() for x in mt.groups()):
                if oid not in subject_oids and (name(oid) or not c["parties"]):
                    c["parties"].add(name(oid) or oid)
    # meeting chats: attendees are parties
    for mt in meetings.values():
        c = convs.get(mt.get("thread_id"))
        if c:
            c["parties"].update(k for k, p in mt["participants"].items() if not p["subject"])
    conv_out = []
    for c in convs.values():
        s, o = c["subject"], c["others"]
        parties = {name(p) or p for p in c["parties"] if p}
        unresolved = {p for p in parties if GUID.match(p)}
        if c["type"] == "1:1" and parties - unresolved:
            parties -= unresolved  # the other party is known by UPN; the id is their home-tenant id
        item = {"id": c["id"], "type": c["type"], "name": c["name"],
                "parties": sorted(parties), "unresolved_parties": sorted(unresolved),
                "subject": {"sent": len(s["sent"]), "edits": len(s["edits"]), "reactions": s["reactions"],
                            "files": sorted(set(s["files"])), "links": sorted(set(s["links"]))},
                "others": {"sent": len(o["sent"]), "edits": len(o["edits"]), "reactions": o["reactions"],
                           "files": o["files"], "links": o["links"]},
                "first_utc": iso_utc(c["first"]), "last_utc": iso_utc(c["last"]), "membership_changes": c["members"]}
        if tz:
            item["first_local"], item["last_local"] = loc(c["first"]), loc(c["last"])
        conv_out.append(item)
    conv_out.sort(key=lambda c: (-(c["subject"]["sent"] + c["others"]["sent"]), c["first_utc"]))

    def finish(box):
        out = []
        for v in box.values():
            v = dict(v)
            v["participants"] = sorted(v["participants"].values(),
                                       key=lambda p: min((s["join_utc"] or "") for s in p["sessions"]))
            joins = [s["join_utc"] for p in v["participants"] for s in p["sessions"] if s["join_utc"]]
            if box is meetings and "start_utc" not in v:
                v["detail_record"] = False  # no MeetingDetail in the window: start = first join
            v.setdefault("start_utc", min(joins) if joins else None)
            out.append(v)
        return sorted(out, key=lambda v: v.get("start_utc") or "")
    days = [dict(v, date=k, conversations=len(v["conversations"])) for k, v in sorted(daily.items())]
    return {"conversations": conv_out, "meetings": finish(meetings), "calls": finish(calls),
            "shares": sorted(shares, key=lambda x: x["t_utc"]), "daily": days}


def cmd_teams(cfg, a):
    """Reconstruct a user's (or one conversation's) Teams activity into normalised JSON."""
    from concurrent.futures import ThreadPoolExecutor
    tz = get_tz(a.tz)
    _, frm_s = resolve_time(a.from_)
    _, to_s = resolve_time(a.to)
    if None in (frm_s, to_s) or frm_s >= to_s:
        raise DevoError("teams needs concrete --from/--to with from < to", code=1)
    now = int(time.time())
    to_s = min(to_s, now)  # Devo waits for a future `to` instead of returning
    if frm_s >= to_s:
        raise DevoError("teams: --from is in the future", code=1)
    ing_to = min(now, to_s + TEAMS_SLACK)
    out_path = os.path.abspath(os.path.expanduser(a.out))
    if os.path.commonpath([out_path, SKILL_DIR]) == SKILL_DIR:
        raise DevoError("--out must not be inside the skill directory (results hold personal data)", code=1)
    queries, notes = [], []
    start = time.time()
    subject = a.subject.strip()
    if subject.startswith("19:"):
        if not THREAD_ID.match(subject):
            raise DevoError(f"{subject!r} doesn't look like a Teams thread id", code=1)
        oids, upns, accounts = set(), set(), []
        threads, mdids, call_ids = {subject}, set(), set()
        base = []
    else:
        term = linq_term(subject, "user")
        accounts = teams_resolve(cfg, term, frm_s - 7 * 86400, ing_to, a.timeout)
        if not accounts:
            raise DevoError(f"no Teams activity by a UserId containing {term!r} between "
                            f"{fmt_epoch(frm_s - 7 * 86400)} and {fmt_epoch(ing_to)}",
                            "check the spelling; a user who never acted in Teams can still be in 1:1 chats: "
                            "pass their 1:1 thread id instead", code=1)
        if len({o for _, o, _ in accounts}) > 1 and not a.all_matches:
            raise DevoError(f"{term!r} matches {len(accounts)} accounts: " +
                            ", ".join(f"{u} ({n} rows)" for u, _, n in accounts[:10]),
                            "pass the full UPN (same display names exist across tenant domains), or --all-matches",
                            code=1)
        oids = {o for _, o, _ in accounts}
        upns = {u for u, _, _ in accounts}
        cond = " or ".join([f'message -> "{o}"' for o in sorted(oids)] + [f'weakhas(message, "{u}")' for u in sorted(upns)])
        linq = teams_select(f"({cond})")
        queries.append(linq)
        base, info = teams_pull(cfg, linq, frm_s, ing_to, a.timeout)
        if info["full"]:
            notes.append("the subject's main query still hit the row limit after splitting: some conversations "
                         "may be missing")
        threads, mdids, call_ids = set(), set(), set()
        for m in base:
            t = teams_time(m)
            if not t or not (frm_s <= t.timestamp() < to_s + TEAMS_SLACK):
                continue
            op = m.get("Operation")
            mine = (m.get("UserKey") or "").lower() in oids
            att = (m.get("Attendees") or [{}])[0]
            attended = (att.get("UserObjectId") or "").lower() in oids or (att.get("UPN") or "").lower() in upns
            org = ((m.get("Organizer") or {}).get("UserObjectId") or "").lower() in oids
            if op == "MeetingParticipantDetail" and (attended or org):
                mdids.add(m.get("MeetingDetailId"))
                if m.get("ChatThreadId") and attended:
                    threads.add(m["ChatThreadId"])
            elif op == "CallParticipantDetail" and attended:
                call_ids.add(m.get("CallId"))
            elif op == "MeetingDetail" and (mine or org):
                mdids.add(m.get("Id"))
            elif m.get("ChatThreadId"):
                tid = m["ChatThreadId"]
                members = {(x.get("UPN") or "").lower() for x in m.get("Members") or []}
                if mine or ONE_ON_ONE.match(tid) and any(o in tid.lower() for o in oids) or members & upns:
                    threads.add(tid)
    bad = {t for t in threads if not THREAD_ID.match(t)}
    if bad:
        notes.append(f"{len(bad)} thread id(s) with unexpected characters skipped")
    threads = sorted(threads - bad)
    mdids = sorted(x for x in mdids if x and GUID.match(x))
    call_ids = sorted(x for x in call_ids if x and GUID.match(x))
    jobs = []
    channels = [t for t in threads if t.endswith("@thread.tacv2")] if subject.startswith("19:") else []
    threads = [t for t in threads if t not in channels]
    for ch in channels:
        jobs.append(teams_select(f'ChannelGuid = "{ch}"'))
    for i in range(0, len(threads), 40):
        part = threads[i:i + 40]
        jobs.append(f"from {TEAMS_TABLE} where Operation not in {linq_set(TEAMS_APP_OPS | MEETING_OPS)} "
                    f"select str(jsonparse(message)[\"ChatThreadId\"]) as chat_id where chat_id in {linq_set(part)} "
                    "select eventdate, Operation, UserId, UserKey, message")
    conds = []
    if mdids:
        conds += [f"mdid in {linq_set(mdids)}", f"Id in {linq_set(mdids)}"]
    if call_ids:
        conds.append(f"call_id in {linq_set(call_ids)}")
    if subject.startswith("19:"):
        conds.append(f'mt_thread = "{subject}"')
    if conds:
        jobs.append(f"from {TEAMS_TABLE} where Operation in {linq_set(MEETING_OPS)} "
                    "select str(jsonparse(message)[\"MeetingDetailId\"]) as mdid, "
                    "str(jsonparse(message)[\"CallId\"]) as call_id, "
                    "str(jsonparse(message)[\"ChatThreadId\"]) as mt_thread "
                    f"where {' or '.join(conds)} select eventdate, Operation, UserId, UserKey, message")
    queries += jobs
    with ThreadPoolExecutor(4) as pool:
        pulled = list(pool.map(lambda q: teams_pull(cfg, q, frm_s, ing_to, a.timeout), jobs))
    records = list(base)
    for recs, info in pulled:
        records.extend(recs)
        if info["full"]:
            notes.append("some windows still hit the row limit after splitting: counts may be incomplete")
    # channel threads: only the subject's own rows (team channels are busy and not "their" conversation)
    if oids:
        records = [m for m in records if not (m.get("ChannelGuid") and not m.get("ChatThreadId")) or
                   (m.get("UserKey") or "").lower() in oids]
    names = {}
    for m in records:
        if "@" in (m.get("UserId") or "") and GUID.match((m.get("UserKey") or "")):
            names[m["UserKey"].lower()] = m["UserId"].lower()
        for att in m.get("Attendees") or []:
            if att.get("UPN") and att.get("UserObjectId"):
                names[att["UserObjectId"].lower()] = att["UPN"].lower()
    want = set()
    for m in records:
        mt = ONE_ON_ONE.match(m.get("ChatThreadId") or "")
        if mt:
            want.update(x.lower() for x in mt.groups())
        org = (m.get("Organizer") or {}).get("UserObjectId")
        if org:
            want.add(org.lower())
    want -= set(names)
    if want:
        names.update(teams_oid_names(cfg, want, to_s, a.timeout))
    model = build_teams(records, oids, upns, frm_s, to_s, tz, names)
    model.update({"subject": {"input": subject, "upns": sorted(upns), "object_ids": sorted(oids)},
                  "window_utc": [fmt_epoch(frm_s), fmt_epoch(to_s)], "tz": a.tz or "UTC",
                  "time_basis": "event time: CreationTime for messages, JoinTime/LeaveTime and StartTime/EndTime "
                                "for meetings and calls (never eventdate)",
                  "queries": queries, "notes": notes + [
                      "message text is never logged; links come from MessageLinks/MessageURLs and appear (almost) "
                      "only on MessageCreatedHasLink/MessageEditedHasLink rows",
                      "channel conversations count only the subject's own posts" if oids else
                      "per-actor counts are under each conversation's subject/others (no subject in thread mode)"]})
    with open(out_path, "w") as f:
        json.dump(model, f, indent=1, ensure_ascii=False, default=sorted)
    by_type = {}
    for c in model["conversations"]:
        by_type[c["type"]] = by_type.get(c["type"], 0) + 1
    p = print
    p(f"Teams {subject} {fmt_epoch(frm_s)} → {fmt_epoch(to_s)} UTC" + (f" (local {a.tz})" if tz else ""))
    if accounts:
        p("  accounts: " + ", ".join(f"{u} ({o})" for u, o, _ in accounts))
    p(f"  conversations: {len(model['conversations'])} (" + ", ".join(f"{k} {v}" for k, v in sorted(by_type.items()))
      + f"); meetings: {len(model['meetings'])}; calls: {len(model['calls'])}; files/links shared: "
      f"{sum(1 for s in model['shares'] if s['kind'] == 'file')}/{sum(1 for s in model['shares'] if s['kind'] == 'link')}")
    for c in model["conversations"][: a.top]:
        s = c["subject"]
        p(f"  {c['type']:<8} {cell(c['name'] or c['id'], 40):<40} sent {s['sent']:>3} edits {s['edits']:>2} "
          f"reacts {s['reactions']:>2} | others sent {c['others']['sent']:>3} | parties: "
          f"{cell(', '.join(c['parties']), 70)}")
    if model["daily"]:
        p("  daily (" + (a.tz or "UTC") + "): " + "; ".join(
            f"{d['date']} sent {d['sent']} react {d['reactions']} meet {d['meeting_joins']} call {d['call_joins']}"
            for d in model["daily"]))
    print(f"# {len(records)} records, {len(queries)} queries, {time.time() - start:.0f}s; JSON in {out_path}",
          file=sys.stderr)
    for n in notes:
        print(f"# {n}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- check

def cmd_check(cfg, a):
    table = "siem.logtrust.collector.counter"
    try:
        fields, _ = table_fields(cfg, table)
        print(f"ok: token valid in region {cfg['region']} ({REGIONS[cfg['region']][0]}); "
              f"{table} has {len(fields)} fields")
        if CACHE:
            s = cache_status(CACHE)
            if s["tables"]["state"] == "missing":
                print("cache: empty (first use). Commands fetch what they need as they go; for the full picture "
                      "run `devo.py cache build` in the background once (several minutes).")
            else:
                print_cache_status(s)
            if s["notes"]["count"]:
                print(f"domain notes: {s['notes']['count']} (`devo.py cache notes`)"
                      + (f", {s['notes']['to_review']} due for re-verification" if s["notes"]["to_review"] else ""))
        return 0
    except DevoError as e:
        print(f"region {cfg['region']}: {e}", file=sys.stderr)
    for r in REGIONS:
        if r == cfg["region"]:
            continue
        try:
            get_json(f"https://{REGIONS[r][0]}/search/table/{table}", cfg["token"], timeout=20)
            print(f"token works in region {r!r}: set DEVO_REGION={r}")
            return 2
        except DevoError:
            pass
    raise DevoError("token rejected in every region", "the token is invalid, expired or revoked")


# ---------------------------------------------------------------- health (the whole domain)

NORM_MSG = [(re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}"), "<id>"), (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hex>"),
            (re.compile(r"\{[^{}]*\}?"), "{…}"), (re.compile(r"\[[^\[\]]*\]?"), "[…]"),
            (re.compile(r"#[^#\s]*#?"), "#"), (re.compile(r"\d+(\.\d+)*"), "#"),
            (re.compile(r"'[^']*'|\"[^\"]*\""), "'…'"), (re.compile(r"(\S+/)+\S+"), "<path>"), (re.compile(r"\s+"), " ")]


AUTH_ERR = re.compile(r"\b(401|403)\b|forbidden|unauthori[sz]ed|expired ?token|invalid (token|credential|client)|"
                      r"access denied|authentication (failed|error)|token .*not (been )?created", re.I)


def norm_msg(m):
    """A collector message with ids, numbers and quoted values blanked, so repeats group together."""
    m = (m or "")[:200]
    for rx, sub in NORM_MSG:
        m = rx.sub(sub, m)
    return m.strip()[:120]


def day_of(v):
    return (v or "")[:10]


def health_tables(cfg, frm_s, to_s, rec_s, timeout):
    """Per table: daily events from the collector counter, baseline vs recent daily means, last day seen."""
    linq = ('from siem.logtrust.collector.counter where kind = "table" '
            'group every 1d by object select sum(events) as events')
    cols, rows, _ = fetch(cfg, linq, frm_s, to_s, 0, timeout, "1d", 7)
    merged, _ = merge_grouped(linq, cols, rows)
    per, totals = {}, {}
    for r in as_dicts(cols, merged if merged is not None else rows):
        d = day_of(r.get("eventdate"))
        per.setdefault(r["object"], {})[d] = per.setdefault(r["object"], {}).get(d, 0) + (r.get("events") or 0)
        totals[d] = totals.get(d, 0) + (r.get("events") or 0)
    today = fmt_epoch(to_s)[:10]
    days = [d for d in day_range(frm_s, to_s) if d != today]
    rec_days = [d for d in days if d >= fmt_epoch(rec_s)[:10]]
    base_days = [d for d in days if d not in rec_days]
    full = sorted(totals[d] for d in days if d in totals)
    med = full[len(full) // 2] if full else 0
    gap_days = [d for d in days if totals.get(d, 0) < 0.3 * med]  # the counter itself under-reports on these
    out = {}
    for t, by in per.items():
        base = [by.get(d, 0) for d in base_days if d not in gap_days]
        rec = [by.get(d, 0) for d in rec_days if d not in gap_days]
        seen = sorted(d for d, n in by.items() if n)
        b = sum(base) / len(base) if base else 0
        r_ = sum(rec) / len(rec) if rec else 0
        b_med = sorted(base)[len(base) // 2] if base else 0
        r_med = sorted(rec)[len(rec) // 2] if rec else 0
        last = seen[-1] if seen else None
        normal_gap = longest_zero_run(base)  # weekday-only or sporadic sources have quiet days in the baseline
        quiet_now = 0
        for d in reversed(days):
            if by.get(d):
                break
            quiet_now += 1
        if by.get(today):
            quiet_now = 0
        sporadic = base and sum(1 for x in base if not x) > 0.3 * len(base)
        if b >= 10 and quiet_now >= 1 and quiet_now > normal_gap and not sporadic:
            state = "stopped"
        elif b_med >= 1000 and r_med < 0.5 * b_med:
            state = "dropped"
        elif b == 0 and r_ > 0:
            state = "new"
        else:
            state = "ok"
        med_all = sorted(by.get(d, 0) for d in days if d not in gap_days)
        m_all = med_all[len(med_all) // 2] if med_all else 0
        low_days = [d for d in days if d not in gap_days and m_all >= 10000 and by.get(d, 0) < 0.1 * m_all]
        out[t] = {"low_days": low_days, "baseline_per_day": round(b), "recent_per_day": round(r_), "baseline_median": b_med,
                  "recent_median": r_med, "last_day": last, "state": state, "today_so_far": by.get(today, 0),
                  "quiet_days": quiet_now, "normal_gap_days": normal_gap, "sporadic": bool(sporadic)}
    return out, {"baseline_days": base_days, "recent_days": rec_days, "counter_gap_days": gap_days, "query": linq}


def longest_zero_run(vals):
    best = cur = 0
    for v in vals:
        cur = cur + 1 if not v else 0
        best = max(best, cur)
    return best


def recheck_table(cfg, table, frm_s, to_s, timeout):
    """Daily counts straight from a table (the collector counter can miss hours or days), one day at a
    time so a window the platform fails on (HTTP 500 during an incident) doesn't lose the rest."""
    linq = f"from {quote_table(table)} group every 1d select count() as n, max(eventdate) as last"
    daily, last, errors, msg = {}, "", 0, ""
    for d0 in range(frm_s - frm_s % 86400, to_s, 86400):
        try:
            cols, rows, _ = fetch(cfg, linq, max(d0, frm_s), min(d0 + 86400, to_s), 0, timeout)
        except DevoError as e:
            errors, msg = errors + 1, str(e)
            if "unknown table" in msg.lower():
                raise
            continue
        for r in as_dicts(cols, rows):
            daily[day_of(r.get("eventdate"))] = daily.get(day_of(r.get("eventdate")), 0) + (r.get("n") or 0)
            last = max(last, r.get("last") or "")
    if errors and not daily and not last:
        raise DevoError(f"every day failed ({errors}): {msg[:100]}")
    return daily, last, errors


EPHEMERAL = re.compile(r"^(ip-\d+-\d+-\d+-\d+|i-[0-9a-f]{8,}|gke-|aks-|eks-|runner-|ec2amaz-|[0-9a-f]{12}$)", re.I)


def health_hosts(cfg, table, field, frm_s, to_s, timeout):
    """Senders seen on at least 3 days of the window whose last event is over a day old. Cloud
    auto-generated names (ip-10-1-2-3, i-0abc…, gke-/aks- nodes, container ids) come and go with
    autoscaling: they are counted separately, not listed."""
    linq = f"from {table} group every 1d by {field} select count() as n, max(eventdate) as last"
    cols, rows, _ = fetch(cfg, linq, frm_s, to_s, 0, timeout, "1d", 7)
    per = {}
    for r in as_dicts(cols, rows):
        h = r.get(field)
        if not h:
            continue
        e = per.setdefault(h, {"days": set(), "last": "", "n": 0})
        e["days"].add(day_of(r.get("eventdate")))
        e["last"] = max(e["last"], r.get("last") or "")
        e["n"] += r.get("n") or 0
    cutoff = fmt_epoch(to_s - 86400)
    all_days = [d for d in day_range(frm_s, to_s)]

    def unusual(e):  # silent for longer than this sender's own longest quiet spell (weekday-only servers)
        seen = [1 if d in e["days"] else 0 for d in all_days]
        last_i = max(i for i, v in enumerate(seen) if v)
        quiet_now = len(seen) - 1 - last_i
        return quiet_now > max(1, longest_zero_run(seen[: last_i + 1]))

    quiet = [(h, e) for h, e in per.items() if len(e["days"]) >= 3 and e["last"] < cutoff and unusual(e)]
    churn = sum(1 for h, _ in quiet if EPHEMERAL.search(h))
    stopped = sorted(({"host": h, "last": e["last"], "days_seen": len(e["days"]),
                       "per_day": round(e["n"] / max(1, len(e["days"])))}
                      for h, e in quiet if not EPHEMERAL.search(h)), key=lambda x: x["last"], reverse=True)
    return {"table": table, "senders": len(per), "stopped": stopped, "ephemeral_quiet": churn, "query": linq}


def health_collectors(cfg, frm_s, to_s, timeout):
    """Collector warnings/errors (normalised and grouped) and each collector's last log line."""
    q1 = ('from devo.collectors.out where level2 = "error" '
          'select substring(msg, 0, 200) as m group by collector_name, service_name, level2, m '
          'select count() as n, max(eventdate) as last')
    q1w = ('from devo.collectors.out where level2 = "warning" '
           'select substring(msg, 0, 70) as m group by collector_name, service_name, level2, m '
           'select count() as n, max(eventdate) as last')
    q2 = "from devo.collectors.out group by collector_name select count() as n, max(eventdate) as last"
    c1, r1, _ = fetch(cfg, q1, frm_s, to_s, 0, timeout, "1d", 7)
    c1w, r1w, _ = fetch(cfg, q1w, frm_s, to_s, 0, timeout, "1d", 7)
    r1 = list(r1) + [[row[c1w.index(c)] if c in c1w else None for c in c1] for row in r1w] if c1 and c1w else (r1 or r1w)
    c1 = c1 or c1w
    c2, r2, _ = fetch(cfg, q2, frm_s, to_s, 0, timeout, "1d", 7)
    groups = {}
    for r in as_dicts(c1, r1):
        k = (r.get("collector_name"), r.get("level2"), norm_msg(r.get("m")))
        g = groups.setdefault(k, {"n": 0, "last": "", "services": set()})
        g["n"] += r.get("n") or 0
        g["last"] = max(g["last"], r.get("last") or "")
        if r.get("service_name"):
            g["services"].add(r.get("service_name"))
    issues = sorted(({"collector": k[0], "level": k[1], "message": k[2], "n": v["n"], "last": v["last"],
                      "services": sorted(v["services"])[:5], "auth": bool(AUTH_ERR.search(k[2]))}
                     for k, v in groups.items()),
                    key=lambda x: (not x["auth"], x["level"] != "error", -x["n"]))
    last = {}
    for r in as_dicts(c2, r2):
        last[r["collector_name"]] = max(last.get(r["collector_name"], ""), r.get("last") or "")
    cutoff = fmt_epoch(to_s - 86400)
    silent = sorted(({"collector": k, "last": v} for k, v in last.items() if v and v < cutoff), key=lambda x: x["last"])
    stops = {}
    for i in issues:
        if re.search(r"signal|stopping|shutting down|terminat", i["message"], re.I):
            stops[i["collector"]] = max(stops.get(i["collector"], ""), i["last"])
    for x in silent:
        t0 = parse_utc(stops.get(x["collector"]))
        if t0:
            wave = [c for c, t in stops.items() if c != x["collector"] and parse_utc(t)
                    and abs((parse_utc(t) - t0).total_seconds()) <= 1800]
            if wave:
                x["wave"] = (f"stopped in a restart that hit {len(wave) + 1} collectors around {stops[x['collector']][:16]}; "
                             "the others came back, this one did not: restart it")
    return {"issues": issues, "silent": silent, "collectors": len(last), "queries": [q1, q2]}


def cmd_health(cfg, a):
    """Health of the whole domain: which tables (sources) are flowing, stopped, dropped or new
    (recent days vs a baseline, from the collector counter, with stopped/dropped tables re-counted on
    the tables themselves because the counter can miss hours), which Windows/Linux senders went quiet,
    collector warnings and errors, and ingestion lag. One report; --out keeps the JSON."""
    from concurrent.futures import ThreadPoolExecutor
    now = int(time.time())
    _, frm_s = resolve_time(a.baseline)
    _, rec_s = resolve_time(a.recent)
    if None in (frm_s, rec_s) or not frm_s < rec_s < now:
        raise DevoError("health needs --baseline older than --recent (e.g. --baseline 21d --recent 7d)", code=1)
    frm_s -= frm_s % 86400
    rec_s -= rec_s % 86400
    have = cached_table_set() or {t for t, _ in domain_tables(cfg)}
    start = time.time()
    jobs = {"tables": (health_tables, (cfg, frm_s, now, rec_s, a.timeout))}
    if not a.no_hosts:
        for key, table, field in (("windows hosts", "box.win_nxlog.security", "host"), ("linux hosts", "box.unix", "machine")):
            if table in have:
                jobs[key] = (health_hosts, (cfg, table, field, max(frm_s, rec_s - 7 * 86400), now, a.timeout))
    if "devo.collectors.out" in have:
        jobs["collectors"] = (health_collectors, (cfg, max(frm_s, rec_s), now, a.timeout))

    def run(item):
        k, (fn, args) = item
        try:
            return k, fn(*args), None
        except DevoError as e:
            return k, None, str(e)

    with ThreadPoolExecutor(4) as pool:
        res = {k: (r, e) for k, r, e in pool.map(run, jobs.items())}
    report = {"window": {"baseline_from": fmt_epoch(frm_s), "recent_from": fmt_epoch(rec_s), "now": fmt_epoch(now)},
              "errors": {k: e for k, (r, e) in res.items() if e}}
    tables, meta = res["tables"][0] or ({}, {})
    unq_cached = set(((CACHE.read("tables") or {}).get("unqueryable") or []) if CACHE else [])
    for t in list(tables):
        if t in unq_cached:
            tables[t]["state"] = "unqueryable"
    report["tables_meta"] = meta
    flagged = sorted((t for t, v in tables.items() if v["state"] in ("stopped", "dropped")),
                     key=lambda t: -tables[t]["baseline_per_day"])[: a.max_recheck]

    def recheck(t):
        try:
            return t, recheck_table(cfg, t, (now - now % 86400) - 9 * 86400, now, a.timeout), None
        except DevoError as e:
            return t, None, str(e)

    with ThreadPoolExecutor(max(1, a.parallel)) as pool:
        for t, got, err in pool.map(recheck, flagged):
            v = tables[t]
            if err and "unknown table" in err.lower():
                v["state"], v["recheck"] = "unqueryable", "listed by the counter, but Devo says the table doesn't exist"
                continue
            if err:
                v["recheck"] = f"error: {err[:100]}"
                continue
            daily, last, errs = got
            v["source_last"] = last
            full_days = sorted(d for d in daily if d != fmt_epoch(now)[:10])
            last3 = full_days[-3:]
            v["source_recent_per_day"] = round(sum(daily[d] for d in last3) / max(1, len(last3)))
            pairs = [(daily[d], daily.get((dt.date.fromisoformat(d) - dt.timedelta(days=7)).isoformat()))
                     for d in full_days[-2:]]
            pairs = [(x, y) for x, y in pairs if y]
            if pairs:
                v["last2_change"] = sum(x for x, _ in pairs) / sum(y for _, y in pairs) - 1
            if v["state"] == "stopped" and last and last >= fmt_epoch(now - 86400):
                v["state"], v["recheck"] = "ok", "counter showed none, but the table has recent rows (counter gap)"
            elif v["state"] == "dropped" and v.get("last2_change") is not None and v["last2_change"] <= -0.35:
                v["state"], v["recheck"] = "recent shift", (f"the last 2 days are {v['last2_change']:+.0%} on the same "
                                                            "weekdays a week earlier")
            elif v["state"] == "dropped" and v["source_recent_per_day"] >= 0.5 * v["baseline_per_day"]:
                v["state"], v["recheck"] = "ok", "counter showed a drop the table itself doesn't"
            else:
                v["recheck"] = "confirmed on the table (last 3 days)" + (f", {errs} day(s) failed" if errs else "")
    movers = [t for t, v in tables.items() if v["state"] == "ok" and v["baseline_median"] >= 50000 and v["baseline_median"]
              and abs(v["recent_median"] - v["baseline_median"]) / v["baseline_median"] >= 0.35][: a.max_recheck]
    today0 = now - now % 86400

    def verify(t):
        try:
            rec_d, _, _ = recheck_table(cfg, t, today0 - 7 * 86400, today0, a.timeout)
            base_d, _, _ = recheck_table(cfg, t, today0 - 14 * 86400, today0 - 7 * 86400, a.timeout)
            return t, rec_d, base_d, None
        except DevoError as e:
            return t, None, None, str(e)

    if movers and not a.no_verify:
        with ThreadPoolExecutor(max(1, a.parallel)) as pool:
            for t, rec_d, base_d, err in pool.map(verify, movers):
                v = tables[t]
                if err:
                    v["mover_check"] = f"re-count failed: {err[:80]}"
                    continue
                med = lambda d_: sorted(d_.values())[len(d_) // 2] if d_ else 0
                rm, bm = med(rec_d), med(base_d)
                v["table_recent_median"], v["table_prev_median"] = rm, bm
                v["table_change"] = (rm - bm) / bm if bm else None
                # a shift in the last two days hides inside a 7-day median: compare them with the same weekdays
                last2 = sorted(rec_d)[-2:]
                pairs = [(rec_d[d_], base_d.get((dt.date.fromisoformat(d_) - dt.timedelta(days=7)).isoformat()))
                         for d_ in last2]
                pairs = [(x, y) for x, y in pairs if y]
                if pairs:
                    ch2 = sum(x for x, _ in pairs) / sum(y for _, y in pairs) - 1
                    v["last2_change"] = ch2
                    if ch2 <= -0.35:
                        v["state"] = "recent shift"
    ups = [t for t, v in tables.items() if (v.get("table_change") or 0) >= 0.35 or (v.get("last2_change") or 0) >= 0.35]
    fams = load_event_time()

    def dup(t):
        fam = event_time_for(t, fams)
        ids = [x for x in (fam or {}).get("dedupe") or [] if x != "timestamp"]
        if len(ids) != 1:
            return t, None
        try:
            cols, rows, _ = fetch(cfg, f"from {quote_table(t)} group every 1d select count() as n, hllppcount({ids[0]}) "
                                       "as ids", today0 - 7 * 86400, today0, 0, a.timeout, "1d", 7)
            r = as_dicts(cols, rows)
            n, i = sum(x.get("n") or 0 for x in r), sum(x.get("ids") or 0 for x in r)
            return t, (n / i if i else None)
        except DevoError:
            return t, None

    if ups and not a.no_verify:
        with ThreadPoolExecutor(max(1, a.parallel)) as pool:
            for t, ratio in pool.map(dup, ups):
                if ratio and ratio >= 1.5:
                    tables[t]["dup_note"] = (f"DUPLICATED: {ratio:.1f} rows per distinct id over the last 7 days "
                                             "(back-fill/re-delivery), not real growth: count distinct ids")
    shifted = [t for t, v in tables.items() if v["state"] in ("recent shift", "dropped", "stopped")][:8]

    def actor_field(t):
        prof = CACHE.get(f"fields/{t}", allow_old=True) if CACHE else None
        if not prof:
            try:
                names = [f for f, _ in schema_fields(cfg, t)]
            except DevoError:
                return None
            for rx in (r"^userIdentity_+arn$", r"^(UserId|Username|actor|user|properties_userPrincipalName|"
                                                r"properties_initiatedBy_user_userPrincipalName|TargetUserName)$"):
                hit = [n for n in names if re.match(rx, n)]
                if hit:
                    return hit[0]
            return None
        c = [(k, f) for k, f in (prof.get("fields") or {}).items() if f.get("role") == "user" and f.get("fill", 0) >= 0.5
             and f.get("type") == "str"]
        return sorted(c, key=lambda kv: -kv[1]["fill"])[0][0] if c else None

    def actors(t):
        f = actor_field(t)
        if not f:
            return t, None, None
        q = f"from {quote_table(t)} group by {f} select count() as n"
        try:
            c1, r1, _ = fetch(cfg, q, today0 - 2 * 86400, today0, 0, a.timeout, "1d", 2)
            c0, r0, _ = fetch(cfg, q, today0 - 9 * 86400, today0 - 7 * 86400, 0, a.timeout, "1d", 2)
        except DevoError:
            return t, f, None
        now_ = {}
        for r in as_dicts(c1, r1):
            now_[r.get(f)] = now_.get(r.get(f), 0) + (r.get("n") or 0)
        was = {}
        for r in as_dicts(c0, r0):
            was[r.get(f)] = was.get(r.get(f), 0) + (r.get("n") or 0)
        diff = sorted(((k, was.get(k, 0), now_.get(k, 0)) for k in set(now_) | set(was)),
                      key=lambda x: -abs(x[2] - x[1]))[:3]
        return t, f, diff

    if shifted and not a.no_verify:
        with ThreadPoolExecutor(max(1, a.parallel)) as pool:
            for t, f, diff in pool.map(actors, shifted):
                if diff:
                    tables[t]["actors"] = {"field": f, "changes": diff}
    report["tables"] = tables
    for k in ("windows hosts", "linux hosts", "collectors"):
        if k in res:
            report[k] = res[k][0]
    quiet = [x for k in ("windows hosts", "linux hosts") for x in ((report.get(k) or {}).get("stopped") or [])]
    if quiet and "edr.sentinelone.agent.agents" in have:  # offline host, or online but not logging?
        try:
            # the agents table keeps snapshotting inactive agents: use the agent's own lastActiveDate
            cols, rws, _ = fetch(cfg, "from edr.sentinelone.agent.agents group by computerName "
                                      "select max(lastActiveDate) as last", now - 2 * 86400, now, 0, a.timeout, "1d", 2)
            seen = {}
            for r in as_dicts(cols, rws):
                h = (r.get("computerName") or "").split(".")[0].lower()
                seen[h] = max(seen.get(h, ""), r.get("last") or "")
            for x in quiet:
                h = (x["host"] or "").split(".")[0].lower()
                if seen.get(h) and seen[h] >= fmt_epoch(now - 86400):
                    x["edr"] = f"EDR agent last active {seen[h][:16]}: host is ONLINE but not logging"
                else:
                    x["edr"] = ("EDR agent " + (f"last active {seen[h][:16]}" if seen.get(h) else "not seen")
                                + " too: host likely offline or retired")
        except DevoError:
            pass
    if not a.no_lag:
        try:
            fams = load_event_time()
            lag_tables = [t for f in fams for t in f.get("lag", []) if t in have]

            def one(t):
                try:
                    return lag_table(cfg, t, event_time_for(t, fams), now - 86400, now, "6h", a.timeout)
                except DevoError as e:
                    return {"table": t, "error": str(e)}

            with ThreadPoolExecutor(max(1, a.parallel)) as pool:
                report["lag"] = list(pool.map(one, lag_tables))
        except DevoError as e:
            report["errors"]["lag"] = str(e)
    if a.out:
        with open(a.out, "w") as f:
            json.dump(report, f, indent=1, ensure_ascii=False, default=list)
    print_health(report, a)
    sys.stdout.flush()
    print(f"# health in {time.time() - start:.0f}s; baseline = the days {fmt_epoch(frm_s)[:10]} → {fmt_epoch(rec_s)[:10]}, "
          f"recent = {fmt_epoch(rec_s)[:10]} → now (UTC). Daily means/medians skip the counter's gap days and today. "
          "'stopped' needs a silence longer than the source's own longest quiet spell in the baseline (weekday-only "
          "and sporadic sources aren't flagged); 'dropped' compares median days. "
          f"Hosts list senders of box.win_nxlog.security / box.unix only: other sources' senders need their own "
          f"query (`coverage`, or group by the sender field).", file=sys.stderr)
    return 0


def print_health(r, a):
    p = print
    t = r.get("tables") or {}
    meta = r.get("tables_meta") or {}
    by = lambda s: sorted((x for x in t.items() if x[1]["state"] == s), key=lambda x: -x[1]["baseline_per_day"])
    p(f"Health {r['window']['baseline_from'][:10]} → {r['window']['now'][:16]} UTC: {len(t)} tables in the collector "
      f"counter; {len(by('stopped'))} stopped, {len(by('dropped'))} dropped, {len(by('recent shift'))} recent shifts, "
      f"{len(by('new'))} new")
    probs = []
    for n, v in by("stopped"):
        probs.append(f"STOPPED   {n} (last {(v.get('source_last') or v['last_day'] or '?')[:16]})")
    for n, v in by("dropped"):
        probs.append(f"DROPPED   {n} ({v['baseline_median']:,} → {v.get('source_recent_per_day', v['recent_median']):,}/day)")
    seen_shift = {}
    for n, v in by("recent shift"):
        key = (v.get("last2_change") and round(v["last2_change"], 2), n.rsplit(".", 1)[0])
        if key in seen_shift and key[0] is not None:
            seen_shift[key].append(n)  # identical numbers: one feed written to sibling tables
            continue
        seen_shift[key] = [n]
    for (ch, _), names in seen_shift.items():
        v = t[names[0]]
        line = (f"RECENT    {names[0]}" + (f" (+{len(names) - 1} sibling table(s) with identical counts)" if len(names) > 1
                                          else "") + f": last 2 days {v.get('last2_change', 0):+.0%} vs the same weekdays")
        if v.get("dup_note"):
            line += "; but the comparison week was inflated by duplicated back-fill"
        if v.get("actors"):
            ch_ = ", ".join(f"{k or '(blank)'} {a_:,}→{b_:,}" for k, a_, b_ in v["actors"]["changes"])
            line += f"; biggest changes by {v['actors']['field']}: {ch_}"
        probs.append(line)
    c_ = r.get("collectors") or {}
    for x in c_.get("silent", []):
        probs.append(f"COLLECTOR {x['collector']} silent since {x['last'][:16]}" + (" (did not restart)" if x.get("wave") else ""))
    recent_cut = fmt_epoch(int(time.time()) - 86400)
    auth = sorted({i["collector"] for i in c_.get("issues", []) if i.get("auth")
                   and (i.get("last", "") >= recent_cut or i.get("n", 0) >= 3)})
    if auth:
        probs.append(f"AUTH      credential/permission errors on collector(s): {', '.join(auth)}")
    for k in ("windows hosts", "linux hosts"):
        h = r.get(k)
        if h and h.get("stopped"):
            online = [x["host"] for x in h["stopped"] if "ONLINE" in (x.get("edr") or "")]
            probs.append(f"HOSTS     {len(h['stopped'])} {k} went quiet"
                         + (f"; {len(online)} still online per the EDR (logging fault): {', '.join(online[:6])}" if online
                            else " (see below; check each in the EDR/inventory: offline or a logging fault?)"))
    gaps_t = sorted(((n, v) for n, v in t.items() if v.get("low_days") and v["state"] != "unqueryable"),
                    key=lambda kv: -len(kv[1]["low_days"]))
    for n, v in gaps_t[:8]:
        probs.append(f"GAPS      {n}: near-empty ingestion on {compress_days(v['low_days'])} (under 10% of its median day; "
                     "data may have arrived later as a back-fill: compare event time)")
    if probs:
        p("\nProblems (details below):")
        for x in probs:
            p("  " + x)
    if meta.get("counter_gap_days"):
        p(f"  ! collector counter under-reports on {', '.join(meta['counter_gap_days'])} (domain-wide totals far "
          "below normal): a platform incident or a counter gap. Check those days on the source tables before "
          "calling them outages.")
    for state, title in (("stopped", "STOPPED (no events for over a day)"), ("dropped", "DROPPED (recent < 50% of baseline)"),
                         ("recent shift", "RECENT SHIFT (last 2 full days well below the same weekdays a week earlier)")):
        rows = by(state)
        if rows:
            p(f"\n{title}:")
            for name, v in rows[: a.limit]:
                p(f"  {name:<55} baseline {v['baseline_per_day']:>12,}/day  recent {v['recent_per_day']:>12,}/day  "
                  f"last {v.get('source_last', '')[:16] or v['last_day'] or 'never'}  {v.get('recheck', '')}")
    unq = [n for n, v in t.items() if v["state"] == "unqueryable"]
    if unq:
        p(f"\nListed by the counter but not queryable ({len(unq)}; ignore unless you expect them): "
          + ", ".join(unq[:15]))
    rechecked = [(n, v) for n, v in t.items() if (v.get("recheck") or "").startswith("counter")]
    if rechecked:
        p(f"\nCleared on re-check ({len(rechecked)}): the counter showed a stop/drop the tables don't: "
          + ", ".join(n for n, _ in rechecked[:10]))
    total = sum(v["recent_per_day"] for v in t.values())
    top = sorted(t.items(), key=lambda kv: -kv[1]["recent_per_day"])[:15]
    p(f"\nVolume (collector counter, unverified): ~{total:,} events/day over "
      f"{sum(1 for v in t.values() if v['recent_per_day'] and v['state'] != 'unqueryable')} tables (recent window). Top 15:")
    for n, v in top:
        ch = (v["recent_median"] - v["baseline_median"]) / v["baseline_median"] if v["baseline_median"] else 0
        p(f"  {n:<55} {v['recent_per_day']:>13,}/day  ({ch:+.0%} vs baseline median)")
    movers = [(n, v) for n, v in t.items() if "table_change" in v or "mover_check" in v]
    if movers:
        real = [(n, v) for n, v in movers if v.get("table_change") is not None and abs(v["table_change"]) >= 0.35]
        p("\nBig movers in the counter (median day ±35%, over 50k/day), re-counted on the tables (median day of the "
          "last 7 full days vs the 7 before):")
        for n, v in sorted(movers, key=lambda kv: kv[1].get("table_change") or 0):
            ch = v.get("table_change")
            l2 = v.get("last2_change")
            failed = v.get("mover_check", "")
            p(f"  {n:<55} counter {((v['recent_median'] - v['baseline_median']) / v['baseline_median']):+.0%}, table "
              + (f"{ch:+.0%} ({v['table_prev_median']:,} → {v['table_recent_median']:,}/day)" if ch is not None
                 else ("not queryable" if "unknown table" in failed.lower() else failed or "?"))
              + (f", last 2 days {l2:+.0%} vs the same weekdays a week earlier" if l2 is not None else "")
              + (f"  ← {v['dup_note']}" if v.get("dup_note") else
                 "  ← REAL" if ch is not None and abs(ch) >= 0.35 else
                 "  ← RECENT SHIFT" if l2 is not None and abs(l2) >= 0.35 else
                 "" if ch is None else "  (counter artefact or weekday mix)"))
    unparsed = [(n, v) for n, v in t.items() if n.startswith("unknown.") and v["recent_per_day"] >= 1000]
    for n, v in unparsed:
        p(f"\nUNPARSED: {n} receives ~{v['recent_per_day']:,} events/day: senders whose tag has no parser (fix the "
          "tag at the source; `devo.py query 'from unknown.unknown group by hostchain select count() as n' --from 1d`)")
    new = [x for x in by("new")]
    if new:
        p(f"\nNEW in the recent window: " + ", ".join(f"{n} ({v['recent_per_day']:,}/day)" for n, v in new[:15]))
    for k in ("windows hosts", "linux hosts"):
        h = r.get(k)
        if h:
            p(f"\n{k.capitalize()} ({h['table']}, {h['senders']} senders): {len(h['stopped'])} went quiet "
              "(seen on 3+ days, nothing for over a day)"
              + (f"; plus {h['ephemeral_quiet']} auto-named cloud instances (autoscaling churn, not listed)"
                 if h.get("ephemeral_quiet") else ""))
            for x in h["stopped"][: a.limit]:
                p(f"  {x['host']:<45} last {x['last'][:16]}  ~{x['per_day']:,}/day on {x['days_seen']} day(s)"
                  + (f"  ({x['edr']})" if x.get("edr") else ""))
    c = r.get("collectors")
    if c:
        p(f"\nCollectors ({c['collectors']} logging to devo.collectors.out):")
        for x in c["silent"]:
            p(f"  SILENT  {x['collector']}: last log line {x['last'][:16]}" + (f"  ← {x['wave']}" if x.get("wave") else ""))
            last_lines = sorted((i for i in c["issues"] if i["collector"] == x["collector"]), key=lambda i: i["last"],
                                reverse=True)[:3]
            for i in last_lines:
                p(f"          last {i['level']}: {i['last'][:16]} {i['message'][:110]}")
        per_c = {}
        for x in c["issues"]:
            per_c.setdefault(x["collector"], []).append(x)
        for name, lst in sorted(per_c.items(), key=lambda kv: (not any(i["auth"] for i in kv[1]),
                                                               all(i["level"] != "error" for i in kv[1]), kv[0])):
            errs = sum(i["n"] for i in lst if i["level"] == "error")
            warns = sum(i["n"] for i in lst if i["level"] != "error")
            auth = any(i["auth"] for i in lst)
            p(f"  {'AUTH ' if auth else ''}{name}: {errs:,} errors, {warns:,} warnings ({len(lst)} distinct messages)"
              + ("  ← credential/permission errors: the collector may be pulling nothing for some services" if auth else ""))
            for i in lst[:3]:
                p(f"    {i['level']:<7} {i['n']:>7,}× last {i['last'][:16]}  {i['message'][:110]}"
                  + (f"  ({', '.join(i['services'][:3])})" if i.get("services") else ""))
    lag = r.get("lag")
    if lag:
        p("\nIngestion lag (last 24 h):")
        for x in lag:
            if x.get("error"):
                p(f"  {x['table']}: ERROR {x['error'][:100]}")
            elif x.get("has_event_time") and x.get("rows"):
                note = (lag_sanity(x, event_time_for(x["table"], load_event_time()) or profile_time_family(x["table"]))
                        or offset_note(x) or ("batchy: some hours arrive much later" if (x.get("worst_hour_p95_s") or 0)
                                              > 6 * 3600 else ""))
                p(f"  {x['table']:<50} p50 {human_secs(x.get('p50_s')):>7}  p95 {human_secs(x.get('p95_s')):>7}  "
                  f"newest event {(x.get('newest_event') or '')[:16]}  {note}")
        if any(offset_note(x) for x in lag if not x.get("error")):
            p("  (an offset names no senders: group the table by its sender field and compare event time with "
              "eventdate, e.g. `query 'from dns.windows group by hostname select ...'`)")
    for k, e in (r.get("errors") or {}).items():
        p(f"\n{k}: ERROR {e}")


# ---------------------------------------------------------------- logons (who logged into which server)

WIN_INTERACTIVE = {"2": "console", "7": "unlock", "10": "remote (RDP)", "11": "cached", "3": "network",
                   "4": "batch", "5": "service", "8": "cleartext", "9": "new credentials"}
SYSTEM_ACCOUNT = re.compile(r"(\$$|^(DWM|UMFD)-\d+$|^(ANONYMOUS LOGON|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|-)$)", re.I)
SERVICE_HINT = re.compile(r"(^|[._-])(svc|service|srv|sa|sql|dba|db|backup|scan|monitor|bot|batch|sched|task|app|api|"
                          r"tools?|reports?|root|admin|prod|test|qa|ftp|sftp|etl|sync|agent)([._-]|\d|$)"
                          r"|^(root|admin|administrator|ec2-user|ubuntu|centos|git|tomcat|www-data|nobody|oracle|"
                          r"postgres|jenkins|ansible|deploy|build\w*)$"
                          r"|^[a-z]+(service|svc|user|admin|root|reports?|tools?|prod\w*)$", re.I)


PERSONAL_ADMIN = re.compile(r"^(adm|admin|da|sa|pa|t[0-2])[._-][a-z]|^[a-z]+[._-][a-z.]+[._-](admin|adm)$|"
                            r"^[a-z]+\.[a-z]+_?(admin|adm)$", re.I)
SHARED_ADMIN = re.compile(r"^(administrator|admin|root)$", re.I)


def person_key(account):
    """One key per person-ish account: no DOMAIN\\, no @domain, lower case (CORP\\jsmith = jsmith@x = JSmith)."""
    leaf = (account or "").split("\\")[-1].split("@")[0]
    return leaf.lower()
HEAVY = 1000  # logons by one account on one host in the window: more than a person does by hand


def win_logon_query(term_filter="", network=False):
    types = ", ".join(f'"{t}"' for t in ("2", "7", "10", "11") + (("3",) if network else ()))
    return ('from box.win_nxlog.security where EventID = 4624, LogonType in {' + types + '}' + term_filter +
            ' select peek(Message, re("Source Network Address:\\\\s*([^\\\\r\\\\n\\\\t]+)"), 1) as src'
            ' group by host, TargetUserName, TargetDomainName, LogonType, ProcessName, src'
            ' select count() as n, min(timestamp) as first, max(timestamp) as last')


def linux_logon_query(term_filter=""):
    return ('from box.unix where appName in {"sshd", "sshd-session"}, message -> "Accepted "' + term_filter +
            ' select peek(message, re("Accepted (\\\\S+) for "), 1) as method,'
            ' peek(message, re("Accepted \\\\S+ for (\\\\S+) from"), 1) as account,'
            ' peek(message, re(" from ([0-9a-fA-F:.]+) port"), 1) as src'
            ' group by machine, method, account, src'
            ' select count() as n, min(eventdate) as first, max(eventdate) as last')


def service_patterns():
    return load_notes().get("service_accounts") or []


def account_kind(account, per_host_max, hosts, patterns, days=7, host=""):
    """person | service? (name, a domain pattern, or volume says automation) | sftp? (an account on a
    file-transfer host: often a partner, not a person) | system (built-in, never a person)."""
    import fnmatch
    leaf = (account or "").split("\\")[-1]
    if not leaf or SYSTEM_ACCOUNT.search(leaf):
        return "system", "built-in/computer account"
    for p in patterns:
        if fnmatch.fnmatch(leaf.lower(), p.lower()):
            return "service", f"matches the domain's service pattern {p!r}"
    if SHARED_ADMIN.match(leaf):
        return "shared-admin", "a shared built-in admin account (no person attached): find who used it"
    if PERSONAL_ADMIN.search(leaf):
        return "person (admin)", "a person's admin account (naming); counted with the people"
    if SERVICE_HINT.search(leaf):
        return "service?", "name looks like a service/shared account"
    if GUID.match(leaf.strip("{}")):
        return "service?", "a GUID, not a person's name"
    if per_host_max >= HEAVY:
        return "service?", f"the account's busiest host had {per_host_max} logons: automation, not a person"
    if "." not in leaf and per_host_max / max(1, days) >= 50:
        return "service?", (f"the account's busiest host had ~{per_host_max // max(1, days)} logons a day and the "
                            "name isn't first.last")
    if re.search(r"s?ftp", host or "", re.I):
        return "sftp?", "an account on a file-transfer host: often a partner or automation"
    return "person", ""


def cmd_logons(cfg, a):
    """Who logged into which servers: Windows interactive/RDP logons (4624 types 2/7/10/11, event time)
    and Linux SSH logins (sshd Accepted, ingestion time), per server and account, with first/last,
    source IPs and a person/service/system label. Chunked, merged, one JSON file plus a text summary."""
    from concurrent.futures import ThreadPoolExecutor
    _, frm_s = resolve_time(a.from_)
    _, to_s = resolve_time(a.to)
    if to_s is not None:
        to_s = min(to_s, int(time.time()))
    if None in (frm_s, to_s) or frm_s >= to_s:
        raise DevoError("logons needs concrete --from/--to with from < to", code=1)
    filt = {"windows": "", "linux": ""}
    if a.host:
        h = linq_term(a.host, "host")
        filt = {"windows": f', weakhas(host, "{h}")', "linux": f', weakhas(machine, "{h}")'}
    if a.user:
        u = linq_term(a.user, "user")
        filt["windows"] += f', weakhas(TargetUserName, "{u}")'
        filt["linux"] += f', weakhas(message, "{u}")'
    oses = [o.strip() for o in a.os.split(",")]
    have = cached_table_set()
    jobs = {}
    if "windows" in oses:
        jobs["windows"] = ("box.win_nxlog.security", win_logon_query(filt["windows"], a.include_network),
                           "event time (timestamp)")
    if "linux" in oses:
        jobs["linux"] = ("box.unix", linux_logon_query(filt["linux"]), "ingestion time (eventdate; Linux has no "
                                                                        "event-time field)")
    skipped = [k for k, (t, _, _) in jobs.items() if have is not None and t not in have]
    for k in skipped:
        cache_say(f"{jobs[k][0]} is not in this domain's table list: {k} skipped")
        del jobs[k]
    if not jobs:
        raise DevoError("no logon source in this domain (box.win_nxlog.security, box.unix)",
                        "find the domain's authentication tables with `devo.py tables --grep 'auth|logon|unix|win'`",
                        code=1)
    chunk = a.chunk or ("6h" if to_s - frm_s <= 3 * 86400 else "1d")
    start = time.time()

    def run(item):
        key, (table, linq, basis) = item
        try:
            cols, rows, info = fetch(cfg, linq, frm_s, to_s, 0, a.timeout, chunk, a.parallel)
            merged, _ = merge_grouped(linq, cols, rows)
            return key, table, linq, basis, as_dicts(cols, merged if merged is not None else rows), None
        except DevoError as e:
            return key, table, linq, basis, [], str(e)

    for os_, (table, _, _) in list(jobs.items()):
        field = "host" if os_ == "windows" else "machine"
        jobs[f"lastseen_{os_}"] = (table, f"from {table} group by {field} select max(eventdate) as last, count() as n",
                                   "ingestion time")
    if a.resolve_ztna and (have is None or "vpn.zscaler.access" in have):
        jobs["ztna"] = ("vpn.zscaler.access",
                        'from vpn.zscaler.access where ServerPort in {3389, 22} '
                        'group by Host, ServerIP, ServerPort, Username, ConnectorIP '
                        'select count() as n, min(eventdate) as first, max(eventdate) as last', "ingestion time")
    with ThreadPoolExecutor(3) as pool:
        results = list(pool.map(run, jobs.items()))
    ztna = next((r for r in results if r[0] == "ztna"), None)
    lastseen = {}
    for r in results:
        if r[0].startswith("lastseen_") and not r[5]:
            for x in r[4]:
                h = (x.get("host") or x.get("machine") or "").split(".")[0].lower()
                lastseen[h] = max(lastseen.get(h, ""), x.get("last") or "")
    results = [r for r in results if r[0] != "ztna" and not r[0].startswith("lastseen_")]
    patterns = service_patterns()
    report = {"window": [fmt_epoch(frm_s), fmt_epoch(to_s)], "sources": {}, "logons": []}
    for key, table, linq, basis, recs, err in results:
        report["sources"][key] = {"table": table, "query": linq, "time_basis": basis, "error": err, "rows": len(recs)}
        per = {}
        for r in recs:
            if key == "windows":  # Windows names are case-insensitive: fold DOMAIN\user variants together
                acct = r.get("TargetUserName") or ""
                dom = r.get("TargetDomainName") or ""
                k = ((r.get("host") or "").split(".")[0].lower(),
                     (f"{dom}\\{acct}" if dom and dom != "-" else acct).lower())
                how = WIN_INTERACTIVE.get(str(r.get("LogonType")), str(r.get("LogonType")))
                exe = re.split(r"[\\/]", str(r.get("ProcessName") or ""))[-1].lower()
                if exe == "consent.exe":
                    how = "UAC elevation prompt"  # an admin credential typed into a UAC prompt, not a new session
                elif exe and exe not in ("-", "winlogon.exe", "svchost.exe", "lsass.exe", "services.exe", "taskhostw.exe",
                                         "logonui.exe", "wininit.exe", "userinit.exe", "explorer.exe", "credentialuibroker.exe"):
                    how = f"app logon ({exe})"  # a program calling LogonUser (report servers, agents): not a person
            else:
                k = (r.get("machine"), r.get("account") or "")
                how = f"ssh {r.get('method') or '?'}"
            shown_acct = (f"{r.get('TargetDomainName')}\\{r.get('TargetUserName')}"
                          if key == "windows" and r.get("TargetDomainName") not in (None, "", "-")
                          else (r.get("TargetUserName") if key == "windows" else r.get("account"))) or ""
            e = per.setdefault(k, {"os": key, "host": r.get("host") if key == "windows" else r.get("machine"),
                                   "account": shown_acct, "variants": [], "logons": 0, "first": None, "last": None,
                                   "how": {}, "sources": {}})
            if shown_acct and shown_acct != e["account"] and shown_acct not in e["variants"]:
                e["variants"].append(shown_acct)
            e["logons"] += r.get("n") or 0
            e["how"][how] = e["how"].get(how, 0) + (r.get("n") or 0)
            src = r.get("src")
            if src and src not in ("-", "::1", "127.0.0.1"):
                e["sources"][src] = e["sources"].get(src, 0) + (r.get("n") or 0)
            for f, pick in (("first", min), ("last", max)):
                vals = [x for x in (e[f], r.get(f)) if x]
                e[f] = pick(vals) if vals else None
        report["logons"] += per.values()
    hosts_per_acct, heavy = {}, {}  # per person key, so DOMAIN\x and x@y get one label
    for e in report["logons"]:
        k = person_key(e["account"])
        hosts_per_acct.setdefault(k, set()).add(e["host"])
        heavy[k] = max(heavy.get(k, 0), e["logons"])
    days = max(1, (to_s - frm_s) / 86400)
    order = {"system": 0, "shared-admin": 1, "service": 1, "person (admin)": 2, "service?": 2, "sftp?": 3, "uac": 3,
             "person": 4}
    label = {}
    for e in report["logons"]:
        k = person_key(e["account"])
        kind = account_kind(e["account"], heavy[k], len(hosts_per_acct[k]), patterns, days, e["host"])
        if kind[0] != "sftp?" and (k not in label or order[kind[0]] < order[label[k][0]]):
            label[k] = kind
    for e in report["logons"]:
        k = person_key(e["account"])
        own = account_kind(e["account"], heavy[k], len(hosts_per_acct[k]), patterns, days, e["host"])
        e["person_key"] = k
        e["kind"], e["why"] = own if own[0] in ("sftp?", "system", "shared-admin", "person (admin)") else label.get(k, own)
        hows = set(e["how"])
        if e["kind"] in ("person", "person (admin)") and hows and all(h == "UAC elevation prompt" for h in hows):
            e["kind"], e["why"] = "uac", "only UAC elevation prompts (the person's own session is under another account)"
        elif e["kind"] == "person" and hows and all(h.startswith("app logon") for h in hows):
            e["kind"], e["why"] = "service?", "only logons made by an application (LogonUser), not interactive"
        e["sources"] = dict(sorted(e["sources"].items(), key=lambda kv: -kv[1])[:5])
        if a.tz:
            for f in ("first", "last"):
                e[f + "_local"] = to_local(e[f], get_tz(a.tz))
    report["logons"].sort(key=lambda e: (e["host"] or "", -e["logons"]))
    keep = ({"person", "person (admin)", "shared-admin"} if a.people_only else
            ({"person", "person (admin)", "shared-admin", "service?", "service", "sftp?", "uac", "system"}
             if a.all_accounts else {"person", "person (admin)", "shared-admin", "service?", "service", "sftp?", "uac"}))
    shown = [e for e in report["logons"] if e["kind"] in keep]
    before = [e for e in shown if e.get("first") and e["first"] < report["window"][0][:19]]
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["os", "host", "account", "kind", "logons", "how", "first_utc", "last_utc", "time_basis",
                        "top_sources", "variants", "via_ztna", "why"])
            for e in shown:
                w.writerow([e["os"], e["host"], e["account"], e["kind"], e["logons"],
                            "; ".join(f"{k} {v}" for k, v in e["how"].items()), e["first"], e["last"],
                            "event" if e["os"] == "windows" else "ingest", "; ".join(e["sources"]),
                            "; ".join(e["variants"]), "; ".join(e.get("via_ztna") or []), e["why"]])
    kinds = {}
    for e in report["logons"]:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    people = [e for e in report["logons"] if e["kind"] in ("person", "person (admin)")]
    print(f"Logons {report['window'][0]} → {report['window'][1]} UTC: "
          f"{len({e['person_key'] for e in people})} people (distinct account names; one person's admin accounts "
          f"count apart) on "
          f"{len({e['host'] for e in people})} servers ({kinds.get('person', 0) + kinds.get('person (admin)', 0)} "
          f"person/server pairs). Other pairs: "
          + (", ".join(f"{k} {v}" for k, v in sorted(kinds.items()) if k not in ("person", "person (admin)")) or "none")
          + f". Listed below: {', '.join(sorted(keep))}" + ("" if a.all_accounts else " (system hidden: --all-accounts)"))
    for k, s_ in report["sources"].items():
        print(f"  {k}: {s_['table']}, {s_['rows']} grouped rows, times are {s_['time_basis']}"
              + (f"  ERROR {s_['error']}" if s_["error"] else ""))
    tzz = get_tz(a.tz)
    fmt_t = lambda v: ((to_local(v, tzz) if tzz else v) or "")[:19]
    quiet_cut = fmt_epoch(to_s - 86400)
    stopped = sorted({(e["host"] or "").split(".")[0].lower() for e in shown
                      if lastseen.get((e["host"] or "").split(".")[0].lower(), "9") < quiet_cut})
    named = [h for h in stopped if not EPHEMERAL.search(h)]
    if stopped:
        print(f"\nServers that STOPPED LOGGING inside the window (logons after the last event can't be seen): "
              + (", ".join(f"{h} (last {lastseen[h][:16]})" for h in named[:20]) or "none with fixed names")
              + (f"; plus {len(stopped) - len(named)} auto-named cloud instances (autoscaling)" if len(stopped) > len(named)
                 else ""))
    report["stopped_logging"] = {h: lastseen[h] for h in stopped}
    servers = {}
    for e in shown:
        sv = servers.setdefault((e["os"], e["host"]), {"people": set(), "accounts": 0, "logons": 0, "first": None,
                                                       "last": None, "sources": {}})
        if e["kind"] in ("person", "person (admin)"):
            sv["people"].add(e["person_key"])
            sv["person_logons"] = sv.get("person_logons", 0) + e["logons"]
        sv["accounts"] += 1
        sv["logons"] += e["logons"]
        for f_, pick in (("first", min), ("last", max)):
            vals = [x for x in (sv[f_], e[f_]) if x]
            sv[f_] = pick(vals) if vals else None
        for src, n in e["sources"].items():
            sv["sources"][src] = sv["sources"].get(src, 0) + n
    srows = sorted(servers.items(), key=lambda kv: (-len(kv[1]["people"]), -kv[1]["logons"]))
    if ztna and not ztna[5]:
        conn, by_srv = set(), {}
        for r in ztna[4]:
            if r.get("ConnectorIP"):
                conn.add(r["ConnectorIP"])
            h = (r.get("Host") or "").split(".")[0].lower()
            by_srv.setdefault(h, {}).setdefault(r.get("Username") or "?", 0)
            by_srv[h][r.get("Username") or "?"] += r.get("n") or 0
        report["ztna"] = {"connector_ips": sorted(conn), "users_by_server": {h: sorted(u) for h, u in by_srv.items()}}
        for e in report["logons"]:
            if set(e["sources"]) & conn:
                e["via_ztna"] = sorted(by_srv.get((e["host"] or "").split(".")[0].lower(), {}))[:10]
        print(f"\nZTNA (vpn.zscaler.access, RDP/SSH ports): {len(conn)} connector IPs; people who reached each server "
              "through it (ZPA connection records over the window, not logons; ingestion time). Only servers whose logon "
              "sources include a connector IP or 0.0.0.0 are attributed this way:")
        for (os_, host), v in srows[: a.limit]:
            us = by_srv.get((host or "").split(".")[0].lower())
            if us and set(v["sources"]) & (conn | {"0.0.0.0"}):
                print(f"  {host}: " + ", ".join(f"{u} ({n})" for u, n in sorted(us.items(), key=lambda kv: -kv[1])[:8]))
    elif ztna and ztna[5]:
        print(f"# ZTNA lookup failed: {ztna[5]}", file=sys.stderr)
    print(f"\nPer server (showing {min(a.limit, len(srows))} of {len(srows)} servers with any listed account, sorted by "
          "people; the CSV/JSON have all):")
    write_rows(sys.stdout, "table", [("os", ""), ("host", ""), ("people", ""), ("person logons", ""), ("accounts", ""),
                                     ("all logons", ""), ("first", ""), ("last", ""), ("top sources", "")],
               [[k[0], k[1], len(v["people"]), v.get("person_logons", 0), v["accounts"], v["logons"], fmt_t(v["first"]),
                 fmt_t(v["last"]),
                 ", ".join(x for x, _ in sorted(v["sources"].items(), key=lambda kv: -kv[1])[:3])]
                for k, v in srows[: a.limit]], a.width)
    by_os = {}
    for e in sorted(shown, key=lambda e: -e["logons"]):
        by_os.setdefault(e["os"], []).append(e)
    share = max(5, a.limit // max(1, len(by_os)))
    for os_, lst in by_os.items():
        print(f"\nTop {min(share, len(lst))} of {len(lst)} {os_} pairs (by logons):")
        write_rows(sys.stdout, "table", [("host", ""), ("account", ""), ("kind", ""), ("logons", ""), ("how", ""),
                                         ("first", ""), ("last", ""), ("top sources", "")],
                   [[e["host"], e["account"] + (f" (+{len(e['variants'])} case variants)" if e["variants"] else ""),
                     e["kind"], e["logons"], ", ".join(f"{k} {v}" for k, v in e["how"].items()), fmt_t(e["first"]),
                     fmt_t(e["last"]), ", ".join(e["sources"])] for e in lst[:share]], a.width)
    if a.out:
        with open(a.out, "w") as f:
            json.dump(report, f, indent=1, ensure_ascii=False)
    sys.stdout.flush()
    print(f"# {len(shown)} pairs listed ({', '.join(sorted(keep))}); 'logons' counts 4624 events (admin logons write "
          "two: elevated and filtered; unlocks add more), so use first/last rather than counts; every pair, with the "
          "reason for each label, is in "
          f"{a.out or a.csv or '--out FILE / --csv FILE'}; {time.time() - start:.0f}s."
          + (f" {len(before)} pair(s) have a first event time before the window (back-filled records)." if before else "")
          + ("" if a.include_network else " Network logons (type 3: file shares, admin tools, DC traffic) are NOT "
             "counted: a user with no pairs may still have them (--include-network).")
          + " Windows: 4624 types 2/7/10/11 (unlocks inflate counts; RDP sources are often 0.0.0.0 or a jump host /"
          " ZTNA connector IP: resolve those in the ZTNA logs). Linux: sshd Accepted, including SFTP sessions (no"
          " su/sudo). kind is a heuristic: confirm service/partner accounts and record them with `devo.py cache"
          " service set '<glob>,...'`. A server that stopped logging is silently absent: check `health`.",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------- creds (credential-attack summary)

CRED_CODES = {50126: "bad password", 50053: "locked (smart lockout)", 50034: "no such user"}
# the password was right but the sign-in was stopped (MFA, Conditional Access, expired password...)
PASSWORD_OK_CODES = {50074: "MFA required", 50076: "MFA required", 50079: "MFA registration required",
                     50072: "MFA registration required", 53003: "blocked by Conditional Access",
                     500121: "MFA failed", 50158: "external security challenge", 530032: "blocked by security defaults",
                     50055: "password expired", 50144: "password expired (AD)"}


SUBSTATUS = {"0xc000006a": "bad password", "0xc0000064": "no such user", "0xc0000234": "locked out",
             "0xc0000072": "disabled", "0xc000006f": "outside logon hours", "0xc0000070": "workstation restriction",
             "0xc0000071": "password expired", "0xc0000193": "account expired", "0xc0000133": "clock skew",
             "0xc000015b": "logon type not granted"}


def is_public_ip(v):
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(v).strip().split("%")[0])
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified)


def slash24(ip):
    ip = str(ip or "")
    if ":" in ip:
        return ":".join(ip.split(":")[:3]) + "::/48"  # one ISP customer/site prefix; /64s rotate
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


def creds_stage2(a):
    """Interpret stage 2: for each success from a failing IP, is it the attacked account or someone else,
    and is that range normal for the user (their 30-day history)? Writes stage3.jsonl with baselines for
    the other successful users."""
    d = os.path.abspath(os.path.expanduser(a.dir))
    s2 = os.path.abspath(os.path.expanduser(a.stage2_dir))

    def rows(base, name):
        path = os.path.join(base, f"{name}.jsonl")
        return list(_read_jsonl(path)) if os.path.exists(path) else []

    failed = {}
    for name in ("entra_failures", "entra_failures_noninteractive"):
        for r in rows(d, name):
            if r.get("properties_status_errorCode") in CRED_CODES:
                failed.setdefault(r.get("properties_ipAddress"), set()).add((r.get("properties_userPrincipalName") or "").lower())
    win0 = ""
    try:
        with open(os.path.join(d, "batch-summary.json")) as f:
            win0 = min(j["range"][0] for j in json.load(f)["jobs"] if j.get("range"))
    except (OSError, ValueError, KeyError):
        pass
    first_fail = min([r.get("first") for n_ in ("entra_failures", "entra_failures_noninteractive") for r in rows(d, n_)
                      if r.get("first") and r.get("properties_status_errorCode") in CRED_CODES] or [""])
    if first_fail:
        win0 = first_fail  # the attack window starts at the first credential failure, not the batch window
    cutoff = fmt_epoch(int(parse_utc(win0).timestamp()) - 86400) if win0 and parse_utc(win0) else ""
    base = {}
    for name in ("targeted_users_baseline", "other_users_baseline"):
        for r in rows(s2, name) + rows(os.path.join(s2, "stage3"), name):
            base.setdefault((r.get("properties_userPrincipalName") or "").lower(), {}).setdefault(
                slash24(r.get("properties_ipAddress")), []).append(r.get("first") or "")
    p = print
    fail_n = {}
    for name in ("entra_failures", "entra_failures_noninteractive"):
        for r in rows(d, name):
            if r.get("properties_status_errorCode") in CRED_CODES:
                k = (r.get("properties_ipAddress"), (r.get("properties_userPrincipalName") or "").lower())
                fail_n[k] = fail_n.get(k, 0) + (r.get("n") or 0)
    pairs, others = {}, set()
    for name in ("success_from_failing_ips_signin", "success_from_failing_ips_noninteractive_user_signin"):
        for r in rows(s2, name):
            ip, u = r.get("properties_ipAddress"), (r.get("properties_userPrincipalName") or "").lower()
            e = pairs.setdefault((u, ip), {"n": 0, "apps": set(), "cc": r.get("properties_location_countryOrRegion"),
                                           "blocked": {}, "devices": set()})
            if r.get("properties_deviceDetail_displayName") and r.get("properties_deviceDetail_trustType"):
                e["devices"].add(f"{r['properties_deviceDetail_displayName']} ({r['properties_deviceDetail_trustType']})")
            code = r.get("properties_status_errorCode") or 0
            if code:
                e["blocked"][PASSWORD_OK_CODES.get(code, code)] = e["blocked"].get(PASSWORD_OK_CODES.get(code, code), 0) + (r.get("n") or 0)
            else:
                e["n"] += r.get("n") or 0
            e["apps"].add(r.get("properties_appDisplayName") or "?")
    acct_per_ip = {}
    for (u, ip) in pairs:
        acct_per_ip.setdefault(ip, set()).add(u)
    stage3_ran = os.path.isdir(os.path.join(s2, "stage3"))
    attacker24 = {slash24(ip) for ip, us in failed.items() if us}
    egress2 = {ip for ip, us in acct_per_ip.items() if len(us) >= a.egress_users}
    held = {}
    hits = []
    for (u, ip), e in pairs.items():
        if ip in egress2:
            held[ip] = held.get(ip, 0) + 1
            continue
        same = u in failed.get(ip, set())
        hist = sorted(x for x in base.get(u, {}).get(slash24(ip), []) if x)
        before = [x for x in hist if not cutoff or x < cutoff]
        nf = fail_n.get((ip, u), 0)
        verdict = ("SAME account that failed from this IP" if same else "a DIFFERENT account than the ones attacked")
        if e["blocked"] and not e["n"]:
            verdict = ("PASSWORD VALID, blocked by " + ", ".join(e["blocked"]) + f" ({verdict.lower()}): treat as a "
                       "compromised password unless it is the user's own device")
        if before:
            verdict += (f"; the user already used this range on {before[0][:10]}, before the attack window "
                        "(their own or a shared range: likely benign)")
            if slash24(ip) in attacker24 and not same:
                verdict += "; note the same range also carried attack traffic against other accounts"
        elif e["devices"] and e["n"]:  # MFA prompts alongside real successes are normal for the user
            verdict += (f"; from a joined/registered device: {', '.join(sorted(e['devices'])[:2])}: likely the user's own "
                        "managed device (check the device belongs to them)")
        elif same and nf <= 2 and e["n"] >= 5 and len(e["apps"]) >= 2:
            verdict += (f"; {nf} failure(s) then normal use of {len(e['apps'])} apps from the same IP: likely the user's "
                        "own device after a typo (confirm with the user)")
        elif u in base:
            verdict += ("; this range is new for the user (not seen before the attack window"
                        + (f" began {win0[:10]}" if win0 else "") + "): INVESTIGATE"
                        + (f" (devices: {', '.join(sorted(e['devices'])[:2])})" if e["devices"] else ""))
        elif stage3_ran:
            verdict += "; the user has no successful sign-in in the last 30 days (no baseline exists): INVESTIGATE"
        else:
            verdict += "; no baseline yet for this user (stage 3)"
            others.add(u)
        hits.append((u, ip, e["n"], ", ".join(sorted(e["apps"]))[:60], e["cc"], verdict))
    count = lambda w: sum(1 for h in hits if w in h[5])
    pending = count("stage 3")
    p(f"Successes (or valid passwords stopped by MFA/CA) from failing IPs: {len(hits)} account/IP pair(s): "
      f"{count('INVESTIGATE')} to investigate, {count('PASSWORD VALID')} valid password, {count('likely benign')} "
      f"likely benign, {count('own device') + count('managed device')} likely the user's own device"
      + (f", {pending} PENDING a baseline: run stage 3 (below) before concluding" if pending else "")
      + f"; attack window from {win0[:16] or '?'}")
    if held:
        p("  held back as shared egress (>= %d accounts succeed from each; not attacks): " % a.egress_users
          + ", ".join(f"{ip} ({n} pairs)" for ip, n in sorted(held.items(), key=lambda kv: -kv[1])))
    for u, ip, n, app, cc, v in sorted(hits, key=lambda h: ("PASSWORD VALID" not in h[5], "INVESTIGATE" not in h[5],
                                                            "SAME" not in h[5])):
        p(f"  {u:<40} {ip:<40} {n:>5}× {cc or ''} {app or ''}\n      → {v}")
    for name, what in (("linux_accepted_from_failing_ips", "Linux sshd Accepted"), ("windows_4624_from_failing_ips",
                                                                                     "Windows 4624")):
        rs = rows(s2, name)
        p(f"{what} from the failing public IPs: {len(rs)} group(s)" + ("" if rs else " (only public IPs were checked)"))
    risk = rows(s2, "risk_event_ip_signins")
    if risk:
        ok = [r for r in risk if r.get("properties_status_errorCode") == 0]
        svc = [r for r in risk if re.search(r"print|scan|java/|python|curl|okhttp", f"{r.get('properties_appDisplayName')} "
                                                                                     f"{r.get('properties_userAgent')}", re.I)]
        p(f"\nSign-ins from Identity Protection risk-detection IPs: {len(risk)} groups, {len(ok)} successful. "
          "A passwordSpray detection means Microsoft saw valid passwords among the attempts."
          + (f" {len(svc)} group(s) look like a service/ROPC flow (print/scan app or a library user agent): a common "
             "false positive; compare with a known service account on those IPs." if svc else ""))
        for r in sorted(risk, key=lambda r: -(r.get("n") or 0))[:10]:
            p(f"  {r.get('properties_ipAddress'):<18} {(r.get('properties_userPrincipalName') or ''):<40} code "
              f"{r.get('properties_status_errorCode')}  {r.get('properties_appDisplayName') or ''}  "
              f"{(r.get('properties_userAgent') or '')[:40]}")
    if others and not stage3_ran:
        q = ", ".join(json.dumps(u) for u in sorted(others)[:200])
        out = os.path.join(s2, "stage3.jsonl")
        with open(out, "w") as f:
            f.write(json.dumps({"name": "other_users_baseline", "from": "30d", "to": "now", "chunk": "1d", "parallel": 6,
                                "limit": 0, "query": "from cloud.azure.ad.signin where properties_status_errorCode = 0, "
                                f"properties_userPrincipalName in {{{q}}} group by properties_userPrincipalName, "
                                "properties_ipAddress, properties_location_countryOrRegion select count() as n, "
                                "min(eventdate) as first, max(eventdate) as last"}) + "\n")
        p(f"\nStage 3: baselines for {len(others)} other successful account(s) → {out}\n  run: devo.py batch {out} "
          f"--out-dir {os.path.join(s2, 'stage3')}  then rerun this command")
    return 0


def cmd_creds(cfg, a):
    """Summarise a credential-attack batch (references/specs/credential-attacks.jsonl) offline: spray
    candidates (one IP, many users), distributed brute force (one user, many IPs), on-prem failure
    sources, and write the stage-2 spec that checks whether anything succeeded."""
    d = os.path.abspath(os.path.expanduser(a.dir))

    def rows(name):
        p = os.path.join(d, f"{name}.jsonl")
        return list(_read_jsonl(p)) if os.path.exists(p) else []

    by_ip, by_user, disabled = {}, {}, {}
    for name in ("entra_failures", "entra_failures_noninteractive"):
        for r in rows(name):
            code = r.get("properties_status_errorCode")
            ip, user, n = r.get("properties_ipAddress"), (r.get("properties_userPrincipalName") or "").lower(), r.get("n") or 0
            if code == 50057:
                disabled[user] = disabled.get(user, 0) + n
                continue
            if code not in CRED_CODES or not ip:
                continue
            e = by_ip.setdefault(ip, {"users": set(), "n": 0, "codes": {}, "apps": set(), "first": None, "last": None,
                                      "user_n": {}})
            e["user_n"][user] = e["user_n"].get(user, 0) + n
            e["users"].add(user)
            e["n"] += n
            e["codes"][code] = e["codes"].get(code, 0) + n
            e["apps"].add(r.get("properties_appDisplayName") or r.get("properties_clientAppUsed") or "?")
            u = by_user.setdefault(user, {"ips": set(), "countries": set(), "n": 0, "codes": {}, "apps": {},
                                          "first": None, "last": None})
            app = r.get("properties_appDisplayName") or r.get("properties_clientAppUsed") or "?"
            u["apps"][app] = u["apps"].get(app, 0) + n
            for k, pick in (("first", min), ("last", max)):
                vals = [x for x in (u[k], r.get(k)) if x]
                u[k] = pick(vals) if vals else None
            u["ips"].add(ip)
            u["countries"].add(r.get("properties_location_countryOrRegion") or "?")
            u["n"] += n
            u["codes"][code] = u["codes"].get(code, 0) + n
            for k, pick in (("first", min), ("last", max)):
                vals = [x for x in (e[k], r.get(k)) if x]
                e[k] = pick(vals) if vals else None
    if a.stage2_dir:
        return creds_stage2(a)
    egress = {x.strip() for x in (a.exclude or "").split(",") if x.strip()}
    ok_users = {}
    for r in rows("entra_success_ip_users") + rows("entra_success_ip_users_noninteractive"):
        ok_users.setdefault(r.get("properties_ipAddress"), set()).add((r.get("properties_userPrincipalName") or "").lower())
    auto_egress = {ip for ip, us in ok_users.items() if ip and len(us) >= a.egress_users}
    if auto_egress and not a.keep_egress:
        egress |= auto_egress
    spray = sorted(((ip, e) for ip, e in by_ip.items() if len(e["users"]) >= a.min_users and ip not in egress),
                   key=lambda kv: -len(kv[1]["users"]))
    for e in by_user.values():
        e["ips"] -= egress
    brute = sorted(((u, e) for u, e in by_user.items() if len(e["ips"]) >= a.min_ips),
                   key=lambda kv: -len(kv[1]["ips"]))
    p = print
    try:
        with open(os.path.join(d, "batch-summary.json")) as f:
            for tname, lt in (json.load(f).get("feed_gaps") or {}).items():
                p(f"FEED GAP: {tname} received nothing after {lt[:16]}: 0 rows there is not 'nothing happened'")
    except (OSError, ValueError):
        pass
    p(f"Entra credential failures (codes {', '.join(map(str, CRED_CODES))}; 50057 disabled reported apart): "
      f"{sum(e['n'] for e in by_ip.values())} rows' worth from {len(by_ip)} IPs against {len(by_user)} accounts")
    if auto_egress:
        p(f"\nShared egress IPs (>= {a.egress_users} accounts signed in successfully from each; your NAT/proxy/ZTNA/VDI "
          f"egress, excluded from the candidates{'' if not a.keep_egress else ' NOT: --keep-egress'}): "
          + ", ".join(f"{ip} ({len(ok_users[ip])} ok, {len(by_ip.get(ip, {}).get('users', ()))} failing)"
                      for ip in sorted(auto_egress, key=lambda x: -len(ok_users[x]))[:10]))
    totals = {}
    for ip, e in by_ip.items():
        totals.setdefault(ip, {"entra": 0, "disabled": 0, "windows": 0, "linux": 0, "accounts": set()})
        totals[ip]["entra"] += e["n"]
        totals[ip]["accounts"] |= e["users"]
    for name in ("entra_failures", "entra_failures_noninteractive"):
        for r in rows(name):
            if r.get("properties_status_errorCode") == 50057 and r.get("properties_ipAddress"):
                t_ = totals.setdefault(r["properties_ipAddress"], {"entra": 0, "disabled": 0, "windows": 0, "linux": 0,
                                                                   "accounts": set()})
                t_["disabled"] += r.get("n") or 0
                t_.setdefault("disabled_accounts", set()).add((r.get("properties_userPrincipalName") or "").lower())
    for name, key, ipf, uf in (("windows_4625", "windows", "src", "TargetUserName"),
                               ("linux_ssh_failures", "linux", "src", "account")):
        for r in rows(name):
            ip = r.get(ipf)
            if ip and is_public_ip(ip):
                t_ = totals.setdefault(ip, {"entra": 0, "disabled": 0, "windows": 0, "linux": 0, "accounts": set()})
                t_[key] += r.get("n") or 0
                t_["accounts"].add((r.get(uf) or "?").lower())
    ranked = sorted(((ip, t_) for ip, t_ in totals.items() if is_public_ip(ip)
                     and (t_["entra"] + t_["windows"] + t_["linux"]) > 0.1 * t_["disabled"]),
                    key=lambda kv: -(kv[1]["entra"] + kv[1]["windows"] + kv[1]["linux"] + kv[1]["disabled"]))
    mostly_disabled_ips = sorted(((ip, t_) for ip, t_ in totals.items() if is_public_ip(ip) and t_["disabled"]
                                  and (t_["entra"] + t_["windows"] + t_["linux"]) <= 0.1 * t_["disabled"]),
                                 key=lambda kv: -kv[1]["disabled"])
    mostly_disabled = len(mostly_disabled_ips)
    raw_top = max(((ip, t_["entra"] + t_["disabled"] + t_["windows"] + t_["linux"]) for ip, t_ in totals.items()
                   if is_public_ip(ip)), key=lambda kv: kv[1], default=None)
    if raw_top:
        t_ = totals[raw_top[0]]
        p(f"\nBy raw count (every failure code) the top public IP is {raw_top[0]}: {raw_top[1]} failures, of which "
          f"{t_['disabled']} are 50057 disabled-account retries"
          + (f"; {len(ok_users.get(raw_top[0], ()))} accounts also signed in OK from it (own egress?)"
             if ok_users.get(raw_top[0]) else ""))
    if mostly_disabled_ips:
        p("Left out of the ranking as almost only 50057 (leavers' devices): " + ", ".join(
            f"{ip} ({t_['disabled']}, {len(t_.get('disabled_accounts', ()))} accounts)" for ip, t_ in mostly_disabled_ips[:8])
          + (" …" if len(mostly_disabled_ips) > 8 else ""))
    if ranked:
        p(f"\nTop public IPs by credential failures (all sources; Entra rows can be duplicated where two collectors feed the table; "
          f"{mostly_disabled} IPs with almost only 50057 disabled-account failures are left out):")
        for ip, t_ in ranked[: a.limit]:
            tot = t_["entra"] + t_["disabled"] + t_["windows"] + t_["linux"]
            tag = ""
            if ip in ok_users:
                tag = f"  ← {len(ok_users[ip])} accounts also signed in OK from it" + (": likely your own egress"
                                                                                       if ip in auto_egress else "")
            if t_["disabled"] and t_["disabled"] >= 0.9 * tot:
                tag += "  (mostly 50057 disabled accounts: leavers' devices)"
            if any(re.search(r"qualys|nessus|tenable|rapid7|nosuchuser|^scan", x_, re.I) for x_ in t_["accounts"]):
                tag += "  (scanner-like account names: a vulnerability scan? confirm before blocking)"
            p(f"  {ip:<40} {tot:>8} failures  (credential {t_['entra']}, disabled {t_['disabled']}, windows "
              f"{t_['windows']}, linux {t_['linux']}) {len(t_['accounts'])} accounts with credential failures"
              + (f", {len(t_.get('disabled_accounts', ()))} disabled" if t_.get("disabled_accounts") else "") + tag)
    p(f"\nSpray candidates (one IP, >= {a.min_users} accounts): {len(spray)}")
    for ip, e in spray[: a.limit]:
        p(f"  {ip:<40} {len(e['users']):>4} accounts  {e['n']:>6} failures  {(e['first'] or '')[:16]} → "
          f"{(e['last'] or '')[:16]}  {', '.join(sorted(e['apps']))[:60]}")
    p(f"\nDistributed brute force (one account, >= {a.min_ips} IPs): {len(brute)}")
    latest = max([e["last"] or "" for e in by_user.values()] + [""])
    for u, e in brute[: a.limit]:
        codes = ", ".join(f"{CRED_CODES.get(c, c)} {n}" for c, n in e["codes"].items())
        apps = ", ".join(k for k, _ in sorted(e["apps"].items(), key=lambda kv: -kv[1])[:3])
        ongoing = e["last"] and latest and e["last"] >= fmt_epoch(int(parse_utc(latest).timestamp()) - 3600)
        locked = e["codes"].get(50053, 0) > 0.5 * e["n"]
        p(f"  {u:<45} {len(e['ips']):>4} IPs  {len(e['countries']):>3} countries  {codes}"
          + ("  (mostly lockouts: a correct password can hide behind them)" if locked else "") + "\n"
          f"      {(e['first'] or '')[:16]} → {(e['last'] or '')[:16]}{'  ONGOING' if ongoing else ''}  via {apps}")
    prefix_targets = {}
    for u, e in brute:
        for ip in e["ips"]:
            prefix_targets.setdefault(slash24(ip) if ":" not in ip else ":".join(ip.split(":")[:2]) + "::/32", set()).add(u)
    shared = sorted(((pfx, us) for pfx, us in prefix_targets.items() if len(us) >= 2), key=lambda kv: -len(kv[1]))
    if shared:
        p("\nShared attack infrastructure (ranges used against several of the accounts above: one campaign):")
        for pfx, us in shared[:8]:
            p(f"  {pfx:<28} {len(us)} accounts: {', '.join(sorted(us)[:6])}")
    if disabled:
        p(f"\nDisabled accounts (50057, usually leavers' devices retrying, not an attack): {len(disabled)} accounts, "
          f"{sum(disabled.values())} failures")
    win, anon = {}, {"n": 0, "srcs": set(), "hosts": set()}
    for r in rows("windows_4625"):
        src = r.get("src") or "-"
        if (not (r.get("TargetUserName") or "").strip("- ") and str(r.get("SubStatus") or "").lower() == "0xc0000064"
                and str(r.get("WorkstationName") or "").upper() in ("WORKSTATION", "-", "")):
            anon["n"] += r.get("n") or 0  # anonymous NTLM retries/probes: no account name, user does not exist
            anon["srcs"].add(src)
            anon["hosts"].add(r.get("host"))
            continue
        w = win.setdefault(src, {"users": set(), "n": 0, "hosts": set(), "by_user": {}})
        acct = (r.get("TargetUserName") or "(blank)").lower()
        w["users"].add(acct)
        w["n"] += r.get("n") or 0
        w["hosts"].add(r.get("host"))
        key = (acct, str(r.get("SubStatus") or r.get("Status") or "").lower())
        w["by_user"][key] = w["by_user"].get(key, 0) + (r.get("n") or 0)
    lin = {}
    for r in rows("linux_ssh_failures"):
        src = r.get("src") or "-"
        w = lin.setdefault(src, {"users": set(), "n": 0, "hosts": set()})
        w["users"].add(r.get("account") or "?")
        w["n"] += r.get("n") or 0
        w["hosts"].add(r.get("machine"))
    for title, m in (("Windows 4625 by true source", win), ("Linux sshd failures by source", lin)):
        if not m:
            continue
        pub = sum(1 for s_ in m if is_public_ip(s_))
        p(f"\n{title}: {len(m)} sources ({pub} public)")
        for s_, w in sorted(m.items(), key=lambda kv: -kv[1]["n"])[: a.limit]:
            p(f"  {s_:<40} {'public ' if is_public_ip(s_) else 'private'} {w['n']:>8} failures  {len(w['users']):>4} "
              f"accounts on {len(w['hosts'])} host(s)  e.g. {', '.join(sorted(w['users'])[:3])}")
            if w.get("by_user") and len(w["users"]) > 3:
                top = sorted(w["by_user"].items(), key=lambda kv: -kv[1])[:5]
                p("      top: " + ", ".join(
                    f"{u_} {n_} ({SUBSTATUS.get(ss, ss) or '?'})" + (" ADMIN?" if re.match(r"(adm|admin|da)[._-]", u_)
                                                                    else "") for (u_, ss), n_ in top))
    if anon["n"]:
        p(f"\nWindows anonymous NTLM noise (blank account, workstation WORKSTATION, 0xc0000064): {anon['n']:,} failures "
          f"from {len(anon['srcs'])} sources to {len(anon['hosts'])} host(s): a misbehaving client or probe, not "
          "password guessing (if the sources are ZTNA connectors, map them to devices via ConnectorIP)")
    kerb = rows("windows_kerberos_ntlm")
    if not kerb and os.path.exists(os.path.join(d, "windows_kerberos_ntlm.jsonl")):
        p("\n4771/4776: no rows: Kerberos pre-auth / NTLM validation failures may not be collected (check a DC)")
    risk = rows("risk_detections")
    if risk:
        spr = [r for r in risk if "spray" in str(r.get("properties__riskEventType") or "").lower()]
        p(f"\nIdentity Protection detections: {len(risk)} groups; passwordSpray: {len(spr)} "
          "(check the source IPs' app/user agent against a known service account: cloud print/ROPC flows are a "
          "common false positive)")
    # stage 2: did anything succeed?
    ips = [ip for ip, _ in spray] + [ip for u, e in brute for ip in e["ips"]]
    ips += [ip for ip, _ in ranked[:20]]  # the top of the failure list is always checked
    top_disabled = sorted(((ip, t_) for ip, t_ in totals.items() if is_public_ip(ip) and t_["disabled"]),
                          key=lambda kv: -kv[1]["disabled"])[:5]
    ips += [ip for ip, _ in top_disabled]
    ips += [s_ for s_, w in list(win.items()) + list(lin.items()) if is_public_ip(s_)]
    unchecked = [(ip, f"shared egress ({len(ok_users.get(ip, ()))} accounts signed in OK from it in 7 days)")
                 for ip in dict.fromkeys(ips) if ip in egress]
    ips = [x for x in dict.fromkeys(ips) if x not in egress][: a.max_ips]
    users = [u for u, _ in brute][:200] + [u for ip, e in spray for u in e["users"]][:200]
    users = list(dict.fromkeys(u for u in users if u))[:300]
    q = lambda vals: ", ".join(json.dumps(v) for v in vals)
    jobs = []
    if ips:
        for t in ("cloud.azure.ad.signin", "cloud.azure.ad.noninteractive_user_signin"):
            jobs.append({"name": f"success_from_failing_ips_{t.rsplit('.', 1)[-1]}", "from": a.window, "to": "now",
                         "chunk": "1d", "limit": 0,
                         "query": f"from {t} where properties_status_errorCode in {{0, "
                                  + ", ".join(str(c) for c in PASSWORD_OK_CODES) + "}, "
                                  f"properties_ipAddress in {{{q(ips)}}} "
                                  "group by properties_ipAddress, properties_userPrincipalName, properties_appDisplayName, "
                                  "properties_location_countryOrRegion, properties_status_errorCode, "
                                  "properties_deviceDetail_displayName, properties_deviceDetail_trustType "
                                  "select count() as n, min(eventdate) as first, max(eventdate) as last"})
        pub = [x for x in ips if is_public_ip(x) and ":" not in x][:100]
        if pub:
            jobs.append({"name": "linux_accepted_from_failing_ips", "from": a.window, "to": "now", "chunk": "1d",
                         "limit": 0, "query": 'from box.unix where appName in {"sshd", "sshd-session"}, '
                                              f'message -> "Accepted ", has(message, {q(pub)}) '
                                              "group by machine, message select count() as n"})
            jobs.append({"name": "windows_4624_from_failing_ips", "from": a.window, "to": "now", "chunk": "1d",
                         "limit": 0, "query": f"from box.win_nxlog.security where EventID = 4624, has(Message, {q(pub)}) "
                                              "group by host, TargetUserName, LogonType select count() as n, "
                                              "min(eventdate) as first, max(eventdate) as last"})
    risk_ips = sorted({str(r.get("properties__ipAddress")) for r in risk if r.get("properties__ipAddress")})[:100]
    if risk_ips:
        jobs.append({"name": "risk_event_ip_signins", "from": a.window, "to": "now", "chunk": "1d", "limit": 0,
                     "query": "from cloud.azure.ad.signin where properties_ipAddress in "
                              f"{{{q(risk_ips)}}} group by properties_ipAddress, properties_userPrincipalName, "
                              "properties_status_errorCode, properties_appDisplayName, properties_userAgent "
                              "select count() as n, min(eventdate) as first, max(eventdate) as last"})
    if users:
        jobs.append({"name": "targeted_users_baseline", "from": "30d", "to": "now", "chunk": "1d", "parallel": 6,
                     "limit": 0, "query": "from cloud.azure.ad.signin where properties_status_errorCode = 0, "
                                          f"properties_userPrincipalName in {{{q(users)}}} group by "
                                          "properties_userPrincipalName, properties_ipAddress, "
                                          "properties_location_countryOrRegion, properties_appDisplayName "
                                          "select count() as n, min(eventdate) as first, max(eventdate) as last"})
    out = a.stage2 or os.path.join(d, "stage2.jsonl")
    with open(out, "w") as f:
        for j in jobs:
            f.write(json.dumps(j, ensure_ascii=False) + "\n")
    if unchecked:
        p("\nNot checked in stage 2 (say so in the answer): " + "; ".join(f"{ip}: {why}" for ip, why in unchecked[:10]))
    p(f"\nStage 2 ({len(jobs)} jobs: successes from {len(ips)} failing IPs over {a.window}, sign-ins from "
      f"{len(risk_ips)} risk-detection IPs, baseline of {len(users)} targeted accounts over 30 days) → {out}\n"
      f"  run: devo.py batch {out} --out-dir {os.path.join(d, 'stage2')}\n"
      f"  then: devo.py creds {d} --stage2-dir {os.path.join(d, 'stage2')}   (interprets the successes)")
    print("# counts are rows summed over the batch's groups (duplicated ingestion inflates them; the distinct "
          "IP/account counts are exact). Exclude your own egress/ZTNA IPs with --exclude ip1,ip2 (they dominate "
          "per-IP lists with users' typos). A success from an attacker's /24 needs the user's 30-day history "
          "before it counts as a compromise.", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- grants (privileged grants summary)

PRIV_ROLES = re.compile(r"global admin|privileged (role|authentication) admin|security admin|exchange admin|"
                        r"sharepoint admin|user admin|application admin|cloud application admin|intune admin|"
                        r"conditional access admin|authentication policy admin|hybrid identity admin|"
                        r"^owner$|user access admin|role based access control admin|key vault (admin|secrets officer)|"
                        r"directory writers", re.I)
PRIV_GROUPS = {"domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
               "backup operators", "server operators", "dnsadmins", "group policy creator owners",
               "enterprise key admins", "key admins"}


def pim_kind(op, service, initiator_app):
    o = op or ""
    if service == "Core Directory" and o in ("Add member to role", "Add eligible member to role"):
        return "direct (not PIM)" if (initiator_app or "") != "MS-PIM" else None  # MS-PIM's copy of a PIM change
    if "requested" in o and "completed" not in o:
        return None  # the completed row carries the outcome
    if "(PIM activation)" in o and o.startswith("Add"):
        return "activation"
    if "outside of PIM" in o:
        return "outside PIM"
    if o.startswith("Remove permanent direct role assignment") or ("Remove" in o and "outside of PIM" in o):
        return "removed a direct (non-PIM) assignment"
    if o.startswith("Add member to role in PIM") and "permanent" in o:
        return "permanent active (via PIM)"
    if o.startswith("Add member to role in PIM"):
        return "time-bound active (via PIM)"
    if o.startswith("Add eligible member"):
        return "eligible"
    if o.startswith(("Remove", "Process role removal")):
        return "removal"
    return None


def parse_json_cell(v):
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v) if v else []
    except ValueError:
        return []


def cmd_grants(cfg, a):
    """Summarise a privileged-grants batch (references/specs/privileged-grants.jsonl) offline: Entra and
    PIM role changes classified (activation, permanent active via PIM, eligible, direct non-PIM,
    removals, failures), permanent grants paired with their removal, flags (privileged role,
    self-grant, service account, no approval), and AD privileged-group changes with machine-account
    policy re-adds and domain joins collapsed and SIDs resolved."""
    d = os.path.abspath(os.path.expanduser(a.dir))

    def rows(name):
        path = os.path.join(d, f"{name}.jsonl")
        return list(_read_jsonl(path)) if os.path.exists(path) else []

    p = print
    try:
        with open(os.path.join(d, "batch-summary.json")) as f:
            for tname, lt in (json.load(f).get("feed_gaps") or {}).items():
                p(f"FEED GAP: {tname} received nothing after {lt[:16]}: changes after that are not visible")
    except (OSError, ValueError):
        pass
    seen, grants = {}, []
    for r in rows("entra_role_changes"):
        pid = r.get("properties_id")
        if pid in seen and not seen[pid].get("tenantId"):
            seen[pid] = r  # prefer the copy with tenantId; one per id
        seen.setdefault(pid, r)
    for r in seen.values():
        kind = pim_kind(r.get("operationName"), r.get("properties_loggedByService"),
                        r.get("properties_initiatedBy_app_displayName"))
        if not kind and r.get("properties_result") == "failure":
            kind = "failed request"  # failures only have a "requested" row
        if not kind:
            continue
        targets = parse_json_cell(r.get("targets"))
        details = {x.get("key"): x.get("value") for x in parse_json_cell(r.get("details")) if isinstance(x, dict)}
        if kind == "removed a direct (non-PIM) assignment" and re.search(r"delete", str(details.get("TriggeredByTargetSubType")
                                                                                       or ""), re.I):
            kind = "removal"  # PIM cleaning up after the member object was deleted, not evidence of a direct grant
        role = next((t.get("displayName") for t in targets if t.get("type") == "Role"), None) or \
            (targets[0].get("displayName") if targets else None)
        member = next((t.get("userPrincipalName") or t.get("displayName") for t in targets
                       if t.get("type") in ("User", "Group", "ServicePrincipal")), None)
        mtype = next((t.get("type") for t in targets if t.get("type") in ("User", "Group", "ServicePrincipal")), "")
        scope = next((t.get("displayName") for t in targets if "/subscriptions/" in json.dumps(t) and t.get("type") != "Role"
                      and t.get("displayName")), None)
        plane = "Azure RBAC" if "/subscriptions/" in json.dumps(targets) else (
            "PIM for groups/resources" if r.get("properties_category") == "ResourceManagement" else "Entra role")
        actor = r.get("properties_initiatedBy_user_userPrincipalName") or r.get("properties_initiatedBy_app_displayName") or ""
        g = {"time": r.get("eventdate"), "kind": kind, "plane": plane, "scope": scope, "role": role, "member": member,
             "member_type": mtype,
             "actor": actor, "result": r.get("properties_result"), "reason": r.get("properties_resultReason"),
             "justification": details.get("Justification") or (r.get("properties_resultReason")
                                                                if r.get("properties_result") == "success" else None),
             "approval_required": details.get("IsActivationRequireApproval"),
             "mfa": details.get("IsAuthenticatedWithMfa"), "expires": details.get("ExpirationTime"),
             "ip": details.get("ipaddr"), "op": r.get("operationName")}
        flags = []
        if role and PRIV_ROLES.search(role):
            flags.append("privileged role")
        if member and actor and member.lower() == actor.lower():
            flags.append("self-grant")
        if mtype == "ServicePrincipal" or (member and re.search(r"service|svc|^sa[._-]", member, re.I)):
            flags.append("service account")
        if kind == "activation" and str(g["approval_required"]).lower() == "false":
            flags.append("no approval")
        j = (g["justification"] or "").strip()
        if j and (len(j) < 4 or re.search(r"last day|leaving|test|temp|asdf|xxx", j, re.I)):
            flags.append(f"justification: {j[:30]!r}")
        g["flags"] = flags
        grants.append(g)
    grants.sort(key=lambda g: g["time"] or "")
    ok = [g for g in grants if g["result"] == "success"]
    # pair permanent/time-bound active grants with the next removal of the same member and role
    for g in ok:
        if g["kind"].startswith(("permanent", "time-bound", "direct", "outside")):
            rem = next((x for x in ok if x["kind"] == "removal" and x["time"] > g["time"] and x["member"] == g["member"]
                        and x["role"] == g["role"]), None)
            if rem:
                secs = (parse_utc(rem["time"]) - parse_utc(g["time"])).total_seconds()
                g["removed"] = f"{rem['time'][:16]} ({human_secs(secs)} later, by {rem['actor'] or '?'})"
            else:
                g["removed"] = "NOT removed in the window: may still be active"
    window = ""
    try:
        with open(os.path.join(d, "batch-summary.json")) as f:
            rng = [j.get("range") for j in json.load(f)["jobs"] if j["name"] == "entra_role_changes"][0]
            window = f"{rng[0]} → {rng[1]} UTC"
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        pass
    p(f"Entra / PIM role changes {window}: {len(seen)} distinct audit records, {len(ok)} successful changes classified")
    for title, kinds in (("Direct grants outside PIM", ("direct (not PIM)", "outside PIM")),
                         ("Direct (non-PIM) assignments removed: evidence of earlier grants outside PIM",
                          ("removed a direct (non-PIM) assignment",)),
                         ("Permanent active assignments made through PIM (no activation, approval or expiry)",
                          ("permanent active (via PIM)",)),
                         ("Time-bound active assignments made by an admin", ("time-bound active (via PIM)",)),
                         ("Eligibility granted", ("eligible",))):
        lst = [g for g in ok if g["kind"] in kinds]
        p(f"\n{title}: {len(lst)}")
        for g in lst[: a.limit]:
            p(f"  {g['time'][:16]}  {g['plane']:<12} {g['role'] or '?'}" + (f" on {g['scope']}" if g.get("scope") else "")
              + f" → {g['member'] or '?'} by {g['actor'] or '?'}"
              + (f"  [{', '.join(g['flags'])}]" if g["flags"] else "")
              + (f"\n      removed: {g['removed']}" if g.get("removed") else "")
              + (f"\n      justification: {cell(g['justification'], 100)}" if g.get("justification") else ""))
    act = [g for g in ok if g["kind"] == "activation"]
    summ = {}
    for g in act:
        k = (g["member"], g["role"] + (f" on {g['scope']}" if g.get("scope") else ""), g["plane"])
        s_ = summ.setdefault(k, {"n": 0, "noappr": 0, "mfa_null": 0, "flags": set(), "just": set()})
        s_["n"] += 1
        s_["noappr"] += "no approval" in g["flags"]
        s_["mfa_null"] += g["mfa"] in (None, "", "null")
        s_["flags"] |= set(g["flags"]) - {"self-grant", "no approval"}
        if g.get("justification"):
            s_["just"].add(cell(g["justification"], 40))
    p(f"\nPIM activations (self-service, time-limited): {len(act)} by {len({k[0] for k in summ})} accounts")
    for (m, r_, pl), s_ in sorted(summ.items(), key=lambda kv: -kv[1]["n"])[: a.limit]:
        p(f"  {m or '?':<45} {r_ or '?':<35} {s_['n']:>4}×  {pl}"
          + (f"  approval not required on {s_['noappr']}" if s_["noappr"] else "")
          + (f"  [{', '.join(sorted(s_['flags']))}]" if s_["flags"] else "")
          + (f"  e.g. \"{next(iter(s_['just']))}\"" if s_["just"] else ""))
    if any(s_["mfa_null"] for s_ in summ.values()):
        p("  (MFA is not recorded on some activations, typically PIM for Azure resources: null is not 'no MFA')")
    fails = [g for g in grants if g["result"] != "success"]
    if fails:
        reasons = {}
        for g in fails:
            reasons[g["reason"] or "?"] = reasons.get(g["reason"] or "?", 0) + 1
        p(f"\nFailed requests: {len(fails)} (" + ", ".join(f"{k} {v}" for k, v in sorted(reasons.items(), key=lambda kv: -kv[1])) + ")")
        per = {}
        for g in fails:
            k = (g["actor"], g["role"], g["reason"])
            per[k] = per.get(k, 0) + 1
        for (act_, role_, why), n_ in sorted(per.items(), key=lambda kv: -kv[1])[: a.limit]:
            p(f"  {n_:>3}× {act_ or '?'} → {role_ or '?'}: {cell(why or '?', 70)}")
    # Azure RBAC visibility: from the batch's own probes, else the cached table list
    probe = [r.get("object") for r in rows("azure_tables")]
    have = set(probe) if probe else cached_table_set()
    sources = sorted({r.get("data_source") for r in rows("cloud_audit_sources") if r.get("data_source")})
    if sources:
        p(f"\nDefender CloudAuditEvents (cloud.azure.others.events) data sources in the last day: {', '.join(sources)}"
          + ("" if any(re.search(r"resource manager|arm|azure$|subscription", x_, re.I) for x_ in sources) else
             ": no Azure Resource Manager audit there, so it doesn't show RBAC changes"))
    if have is None:
        p("\nAzure RBAC: visibility unknown (no table list: rerun the spec, which probes it, or `devo.py tables`)")
    if have is not None:
        act_tables = [t for t in have if re.search(r"azure\.(activity|.*administrative)", t)]
        p("\nAzure RBAC: " + (f"Activity Log table(s) present ({', '.join(act_tables)}): query "
                              "Microsoft.Authorization/roleAssignments/write there for direct assignments" if act_tables
                              else "no Azure Activity Log table in this domain, so direct RBAC role assignments are NOT "
                                   "visible; only those made through PIM appear above. Say so in the answer"
                                   + (" (check the DataSource of Defender CloudAuditEvents in cloud.azure.others.events "
                                      "first: investigations.md §4)" if "cloud.azure.others.events" in have else "") + "."))
    p("Not covered by this batch: membership changes to role-assignable Entra groups (GroupManagement), which grant "
      "roles without PIM role operations.")
    # AD
    sids = {}
    for r in rows("sid_names"):
        sids[r.get("TargetUserSid")] = f"{r.get('TargetDomainName')}\\{r.get('TargetUserName')}"
    created = {(r.get("host"), r.get("TargetSid")): r for r in rows("ad_accounts_created")}
    for r in rows("ad_accounts_created"):
        if r.get("TargetSid") and r.get("TargetUserName"):
            sids.setdefault(r["TargetSid"], f"{r.get('host')}\\{r.get('TargetUserName')}")

    def subject_flags(r):
        out = []
        if str(r.get("SubjectUserSid") or "").endswith("-500"):
            out.append("BUILT-IN Administrator (RID 500)" + (f", renamed '{r.get('SubjectUserName')}'"
                                                              if (r.get("SubjectUserName") or "").lower() != "administrator"
                                                              else ""))
        dom, host = (r.get("SubjectDomainName") or "").upper(), (r.get("host") or "").split(".")[0].upper()
        if dom and host and dom == host:
            out.append("local account (not AD): no per-person accountability")
        return out
    adds = [r for r in rows("ad_group_changes") if r.get("EventID") in (4728, 4732, 4756, "4728", "4732", "4756")]
    priv = [r for r in adds if (r.get("TargetUserName") or "").lower() in PRIV_GROUPS]
    machine = [r for r in priv if (r.get("SubjectUserName") or "").endswith("$")]
    join = [r for r in machine if str(r.get("MemberSid") or "").endswith("-512")]
    people = [r for r in priv if not (r.get("SubjectUserName") or "").endswith("$")]
    domain_groups = [r for r in people if (r.get("TargetUserName") or "").lower() != "administrators"]
    p(f"\nAD privileged groups: {len(priv)} add groups ({len(machine)} by machine accounts: policy re-adds / "
      f"Restricted Groups, incl. {len(join)} domain-join adds of Domain Admins -512; collapsed)")
    p(f"  Domain-level privileged groups changed by people: {len(domain_groups)}")
    for r in sorted(people, key=lambda r: r.get("first") or "")[: a.limit * 2]:
        sid = r.get("MemberSid") or ""
        who = r.get("MemberName") if r.get("MemberName") not in (None, "", "-") else sids.get(sid, sid)
        new_local = (r.get("host"), sid) in created
        fl = subject_flags(r) + (["account created on this host in the window"] if new_local else []) + \
            (["Domain Admins -512: domain join?"] if sid.endswith("-512") else [])
        p(f"  {(r.get('first') or '')[:16]}  {r.get('host')}: {r.get('SubjectUserName')} added {who} to "
          f"{r.get('TargetUserName')} ({r.get('n')}×)" + (f"  [{'; '.join(fl)}]" if fl else ""))
    custom = [r for r in adds if (r.get("TargetUserName") or "").lower() not in PRIV_GROUPS
              and re.search(r"admin|operator|owner|priv|tier ?0|local ?admin|root|sudo", r.get("TargetUserName") or "", re.I)
              and not (r.get("SubjectUserName") or "").endswith("$")]
    if custom:
        p(f"\nPossibly privileged custom groups changed by people (names look admin-like; confirm locally): {len(custom)}")
        for r in sorted(custom, key=lambda r: r.get("first") or "")[: a.limit]:
            sid = r.get("MemberSid") or ""
            who = r.get("MemberName") if r.get("MemberName") not in (None, "", "-") else sids.get(sid, sid)
            p(f"  {(r.get('first') or '')[:16]}  {r.get('host')}: {r.get('SubjectUserName')} added {who} to "
              f"{r.get('TargetUserName')}")
    dcs = sorted({r.get("host") for r in rows("ad_group_changes") if r.get("EventID") in (4728, 4756, "4728", "4756")})
    p(f"\nHosts reporting global/universal group changes (4728/4756; DCs among them): {', '.join(dcs) or 'none'}: "
      "a DC missing here means its changes are invisible (check with `coverage`)")
    local_made = [r for r in rows("ad_accounts_created") if not (r.get("SubjectUserName") or "").endswith("$")]
    if local_made:
        p(f"\nAccounts created (4720) by people: {len(local_made)}"
          + (f" (showing {a.limit}; all in ad_accounts_created.jsonl)" if len(local_made) > a.limit else ""))
        for r in sorted(local_made, key=lambda r: r.get("first") or "")[: a.limit]:
            fl = subject_flags(r)
            p(f"  {(r.get('first') or '')[:16]}  {r.get('host')}: {r.get('SubjectUserName')} created {r.get('TargetUserName')}"
              + (f"  [{'; '.join(fl)}]" if fl else ""))
    print("# Classification uses the PIM operation names (investigations.md §4 Privileged grants). Removal pairing "
          "matches the next removal of the same member and role; check unpaired permanent grants in the portal.",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------- local cache (domain data)
#
# Nothing about a particular Devo domain ships with the skill. The first time a command needs the
# domain's table list, a table's schema or field profile, the validated sweep sources or the verified
# event-time families, it fetches them live and caches them on this machine (never in the skill
# directory). Entries expire (TTL below), are marked stale when a query contradicts them (an "Unknown
# table" or "Unknown identifier" for something the cache said exists), and can be refreshed, verified
# or cleared with `devo.py cache ...`. The files in references/hints/ are generic seeds: the cache holds
# the domain-validated copies that the commands actually read.

CACHE_VERSION = 1
DAY = 86400
TTL = {"tables": 7 * DAY, "schema": 30 * DAY, "fields": 30 * DAY, "field-map": 30 * DAY,
       "event-time": 30 * DAY, "sources": 7 * DAY}  # notes and naming never expire (they are reviewed)
NOTE_REVIEW = 90 * DAY  # notes not re-verified for this long are flagged for review
DEFAULT_NAMING = ["{upn}", "{first}.{last}", "{f}{last}"]
NOT_SWEPT = re.compile(r"^(siem|devo)\.|^my\.lookup|(^|\.)all(\.|$)|_all$")  # internal and union tables
CACHE_NAME = re.compile(r"^[A-Za-z0-9_-]+(/[A-Za-z0-9_.-]+)?$")
TABLES_WINDOW = "7d"
CACHE = None  # the active Cache, set by main()


def cache_root(env=None):
    env = os.environ if env is None else env
    if env.get("DEVO_CACHE_DIR"):
        return os.path.abspath(os.path.expanduser(env["DEVO_CACHE_DIR"]))
    return os.path.join(env.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "devo-skill")


def cache_key(cfg, env=None):
    """The cache directory name for a domain: DEVO_CACHE_KEY when set (keeps the cache across token
    rotations), otherwise the region plus a hash of the token (the token itself is never stored)."""
    env = os.environ if env is None else env
    key = env.get("DEVO_CACHE_KEY") or (cfg or {}).get("cache_key")
    if key:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key) or key in (".", ".."):
            raise DevoError(f"DEVO_CACHE_KEY {key!r}: use letters, digits and . _ - only", code=1)
        return key
    import hashlib
    digest = hashlib.sha256(f"{cfg['region']}:{cfg['token']}".encode()).hexdigest()[:16]
    return f"{cfg['region']}-{digest}"


class Cache:
    """One directory per domain, one JSON file per entry: {version, fetched, stale, data, ...}."""

    def __init__(self, cfg, root=None, env=None):
        env = os.environ if env is None else env
        self.root = os.path.abspath(root or cache_root(env))
        self.dir = os.path.join(self.root, cache_key(cfg, env))
        if os.path.commonpath([os.path.abspath(self.dir), SKILL_DIR]) == SKILL_DIR:
            raise DevoError("the cache must not live inside the skill directory", code=1)
        cap = env.get("DEVO_CACHE_MAX_AGE_DAYS")
        try:
            self.cap = float(cap) * DAY if cap else None
        except ValueError:
            raise DevoError(f"DEVO_CACHE_MAX_AGE_DAYS {cap!r} is not a number", code=1)

    def path(self, name):
        if not CACHE_NAME.match(name) or ".." in name:
            raise DevoError(f"bad cache entry name {name!r}", code=1)
        return os.path.join(self.dir, *name.split("/")) + ".json"

    def ttl(self, name):
        t = TTL.get(name.split("/")[0])
        return min(t, self.cap) if t and self.cap is not None else t

    def read(self, name):
        try:
            with open(self.path(name)) as f:
                e = json.load(f)
        except (OSError, ValueError):
            return None
        return e if isinstance(e, dict) and e.get("version") == CACHE_VERSION and "data" in e else None

    def state(self, name, e=None):
        e = self.read(name) if e is None else e
        if e is None:
            return "missing"
        if e.get("stale"):
            return "stale"
        ttl = self.ttl(name)
        return "expired" if ttl is not None and time.time() - e.get("fetched", 0) > ttl else "fresh"

    def get(self, name, allow_old=False):
        """The entry's data when fresh (or, with allow_old, whatever is there), else None."""
        e = self.read(name)
        if e is None:
            return None
        return e["data"] if allow_old or self.state(name, e) == "fresh" else None

    def mkdirs(self, d):
        """Create d and every directory from the cache root down to it as 0700, and tighten any that
        already exist (makedirs applies its mode to the last directory only): domain data is for
        the user's eyes only."""
        os.makedirs(os.path.dirname(self.root), exist_ok=True)  # e.g. ~/.cache: not ours to change
        rel = os.path.relpath(d, self.root)
        parts = [] if rel == "." else rel.split(os.sep)
        cur = self.root
        for part in [None] + parts:
            cur = cur if part is None else os.path.join(cur, part)
            try:
                os.mkdir(cur, 0o700)
            except FileExistsError:
                pass
            if stat.S_IMODE(os.stat(cur).st_mode) != 0o700:
                os.chmod(cur, 0o700)

    def _write(self, name, e):
        path = self.path(name)
        self.mkdirs(os.path.dirname(path))
        tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(e, f, ensure_ascii=False)
        os.replace(tmp, path)

    def put(self, name, data, **extra):
        self._write(name, dict(extra, version=CACHE_VERSION, fetched=int(time.time()), data=data))
        return data

    def invalidate(self, name, reason=""):
        """Mark an entry stale (kept as a fallback, refetched on next use). True if it changed."""
        e = self.read(name)
        if e is None or e.get("stale"):
            return False
        e.update(stale=True, stale_reason=reason)
        self._write(name, e)
        return True

    def drop(self, name):
        try:
            os.remove(self.path(name))
            return True
        except FileNotFoundError:
            return False

    def names(self, prefix=""):
        out = []
        for dirpath, _, files in os.walk(self.dir):
            rel = os.path.relpath(dirpath, self.dir)
            for fn in files:
                if fn.endswith(".json"):
                    n = fn[:-5] if rel == "." else f"{rel.replace(os.sep, '/')}/{fn[:-5]}"
                    if n.startswith(prefix):
                        out.append(n)
        return sorted(out)

    def wipe(self, keep=("notes",)):
        gone = 0
        for n in self.names():
            if n not in keep and self.drop(n):
                gone += 1
        return gone


QUIET = {"cache": False}


def cache_say(msg, noisy=False):
    if noisy and QUIET["cache"]:
        return
    print(f"# cache: {msg}", file=sys.stderr)


def known_fields(d):
    """Field names from a cached schema ([[name, type]]) or profile ({fields, empty})."""
    if isinstance(d, dict):
        return set(d.get("fields") or {}) | set(d.get("empty") or [])
    return {f for f, _ in d or []}


def live_tables(cfg, frm, timeout):
    linq = ("from siem.logtrust.collector.counter where kind = \"table\" "
            "group by object select sum(events) as events")
    frm_e, _ = resolve_time(frm)
    rows = [r for _, r in run_query(cfg, linq, frm_e, resolve_time("now")[0], 0, timeout) if r]
    return sorted(([r[0], r[1] or 0] for r in rows if r[0]), key=lambda x: -x[1])


def domain_tables(cfg, refresh=False, timeout=300):
    """[(table, events in TABLES_WINDOW)]: from the cache, fetched live when missing, expired or stale."""
    c = CACHE
    if c and not refresh:
        d = c.get("tables")
        if d is not None:
            return [tuple(x) for x in d]
    try:
        rows = live_tables(cfg, TABLES_WINDOW, timeout)
    except DevoError as e:
        old = c.get("tables", allow_old=True) if c else None
        if old is None:
            raise
        cache_say(f"live table list failed ({e}); using the cached copy")
        return [tuple(x) for x in old]
    if c:
        before = cached_table_set()
        old = c.read("tables") or {}
        unq = set(old.get("unqueryable") or [])
        if not refresh:  # keep tables known to be unqueryable out of an automatic refetch
            rows = [r for r in rows if r[0] not in unq]
        c.put("tables", rows, window=TABLES_WINDOW, unqueryable=sorted(unq) if not refresh else [])
        if before is not None and before != {t for t, _ in rows}:
            for n in ("sources", "event-time"):  # derived from the table list
                c.invalidate(n, "table list changed")
    return [tuple(x) for x in rows]


def cached_table_set():
    """Table names from the cache (any age), or None when there is no list. Never fetches."""
    d = CACHE.get("tables", allow_old=True) if CACHE else None
    return {t for t, _ in d} if d is not None else None


def schema_fields(cfg, table, refresh=False):
    """[[field, type]] of a table: the live schema, cached."""
    c, name = CACHE, f"schema/{table}"
    if c and not refresh:
        d = c.get(name)
        if d is not None:
            return d
    fields, how = table_fields(cfg, table)
    d = [[f, t] for f, t in fields]
    if c and d:
        c.put(name, d, via=how)
    return d


def table_profile(cfg, table, refresh=False, sample=300, timeout=300):
    """A table's field profile (shapes only): from the cache, or profiled live and cached."""
    c, name = CACHE, f"fields/{table}"
    if c and not refresh:
        d = c.get(name)
        if d is not None:
            return d
    cols, rows, used = sample_table(cfg, table, sample, timeout)
    if not cols:
        raise DevoError(f"{table}: no rows in the last 30 days to profile", "check the name with `devo.py tables`")
    prof = compact_profile({"window": used, "rows": len(rows), "fields": profile_rows(cols, rows)})
    prof["profiled"] = fmt_epoch(int(time.time()))[:10]
    if c:
        c.put(name, prof)
        c.put(f"schema/{table}", [[n, t] for n, t in cols], via="profile sample")
        c.drop("field-map")  # the merged map is rebuilt from the per-table profiles on next use
    return prof


def cached_field_map():
    """The merged field map (every cached profile, any age, with the curated roles applied), itself
    cached as one file so `fields --role` and `timeline` don't read every profile each time."""
    c = CACHE
    if not c:
        return {"tables": {}}
    fm = c.get("field-map")
    if fm is not None:
        return fm
    tables = {}
    for n in c.names("fields/"):
        d = c.get(n, allow_old=True)
        if d:
            tables[n.split("/", 1)[1]] = d
    fm = apply_roles({"tables": dict(sorted(tables.items()))}, FIELD_ROLES)
    if tables:
        c.put("field-map", fm)
    return fm


def cache_mismatch(linq, err, cfg=None):
    """A query failed in a way that contradicts the cache: mark the entries it relied on stale, so the
    next use refetches them."""
    c = CACHE
    if not c:
        return
    msg = str(err)
    low = msg.lower()
    tabs = re.findall(r"\bfrom\s+`?([A-Za-z0-9_.-]+)`?", linq)
    if "unknown table" in low or "access not allowed for table" in low:
        bad = [t for t in tabs if t in (cached_table_set() or set())]
        if bad:
            # the collector counter can list a table that isn't queryable: drop it from the cached list
            # and remember it, rather than refetching a list that would only bring it back
            e = c.read("tables")
            gone = set(e.get("unqueryable") or []) | set(bad)
            c.put("tables", [r for r in e["data"] if r[0] not in gone], window=e.get("window"),
                  unqueryable=sorted(gone))
            c.invalidate("sources", f"{bad[0]} isn't queryable")
            cache_say(f"{bad[0]} is listed by the collector counter but Devo says it doesn't exist: dropped from "
                      "the cached table list (`tables --live` refetches the list)", noisy=True)
    elif "unknown identifier" in low:
        m = re.search(r"identifier\W+`?([A-Za-z_]\w*)", msg, re.I)
        if not m:
            return
        for t in tabs:
            cached = [n for n in (f"fields/{t}", f"schema/{t}")
                      if m.group(1) in known_fields(c.get(n, allow_old=True) or [])]
            if not cached:
                continue
            if cfg:  # confirm against the live schema before doubting the cache
                try:
                    live = {f for f, _ in table_fields(cfg, t)[0]}
                except DevoError:
                    live = set()
                if m.group(1) in live:
                    err.hint = (f"{m.group(1)} exists in {t}: it was probably used after `group by` without being "
                                "a group key (or out of scope in a subquery); add it to the group or aggregate it")
                    continue
            hit = False
            for n in cached:
                if c.invalidate(n, f"Devo doesn't know {m.group(1)}"):
                    hit = True
            if hit:
                c.drop("field-map")
                c.invalidate("sources", f"{t} schema changed")
                cache_say(f"{t}.{m.group(1)} is in the cached schema but Devo doesn't know it: {t}'s cached schema "
                          "and profile are marked stale and will be refetched on next use")


# ---- event time, verified against the domain

def verify_event_time(cfg, tables, timeout=120):
    """The hint families with each expression test-run on the domain's busiest matching table. A family
    whose expression fails or yields nothing falls back to eventdate (linq None); `check` says why."""
    hints = load_event_time(EVENT_TIME)
    vol = dict(tables)
    out = []
    for fam in hints:
        f = dict(fam, lag=[t for t in fam.get("lag", []) if t in vol])
        present = sorted((t for t in vol if event_time_for(t, hints) is fam), key=lambda t: -vol[t])
        if not present:
            f["check"] = "no matching tables in this domain"
        elif not fam.get("linq"):
            f["check"] = "no event-time field for this family (hint)"
        else:
            t = present[0]
            linq = f"from {quote_table(t)} select {fam['linq']} as event_time select eventdate, event_time"
            try:
                rows = []
                for w in ("6h", "3d"):
                    _, frm_s = resolve_time(w)
                    cols, rows, _ = fetch(cfg, linq, frm_s, int(time.time()), 20, timeout)
                    if rows:
                        break
                if not rows:
                    f["check"] = f"{t}: no rows to test it on (kept, unverified)"
                else:
                    i = [n for n, _ in cols].index("event_time")
                    if any(r[i] not in (None, "", 0) for r in rows):
                        f["check"] = f"ok on {t}"
                    else:
                        f["linq"], f["check"] = None, f"{t}: the expression gave no value; using eventdate"
            except (DevoError, ValueError) as e:
                f["linq"], f["check"] = None, f"{t}: the expression failed ({str(e)[:120]}); using eventdate"
        out.append(f)
    return out


def domain_event_time(cfg, refresh=False):
    c = CACHE
    if c and not refresh:
        d = c.get("event-time")
        if d is not None:
            return d
    fams = verify_event_time(cfg, domain_tables(cfg))
    if c:
        c.put("event-time", fams)
    _EVENT_TIME_CACHE.clear()
    return fams


# ---- sweep sources, validated against the domain

LINQ_WORDS = {"and", "or", "not", "as", "in", "select", "where", "group", "by", "every", "from", "true", "false",
              "null", "each", "with"}
SWEEP_TYPES = {"str", "ip4", "ip6", "int4", "int8", "bool", "float8"}


def linq_identifiers(*exprs):
    """Field-like identifiers in LINQ fragments: string literals, {T}, function names and keywords removed."""
    names = set()
    for e in exprs:
        if not e or e.strip() == "*":
            continue
        s = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", e.replace("{T}", " "))
        for m in re.finditer(r"(?<![\w.$`])([A-Za-z_]\w*)\b(?!\s*\()", s):
            if m.group(1).lower() not in LINQ_WORDS:
                names.add(m.group(1))
    return names


def source_fields(src):
    """The fields a sweep source reads (its own aliases excluded)."""
    aliases = set(pre_aliases(src.get("pre"))) | set(pre_aliases(src.get("select"))) | {"event_time"}
    return linq_identifiers(src.get("filter"), src.get("pre"), src.get("group"), src.get("select")) - aliases


def generated_source(table, prof, by):
    """A sweep source for a table the hints don't cover, from its profile: match the fields with the
    `by` role, group by them plus the action, user, IP, host and outcome fields with the best fill."""
    fields = prof.get("fields") or {}

    def pick(role, n, min_fill=0.05):
        c = [(k, f) for k, f in fields.items() if f.get("role") == role and f.get("fill", 0) >= min_fill
             and f.get("type") in SWEEP_TYPES and f.get("len", 0) <= 200
             and not (role in ("user", "host", "ip") and f.get("distinct", 99) <= 3 and prof.get("rows", 0) >= 50)]
        # (an entity field with 1-3 values in a sample of 50+ rows is a collector, pod or tenant, not an entity)
        return [k for k, _ in sorted(c, key=lambda kv: -kv[1]["fill"])[:n]]

    keys = pick(by, 3)
    if not keys:
        return None
    match = [f"{k} = {{T}}" if fields[k]["type"] in ("ip4", "ip6") else f"weakhas({k}, {{T}})" for k in keys]
    group = list(dict.fromkeys(keys + pick("action", 2) + pick("user", 2) + pick("ip", 2) + pick("host", 1)
                               + pick("outcome", 1)))[:8]
    return {"by": by, "name": f"auto_{by}_" + re.sub(r"[^A-Za-z0-9]+", "_", table), "table": table,
            "filter": " or ".join(match), "group": ", ".join(group), "accounts": keys, "generated": True,
            "note": "generated from the field profile; check the results make sense"}


def build_sources(cfg, parallel=6):
    """The hint sweep sources whose table exists and whose fields are all in the live schema, plus
    generated sources for profiled tables the hints don't cover. Cached as `sources`."""
    from concurrent.futures import ThreadPoolExecutor
    hints = load_activity_sources(HINT_SOURCES)
    vol = dict(domain_tables(cfg))
    every = hints["sources"] + [hints["graph"]]
    need = sorted({s["table"] for s in every if s["table"] in vol})

    def schema(t):
        try:
            return t, known_fields(schema_fields(cfg, t)), None
        except DevoError as e:
            return t, None, str(e)

    with ThreadPoolExecutor(max(1, parallel)) as pool:
        got = {t: (f, e) for t, f, e in pool.map(schema, need)}
    kept, skipped, absent = [], [], 0

    def check(s):
        nonlocal absent
        if s["table"] not in vol:
            absent += 1
            return False
        f, err = got[s["table"]]
        missing = sorted(source_fields(s) - (f or set()))
        if f is None or not f or missing:
            skipped.append({"name": s["name"], "table": s["table"],
                            "reason": f"schema unavailable ({err})" if f is None or not f
                            else "fields not in this domain's schema: " + ", ".join(missing)})
            return False
        return True

    kept = [s for s in hints["sources"] if check(s)]
    graph = hints["graph"] if check(hints["graph"]) else None
    covered = {(s.get("by", "user"), s["table"]) for s in kept}
    generated = 0
    for t, prof in cached_field_map()["tables"].items():
        if t not in vol or NOT_SWEPT.search(t):
            continue
        for by in ("user", "ip", "host"):
            g = None if (by, t) in covered else generated_source(t, prof, by)
            if g:
                kept.append(g)
                generated += 1
    data = {"sources": kept, "graph": graph, "skipped": skipped,
            "counts": {"hint": len(kept) - generated, "generated": generated, "skipped": len(skipped),
                       "hint_tables_absent": absent, "profiled_tables": len(cached_field_map()["tables"])}}
    if CACHE:
        CACHE.put("sources", data)
    return data


def domain_sources(cfg, refresh=False):
    c = CACHE
    if c and not refresh:
        d = c.get("sources")
        if d is not None:
            return d
    if c and c.read("sources") is None:
        cache_say("first use: validating the sweep sources against this domain's tables and schemas "
                  "(once; cached for 7 days)")
    return build_sources(cfg)


# ---- notes and naming (kept by the analyst/Claude; never expire, flagged for review)

def load_notes():
    d = CACHE.get("notes", allow_old=True) if CACHE else None
    return d if isinstance(d, dict) else {"notes": [], "naming": None}


def save_notes(d):
    CACHE.put("notes", d)


def naming_templates():
    return load_notes().get("naming") or DEFAULT_NAMING


# ---- the `cache` command

def entry_line(c, name):
    e = c.read(name)
    st = c.state(name, e)
    if e is None:
        return st, ""
    age = human_secs(time.time() - e.get("fetched", 0))
    why = f" ({e['stale_reason']})" if e.get("stale_reason") else ""
    return st, f"{age} old{why}"


def cache_status(c):
    tables = c.get("tables", allow_old=True)
    profiled = c.names("fields/")
    schemas = c.names("schema/")
    fam = c.get("event-time", allow_old=True) or []
    src = c.get("sources", allow_old=True) or {}
    notes = load_notes()
    now = time.time()
    review = [n for n in notes["notes"] if now - n.get("verified", n.get("added", 0)) > NOTE_REVIEW]
    old = [n for n in profiled + schemas if c.state(n) != "fresh"]
    return {
        "dir": c.dir,
        "tables": dict(zip(("state", "age"), entry_line(c, "tables")), count=len(tables or [])),
        "fields": {"profiled": len(profiled), "of": len(tables or []), "schemas": len(schemas),
                   "not_fresh": len(old)},
        "event-time": dict(zip(("state", "age"), entry_line(c, "event-time")),
                           ok=sum(1 for f in fam if (f.get("check") or "").startswith("ok")),
                           fallback=[f["family"] for f in fam if "using eventdate" in (f.get("check") or "")]),
        "sources": dict(zip(("state", "age"), entry_line(c, "sources")), **(src.get("counts") or {})),
        "notes": {"count": len(notes["notes"]), "to_review": len(review),
                  "naming": notes.get("naming") or f"default {DEFAULT_NAMING}"},
    }


def print_cache_status(s):
    p = print
    p(f"Devo cache: {s['dir']}")
    t = s["tables"]
    p(f"  tables      {t['state']:<8} {t['count']} tables {t['age']}")
    f = s["fields"]
    p(f"  fields      {f['profiled']}/{f['of']} tables profiled, {f['schemas']} schemas"
      + (f", {f['not_fresh']} expired or stale" if f["not_fresh"] else ""))
    e = s["event-time"]
    p(f"  event-time  {e['state']:<8} {e['ok']} families verified {e['age']}"
      + (f"; falling back to eventdate: {', '.join(e['fallback'])}" if e["fallback"] else ""))
    so = s["sources"]
    if so["state"] == "missing":
        p("  sources     missing  (built on the first `activity` run, or by `cache build`)")
    else:
        p(f"  sources     {so['state']:<8} {so.get('hint', 0)} from hints, {so.get('generated', 0)} generated, "
          f"{so.get('skipped', 0)} skipped (fields missing) {so['age']}")
    n = s["notes"]
    p(f"  notes       {n['count']} notes" + (f", {n['to_review']} due for re-verification" if n["to_review"] else "")
      + f"; naming {n['naming']}")


def cmd_cache(cfg, a):
    from concurrent.futures import ThreadPoolExecutor
    c = CACHE
    act = a.action
    what = a.what or []
    if act == "status":
        s = cache_status(c)
        if a.json:
            print(json.dumps(s, indent=1))
        else:
            print_cache_status(s)
        return 0
    if act in ("build", "refresh", "verify"):
        start = time.time()
        targets = set(what) or {"all"}
        unknown = targets - {"all", "tables", "fields", "event-time", "sources"}
        tables_arg = [w for w in unknown if "." in w]
        unknown -= set(tables_arg)
        if unknown:
            raise DevoError(f"unknown cache entry {sorted(unknown)[0]!r}",
                            "use tables, fields [TABLE ...], event-time, sources or all", code=1)
        everything = "all" in targets
        refresh = act != "build"
        before = cached_table_set()
        if everything or "tables" in targets or act == "verify":
            tables = domain_tables(cfg, refresh=refresh or c.state("tables") != "fresh", timeout=a.timeout)
            now_set = {t for t, _ in tables}
            if before is not None and before != now_set:
                cache_say(f"table list changed: +{len(now_set - before)} -{len(before - now_set)} "
                          + " ".join([f"+{t}" for t in sorted(now_set - before)][:10]
                                     + [f"-{t}" for t in sorted(before - now_set)][:10]))
                for t in before - now_set:
                    for n in (f"fields/{t}", f"schema/{t}"):
                        c.drop(n)
                c.drop("field-map")
            cache_say(f"{len(tables)} tables with data in the last {TABLES_WINDOW}")
        else:
            tables = domain_tables(cfg)
        vol = dict(tables)
        # which profiles to (re)fetch
        if tables_arg:
            prof_targets = tables_arg
        elif act == "verify":
            prof_targets = []
        elif everything or "fields" in targets:
            if act == "build" and a.profile == "none":
                prof_targets = []
            else:
                cand = [t for t, n in tables if n > 0]
                if act == "refresh":  # re-profile what is cached; `build` adds the rest
                    cached = {n.split("/", 1)[1] for n in c.names("fields/")}
                    cand = [t for t in cand if t in cached]
                elif a.profile not in ("all", "none"):
                    if not a.profile.isdigit():
                        raise DevoError("--profile takes all, none or a number of tables", code=1)
                    cand = cand[:int(a.profile)]
                prof_targets = cand if refresh else [t for t in cand if c.state(f"fields/{t}") != "fresh"]
        else:
            prof_targets = []
        if act == "verify":  # compare every cached schema with the live one; refetch the ones that differ
            cached = [n.split("/", 1)[1] for n in c.names("schema/")]

            def cmp(t):
                if t not in vol:
                    return t, "gone"
                try:
                    live = {f for f, _ in table_fields(cfg, t)[0]}
                except DevoError as e:
                    return t, f"error {e}"
                old = known_fields(c.get(f"schema/{t}", allow_old=True))
                return t, "same" if live == old or not live else "changed"

            with ThreadPoolExecutor(max(1, a.parallel)) as pool:
                res = list(pool.map(cmp, cached))
            changed = [t for t, r in res if r in ("changed", "gone")]
            for t in changed:
                c.drop(f"schema/{t}")
                if t in vol and c.read(f"fields/{t}") is not None:
                    prof_targets.append(t)
                else:
                    c.drop(f"fields/{t}")
            if changed:
                c.drop("field-map")
            cache_say(f"verified {len(res)} cached schemas: {len(changed)} changed or gone"
                      + (f" ({', '.join(changed[:10])})" if changed else ""))
        QUIET["cache"] = True  # one summary line instead of a line per unqueryable table
        if prof_targets:
            cache_say(f"profiling {len(prof_targets)} tables ({a.parallel} at a time; sample {a.sample} rows each)")

            def prof(t):
                try:
                    table_profile(cfg, t, refresh=True, sample=a.sample, timeout=a.timeout)
                    return t, None
                except DevoError as e:
                    return t, str(e)

            with ThreadPoolExecutor(max(1, a.parallel)) as pool:
                errs = [(t, e) for t, e in pool.map(prof, prof_targets) if e]
            for t, e in [x for x in errs if "unknown table" not in x[1].lower()][:10]:
                cache_say(f"profile {t}: {e}")
            cache_say(f"profiled {len(prof_targets) - len(errs)}/{len(prof_targets)} tables")
            unq = (c.read("tables") or {}).get("unqueryable") or []
            if unq:
                cache_say(f"{len(unq)} table(s) listed by the collector counter aren't queryable and were dropped "
                          f"from the list: {', '.join(unq[:8])}{' …' if len(unq) > 8 else ''}")
        if everything or "event-time" in targets or act == "verify":
            if refresh or c.state("event-time") != "fresh":
                fams = domain_event_time(cfg, refresh=True)
                cache_say("event time: " + "; ".join(f"{f['family']}: {f['check']}" for f in fams
                                                       if "no matching tables" not in f.get("check", "")))
        if everything or "sources" in targets or prof_targets or act == "verify":
            d = build_sources(cfg, a.parallel)
            k = d["counts"]
            cache_say(f"sweep sources: {k['hint']} from hints, {k['generated']} generated, {k['skipped']} skipped")
        cache_say(f"{act} done in {time.time() - start:.0f}s")
        print_cache_status(cache_status(c))
        return 0
    if act == "clear":
        if a.all or not what or "all" in what:
            keep = () if a.include_notes else ("notes",)
            n = c.wipe(keep)
            print(f"cleared {n} cache entries in {c.dir}" + ("" if a.include_notes else " (notes and naming kept; "
                                                                "--include-notes removes them too)"))
            return 0
        n = 0
        for w in what:
            if w in ("tables", "event-time", "sources", "field-map"):
                n += c.drop(w)
            elif w == "fields":
                for x in c.names("fields/") + c.names("schema/") + ["field-map"]:
                    n += c.drop(x)
            elif w == "notes":
                n += c.drop("notes")
            else:
                for x in (f"fields/{w}", f"schema/{w}"):
                    n += c.drop(x)
                c.drop("field-map")
        for w in what:  # derived entries follow their inputs
            if w in ("tables", "fields") or "." in w:
                c.invalidate("sources", f"{w} cleared")
        print(f"cleared {n} cache entries")
        return 0
    if act == "notes":
        d = load_notes()
        now = time.time()
        if a.json:
            print(json.dumps(d, indent=1, ensure_ascii=False))
            return 0
        for x in d["notes"]:
            age = now - x.get("verified", x.get("added", 0))
            flag = "  [re-verify]" if age > NOTE_REVIEW else ""
            print(f"{x['id']:>3}  {fmt_epoch(x.get('verified', x.get('added', 0)))[:10]}  {x['text']}{flag}")
        print(f"# {len(d['notes'])} notes; naming {d.get('naming') or 'default ' + str(DEFAULT_NAMING)}",
              file=sys.stderr)
        return 0
    if act == "note":
        d = load_notes()
        if not what:
            raise DevoError("cache note add TEXT | verify ID | rm ID", code=1)
        sub, rest = what[0], what[1:]
        now = int(time.time())
        if sub == "add":
            text = " ".join(rest).strip()
            if not text:
                raise DevoError("cache note add needs the note text", code=1)
            nid = max([x["id"] for x in d["notes"]] + [0]) + 1
            d["notes"].append({"id": nid, "text": text, "added": now, "verified": now})
            save_notes(d)
            print(f"note {nid} added")
            return 0
        if sub in ("verify", "rm") and rest:
            ids = {int(x) for x in rest if x.isdigit()}
            hit = [x for x in d["notes"] if x["id"] in ids]
            if not hit:
                raise DevoError(f"no note with id {', '.join(rest)}", "list them with `devo.py cache notes`", code=1)
            if sub == "rm":
                d["notes"] = [x for x in d["notes"] if x["id"] not in ids]
            else:
                for x in hit:
                    x["verified"] = now
            save_notes(d)
            print(f"{'removed' if sub == 'rm' else 're-verified'} {len(hit)} note(s)")
            return 0
        raise DevoError("cache note add TEXT | verify ID | rm ID", code=1)
    if act == "service":
        d = load_notes()
        if not what or what[0] == "show":
            print(", ".join(d.get("service_accounts") or []) or "(none recorded)")
            return 0
        if what[0] == "reset":
            d["service_accounts"] = []
        elif what[0] in ("set", "add") and len(what) > 1:
            new_ = [x.strip() for x in ",".join(what[1:]).split(",") if x.strip()]
            bad = [x for x in new_ if not re.fullmatch(r"[A-Za-z0-9_.@$*?\-\[\]]+", x)]
            if bad:
                raise DevoError(f"service pattern {bad[0]!r}: use account-name globs like svc-*, ec2-user", code=1)
            d["service_accounts"] = list(dict.fromkeys(((d.get("service_accounts") or []) if what[0] == "add" else [])
                                                       + new_))
        else:
            raise DevoError("cache service show | set GLOB[,GLOB...] | add GLOB[,...] | reset", code=1)
        save_notes(d)
        print("service accounts: " + (", ".join(d["service_accounts"]) or "(none)"))
        return 0
    if act == "naming":
        d = load_notes()
        if not what or what[0] == "show":
            print(", ".join(naming_templates()) + ("" if d.get("naming") else "  (default)"))
            return 0
        if what[0] == "reset":
            d["naming"] = None
        elif what[0] == "set" and len(what) > 1:
            tpl = [x.strip() for x in ",".join(what[1:]).split(",") if x.strip()]
            for x in tpl:
                bad = set(re.findall(r"\{(\w*)\}", x)) - {"upn", "local", "first", "last", "f", "l"}
                if bad or not re.fullmatch(r"[A-Za-z0-9_.@$\-{}]+", x):
                    raise DevoError(f"naming template {x!r}: use {{upn}} {{local}} {{first}} {{last}} {{f}} {{l}} "
                                    "and letters, digits, . _ @ $ -", code=1)
            d["naming"] = tpl
        else:
            raise DevoError("cache naming show | set TEMPLATE[,TEMPLATE...] | reset", code=1)
        save_notes(d)
        print("naming: " + ", ".join(naming_templates()))
        return 0
    raise DevoError(f"unknown cache action {act!r}", code=1)


# ---------------------------------------------------------------- CLI

def add_split_args(s):
    g = s.add_mutually_exclusive_group()
    g.add_argument("--auto-split", dest="auto_split", action="store_true", default=None,
                   help="when a window returns --limit rows, halve it and re-run both halves (down to "
                        "--min-split). Default: on for raw-row queries with --limit >= 1000, off for smaller "
                        "limits (samples) and `group` queries")
    g.add_argument("--no-auto-split", dest="auto_split", action="store_false")
    s.add_argument("--min-split", default="5m", help="smallest window --auto-split creates (default 5m)")


def build_parser():
    ap = argparse.ArgumentParser(prog="devo.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    fmts = ["table", "jsonl", "json", "csv", "tsv"]

    s = sub.add_parser("check", help="verify token and region")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("query", help="run a LINQ query", formatter_class=argparse.RawDescriptionHelpFormatter,
                       description="Run a LINQ query ('-' reads it from stdin).\n\n" + __doc__.split("Times", 1)[1])
    s.add_argument("linq")
    s.add_argument("--from", dest="from_", default="1h", help="start (default 1h = one hour ago)")
    s.add_argument("--to", default="now", help="end (default now)")
    s.add_argument("--limit", type=int, default=200, help="max rows (default 200; 0 = no limit, careful)")
    s.add_argument("--format", choices=fmts, default="table")
    s.add_argument("--sort", help="client-side sort of the returned rows: --sort=field or --sort=-field (desc), "
                                  "comma-separated (LINQ has no ORDER BY)")
    s.add_argument("--width", type=int, default=80, help="table cell truncation (0 = none)")
    s.add_argument("--out", help="write rows to this file instead of stdout")
    s.add_argument("--timeout", type=int, default=600, help="seconds before aborting (default 600)")
    s.add_argument("--chunk", help="split the range into windows of this size (e.g. 6h) and run them "
                                   "in parallel; for long ranges on busy tables")
    s.add_argument("--parallel", type=int, default=4, help="concurrent chunks (default 4)")
    add_split_args(s)
    s.add_argument("--head", type=int, help="print only the first N rows (the count of all rows still goes to stderr)")
    s.add_argument("--stats", action="store_true",
                   help="print row count, and per column filled/distinct counts and the top 5 values, instead of rows")
    s.add_argument("--no-summary", action="store_true", help="with --out: print nothing to stdout (default: --stats)")
    s.add_argument("--no-merge", action="store_true",
                   help="keep grouped rows per window (by default a chunked/split `group by` is merged into one "
                        "row per group: counts and sums added, min/max combined)")
    s.add_argument("--tz", help="IANA zone (e.g. Europe/London): add a <field>_local column after each timestamp")
    s.add_argument("--ui-safe", action="store_true",
                   help="warn about identifiers the Devo web UI rejects (for queries the user will paste there)")
    s.add_argument("--epoch", action="store_true", help="keep timestamps as epoch ms")
    s.add_argument("--raw-ip", action="store_true", help="IPs as integers instead of dotted strings")
    s.add_argument("--dry-run", action="store_true", help="print the request body, don't send it")
    s.set_defaults(fn=cmd_query)

    s = sub.add_parser("schema", help="list a table's fields")
    s.add_argument("table")
    s.add_argument("--grep", help="only fields whose name matches this regex")
    s.add_argument("--format", choices=["table", "json"], default="table")
    s.set_defaults(fn=cmd_schema)

    s = sub.add_parser("tables", help="tables with data in this domain (cached; fetched live on first use)")
    s.add_argument("--grep", help="regex filter on table name")
    s.add_argument("--live", action="store_true", help="query siem.logtrust.collector.counter now and refresh the cache")
    s.add_argument("--from", dest="from_", default=TABLES_WINDOW,
                   help=f"with --live: look-back (default {TABLES_WINDOW}; another window is shown but not cached)")
    s.add_argument("--timeout", type=int, default=300)
    s.set_defaults(fn=cmd_tables)

    s = sub.add_parser("alerts", help="list triggered alerts")
    s.add_argument("--from", dest="from_", default="24h")
    s.add_argument("--to", default="now")
    s.add_argument("--limit", type=int, default=50, help="alerts to show, newest first (default 50)")
    s.add_argument("--max", type=int, default=1000, help="max alerts to fetch (default 1000)")
    s.add_argument("--open", action="store_true", help="hide Closed (300) and False-positive (2) alerts")
    s.add_argument("--all", action="store_true", help=argparse.SUPPRESS)  # old flag; all statuses is the default
    s.add_argument("--name", help="only alerts whose definition name contains this text (case-insensitive)")
    s.add_argument("--group-by", help="group alerts into incidents by extra-data values: file, site, user, host, hash, "
                                      "ip (comma-separated) or a key regex")
    s.add_argument("--group-by-parent", action="store_true",
                   help="with --group-by file: group by the file's folder (one incident across many cached files)")
    s.add_argument("--by-def", action="store_true",
                   help="one row per alert definition: counts per status, priority, source table, newest alert")
    s.add_argument("--format", choices=["table", "json", "csv", "tsv", "jsonl"], default="table")
    s.add_argument("--width", type=int, default=70)
    s.set_defaults(fn=cmd_alerts)

    s = sub.add_parser("alert", help="show one triggered alert")
    s.add_argument("id")
    s.add_argument("--json", action="store_true")
    s.add_argument("--full", action="store_true", help="don't truncate long extra-data values")
    s.set_defaults(fn=cmd_alert)

    s = sub.add_parser("alert-defs", help="list alert definitions")
    s.add_argument("--name", help="name filter (server-side)")
    s.add_argument("--page", type=int, default=0)
    s.add_argument("--size", type=int, default=20)
    s.add_argument("--query", action="store_true", help="show each definition's LINQ query")
    s.add_argument("--format", choices=["table", "json"], default="table")
    s.set_defaults(fn=cmd_alert_defs)

    s = sub.add_parser("coverage", help="is a host sending logs? daily coverage, gaps, restarts, Zscaler")
    s.add_argument("name", help="distinctive part of the host name (case-insensitive substring)")
    s.add_argument("--from", dest="from_", default="30d", help="Windows window start (default 30d)")
    s.add_argument("--to", default="now", help="window end (default now)")
    s.add_argument("--linux-from", default="7d", help="Linux and Zscaler window start (default 7d; slow table)")
    s.add_argument("--no-linux", action="store_true", help="skip box.unix and Zscaler (a quick Windows-only answer)")
    s.add_argument("--low-ratio", type=float, default=0.1, help="flag days below this share of the median day")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("--timeout", type=int, default=600)
    s.set_defaults(fn=cmd_coverage)

    s = sub.add_parser("activity", help="everything a user did: parallel multi-source sweep to --out-dir")
    s.add_argument("term", nargs="?", help="--by user: the surname (case-insensitive substring); --by ip: an IP "
                                           "address; --by host: the shortest distinctive part of the host name")
    s.add_argument("--term", dest="term_opt", action="append", help="another term (repeatable); all terms are "
                                                                     "OR'd in every source")
    s.add_argument("--terms", action="append", help="comma-separated terms, e.g. first.last,jsmith,adm-jsmith")
    s.add_argument("--expand", action="store_true",
                   help="from a UPN first.last@domain also search the account forms in the domain's naming "
                        "templates (`devo.py cache naming`; default {upn}, {first}.{last}, {f}{last})")
    s.add_argument("--rows", action="store_true",
                   help="raw rows (event_time, the group fields and the dedupe id) instead of grouped counts: "
                        "for `timeline`; slower and bigger")
    s.add_argument("--tz", help="IANA zone: add *_local next to eventdate/first/last/event times")
    s.add_argument("--by", choices=["user", "ip", "host"], default="user",
                   help="which sweep to run (the domain's validated sources tagged with this; default user)")
    s.add_argument("--from", dest="from_", default="today", help="window start (default today, UTC)")
    s.add_argument("--to", default="now", help="window end (default now)")
    s.add_argument("--out-dir", required=True, help="directory for <source>.jsonl and summary.json (scratchpad)")
    s.add_argument("--graph-ids", help="comma-separated Entra object ids for the Graph activity pass")
    s.add_argument("--graph-only", action="store_true",
                   help="run only the Graph pass (--graph-ids) and add it to the summary already in --out-dir")
    s.add_argument("--only", help="comma-separated source names to run (`devo.py cache status` / the hints file)")
    s.add_argument("--skip", help="comma-separated source names to skip")
    s.add_argument("--limit", type=int, default=5000, help="max rows per source (per chunk) (default 5000)")
    s.add_argument("--parallel-sources", type=int, default=8, help="sources run at once (default 8)")
    s.add_argument("--no-auto", action="store_true",
                   help="skip the sources generated from field profiles (auto_*): faster, curated sources only")
    s.add_argument("--sources", help="use this sources file as is, instead of the domain's validated, cached sources")
    s.add_argument("--width", type=int, default=60)
    s.add_argument("--timeout", type=int, default=600)
    s.set_defaults(fn=cmd_activity)

    s = sub.add_parser("lag", help="measure ingestion lag per table now (eventdate − event time)",
                       description="Ingestion lag per table: eventdate (ingestion) minus the record's own event "
                                   "time, per hour of ingestion, from the event-time families (references/hints/event-time.json, verified per domain in the cache). Lag is variable "
                                   "and batch-driven (Microsoft 365 back-fills), so run this before trusting a "
                                   "recent window.\n\nExample: devo.py lag --tables 'office365|win_nxlog' --from 7d",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("--tables", help="regex: only default tables matching it (default: every `lag` table in "
                                    "event-time.json)")
    s.add_argument("--table", action="append", help="add a table outside the default set (repeatable)")
    s.add_argument("--from", dest="from_", default="24h", help="window start (default 24h)")
    s.add_argument("--to", default="now")
    s.add_argument("--chunk", help="chunk size (default 6h up to 2 days, else 1d)")
    s.add_argument("--parallel", type=int, default=4, help="tables measured at once (default 4)")
    s.add_argument("--hourly", action="store_true", help="also print each table's per-hour rows")
    s.add_argument("--out", help="write the full result (with hourly rows) as JSON")
    s.add_argument("--tz", help="IANA zone for the printed times")
    s.add_argument("--width", type=int, default=60)
    s.add_argument("--timeout", type=int, default=600)
    s.set_defaults(fn=cmd_lag)

    s = sub.add_parser("batch", help="run many queries from a JSON/JSONL spec in parallel (no shell scripting)",
                       description="Run the jobs in a spec file in parallel. Each job is an object "
                                   "{name, query | query_file (a .linq file next to the spec), from?, to?, chunk?, parallel?, limit?, format?, auto_split?, "
                                   "timeout?}; the file is a JSON list, {\"jobs\": [...]}, or JSON Lines ('-' = "
                                   "stdin). Each job writes <out-dir>/<name>.jsonl (or .csv/.tsv/.json) and "
                                   "<name>.log; a summary table and batch-summary.json follow. {var} placeholders "
                                   "in any job field are filled from --vars (other braces, e.g. LINQ sets, are "
                                   "left alone).\n\nExample:\n  devo.py batch sweep.jsonl --out-dir /tmp/s "
                                   "--vars user=jsmith,from=7d",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("spec", help="JSON / JSONL job file, or - for stdin")
    s.add_argument("--out-dir", required=True, help="directory for the outputs (scratchpad)")
    s.add_argument("--vars", action="append", help="name=value[,name=value…] substituted for {name} (repeatable)")
    s.add_argument("--parallel", type=int, default=4, help="jobs at once (default 4; each job's chunks run "
                                                           "in parallel too)")
    s.add_argument("--from", dest="from_", default="1h", help="default `from` for jobs without one (default 1h)")
    s.add_argument("--to", default="now", help="default `to` (default now)")
    s.add_argument("--limit", type=int, default=10000, help="default row limit per window (default 10000; 0 = none)")
    s.add_argument("--tz", help="IANA zone: add <field>_local after each timestamp column")
    s.add_argument("--width", type=int, default=80)
    s.add_argument("--timeout", type=int, default=600)
    s.set_defaults(fn=cmd_batch)

    s = sub.add_parser("timeline", help="merge an activity --out-dir into one sorted timeline (offline)",
                       description="Merge every <source>.jsonl of an `activity` output directory into one sorted "
                                   "list of {t_utc, t_local, source, table, actor, action, target, detail, ip, host} "
                                   "using the event-time field per table (references/hints/event-time.json, verified per domain), "
                                   "de-duplicating repeated records (SharePoint/OneDrive Id, Entra properties_id "
                                   "and the audit tenantId copy, Defender report_id). Writes JSON plus a per-day "
                                   "text summary. Grouped activity rows become one event each (count, first..last); "
                                   "run `activity --rows` for per-event detail.\n\nExample: devo.py timeline "
                                   "<dir> --tz Europe/London --out <dir>/timeline.json",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("dir", help="an `activity --out-dir` directory (has summary.json)")
    s.add_argument("--out", help="JSON output (default <dir>/timeline.json); the text summary goes next to it (.txt)")
    s.add_argument("--keep-outside", action="store_true",
                   help="keep events whose event time is before the sweep window (back-filled records)")
    s.add_argument("--tz", help="IANA zone for t_local and the per-day summary (e.g. Europe/London)")
    s.set_defaults(fn=cmd_timeline)

    s = sub.add_parser("teams", help="reconstruct a user's or a thread's Teams activity into normalised JSON",
                       description="Teams reconstruction from cloud.office365.management.microsoftteams: "
                                   "conversations (1:1 / group / meeting / channel, other parties as UPNs, messages "
                                   "sent, edits, reactions, files, links), meetings and calls per occurrence "
                                   "(MeetingDetailId / CallId, join/leave per participant, what was shared), and "
                                   "daily counts. Times are event times (CreationTime, JoinTime/LeaveTime, "
                                   "StartTime/EndTime), never eventdate. Only conversations the user is in are "
                                   "counted; channel threads count only the user's own posts.\n\nExample: "
                                   "devo.py teams first.last@example.com --from 2026-09-29 --to 2026-10-02 "
                                   "--tz Europe/London --out teams.json",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("subject", help="the user's UPN (or a distinctive part of it), or a thread id 19:…")
    s.add_argument("--from", dest="from_", default="today", help="start of the event-time window (default today)")
    s.add_argument("--to", default="now", help="end (default now); ingestion is searched up to a day past it")
    s.add_argument("--out", required=True, help="JSON output file (scratchpad)")
    s.add_argument("--tz", help="IANA zone for *_local times and the daily buckets (e.g. Europe/London)")
    s.add_argument("--all-matches", action="store_true", help="keep every account the term matches")
    s.add_argument("--top", type=int, default=15, help="conversations listed on stdout (default 15)")
    s.add_argument("--timeout", type=int, default=600)
    s.set_defaults(fn=cmd_teams)

    s = sub.add_parser("profile", help="profile tables from live samples: fields, fill, patterns, roles (no values)")
    s.add_argument("tables", nargs="*")
    s.add_argument("--from-file", help="file with one table per line (last word of each line)")
    s.add_argument("--sample", type=int, default=300, help="rows per table (default 300)")
    s.add_argument("--parallel", type=int, default=6)
    s.add_argument("--write", help="also merge results into this field-map JSON file (an export; the cache is "
                                   "always updated)")
    s.add_argument("--all", action="store_true", help="also list fields with no data in the sample")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("--timeout", type=int, default=300)
    s.set_defaults(fn=cmd_profile)

    s = sub.add_parser("fields", help="field map: a table's populated fields (profiled and cached on first use), "
                                      "or cached tables with a role")
    s.add_argument("table", nargs="?", help="table (exact or substring); omit and use --role")
    s.add_argument("--role", choices=["user", "host", "ip", "time", "join-id", "hash", "url/domain",
                                      "process/file", "action", "outcome", "text", "constant"],
                   help="without a table: tables/fields with this role (default ip); with a table: only those fields")
    s.add_argument("--grep", help="with a table: only fields matching this regex; with --role: only tables matching it")
    s.add_argument("--min-fill", type=float, default=0.05, help="ignore fields filled in fewer rows (default 0.05)")
    s.add_argument("--all", action="store_true", help="with a table: include empty fields")
    s.add_argument("--refresh", action="store_true", help="with a table: re-profile it live now")
    s.add_argument("--map", help=argparse.SUPPRESS)
    s.add_argument("--roles", help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_fields)

    s = sub.add_parser("comment", help="comment on a triggered alert (preview; --confirm posts)")
    s.add_argument("id")
    s.add_argument("--title", required=True)
    s.add_argument("--msg", required=True)
    s.add_argument("--confirm", action="store_true",
                   help="actually post it; only after the user approved the previewed text")
    s.set_defaults(fn=cmd_comment)

    s = sub.add_parser("creds", help="summarise a credential-attack batch (spray / distributed brute force) and "
                                     "write the stage-2 'did anything succeed' spec (offline)",
                       description=cmd_creds.__doc__)
    s.add_argument("dir", help="the --out-dir of `batch references/specs/credential-attacks.jsonl`")
    s.add_argument("--min-users", type=int, default=5, help="spray: accounts per IP (default 5)")
    s.add_argument("--min-ips", type=int, default=5, help="brute force: IPs per account (default 5)")
    s.add_argument("--exclude", help="comma-separated IPs to ignore (your own egress / ZTNA / NAT addresses)")
    s.add_argument("--window", default="7d", help="stage-2 window for successes from the failing IPs (default 7d)")
    s.add_argument("--max-ips", type=int, default=300)
    s.add_argument("--stage2", help="stage-2 spec path (default <dir>/stage2.jsonl)")
    s.add_argument("--stage2-dir", help="interpret the stage-2 batch output in this directory (same/different account, "
                                        "known range?) and write stage3.jsonl for other successful accounts")
    s.add_argument("--egress-users", type=int, default=10,
                   help="IPs with this many successful accounts (interactive or not, 7 days) are shared egress, excluded "
                        "(default 10)")
    s.add_argument("--keep-egress", action="store_true", help="don't exclude the shared egress IPs")
    s.add_argument("--limit", type=int, default=15)
    s.set_defaults(fn=cmd_creds)

    s = sub.add_parser("grants", help="summarise a privileged-grants batch: Entra/PIM role changes classified, "
                                      "AD privileged groups (offline)", description=cmd_grants.__doc__)
    s.add_argument("dir", help="the --out-dir of `batch references/specs/privileged-grants.jsonl`")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(fn=cmd_grants)

    s = sub.add_parser("health", help="health of the whole domain: tables stopped/dropped/new, quiet senders, "
                                      "collector errors, lag", description=cmd_health.__doc__)
    s.add_argument("--baseline", default="21d", help="start of the baseline (default 21d)")
    s.add_argument("--recent", default="7d", help="start of the recent window compared with it (default 7d)")
    s.add_argument("--no-hosts", action="store_true", help="skip the Windows/Linux sender check (the slow part)")
    s.add_argument("--no-lag", action="store_true", help="skip the lag measurement")
    s.add_argument("--max-recheck", type=int, default=40, help="stopped/dropped tables re-counted directly (default 40)")
    s.add_argument("--no-verify", action="store_true", help="don't re-count the counter's big movers on the tables")
    s.add_argument("--limit", type=int, default=25, help="rows per section (default 25; --out has all)")
    s.add_argument("--parallel", type=int, default=6)
    s.add_argument("--out", help="full JSON report")
    s.add_argument("--timeout", type=int, default=600)
    s.set_defaults(fn=cmd_health)

    s = sub.add_parser("logons", help="who logged into which Windows/Linux servers: per server and account, "
                                      "first/last, sources, person/service label",
                       description=cmd_logons.__doc__)
    s.add_argument("--from", dest="from_", default="7d", help="window start (default 7d)")
    s.add_argument("--to", default="now")
    s.add_argument("--os", default="windows,linux", help="windows, linux or both (default)")
    s.add_argument("--host", help="only servers whose name contains this (case-insensitive)")
    s.add_argument("--user", help="only accounts containing this (case-insensitive)")
    s.add_argument("--people-only", action="store_true", help="list only accounts labelled person")
    s.add_argument("--resolve-ztna", action="store_true",
                   help="also list who reached each server over RDP/SSH through Zscaler ZPA (sources that are connector "
                        "IPs or 0.0.0.0 then have names)")
    s.add_argument("--include-network", action="store_true",
                   help="also count network logons (type 3: shares, admin consoles, DC traffic); much more volume")
    s.add_argument("--all-accounts", action="store_true", help="also show built-in/computer accounts (DWM-, UMFD-, $)")
    s.add_argument("--out", help="full JSON report (every pair, sources, queries, label reasons)")
    s.add_argument("--csv", help="the listed pairs as CSV (the analyst deliverable)")
    s.add_argument("--tz", help="IANA zone for first/last")
    s.add_argument("--chunk", help="window size (default 6h up to 3 days, else 1d)")
    s.add_argument("--parallel", type=int, default=6)
    s.add_argument("--limit", type=int, default=40, help="rows per printed table (default 40; --out/--csv have all)")
    s.add_argument("--width", type=int, default=40)
    s.add_argument("--timeout", type=int, default=600)
    s.set_defaults(fn=cmd_logons)

    s = sub.add_parser("cache", help="the domain data cached on this machine: status, build, verify, refresh, clear, "
                                     "notes, note, naming", formatter_class=argparse.RawDescriptionHelpFormatter,
                       description="""Domain data cached on this machine (never in the skill directory).

  cache status [--json]              what is cached, how old, what is stale
  cache build [--profile all|none|N] fetch everything not fresh: tables, event time, schemas, field
                                     profiles (all tables by default; N = the N busiest), sweep sources
  cache verify                       refetch the table list, compare every cached schema with the live
                                     one, re-profile what changed, re-verify event time, rebuild sources
  cache refresh [tables|fields [TABLE ...]|event-time|sources|all]
                                     refetch those entries now, fresh or not
  cache clear [tables|fields|TABLE|event-time|sources|notes|all] [--include-notes]
                                     drop entries; `clear` alone (or all) drops everything but the notes
  cache notes [--json]               the domain notes (facts verified in this domain)
  cache note add TEXT | verify ID ... | rm ID ...
  cache naming show | set TEMPLATE[,...] | reset
                                     account forms for `activity --expand`: {upn} {local} {first} {last} {f} {l}
  cache service show | set|add GLOB[,...] | reset
                                     confirmed service/shared account names (globs), labelled by `logons`

Entries expire on their own (tables and sources 7 days, schemas, profiles and event time 30;
DEVO_CACHE_MAX_AGE_DAYS caps every TTL) and are marked stale when a query contradicts them.""")
    s.add_argument("action", choices=["status", "build", "verify", "refresh", "clear", "notes", "note", "naming",
                                      "service"])
    s.add_argument("what", nargs="*")
    s.add_argument("--profile", default="all", help="build: which tables to profile: all (default), none, or N busiest")
    s.add_argument("--sample", type=int, default=300, help="rows per profiled table (default 300)")
    s.add_argument("--parallel", type=int, default=6)
    s.add_argument("--timeout", type=int, default=300)
    s.add_argument("--all", action="store_true", help="clear: everything except the notes")
    s.add_argument("--include-notes", action="store_true", help="clear: the notes and naming too")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_cache)
    return ap


def main(argv=None):
    global CACHE
    a = build_parser().parse_args(argv)
    try:
        if (a.fn is cmd_fields and a.map) or a.fn is cmd_creds:  # local files only
            cfg = None
        elif a.fn in (cmd_timeline, cmd_grants):  # offline; the credentials only locate the cache
            try:
                cfg = load_config()
            except DevoError:
                cfg = None
        else:
            cfg = load_config()
        CACHE = Cache(cfg) if cfg or os.environ.get("DEVO_CACHE_KEY") else None
        _EVENT_TIME_CACHE.clear()
        return a.fn(cfg, a)
    except DevoError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if e.hint:
            print(f"hint: {e.hint}", file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
