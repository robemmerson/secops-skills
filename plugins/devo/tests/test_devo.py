"""Offline tests for plugins/devo/skills/devo/scripts/devo.py. Run: python3 -m unittest discover plugins/devo/tests"""
import contextlib, io, json, os, re, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "devo", "scripts"))
import devo  # noqa: E402

# never touch the real cache in ~/.cache: every test run gets an empty one
os.environ["DEVO_CACHE_DIR"] = tempfile.mkdtemp(prefix="devo-cache-test-")
os.environ.pop("DEVO_CACHE_KEY", None)

NOW = 1790611381  # 2026-09-28 16:03:01 UTC


class FakeResp:
    """Mimics http.client.HTTPResponse: read1() returns the body in small chunks."""

    def __init__(self, body, chunk=17):
        self.data = body.encode() if isinstance(body, str) else body
        self.chunk = chunk

    def read1(self, n):
        piece, self.data = self.data[: self.chunk], self.data[self.chunk:]
        return piece

    def read(self, n=-1):
        piece, self.data = self.data, b""
        return piece

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, body):
    import urllib.error
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(body.encode()))


COMPACT = (
    '{"m":{"eventdate":{"type":"timestamp","index":0},"srcIp":{"type":"ip4","index":1},'
    '"n":{"type":"int8","index":2}},"metadata":[{"name":"eventdate","type":"timestamp"},'
    '{"name":"srcIp","type":"ip4"},{"name":"n","type":"int8"}]}\n'
    '        \n'  # keep-alive padding
    '{"d":[1790611330000,"203.0.113.10",5]}\n'
    '{"d":[1790611331000,null,7]}\n'
)
CFG = {"token": "SECRET-TOKEN-123", "region": "eu"}


def run_cli(argv, responses):
    """Run devo.main with urlopen patched to return/raise the given responses in order.
    Returns (exit_code, stdout, stderr, requests)."""
    reqs = []
    it = iter(responses)

    def fake_urlopen(req, timeout=None):
        reqs.append(req)
        r = next(it)
        if isinstance(r, Exception):
            raise r
        return r

    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(devo.urllib.request, "urlopen", fake_urlopen), \
            mock.patch.object(devo, "load_config", lambda: dict(CFG)), \
            mock.patch.object(devo.time, "time", lambda: NOW), \
            mock.patch.object(devo, "RETRY_DELAY", 0), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = devo.main(argv)
    return code, out.getvalue(), err.getvalue(), reqs


class TimeTests(unittest.TestCase):
    def r(self, v):
        return devo.resolve_time(v, now=NOW)

    def test_durations(self):
        self.assertEqual(self.r("1h"), (NOW - 3600, NOW - 3600))
        self.assertEqual(self.r("7d")[0], NOW - 7 * 86400)
        self.assertEqual(self.r("30m ago")[0], NOW - 1800)
        self.assertEqual(self.r("-2w")[0], NOW - 14 * 86400)

    def test_words(self):
        self.assertEqual(self.r("now")[0], NOW)
        self.assertEqual(self.r("today")[0], 1790553600)  # 2026-09-28 00:00Z
        self.assertEqual(self.r("yesterday")[0], 1790553600 - 86400)

    def test_epoch_seconds_and_ms(self):
        self.assertEqual(self.r("1790607781")[0], 1790607781)
        # ms must be converted: Devo reads bare ms as seconds and the query hangs
        self.assertEqual(self.r("1790607781000")[0], 1790607781)

    def test_iso(self):
        self.assertEqual(self.r("2026-09-28")[0], 1790553600)
        self.assertEqual(self.r("2026-09-28T14:00")[0], 1790553600 + 14 * 3600)
        self.assertEqual(self.r("2026-09-28 14:00:00Z")[0], 1790553600 + 14 * 3600)
        self.assertEqual(self.r("2026-09-28T15:00:00+01:00")[0], 1790553600 + 14 * 3600)
        self.assertEqual(self.r("2026-09-28T15:00:00+0100")[0], 1790553600 + 14 * 3600)

    def test_relative_language_passthrough(self):
        self.assertEqual(self.r("now() - 3h"), ("now() - 3h", None))
        self.assertEqual(self.r("(now() - 1d) @ 1d"), ("(now() - 1d) @ 1d", None))

    def test_garbage(self):
        with self.assertRaises(devo.DevoError):
            self.r("last tuesday")


class ConfigTests(unittest.TestCase):
    def test_env_wins(self):
        c = devo.load_config({"DEVO_TOKEN": "abc", "DEVO_ENV_FILE": "/nonexistent"})
        self.assertEqual(c, {"token": "abc", "region": "eu"})

    def test_env_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write('# comment\nexport DEVO_TOKEN="fromfile"\nDEVO_REGION=US\n')
        try:
            c = devo.load_config({"DEVO_ENV_FILE": f.name})
            self.assertEqual(c, {"token": "fromfile", "region": "us"})
        finally:
            os.unlink(f.name)

    def test_missing_token(self):
        with self.assertRaises(devo.DevoError) as cm:
            devo.load_config({"DEVO_ENV_FILE": "/nonexistent"})
        self.assertEqual(cm.exception.code, 1)


class StreamTests(unittest.TestCase):
    def test_compact_with_padding_and_chunking(self):
        p = devo.CompactStream()
        rows = []
        for i in range(0, len(COMPACT), 5):
            rows += p.feed(COMPACT[i:i + 5])
        rows += p.close()
        self.assertEqual(p.columns, [("eventdate", "timestamp"), ("srcIp", "ip4"), ("n", "int8")])
        self.assertEqual(rows, [[1790611330000, "203.0.113.10", 5], [1790611331000, None, 7]])

    def test_midstream_error(self):
        p = devo.CompactStream()
        with self.assertRaises(devo.DevoError):
            p.feed('{"m":{"a":{"type":"str","index":0}}}\n{"e":[500,"boom"]}\n')

    def test_quote_table(self):
        self.assertEqual(devo.quote_table("firewall.all.traffic"), "firewall.all.traffic")
        self.assertEqual(devo.quote_table("web.iis.access-w3c-all"), "`web.iis.access-w3c-all`")


class ErrorTests(unittest.TestCase):
    def test_linq_error(self):
        body = ('{"msg":"Error Launching Query","status":500,"object":["Error Launching Query",'
                '"Unknown identifier `nosuchfield`","1101001","QUERY_PARSING_ERROR","NO"]}')
        e = devo.api_error(500, body)
        self.assertIn("Unknown identifier `nosuchfield`", str(e))
        self.assertIn("QUERY_PARSING_ERROR", str(e))
        self.assertIn("schema", e.hint)

    def test_parse_error(self):
        e = devo.api_error(500, '{"error":"Unable to Start Task: Query parsing error","status":500}')
        self.assertIn("Query parsing error", str(e))
        self.assertIn("syntax", e.hint)

    def test_bad_date(self):
        e = devo.api_error(400, '{"error":"Bad parameters","status":400,"object":["406 : Date from not valid format"]}')
        self.assertIn("406", str(e))
        self.assertIn("time range", e.hint)

    def test_alerts_error_object(self):
        body = '{"msg":"Alert doesn\'t exist.","code":400,"error":{"message":"Alert doesn\'t exist."}}'
        self.assertIn("Alert doesn't exist", str(devo.api_error(400, body)))

    def test_alerts_validation(self):
        body = ('{"msg":"Invalid data.","code":618,"context":{"fields":[{"path":"from","errors":'
                '["must not be null"]}]},"error":{"message":"Invalid data."}}')
        self.assertIn("from: must not be null", str(devo.api_error(400, body)))

    def test_cloudflare_and_html(self):
        self.assertIn("Cloudflare", str(devo.api_error(403, "error code: 1010")))
        self.assertIn("Error 404", str(devo.api_error(404, "<html><title>Error 404 Not Found</title></html>")))

    def test_token_redacted(self):
        e = devo.api_error(500, "weird SECRET-TOKEN-123 echo", token="SECRET-TOKEN-123")
        self.assertNotIn("SECRET-TOKEN-123", str(e))


class QueryCliTests(unittest.TestCase):
    def test_query_table_output_and_request(self):
        code, out, err, reqs = run_cli(["query", "from web.iis.access-w3c-all select *", "--from", "1h"],
                                       [FakeResp(COMPACT)])
        self.assertEqual(code, 0)
        body = json.loads(reqs[0].data)
        self.assertEqual(body["query"], "from `web.iis.access-w3c-all` select *")
        self.assertEqual(body["from"], NOW - 3600)
        self.assertEqual(body["to"], NOW)  # always sent: no `to` = endless query
        self.assertEqual(body["limit"], 200)
        self.assertTrue(body["ipAsString"])
        self.assertEqual(body["mode"], {"type": "json/simple/compact"})
        self.assertEqual(reqs[0].get_header("User-agent"), devo.USER_AGENT)
        self.assertIn("2026-09-28T16:02:10.000Z", out)
        self.assertIn("203.0.113.10", out)
        self.assertIn("2 rows", err)
        self.assertNotIn(CFG["token"], out + err)

    def test_query_formats(self):
        _, out, _, _ = run_cli(["query", "from t select *", "--format", "jsonl"], [FakeResp(COMPACT)])
        first = json.loads(out.splitlines()[0])
        self.assertEqual(first, {"eventdate": "2026-09-28T16:02:10.000Z", "srcIp": "203.0.113.10", "n": 5})
        _, out, _, _ = run_cli(["query", "from t select *", "--format", "csv", "--epoch"], [FakeResp(COMPACT)])
        self.assertEqual(out.splitlines()[0], "eventdate,srcIp,n")
        self.assertEqual(out.splitlines()[2], "1790611331000,,7")

    def test_zero_rows_hint_and_limit_note(self):
        meta = COMPACT.split("\n")[0] + "\n"
        _, _, err, _ = run_cli(["query", "from t select *"], [FakeResp(meta)])
        self.assertIn("0 rows", err)
        _, _, err, _ = run_cli(["query", "from t select *", "--limit", "2", "--no-auto-split"], [FakeResp(COMPACT)])
        self.assertIn("limit 2 reached", err)
        self.assertIn("--auto-split halves", err)
        _, _, err, _ = run_cli(["query", "from t group by n select count() as c", "--limit", "2", "--sort=-n"],
                               [FakeResp(COMPACT)])  # grouped: no auto-split by default
        self.assertIn("WARNING: --sort ran on a truncated result", err)

    def test_zero_rows_case_hint_for_name_fields(self):
        meta = COMPACT.split("\n")[0] + "\n"
        for q in ['from t where host -> "HOST01" select *', 'from t where TargetUserName = "Alice" select *',
                  'from t where has(machine, "Web01") select *']:
            _, _, err, _ = run_cli(["query", q], [FakeResp(meta)])
            self.assertIn("case-sensitive", err, q)
            self.assertIn("weakhas", err, q)
        _, _, err, _ = run_cli(["query", 'from t where weakhas(host, "host01") select *'], [FakeResp(meta)])
        self.assertNotIn("case-sensitive", err)
        _, _, err, _ = run_cli(["query", 'from t where host -> "HOST01" select *'], [FakeResp(COMPACT)])
        self.assertNotIn("case-sensitive", err)        # only when nothing matched

    def test_relative_passthrough_and_order_check(self):
        _, _, _, reqs = run_cli(["query", "from t select *", "--from", "(now() - 1d) @ 1d",
                                 "--to", "now() @ 1d"], [FakeResp(COMPACT)])
        body = json.loads(reqs[0].data)
        self.assertEqual((body["from"], body["to"]), ("(now() - 1d) @ 1d", "now() @ 1d"))
        code, _, err, reqs = run_cli(["query", "from t select *", "--from", "now", "--to", "1h"], [])
        self.assertEqual(code, 1)
        self.assertEqual(reqs, [])

    def test_future_to_is_clamped_to_now(self):
        code, _, err, reqs = run_cli(["query", "from t select *", "--from", "1h", "--to", "2026-09-29T00:00Z"],
                                     [FakeResp(COMPACT)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(reqs[0].data)["to"], NOW)  # Devo would wait until a future `to`
        self.assertIn("--to is in the future", err)

    def test_api_error_exit_code(self):
        body = ('{"msg":"Error Launching Query","status":500,"object":["Error Launching Query",'
                '"Unknown table `no.such.table`","2086000","MISSING_RESOURCE","MANUAL"]}')
        code, _, err, _ = run_cli(["query", "from no.such.table select *"], [http_error(500, body)])
        self.assertEqual(code, 2)
        self.assertIn("Unknown table", err)
        self.assertIn("hint:", err)

    def test_sort(self):
        _, out, _, _ = run_cli(["query", "from t select *", "--sort=-n", "--format", "csv"],
                               [FakeResp(COMPACT)])
        self.assertEqual([l.split(",")[2] for l in out.splitlines()[1:]], ["7", "5"])
        rows = devo.sort_rows([[None, 1], ["b", 2], ["a", 3]], ["x", "y"], "x")
        self.assertEqual(rows, [["a", 3], ["b", 2], [None, 1]])
        with self.assertRaises(devo.DevoError):
            devo.sort_rows([[1]], ["x"], "nope")

    def test_chunked_query(self):
        code, out, err, reqs = run_cli(["query", "from t select *", "--from", "3h", "--chunk", "1h",
                                        "--parallel", "1", "--format", "csv"],
                                       [FakeResp(COMPACT) for _ in range(4)])
        self.assertEqual(code, 0)
        bodies = [json.loads(r.data) for r in reqs]
        h = NOW - NOW % 3600
        self.assertEqual([(b["from"], b["to"]) for b in bodies],
                         [(NOW - 10800, h - 7200), (h - 7200, h - 3600), (h - 3600, h), (h, NOW)])
        self.assertEqual(len(out.splitlines()), 1 + 8)
        self.assertIn("chunked: 4 windows", err)

    def test_chunks_align_to_boundaries(self):
        # --from 3h at NOW=16:03:01 -> windows 13:03:01-14:00, 14-15, 15-16, 16:00-16:03:01
        _, _, _, reqs = run_cli(["query", "from t select *", "--from", "3h", "--chunk", "1h", "--parallel", "1"],
                                [FakeResp(COMPACT) for _ in range(4)])
        starts = [json.loads(r.data)["from"] for r in reqs]
        self.assertEqual(starts[0], NOW - 10800)
        self.assertTrue(all(s % 3600 == 0 for s in starts[1:]))
        self.assertEqual(json.loads(reqs[-1].data)["to"], NOW)

    def test_truncated_stream_is_retried_then_reported(self):
        import http.client

        class Broken(FakeResp):
            def read1(self, n):
                raise http.client.IncompleteRead(b"partial")
        # plain query: retried twice, then a clean error, not a traceback
        code, _, err, _ = run_cli(["query", "from t select *"], [Broken(""), Broken(""), Broken("")])
        self.assertEqual(code, 2)
        self.assertIn("connection dropped", err)
        # chunked: a failing chunk is retried and succeeds
        code, out, err, reqs = run_cli(["query", "from t select *", "--from", "1h", "--chunk", "1h", "--parallel", "1",
                                        "--format", "csv"], [Broken(""), FakeResp(COMPACT), FakeResp(COMPACT)])
        self.assertEqual(len(reqs), 3)  # 2 aligned windows + 1 retry
        self.assertEqual(code, 0)
        self.assertIn("retried", err)

    def test_chunk_rejects_relative_expressions(self):
        code, _, err, reqs = run_cli(["query", "from t select *", "--from", "now() - 3h", "--chunk", "1h"], [])
        self.assertEqual((code, reqs), (1, []))

    def test_dry_run_sends_nothing(self):
        code, out, _, reqs = run_cli(["query", "from t select *", "--dry-run"], [])
        self.assertEqual((code, reqs), (0, []))
        self.assertNotIn(CFG["token"], out)


class SchemaTests(unittest.TestCase):
    def test_schema_api(self):
        body = '{"cid":"x","msg":"","object":[{"fieldName":"eventdate","type":"timestamp"},{"fieldName":"user","type":"str"}]}'
        code, out, _, reqs = run_cli(["schema", "auth.all"], [FakeResp(body)])
        self.assertEqual(code, 0)
        self.assertIn("user", out)
        self.assertTrue(reqs[0].full_url.endswith("/search/table/auth.all"))

    def test_schema_falls_back_to_query(self):
        code, out, err, reqs = run_cli(["schema", "my.app.thing"],
                                       [http_error(404, "<html><title>Not Found</title></html>"),
                                        FakeResp(COMPACT)])
        self.assertEqual(code, 0)
        self.assertIn("srcIp", out)
        self.assertIn("1-row query", err)


ALERT = {
    "id": 123456, "priority": 6.0, "status": 0, "createDate": 1790611330000, "updateDate": 1790611330000,
    "context": "my.alert.demo.Suspicious_Login", "username": "alice@example.com", "srcIp": "203.0.113.10",
    "dstIp": None, "srcHost": None, "dstHost": None,
    "extraData": json.dumps({"eventdate": "2026-09-28+16%3A02%3A10.000", "client": "demo%40example"}),
    "alertDefinition": {"name": "Suspicious Login", "description": "desc",
                        "alertCorrelationContext": {"sourceTable": "auth.all",
                                                    "querySourceCode": "from auth.all\nwhere result = \"FAIL\""}},
    "commentsList": [{"author": {"user": {"username": "bob@example.com"}}, "creationDate": 1790611331000,
                      "title": "Triage", "msg": "looking"}],
}


class AlertTests(unittest.TestCase):
    def test_alerts_list(self):
        code, out, err, reqs = run_cli(["alerts", "--from", "24h"],
                                       [FakeResp(json.dumps([ALERT])), FakeResp("[]")])
        self.assertEqual(code, 0)
        url = reqs[0].full_url
        self.assertIn("api-eu.devo.com/alerts/v1/alerts/list?", url)
        self.assertIn(f"from={(NOW - 86400) * 1000}", url)  # the Alerts API wants epoch ms
        self.assertIn(f"to={NOW * 1000}", url)
        self.assertIn("Suspicious Login", out)
        self.assertIn("6 high", out)
        self.assertIn("0 Unread", out)
        self.assertIn("all statuses", err)
        self.assertNotIn("showAll", url)  # showAll=true hides Closed alerts live (docs say otherwise)

    def test_alerts_open_filter(self):
        closed = dict(ALERT, id=9, status=300)
        _, out, err, _ = run_cli(["alerts", "--open", "--format", "json"],
                                 [FakeResp(json.dumps([ALERT, closed])), FakeResp("[]")])
        self.assertEqual([x["id"] for x in json.loads(out)], [123456])
        self.assertIn("hidden", err)

    def test_alerts_table_shows_source_and_event_time(self):
        code, out, _, _ = run_cli(["alerts", "--width", "0"], [FakeResp(json.dumps([ALERT])), FakeResp("[]")])
        self.assertEqual(code, 0)
        header = out.splitlines()[0]
        self.assertIn("source", header)
        self.assertIn("event_utc", header)
        self.assertIn("auth.all", out)                 # alertDefinition...sourceTable
        self.assertIn("2026-09-28 16:02:10", out)      # decoded extraData eventdate

    def test_alerts_pages_until_empty_dedupes_and_sorts_newest_first(self):
        # the API returns short pages even when more exist, oldest first
        a1 = dict(ALERT, id=1, createDate=1000)
        a2 = dict(ALERT, id=2, createDate=3000)
        a3 = dict(ALERT, id=3, createDate=2000)
        code, out, err, reqs = run_cli(
            ["alerts", "--limit", "2", "--format", "json"],
            [FakeResp(json.dumps([a1, a3])), FakeResp(json.dumps([a3, a2])), FakeResp("[]")])
        self.assertEqual(code, 0)
        self.assertEqual(len(reqs), 3)
        self.assertIn("offset=100", reqs[1].full_url)
        self.assertEqual([x["id"] for x in json.loads(out)], [2, 3])
        self.assertIn("3 alerts", err)
        self.assertIn("showing 2", err)

    def test_alert_detail_fetches_missing_definition(self):
        bare = {k: v for k, v in ALERT.items() if k != "alertDefinition"}
        code, out, _, reqs = run_cli(["alert", "123456"],
                                     [FakeResp(json.dumps(bare)), FakeResp(json.dumps([ALERT])),
                                      FakeResp("[]")])
        self.assertEqual(code, 0)
        self.assertIn("alerts/list?", reqs[1].full_url)
        self.assertIn(f"from={ALERT['createDate'] - 60000}", reqs[1].full_url)
        self.assertIn("where result = \"FAIL\"", out)

    def test_lu_error_hint(self):
        e = devo.api_error(500, '{"msg":"Error Launching Query","object":["Error Launching Query",'
                                '"No function named `lu` that can be applied to given arguments","1101009",'
                                '"QUERY_PARSING_ERROR","NO"]}')
        self.assertIn("lookup", e.hint)

    def test_alerts_rejects_relative_expression(self):
        code, _, err, reqs = run_cli(["alerts", "--from", "now() - 1d"], [])
        self.assertEqual((code, reqs), (1, []))

    def test_alert_detail(self):
        code, out, _, reqs = run_cli(["alert", "123456"], [FakeResp(json.dumps(ALERT))])
        self.assertEqual(code, 0)
        self.assertIn("alerts/get?id=123456", reqs[0].full_url)
        self.assertIn("2026-09-28 16:02:10.000", out)  # URL-decoded extraData
        self.assertIn("demo@example", out)
        self.assertIn("where result = \"FAIL\"", out)  # detection query shown
        self.assertIn("sourceTable auth.all", out)
        self.assertIn("bob@example.com: Triage: looking", out)

    def test_status_and_priority_labels(self):
        self.assertEqual(devo.status_label(850), "850 custom (see comments)")
        self.assertEqual(devo.priority_label(9), "9 very high")
        self.assertEqual(devo.priority_label(1), "1 very low")


DAY = 86400
TODAY0 = NOW - NOW % DAY  # 2026-09-28 00:00Z


def compact(columns, rows):
    """A json/simple/compact body: columns = [(name, type)], rows = lists."""
    meta = {"m": {n: {"type": t, "index": i} for i, (n, t) in enumerate(columns)},
            "metadata": [{"name": n, "type": t} for n, t in columns]}
    return "\n".join([json.dumps(meta)] + [json.dumps({"d": r}) for r in rows]) + "\n"


def run_routed(argv, route):
    """Run devo.main with urlopen answering each POST via route(query, from, to) -> body text,
    or an Exception. Thread-safe and order-independent (coverage/activity run in parallel)."""
    import threading
    reqs, lock = [], threading.Lock()

    def fake_urlopen(req, timeout=None):
        body = json.loads(req.data)
        with lock:
            reqs.append(body)
        r = route(body["query"], body["from"], body["to"])
        if isinstance(r, Exception):
            raise r
        return FakeResp(r, chunk=4096)

    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(devo.urllib.request, "urlopen", fake_urlopen), \
            mock.patch.object(devo, "load_config", lambda: dict(CFG)), \
            mock.patch.object(devo.time, "time", lambda: NOW), \
            mock.patch.object(devo, "RETRY_DELAY", 0), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = devo.main(argv)
    return code, out.getvalue(), err.getvalue(), reqs


def daily(field, entity, counts, frm, to):
    """group-every-1d rows for days (epoch midnights -> n) that fall inside [frm, to)."""
    cols = [("eventdate", "timestamp"), (field, "str"), ("n", "int8"), ("first", "timestamp"), ("last", "timestamp")]
    rows = [[d * 1000, entity, n, (max(d, frm)) * 1000, (min(d + DAY, to) - 60) * 1000]
            for d, n in sorted(counts.items()) if frm <= d + DAY - 1 and d < to]
    return compact(cols, rows)


class CoverageTests(unittest.TestCase):
    def route(self, q, frm, to):
        if "box.win_nxlog.system" in q and "EventID = 7036" in q:
            routine = [[(TODAY0 - k * DAY + 7000) * 1000, "host01.corp.example",
                        f"The nxlog service entered the {st} state."] for k in range(0, 5) for st in ("stopped", "running")]
            after_gap = [[(TODAY0 - DAY + 37260) * 1000, "host01.corp.example",
                          "The nxlog service entered the running state."]]
            return compact([("eventdate", "timestamp"), ("host", "str"), ("Message", "str")], routine + after_gap)
        if "box.win_nxlog.system" in q:
            # 5-day window ending today: day -2 missing, day -3 low
            counts = {TODAY0 - k * DAY: 1000 for k in (0, 1, 4, 5)}
            counts[TODAY0 - 3 * DAY] = 10
            return daily("host", "host01.corp.example", counts, frm, to)
        if "box.unix" in q:
            return daily("machine", "host01", {TODAY0 - k * DAY: 500 for k in range(0, 3)}, frm, to)
        if "vpn.zscaler.access" in q:
            cols = [(c, "str") for c in ("Username", "Host", "ServerIP", "ServerPort", "ConnectorIP",
                                          "ConnectionStatus")] + [("n", "int8"), ("first", "timestamp"),
                                                                  ("last", "timestamp")]
            return compact(cols, [["first.last@example.com", "host01.corp.example", "10.1.2.3", "22", "198.51.100.9",
                                   "close", 3, frm * 1000, (frm + 60) * 1000]])
        return compact([("eventdate", "timestamp"), ("host", "str"), ("n", "int8"), ("first", "timestamp"),
                        ("last", "timestamp")], [])  # other Windows tables: no data

    def test_report(self):
        code, out, err, reqs = run_routed(["coverage", "host01", "--from", "5d", "--linux-from", "3d"], self.route)
        self.assertEqual(code, 0, err)
        queries = [b["query"] for b in reqs]
        for t in ("system", "security", "sysmon", "powershell", "application"):
            self.assertTrue(any(f"from box.win_nxlog.{t} where weakhas(host, \"host01\")" in q for q in queries), t)
        self.assertTrue(any('from box.unix where weakhas(machine, "host01")' in q for q in queries))
        self.assertTrue(all(b["to"] == NOW for b in reqs if "box.win_nxlog" in b["query"]
                            and "7036" not in b["query"] and b["to"] > NOW - DAY))  # always up to now
        self.assertIn("box.win_nxlog.system  [host01.corp.example]", out)
        self.assertIn("MISSING days: 2026-09-26", out)
        self.assertIn("LOW days: 2026-09-25 (10 events)", out)
        self.assertIn("box.win_nxlog.security: 0 rows", out)
        self.assertIn("box.unix  [host01]  3/4 days", out)   # linux window 3d -> 4 calendar days
        self.assertIn("first.last@example.com  →  host01.corp.example 10.1.2.3:22  via 198.51.100.9", out)
        self.assertIn("stopped", out)
        near = out[out.index("nxlog restarts"):]
        self.assertIn("around gaps", near)
        self.assertIn("2026-09-27T10:21:00.000Z  host01.corp.example  running", near)  # the day after the gap
        self.assertLess(near.index("around gaps"), near.index("10:21"))
        self.assertIn("case-insensitive", err)

    def test_no_linux_and_json(self):
        code, out, _, reqs = run_routed(["coverage", "host01", "--from", "5d", "--no-linux", "--format", "json"],
                                        self.route)
        self.assertEqual(code, 0)
        self.assertFalse(any("box.unix" in b["query"] or "zscaler" in b["query"] for b in reqs))
        rep = json.loads(out)
        self.assertEqual(rep["results"]["box.win_nxlog.system"]["entities"]["host01.corp.example"]["missing"],
                         ["2026-09-26"])

    def test_one_failing_source_does_not_stop_the_rest(self):
        def route(q, frm, to):
            if "sysmon" in q:
                return http_error(500, '{"msg":"Error Launching Query","object":["Error Launching Query",'
                                       '"Unknown table `x`","2086000","MISSING_RESOURCE","MANUAL"]}')
            return self.route(q, frm, to)
        code, out, _, _ = run_routed(["coverage", "host01", "--from", "5d", "--no-linux"], route)
        self.assertEqual(code, 0)
        self.assertIn("box.win_nxlog.sysmon: ERROR", out)
        self.assertIn("MISSING days", out)

    def test_rejects_unsafe_name(self):
        code, _, err, reqs = run_routed(["coverage", 'x" or 1=1'], self.route)
        self.assertEqual((code, reqs), (1, []))

    def test_day_helpers(self):
        days = ["2026-09-24", "2026-09-25", "2026-09-26", "2026-09-27", "2026-09-28"]
        missing, low = devo.day_gaps({"2026-09-24": 5, "2026-09-25": 900, "2026-09-27": 1000, "2026-09-28": 3},
                                     days, 0.1)
        self.assertEqual(missing, ["2026-09-26"])
        self.assertEqual(low, [])  # first/last day are partial, never "low"
        self.assertEqual(devo.compress_days(["2026-09-14", "2026-09-15", "2026-09-16", "2026-09-20"]),
                         "2026-09-14..2026-09-16, 2026-09-20")
        self.assertEqual(devo.day_range(TODAY0 - DAY + 5, TODAY0 + 10), ["2026-09-27", "2026-09-28"])


class ActivityTests(unittest.TestCase):
    SOURCES = {"sources": [
        {"name": "signin", "table": "t.signin", "filter": "weakhas(upn, {T})", "group": "upn, ip",
         "chunk": "1h", "parallel": 3, "accounts": ["upn"], "note": "n1"},
        {"name": "audit", "table": "t.audit", "filter": "weakhas(actor, {T})", "select": "eventdate, actor, op",
         "accounts": ["actor"]},
        {"name": "broken", "table": "t.broken", "filter": "weakhas(u, {T})", "group": "u", "accounts": ["u"]},
        {"name": "empty", "table": "t.empty", "filter": "weakhas(u, {T})", "group": "u", "accounts": ["u"]}],
        "graph": {"name": "graph", "table": "t.graph", "filter": "uid -> {T}", "group": "uri", "chunk": "1h",
                  "parallel": 2}}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "sources.json")
        with open(self.src, "w") as f:
            json.dump(self.SOURCES, f)
        self.out = os.path.join(self.tmp, "out")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def route(self, q, frm, to):
        agg = [("n", "int8"), ("first", "timestamp"), ("last", "timestamp")]
        if "t.signin" in q:  # same group key in every chunk -> must be merged
            return compact([("upn", "str"), ("ip", "str")] + agg,
                           [["jsmith@example.com", "203.0.113.1", 2, frm * 1000, (to - 1) * 1000],
                            ["svc-other@example.com", "203.0.113.2", 1, frm * 1000, frm * 1000]])
        if "t.audit" in q:
            return compact([("eventdate", "timestamp"), ("actor", "str"), ("op", "str")],
                           [[(frm + 5) * 1000, "adm-jsmith@example.com", "Add member to role"],
                            [(frm + 6) * 1000, '"adm-jsmith@example.com"', "Update user"]])
        if "t.broken" in q:
            return http_error(500, '{"msg":"Error Launching Query","object":["Error Launching Query",'
                                   '"Unknown identifier `u`","1101001","QUERY_PARSING_ERROR","NO"]}')
        if "t.graph" in q:
            return compact([("uri", "str")] + agg, [["/v1.0/me", 1, frm * 1000, frm * 1000]])
        return compact([("u", "str")] + agg, [])

    def run_activity(self, *extra):
        return run_routed(["activity", "jsmith", "--from", "3h", "--out-dir", self.out, "--sources", self.src,
                           "--parallel-sources", "2", *extra], self.route)

    def test_sweep(self):
        code, out, err, reqs = self.run_activity()
        self.assertEqual(code, 0, err)
        signin = [b for b in reqs if "t.signin" in b["query"]]
        self.assertEqual(len(signin), 4)  # 3h from 16:03:01 -> 4 hour-aligned chunks
        self.assertIn('from t.signin where weakhas(upn, "jsmith") group by upn, ip select count() as n',
                      signin[0]["query"])
        with open(os.path.join(self.out, "signin.jsonl")) as f:
            rows = [json.loads(line) for line in f]
        merged = {r["upn"]: r["n"] for r in rows}
        self.assertEqual(merged, {"jsmith@example.com": 8, "svc-other@example.com": 4})  # re-aggregated
        with open(os.path.join(self.out, "summary.json")) as f:
            summ = {r["source"]: r for r in json.load(f)["sources"]}
        self.assertEqual(summ["signin"]["accounts"], ["jsmith@example.com"])  # only values matching the term
        self.assertEqual(summ["signin"]["events"], 12)
        self.assertEqual(summ["audit"]["accounts"], ["adm-jsmith@example.com"])
        self.assertIn("Unknown identifier", summ["broken"]["error"])
        self.assertIn("jsmith@example.com", out)
        self.assertIn("# 0 rows (1): empty", err)
        self.assertIn("# errors (1): broken", err)

    def test_graph_ids_and_validation(self):
        oid = "11111111-2222-3333-4444-555555555555"
        code, _, _, reqs = self.run_activity("--graph-ids", oid, "--only", "audit")
        self.assertEqual(code, 0)
        self.assertEqual({b["query"].split(" where")[0] for b in reqs}, {"from t.audit", "from t.graph"})
        self.assertTrue(any(f'uid -> "{oid}"' in b["query"] for b in reqs))
        code, _, _, reqs = run_routed(["activity", "jsmith", "--out-dir", self.out, "--sources", self.src,
                                       "--graph-ids", "not-a-guid"], self.route)
        self.assertEqual((code, reqs), (1, []))

    def test_by_ip_uses_only_ip_sources(self):
        conf = dict(self.SOURCES)
        conf["sources"] = self.SOURCES["sources"] + [
            {"name": "fw", "by": "ip", "table": "t.fw", "filter": "srcIp = {T} or dstIp = {T}",
             "group": "srcIp, dstIp", "accounts": ["srcIp", "dstIp"]}]
        with open(self.src, "w") as f:
            json.dump(conf, f)

        def route(q, frm, to):
            if "t.fw" in q:
                return compact([("srcIp", "ip4"), ("dstIp", "ip4"), ("n", "int8"), ("first", "timestamp"),
                                ("last", "timestamp")], [["203.0.113.10", "10.1.2.3", 5, frm * 1000, frm * 1000]])
            return self.route(q, frm, to)
        code, out, err, reqs = run_routed(["activity", "203.0.113.10", "--by", "ip", "--from", "1h", "--out-dir",
                                           self.out, "--sources", self.src], route)
        self.assertEqual(code, 0, err)
        self.assertEqual({b["query"].split(" where")[0] for b in reqs}, {"from t.fw"})
        self.assertIn('srcIp = "203.0.113.10" or dstIp = "203.0.113.10"', reqs[0]["query"])
        self.assertIn("203.0.113.10", out)
        code, _, err, reqs = run_routed(["activity", "not-an-ip", "--by", "ip", "--out-dir", self.out,
                                         "--sources", self.src], route)
        self.assertEqual((code, reqs), (1, []))

    def test_refuses_out_dir_inside_skill(self):
        inside = os.path.join(devo.SKILL_DIR, "references", "sweep")
        code, _, err, reqs = run_routed(["activity", "jsmith", "--out-dir", inside, "--sources", self.src],
                                        self.route)
        self.assertEqual((code, reqs), (1, []))
        self.assertFalse(os.path.exists(inside))

    def test_pre_select_before_group(self):
        src = {"name": "x", "table": "t.unix", "filter": "weakhas(message, {T})",
               "pre": "peek(message, re(\"for (\\\\S+)\"), 1) as acct", "group": "machine, acct"}
        q = devo.source_query(src, "jsmith")
        self.assertEqual(q, 'from t.unix where weakhas(message, "jsmith") select peek(message, re("for (\\\\S+)"), 1) '
                            'as acct group by machine, acct select count() as n, min(eventdate) as first, '
                            'max(eventdate) as last')

    def test_real_sources_file_is_well_formed(self):
        conf = devo.load_activity_sources()
        names = [x["name"] for x in conf["sources"]]
        self.assertEqual(len(names), len(set(names)))
        for x in conf["sources"] + [conf["graph"]]:
            self.assertTrue(x["table"] and "{T}" in x["filter"], x["name"])
            self.assertTrue(bool(x.get("group")) != bool(x.get("select")), x["name"])
            if x.get("chunk"):
                devo.chunk_step(x["chunk"])
        for x in conf["sources"]:
            self.assertIn(x.get("by", "user"), ("user", "ip", "host"), x["name"])
            q = devo.source_query(x, "jsmith")
            self.assertTrue(q.startswith(f"from {x['table']} where "), x["name"])
            self.assertIn('"jsmith"', q, x["name"])


class ProfileTests(unittest.TestCase):
    COLS = [("eventdate", "timestamp"), ("UserId", "str"), ("ClientIP", "str"), ("host", "str"),
            ("Operation", "str"), ("ChatThreadId", "str"), ("Policy", "str"), ("Message", "str"), ("Empty", "str")]
    ROWS = [[1790611330000, "alice@example.com", "203.0.113.10", "host01.corp.example", "MessageSent",
             "19:abc@thread.v2", "null", "Alice said hello to bob@example.com", None],
            [1790611331000, "bob@example.com", "203.0.113.11", "host02.corp.example", "ChatCreated",
             "19:abc@thread.v2", "null", "secret text", ""]]

    def test_patterns_and_roles(self):
        self.assertEqual(devo.classify("11111111-2222-3333-4444-555555555555"), "guid")
        self.assertEqual(devo.classify('"11111111-2222-3333-4444-555555555555"'), "guid-quoted")
        self.assertEqual(devo.classify("CORP\\alice"), "domain\\user")
        self.assertEqual(devo.classify("10.1.2.3"), "ipv4")
        self.assertEqual(devo.classify("host01.corp.example"), "fqdn")
        self.assertEqual(devo.classify("d41d8cd98f00b204e9800998ecf8427e"), "md5")
        prof = devo.profile_rows(self.COLS, self.ROWS)
        self.assertEqual(prof["eventdate"]["role"], "time")
        self.assertEqual(prof["UserId"]["role"], "user")
        self.assertEqual(prof["UserId"]["case"], "lower")
        self.assertEqual(prof["ClientIP"]["role"], "ip")
        self.assertEqual(prof["host"]["role"], "host")
        self.assertEqual(prof["ChatThreadId"]["role"], "join-id")
        self.assertEqual(prof["Empty"]["fill"], 0.0)
        self.assertEqual(prof["Policy"]["fill"], 0.0)  # the string "null" counts as empty

    def test_values_only_for_categorical_field_names(self):
        cols = [("repo", "str"), ("AppGroup", "str"), ("Customer", "str"), ("action", "str"), ("Version", "str"),
                ("EventID", "int4"), ("tenantId", "str")]
        rows = [["acme/secret-repo", "Acme-ZPA", "Acme Services", "accept", "1.2.3.4", 4624,
                 "00000000-1111-2222-3333-444444444444"]]
        prof = devo.profile_rows(cols, rows)
        for f in ("repo", "AppGroup", "Customer", "Version", "tenantId"):
            self.assertNotIn("values", prof[f], f)
        self.assertEqual(prof["action"]["values"], ["accept"])
        self.assertEqual(prof["EventID"]["values"], ["4624"])

    def test_no_identity_values_kept(self):
        prof = devo.profile_rows(self.COLS, self.ROWS)
        self.assertEqual(prof["Operation"]["values"], ["ChatCreated", "MessageSent"])  # enum kept
        for f in ("UserId", "ClientIP", "host", "ChatThreadId", "Message"):
            self.assertNotIn("values", prof[f], f)
        dump = json.dumps(prof)
        for secret in ("alice", "bob", "203.0.113", "host01", "secret text", "abc@thread"):
            self.assertNotIn(secret, dump)

    def test_curated_roles_override_the_profile(self):
        fm = {"tables": {"t.one": devo.compact_profile({"window": "15m", "rows": 2,
                                                        "fields": devo.profile_rows(self.COLS, self.ROWS)})}}
        d = tempfile.mkdtemp()
        path, roles = os.path.join(d, "fm.json"), os.path.join(d, "roles.json")
        with open(path, "w") as f:
            json.dump(fm, f)
        with open(roles, "w") as f:
            json.dump({"t.one": {"host": "ip", "Message": None, "Nope": "user"}}, f)
        merged = devo.load_field_map(path, roles)
        self.assertEqual(merged["tables"]["t.one"]["fields"]["host"]["role"], "ip")
        self.assertNotIn("role", merged["tables"]["t.one"]["fields"]["Message"])
        self.assertTrue(merged["tables"]["t.one"]["fields"]["host"].get("curated"))
        self.assertNotIn("Nope", merged["tables"]["t.one"]["fields"])  # only fields with data

    def test_fields_lookup_is_offline(self):
        fm = {"tables": {"t.one": devo.compact_profile({"window": "15m", "rows": 2, "fields": devo.profile_rows(self.COLS, self.ROWS)}),
                         "t.two": {"window": "15m", "rows": 1, "fields": {"x": {"type": "str", "fill": 1.0,
                                                                                "role": "user"}}}}}
        path = os.path.join(tempfile.mkdtemp(), "fm.json")
        with open(path, "w") as f:
            json.dump(fm, f)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(devo, "load_config", side_effect=AssertionError("no creds needed")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(devo.main(["fields", "--role", "ip", "--map", path]), 0)
            self.assertEqual(devo.main(["fields", "t.one", "--map", path]), 0)
        self.assertIn("t.one: ClientIP (100%)", out.getvalue())
        self.assertNotIn("t.two:", out.getvalue().split("t.one  (")[0])
        self.assertIn("ChatThreadId", out.getvalue())
        self.assertNotIn("Empty ", out.getvalue())  # empty fields hidden unless --all


class TablesTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"DEVO_CACHE_DIR": self.root})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    @staticmethod
    def route(q, frm, to):
        assert "siem.logtrust.collector.counter" in q, q
        return compact([("object", "str"), ("events", "int8")],
                       [["box.win_nxlog.security", 900], ["siem.logtrust.alert.info", 50]])

    def test_first_use_fetches_then_serves_from_cache(self):
        code, out, err, reqs = run_routed(["tables", "--grep", "^siem\\.logtrust\\.alert"], self.route)
        self.assertEqual((code, len(reqs)), (0, 1), err)
        self.assertIn("siem.logtrust.alert.info", out)
        self.assertIn("fetched live now, cached", err)
        code, out, err, reqs = run_routed(["tables"], self.route)
        self.assertEqual((code, reqs), (0, []), err)  # cached: no request
        self.assertLess(out.index("box.win_nxlog.security"), out.index("siem.logtrust.alert.info"))  # by volume
        code, out, err, reqs = run_routed(["tables", "--live"], self.route)
        self.assertEqual((code, len(reqs)), (0, 1))
        code, out, err, reqs = run_routed(["tables", "--live", "--from", "1h"], self.route)  # shown, not cached
        self.assertEqual((code, len(reqs)), (0, 1))
        self.assertIn("events since 1h", err)

    def test_expired_list_is_refetched(self):
        run_routed(["tables"], self.route)
        with mock.patch.object(devo, "TTL", dict(devo.TTL, tables=-1)):
            code, _, _, reqs = run_routed(["tables"], self.route)
        self.assertEqual((code, len(reqs)), (0, 1))


class CommentTests(unittest.TestCase):
    ARGS = ["comment", "123456", "--title", "TEST - title", "--msg", "hello world"]

    def test_preview_sends_nothing(self):
        code, out, err, reqs = run_cli(self.ARGS, [FakeResp(json.dumps(ALERT))])
        self.assertEqual(code, 0)
        self.assertEqual([r.get_method() for r in reqs], ["GET"])  # only reads the alert for context
        self.assertIn("NOT SENT", out + err)
        self.assertIn('"commentTitle": "TEST - title"', out)
        self.assertIn("Suspicious Login", out)
        self.assertNotIn(CFG["token"], out + err)

    def test_confirm_posts_and_verifies(self):
        after = dict(ALERT, commentsList=ALERT["commentsList"] + [
            {"author": {"user": {"username": "me@example.com"}}, "creationDate": 1790611400000,
             "title": "TEST - title", "msg": "hello world"}])
        code, out, err, reqs = run_cli(self.ARGS + ["--confirm"],
                                       [FakeResp(json.dumps(ALERT)), FakeResp("true"), FakeResp(json.dumps(after))])
        self.assertEqual(code, 0)
        post = reqs[1]
        self.assertEqual(post.get_method(), "POST")
        self.assertTrue(post.full_url.endswith("/alerts/v1/comments/add"))
        self.assertEqual(json.loads(post.data), {"elementId": "123456", "commentType": "ALERT",
                                                 "commentTitle": "TEST - title", "commentMsg": "hello world"})
        self.assertIn("verified", out + err)

    def test_confirm_reports_unverified(self):
        code, out, err, _ = run_cli(self.ARGS + ["--confirm"],
                                    [FakeResp(json.dumps(ALERT)), FakeResp("true"), FakeResp(json.dumps(ALERT))])
        self.assertEqual(code, 2)
        self.assertIn("could not verify", err)

    def test_rejects_empty_and_bad_id(self):
        code, _, _, reqs = run_cli(["comment", "12x", "--title", "t", "--msg", "m", "--confirm"], [])
        self.assertEqual((code, reqs), (1, []))
        code, _, _, reqs = run_cli(["comment", "123", "--title", " ", "--msg", "m", "--confirm"], [])
        self.assertEqual((code, reqs), (1, []))


class WriteSurfaceTests(unittest.TestCase):
    def test_only_expected_writes(self):
        with open(devo.__file__) as f:
            src = f.read()
        for verb in ("updateStatus", "/tags", "alertDefinitions/status"):
            self.assertNotIn(verb, src)
        # POSTs: the Query API and comments/add (behind --confirm)
        self.assertEqual(src.count('http_open("POST"'), 2)
        self.assertIn('"comments/add"', src)
        # Activeboard writes only through board_call, one call site per verb, each behind --confirm
        for verb, n in (('"PUT"', 1), ('"PATCH"', 1), ('"DELETE"', 1), ('board_call(cfg, "POST"', 2)):
            self.assertEqual(src.count(verb), n, verb)
        self.assertNotIn('http_open("PUT"', src)
        self.assertNotIn('http_open("DELETE"', src)
        writers = ("cmd_board_push", "cmd_board_set", "cmd_board_clone", "cmd_board_delete")
        for name in writers:
            body = src[src.index(f"def {name}("):]
            body = body[:body.index("\ndef ", 1)]
            self.assertLess(body.index("if not a.confirm"), body.index("board_call(cfg, \"" ), name)
        for m in re.finditer(r'board_call\(cfg, "(POST|PUT|PATCH|DELETE)"', src):
            owner = src.rfind("\ndef ", 0, m.start())
            self.assertIn(src[owner + 5:src.index("(", owner)], writers)

    def test_cloudflare_hint_only_for_1010(self):
        e = devo.api_error(504, '{"title":"Error 504: Gateway time-out","detail":"The origin web server '
                                'did not respond to Cloudflare within the allowed time"}')
        self.assertNotIn("User-Agent", e.hint)
        self.assertIn("504", str(e))
        self.assertIn("User-Agent", devo.api_error(403, "error code: 1010").hint)


class AutoSplitTests(unittest.TestCase):
    """fetch() halves windows that come back full, down to min_split."""
    def route_factory(self, per_minute):
        cols = [("eventdate", "timestamp"), ("x", "int8")]

        def route(q, frm, to):
            n = (to - frm) // 60 * per_minute
            limit = 100
            rows = [[(frm + i) * 1000, i] for i in range(min(n, limit))]
            return compact(cols, rows)
        return route

    def run_q(self, *extra, per_minute=1):
        return run_routed(["query", "from t select *", "--from", "2026-09-28T10:00", "--to", "2026-09-28T13:00",
                           "--limit", "100", "--format", "jsonl", *extra], self.route_factory(per_minute))

    def test_splits_until_complete(self):
        code, out, err, reqs = self.run_q("--auto-split")  # 180 rows over 3h, 100 per window
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.strip().splitlines()), 180)
        self.assertIn("auto-split: 1 window(s) hit --limit 100", err)
        self.assertNotIn("results incomplete", err)
        self.assertEqual(len(reqs), 3)

    def test_still_full_at_min_split_warns(self):
        code, out, err, _ = self.run_q("--auto-split", "--min-split", "1h", per_minute=10)
        self.assertEqual(code, 0, err)
        self.assertIn("even at the minimum split", err)
        self.assertIn("raise --limit", err)

    def test_defaults(self):
        self.assertTrue(devo.default_auto_split("from t select *", 5000))
        self.assertFalse(devo.default_auto_split("from t select *", 200))  # a sample
        self.assertFalse(devo.default_auto_split("from t group by a select count() as n", 5000))
        self.assertFalse(devo.default_auto_split("from t select *", None))
        _, _, err, reqs = self.run_q()  # --limit 100: off by default
        self.assertEqual(len(reqs), 1)
        self.assertIn("--auto-split halves", err)

    def test_split_cap(self):
        self.assertGreater(devo.MAX_SPLITS, 0)
        code, _, err, reqs = run_routed(["query", "from t select *", "--from", "2026-09-01", "--to", "2026-09-28",
                                         "--limit", "100", "--auto-split", "--min-split", "1m"],
                                        self.route_factory(10))
        self.assertEqual(code, 0, err)
        self.assertLessEqual(len(reqs), 2 * devo.MAX_SPLITS + 1)


class OutputControlTests(unittest.TestCase):
    def test_stats_head_out_and_tz(self):
        code, out, err, _ = run_cli(["query", "from t select *", "--stats"], [FakeResp(COMPACT)])
        self.assertEqual(code, 0)
        self.assertIn("# stats: 2 rows, 3 columns", out)
        self.assertIn("srcIp · 1 · 1 · 203.0.113.10 ×1", out)
        code, out, err, _ = run_cli(["query", "from t select *", "--head", "1", "--format", "csv"],
                                    [FakeResp(COMPACT)])
        self.assertEqual(len(out.strip().splitlines()), 2)  # header + 1 row
        self.assertIn("showing the first 1 of 2 rows", err)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            code, out, err, _ = run_cli(["query", "from t select *", "--format", "csv", "--out", path],
                                        [FakeResp(COMPACT)])
            self.assertIn("# stats:", out)  # summary only on stdout
            with open(path) as f:
                self.assertEqual(len(f.read().strip().splitlines()), 3)
            code, out, err, _ = run_cli(["query", "from t select *", "--out", path, "--no-summary"],
                                        [FakeResp(COMPACT)])
            self.assertEqual(out, "")
        code, out, err, _ = run_cli(["query", "from t select *", "--format", "csv", "--tz", "Europe/London"],
                                    [FakeResp(COMPACT)])
        self.assertIn("eventdate,eventdate_local,srcIp,n", out)
        self.assertIn("2026-09-28T16:02:10.000Z,2026-09-28T17:02:10+01:00", out)  # summer time (UTC+1)

    def test_ui_lint(self):
        self.assertTrue(devo.ui_lint("from t select timestamp as t2"))
        self.assertFalse(devo.ui_lint("from t select timestamp(1) as t2"))
        self.assertFalse(devo.ui_lint('from t where msg -> "timestamp"'))
        _, _, err, _ = run_cli(["query", "from t select timestamp", "--ui-safe"], [FakeResp(COMPACT)])
        self.assertIn("ui-safe", err)


class LocalTimeTests(unittest.TestCase):
    def test_parse_and_local(self):
        tz = devo.get_tz("Europe/London")
        self.assertEqual(devo.to_local("2026-10-02T13:04:32.123Z", tz), "2026-10-02T14:04:32+01:00")
        self.assertEqual(devo.to_local("2026-11-02T13:04:32", tz), "2026-11-02T13:04:32+00:00")  # GMT, no Z = UTC
        self.assertEqual(devo.to_local(1790946160870, tz), devo.to_local("2026-10-02T13:02:40.870Z", tz))
        self.assertEqual(devo.iso_utc(devo.parse_utc("2026-10-02T12:40:06.3413563+00:00")), "2026-10-02T12:40:06Z")
        self.assertEqual(devo.iso_utc(devo.parse_utc("2026-10-02 14:40:06+01:00")), "2026-10-02T13:40:06Z")
        self.assertIsNone(devo.parse_utc("not a time"))
        self.assertIsNone(devo.parse_utc(""))
        with self.assertRaises(devo.DevoError):
            devo.get_tz("Mars/Olympus")


class TermTests(unittest.TestCase):
    def test_split_top_and_term_filter(self):
        self.assertEqual(devo.split_top('a = 1, f(x, y), b in {1, 2}, c = "p,q"'),
                         ["a = 1", "f(x, y)", "b in {1, 2}", 'c = "p,q"'])
        self.assertEqual(devo.term_filter("EventID = 4103, weakhas(f, {T})", ["a"]),
                         'EventID = 4103, weakhas(f, "a")')
        self.assertEqual(devo.term_filter("EventID = 4103, weakhas(f, {T}) or weakhas(g, {T})", ["a", "b"]),
                         'EventID = 4103, ((weakhas(f, "a") or weakhas(g, "a")) or (weakhas(f, "b") or '
                         'weakhas(g, "b")))')

    def test_expand(self):
        self.assertEqual(devo.expand_terms("Jane.Smith@example.com"),
                         ["jane.smith@example.com", "jane.smith", "jsmith"])
        self.assertEqual(devo.expand_terms("Jane.Smith@example.com", ["{local}", "x.{f}{l}", "{first}-{last}"]),
                         ["jane.smith", "x.js", "jane-smith"])
        with self.assertRaises(devo.DevoError):
            devo.expand_terms("jane.smith@example.com", ["{nope}"])
        with self.assertRaises(devo.DevoError):
            devo.expand_terms("jsmith")


class EventTimeTests(unittest.TestCase):
    def test_map_is_well_formed_and_documented(self):
        fams = devo.load_event_time()
        with open(os.path.join(devo.SKILL_DIR, "references", "table-guide.md")) as f:
            guide = f.read()
        self.assertIn("## Event time per family", guide)
        for fam in fams:
            re_ = __import__("re")
            re_.compile(fam["tables"])
            self.assertIsInstance(fam["dedupe"], list, fam["family"])
            for t in fam["lag"]:
                self.assertIs(devo.event_time_for(t, fams), fam, t)  # first match wins: no shadowing
            if fam["linq"] and re_.fullmatch(r"\w+", fam["linq"]):
                self.assertIn(f"`{fam['linq']}`", guide, fam["family"])
        self.assertIsNone(devo.event_time_for("box.unix")["linq"])
        self.assertIn("CreationTime", devo.event_time_for("cloud.office365.management.sharepoint")["linq"])
        self.assertIn("rawMessage", devo.event_time_for("cloud.office365.management.powerplatform")["linq"])
        self.assertIsNone(devo.event_time_for("no.such.table"))

    def test_source_query_event_time_and_rows(self):
        et = {"linq": "timestamp", "dedupe": ["report_id"]}
        grouped = {"name": "g", "table": "t.x", "filter": "weakhas(u, {T})", "group": "host, u"}
        q = devo.source_query(grouped, ["a"], et=et)
        self.assertIn("select timestamp as event_time group by host, u", q)
        self.assertIn("min(event_time) as first_event, max(event_time) as last_event", q)
        q = devo.source_query(grouped, ["a"], rows=True, et=et, dedupe=["report_id"])
        self.assertTrue(q.endswith("select timestamp as event_time select eventdate, host, u, report_id"), q)
        pre = dict(grouped, pre="peek(m, re(\"x\"), 1) as src", group="host, src")
        q = devo.source_query(pre, ["a"], rows=True, et=et)
        self.assertTrue(q.endswith("select eventdate, host"), q)  # derived src is output already
        plain = {"name": "p", "table": "t.y", "filter": "weakhas(u, {T})", "select": "*"}
        self.assertTrue(devo.source_query(plain, ["a"], et=et).endswith("select timestamp as event_time select *"))
        self.assertTrue(devo.source_query(plain, ["a"]).endswith('weakhas(u, "a") select *'))

    def test_merge_agg_event_times(self):
        rows = [{"k": 1, "n": 2, "first": "b", "last": "c", "first_event": "a2", "last_event": "c2"},
                {"k": 1, "n": 3, "first": "a", "last": "d", "first_event": "a1", "last_event": "d1"}]
        m = devo.merge_agg(rows, ["k"])[0]
        self.assertEqual((m["n"], m["first"], m["last"], m["first_event"], m["last_event"]),
                         (5, "a", "d", "a1", "d1"))


class ActivityTermsTests(ActivityTests):
    def test_terms_or_and_matched(self):
        code, out, err, reqs = run_routed(["activity", "--terms", "jsmith,adm-jsmith", "--term", "nobody",
                                           "--from", "3h", "--out-dir", self.out, "--sources", self.src,
                                           "--only", "audit"], self.route)
        self.assertEqual(code, 0, err)
        self.assertIn('((weakhas(actor, "jsmith")) or (weakhas(actor, "adm-jsmith")) or (weakhas(actor, "nobody")))',
                      reqs[0]["query"])
        self.assertIn("matched term (events)", out)
        self.assertIn("terms not matched in any source that names its term: nobody", err)
        with open(os.path.join(self.out, "summary.json")) as f:
            summ = json.load(f)
        self.assertEqual(summ["terms"], ["jsmith", "adm-jsmith", "nobody"])
        self.assertEqual(summ["sources"][0]["matched"], {"jsmith": 2, "adm-jsmith": 2})

    def test_expand_needs_upn(self):
        code, _, err, reqs = run_routed(["activity", "jsmith", "--expand", "--out-dir", self.out, "--sources",
                                         self.src], self.route)
        self.assertEqual((code, reqs), (1, []))
        code, _, err, reqs = run_routed(["activity", "jane.smith@example.com", "--expand", "--from", "1h",
                                         "--only", "audit", "--out-dir", self.out, "--sources", self.src],
                                        self.route)
        self.assertEqual(code, 0, err)
        self.assertIn('"jsmith"', reqs[0]["query"])  # default naming: {upn}, {first}.{last}, {f}{last}
        self.assertIn("default naming", err)
        with mock.patch.dict(os.environ, {"DEVO_CACHE_DIR": tempfile.mkdtemp()}):
            self.assertEqual(run_routed(["cache", "naming", "set", "{upn},adm.{f}{last}"], self.route)[0], 0)
            code, _, err, reqs = run_routed(["activity", "jane.smith@example.com", "--expand", "--from", "1h",
                                             "--only", "audit", "--out-dir", self.out, "--sources", self.src],
                                            self.route)
        self.assertEqual(code, 0, err)
        self.assertIn('"adm.jsmith"', reqs[0]["query"])
        self.assertNotIn('"jane.smith"', reqs[0]["query"])

    def test_tz_adds_local_fields(self):
        code, _, err, _ = run_routed(["activity", "jsmith", "--from", "1h", "--only", "audit", "--tz", "UTC",
                                      "--out-dir", self.out, "--sources", self.src], self.route)
        self.assertEqual(code, 0, err)
        with open(os.path.join(self.out, "audit.jsonl")) as f:
            rec = json.loads(f.readline())
        self.assertTrue(rec["eventdate_local"].endswith("+00:00"))


class LagTests(unittest.TestCase):
    def route(self, q, frm, to):
        if "box.unix" in q:
            return compact([("eventdate", "timestamp"), ("n", "int8"), ("newest_ingest", "timestamp")],
                           [[frm * 1000, 10, (frm + 60) * 1000]])
        if "ah.overflow" in q and "/ 1000)" in q:
            return http_error(200, '{"e":[500,"Error Processing Query: Maximum number of elements surpassed for '
                                   'operation `collectcompact` (configured maximum: 100000)",1090001,"QUERY_LIMIT","NO"]}')
        cols = [("eventdate", "timestamp"), ("n", "int8"), ("p50", "int8"), ("p95", "int8"),
                ("newest_event", "timestamp"), ("newest_ingest", "timestamp")]
        return compact(cols, [[frm * 1000, 100, 60, 600, (frm + 30) * 1000, (frm + 90) * 1000],
                              [(frm + 3600) * 1000, 300, 120, 900, (frm + 3700) * 1000, (frm + 3720) * 1000]])

    def test_weighted_pct(self):
        self.assertEqual(devo.weighted_pct([(60, 100), (120, 300)], 50), 120)
        self.assertEqual(devo.weighted_pct([(60, 300), (120, 100)], 50), 60)
        self.assertIsNone(devo.weighted_pct([], 50))
        self.assertEqual(devo.human_secs(45), "45s")
        self.assertEqual(devo.human_secs(5400), "90m")
        self.assertEqual(devo.human_secs(3 * 86400), "3.0d")

    def test_lag_table_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "lag.json")
            code, stdout, err, reqs = run_routed(["lag", "--tables", "win_nxlog.security|box.unix", "--from", "3h",
                                                  "--table", "t.overflow", "--out", out], self.route)
            self.assertEqual(code, 0, err)
            with open(out) as f:
                res = {r["table"]: r for r in json.load(f)["tables"]}
        self.assertEqual(sorted(res), ["box.unix", "box.win_nxlog.security", "t.overflow"])  # --table always added
        sec = res["box.win_nxlog.security"]
        self.assertEqual((sec["p50_s"], sec["worst_hour_p95_s"], sec["latest_hour_p50_s"]), (120, 900, 120))
        self.assertIn("select timestamp as event_time", sec["query"])
        self.assertFalse(res["box.unix"]["has_event_time"])
        self.assertIn("no event-time field", stdout)
        code, stdout, err, reqs = run_routed(["lag", "--tables", "ah\\.overflow", "--table", "cloud.azure.ah.overflow",
                                              "--from", "1h"], self.route)
        self.assertEqual(code, 0, err)
        self.assertTrue(any("/ 60000)" in b["query"] for b in reqs))  # minute fallback
        self.assertIn("2.0h", stdout)  # hourly p50s of 60 and 120 minutes, weighted 100:300


class BatchTests(unittest.TestCase):
    def route(self, q, frm, to):
        if "bad" in q:
            return http_error(500, '{"msg":"Error Launching Query","object":["Error Launching Query",'
                                   '"Unknown identifier `bad`","1101001","QUERY_PARSING_ERROR","NO"]}')
        return compact([("eventdate", "timestamp"), ("u", "str")], [[frm * 1000, q.split('"')[1]]])

    def test_batch(self):
        with tempfile.TemporaryDirectory() as d:
            spec = os.path.join(d, "spec.jsonl")
            with open(spec, "w") as f:
                f.write('# comment\n')
                f.write(json.dumps({"name": "a", "query": 'from t where u = "{user}", x in {1, 2} select u',
                                    "from": "{from}"}) + "\n")
                f.write(json.dumps({"name": "b", "query": 'from t where u = "{user}" select bad', "format": "csv"})
                        + "\n")
                f.write(json.dumps({"name": "c", "query": 'from t where u = "{other}" select u', "format": "csv"})
                        + "\n")
            out = os.path.join(d, "out")
            code, stdout, err, reqs = run_routed(["batch", spec, "--out-dir", out, "--vars", "user=jsmith,from=2h",
                                                  "--tz", "UTC"], self.route)
            self.assertEqual(code, 2)  # one job failed
            self.assertIn('u = "jsmith", x in {1, 2}', reqs[0]["query"] + reqs[1]["query"] + reqs[2]["query"])
            self.assertIn("unreplaced placeholder(s) other", err)
            self.assertEqual(sorted(os.listdir(out)), ["a.jsonl", "a.log", "b.log", "batch-summary.json", "c.csv",
                                                       "c.log"])
            with open(os.path.join(out, "a.jsonl")) as f:
                rec = json.loads(f.readline())
            self.assertEqual(rec["u"], "jsmith")
            self.assertIn("eventdate_local", rec)
            with open(os.path.join(out, "b.log")) as f:
                self.assertIn("Unknown identifier", f.read())
            self.assertIn("limit reached", stdout)
            a_from = [b for b in reqs if "select u" in b["query"] and "jsmith" in b["query"]][0]["from"]
            self.assertEqual(a_from, NOW - 7200)

    def test_spec_validation(self):
        with tempfile.TemporaryDirectory() as d:
            spec = os.path.join(d, "spec.json")
            for jobs in ([{"name": "../x", "query": "from t"}], [{"name": "a"}],
                         [{"name": "a", "query": "q"}, {"name": "a", "query": "q"}]):
                with open(spec, "w") as f:
                    json.dump(jobs, f)
                code, _, err, reqs = run_routed(["batch", spec, "--out-dir", os.path.join(d, "o")], self.route)
                self.assertEqual((code, reqs), (1, []), jobs)
        with tempfile.TemporaryDirectory() as d:  # a single job (JSONL with one line) is a valid spec
            spec = os.path.join(d, "one.jsonl")
            with open(spec, "w") as f:
                f.write(json.dumps({"name": "a", "query": 'from t where u = "x" select u'}) + "\n")
            self.assertEqual(len(devo.load_spec(spec)), 1)
            with open(spec, "w") as f:
                f.write(json.dumps({"name": "a", "query": "q", "limit": "500"}) + "\n")
            code, _, err, reqs = run_routed(["batch", spec, "--out-dir", os.path.join(d, "o")], self.route)
            self.assertEqual((code, reqs), (1, []))
            self.assertIn("limit must be a whole number", err)
        with self.assertRaises(devo.DevoError):
            devo.parse_vars(['user=a"b'])
        self.assertEqual(devo.substitute({"q": "x {a} {b} {4624}"}, {"a": "1"}), {"q": "x 1 {b} {4624}"})


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        sp = '{"Id": "rec-1", "CreationTime": "2026-10-01T09:00:00", "Operation": "FileDownloaded"}'
        files = {
            "o365_sharepoint": ("cloud.office365.management.sharepoint", [
                {"eventdate": "2026-10-01T09:05:00.000Z", "event_time": "2026-10-01T09:00:00.000Z", "UserId": "j@x",
                 "Operation": "FileDownloaded", "Id": "rec-1"},
                {"eventdate": "2026-10-01T10:05:00.000Z", "event_time": "2026-10-01T09:00:00.000Z", "UserId": "j@x",
                 "Operation": "FileDownloaded", "Id": "rec-1"},  # back-fill duplicate
                {"eventdate": "2026-10-01T09:06:00.000Z", "UserId": "j@x", "Operation": "FileAccessed",
                 "message": sp.replace("rec-1", "rec-2").replace("09:00:00", "08:30:00")}]),
            "entra_audit": ("cloud.azure.ad.audit", [
                {"operationName": "Add member", "tenantId": "t1", "n": 1, "first": "2026-10-01T07:00:00.000Z",
                 "last": "2026-10-01T07:00:00.000Z", "first_event": "2026-10-01T06:59:00.000Z",
                 "last_event": "2026-10-01T06:59:00.000Z"},
                {"operationName": "Add member", "tenantId": None, "n": 1, "first": "2026-10-01T07:00:00.000Z",
                 "last": "2026-10-01T07:00:00.000Z"}]),
            "linux": ("box.unix", [{"machine": "web01", "appName": "sshd", "n": 3,
                                    "first": "2026-09-30T23:30:00.000Z", "last": "2026-09-30T23:50:00.000Z"}]),
        }
        sources = []
        for name, (table, recs) in files.items():
            path = os.path.join(self.dir, f"{name}.jsonl")
            with open(path, "w") as f:
                for r in recs:
                    f.write(json.dumps(r) + "\n")
            sources.append({"source": name, "table": table, "rows": len(recs), "file": path,
                            "mode": "rows" if name == "o365_sharepoint" else "grouped"})
        with open(os.path.join(self.dir, "summary.json"), "w") as f:
            json.dump({"term": "j", "terms": ["j"], "window": ["a", "b"], "sources": sources}, f)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir)

    def test_backfill_before_the_window_is_dropped(self):
        with open(os.path.join(self.dir, "summary.json")) as f:
            summ = json.load(f)
        summ["window"] = ["2026-10-01T08:00:00Z", "2026-10-02T00:00:00Z"]
        with open(os.path.join(self.dir, "summary.json"), "w") as f:
            json.dump(summ, f)
        with mock.patch.object(devo, "load_config", side_effect=devo.DevoError("no Devo token found", code=1)):
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                self.assertEqual(devo.main(["timeline", self.dir]), 0)
                self.assertEqual(devo.main(["timeline", self.dir, "--keep-outside", "--out",
                                            os.path.join(self.dir, "all.json")]), 0)
        with open(os.path.join(self.dir, "timeline.json")) as f:
            kept = json.load(f)["events"]
        with open(os.path.join(self.dir, "all.json")) as f:
            every = json.load(f)["events"]
        self.assertTrue(all(e["t_utc"] >= "2026-10-01T08:00" for e in kept))
        self.assertGreater(len(every), len(kept))
        self.assertIn("before the window", err.getvalue())

    def test_timeline_offline(self):
        with mock.patch.object(devo, "load_config", side_effect=devo.DevoError("no Devo token found", code=1)):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = devo.main(["timeline", self.dir, "--tz", "Europe/London"])
        self.assertEqual(code, 0, err.getvalue())
        with open(os.path.join(self.dir, "timeline.json")) as f:
            tl = json.load(f)
        ev = tl["events"]
        self.assertEqual([e["source"] for e in ev], ["linux", "entra_audit", "o365_sharepoint", "o365_sharepoint"])
        self.assertEqual(ev[0]["time_basis"], "ingest")
        self.assertEqual(ev[0]["t_local"], "2026-10-01T00:30:00+01:00")  # local day differs from UTC day
        self.assertEqual(ev[0]["count"], 3)
        self.assertEqual(ev[1]["t_utc"], "2026-10-01T06:59:00Z")  # first_event, and only one audit copy
        self.assertEqual(ev[2]["t_utc"], "2026-10-01T08:30:00Z")  # CreationTime from message
        self.assertEqual(ev[3]["action"], "FileDownloaded")
        self.assertIn("dropped 1 duplicate", err.getvalue())
        self.assertIn("2026-10-01 Thu: 6 direct events", out.getvalue())  # all on the local day 10-01
        self.assertTrue(os.path.exists(os.path.join(self.dir, "timeline.txt")))
        self.assertTrue(any("no event-time field" in n for n in tl["notes"]))
        import shutil  # a moved directory still works: files are found next to summary.json
        moved = self.dir + "-moved"
        shutil.move(self.dir, moved)
        try:
            events, _, _ = devo.build_timeline(moved)
            self.assertEqual(len(events), 4)
        finally:
            shutil.move(moved, self.dir)


class TeamsTests(unittest.TestCase):
    ME, OTHER, THIRD = ("aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002",
                        "cccccccc-0000-0000-0000-000000000003")
    ONE = f"19:{ME}_{OTHER}@unq.gbl.spaces"
    GROUP = "19:0123456789abcdef0123456789abcdef@thread.v2"
    MEET = "19:meeting_ABCdef123=@thread.v2"
    MD1, MD2 = "dddddddd-0000-0000-0000-000000000001", "dddddddd-0000-0000-0000-000000000002"

    def recs(self):
        me, other = self.ME, self.OTHER

        def msg(i, op, who, oid, tid, t, **kw):
            return dict({"Id": f"r{i}", "Operation": op, "UserId": who, "UserKey": oid, "ChatThreadId": tid,
                         "CreationTime": t, "MessageId": f"m{i}"}, **kw)
        return [
            msg(1, "MessageSent", "me@x.com", me, self.ONE, "2026-10-01T08:00:00", CommunicationType="OneOnOne"),
            msg(2, "MessageCreatedHasLink", "me@x.com", me, self.ONE, "2026-10-01T08:00:00",
                CommunicationType="OneOnOne", MessageId="m1",
                MessageFiles=[{"FileUrl": "https://t.sharepoint.com/a%20b.docx"}],
                MessageURLs=["https://t.sharepoint.com/a%20b.docx", "https://example.org/x",
                             "https://statics.teams.cdn.office.net/emoji.png"]),
            msg(1, "MessageSent", "me@x.com", me, self.ONE, "2026-10-01T08:00:00"),  # duplicate record id
            msg(3, "ReactedToMessage", "other@x.com", other, self.ONE, "2026-10-01T08:01:00",
                CommunicationType="OneOnOne"),
            msg(4, "MessageUpdated", "me@x.com", me, self.GROUP, "2026-10-01T23:30:00", CommunicationType="GroupChat",
                ChatName="Project", MessageVersion="2"),
            msg(5, "MessageSent", "third@y.com", self.THIRD, self.GROUP, "2026-10-01T23:31:00",
                CommunicationType="GroupChat"),
            {"Id": "r6", "Operation": "MeetingDetail", "UserId": "other@x.com", "UserKey": other, "ChatThreadId": self.MEET,
             "CreationTime": "2026-10-01T15:00:00", "StartTime": "2026-10-01T13:00:00", "EndTime": "2026-10-01T14:00:00",
             "Organizer": {"UserObjectId": other}, "CommunicationSubType": "RecurringMeeting", "Modalities": "Audio",
             "ArtifactsShared": [{"ArtifactSharedName": "MeetingRecorded"}]},
            {"Id": "r6b", "Operation": "MeetingDetail", "UserId": "other@x.com", "UserKey": other,
             "ChatThreadId": self.MEET, "CreationTime": "2026-10-02T15:00:00", "StartTime": "2026-10-02T13:00:00",
             "EndTime": "2026-10-02T13:30:00", "Organizer": {"UserObjectId": other}, "Id2": self.MD2},
            {"Id": "r7", "Operation": "MeetingParticipantDetail", "UserId": "other@x.com", "MeetingDetailId": self.MD1,
             "ChatThreadId": self.MEET, "CreationTime": "2026-10-01T15:00:00", "JoinTime": "2026-10-01T13:01:00",
             "LeaveTime": "2026-10-01T13:50:00", "Attendees": [{"UPN": "me@x.com", "UserObjectId": me, "Role": 1}],
             "ArtifactsShared": [{"ArtifactSharedName": "screenShared"}]},
            {"Id": "r8", "Operation": "MeetingParticipantDetail", "UserId": "other@x.com", "MeetingDetailId": self.MD2,
             "ChatThreadId": self.MEET, "CreationTime": "2026-10-02T15:00:00", "JoinTime": "2026-10-02T13:00:00",
             "LeaveTime": "2026-10-02T13:30:00", "Attendees": [{"DisplayName": "Guest (External)", "Role": 3}]},
            {"Id": "r9", "Operation": "MessageSent", "UserId": "me@x.com", "UserKey": me, "ChannelGuid":
             "19:chan@thread.tacv2", "ChannelName": "General", "TeamName": "Team", "CreationTime": "2026-10-01T09:00:00",
             "CommunicationType": "Channel", "MessageId": "m9"},
            msg(10, "MessageSent", "me@x.com", me, self.ONE, "2026-09-20T08:00:00"),  # outside the window
        ]

    def test_build_model(self):
        recs = self.recs()
        recs[6]["Id"] = self.MD1
        recs[7]["Id"] = self.MD2
        frm, to = devo.resolve_time("2026-10-01")[1], devo.resolve_time("2026-10-03")[1]
        m = devo.build_teams(recs, {self.ME}, {"me@x.com"}, frm, to, devo.get_tz("Europe/London"),
                             {self.OTHER: "other@x.com"})
        conv = {c["id"]: c for c in m["conversations"]}
        one = conv[self.ONE]
        self.assertEqual(one["type"], "1:1")
        self.assertEqual(one["parties"], ["other@x.com"])
        self.assertEqual(one["subject"]["sent"], 1)  # MessageSent + HasLink with one MessageId, duplicate dropped
        self.assertEqual(one["subject"]["files"], ["https://t.sharepoint.com/a b.docx"])
        self.assertEqual(one["subject"]["links"], ["https://example.org/x"])  # not the file, not the emoji
        self.assertEqual(one["others"]["reactions"], 1)
        grp = conv[self.GROUP]
        self.assertEqual((grp["type"], grp["name"], grp["subject"]["edits"], grp["others"]["sent"]),
                         ("group", "Project", 1, 1))
        self.assertEqual(grp["parties"], ["third@y.com"])
        self.assertEqual(conv["19:chan@thread.tacv2"]["type"], "channel")
        meetings = {x["meeting_detail_id"]: x for x in m["meetings"]}
        self.assertEqual(set(meetings), {self.MD1, self.MD2})  # one per occurrence, not per thread
        first = meetings[self.MD1]
        self.assertEqual((first["organizer"], first["start_utc"], first["artifacts"][0]["name"]),
                         ("other@x.com", "2026-10-01T13:00:00Z", "MeetingRecorded"))
        p = first["participants"][0]
        self.assertTrue(p["subject"])
        self.assertEqual(p["sessions"][0]["shared"], ["screenShared"])
        self.assertEqual(p["sessions"][0]["join_local"], "2026-10-01T14:01:00+01:00")
        self.assertEqual(meetings[self.MD2]["participants"][0]["who"], "Guest (External)")
        days = {d["date"]: d for d in m["daily"]}
        self.assertEqual(days["2026-10-01"]["sent"], 2)  # 1:1 + channel
        self.assertEqual(days["2026-10-02"]["edits"], 1)  # 23:30 UTC is 00:30 local time the next day
        self.assertEqual(days["2026-10-01"]["meeting_joins"], 1)
        self.assertEqual([s["kind"] for s in m["shares"]], ["file", "link"])

    def test_cli(self):
        recs = self.recs()
        recs[6]["Id"] = self.MD1
        recs[7]["Id"] = self.MD2

        def rows(ms):
            return compact([("eventdate", "timestamp"), ("Operation", "str"), ("UserId", "str"), ("UserKey", "str"),
                            ("message", "str")], [[1790000000000, x["Operation"], x["UserId"], x.get("UserKey"),
                                                    json.dumps(x)] for x in ms])

        def route(q, frm, to):
            if "group by UserId, UserKey" in q:
                return compact([("UserId", "str"), ("UserKey", "str"), ("n", "int8")],
                               [["me@x.com", self.ME, 5], ["app", "x", 1]])
            if "group by UserKey, UserId" in q:
                return compact([("UserKey", "str"), ("UserId", "str"), ("n", "int8")], [])
            if frm > devo.resolve_time("2026-10-02")[1]:
                return rows([])
            if "chat_id in" in q:
                return rows([x for x in recs if x.get("ChatThreadId") in (self.ONE, self.GROUP)])
            if "mdid in" in q:
                return rows([x for x in recs if x["Operation"].startswith("Meeting")])
            return rows([x for x in recs if self.ME in json.dumps(x) or "me@x.com" in json.dumps(x)])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "t.json")
            code, stdout, err, reqs = run_routed(["teams", "me@x.com", "--from", "2026-10-01", "--to", "2026-09-28T16:00",
                                                  "--out", out], route)
            self.assertEqual(code, 1)  # from after to
            code, stdout, err, reqs = run_routed(["teams", "me@x.com", "--from", "2026-09-26", "--to", "2026-09-28",
                                                  "--out", out, "--tz", "Europe/London"], route)
            self.assertEqual(code, 0, err)
            with open(out) as f:
                model = json.load(f)
            self.assertEqual(model["subject"]["object_ids"], [self.ME])
            self.assertTrue(any("Operation not in" in b["query"] and "MessagesListed" in b["query"] for b in reqs))
            self.assertIn("conversations:", stdout)
            code, _, err, reqs = run_routed(["teams", "x", "--from", "2026-09-26", "--to", "2026-09-28", "--out", out],
                                            lambda q, f, t: compact([("UserId", "str"), ("UserKey", "str"), ("n", "int8")],
                                                                    [["a.x@x.com", self.ME, 1], ["b.x@y.com", self.OTHER, 1]]))
            self.assertEqual(code, 1)
            self.assertIn("matches 2 accounts", err)
            code, _, err, _ = run_routed(["teams", "me", "--out", os.path.join(devo.SKILL_DIR, "t.json")], route)
            self.assertEqual(code, 1)


def board_settings(children=None, layout=None):
    children = children if children is not None else {
        "Table0": {"name": "Table0", "type": "widget", "subtype": "Table",
                   "datasource": 'query(from siem.logtrust.web.activity where eq(method, "POST"))',
                   "date": {}, "settings": {}, "extra": {}, "children": None, "version": 3}}
    if layout is None:
        layout = {k: {"x": 0, "y": 0, "w": 6, "h": 10, "i": k, "moved": False, "static": False} for k in children}
    return {"type": "container", "subtype": "Grid", "date": {"realTime": False, "from": "now() - 15m", "to": "now()"},
            "settings": {"layout": layout, "header": False}, "extra": {}, "children": children, "version": 3}


BOARD = {"id": 34567, "name": "Test board", "description": "", "updateDate": 1790611330000, "isPrivate": True,
         "isDefault": False, "favorite": False, "editable": True, "tags": ["soc"],
         "owner": {"username": "jsmith@example.com"}, "settings": board_settings()}


class BoardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="devo-board-test-")

    def write(self, name, obj):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def test_board_query_extraction(self):
        q = devo.board_query
        self.assertEqual(q("query(from t where eq(a, \"x)\"))"), 'from t where eq(a, "x)")')
        self.assertEqual(q("take(query(from t select a), 5)"), "from t select a")
        self.assertIsNone(q("query(Input0.value)"))
        self.assertIsNone(q("query(from t where eq(a, 1)"))  # unbalanced
        self.assertIsNone(q(None))
        # boards built in the UI store plain LINQ [verified]
        self.assertEqual(q(" from t group by a select count() as n "), "from t group by a select count() as n")

    def test_lint(self):
        self.assertEqual(devo.board_lint(board_settings()), ([], []))
        s = board_settings(layout={"Other": {"x": 0, "y": 0, "w": 6, "h": 4, "i": "Wrong"}})
        errs, warns = devo.board_lint(s)
        self.assertTrue(any("Table0: no layout entry" in e for e in errs))
        self.assertTrue(any("layout.i" in e for e in errs))
        self.assertTrue(any("stale entry" in w for w in warns))
        child = dict(BOARD["settings"]["children"]["Table0"], datasource=" ", name="Requests by method")
        errs, warns = devo.board_lint(board_settings({"Table0": child}))
        self.assertTrue(any("no datasource" in e for e in errs))
        self.assertFalse(any("name" in w for w in warns))  # name is the display title, not the id
        child["datasource"] = "from t group every $*Select0.value"
        errs, _ = devo.board_lint(board_settings({"Table0": child}))
        self.assertTrue(any("no element Select0" in e for e in errs))

    def test_fill_inputs(self):
        linq, missing = devo.board_fill_inputs('from t where method=$Input0.value group every $*Sel.value', {"Input0": "GET"})
        self.assertEqual(missing, {"Sel"})
        self.assertIn('method="GET"', linq)
        linq, _ = devo.board_fill_inputs("x > $Input0.value every $*Sel.value", {"Input0": "5", "Sel": "1h"})
        self.assertEqual(linq, "x > 5 every 1h")

    def test_board_new_layout_and_wrapping(self):
        spec = self.write("spec.json", {"name": "N", "widgets": [
            {"type": "Table", "query": "from a select b", "title": "B"}, {"type": "Line", "query": "query(from a)", "w": 8},
            {"id": "Select0", "type": "Input", "w": 3}]})
        out = os.path.join(self.tmp, "b.json")
        code, _, err, reqs = run_cli(["board-new", spec, "--out", out], [])
        self.assertEqual((code, reqs), (0, []))
        with open(out) as f:
            doc = json.load(f)
        s = doc["settings"]
        self.assertEqual(s["children"]["Table0"]["datasource"], "from a select b")
        self.assertEqual(s["children"]["Table0"]["name"], "B")
        self.assertEqual(s["children"]["Line0"]["datasource"], "query(from a)")
        lay = s["settings"]["layout"]
        self.assertEqual((lay["Table0"]["x"], lay["Table0"]["y"]), (0, 0))
        self.assertEqual((lay["Line0"]["x"], lay["Line0"]["y"]), (0, 10))  # 6 + 8 > 12: next row
        self.assertEqual((lay["Select0"]["x"], lay["Select0"]["y"]), (8, 10))
        self.assertEqual(devo.board_lint(s)[0], [])
        self.assertEqual(os.stat(out).st_mode & 0o077, 0)

    def test_list_uses_activeboards_api_and_hides_token(self):
        code, out, err, reqs = run_cli(["boards", "--grep", "soc"], [FakeResp(json.dumps([BOARD]))])
        self.assertEqual(code, 0)
        self.assertEqual(reqs[0].full_url, "https://api-eu.devo.com/activeboards/v2/activeboards")
        self.assertEqual(reqs[0].get_method(), "GET")
        self.assertEqual(reqs[0].get_header("Standalonetoken"), CFG["token"])
        self.assertIn("34567", out)
        self.assertIn("[P]", out)
        self.assertNotIn(CFG["token"], out + err)

    def test_board_export_roundtrip(self):
        out = os.path.join(self.tmp, "export.json")
        code, text, _, _ = run_cli(["board", "34567", "--out", out], [FakeResp(json.dumps(BOARD))])
        self.assertEqual(code, 0)
        self.assertIn('eq(method, "POST")', text)
        with open(out) as f:
            doc = json.load(f)
        self.assertEqual(doc["exported_from"], {"id": 34567, "updateDate": 1790611330000})
        self.assertNotIn("owner", doc)

    def test_bad_id_rejected_before_any_request(self):
        code, _, err, reqs = run_cli(["board", "12/../x"], [])
        self.assertEqual((code, reqs), (1, []))

    def test_push_preview_sends_nothing(self):
        f = self.write("b.json", {"name": "New", "settings": board_settings()})
        code, out, err, reqs = run_cli(["board-push", f], [])
        self.assertEqual((code, reqs), (0, []))
        self.assertIn("POST https://api-eu.devo.com/activeboards/v2/activeboards", out)
        self.assertIn("NOT SENT", err)

    def test_push_refuses_lint_errors(self):
        f = self.write("b.json", {"name": "New", "settings": board_settings(layout={})})
        code, _, err, reqs = run_cli(["board-push", f, "--confirm"], [])
        self.assertEqual((code, reqs), (1, []))
        self.assertIn("no layout entry", err)

    def test_push_create_confirm_verifies(self):
        f = self.write("b.json", {"name": "New", "settings": board_settings()})
        created = dict(BOARD, id=99, name="New")
        code, _, err, reqs = run_cli(["board-push", f, "--confirm"],
                                     [FakeResp(json.dumps(created)), FakeResp(json.dumps(created))])
        self.assertEqual(code, 0, err)
        self.assertEqual([r.get_method() for r in reqs], ["POST", "GET"])
        self.assertEqual(json.loads(reqs[0].data)["name"], "New")
        self.assertTrue(reqs[1].full_url.endswith("/activeboards/99"))
        self.assertIn("created and verified", err)

    def test_push_update_backs_up_and_warns_on_concurrent_edit(self):
        f = self.write("b.json", {"name": "Test board", "settings": board_settings(),
                                  "exported_from": {"id": 34567, "updateDate": 1}})
        code, out, err, reqs = run_cli(["board-push", f, "--id", "34567"], [FakeResp(json.dumps(BOARD))])
        self.assertEqual([r.get_method() for r in reqs], ["GET"])
        self.assertIn("changed since the export", err)
        code, out, err, reqs = run_cli(["board-push", f, "--id", "34567", "--confirm"],
                                       [FakeResp(json.dumps(BOARD)) for _ in range(3)])
        self.assertEqual(code, 0, err)
        self.assertEqual([r.get_method() for r in reqs], ["GET", "PUT", "GET"])
        backup = re.search(r"backup of the current board: (\S+)", err).group(1)
        self.assertTrue(backup.startswith(os.environ["DEVO_CACHE_DIR"]))
        self.assertEqual(os.stat(backup).st_mode & 0o077, 0)
        with open(backup) as fh:
            self.assertEqual(json.load(fh)["settings"], BOARD["settings"])

    def test_set_patches(self):
        code, out, err, reqs = run_cli(["board-set", "34567", "--private", "false", "--tags", "soc, web"],
                                       [FakeResp(json.dumps(BOARD))])
        self.assertEqual(len(reqs), 1)
        self.assertIn("NOT SENT", err)
        after = dict(BOARD, isPrivate=False, tags=["soc", "web"])
        code, out, err, reqs = run_cli(["board-set", "34567", "--private", "false", "--tags", "soc, web", "--confirm"],
                                       [FakeResp(json.dumps(BOARD)), FakeResp(""), FakeResp(""),
                                        FakeResp(json.dumps(after))])
        self.assertEqual(code, 0, err)
        patches = [(r.full_url.rsplit("/", 1)[1], json.loads(r.data)) for r in reqs if r.get_method() == "PATCH"]
        self.assertEqual(patches, [("privacy", {"privacy": False}), ("tags", {"tags": "soc, web"})])

    def test_delete_backs_up_then_verifies_gone(self):
        code, _, err, reqs = run_cli(["board-delete", "34567", "--confirm"],
                                     [FakeResp(json.dumps(BOARD)), FakeResp(""), http_error(404, "{}")])
        self.assertEqual(code, 0, err)
        self.assertEqual([r.get_method() for r in reqs], ["GET", "DELETE", "GET"])
        self.assertIn("backup:", err)
        self.assertIn("deleted and verified", err)

    def test_check_run_executes_widget_queries(self):
        child = dict(BOARD["settings"]["children"]["Table0"])
        sel = {"name": "Select0", "type": "input", "subtype": "Input", "datasource": None}
        trend = dict(child, name="Trend", datasource="query(from t group every $*Select0.value select count() as n)")
        f = self.write("b.json", {"name": "x", "settings": board_settings({"Table0": child, "Select0": sel,
                                                                          "Trend": trend})})
        code, out, err, reqs = run_cli(["board-check", f, "--run"], [FakeResp(COMPACT)])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(len(reqs), 1)
        self.assertEqual(json.loads(reqs[0].data)["query"],
                         'from siem.logtrust.web.activity where eq(method, "POST")')
        self.assertIn("ok      Table0: 2 row(s)", out)
        self.assertIn("skip    Trend: needs --input Select0=...", out)
        code, out, err, reqs = run_cli(["board-check", f, "--run", "--input", "Select0=1h"],
                                       [FakeResp(COMPACT), FakeResp(COMPACT)])
        self.assertIn("group every 1h", json.loads(reqs[1].data)["query"])


class TimelineActorTests(unittest.TestCase):
    """The timeline actor is the field the source names, not the first user-like column: Devo returns
    computed `pre` columns (target_upn) ahead of the initiator."""
    ADMIN, USER = "admin.one@example.test", "user.two@example.test"
    GUEST = "guest_partner.test#EXT#@tenant.example.test"
    AUDIT = "cloud.azure.ad.audit"

    def audit(self, op, target, initiator=ADMIN, app=None, t="2026-10-01T09:00:00.000Z"):
        rec = {"target_upn": target, "target_name": target.split("@")[0], "event_time": t, "eventdate": t,
               "operationName": op, "tenantId": "t1", "properties_loggedByService": "Core Directory",
               "properties_result": "success", "properties_initiatedBy_user_userPrincipalName": initiator}
        if app:
            rec["properties_initiatedBy_app_displayName"] = app
        return rec

    def timeline(self, files, recorded=False):
        """files: {source: (table, records)}. recorded: write actor/target fields into summary.json as
        activity now does; otherwise the summary predates them and the recipe supplies them."""
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d)
        recipes = {s["name"]: s for s in devo.load_activity_sources()["sources"]}
        sources = []
        for name, (table, recs) in files.items():
            path = os.path.join(d, f"{name}.jsonl")
            with open(path, "w") as f:
                for r in recs:
                    f.write(json.dumps(r) + "\n")
            s = {"source": name, "table": table, "rows": len(recs), "file": path, "mode": "rows"}
            if name in recipes and recipes[name].get("attribution"):
                s["attribution"] = recipes[name]["attribution"]
            if recorded and name in recipes:
                s["actor_fields"] = devo.actor_fields(recipes[name])
                s["target_fields"] = recipes[name].get("target") or []
            sources.append(s)
        with open(os.path.join(d, "summary.json"), "w") as f:
            json.dump({"term": "x", "terms": ["x"], "window": ["a", "b"], "sources": sources}, f)
        roles = os.path.join(devo.HINTS, "field-roles.json")
        out = {}
        for label, fm in (("name-only", {"tables": {}}),
                          ("curated", devo.apply_roles({"tables": {t: {"fields": {
                              k: {"role": devo.guess_role(k, "str", set())} for r in recs for k in r}}
                              for t, recs in files.values()}}, roles))):  # as profiled, then curated
            out[label] = devo.build_timeline(d, fm=fm)[0]
        return out

    def each(self, files, check, recorded=(False, True)):
        for rec in recorded:
            for label, events in self.timeline(files, rec).items():
                with self.subTest(roles=label, recorded=rec):
                    check(events) if check.__code__.co_argcount == 1 else check(events, label)

    def test_add_member_actor_is_the_initiator(self):
        def check(ev):
            self.assertEqual(len(ev), 1)
            self.assertEqual(ev[0]["actor"], self.ADMIN)
            self.assertEqual(ev[0]["target"], self.USER)
            self.assertNotIn(self.ADMIN, ev[0]["ip"] or "")
        self.each({"entra_audit": (self.AUDIT, [self.audit("Add member to group", self.USER)])}, check)

    def test_invite_external_user_actor_is_the_initiator(self):
        def check(ev):
            self.assertEqual(ev[0]["actor"], self.ADMIN)
            self.assertEqual(ev[0]["target"], self.GUEST)
        self.each({"entra_audit": (self.AUDIT, [self.audit("Invite external user", self.GUEST)])}, check)

    def test_app_initiated_change_does_not_make_the_target_the_actor(self):
        def check(ev):
            self.assertNotEqual(ev[0]["actor"], self.USER)
            self.assertEqual(ev[0]["actor"], "Example Sync App")
            self.assertEqual(ev[0]["target"], self.USER)
        self.each({"entra_audit": (self.AUDIT, [self.audit("Add user", self.USER, initiator=None,
                                                           app="Example Sync App")])}, check)

    def test_target_attribution_source_is_unchanged(self):
        rec = {"operationName": "Add member to group", "properties_loggedByService": "Core Directory",
               "properties_initiatedBy_user_userPrincipalName": self.ADMIN, "n": 2,
               "first": "2026-10-01T09:00:00.000Z", "last": "2026-10-01T09:30:00.000Z"}

        def check(ev):
            self.assertEqual(ev[0]["actor"], self.ADMIN)
            self.assertEqual(ev[0]["attribution"], "target")
            self.assertEqual(ev[0]["action"], "Add member to group")
            self.assertEqual(ev[0]["count"], 2)
        self.each({"entra_audit_target": (self.AUDIT, [rec])}, check)

    def test_source_without_pre_is_unchanged(self):
        iam = {"userIdentity_arn": "arn:aws:iam::111122223333:user/jsmith", "eventName": "CreateAccessKey",
               "sourceIPAddress": "203.0.113.10", "errorCode": None, "n": 1,
               "first": "2026-10-01T08:00:00.000Z", "last": "2026-10-01T08:00:00.000Z"}
        unix = {"machine": "host01", "appName": "sshd", "n": 3,
                "first": "2026-10-01T07:00:00.000Z", "last": "2026-10-01T07:10:00.000Z"}

        def check(ev, roles):  # the values the timeline gave before actor fields existed
            by = {e["source"]: e for e in ev}
            self.assertEqual({k: by["aws_iam"][k] for k in ("actor", "action", "target", "ip", "host")},
                             {"actor": "arn:aws:iam::111122223333:user/jsmith", "action": "CreateAccessKey",
                              "target": None, "ip": "203.0.113.10", "host": None})
            self.assertEqual({k: by["linux"][k] for k in ("actor", "action", "target", "ip", "host", "detail")},
                             {"actor": None, "action": None, "ip": None, "host": "host01",
                              **({"target": "sshd", "detail": None} if roles == "curated"  # appName: process/file
                                 else {"target": None, "detail": "appName=sshd"})})
        self.each({"aws_iam": ("cloud.aws.cloudtrail.iam", [iam]), "linux": ("box.unix", [unix])}, check)

    def test_target_like_field_never_becomes_the_actor(self):
        # a generated source (no recipe) whose row has a computed target column first
        rec = {"target_upn": self.USER, "eventdate": "2026-10-01T09:00:00.000Z", "Operation": "Shared",
               "UserId": self.ADMIN}

        def check(ev):
            self.assertEqual(ev[0]["actor"], self.ADMIN)
            self.assertEqual(ev[0]["target"], self.USER)
        self.each({"auto_user_example_table": ("app.example.audit", [rec])}, check, recorded=(False,))

    def test_actor_fields_from_recipes(self):
        self.assertEqual(devo.actor_fields({"by": "user", "accounts": ["a", "target_upn"]}), ["a"])
        self.assertEqual(devo.actor_fields({"by": "ip", "accounts": ["srcIp"]}), [])  # swept IP, not an actor
        self.assertEqual(devo.actor_fields({"by": "user", "accounts": ["a"], "actor": ["b"]}), ["b"])
        g = devo.generated_source("app.example.audit", {"rows": 100, "fields": {
            "target_upn": {"role": "user", "fill": 0.9, "type": "str", "len": 20},
            "actor_email": {"role": "user", "fill": 0.8, "type": "str", "len": 20},
            "op": {"role": "action", "fill": 1.0, "type": "str", "len": 10}}}, "user")
        self.assertEqual(g["actor"], ["actor_email"])
        self.assertEqual(g["target"], ["target_upn"])

    def test_principal_is_not_an_ip_field(self):
        for name in ("properties_initiatedBy_user_userPrincipalName", "properties_servicePrincipalName",
                     "ShipTo"):
            self.assertNotEqual(devo.guess_role(name, "str", set()), "ip", name)
        for name in ("srcIp", "clientIP", "ClientIPAddress", "sourceIPAddress", "IpAddress", "remote_ip",
                     "actor_ipv4", "ip"):
            self.assertEqual(devo.guess_role(name, "str", set()), "ip", name)


if __name__ == "__main__":
    unittest.main()
