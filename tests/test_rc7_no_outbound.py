"""RC-7 (D-4 / D-5 engine hunk): no outbound alerting, alert_records table, 15-minute sane_ts window."""
import ast
import contextlib
import inspect
import io
import json
import os
import re
import socket
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rpot.console.engine import Engine, parse_ts  # noqa: E402
from test_unit import FS, ev, mkcfg  # noqa: E402

CONSOLE = os.path.join(ROOT, "rpot", "console")
NET_MODULES = {"urllib", "urllib2", "urllib3", "requests", "httpx", "aiohttp", "http", "smtplib", "ftplib",
               "telnetlib", "xmlrpc", "websocket", "websockets", "pycurl"}


def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def console_files(exts):
    for d, _, files in os.walk(CONSOLE):
        for f in files:
            if f.endswith(exts):
                yield os.path.join(d, f)


class TestNoOutbound(unittest.TestCase):
    def test_alerts_module_is_gone(self):
        self.assertFalse(os.path.exists(os.path.join(CONSOLE, "alerts.py")))

    def test_no_http_client_imports_in_console(self):
        for p in console_files((".py",)):
            with open(p, encoding="utf-8") as f:
                tree = ast.parse(f.read(), p)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                for n in names:
                    self.assertNotIn(n.split(".")[0], NET_MODULES, f"{p}: import {n}")

    def test_no_outbound_alerting_strings_in_console(self):
        bad = re.compile(r"telegram|webhook|sendMessage|urlopen|public_url|Alerter|MAX_PER_HOUR|/api/alerts\b", re.I)
        for p in console_files((".py", ".js", ".html", ".css")):
            with open(p, encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    self.assertIsNone(bad.search(line), f"{p}:{i}: {line.strip()}")

    def test_tamper_banner_text(self):
        with open(os.path.join(CONSOLE, "static", "app.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertIn("L4 tamper incident opened", js)
        self.assertNotIn("tamper alert sent", js)


class TestEngineInterface(unittest.TestCase):
    def test_signature_and_schema(self):
        self.assertEqual(list(inspect.signature(Engine.__init__).parameters),
                         ["self", "cfg", "db_path", "geo_dir", "log_dir"])
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "t.db")
            e = Engine(mkcfg(tmp), p)
            self.assertEqual(e.db_path, p)
            self.assertFalse(hasattr(e, "alerter"))
            tables = {r[0] for r in e.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("alert_records", tables)
            self.assertNotIn("alerts", tables)
            cols = [r[1] for r in e.db.execute("PRAGMA table_info(alert_records)")]
            self.assertEqual(cols, ["id", "ts", "incident_id", "level", "record"])
            idx = [r[1] for r in e.db.execute("PRAGMA index_list(alert_records)")]
            self.assertTrue(any([c[2] for c in e.db.execute(f"PRAGMA index_info({i})")] == ["ts"] for i in idx))
            e.db.close()


class TestAlertRecords(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = mkcfg(self.tmp.name)
        self.logs = os.path.join(self.tmp.name, "logs")

    def tearDown(self):
        self.tmp.cleanup()

    def lines(self):
        p = os.path.join(self.logs, "alerts.json")
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(x) for x in f]

    @staticmethod
    def rows(e):
        return [(r[0], r[1], r[2], json.loads(r[3])) for r in
                e.db.execute("SELECT ts, incident_id, level, record FROM alert_records ORDER BY id")]

    def attack(self, e):
        e.ingest([ev("tcp.connect"), ev("auth.failed", username="root"), ev("file.read", path="x"),
                  ev("honeytoken.used", sensor="WEB01", port=22, proto="ssh", username="deploy", success=True),
                  ev("auth.failed", src="172.30.0.51", username="admin")])
        s = [x for x in e.sensors() if x["name"] == "BKP01"][0]
        e._sensor_alert(s, "sensor.offline", "Sensor BKP01 stopped reporting")
        e._sensor_alert(s, "sensor.online", "Sensor BKP01 is reporting again")

    def test_every_alerts_json_line_has_a_row(self):
        e = Engine(self.cfg, os.path.join(self.tmp.name, "t.db"), log_dir=self.logs)
        self.attack(e)
        lines, rows = self.lines(), self.rows(e)
        self.assertGreaterEqual(len(lines), 5)
        self.assertEqual([r[3] for r in rows], lines)                        # same records, same order
        for ts, iid, level, rec in rows:
            self.assertEqual((ts, iid, level), (rec["timestamp"], rec["alert"]["incident_id"], rec["level"]))

    def test_rows_written_when_alerts_json_is_off(self):
        self.cfg["logs"] = {"alerts": False}
        e = Engine(self.cfg, os.path.join(self.tmp.name, "t.db"), log_dir=self.logs)
        self.attack(e)
        self.assertIsNone(e.alert_log)
        self.assertEqual(self.lines(), [])
        self.assertGreaterEqual(len(self.rows(e)), 5)

    def test_rolled_back_batch_leaves_neither_line_nor_row(self):
        e = Engine(self.cfg, os.path.join(self.tmp.name, "t.db"), log_dir=self.logs)
        orig = e._host

        def boom(evt, lvl):
            if evt.get("session") == "boom":
                raise RuntimeError("boom")
            return orig(evt, lvl)
        e._host = boom
        with self.assertRaises(RuntimeError):
            e.ingest([ev("auth.failed", src="172.30.0.70"), dict(ev("tcp.connect", src="172.30.0.70"), session="boom")])
        self.assertEqual((self.lines(), self.rows(e)), ([], []))
        e.ingest([ev("auth.failed", src="172.30.0.70")])                    # next batch is clean
        self.assertEqual([r[3] for r in self.rows(e)], self.lines())
        self.assertEqual(len(self.lines()), 1)

    def test_purge_removes_old_alert_records(self):
        e = Engine(self.cfg, os.path.join(self.tmp.name, "t.db"), log_dir=self.logs)
        e.ingest([ev("auth.failed")])
        e.db.execute("INSERT INTO alert_records(ts, incident_id, level, record) VALUES(?,?,?,?)",
                     (ago(days=100), 1, 3, "{}"))
        self.assertEqual(len(self.rows(e)), 2)
        e.purge(90)
        rows = self.rows(e)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][3]["src_ip"], "172.30.0.50")


class TestAppNoAlertsApi(unittest.TestCase):
    def test_api_alerts_404_and_legacy_keys_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            # rpot.json files written before RC-3 may still carry these keys: they must be ignored, never used
            cfg = mkcfg(tmp, alerts={"min_level": 3, "telegram": {"bot_token": "123:abc", "chat_id": "42"},
                                     "webhook": "http://127.0.0.1:9/hook", "public_url": "http://console"})
            from rpot.console.app import create_app, create_sensor_app
            calls = []
            real_cc, real_connect = socket.create_connection, socket.socket.connect

            def cc(*a, **k):
                calls.append(a)
                raise OSError("outbound connection attempted")
            socket.create_connection = cc
            socket.socket.connect = lambda self, *a: cc(*a)
            try:
                app = create_app(cfg, os.path.join(tmp, "a.db"), log_dir=os.path.join(tmp, "logs"))
                c, s = app.test_client(), create_sensor_app(app.engine).test_client()
                self.assertEqual(s.post("/api/ingest", json={"events": [
                    ev("honeytoken.used", src="172.30.0.80", username="deploy", success=True)]}, headers=FS).status_code, 200)
                self.assertIn(c.post("/login", data={"token": "at"}).status_code, (302, 303))
                self.assertEqual(c.get("/api/alerts").status_code, 404)
                self.assertEqual(c.get("/api/incidents").status_code, 200)
            finally:
                socket.create_connection, socket.socket.connect = real_cc, real_connect
            self.assertEqual(calls, [])
            n = app.engine.db.execute("SELECT COUNT(*) FROM alert_records WHERE level=5").fetchone()[0]
            self.assertEqual(n, 1)

    def test_no_alerts_block_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp)
            cfg.pop("alerts")
            from rpot.console.app import create_app
            app = create_app(cfg, os.path.join(tmp, "a.db"))
            app.engine.ingest([ev("auth.failed", src="172.30.0.81")])           # default min_level 3
            self.assertEqual(app.engine.db.execute("SELECT COUNT(*) FROM alert_records").fetchone()[0], 1)


class TestSensorTimestamps(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = Engine(mkcfg(self.tmp.name), os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def ingest_quiet(self, events):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.e.ingest(events)
        return out.getvalue()

    def stored(self, ip):
        return self.e.events(src=ip)[0]

    def test_old_and_future_events_restamped_with_sensor_ts_kept(self):
        cases = {"172.30.0.90": ago(days=8), "172.30.0.91": ago(minutes=20),
                 "172.30.0.92": ago(minutes=-10)}                              # 10 min in the future
        before = datetime.now(timezone.utc)
        self.ingest_quiet([dict(ev("auth.failed", src=ip), ts=ts) for ip, ts in cases.items()])
        for ip, ts in cases.items():
            x = self.stored(ip)
            self.assertLess(abs((parse_ts(x["ts"]) - before).total_seconds()), 60, ip)
            self.assertEqual(x["data"]["sensor_ts"], ts, ip)
        rec = json.loads(self.e.db.execute("SELECT record FROM alert_records WHERE record LIKE '%172.30.0.90%'").fetchone()[0])
        self.assertLess(abs((parse_ts(rec["timestamp"]) - before).total_seconds()), 60)   # alert time = server time
        self.assertEqual(rec["event"]["data"]["sensor_ts"], cases["172.30.0.90"])

    def test_recent_event_keeps_its_time(self):
        ts = ago(minutes=10)
        self.assertEqual(self.ingest_quiet([dict(ev("auth.failed", src="172.30.0.93"), ts=ts)]), "")
        x = self.stored("172.30.0.93")
        self.assertEqual(x["ts"][:19], ts[:19])
        self.assertNotIn("sensor_ts", x["data"])

    def test_skew_warning_once_per_sensor(self):
        out = self.ingest_quiet([dict(ev("auth.failed", src="172.30.0.94"), ts=ago(days=8)),
                                 dict(ev("auth.failed", src="172.30.0.95"), ts=ago(minutes=20)),
                                 dict(ev("tcp.connect", src="172.30.0.96", sensor="WEB01"), ts=ago(minutes=-30)),
                                 dict(ev("tcp.connect", src="172.30.0.97", sensor="BKP01"), ts="garbage")])
        out += self.ingest_quiet([dict(ev("auth.failed", src="172.30.0.98"), ts=ago(hours=2))])
        warn = [x for x in out.splitlines() if "WARNING" in x and "clock" in x]
        self.assertEqual(len(warn), 2, out)
        self.assertIn("'FS01'", warn[0])
        self.assertIn("behind", warn[0])
        self.assertIn("'WEB01'", warn[1])
        self.assertIn("ahead of", warn[1])
        self.assertEqual(self.stored("172.30.0.97")["data"]["sensor_ts"], "garbage")   # malformed: kept, no warning


if __name__ == "__main__":
    unittest.main()
