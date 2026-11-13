"""RC-9 (design T8, D-4 + addendum S-1 M6/M7/L12): JSON Export API, `rpotctl export` and `rpotctl slots`."""
import contextlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
import urllib.parse
from datetime import date, datetime, timedelta, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.common.edition import EDITION, MAX_DECOYS  # noqa: E402
from rpot.console import export as X  # noqa: E402
from rpot.console.app import create_app  # noqa: E402
from test_unit import ev, mkcfg  # noqa: E402

H = {"X-Requested-With": "rpot"}
CTL = os.path.join(ROOT, "rpotctl.py")
TODAY = datetime.now(timezone.utc).date()


def strict_loads(s):
    """json.loads that refuses NaN/Infinity (the export must be strict JSON)."""
    def bad(c):
        raise ValueError(c)
    return json.loads(s, parse_constant=bad)


def url(frm, to):
    return f"/api/export?from={frm}&to={to}"


def day(d, hhmmss="12:00:00"):
    return f"{d.isoformat()}T{hhmmss}.000Z"


class Base(unittest.TestCase):
    n_local = 3

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.cfg = mkcfg(self.tmp)
        self.cfg["sensors"] = self.cfg["sensors"][:self.n_local]
        self.cfg["version"] = 2
        self.db_path = os.path.join(self.tmp, "c.db")
        with contextlib.redirect_stdout(io.StringIO()):
            self.app = create_app(self.cfg, self.db_path)
        self.eng = self.app.engine
        self.db = self.eng.db
        self.c = self.app.test_client()
        self.c.post("/login", data={"token": "at"})
        self.assertFalse(X.GATE.busy())

    def tearDown(self):
        busy = X.GATE.busy()
        X.GATE._owner = None                       # never leak the module gate into other tests
        self.db.close()
        self._tmp.cleanup()
        self.assertFalse(busy, "export gate still held after the test")

    def inc(self, first, last, src="198.51.100.7", subject=None, title="t", sensors='["FS01"]', level=3, note=None):
        return self.db.execute("INSERT INTO incidents(src_ip, subject, first_ts, last_ts, level, title, sensors, count, note) "
                               "VALUES(?,?,?,?,?,?,?,1,?)", (src, subject, first, last, level, title, sensors, note)).lastrowid

    def alert(self, ts, record, iid=1, level=3):
        if not isinstance(record, (str, bytes)):
            record = json.dumps(record, ensure_ascii=False)
        return self.db.execute("INSERT INTO alert_records(ts, incident_id, level, record) VALUES(?,?,?,?)",
                               (ts, iid, level, record)).lastrowid

    def export(self, frm=None, to=None, client=None, **kw):
        """buffered=True: read the whole body, then close (what the WSGI server does)."""
        frm, to = frm or TODAY.isoformat(), to or TODAY.isoformat()
        kw.setdefault("buffered", True)
        return (client or self.c).get(url(frm, to), headers=H, **kw)

    def ok_doc(self, r):
        self.assertEqual(r.status_code, 200, r.data[:300])
        doc = strict_loads(r.get_data(as_text=True))
        self.assertIs(doc.get("complete"), True)
        return doc


# ------------------------------------------------------------------------------------------- validation (L12)
class TestParseRange(unittest.TestCase):
    T = date(2026, 11, 13)

    def test_valid_range_and_utc_bounds(self):
        self.assertEqual(X.parse_range("2026-11-01", "2026-11-13", self.T),
                         ("2026-11-01T00:00:00.000Z", "2026-11-14T00:00:00.000Z"))
        self.assertEqual(X.parse_dates("2026-11-13", "2026-11-13", self.T), (self.T, self.T))

    def test_bad_formats(self):
        for v in ["", None, "2026-1-01", "2026-11-1", "26-11-13", "2026/11/13", "2026-11-13T00", " 2026-11-13",
                  "2026-11-13\n", "x" * 5000, "２０２６-１１-１３", "٢٠٢٦-١١-١٣", "2026-11-1३", "+2026-11-13",
                  "2026-02-30", "2026-13-01", "2026-00-10", 20261113, ["2026-11-13"]]:
            with self.subTest(v=v), self.assertRaises(ValueError):
                X.parse_dates(v, "2026-11-13", self.T)
            with self.subTest(to=v), self.assertRaises(ValueError):
                X.parse_dates("2026-11-01", v, self.T)

    def test_bounds(self):
        with self.assertRaisesRegex(ValueError, "after"):
            X.parse_dates("2026-11-13", "2026-11-12", self.T)                   # reversed
        X.parse_dates("2025-11-12", "2026-11-13", self.T)                       # exactly 366 days
        with self.assertRaisesRegex(ValueError, "366"):
            X.parse_dates("2025-11-11", "2026-11-13", self.T)                   # 367
        X.parse_dates("2000-01-01", "2000-01-02", self.T)
        with self.assertRaises(ValueError):
            X.parse_dates("1999-12-31", "2000-01-02", self.T)
        X.parse_dates("2026-11-14", "2026-11-14", self.T)                       # today + 1 (UTC skew)
        with self.assertRaisesRegex(ValueError, "future"):
            X.parse_dates("2026-11-14", "2026-11-15", self.T)

    def test_filename_from_isoformat(self):
        d1, d2 = X.parse_dates("2026-01-05", "2026-02-01", self.T)
        self.assertEqual(X.filename(d1, d2), "redpot-export-2026-01-05_2026-02-01.json")


# ------------------------------------------------------------------------------------------- HTTP API
class TestExportAuth(Base):
    def test_401_without_login(self):
        c = self.app.test_client()
        self.assertEqual(c.get(url(TODAY, TODAY), headers=H).status_code, 401)

    def test_403_wall_role(self):
        self.cfg["console"]["wall_token"] = "wt"
        w = self.app.test_client()
        self.assertEqual(w.get("/wall?k=wt").status_code, 302)
        self.assertEqual(w.get(url(TODAY, TODAY), headers=H).status_code, 403)

    def test_403_without_header(self):
        self.assertEqual(self.c.get(url(TODAY, TODAY)).status_code, 403)
        self.assertEqual(self.c.get(url(TODAY, TODAY), headers={"X-Requested-With": "XMLHttpRequest"}).status_code, 403)
        self.assertFalse(X.GATE.busy())

    def test_400_bad_reversed_long(self):
        t = TODAY
        for frm, to in [("bad", t), (t, "2026-1-1"), (t, t + timedelta(days=2)), (t, t - timedelta(days=1)),
                        (t - timedelta(days=367), t), ("２０２６-１１-１３", t)]:
            with self.subTest(frm=frm, to=to):
                r = self.c.get(url(frm, to), headers=H)
                self.assertEqual(r.status_code, 400)
                self.assertIn("error", r.get_json())
                self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertEqual(self.c.get("/api/export", headers=H).status_code, 400)
        self.assertFalse(X.GATE.busy())

    def test_validation_before_lock(self):
        """M7: a bad request never touches the gate, even while another export holds it."""
        tok = X.GATE.acquire()
        try:
            self.assertEqual(self.c.get(url("bad", TODAY), headers=H).status_code, 400)
        finally:
            X.GATE.release(tok)


class TestExportContent(Base):
    def test_document_shape_headers_and_selection(self):
        d = date(2026, 3, 10)
        prev, nxt = d - timedelta(days=1), d + timedelta(days=1)
        a = self.inc(day(prev), day(d, "00:00:00"), src="198.51.100.1")         # touches start -> included
        self.inc(day(prev, "01:00:00"), day(prev, "23:59:59"), src="198.51.100.2")   # ends before -> excluded
        c = self.inc(day(nxt, "00:00:00"), day(nxt), src="198.51.100.3")        # starts at end -> excluded
        b = self.inc(day(d, "08:00:00"), day(nxt), subject="sensor:FS01", src=None, level=4,
                     title="Decoy FS01 stopped", sensors='not json', note="n")
        self.alert(day(prev, "23:59:59"), {"x": 0})
        a1 = self.alert(day(d, "00:00:00"), {"src_ip": "198.51.100.1", "alert": {"summary": "héllo 𝔘"}}, iid=a)
        a2 = self.alert(day(d, "23:59:59"), {"y": 2}, iid=b, level=4)
        self.alert(day(nxt, "00:00:00"), {"z": 3}, iid=c)
        r = self.export(d.isoformat(), d.isoformat())
        self.assertEqual(r.headers["Content-Disposition"], 'attachment; filename="redpot-export-2026-03-10_2026-03-10.json"')
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertTrue(r.mimetype == "application/json")
        raw = r.get_data()
        self.assertTrue(raw.isascii())
        doc = self.ok_doc(r)
        self.assertEqual(list(doc), ["meta", "incidents", "alerts", "complete"])
        m = doc["meta"]
        self.assertEqual((m["product"], m["edition"]), ("ReD-Pot", EDITION))
        self.assertEqual(m["range"], {"from": "2026-03-10", "to": "2026-03-10", "start": "2026-03-10T00:00:00.000Z",
                                      "end": "2026-03-11T00:00:00.000Z"})
        self.assertEqual(m["counts"], {"incidents": 2, "alerts": 2})
        self.assertEqual([i["id"] for i in doc["incidents"]], [a, b])
        self.assertEqual([x["id"] for x in doc["alerts"]], [a1, a2])
        i0, i1 = doc["incidents"]
        self.assertEqual(set(i0), {"id", "kind", "src_ip", "subject", "first_ts", "last_ts", "level", "level_name",
                                   "title", "status", "sensors", "count", "note"})
        self.assertEqual((i0["kind"], i0["sensors"], i0["level_name"]), ("attacker", ["FS01"], "intent"))
        self.assertEqual((i1["kind"], i1["subject"], i1["sensors"]), ("sensor", "sensor:FS01", ["not json"]))
        rec = doc["alerts"][0]["record"]
        self.assertIsInstance(rec, dict)                                        # M6: parsed object, not a string
        self.assertEqual(rec["alert"]["summary"], "héllo 𝔘")

    def test_real_ingest_records(self):
        self.eng.ingest([ev("smb.tree", src="198.51.100.9", share="Finance"), ev("smb.tree", src="198.51.100.9", share="HR")])
        doc = self.ok_doc(self.export())
        self.assertGreaterEqual(doc["meta"]["counts"]["alerts"], 1)
        self.assertEqual(doc["incidents"][0]["src_ip"], "198.51.100.9")
        self.assertEqual(doc["alerts"][0]["record"]["src_ip"], "198.51.100.9")

    def test_tolerant_rows_stay_strict_json(self):
        t = day(TODAY, "01:00:00")
        self.inc(t, t, sensors='{"a":1}', title="\x00\x1f\"\\ 𝔘")
        self.inc(t, t, sensors=None)
        self.alert(t, "not json {")
        self.alert(t, '{"v": NaN}')
        self.alert(t, '{"v": 1e400}')
        self.alert(t, b'\xff\xfe{"bin":1}')
        self.alert(t, '[' * 50000 + ']' * 50000)                               # recursion depth
        self.db.execute("INSERT INTO alert_records(ts, incident_id, level, record) VALUES(?,?,?,NULL)", (t, 1, 9.5))
        doc = self.ok_doc(self.export())
        self.assertEqual(doc["incidents"][0]["sensors"], ['{"a":1}'])
        self.assertEqual(doc["incidents"][0]["title"], "\x00\x1f\"\\ 𝔘")
        self.assertEqual(doc["incidents"][1]["sensors"], [])
        recs = [a["record"] for a in doc["alerts"]]
        self.assertEqual(recs[0], "not json {")
        self.assertEqual(recs[1], '{"v": NaN}')
        self.assertEqual(recs[2], '{"v": 1e400}')
        self.assertIsInstance(recs[3], str)
        self.assertIsInstance(recs[4], str)
        self.assertIsNone(recs[5])


class TestExportCapsAndLock(Base):
    def fill(self, n=50, d=None):
        t = day(d or TODAY, "02:00:00")
        self.db.execute("BEGIN")
        iid = self.inc(t, t)
        for i in range(n):
            self.alert(t, {"i": i, "pad": "x" * 200}, iid=iid)
        self.db.execute("COMMIT")

    def test_413_with_counts_then_200(self):
        """M7: 413 releases the gate; the next export works."""
        self.fill(50)
        with mock.patch.object(X, "MAX_BYTES", 4096):
            r = self.export()
            self.assertEqual(r.status_code, 413)
            j = r.get_json()
            self.assertEqual(set(j), {"error", "incidents", "alerts", "bytes", "max_bytes"})
            self.assertEqual((j["incidents"], j["alerts"], j["max_bytes"]), (1, 50, 4096))
            self.assertGreater(j["bytes"], 4096)
            self.assertIn("narrow the date range", j["error"])
            self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertFalse(X.GATE.busy())
        doc = self.ok_doc(self.export())
        self.assertEqual(len(doc["alerts"]), 50)

    def test_429_concurrent_then_free(self):
        self.fill(5)
        r1 = self.export(buffered=False)
        self.assertEqual(r1.status_code, 200)
        self.assertTrue(X.GATE.busy())
        r2 = self.export()
        self.assertEqual(r2.status_code, 429)
        r1.close()
        self.assertFalse(X.GATE.busy())
        self.ok_doc(self.export())

    def test_client_disconnect_mid_stream_frees_lock(self):
        """M7: the client goes away after the first chunk; closing the response frees gate + connection."""
        self.fill(300)
        with mock.patch.object(X, "BATCH_BYTES", 1024):
            r = self.export(buffered=False)
            it = iter(r.response)
            first = next(it)
            self.assertTrue(first.startswith(b'{"meta":'))
            self.assertTrue(X.GATE.busy())
            r.close()                                  # what the WSGI server does on a client disconnect
        self.assertFalse(X.GATE.busy())
        self.ok_doc(self.export())

    def test_response_never_iterated_is_released_on_close(self):
        self.fill(5)
        r = self.export(buffered=False)
        r.close()
        self.assertFalse(X.GATE.busy())

    def test_error_path_releases(self):
        self.fill(5)
        with mock.patch.object(X, "stats", side_effect=sqlite3.OperationalError("boom")):
            try:
                r = self.export()
                self.assertEqual(r.status_code, 500)
            except sqlite3.OperationalError:
                pass
        self.assertFalse(X.GATE.busy())
        with mock.patch.object(X, "open_snapshot", side_effect=sqlite3.OperationalError("boom")):
            try:
                self.export()
            except sqlite3.OperationalError:
                pass
        self.assertFalse(X.GATE.busy())

    def test_stale_holder_is_taken_over(self):
        tok = X.GATE.acquire()
        X.GATE._since -= X.WALL_SECONDS + X.STALE_GRACE + 1                      # a leaked, never-closed export
        self.ok_doc(self.export())
        X.GATE.release(tok)                                                     # late release of the old owner: no-op
        self.assertFalse(X.GATE.busy())

    def test_wall_time_cap(self):
        """M7: past the deadline the stream ends without "complete" (and the gate is still released)."""
        self.fill(20)
        with mock.patch.object(X, "WALL_SECONDS", -1):
            r = self.export()
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b'"complete"', r.data)
        self.assertFalse(X.GATE.busy())

    def test_per_ip_throttle(self):
        codes = [self.export().status_code for _ in range(11)]
        self.assertEqual(codes, [200] * 10 + [429])
        other = self.app.test_client()
        other.post("/login", data={"token": "at"}, environ_base={"REMOTE_ADDR": "10.9.9.9"})
        self.assertEqual(self.export(client=other, environ_base={"REMOTE_ADDR": "10.9.9.9"}).status_code, 200)

    def test_ingest_continues_during_export(self):
        """Separate read-only snapshot: ingest commits mid-stream; the export stays consistent (counts = rows)."""
        self.fill(400)
        with mock.patch.object(X, "BATCH_BYTES", 2048), mock.patch.object(X, "FETCH_ROWS", 10):
            r = self.export(buffered=False)
            it = iter(r.response)
            parts = [next(it)]
            t0 = time.monotonic()
            stored = self.eng.ingest([ev("smb.tree", src="203.0.113.77", share="Finance")])
            self.assertEqual(stored, 1)
            self.assertLess(time.monotonic() - t0, 5)                             # not blocked by the reader
            n = self.db.execute("SELECT COUNT(*) FROM events WHERE src_ip='203.0.113.77'").fetchone()[0]
            self.assertEqual(n, 1)
            parts.extend(it)
            r.close()
        doc = strict_loads(b"".join(parts).decode())
        self.assertIs(doc["complete"], True)
        self.assertEqual(doc["meta"]["counts"], {"incidents": len(doc["incidents"]), "alerts": len(doc["alerts"])})
        self.assertNotIn("203.0.113.77", json.dumps(doc))                        # snapshot taken before the ingest
        self.assertIn("203.0.113.77", json.dumps(self.ok_doc(self.export())))


# ------------------------------------------------------------------------------------------- M6 size
class TestExportSize(Base):
    def flood(self, n=2000):
        t = day(TODAY, "03:00:00")
        iid = self.inc(t, t, title="漢字𝔘" * 50)
        astral = "😀𝔘" * 120 + "漢字ü" * 100 + "\u0000\u001f"                  # 4-, 3-, 2-byte chars + controls
        rows = [(t, iid, 3, json.dumps({"i": i, "s": astral}, ensure_ascii=False)) for i in range(n)]
        self.db.execute("BEGIN")
        self.db.executemany("INSERT INTO alert_records(ts, incident_id, level, record) VALUES(?,?,?,?)", rows)
        self.db.execute("COMMIT")
        return iid

    def test_estimate_is_upper_bound_for_non_ascii(self):
        self.flood(300)
        conn = X.open_snapshot(self.db_path)
        try:
            rng = X.parse_range(TODAY.isoformat(), TODAY.isoformat())
            st = X.stats(conn, rng)
            blob = conn.execute("SELECT SUM(LENGTH(CAST(record AS BLOB))) FROM alert_records").fetchone()[0]
            out = "".join(X.iter_json(conn, rng, X.build_meta(TODAY, TODAY, st), max_bytes=10 ** 9))
        finally:
            conn.close()
        self.assertTrue(out.endswith(X.TAIL))
        self.assertTrue(out.isascii())
        self.assertGreater(len(out), 2 * blob)              # escaping more than doubles astral/CJK text ...
        self.assertGreaterEqual(st["bytes"], len(out))      # ... and the estimate still covers it

    def test_flood_refused_over_cap_http(self):
        self.flood(2000)
        with mock.patch.object(X, "MAX_BYTES", 2 * 2 ** 20):
            r = self.export()
        self.assertEqual(r.status_code, 413)
        self.assertEqual(r.get_json()["alerts"], 2000)
        self.assertFalse(X.GATE.busy())

    def test_generator_byte_cap_and_memory_bound(self):
        """M6: the generator never emits more than max_bytes, ends without "complete", yields chunks of at most
        BATCH_BYTES, and streams a ~6 MB document with a bounded peak allocation."""
        self.flood(2000)
        rng = X.parse_range(TODAY.isoformat(), TODAY.isoformat())
        conn = X.open_snapshot(self.db_path)
        try:
            meta = X.build_meta(TODAY, TODAY, X.stats(conn, rng))
            cap = 1_000_000
            chunks = list(X.iter_json(conn, rng, meta, max_bytes=cap, batch_bytes=64 * 1024))
            total = sum(len(c) for c in chunks)
            self.assertLessEqual(total, cap)
            self.assertGreater(total, cap - 10_000)
            self.assertTrue(all(len(c) <= 64 * 1024 for c in chunks))
            self.assertNotIn('"complete"', chunks[-1])
        finally:
            conn.close()
        conn = X.open_snapshot(self.db_path)
        try:
            tracemalloc.start()
            try:
                total = n = 0
                for c in X.iter_json(conn, rng, meta, max_bytes=10 ** 9, batch_bytes=256 * 1024):
                    total += len(c)
                    n += 1
                    last = c
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        finally:
            conn.close()
        self.assertTrue(last.endswith(X.TAIL))
        self.assertGreater(total, 5 * 2 ** 20)
        self.assertLess(peak, 4 * 2 ** 20, f"peak {peak} bytes while streaming {total} bytes")

    def test_single_huge_row_is_sliced(self):
        t = day(TODAY, "04:00:00")
        self.alert(t, {"big": "a" * 300_000})
        conn = X.open_snapshot(self.db_path)
        try:
            rng = X.parse_range(TODAY.isoformat(), TODAY.isoformat())
            chunks = list(X.iter_json(conn, rng, X.build_meta(TODAY, TODAY, X.stats(conn, rng)), batch_bytes=65536))
        finally:
            conn.close()
        self.assertTrue(all(len(c) <= 65536 for c in chunks))
        self.assertEqual(strict_loads("".join(chunks))["alerts"][0]["record"]["big"], "a" * 300_000)


class TestSnapshotUri(unittest.TestCase):
    def test_ro_uri_quoted_path(self):
        """L12: the db path is percent-quoted into the URI ('?', '#', '%' and spaces are not URI syntax)."""
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "we ird?mode=rw#x%41")
            os.makedirs(d)
            p = os.path.join(d, "c.db")
            c = sqlite3.connect(p)
            c.executescript("CREATE TABLE incidents(id); CREATE TABLE alert_records(id);")
            c.close()
            self.assertEqual(X.ro_uri(p), "file://" + urllib.parse.quote(p) + "?mode=ro")
            conn = X.open_snapshot(p)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    conn.execute("INSERT INTO incidents VALUES(1)")
            finally:
                conn.close()
            self.assertEqual(sorted(os.listdir(td)), ["we ird?mode=rw#x%41"])    # nothing created elsewhere
            with self.assertRaises(sqlite3.OperationalError):
                X.open_snapshot(os.path.join(d, "missing.db"))                  # mode=ro never creates a file
            self.assertFalse(os.path.exists(os.path.join(d, "missing.db")))


# ------------------------------------------------------------------------------------------- rpotctl
def ctl(*args):
    return subprocess.run([sys.executable, CTL, *args], capture_output=True, text=True, timeout=120,
                          stdin=subprocess.DEVNULL)


class TestCtl(Base):
    n_local = 2

    def setUp(self):
        super().setUp()
        self.cfg_path = os.path.join(self.tmp, "rpot.json")
        with open(self.cfg_path, "w") as f:
            json.dump(self.cfg, f)

    def test_slots_one_json_line(self):
        self.eng.fleet.create_enrollment("REM01", "linux-web-hosting")
        p = ctl("slots", "--db", self.db_path, "--config", self.cfg_path)
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        d = json.loads(lines[-1])
        self.assertEqual(list(d), ["max", "used", "local", "remote", "pending"])
        self.assertEqual(d, {"max": MAX_DECOYS, "used": 3, "local": 2, "remote": 0, "pending": 1})
        self.assertEqual(d, {k: v for k, v in self.eng.fleet.slots().items()})

    def test_slots_errors(self):
        cfg = dict(self.cfg, version=1)
        old = os.path.join(self.tmp, "old.json")
        with open(old, "w") as f:
            json.dump(cfg, f)
        p = ctl("slots", "--db", self.db_path, "--config", old)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("fresh installs only", p.stderr)
        self.assertEqual(p.stdout, "")
        p = ctl("slots", "--db", os.path.join(self.tmp, "nope.db"), "--config", self.cfg_path)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot read the manager database", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "nope.db")))
        p = ctl("slots", "--db", self.db_path, "--config", os.path.join(self.tmp, "nope.json"))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("error:", p.stderr)

    def test_export_cli_ok(self):
        self.eng.ingest([ev("smb.tree", src="198.51.100.9", share="Finance")])
        t = TODAY.isoformat()
        p = ctl("export", "--db", self.db_path, "--config", self.cfg_path, "--from", t, "--to", t)
        self.assertEqual(p.returncode, 0, p.stderr)
        doc = strict_loads(p.stdout)
        self.assertIs(doc["complete"], True)
        self.assertEqual(doc["incidents"][0]["src_ip"], "198.51.100.9")
        self.assertIsInstance(doc["alerts"][0]["record"], dict)
        self.assertEqual(p.stderr, "")

    def test_export_cli_bad_range_exit_2(self):
        for frm, to in [("2026-1-1", "2026-11-13"), ("2026-11-13", "2026-11-01"), ("2024-01-01", "2026-01-01")]:
            p = ctl("export", "--db", self.db_path, "--config", self.cfg_path, "--from", frm, "--to", to)
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertEqual(p.stdout, "")
            self.assertIn("error:", p.stderr)

    def test_export_cli_refuses_v1_config(self):
        old = os.path.join(self.tmp, "old.json")
        with open(old, "w") as f:
            json.dump(dict(self.cfg, version=1), f)
        t = TODAY.isoformat()
        p = ctl("export", "--db", self.db_path, "--config", old, "--from", t, "--to", t)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("fresh installs only", p.stderr)

    def run_main(self, *argv):
        import rpotctl
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(sys, "argv", ["rpotctl.py", *argv]), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                rpotctl.main()
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_export_cli_too_large_exit_3(self):
        t = day(TODAY, "02:00:00")
        for i in range(50):
            self.alert(t, {"i": i, "pad": "x" * 200})
        d = TODAY.isoformat()
        with mock.patch.object(X, "MAX_BYTES", 4096):
            code, out, err = self.run_main("export", "--db", self.db_path, "--config", self.cfg_path, "--from", d, "--to", d)
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertIn("too large", err)

    def test_export_cli_cut_off_exit_3(self):
        """Generator backstop: if the cap is hit while streaming, exit 3 and the output has no "complete"."""
        t = day(TODAY, "02:00:00")
        for i in range(50):
            self.alert(t, {"i": i})
        d = TODAY.isoformat()
        with mock.patch.object(X, "stats", return_value={"incidents": 0, "alerts": 50, "bytes": 1}), \
                mock.patch.object(X, "MAX_BYTES", 1500):
            code, out, err = self.run_main("export", "--db", self.db_path, "--config", self.cfg_path, "--from", d, "--to", d)
        self.assertEqual(code, 3)
        self.assertLessEqual(len(out), 1500)
        self.assertNotIn('"complete"', out)
        self.assertIn("cut off", err)


if __name__ == "__main__":
    unittest.main()
