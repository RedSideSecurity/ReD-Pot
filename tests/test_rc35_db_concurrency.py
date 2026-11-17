"""RC-35 B7 (client report): "Network map: /api/graph ... 500". The engine shared ONE sqlite3 connection between all
threads, and the read paths ran on it without the lock: concurrent ingest + reads gave sqlite3.InterfaceError
("bad parameter or other API misuse"), IndexError, and failed ingest batches (UNIQUE constraint, rolled back).

Bounded version of the coordinator's race.py: 2 writers + 3 readers for ~2 s, zero errors allowed."""
import os
import random
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.common.events import now_iso  # noqa: E402
from rpot.console.dbconn import Result, SharedDB  # noqa: E402
from rpot.console.engine import Engine  # noqa: E402
from test_unit import mkcfg  # noqa: E402

SECONDS = 2.0


def batch(n=50):
    return [{"ts": now_iso(), "sensor": "FS01", "role": "windows-file-server", "sensor_ip": "172.30.0.21",
             "src_ip": random.choice([f"192.168.{random.randint(1, 40)}.{random.randint(1, 250)}",
                                      f"45.95.{random.randint(0, 3)}.{random.randint(1, 250)}"]),
             "src_port": 5, "dst_port": 445, "proto": "smb",
             "type": random.choice(["tcp.connect", "smb.share_enum", "smb.auth", "auth.failed"]), "data": {}}
            for _ in range(n)]


class TestConcurrentIngestAndReads(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = Engine(mkcfg(self.tmp.name), os.path.join(self.tmp.name, "t.db"))
        self.e.ingest(batch(200))

    def tearDown(self):
        self.e.db.close()
        self.tmp.cleanup()

    def test_no_errors_under_concurrent_load(self):
        e, stop = self.e, time.monotonic() + SECONDS
        errors, calls, lock = [], {}, threading.Lock()

        def loop(name, fn):
            while time.monotonic() < stop:
                try:
                    fn()
                    with lock:
                        calls[name] = calls.get(name, 0) + 1
                except Exception as ex:                       # noqa: BLE001 — every error is the finding
                    with lock:
                        errors.append(f"{name}: {type(ex).__name__}: {ex}")
        jobs = [("ingest", lambda: e.ingest(batch())), ("ingest", lambda: e.ingest(batch())),
                ("graph", lambda: e.graph(24, 3, "internal")), ("graph-all", lambda: e.graph(24, 1, "all")),
                ("panels", lambda: (e.summary(), e.worldmap(), e.incidents(), e.hosts(), e.events(limit=200)))]
        ts = [threading.Thread(target=loop, args=j, daemon=True) for j in jobs]
        for t in ts:
            t.start()
        for t in ts:
            t.join(SECONDS + 60)
        self.assertEqual(errors[:10], [])
        for k in ("ingest", "graph", "graph-all", "panels"):
            self.assertGreater(calls.get(k, 0), 0, calls)
        n = e.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertGreater(n, 200)

    def _readers(self, jobs, seconds):
        stop, errors, calls, lock = time.monotonic() + seconds, [], {}, threading.Lock()

        def loop(name, fn):
            while time.monotonic() < stop:
                try:
                    fn()
                    with lock:
                        calls[name] = calls.get(name, 0) + 1
                except Exception as ex:                       # noqa: BLE001
                    with lock:
                        errors.append(f"{name}: {type(ex).__name__}: {ex}")
        ts = [threading.Thread(target=loop, args=j, daemon=True) for j in jobs]
        for t in ts:
            t.start()
        return ts, errors, calls

    def test_parallel_reads_without_ingest(self):
        """QA vm1 control run: parallel API reads alone (no ingest) broke graph, incidents and summary in 1.0.0."""
        e = self.e
        jobs = [("incidents", lambda: e.incidents(24 * 7, 2, "open"))] * 3 + [("summary", lambda: e.summary(24))] * 3 + \
               [("graph", lambda: e.graph(24, 3, "internal"))] * 2
        ts, errors, calls = self._readers(jobs, 2.0)
        for t in ts:
            t.join(60)
        self.assertEqual(errors[:10], [])
        for k in ("incidents", "summary", "graph"):
            self.assertGreater(calls.get(k, 0), 0, calls)

    def test_ingest_batch_is_atomic_under_concurrent_reads(self):
        """QA vm1: a batch answered 500 had been PARTLY committed (another thread's statement ended the transaction),
        so the sender's retry stored duplicates. Now a failing batch stores nothing, also while readers run."""
        e = self.e
        real = e._one

        def one(ev):
            if ev.get("type") == "boom":
                raise RuntimeError("bad event in the middle of the batch")
            return real(ev)
        e._one = one
        ts, errors, _ = self._readers([("incidents", lambda: e.incidents()), ("summary", lambda: e.summary()),
                                       ("graph", lambda: e.graph(24, 1, "all"))], 2.0)
        before = e.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        failed = 0
        for i in range(20):
            b = batch(10)
            b.insert(5, dict(b[0], type="boom"))
            try:
                e.ingest(b)
            except RuntimeError:
                failed += 1
            self.assertFalse(e.db.in_transaction)
        for t in ts:
            t.join(60)
        self.assertEqual(failed, 20)
        self.assertEqual(e.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], before)   # nothing half-stored
        e.ingest(batch(10))                                                                    # and ingest still works
        self.assertEqual(e.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] - before >= 10, True)
        self.assertEqual(errors[:10], [])

    def test_reads_use_a_read_only_connection_outside_transactions(self):
        db = self.e.db
        self.assertIsInstance(db, SharedDB)
        r = db.execute("SELECT COUNT(*) FROM events")
        self.assertIsInstance(r, Result)
        ro = db._tl.conn
        self.assertIsNotNone(ro)
        import sqlite3
        with self.assertRaises(sqlite3.OperationalError):     # it really is read-only
            ro.execute("DELETE FROM events")

    def test_reads_inside_the_writers_transaction_see_its_rows(self):
        db = self.e.db
        with self.e.lock:
            db.execute("BEGIN")
            db.execute("INSERT INTO sensors(name, role, ip) VALUES('TXN1', 'x', '1.2.3.4')")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sensors WHERE name='TXN1'").fetchone()[0], 1)
            seen = []
            t = threading.Thread(target=lambda: seen.append(
                db.execute("SELECT COUNT(*) FROM sensors WHERE name='TXN1'").fetchone()[0]))
            t.start()
            t.join(10)
            self.assertEqual(seen, [0])                       # other threads: last committed state, not blocked
            db.execute("ROLLBACK")

    def test_result_behaves_like_a_cursor(self):
        db = self.e.db
        r = db.execute("SELECT name FROM sensors ORDER BY name")
        first = r.fetchone()
        rest = r.fetchall()
        self.assertEqual(len(rest) + 1, len(db.execute("SELECT name FROM sensors").fetchall()))
        self.assertIsNotNone(first)
        self.assertIsNone(r.fetchone())
        cur = db.execute("INSERT INTO sensors(name, role, ip) VALUES('RC1', 'x', '1.2.3.4')")
        self.assertGreater(cur.lastrowid, 0)
        self.assertEqual(db.execute("DELETE FROM sensors WHERE name='RC1'").rowcount, 1)



class TestApiMemo(unittest.TestCase):
    """Client B7 follow-up: identical /api/graph | /api/worldmap requests share one computation (single flight) and
    a result is reused for up to MEMO_TTL s; the engine methods themselves are not cached."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = Engine(mkcfg(self.tmp.name), os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.e.db.close()
        self.tmp.cleanup()

    def test_single_flight_and_ttl(self):
        n, gate = [], threading.Event()

        def slow():
            n.append(1)
            gate.wait(5)
            return {"v": len(n)}
        out = []
        ts = [threading.Thread(target=lambda: out.append(self.e.memo(("k",), slow))) for _ in range(5)]
        for t in ts:
            t.start()
        time.sleep(0.3)
        gate.set()
        for t in ts:
            t.join(10)
        self.assertEqual(len(n), 1)                       # five concurrent callers, one computation
        self.assertEqual(out, [{"v": 1}] * 5)
        self.assertEqual(self.e.memo(("k",), slow), {"v": 1})   # within the TTL: reused
        self.assertEqual(len(n), 1)
        exp, val = self.e._memo[("k",)]
        self.e._memo[("k",)] = (0, val)                                # expired
        self.assertEqual(self.e.memo(("k",), slow), {"v": 2})          # computed again
        r = self.e.memo(("k2",), lambda: {"a": 1})
        r["a"] = 2                                         # callers get a copy: the cached value is not changed
        self.assertEqual(self.e.memo(("k2",), lambda: {"a": 9}), {"a": 1})

    def test_api_uses_the_memo_and_engine_stays_fresh(self):
        from rpot.console.app import create_app
        app = create_app(mkcfg(self.tmp.name), os.path.join(self.tmp.name, "a.db"))
        c = app.test_client()
        c.post("/login", data={"token": "at"})
        calls = []
        real = app.engine.graph
        app.engine.graph = lambda *a: calls.append(a) or real(*a)
        for _ in range(3):
            self.assertEqual(c.get("/api/graph?hours=24&min_level=3&scope=internal").status_code, 200)
        self.assertEqual(len(calls), 1)
        self.assertEqual(c.get("/api/graph?hours=1&min_level=3").status_code, 200)   # other parameters: own entry
        self.assertEqual(len(calls), 2)
        self.e.ingest(batch(5))
        self.assertTrue(self.e.graph(24, 1, "all")["nodes"])          # direct engine call: never cached


    def test_memo_stays_bounded(self):
        """Final review R3-L3: no lock left behind per key, at most MEMO_MAX cached results."""
        for i in range(500):
            self.e.memo(("k", i), lambda: {"i": 1})
        self.assertEqual(self.e._flight, {})
        self.assertLessEqual(len(self.e._memo), Engine.MEMO_MAX)

    def test_api_hours_rounded_to_presets(self):
        from rpot.console.app import create_app
        app = create_app(mkcfg(self.tmp.name), os.path.join(self.tmp.name, "b.db"))
        c = app.test_client()
        c.post("/login", data={"token": "at"})
        seen = []
        real = app.engine.graph
        app.engine.graph = lambda *a: seen.append(a[0]) or real(*a)
        for h in ("0.3", "0.5", "1", "2", "12.7", "24", "100", "169", "5000", "nan", "abc"):
            self.assertEqual(c.get(f"/api/graph?hours={h}&min_level=3").status_code, 200)
        self.assertTrue(set(seen) <= {0.25, 1, 24, 168, 720, 2160}, seen)
        self.assertLessEqual(len(app.engine._memo), 6)
        self.assertEqual(app.engine._flight, {})


if __name__ == "__main__":
    unittest.main()
