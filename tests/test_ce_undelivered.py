"""CE D-5/D-9: no offline replay. A failed batch is retried in memory for at most 60 s, then it and
everything of the outage go to a write-only local log that is never sent; on reconnect exactly one
counts-only sensor.gap event goes to the manager, which turns it into a note on the decoy.

Fake client + injectable clock/sleep: no real 60 s waits."""
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.common import events as E  # noqa: E402
from rpot.common.events import Emitter  # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, d):
        self.slept.append(d)
        self.t += d


class FakeClient:
    """Manager stand-in: `up` decides whether a POST is accepted. Only accepted batches count as delivered."""
    def __init__(self, up=True):
        self.up = up
        self.delivered = []          # list of batches
        self.attempts = 0

    def request(self, method, path, body=None):
        self.attempts += 1
        if not self.up:
            raise ConnectionRefusedError("manager down")
        self.delivered.append(list(body["events"]))
        return 200, {"ok": True}

    def events(self):
        return [e for b in self.delivered for e in b]

    def types(self):
        return [e["type"] for e in self.events()]


def mk(d, clock, client=None, **kw):
    kw.setdefault("interval", 0.001)
    em = Emitter("FS01", "windows-file-server", None, None, sensor_ip="10.0.0.5", data_dir=d, stdout=False,
                 clock=clock, sleep=clock.sleep, start=False, **kw)
    em.client = client
    return em


def ev(em, n):
    return em.emit("smb.auth", src=("10.0.0.9", 5000 + n), dst_port=445, proto="smb", session=f"s{n}", user=f"u{n}")


def read_log(em):
    with open(em.local_log, "rb") as f:
        return [json.loads(x) for x in f.read().splitlines() if x]


def run_until(em, cond, limit=500):
    for _ in range(limit):
        if cond():
            return True
        em._step()
        if em.down and isinstance(em._clock, FakeClock):
            em._clock.t += 1.0                           # down mode waits on the queue, not on sleep()
    return cond()


class TestNoReplay(unittest.TestCase):
    def test_outage_events_never_posted_and_one_gap_after_reconnect(self):
        with tempfile.TemporaryDirectory() as d:
            clk, cl = FakeClock(), FakeClient(up=False)
            em = mk(d, clk, cl)
            t0 = clk.t
            a = ev(em, 1)
            em._step()                                   # first POST fails → batch kept in memory
            self.assertFalse(em.down)
            self.assertEqual([e["session"] for e in em._pending], ["s1"])
            self.assertTrue(run_until(em, lambda: em.down))
            self.assertGreaterEqual(clk.t - t0, 60)      # retried for the whole window …
            self.assertLessEqual(clk.t - t0, 61)         # … and not longer
            self.assertTrue(all(s <= 10 for s in clk.slept))
            b, c = ev(em, 2), ev(em, 3)
            em._step()                                   # down: straight to the local log
            em._step()
            cl.up = True                                 # manager is back
            self.assertTrue(run_until(em, lambda: not em.down))
            for _ in range(5):                           # more cycles: still exactly one gap note
                em._step()
            live = ev(em, 4)
            run_until(em, lambda: "s4" in [e.get("session") for e in cl.events()])
            for _ in range(3):
                em._step()

            sent_sessions = [e.get("session") for e in cl.events()]
            for s in ("s1", "s2", "s3"):
                self.assertNotIn(s, sent_sessions)       # outage events never POSTed
            self.assertIn("s4", sent_sessions)
            gaps = [e for e in cl.events() if e["type"] == "sensor.gap"]
            self.assertEqual(len(gaps), 1)
            self.assertEqual(gaps[0]["data"], {"undelivered": 3, "first_ts": a["ts"], "last_ts": c["ts"]})
            self.assertEqual(set(json.dumps(gaps[0]["data"])) & set("<>"), set())
            self.assertNotIn("u1", json.dumps(gaps))     # no event content in the gap
            self.assertLess(cl.types().index("sensor.gap"), sent_sessions.index("s4"))

            logged = read_log(em)
            self.assertEqual([e["session"] for e in logged], ["s1", "s2", "s3"])
            self.assertEqual(logged[0], a)
            self.assertEqual(logged[2], c)
            self.assertNotIn("sensor.heartbeat", [e["type"] for e in logged])
            self.assertEqual(stat.S_IMODE(os.stat(em.local_log).st_mode), 0o600)
            self.assertEqual(os.path.basename(em.local_log), "undelivered-FS01.jsonl")
            self.assertEqual(em.undelivered, 0)
            self.assertEqual(live["session"], "s4")

    def test_inflight_batch_delivered_if_manager_returns_within_window(self):
        with tempfile.TemporaryDirectory() as d:
            clk, cl = FakeClock(), FakeClient(up=False)
            em = mk(d, clk, cl)
            t0 = clk.t
            ev(em, 1)
            for _ in range(4):
                em._step()                               # 4 failures, backoff 1, 2, 4, 8 s
            self.assertEqual(clk.slept, [1.0, 2.0, 4.0, 8.0])
            ev(em, 2)                                    # queued behind the in-flight batch
            cl.up = True
            run_until(em, lambda: "s2" in [e.get("session") for e in cl.events()])
            self.assertLess(clk.t - t0, 60)
            self.assertEqual([e.get("session") for e in cl.events() if e["type"] == "smb.auth"], ["s1", "s2"])
            self.assertNotIn("sensor.gap", cl.types())   # nothing lost → no gap note
            self.assertFalse(os.path.exists(em.local_log))
            self.assertFalse(em.down)

    def test_no_client_at_all_goes_to_log_after_window(self):
        with tempfile.TemporaryDirectory() as d:
            clk = FakeClock()
            em = mk(d, clk, None)
            ev(em, 1)
            self.assertTrue(run_until(em, lambda: em.down))
            self.assertEqual([e["session"] for e in read_log(em)], ["s1"])

    def test_memory_cap_during_retry_window(self):
        with tempfile.TemporaryDirectory() as d:
            clk, cl = FakeClock(), FakeClient(up=False)
            em = mk(d, clk, cl, queue_max=5)
            ev(em, 0)
            em._step()                                   # s0 in flight
            for i in range(1, 21):                       # flood during the retry window
                ev(em, i)
                self.assertLessEqual(em.q.qsize(), 5)
            self.assertEqual(em.q.qsize(), 5)
            self.assertEqual(len(em._pending), 1)
            self.assertEqual(em.undelivered, 15)         # overflow went to the local log, not to memory
            self.assertEqual([e["session"] for e in read_log(em)], [f"s{i}" for i in range(6, 21)])
            self.assertTrue(run_until(em, lambda: em.down))
            self.assertEqual(em.q.qsize(), 0)
            self.assertEqual(sorted(e["session"] for e in read_log(em)), sorted(f"s{i}" for i in range(21)))
            self.assertEqual(em.undelivered, 21)
            self.assertEqual(cl.delivered, [])

    def test_stop_during_window_writes_batch_to_log(self):
        with tempfile.TemporaryDirectory() as d:
            clk, cl = FakeClock(), FakeClient(up=False)
            em = mk(d, clk, cl)
            ev(em, 1)
            em._step()
            em._stop.set()
            em._step()
            self.assertIsNone(em._pending)
            self.assertEqual([e["session"] for e in read_log(em)], ["s1"])


class TestLocalLogHardening(unittest.TestCase):
    def test_heartbeat_and_gap_never_logged(self):
        with tempfile.TemporaryDirectory() as d:
            em = mk(d, FakeClock())
            em._log_local([em._heartbeat(), {"type": "sensor.gap", "data": {"undelivered": 1}}])
            self.assertFalse(os.path.exists(em.local_log))
            self.assertEqual(em.undelivered, 0)

    def test_symlink_at_log_path_refused(self):
        with tempfile.TemporaryDirectory() as d:
            em = mk(d, FakeClock())
            victim = os.path.join(d, "victim")
            with open(victim, "w") as f:
                f.write("keep\n")
            os.symlink(victim, em.local_log)
            em._log_local([{"type": "smb.auth", "ts": "2026-11-13T10:00:00.000Z"}])
            with open(victim) as f:
                self.assertEqual(f.read(), "keep\n")
            self.assertIn("local log", em.last_error)
            self.assertEqual(em.undelivered, 1)          # still counted for the gap note

    def _no_block(self, em):
        t = threading.Thread(target=em._log_local, args=([{"type": "smb.auth", "ts": "2026-11-13T10:00:00.000Z"}],),
                             daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "writing to a FIFO blocked the sender")
        self.assertIn("local log", em.last_error)

    def test_fifo_without_reader_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as d:
            em = mk(d, FakeClock())
            os.mkfifo(em.local_log, 0o600)
            self._no_block(em)

    def test_fifo_with_reader_refused(self):
        with tempfile.TemporaryDirectory() as d:
            em = mk(d, FakeClock())
            os.mkfifo(em.local_log, 0o600)
            r = os.open(em.local_log, os.O_RDONLY | os.O_NONBLOCK)
            try:
                self._no_block(em)
                self.assertIn("not a regular file", em.last_error)
                try:
                    got = os.read(r, 10)
                except BlockingIOError:
                    got = b""
                self.assertEqual(got, b"")               # nothing was written into the pipe
            finally:
                os.close(r)

    def test_existing_file_mode_forced_to_0600(self):
        with tempfile.TemporaryDirectory() as d:
            em = mk(d, FakeClock())
            with open(em.local_log, "w"):
                pass
            os.chmod(em.local_log, 0o644)
            em._log_local([{"type": "smb.auth", "ts": "x"}])
            self.assertEqual(stat.S_IMODE(os.stat(em.local_log).st_mode), 0o600)

    def test_cap_keeps_newest_half_with_atomic_rotation(self):
        with tempfile.TemporaryDirectory() as d:
            em = mk(d, FakeClock(), log_max_bytes=4096)
            for i in range(300):
                em._log_local([{"type": "smb.auth", "ts": "2026-11-13T10:00:00.000Z", "n": i, "pad": "x" * 60}])
                self.assertLessEqual(os.path.getsize(em.local_log), 4096)
            rows = read_log(em)                          # every line is still whole JSON
            self.assertEqual(rows[-1]["n"], 299)
            self.assertNotIn(0, [r["n"] for r in rows])
            self.assertEqual([r["n"] for r in rows], list(range(rows[0]["n"], 300)))
            self.assertEqual(stat.S_IMODE(os.stat(em.local_log).st_mode), 0o600)
            self.assertEqual(sorted(os.listdir(d)), ["undelivered-FS01.jsonl"])   # no temp files left
            self.assertEqual(em.undelivered, 300)

    def test_oversized_batch_trimmed_to_newest(self):
        with tempfile.TemporaryDirectory() as d:
            em = mk(d, FakeClock(), log_max_bytes=2048)
            em._log_local([{"type": "smb.auth", "n": i, "pad": "y" * 50} for i in range(100)])
            rows = read_log(em)
            self.assertLessEqual(os.path.getsize(em.local_log), 2048)
            self.assertEqual(rows[-1]["n"], 99)

    def test_cap_from_env(self):
        with mock.patch.dict(os.environ, {"RPOT_UNDELIVERED_MAX_MB": "7"}):
            self.assertEqual(E.undelivered_max_bytes(), 7 * 1024 * 1024)
            with tempfile.TemporaryDirectory() as d:
                self.assertEqual(mk(d, FakeClock()).log_max, 7 * 1024 * 1024)
        for bad in ("x", "0", "-3"):
            with mock.patch.dict(os.environ, {"RPOT_UNDELIVERED_MAX_MB": bad}):
                self.assertEqual(E.undelivered_max_bytes(), 50 * 1024 * 1024)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RPOT_UNDELIVERED_MAX_MB", None)
            self.assertEqual(E.undelivered_max_bytes(), 50 * 1024 * 1024)

    def test_disk_errors_never_stop_the_decoy(self):
        with tempfile.TemporaryDirectory() as d:
            clk, cl = FakeClock(), FakeClient(up=False)
            em = mk(d, clk, cl)
            os.mkdir(em.local_log)                       # unusable log path
            ev(em, 1)
            self.assertTrue(run_until(em, lambda: em.down))
            self.assertIn("local log", em.last_error)
            cl.up = True
            ev(em, 2)
            run_until(em, lambda: not em.down)
            ev(em, 3)
            run_until(em, lambda: "s3" in [e.get("session") for e in cl.events()])
            self.assertIn("s3", [e.get("session") for e in cl.events()])
            gaps = [e for e in cl.events() if e["type"] == "sensor.gap"]
            self.assertEqual(len(gaps), 1)
            self.assertEqual(gaps[0]["data"]["undelivered"], 2)

    def test_no_read_back_code(self):
        src = open(E.__file__).read()
        for bad in ("_replay", "_read_", "json.load", "open(self.local_log", "O_RDONLY", "readline"):
            self.assertNotIn(bad, src)
        self.assertEqual(src.count("os.pread("), 1)        # only the rotation copies the newest tail


class TestThreaded(unittest.TestCase):
    """The real sender thread, with a short window (still no long sleeps)."""
    def test_thread_outage_and_reconnect(self):
        with tempfile.TemporaryDirectory() as d:
            cl = FakeClient(up=False)
            em = Emitter("FS01", "windows-file-server", None, None, sensor_ip="10.0.0.5", data_dir=d, stdout=False,
                         interval=0.01, retry_window=0.2, sleep=lambda s: time.sleep(min(s, 0.02)), start=False)
            em.client = cl
            em.thread.start()
            try:
                ev(em, 1)
                deadline = time.monotonic() + 10
                while not em.down and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(em.down)
                em._next_probe = 0                       # probe at once instead of after the 2 s backoff
                cl.up = True
                while "sensor.gap" not in cl.types() and time.monotonic() < deadline:
                    time.sleep(0.01)
                ev(em, 2)
                while "s2" not in [e.get("session") for e in cl.events()] and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(em.thread.is_alive())
                self.assertEqual(cl.types().count("sensor.gap"), 1)
                self.assertNotIn("s1", [e.get("session") for e in cl.events()])
                self.assertIn("s2", [e.get("session") for e in cl.events()])
            finally:
                em.close()


class TestEngineGap(unittest.TestCase):
    def _eng(self, tmp):
        from test_unit import mkcfg
        from rpot.console.engine import Engine
        return Engine(mkcfg(tmp), os.path.join(tmp, "x.db"))

    def _gap(self, sensor="FS01", **data):
        return {"ts": "2026-11-13T10:05:00.000Z", "sensor": sensor, "role": "windows-file-server",
                "sensor_ip": "172.30.0.21", "type": "sensor.gap", "data": data}

    @staticmethod
    def _ago(minutes):
        """Gap first/last_ts are the decoy's clock and must lie in [now-30d, now+5min] (F10): relative times."""
        from datetime import datetime, timedelta, timezone
        t = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return t.strftime("%Y-%m-%dT%H:%M:%S.000Z"), t.strftime("%Y-%m-%d %H:%M:%S")

    def test_gap_without_open_incident_creates_low_level_decoy_incident(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = self._eng(tmp)
            (f, f_txt), (la, _) = self._ago(60), self._ago(30)
            self.assertEqual(eng.ingest([self._gap(undelivered=42, first_ts=f, last_ts=la)]), 1)
            rows = eng.db.execute("SELECT * FROM incidents WHERE subject='sensor:FS01'").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["level"], 1)
            self.assertIsNone(rows[0]["src_ip"])
            self.assertIn("42 event(s)", rows[0]["note"])
            self.assertIn(f_txt, rows[0]["note"])
            evs = eng.events(incident=rows[0]["id"])
            self.assertEqual([e["type"] for e in evs], ["sensor.gap"])
            self.assertIn("42 event(s)", evs[0]["desc"])
            self.assertEqual(evs[0]["source"], "decoy FS01")
            self.assertIn("sensor.gap", [e["type"] for e in eng.events(hours=24 * 3650)])

    def test_gap_attaches_to_open_tamper_incident(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = self._eng(tmp)
            iid = eng.db.execute("INSERT INTO incidents(src_ip, subject, first_ts, last_ts, level, title, sensors, count, note) "
                                 "VALUES(NULL,'sensor:FS01','2026-11-13T09:00:00.000Z','2026-11-13T09:00:00.000Z',4,"
                                 "'Decoy FS01 stopped reporting','[\"FS01\"]',1,'earlier note')").lastrowid
            eng.ingest([self._gap(undelivered=7, first_ts="2026-11-13T09:01:00.000Z", last_ts="2026-11-13T09:02:00.000Z")])
            rows = eng.db.execute("SELECT * FROM incidents WHERE subject='sensor:FS01'").fetchall()
            self.assertEqual([r["id"] for r in rows], [iid])
            self.assertEqual(rows[0]["level"], 4)
            self.assertTrue(rows[0]["note"].startswith("earlier note\n"))
            self.assertIn("7 event(s)", rows[0]["note"])
            self.assertEqual(rows[0]["count"], 2)

    def test_hostile_gap_data_is_reduced_to_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = self._eng(tmp)
            eng.ingest([self._gap(undelivered="lots<script>", first_ts="<img src=x>", last_ts=["x"],
                                  content={"password": "Secret1"})])
            r = eng.db.execute("SELECT data FROM events WHERE type='sensor.gap'").fetchone()
            data = json.loads(r["data"])
            self.assertEqual({k: data[k] for k in ("undelivered", "first_ts", "last_ts")},
                             {"undelivered": 0, "first_ts": None, "last_ts": None})
            self.assertNotIn("Secret1", r["data"])
            self.assertNotIn("<", r["data"])
            eng.ingest([self._gap("FS02", undelivered=True), self._gap("FS03", undelivered=-5),
                        self._gap("FS04", undelivered=10 ** 15)])
            vals = [json.loads(x[0])["undelivered"] for x in eng.db.execute("SELECT data FROM events WHERE type='sensor.gap'")]
            self.assertEqual(vals, [0, 0, 0, 0])


class TestJoin409(unittest.TestCase):
    def test_enrollment_refused_message(self):
        from rpot.sensor import main as M
        from rpot.common import tlsutil

        class C:
            def __init__(self, *a, **k):
                pass

            def request(self, *a, **k):
                return 409, {"error": "decoy limit reached"}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(tlsutil, "PinnedClient", C), \
                mock.patch.object(tlsutil, "parse_join", lambda s: ("https://10.0.0.1:8741", "tok", "AB" * 32)):
            with self.assertRaises(SystemExit) as cm:
                M.join("redpot://10.0.0.1:8741/tok#" + "AB" * 32, d)
            msg = str(cm.exception.code)
            self.assertTrue(msg.startswith("[x] enrollment refused: decoy limit reached (Community Edition: 3)"), msg)
            self.assertFalse(os.path.exists(os.path.join(d, "sensor.json")))


if __name__ == "__main__":
    unittest.main()
