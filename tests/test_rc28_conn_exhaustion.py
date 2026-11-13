"""RC-28 / pentest F-02: connection exhaustion must not kill decoy listeners silently.

  * every accept loop survives Thread.start() failures (pids limit) and keeps serving;
  * one decoy-wide connection budget (global / per source IP / thread ceiling) shared by serve_tcp, SMB and
    HTTP, with a rate-limited level-3 `conn.flood` event per source;
  * SMB idles out after IDLE_UNAUTH s until a named user has logged on;
  * a self-check finds a dead / unbound listener, emits sensor.service_down, restarts it, emits service_up;
  * the manager raises an L4 "service down - possible DoS" decoy incident and shows per-service health.

Bounded: no real floods. Thread exhaustion is simulated by monkeypatching Thread.start, caps are tiny.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.sensor import base  # noqa: E402


class Rec:
    """Ctx stand-in: records emitted events."""

    def __init__(self):
        self.events, self.lock = [], threading.Lock()

    def emit(self, type_, src=None, dst_port=None, proto=None, session=None, **data):
        with self.lock:
            self.events.append(dict(data, type=type_, src=src, dst_port=dst_port, proto=proto))

    def of(self, t):
        with self.lock:
            return [e for e in self.events if e["type"] == t]


def connect(port, timeout=2.0):
    c = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return c


def refused(c, wait=3.0):
    """True when the server closed this connection (refused by a cap). An admitted idle client gets no data,
    so the wait only runs out (= False) for admitted ones; generous so a loaded box cannot fake a pass/fail."""
    c.settimeout(wait)
    try:
        return c.recv(1) == b""
    except socket.timeout:
        return False
    except OSError:                     # ECONNRESET: closed with unread data
        return True


def wait_for(cond, secs=8.0):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


class _Fresh(unittest.TestCase):
    """Own budget, registry and rate limiters per test (module globals otherwise leak between tests)."""
    budget = dict(total=50, per_ip=20, threads=10000)

    def setUp(self):
        self.ctx = Rec()
        self.b = base.ConnBudget(**self.budget)
        self.reg = base.Registry()
        self._p = [mock.patch.object(base, "BUDGET", self.b), mock.patch.object(base, "REGISTRY", self.reg),
                   mock.patch.object(base, "_FLOOD", base.FloodLog(60)), mock.patch.object(base, "_THREAD_FAIL", base._Every(60))]
        for p in self._p:
            p.start()
        self.socks = []

    def tearDown(self):
        for c in self.socks:
            c.close()
        for li in self.reg.items:
            base._shut(li.sock)
        for p in reversed(self._p):
            p.stop()

    def c(self, port):
        s = connect(port)
        self.socks.append(s)
        return s


def failing_start(match, n):
    """Thread.start replacement: the first n starts of threads whose name contains `match` raise like a
    container at its pids limit; everything else starts normally."""
    real = threading.Thread.start
    left = [n]

    def start(self):
        if match in self.name and left[0] > 0:
            left[0] -= 1
            raise RuntimeError("can't start new thread")
        return real(self)
    return start


class TestThreadExhaustion(_Fresh):
    def test_accept_loop_survives_thread_start_failure(self):
        """F-02 root cause: RuntimeError from Thread.start() ended the accept loop → port dead for good."""
        s = base.serve_tcp(self.ctx, 0, lambda c, a, sess: c.sendall(b"ok"), "rdp", host="127.0.0.1")
        port = s.getsockname()[1]
        with mock.patch.object(threading.Thread, "start", failing_start("guarded", 3)):
            for _ in range(3):
                self.assertTrue(refused(self.c(port), wait=3))      # dropped, never left hanging
            c = self.c(port)
            c.settimeout(3)
            self.assertEqual(c.recv(2), b"ok")                      # the 4th client is served
        li = self.reg.items[0]
        self.assertIsNone(li.problem())
        self.assertTrue(wait_for(lambda: self.b.n == 0))             # budget given back for every client
        err = self.ctx.of("sensor.error")
        self.assertEqual(len(err), 1)                                # rate-limited report
        self.assertIn("cannot start client thread", err[0]["error"])

    def test_socketserver_survives_thread_start_failure(self):
        """SMB / HTTP path (socketserver): the client is dropped, the budget released, the server keeps going."""
        import socketserver

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"ok")

        class S(socketserver.ThreadingTCPServer):
            daemon_threads, allow_reuse_address = True, True
        srv = S(("127.0.0.1", 0), H)
        base.serve_socketserver(self.ctx, srv, srv.server_address[1], "smb")
        port = srv.server_address[1]
        try:
            with mock.patch.object(threading.Thread, "start", failing_start("process_request_thread", 2)):
                self.assertTrue(refused(self.c(port), wait=3))
                self.assertTrue(refused(self.c(port), wait=3))
                c = self.c(port)
                c.settimeout(3)
                self.assertEqual(c.recv(2), b"ok")
            self.assertTrue(wait_for(lambda: self.b.n == 0))
            self.assertIsNone(self.reg.items[0].problem())
        finally:
            srv.shutdown()
            srv.server_close()


class TestBudget(_Fresh):
    budget = dict(total=3, per_ip=2, threads=10000)

    def test_per_ip_cap_and_flood_event(self):
        s = base.serve_tcp(self.ctx, 0, lambda c, a, sess: c.recv(10), "rdp", host="127.0.0.1")
        port = s.getsockname()[1]
        held = [self.c(port), self.c(port)]
        self.assertTrue(wait_for(lambda: self.b.n == 2))
        for _ in range(5):
            self.assertTrue(refused(self.c(port)))
        fl = self.ctx.of("conn.flood")
        self.assertEqual(len(fl), 1)                                  # one event per source per window
        self.assertEqual((fl[0]["reason"], fl[0]["limit"], fl[0]["src"][0]), ("per_ip", 2, "127.0.0.1"))
        held[0].close()
        self.assertTrue(wait_for(lambda: self.b.n == 1))
        self.assertFalse(refused(self.c(port), wait=0.5))             # a slot freed → admitted again

    def test_global_budget_is_shared_by_all_listeners(self):
        a = base.serve_tcp(self.ctx, 0, lambda c, x, sess: c.recv(10), "ldap", host="127.0.0.1").getsockname()[1]
        b = base.serve_tcp(self.ctx, 0, lambda c, x, sess: c.recv(10), "rdp", host="127.0.0.1").getsockname()[1]
        self.b.ips.limit = 10
        self.c(a), self.c(a), self.c(b)
        self.assertTrue(wait_for(lambda: self.b.n == 3))
        self.assertTrue(refused(self.c(b)), (self.b.n, self.ctx.events))
        self.assertEqual(self.ctx.of("conn.flood")[0]["reason"], "global")

    def test_thread_ceiling(self):
        b = base.ConnBudget(total=100, per_ip=100, threads=threading.active_count())
        self.assertEqual(b.take("10.0.0.1"), "threads")
        b.threads += 50
        self.assertIsNone(b.take("10.0.0.1"))
        b.give("10.0.0.1")
        self.assertEqual((b.n, b.ips.n), (0, {}))

    def test_defaults_fit_the_container(self):
        """Caps stay well below the decoy container's pids_limit (rpotctl compose: 384)."""
        import re
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rpotctl.py")).read()
        pids = int(re.search(r'"    mem_limit: 192m", "    pids_limit: (\d+)"', src).group(1))
        self.assertLessEqual(base.MAX_CONN + 64, pids)
        self.assertLessEqual(base.THREAD_CEILING + 32, pids)
        self.assertEqual(base.MAX_PER_IP, 20)
        self.assertEqual(base.IDLE_UNAUTH, 60)

    def test_pids_max_reader(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "pids.max")
            with open(p, "w") as f:
                f.write("384\n")
            self.assertEqual(base._pids_max(p), 384)
            with open(p, "w") as f:
                f.write("max\n")
            self.assertIsNone(base._pids_max(p))
        self.assertIsNone(base._pids_max(os.path.join(d, "gone")))

    def test_every_limiter(self):
        e = base._Every(60, max_keys=3)
        self.assertEqual(e.hit("a"), 1)
        self.assertIsNone(e.hit("a"))
        self.assertIsNone(e.hit("a"))
        e.last["a"] -= 61
        self.assertEqual(e.hit("a"), 3)                               # suppressed hits are counted
        for k in "bcdefg":
            e.hit(k)
        self.assertLessEqual(len(e.last), 3)                          # bounded


class TestSMBCaps(_Fresh):
    budget = dict(total=10, per_ip=2, threads=10000)

    @classmethod
    def setUpClass(cls):
        from test_sensor_services import B, ctx_for
        cls.tmp = tempfile.TemporaryDirectory()
        co = B.make_persona("corp.ararat.am", "bank", seed=5)
        co["token_salt"] = "s4lt"
        cls.co = co
        sensors = [{"name": "FS01", "role": "windows-file-server", "ip": "10.9.0.20"}]
        cls.tokens = B.generate({"company": co, "console": {}, "sensors": sensors}, os.path.join(cls.tmp.name, "baits"))
        cls.sctx, cls.em = ctx_for(cls.tmp.name, cls.tokens, co, sensors, "FS01", "windows-file-server")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def start(self):
        from rpot.sensor.services.smb import start_smb
        from test_dc_dns import free_port
        port = free_port()
        svc = next(x for x in self.sctx.role["services"] if x["type"] == "smb")
        s = start_smb(self.sctx, dict(svc, port=port))
        self.addCleanup(lambda: (s.getServer().shutdown(), s.getServer().server_close()))
        time.sleep(0.2)
        return port

    def test_smb_respects_caps_and_still_serves(self):
        with mock.patch.object(base, "bind_ip", return_value="127.0.0.1"):
            port = self.start()
        self.assertEqual(len(self.reg.items), 1)                      # registered for the self-check
        held = [self.c(port), self.c(port)]                           # idle SMB clients (the F-02 pattern)
        self.assertTrue(wait_for(lambda: self.b.n == 2))
        self.assertTrue(refused(self.c(port)))                        # 3rd from the same source: refused
        self.assertTrue(any(e["type"] == "conn.flood" and e.get("reason") == "per_ip" for e in self.em.events))
        for h in held:
            h.close()
        self.assertTrue(wait_for(lambda: self.b.n == 0))
        from impacket.smbconnection import SMBConnection                # a real client works again
        c = SMBConnection("FS01", "127.0.0.1", sess_port=port, timeout=5)
        # RC-27 F-04: a null session may not enumerate shares (Server 2019) - log on with a bait credential
        t = next(t for t in self.tokens.values()
                 if t["kind"] == "credential" and "FS01:smb" in (t.get("valid_on") or []))
        c.login(t["username"], t["password"], self.co["netbios"])
        self.assertIn("Public", {x["shi1_netname"][:-1] for x in c.listShares()})
        c.close()

    def test_unauthenticated_idle_limit(self):
        with mock.patch.object(base, "bind_ip", return_value="127.0.0.1"), mock.patch.object(base, "IDLE_UNAUTH", 1):
            port = self.start()
            c = self.c(port)
            c.settimeout(5)
            t = time.monotonic()
            try:
                self.assertEqual(c.recv(1), b"")                      # the decoy hangs up an idle socket
            except ConnectionResetError:
                pass
            self.assertLess(time.monotonic() - t, 4.5)
            self.assertTrue(wait_for(lambda: self.b.n == 0))

    def test_named_logon_gets_the_longer_idle_limit(self):
        with mock.patch.object(base, "bind_ip", return_value="127.0.0.1"):
            self.start()
        from impacket.smbserver import SMBSERVERHandler
        server = mock.Mock()
        h = object.__new__([c for c in SMBSERVERHandler.__subclasses__() if c.__name__ == "Capped"][-1])
        h.server, h._SMBSERVERHandler__connId = server, "Thread-1"
        server.getConnectionData.return_value = {"Authenticated": True, "user_name": ""}      # null session
        self.assertEqual(h._SMBSERVERHandler__timeOut, base.IDLE_UNAUTH)
        server.getConnectionData.return_value = {"Authenticated": True, "user_name": "j.doe"}
        self.assertEqual(h._SMBSERVERHandler__timeOut, 300)
        server.getConnectionData.side_effect = KeyError("gone")
        self.assertEqual(h._SMBSERVERHandler__timeOut, base.IDLE_UNAUTH)
        h._SMBSERVERHandler__timeOut = 5                                 # impacket's __init__ assignment is ignored
        self.assertEqual(h._SMBSERVERHandler__timeOut, base.IDLE_UNAUTH)


class TestSelfCheck(_Fresh):
    def test_detects_closed_listener_reports_and_restarts(self):
        self.reg.current = "rdp/3389"
        s = base.serve_tcp(self.ctx, 0, lambda c, a, sess: c.sendall(b"ok"), "rdp", host="127.0.0.1")
        self.reg.current = None
        port = s.getsockname()[1]
        li = self.reg.items[0]
        self.assertEqual(li.service, "rdp/3389")
        self.assertEqual([w for _, w in self.reg.check(self.ctx)], [None])
        self.assertEqual(self.ctx.of("sensor.service_down"), [])
        base._shut(li.sock)                                          # the listener dies (F-02: thread + socket gone)
        self.assertTrue(wait_for(lambda: not li.thread.is_alive()))
        self.assertIsNotNone(li.problem())
        res = self.reg.check(self.ctx)
        self.assertEqual([w for _, w in res], [None])                 # restarted in the same pass
        down, up = self.ctx.of("sensor.service_down"), self.ctx.of("sensor.service_up")
        self.assertEqual(len(down), 1)
        self.assertEqual((down[0]["service"], down[0]["dst_port"], down[0]["proto"]), ("rdp/3389", port, "rdp"))
        self.assertEqual((len(up), up[0]["restarted"]), (1, True))
        c = self.c(port)                                              # same port, serving again
        c.settimeout(3)
        self.assertEqual(c.recv(2), b"ok")

    def test_dead_thread_with_bound_socket(self):
        """The exact pentest state: socket still bound (backlog fills) but no thread accepting."""
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(5)
        dead = threading.Thread(target=lambda: None)
        dead.start()
        dead.join()
        calls = []

        def start():
            if not calls:
                calls.append(1)
                return s, dead
            n = socket.socket()
            n.listen(1)
            t = threading.Thread(target=time.sleep, args=(5,), daemon=True)
            t.start()
            return n, t
        li = self.reg.add(base.Listener("tcp", 3389, "rdp", start, service="rdp/3389"))
        self.assertEqual(li.problem(), "serving thread stopped")
        self.reg.check(self.ctx)
        self.assertEqual(self.ctx.of("sensor.service_down")[0]["reason"], "serving thread stopped")
        self.assertIsNone(li.problem())
        self.assertEqual(s.fileno(), -1)                              # the stale socket was released

    def test_restart_failure_reported_once_and_retried(self):
        s = base.serve_udp(self.ctx, 0, lambda d, a: None, "ntp", host="127.0.0.1")
        li = self.reg.items[0]
        self.assertEqual(li.label, f"ntp/udp:{s.getsockname()[1]}")
        good = li._start
        li._start = mock.Mock(side_effect=OSError(98, "Address already in use"))
        base._shut(li.sock)
        self.assertTrue(wait_for(lambda: not li.thread.is_alive()))
        self.assertIsNotNone(self.reg.check(self.ctx)[0][1])
        self.assertIsNotNone(self.reg.check(self.ctx)[0][1])
        self.assertEqual(len(self.ctx.of("sensor.service_down")), 1)  # one edge, not one per pass
        self.assertIn("Address already in use", li.last_error)
        li._start = good
        self.assertIsNone(self.reg.check(self.ctx)[0][1])
        self.assertEqual(len(self.ctx.of("sensor.service_up")), 1)

    def test_watchdog_thread_survives_errors(self):
        stop = threading.Event()
        n = []
        with mock.patch.object(self.reg, "check", side_effect=lambda ctx: n.append(1) or 1 / 0):
            t = self.reg.start(self.ctx, every=0.02, stop=stop)
            self.assertTrue(wait_for(lambda: len(n) >= 3))
            self.assertTrue(t.is_alive())
        stop.set()
        t.join(2)
        self.assertFalse(t.is_alive())


class TestEngineHealth(unittest.TestCase):
    def setUp(self):
        from test_unit import mkcfg
        from rpot.console.engine import Engine
        self._td = tempfile.TemporaryDirectory()
        self.eng = Engine(mkcfg(self._td.name), os.path.join(self._td.name, "x.db"))

    def tearDown(self):
        self.eng.db.close()
        self._td.cleanup()

    def ev(self, type_, src=None, port=None, proto=None, **data):
        from rpot.common.events import now_iso
        return {"ts": now_iso(), "sensor": "FS01", "role": "windows-file-server", "sensor_ip": "172.30.0.21",
                "src_ip": src, "src_port": 40000 if src else None, "dst_port": port, "proto": proto, "type": type_,
                "session": None, "data": data}

    def sensor(self):
        return next(s for s in self.eng.sensors() if s["name"] == "FS01")

    def incident(self):
        return self.eng.db.execute("SELECT * FROM incidents WHERE subject='sensor:FS01'").fetchone()

    def test_service_down_incident_health_and_recovery(self):
        e = self.eng
        e.ingest([self.ev("sensor.start", services=["msrpc/135", "smb/445", "rdp/3389"])])
        self.assertEqual(self.sensor()["services_down"], [])
        e.ingest([self.ev("sensor.service_down", port=3389, proto="rdp", service="rdp/3389", listener="rdp/3389",
                          reason="serving thread stopped")])
        inc = self.incident()
        self.assertEqual(inc["level"], 4)
        self.assertIn("rdp/3389 down - possible DoS", inc["title"])
        self.assertIn("serving thread stopped", inc["note"])
        recs = [json.loads(r[0]) for r in e.db.execute("SELECT record FROM alert_records")]
        self.assertEqual([(r["alert"]["type"], r["level"]) for r in recs], [("sensor.service_down", 4)])
        s = self.sensor()
        self.assertTrue(s["online"])
        self.assertEqual(s["services_down"], ["rdp/3389"])
        sh = {x["service"]: x for x in s["service_health"]}
        self.assertEqual((sh["rdp/3389"]["status"], sh["smb/445"]["status"]), ("down", "ok"))
        self.assertEqual(sh["rdp/3389"]["reason"], "serving thread stopped")

        e.ingest([self.ev("sensor.service_up", port=3389, proto="rdp", service="rdp/3389", listener="rdp/3389",
                          restarted=True, was="serving thread stopped")])
        self.assertEqual(self.sensor()["services_down"], [])
        self.assertIn("serving again (restarted by the decoy self-check)", self.incident()["note"])

        # a second outage soon after: noted on the same incident, no alert storm
        e.ingest([self.ev("sensor.service_down", port=445, proto="smb", service="smb/445", listener="smb/445",
                          reason="socket not listening")])
        self.assertEqual(e.db.execute("SELECT COUNT(*) FROM alert_records").fetchone()[0], 1)
        self.assertEqual(e.db.execute("SELECT COUNT(*) FROM incidents WHERE subject='sensor:FS01'").fetchone()[0], 1)
        self.assertIn("smb/445", self.incident()["title"])
        self.assertEqual(self.sensor()["services_down"], ["smb/445"])

        e.ingest([self.ev("sensor.start", services=["msrpc/135", "smb/445", "rdp/3389"])])   # process restarted
        self.assertEqual(self.sensor()["services_down"], [])

    def test_health_map_is_bounded_and_tolerates_junk(self):
        from rpot.console import engine as E
        evs = [self.ev("sensor.service_down", port=i, proto="x", service=f"x/{i}", listener=f"x/{i}")
               for i in range(E.HEALTH_MAX + 10)]
        evs.append(self.ev("sensor.service_down", port="junk", proto=None, service={"a": 1}, listener=[1]))
        self.eng.ingest(evs)
        self.assertLessEqual(len(self.sensor()["health"]), E.HEALTH_MAX)
        self.eng.db.execute("UPDATE sensors SET health='not json' WHERE name='FS01'")
        self.assertEqual(self.sensor()["health"], {})

    def test_conn_flood_is_a_level_3_attack_event(self):
        from rpot.console import scoring
        ev = self.ev("conn.flood", src="172.30.0.66", port=445, proto="smb", reason="per_ip", limit=20, refused=37)
        self.assertEqual(scoring.score(ev), 3)
        self.assertIn("37 connection(s) refused (per-source cap 20)", scoring.describe(ev))
        self.eng.ingest([ev])
        inc = self.eng.db.execute("SELECT level, title FROM incidents WHERE src_ip='172.30.0.66'").fetchone()
        self.assertEqual(inc["level"], 3)
        self.assertIn("Connection flood", inc["title"])


class TestApiSensorsHealth(unittest.TestCase):
    def test_api_sensors_shows_per_service_health(self):
        from test_unit import mkcfg, FS
        from rpot.console.app import create_app, create_sensor_app
        from rpot.common.events import now_iso
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp)
            cfg["sensors"] = cfg["sensors"][:2]
            app = create_app(cfg, os.path.join(tmp, "a.db"))
            s = create_sensor_app(app.engine).test_client()
            base_ev = {"sensor": "FS01", "role": "windows-file-server", "sensor_ip": "172.30.0.21", "src_ip": None}
            s.post("/api/ingest", json={"events": [
                dict(base_ev, ts=now_iso(), type="sensor.start", data={"services": ["smb/445", "rdp/3389"]}),
                dict(base_ev, ts=now_iso(), type="sensor.service_down", dst_port=3389, proto="rdp",
                     data={"service": "rdp/3389", "listener": "rdp/3389", "reason": "serving thread stopped"})]},
                headers=FS)
            c = app.test_client()
            c.post("/login", data={"token": "at"})
            fs = next(x for x in c.get("/api/sensors").get_json() if x["name"] == "FS01")
            self.assertEqual(fs["services_down"], ["rdp/3389"])
            self.assertEqual([x["status"] for x in fs["service_health"]], ["ok", "down"])


if __name__ == "__main__":
    unittest.main()
