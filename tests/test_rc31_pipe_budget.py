"""RC-31 / pentest round 2 N-3: SMB named pipes (and SSH channels) must not bypass the connection budget.

N-3: one anonymous SMB connection opened \\wkssvc 330x; every open started a pipe thread (300 s) not charged to the
budget, the decoy hit THREAD_CEILING and refused every new client from every source. Now:
  * pipes run without a thread (each RPC request answered in the SMB handler thread);
  * every open pipe holds a budget slot: 8 per SMB connection, 16 per source IP, decoy-wide cap, and none inside the
    thread headroom; a refused open gets STATUS_INSUFFICIENT_RESOURCES and the session stays usable;
  * pipe slots are freed on CLOSE, TCP drop and after the idle limit (60 s null session / 300 s named logon);
  * a source hitting its own pipe cap raises `smb.pipe_flood` (level 4 -> incident; SSH: `resource.exhaustion`);
  * threat-hunt C1: a decoy-wide cap (threads / global) is a decoy-health incident naming the top holders, with an
    alert line; C3: flood events carry the total refused since the flood started, summarised within 60 s.
  * SSH: at most 10 channels per connection (OpenSSH MaxSessions), charged the same way.

Bounded: the flood replays tools/pipeflood.py in-process on 127.0.0.1 with small caps (tens of opens).
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
from test_rc28_conn_exhaustion import wait_for  # noqa: E402

PIPE = dict(desiredAccess=0x12019f, shareMode=3, creationOption=0x40, creationDisposition=1, fileAttributes=0x80)


def lab_persona(names):
    from test_sensor_services import B
    co = B.make_persona("corp.ararat.am", "bank", seed=5)
    co["token_salt"] = "s4lt"
    roles = {"FS01": "windows-file-server", "BKP01": "ftp-backup-server"}
    sensors = [{"name": n, "role": roles[n], "ip": f"10.9.0.{20 + i}"} for i, n in enumerate(names)]
    return co, sensors


class _Budgeted(unittest.TestCase):
    """Own small budget + rate limiters per test."""
    budget = dict(total=50, per_ip=20, threads=10000, aux_total=40, aux_per_ip=16)

    def setUp(self):
        self.b = base.ConnBudget(**self.budget)
        self._p = [mock.patch.object(base, "BUDGET", self.b), mock.patch.object(base, "REGISTRY", base.Registry()),
                   mock.patch.object(base, "_FLOOD", base.FloodLog(60)), mock.patch.object(base, "_EXHAUST", base.FloodLog(60)),
                   mock.patch.object(base, "bind_ip", return_value="127.0.0.1")]
        for p in self._p:
            p.start()

    def tearDown(self):
        for p in reversed(self._p):
            p.stop()


class TestAuxBudget(unittest.TestCase):
    def test_per_ip_global_and_release(self):
        b = base.ConnBudget(total=10, per_ip=10, threads=10000, aux_total=5, aux_per_ip=3)
        self.assertEqual([b.take_aux("10.0.0.1", "p") for _ in range(4)], [None, None, None, "per_ip"])
        self.assertEqual([b.take_aux("10.0.0.2", "p") for _ in range(3)], [None, None, "global"])
        self.assertIsNone(b.take_aux("10.0.0.2", "other-kind"))     # caps are per kind
        self.assertEqual(b.top_aux("p"), ("10.0.0.1", 3))
        for _ in range(3):
            b.give_aux("10.0.0.1", "p")
        self.assertIsNone(b.take_aux("10.0.0.3", "p"))
        self.assertEqual(b.aux_limit("per_ip"), 3)
        self.assertEqual(b.n, 0)                                      # connection slots untouched

    def test_thread_headroom_refuses_extras_before_clients(self):
        """Near the ceiling the pipe/channel is refused - a new TCP client still gets in."""
        now = threading.active_count()
        b = base.ConnBudget(total=10, per_ip=10, threads=now + 5, headroom=10)
        self.assertEqual(b.take_aux("10.0.0.1", "p"), "threads")
        self.assertIsNone(b.take("10.0.0.9"))

    def test_defaults(self):
        self.assertEqual((base.MAX_AUX_PER_IP, base.MAX_AUX, base.AUX_HEADROOM), (16, 128, 32))
        from rpot.sensor.services import smb, ssh
        self.assertEqual((smb.PIPES_PER_SESSION, smb.PIPE_IDLE_ANON, smb.PIPE_IDLE_NAMED), (8, 60, 300))
        self.assertEqual(ssh.MAX_CHANNELS, 10)

    def test_decoy_wide_cap_blames_the_source_holding_its_slots(self):
        class Ctx:
            def __init__(s):
                s.events = []

            def emit(s, t, src=None, *a, **k):
                s.events.append(dict(k, type=t, src=src))
        ctx, b = Ctx(), base.ConnBudget(total=3, per_ip=3, threads=10000)
        with mock.patch.object(base, "_FLOOD", base.FloodLog(60)), mock.patch.object(base, "_EXHAUST", base.FloodLog(60)):
            for _ in range(3):
                self.assertTrue(base.admit(ctx, socket.socket(), ("10.6.6.6", 1), 445, "smb", b))
            victim = socket.socket()
            self.assertFalse(base.admit(ctx, victim, ("10.1.1.1", 2), 445, "smb", b))
        self.assertEqual(victim.fileno(), -1)                         # refused client closed
        fl = [e for e in ctx.events if e["type"] == "conn.flood"]
        ex = [e for e in ctx.events if e["type"] == "resource.exhaustion"]
        self.assertEqual(fl[0]["src"][0], "10.1.1.1")                 # the refused one ...
        self.assertEqual(fl[0]["top_sources"], [{"ip": "10.6.6.6", "conns": 3}])   # ... names the holder
        self.assertEqual((ex[0]["src"][0], ex[0]["resource"], ex[0]["cap"]), ("10.6.6.6", "connections", "global"))


class TestFloodAccounting(unittest.TestCase):
    """C3: one report at once, then cumulative totals, and flush() reports what is pending (<= 60 s)."""

    def test_totals_and_flush(self):
        got, clock = [], [1000.0]
        f = base.FloodLog(60)
        emit = lambda **n: got.append(n)
        with mock.patch.object(base.time, "monotonic", lambda: clock[0]):
            for _ in range(5):
                f.hit("k", emit)
            self.assertEqual([g["refused"] for g in got], [1])         # first refusal reported at once
            clock[0] += 20
            self.assertEqual(f.flush(), 0)                             # < every/2 since the last report
            clock[0] += 15
            self.assertEqual(f.flush(), 1)                             # 35 s: pending summary
            self.assertEqual((got[-1]["refused"], got[-1]["new"], got[-1]["duration_s"]), (5, 4, 35.0))
            f.hit("k", emit)
            clock[0] += 61
            f.hit("k", emit)                                           # >= every since the last report: at once
            self.assertEqual((got[-1]["refused"], got[-1]["new"]), (7, 2))
            clock[0] += 200
            self.assertEqual(f.flush(), 0)                             # quiet flood forgotten ...
            f.hit("k", emit)
            self.assertEqual(got[-1]["refused"], 1)                    # ... a new one starts from 1


class TestSMBPipeFlood(_Budgeted):
    @classmethod
    def setUpClass(cls):
        from test_sensor_services import B, ctx_for
        cls.tmp = tempfile.TemporaryDirectory()
        cls.co, sensors = lab_persona(["FS01"])
        cls.tokens = B.generate({"company": cls.co, "console": {}, "sensors": sensors}, os.path.join(cls.tmp.name, "baits"))
        cls.ctx, cls.em = ctx_for(cls.tmp.name, cls.tokens, cls.co, sensors, "FS01", "windows-file-server")
        cls.cred = next(t for t in cls.tokens.values()
                        if t["kind"] == "credential" and "FS01:smb" in (t.get("valid_on") or []))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        super().setUp()
        from rpot.sensor.services.smb import start_smb
        from test_dc_dns import free_port
        self.em.events.clear()
        self.port = free_port()
        svc = next(x for x in self.ctx.role["services"] if x["type"] == "smb")
        s = start_smb(self.ctx, dict(svc, port=self.port))
        self.addCleanup(lambda: (s.getServer().shutdown(), s.getServer().server_close()))
        self.conns = []
        self.addCleanup(lambda: [c.close() for c in self.conns])

    def client(self, named=False):
        from impacket.smbconnection import SMBConnection
        c = SMBConnection("FS01", "127.0.0.1", sess_port=self.port, timeout=5)
        if named:
            c.login(self.cred["username"], self.cred["password"], self.co["netbios"])
        else:
            c.login("", "")
        self.conns.append(c)
        return c

    def flood(self, c, n, pipe="\\wkssvc"):
        """pipeflood.py: open the pipe n times on one connection -> (fids, error codes of refused opens)."""
        from impacket.smbconnection import SessionError
        tid, fids, errs = c.connectTree("IPC$"), [], []
        for _ in range(n):
            try:
                fids.append(c.openFile(tid, pipe, **PIPE))
            except SessionError as e:
                errs.append(e.getErrorCode())
        return tid, fids, errs

    def pipes(self):
        return self.b.aux_n.get("smb-pipe", 0)

    def test_pipe_flood_is_capped_and_others_still_served(self):
        from impacket.nt_errors import STATUS_INSUFFICIENT_RESOURCES
        threads = threading.active_count()
        c = self.client()
        tid, fids, errs = self.flood(c, 30)
        self.assertEqual(len(fids), 8)                                 # PIPES_PER_SESSION
        self.assertEqual(set(errs), {STATUS_INSUFFICIENT_RESOURCES})
        self.assertEqual(self.pipes(), 8)
        self.assertLessEqual(threading.active_count(), threads + 2)    # no thread per pipe
        c.getSMBServer().echo()                                        # the flooding session itself still works
        other = self.client(named=True)                                # another client: served
        self.assertIn("Public", {x["shi1_netname"][:-1] for x in other.listShares()})
        ex = self.em.of("smb.pipe_flood")
        self.assertEqual(len(ex), 1)                                   # first refusal at once, the rest summarised
        self.assertEqual((ex[0]["resource"], ex[0]["cap"], ex[0]["limit"], ex[0]["proto"], ex[0]["pipes"]),
                         ("smb_pipe", "per_session", 8, "smb", 8))
        self.assertEqual(ex[0]["src"][0], "127.0.0.1")
        base._EXHAUST.flush(time.monotonic() + 31)                     # self-check pass: summary with the total
        ex = self.em.of("smb.pipe_flood")
        self.assertEqual((len(ex), ex[-1]["refused"], ex[-1]["new"]), (2, 22, 21))
        n = self.pipes()                                               # 8 + the share listing's srvsvc
        c.closeFile(tid, fids[0])                                      # CLOSE frees the slot
        self.assertEqual(self.pipes(), n - 1)
        c.openFile(tid, "\\wkssvc", **PIPE)
        self.assertEqual(self.pipes(), n)

    def test_per_ip_cap_across_connections_and_tcp_drop_frees_all(self):
        got = [len(self.flood(self.client(), 8)[1]) for _ in range(3)]
        self.assertEqual(got, [8, 8, 0])                               # MAX_AUX_PER_IP 16 for one source
        self.assertEqual(self.pipes(), 16)
        self.assertEqual({e["cap"] for e in self.em.of("smb.pipe_flood")}, {"per_ip"})
        for c in self.conns:
            c.getSMBServer().get_socket().close()                      # TCP drop without closing the pipes
        self.assertTrue(wait_for(lambda: self.pipes() == 0 and self.b.n == 0))

    def test_pipe_rpc_still_works_and_survives_garbage(self):
        from impacket.dcerpc.v5 import transport, wkst
        c = self.client(named=True)
        t = transport.SMBTransport("127.0.0.1", filename=r"\wkssvc", smb_connection=c)
        d = t.get_dce_rpc()
        d.connect()
        d.bind(wkst.MSRPC_UUID_WKST)
        for _ in range(3):                                             # several requests on one pipe
            r = wkst.hNetrWkstaGetInfo(d, 100)
            self.assertEqual(r["WkstaInfo"]["WkstaInfo100"]["wki100_platform_id"], 500)
        d.disconnect()
        tid = c.connectTree("IPC$")
        fid = c.openFile(tid, "\\wkssvc", **PIPE)
        bad = b"\x05\x00\x0b\x03\x10\x00\x00\x00" + b"\x08\x00" + b"\x00" * 6   # frag_len 8: malformed
        try:
            c.writeFile(tid, fid, bad)
        except Exception:
            pass
        self.assertIn("Public", {x["shi1_netname"][:-1] for x in c.listShares()})   # session unaffected

    def test_idle_pipe_is_closed_and_slot_freed(self):
        """No sleeps: the sweep is run with a clock 61 s ahead (anonymous pipes idle out after 60 s)."""
        from rpot.sensor.services import smb
        c = self.client()
        self.flood(c, 8)
        self.assertEqual(self.pipes(), 8)
        with mock.patch.object(smb.time, "monotonic", lambda real=time.monotonic: real() + 61):
            _, fids, errs = self.flood(self.client(), 1)               # the next open sweeps idle pipes
        self.assertEqual((len(fids), errs), (1, []))
        self.assertEqual(self.pipes(), 1)
        _, fids, _ = self.flood(c, 8)                                  # c's handles were closed by the sweep
        self.assertEqual(len(fids), 8)

    def test_pipe_refused_near_ceiling_new_client_admitted(self):
        """Inside the thread headroom the pipe open is refused, not the next TCP client."""
        from impacket.nt_errors import STATUS_INSUFFICIENT_RESOURCES
        c = self.client()
        self.b.threads, self.b.headroom = threading.active_count() + 4, 8   # inside the headroom, below the ceiling
        _, fids, errs = self.flood(c, 2)
        self.assertEqual((fids, errs), ([], [STATUS_INSUFFICIENT_RESOURCES] * 2))
        self.client(named=True)                                        # a new client is still admitted
        self.assertEqual(self.em.of("smb.pipe_flood"), [])             # decoy-wide cap and nobody holds pipes

    def test_named_logon_gets_the_longer_pipe_idle(self):
        from rpot.sensor.services import smb
        self.flood(self.client(named=True), 2)
        self.flood(self.client(), 2)
        smb._sweep(time.monotonic() + 61)
        self.assertEqual(self.pipes(), 2)                              # named-logon pipes kept (300 s)
        smb._sweep(time.monotonic() + 301)
        self.assertEqual(self.pipes(), 0)

class TestSSHChannelCap(_Budgeted):
    @classmethod
    def setUpClass(cls):
        from test_sensor_services import B, ctx_for
        cls.tmp = tempfile.TemporaryDirectory()
        co, sensors = lab_persona(["BKP01"])
        tokens = B.generate({"company": co, "console": {}, "sensors": sensors}, os.path.join(cls.tmp.name, "baits"))
        cls.ctx, cls.em = ctx_for(cls.tmp.name, tokens, co, sensors, "BKP01", "ftp-backup-server")
        cls.cred = next(t for t in tokens.values()
                        if t["kind"] == "credential" and "BKP01:ssh" in (t.get("valid_on") or []))
        from rpot.sensor.services.ssh import _host_keys
        _host_keys(cls.ctx)                                            # generate the host keys once, up front

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_channel_cap_per_connection(self):
        import paramiko
        from rpot.sensor.services.ssh import start_ssh
        from test_dc_dns import free_port
        self.em.events.clear()
        port = free_port()
        start_ssh(self.ctx, {"type": "ssh", "port": port})
        threads = threading.active_count()
        t = paramiko.Transport(socket.create_connection(("127.0.0.1", port), timeout=5))
        try:
            t.start_client(timeout=10)
            t.auth_password(self.cred["username"], self.cred["password"])
            chans, failed = [], 0
            for _ in range(13):
                try:
                    chans.append(t.open_session(timeout=5))
                except paramiko.ChannelException as e:
                    failed += 1
                    self.assertEqual(e.code, paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)
            self.assertEqual((len(chans), failed), (10, 3))
            self.assertTrue(wait_for(lambda: self.b.aux_n.get("ssh-channel") == 10))
            self.assertLessEqual(threading.active_count(), threads + 6 + 10)   # transport + handler + 10 channels (+ slack)
            ex = self.em.of("resource.exhaustion")
            self.assertEqual(len(ex), 1)
            self.assertEqual((ex[0]["resource"], ex[0]["cap"], ex[0]["limit"]), ("ssh_channel", "per_connection", 10))
            chans[0].exec_command("id")                                # channels still work
            chans[0].recv_exit_status()
            self.assertTrue(wait_for(lambda: self.b.aux_n.get("ssh-channel") == 9))
            chans.append(t.open_session(timeout=5))                    # a freed slot can be used again
        finally:
            t.close()
        self.assertTrue(wait_for(lambda: self.b.aux_n.get("ssh-channel", 0) == 0 and self.b.n == 0, secs=15))


class TestConsoleIncident(unittest.TestCase):
    def setUp(self):
        from rpot.console.engine import Engine
        from test_unit import mkcfg
        self._td = tempfile.TemporaryDirectory()
        self.eng = Engine(mkcfg(self._td.name), os.path.join(self._td.name, "x.db"))
        self.eng._rdns = lambda ip: None                               # no reverse DNS lookups from tests

    def tearDown(self):
        self.eng.db.close()
        self._td.cleanup()

    def ev(self, type_, src, **data):
        from rpot.common.events import now_iso
        return {"ts": now_iso(), "sensor": "FS01", "role": "windows-file-server", "sensor_ip": "172.30.0.21",
                "src_ip": src, "src_port": 40000, "dst_port": 445, "proto": "smb", "type": type_, "session": None,
                "data": data}

    def alerts(self):
        return [json.loads(r["record"]) for r in self.eng.db.execute("SELECT record FROM alert_records ORDER BY id")]

    def test_pipe_flood_is_an_l4_incident_with_alert(self):
        from rpot.console import scoring
        ev = self.ev("smb.pipe_flood", "192.168.56.10", resource="smb_pipe", cap="per_session", limit=8, refused=322)
        self.assertEqual(scoring.score(ev), 4)
        self.assertEqual(scoring.score(self.ev("resource.exhaustion", "192.168.56.10", resource="ssh_channel")), 4)
        self.assertEqual(scoring.describe(ev), "Decoy resource exhaustion attempt on FS01/smb: 322 SMB named-pipe "
                                               "opens refused (per-session cap 8)")
        self.eng.ingest([ev])
        row = self.eng.db.execute("SELECT * FROM incidents WHERE src_ip='192.168.56.10'").fetchone()
        self.assertEqual(row["level"], 4)
        self.assertTrue(row["title"].startswith("Decoy resource exhaustion attempt"))
        self.assertEqual([(a["alert"]["level"], a["event"]["type"]) for a in self.alerts()], [(4, "smb.pipe_flood")])

    def test_saturation_is_a_decoy_incident_naming_the_holder(self):
        """G1: the thread-ceiling refusal of an innocent client must not become that client's incident; the decoy
        gets an L4 'saturated' incident naming the holder, with an alert line."""
        top = [{"ip": "192.168.56.10", "conns": 1, "smb-pipe": 16}, {"ip": "10.0.0.7", "conns": 2}]
        self.eng.ingest([self.ev("conn.flood", "10.1.1.1", reason="threads", limit=320, refused=726, top_sources=top)])
        self.assertIsNone(self.eng.db.execute("SELECT * FROM incidents WHERE src_ip='10.1.1.1'").fetchone())
        inc = self.eng.db.execute("SELECT * FROM incidents WHERE subject='sensor:FS01'").fetchone()
        self.assertEqual(inc["level"], 4)
        self.assertIn("saturated", inc["title"])
        self.assertIn("192.168.56.10 (1 conns, 16 smb-pipe)", inc["title"])
        self.assertIn("726 client(s) refused", inc["note"])
        a = self.alerts()
        self.assertEqual(len(a), 1)
        self.assertEqual((a[0]["level"], a[0]["alert"]["type"], a[0]["alert"]["top_sources"][0]["ip"]),
                         (4, "decoy.saturated", "192.168.56.10"))
        self.eng.ingest([self.ev("conn.flood", "10.1.1.2", reason="global", limit=250, refused=800, top_sources=top)])
        self.assertEqual(len(self.alerts()), 1)                        # same decoy within the window: no repeat
        self.assertEqual(self.eng.db.execute("SELECT count(*) FROM incidents").fetchone()[0], 1)

    def test_saturation_raises_an_existing_lower_decoy_incident_with_alert(self):
        self.eng.db.execute("INSERT INTO incidents(src_ip, subject, first_ts, last_ts, level, title, sensors, count, "
                            "alerted_level) VALUES(NULL,'sensor:FS01','2026-11-13T10:00:00Z','2026-11-13T10:00:00Z',1,"
                            "'Decoy FS01: reporting again','[\"FS01\"]',1,1)")
        self.eng._svc_alerted[("FS01", "saturated")] = time.monotonic()   # even inside the rate-limit window
        self.eng.ingest([self.ev("conn.flood", "10.1.1.1", reason="threads", limit=320, refused=5,
                                 top_sources=[{"ip": "192.168.56.10", "conns": 20}])])
        inc = self.eng.db.execute("SELECT * FROM incidents WHERE subject='sensor:FS01'").fetchone()
        self.assertEqual((inc["level"], inc["alerted_level"]), (4, 4))
        self.assertEqual(len(self.alerts()), 1)                        # level rise -> alert line

    def test_per_ip_flood_stays_l3_on_the_source(self):
        self.eng.ingest([self.ev("conn.flood", "10.1.1.1", reason="per_ip", limit=20, refused=3)])
        row = self.eng.db.execute("SELECT * FROM incidents WHERE src_ip='10.1.1.1'").fetchone()
        self.assertEqual(row["level"], 3)


if __name__ == "__main__":
    unittest.main()


class TestSSHShellOutlivesAcceptWait(TestSSHChannelCap):
    """RC-34: an open interactive shell must not be closed when no NEW channel arrives within ACCEPT_WAIT."""

    def test_shell_survives_accept_wait(self):
        import paramiko
        from rpot.sensor.services import ssh
        from test_dc_dns import free_port
        old = ssh.ACCEPT_WAIT
        ssh.ACCEPT_WAIT = 1
        try:
            port = free_port()
            ssh.start_ssh(self.ctx, {"type": "ssh", "port": port})
            t = paramiko.Transport(socket.create_connection(("127.0.0.1", port), timeout=5))
            try:
                t.start_client(timeout=10)
                t.auth_password(self.cred["username"], self.cred["password"])
                ch = t.open_session(timeout=5)
                ch.get_pty()
                ch.invoke_shell()
                ch.settimeout(5)
                time.sleep(3)                                  # > ACCEPT_WAIT with no new channel
                ch.recv(65535)                                 # banner + prompt
                ch.send("whoami\n")
                out = b""
                end = time.time() + 5
                while time.time() < end and self.cred["username"].encode() not in out:
                    try:
                        out += ch.recv(4096)
                    except socket.timeout:
                        break
                self.assertTrue(t.is_active(), "transport closed while the shell was open")
                self.assertIn(self.cred["username"].encode(), out)
            finally:
                t.close()
        finally:
            ssh.ACCEPT_WAIT = old

    def test_channel_cap_per_connection(self):                 # inherited test runs in the parent class only
        pass
