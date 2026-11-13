"""RC-21 / B1: SMB share enumeration must work under the host-mode egress guard (REDPOT-OUT).

On a host-mode decoy, uid 10001 may only reply and reach the sensor API; every NEW TCP connection to
127.0.0.1 is rejected (tcp-reset). impacket forwards named pipes (srvsvc / wkssvc) to its DCE/RPC servers
over TCP 127.0.0.1:<random port>, so share enumeration came back empty / ACCESS_DENIED on the VM.

These tests run the real SMB decoy (FS and DC persona) inside a simulated egress guard: every AF_INET /
AF_INET6 connect() in this process is refused with ECONNREFUSED (= REJECT --reject-with tcp-reset)
except to the decoy's own SMB port, which stands for the attacker reaching the decoy from the LAN (the
test client shares the decoy's process). AF_UNIX is not filtered by netfilter and stays allowed.
"""
import errno
import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_sensor_services import B, ctx_for  # noqa: E402
from test_dc_dns import free_port  # noqa: E402

FS_SHARES = {"ADMIN$", "C$", "IPC$", "Finance", "HR", "IT", "Public"}
DC_SHARES = {"ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"}


class EgressGuard:
    """Process-wide model of REDPOT-OUT for the decoy uid: NEW inet connections are refused unless the
    (host, port) is allowed. Records every refused attempt."""

    def __init__(self):
        self.allowed, self.refused = set(), []
        self._orig = {}

    def _check(self, sock, addr):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            key = (addr[0], addr[1])
            if key not in self.allowed:
                self.refused.append(key)
                return False
        return True

    def start(self):
        guard = self
        self._orig = {"connect": socket.socket.connect, "connect_ex": socket.socket.connect_ex}
        oc, ox = self._orig["connect"], self._orig["connect_ex"]

        def connect(sock, addr):
            if not guard._check(sock, addr):
                raise ConnectionRefusedError(errno.ECONNREFUSED, "REDPOT-OUT (simulated): connection refused")
            return oc(sock, addr)

        def connect_ex(sock, addr):
            return ox(sock, addr) if guard._check(sock, addr) else errno.ECONNREFUSED
        socket.socket.connect, socket.socket.connect_ex = connect, connect_ex
        return self

    def stop(self):
        for k, v in self._orig.items():
            setattr(socket.socket, k, v)


class GuardedLab(unittest.TestCase):
    """FS01 + DC01 SMB decoys started AND exercised under the egress guard."""

    @classmethod
    def setUpClass(cls):
        from rpot.sensor.services.smb import start_smb
        cls.tmp = __import__("tempfile").TemporaryDirectory()
        co = B.make_persona("corp.ararat.am", "bank", seed=5)
        co["token_salt"] = "s4lt"
        cls.co = co
        sensors = [{"name": "FS01", "role": "windows-file-server", "ip": "10.9.0.20"},
                   {"name": "DC01", "role": "windows-domain-controller", "ip": "10.9.0.10"}]
        cls.tokens = B.generate({"company": co, "console": {}, "sensors": sensors}, os.path.join(cls.tmp.name, "baits"))
        cls.pw = {t["username"]: t["password"] for t in cls.tokens.values() if t["kind"] == "credential"}
        cls.fs, cls.fs_em = ctx_for(cls.tmp.name, cls.tokens, co, sensors, "FS01", "windows-file-server")
        cls.dc, cls.dc_em = ctx_for(cls.tmp.name, cls.tokens, co, sensors, "DC01", "windows-domain-controller")
        cls.fs_port, cls.dc_port = free_port(), free_port()
        cls.guard = EgressGuard()
        cls.guard.allowed = {("127.0.0.1", cls.fs_port), ("127.0.0.1", cls.dc_port)}
        cls.guard.start()
        try:
            cls.servers = {}
            for ctx, port in ((cls.fs, cls.fs_port), (cls.dc, cls.dc_port)):
                svc = next(x for x in ctx.role["services"] if x["type"] == "smb")
                cls.servers[ctx.name] = start_smb(ctx, dict(svc, port=port))
            time.sleep(0.3)
        except Exception:
            cls.guard.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.guard.stop()
        cls.tmp.cleanup()

    def setUp(self):
        self.guard.refused.clear()

    def tearDown(self):
        self.assertEqual(self.guard.refused, [], "the decoy tried a connection the egress guard rejects")

    def bait(self, port, name="FS01"):
        """RC-27 F-04: a null session may not enumerate shares (Server 2019) - log on with a bait credential."""
        user = next(t["username"] for t in self.tokens.values()
                    if t["kind"] == "credential" and f"{name}:smb" in (t.get("valid_on") or []))
        return self.conn(port, user, self.pw[user], name)

    def conn(self, port, user="", pw="", name="FS01"):
        from impacket.smbconnection import SMBConnection
        c = SMBConnection(name, "127.0.0.1", sess_port=port, timeout=5)
        c.login(user, pw, self.co["netbios"])
        return c

    def rpc(self, c, pipe, iface):
        from impacket.dcerpc.v5 import transport
        t = transport.SMBTransport(c.getRemoteHost(), filename=pipe, smb_connection=c)
        d = t.get_dce_rpc()
        d.connect()
        d.bind(iface)
        return d

    @staticmethod
    def names(c):
        return {s["shi1_netname"][:-1] for s in c.listShares()}


class TestGuardModel(GuardedLab):
    def test_guard_rejects_loopback_tcp(self):
        """Sanity: the simulated guard really bites (this is what broke share enumeration on the VM)."""
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        addr = ls.getsockname()
        try:
            with self.assertRaises(ConnectionRefusedError):
                socket.create_connection(addr, timeout=2)
        finally:
            ls.close()
        self.assertEqual(self.guard.refused, [addr])
        self.guard.refused.clear()

    def test_no_rpc_listener_on_loopback(self):
        for s in self.servers.values():
            for rpc in (s._SimpleSMBServer__srvsServer, s._SimpleSMBServer__wkstServer):
                self.assertIsNone(rpc._sock)                      # impacket's 127.0.0.1 socket is closed
            pipes = s.getRegisteredNamedPipes()
            # RC-27 F-01: registered under the empty IPC$ directory (impacket joins share path + name)
            self.assertEqual({os.path.basename(k) for k in pipes}, {"srvsvc", "wkssvc"})
            for addr in pipes.values():
                self.assertNotIsInstance(addr, tuple)             # no ('127.0.0.1', port) left


class TestFileServerUnderGuard(GuardedLab):
    def test_anonymous_share_list_denied(self):
        """RC-27 F-04: like Server 2019 (RestrictAnonymous), a null session cannot enumerate shares - the
        attempt is still logged (smb.share_enum, denied) and nothing tries a loopback connection."""
        from impacket.smbconnection import SessionError
        c = self.conn(self.fs_port)
        with self.assertRaises(SessionError) as e:
            c.listShares()
        self.assertEqual(e.exception.getErrorCode(), 0xC0000022)
        c.logoff()
        self.assertTrue(any(x.get("denied") for x in self.fs_em.of("smb.share_enum")))

    def test_bait_share_list_like_windows(self):
        c = self.bait(self.fs_port)
        shares = {s["shi1_netname"][:-1]: s["shi1_type"] for s in c.listShares()}
        c.logoff()
        self.assertEqual(set(shares), FS_SHARES)
        self.assertEqual(shares["IPC$"], 0x80000003)
        self.assertEqual((shares["ADMIN$"], shares["C$"]), (0x80000000, 0x80000000))
        self.assertTrue([x for x in self.fs_em.of("smb.share_enum") if not x.get("denied")])

    def test_authenticated_share_list(self):
        user = next(t["username"] for t in self.tokens.values()
                    if t["kind"] == "credential" and "FS01:smb" in (t.get("valid_on") or []))
        c = self.conn(self.fs_port, user, self.pw[user])
        self.assertEqual(self.names(c), FS_SHARES)
        c.logoff()

    def test_wkssvc_pipe(self):
        from impacket.dcerpc.v5 import wkst
        c = self.bait(self.fs_port)
        w = self.rpc(c, r"\wkssvc", wkst.MSRPC_UUID_WKST)
        r = wkst.hNetrWkstaGetInfo(w, 100)                        # the RPC round trip through the pipe works
        self.assertEqual((r["ErrorCode"], r["WkstaInfo"]["WkstaInfo100"]["wki100_platform_id"]), (0, 500))
        w.disconnect()
        c.logoff()

    def test_held_open_pipe_does_not_block_others(self):
        hog = self.bait(self.fs_port)
        tid = hog.connectTree("IPC$")
        hog.openFile(tid, "srvsvc")                               # never closed
        c = self.bait(self.fs_port)
        self.assertEqual(self.names(c), FS_SHARES)
        c.logoff()
        hog.close()

    def test_dropped_client_ends_its_pipes(self):
        """RC-31 (N-3): pipes run without threads; a dropped client's open pipes are closed and their budget
        slots given back."""
        from rpot.sensor import base as sbase

        def pipes():
            return sbase.BUDGET.aux_n.get("smb-pipe", 0)
        base = pipes()
        threads = threading.active_count()
        c = self.bait(self.fs_port)
        tid = c.connectTree("IPC$")
        for _ in range(3):
            c.openFile(tid, "srvsvc")
        self.assertEqual(pipes(), base + 3)
        self.assertLessEqual(threading.active_count(), threads + 1)     # the client's handler thread only
        c.getSMBServer().get_socket().close()                    # TCP drop without closing the pipes
        deadline = time.monotonic() + 10
        while pipes() > base and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertLessEqual(pipes(), base)


class TestDomainControllerUnderGuard(GuardedLab):
    def test_dc_share_list(self):
        c = self.bait(self.dc_port, name="DC01")
        self.assertEqual(self.names(c), DC_SHARES)
        c.logoff()
        self.assertTrue(self.dc_em.of("smb.share_enum"))

    def test_dc_other_pipes_open_no_loopback(self):
        """samr / lsarpc / netlogon are not served by an RPC backend (no socket at all): the open fails like
        a missing pipe, the attempt is logged, and nothing tries a loopback connection (tearDown)."""
        from impacket.smbconnection import SessionError
        c = self.bait(self.dc_port, name="DC01")
        tid = c.connectTree("IPC$")
        for p in ("samr", "lsarpc", "netlogon"):
            with self.assertRaises(SessionError):
                c.openFile(tid, p)
        c.logoff()
        self.assertTrue({"samr", "lsarpc", "netlogon"} <= {e["pipe"] for e in self.dc_em.of("smb.pipe")})


class TestServerGetInfoUnderGuard(GuardedLab):
    """srvsvc NetrServerGetInfo (opnum 21, what Windows clients call next to NetShareEnumAll): persona name, OS
    version and server type; impacket's own handler raised on every call (pipe dropped)."""

    def info(self, port, name):
        from impacket.dcerpc.v5 import srvs
        c = self.bait(port, name=name)
        d = self.rpc(c, r"\srvsvc", srvs.MSRPC_UUID_SRVS)
        r = srvs.hNetrServerGetInfo(d, 101)
        d.disconnect()
        c.logoff()
        self.assertEqual(r["ErrorCode"], 0)
        return r["InfoStruct"]["ServerInfo101"]

    def test_file_server(self):
        from rpot.sensor.base import win_version
        i = self.info(self.fs_port, "FS01")
        self.assertEqual(i["sv101_name"], "FS01\x00")
        self.assertEqual((i["sv101_platform_id"], i["sv101_type"]), (500, 0x9003))
        self.assertEqual((i["sv101_version_major"], i["sv101_version_minor"]), win_version(self.fs.os)[:2])

    def test_domain_controller(self):
        i = self.info(self.dc_port, "DC01")
        self.assertEqual(i["sv101_name"], "DC01\x00")
        self.assertEqual(i["sv101_type"], 0x9003 | 0x2B)


class TestPipeSocketFallback(unittest.TestCase):
    def test_tuple_address_is_plain_tcp(self):
        """impacket.smbserver's socket shim only diverts _LocalPipe addresses; anything else is real TCP."""
        from impacket import smbserver
        import rpot.sensor.services.smb  # noqa: F401  (installs the shim)
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        s = smbserver.socket.socket()
        s.connect(ls.getsockname())
        a, _ = ls.accept()
        s.sendall(b"ping")
        self.assertEqual(a.recv(4), b"ping")
        for x in (a, s, ls):
            x.close()
        self.assertIs(smbserver.socket.AF_INET, socket.AF_INET)
        with smbserver.socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
            self.assertIsInstance(t, socket.socket)


if __name__ == "__main__":
    unittest.main()
