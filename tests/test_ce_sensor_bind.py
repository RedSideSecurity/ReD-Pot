"""S-1 L14 (RC-6): a remote sensor on its manager-link interface binds that interface's address (never 0.0.0.0),
is restarted when DHCP changes it, and still hears NetBIOS broadcasts (0.0.0.0 + SO_BINDTODEVICE on the decoy
interface). Loopback only; nothing leaves this host."""
import os
import socket
import sys
import threading
import time
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from rpot.sensor import base, main as sm  # noqa: E402

ENV = ("RPOT_BIND_IP", "RPOT_SENSOR_IFACE")


class _Env(unittest.TestCase):
    def setUp(self):
        self.saved = {k: os.environ.pop(k, None) for k in ENV}

    def tearDown(self):
        for k, v in self.saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class TestBindAddress(_Env):
    def test_bind_ip(self):
        self.assertEqual(base.bind_ip(), "0.0.0.0")                       # Docker-bridge lab
        os.environ["RPOT_SENSOR_IFACE"] = "lo"
        self.assertEqual(base.bind_ip(), "127.0.0.1")                     # the interface's address, not 0.0.0.0
        os.environ["RPOT_BIND_IP"] = "10.9.9.9"
        self.assertEqual(base.bind_ip(), "10.9.9.9")                      # a fixed address wins
        self.assertEqual(sm.iface_ipv4("lo"), "127.0.0.1")                # still importable from main

    def test_bind_device(self):
        self.assertIsNone(base.bind_device())
        os.environ["RPOT_BIND_IP"] = "127.0.0.1"
        self.assertEqual(base.bind_device(), "lo")                        # found from the bound address
        os.environ["RPOT_BIND_IP"] = "192.0.2.123"
        self.assertIsNone(base.bind_device())
        os.environ["RPOT_SENSOR_IFACE"] = "lo"
        self.assertEqual(base.bind_device(), "lo")

    def test_tcp_listener_on_the_interface_address(self):
        os.environ["RPOT_SENSOR_IFACE"] = "lo"
        ctx = mock.Mock()
        s = base.serve_tcp(ctx, 0, lambda c, a, sess: c.sendall(b"hi"), "test")
        try:
            self.assertEqual(s.getsockname()[0], "127.0.0.1")
        finally:
            s.close()


class TestBroadcastUdp(_Env):
    def _udp(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s, base._bind_udp(s, base.bind_ip(), port)

    def test_netbios_port_binds_wildcard_on_the_device(self):
        os.environ["RPOT_BIND_IP"] = "127.0.0.1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with mock.patch.object(base, "BROADCAST_UDP", {port}):
            s, how = self._udp(port)
        try:
            if how == "127.0.0.1":
                self.skipTest("SO_BINDTODEVICE not permitted here (kernel < 5.7 without CAP_NET_RAW)")
            self.assertEqual(how, "0.0.0.0%lo")
            self.assertEqual(s.getsockname()[0], "0.0.0.0")
            dev = s.getsockopt(socket.SOL_SOCKET, base.SO_BINDTODEVICE, 16).rstrip(b"\0")
            self.assertEqual(dev, b"lo")
        finally:
            s.close()

    def test_other_ports_and_failures_keep_the_unicast_address(self):
        os.environ["RPOT_BIND_IP"] = "127.0.0.1"
        s, how = self._udp(0)                                             # not a broadcast port
        self.assertEqual((how, s.getsockname()[0]), ("127.0.0.1", "127.0.0.1"))
        s.close()

        class NoDevice(socket.socket):
            def setsockopt(self, level, opt, val):
                if opt == base.SO_BINDTODEVICE:
                    raise PermissionError("EPERM")
                return super().setsockopt(level, opt, val)
        s = NoDevice(socket.AF_INET, socket.SOCK_DGRAM)
        with mock.patch.object(base, "BROADCAST_UDP", {0}):
            how = base._bind_udp(s, "127.0.0.1", 0)
        self.assertEqual((how, s.getsockname()[0]), ("127.0.0.1", "127.0.0.1"))
        s.close()


class TestFollowDhcp(unittest.TestCase):
    def test_address_change_triggers_a_rebind(self):
        addrs = iter(["10.0.0.5", "10.0.0.5", "10.0.0.77"])
        em = mock.Mock(sensor_ip="10.0.0.5")
        fired = threading.Event()
        with mock.patch.object(sm, "iface_ipv4", lambda n: next(addrs, "10.0.0.77")):
            t = sm._follow_iface_ip(em, "eth0", "BR-FS-01", every=0.01, on_change=fired.set)
            self.assertTrue(fired.wait(5))
            t.join(5)
        self.assertFalse(t.is_alive())                                    # stops after asking for the restart
        self.assertEqual(em.sensor_ip, "10.0.0.77")
        self.assertIsNone(sm._follow_iface_ip(em, None, "X"))            # fixed address / lab: nothing to follow

    def test_waits_for_the_interface_address(self):
        seq = iter([None, None, "10.0.0.5"])
        with mock.patch.object(sm, "iface_ipv4", lambda n: next(seq)), mock.patch.object(sm.time, "sleep", lambda s: None):
            self.assertEqual(sm.wait_iface_ip("eth0", secs=60), "10.0.0.5")
        t0 = time.monotonic()
        with mock.patch.object(sm, "iface_ipv4", lambda n: None):
            self.assertIsNone(sm.wait_iface_ip("eth0", secs=0.05, step=0.01))
        self.assertLess(time.monotonic() - t0, 5)


if __name__ == "__main__":
    unittest.main()
