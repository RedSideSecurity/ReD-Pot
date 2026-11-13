"""Regression tests for the issues found in the VM re-test (2026-11-11):
F2 self-test treated UDP-only DC ports as missing · F3 remove-decoy said tokens "changed" when they were removed ·
F4 pwdLastSet identical on every install · F5 tamper-recovery note lost after a console restart ·
F6 world-map notice said "all internal" although decoys had public IPs · F7 the fake shell forgot its own writes."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class _Ctx:
    os, name = "Ubuntu 22.04.4 LTS", "BKP01"

    def emit(self, *a, **k):
        pass


class TestFakeShellSessionFiles(unittest.TestCase):
    """F7: `echo hi > /tmp/x && cat /tmp/x` printed 'No such file' — real bash prints hi."""

    def sh(self):
        from rpot.sensor.services.ssh import FakeShell
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        os.makedirs(os.path.join(d.name, "home", "bob"))
        return FakeShell(_Ctx(), "bob", d.name)

    def test_write_then_read_in_session(self):
        sh = self.sh()
        self.assertEqual(sh.run("echo hi > /tmp/x && cat /tmp/x"), "hi\n")
        self.assertEqual(sh.run("echo two >> /tmp/x; cat /tmp/x"), "hi\ntwo\n")
        self.assertEqual(sh.run("echo new > ~/n.txt; head -1 ~/n.txt"), "new\n")
        self.assertEqual(sh.run("wc -l < /tmp/x").strip(), "2")

    def test_forbidden_and_devnull_not_stored(self):
        sh = self.sh()
        self.assertIn("Permission denied", sh.run("echo x > /etc/x"))
        sh.run("echo gone > /dev/null")
        self.assertEqual(sh.vfs, {})

    def test_store_is_capped(self):
        sh = self.sh()
        for i in range(80):
            sh.run(f"echo {i} > /tmp/f{i}")
        self.assertLessEqual(len(sh.vfs), 50)
        sh.run("head -c 200000 /dev/zero > /tmp/big")          # unknown command output: still bounded
        self.assertLessEqual(sum(map(len, sh.vfs.values())), 65536 + 65536)


class TestSelfTestUdp(unittest.TestCase):
    """F2: the DC's ntp/123 and nbns/137 are UDP-only; the self-test read only /proc/net/tcp → false ✗."""

    def test_role_udp_and_proc_parsing(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "installer"))
        import redpot_install as I
        I.role_catalog()
        self.assertEqual(I.ROLE_UDP["windows-domain-controller"], {123, 137})
        self.assertEqual(I.ROLE_UDP["windows-file-server"], set())
        self.assertIn(389, I.ROLE_PORTS["windows-domain-controller"])          # 389 tcp stays a TCP check
        udp = ("  sl  local_address rem_address   st\n"
               "   0: BE01A8C0:007B 00000000:0000 07 00000000:00000000\n"
               "   1: BE01A8C0:0089 00000000:0000 07 00000000:00000000\n"
               "   2: 0100007F:0143 00000000:0000 07 00000000:00000000\n")
        self.assertEqual(I._proc_listening(udp, "192.168.1.190", state="07"), {123, 137})
        self.assertEqual(I._proc_listening(udp, None, state="07"), {123, 137, 323})


class TestPwdLastSetPerInstall(unittest.TestCase):
    """F4: pwdLastSet was 2023-09-24 03:40:11 for svc_sql on every install (fixed base + name only)."""

    def directory(self, secret):
        from rpot.sensor.services import ldap as L

        class Ctx:
            cfg = {"company": {"name": "X", "domain": "corp.example.com", "netbios": "CORP", "users": []}}
            name, netbios, domain, bait_dir = "DC01", "CORP", "corp.example.com", "/nonexistent"

            def persona_secret(self, label):
                import hashlib
                return hashlib.sha256((secret + label).encode()).digest()
        d = L.Directory.__new__(L.Directory)
        d.ctx, d.dom = Ctx(), "corp.example.com"
        return d

    def test_differs_between_installs_and_is_stable(self):
        a, b = self.directory("install-a"), self.directory("install-b")
        self.assertNotEqual(a.pwd_epoch(), b.pwd_epoch())
        self.assertEqual(a.pwd_epoch(), a.pwd_epoch())
        self.assertTrue(1640995200 <= a.pwd_epoch() < 1640995200 + 3 * 365 * 86400)


class TestEngineRestartAndMapNotice(unittest.TestCase):
    def engine(self, d, cfg_extra=None):
        from rpot.console.engine import Engine
        cfg = {"company": {"name": "X"}, "console": {"watch_offline": False}, "internal_nets": ["192.168.0.0/16"],
               "sensors": [{"name": "FS01", "role": "windows-file-server", "ip": "192.168.56.108"}]}
        cfg.update(cfg_extra or {})
        return Engine(cfg, os.path.join(d, "rpot.db"))

    def test_offline_state_survives_console_restart(self):
        """F5: decoy offline → console restarted → decoy back: the 'reporting again' note never came."""
        with tempfile.TemporaryDirectory() as d:
            e = self.engine(d)
            e._sensor_alert({"name": "FS01", "role": "windows-file-server", "ip": "192.168.56.108"},
                            "sensor.offline", "Sensor FS01 stopped reporting 130 s ago")
            e.db.commit()
            e2 = self.engine(d)
            self.assertIn("FS01", e2._offline)
            e2._sensor_alert({"name": "FS01", "role": "windows-file-server", "ip": "192.168.56.108"},
                             "sensor.online", "Sensor FS01 is reporting again")
            e2.db.commit()
            self.assertNotIn("FS01", self.engine(d)._offline)       # back online: no repeated note next restart

    def test_public_decoy_is_not_internal_only(self):
        """F6: decoys with a public_ip (VPS/NAT) got the 'all of them are on internal addresses' notice."""
        with tempfile.TemporaryDirectory() as d:
            e = self.engine(d)
            self.assertIn("internal_only", (e._worldmap_notice([], "2000-01-01T00:00:00Z") or {}).get("reasons", []))
            e2 = self.engine(os.path.join(d), {"sensors": [{"name": "FS01", "role": "windows-file-server",
                                                            "ip": "192.168.56.108", "public_ip": "8.8.8.8"}]})
            self.assertNotIn("internal_only", (e2._worldmap_notice([], "2000-01-01T00:00:00Z") or {}).get("reasons", []))


class TestRemoveDecoyMessage(unittest.TestCase):
    """F3: removing a decoy printed '3 of 6 existing honeytokens changed' — they were removed with it."""

    def test_removed_tokens_reported_as_removed(self):
        import io
        import contextlib
        import rpotctl
        cfg = {"tokens": {"a": {"kind": "credential", "username": "u", "password": "p"},
                          "b": {"kind": "credential", "username": "v", "password": "q"}}}
        orig = (rpotctl._baits, rpotctl._sensor_bundles)
        rpotctl._baits = lambda c, d: c.update(tokens={"a": dict(c["tokens"]["a"])})
        rpotctl._sensor_bundles = lambda c, d, keep=False: None
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rpotctl._regen_keep(cfg, "/nonexistent")
        finally:
            rpotctl._baits, rpotctl._sensor_bundles = orig
        self.assertIn("1 honeytoken(s) removed together with the decoy", out.getvalue())
        self.assertNotIn("changed", out.getvalue())


if __name__ == "__main__":
    unittest.main()
