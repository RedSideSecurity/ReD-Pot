"""RC-27 / pentest F-01 (critical): IPC$ served the decoy's working directory (/opt/rpot = the ReD-Pot source)
to anonymous users. IPC$ must be pipe-only, ADMIN$/C$ must never map to a directory, every attempt to use
them as a disk is an L3 event, and the decoy process runs from an empty directory.

The decoy is started with its CWD set to a fake "/opt/rpot" holding sentinel source files, so any regression
that falls back to the CWD shows up as a readable rpotctl.py.
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_sensor_services import B, ctx_for  # noqa: E402
from test_dc_dns import free_port  # noqa: E402

SENTINEL = b"RPOT-SOURCE-SENTINEL"
ADMIN = ("IPC$", "ADMIN$", "C$")


class IpcLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from rpot.sensor.services.smb import start_smb
        cls.tmp = tempfile.TemporaryDirectory()
        cls.src = os.path.join(cls.tmp.name, "opt-rpot")                 # stands for WORKDIR /opt/rpot
        os.makedirs(os.path.join(cls.src, "rpot", "common"))
        for rel in ("rpotctl.py", "requirements.txt", os.path.join("rpot", "common", "edition.py")):
            with open(os.path.join(cls.src, rel), "wb") as f:
                f.write(SENTINEL)
        cls.old_cwd = os.getcwd()
        os.chdir(cls.src)
        try:
            co = B.make_persona("corp.ararat.am", "bank", seed=5)
            co["token_salt"] = "s4lt"
            cls.co = co
            sensors = [{"name": "FS01", "role": "windows-file-server", "ip": "10.9.0.20"},
                       {"name": "DC01", "role": "windows-domain-controller", "ip": "10.9.0.10"}]
            cls.tokens = B.generate({"company": co, "console": {}, "sensors": sensors},
                                    os.path.join(cls.tmp.name, "baits"))
            cls.pw = {t["username"]: t["password"] for t in cls.tokens.values() if t["kind"] == "credential"}
            cls.ctx, cls.em = ctx_for(cls.tmp.name, cls.tokens, co, sensors, "FS01", "windows-file-server")
            cls.dc, cls.dc_em = ctx_for(cls.tmp.name, cls.tokens, co, sensors, "DC01", "windows-domain-controller")
            cls.port, cls.dc_port = free_port(), free_port()
            cls.servers = {}
            for ctx, port in ((cls.ctx, cls.port), (cls.dc, cls.dc_port)):
                svc = next(x for x in ctx.role["services"] if x["type"] == "smb")
                cls.servers[ctx.name] = start_smb(ctx, dict(svc, port=port))
            time.sleep(0.3)
        except Exception:
            os.chdir(cls.old_cwd)
            raise

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.old_cwd)
        cls.tmp.cleanup()

    def bait_user(self, name="FS01"):
        return next(t["username"] for t in self.tokens.values()
                    if t["kind"] == "credential" and f"{name}:smb" in (t.get("valid_on") or []))

    def conn(self, user="", port=None, name="FS01"):
        from impacket.smbconnection import SMBConnection
        c = SMBConnection(name, "127.0.0.1", sess_port=port or self.port, timeout=5)
        c.login(user, self.pw.get(user, ""), self.co["netbios"])
        return c

    def logins(self):
        return (("anonymous", ""), ("bait", self.bait_user()))

    def status(self, fn):
        from impacket import smb3
        from impacket.smbconnection import SessionError
        try:
            r = fn()
        except SessionError as e:
            return e.getErrorCode()
        except smb3.SessionError as e:
            return e.get_error_code()
        return ("OK", r)


class TestAdminSharesNotADisk(IpcLab):
    def test_recursive_ls_and_get_return_nothing_from_the_cwd(self):
        """smbclient -N //host/IPC$ -c 'recurse ON; ls' / get rpotctl.py - anonymous and with a bait credential."""
        got = []
        for label, user in self.logins():
            c = self.conn(user)
            for share in ADMIN:
                for pattern in ("*", "\\*", "rpot\\*", "rpot\\common\\*"):
                    r = self.status(lambda: [f.get_longname() for f in c.listPath(share, pattern)])
                    self.assertNotEqual(r[:1] if isinstance(r, tuple) else r, ("OK",), (label, share, pattern, r))
                for path in ("rpotctl.py", "\\rpotctl.py", "requirements.txt", "rpot\\common\\edition.py",
                             "RPOTCTL.PY"):
                    r = self.status(lambda: c.getFile(share, path, got.append))
                    self.assertIsInstance(r, int, (label, share, path, r))
            c.logoff()
        self.assertNotIn(SENTINEL, b"".join(got))

    def test_status_codes_like_windows(self):
        c = self.conn(self.bait_user())
        self.assertEqual(self.status(lambda: c.listPath("IPC$", "*")), 0xC0000022)              # ACCESS_DENIED
        self.assertEqual(self.status(lambda: c.getFile("IPC$", "rpotctl.py", lambda d: None)), 0xC0000034)  # NOT_FOUND
        for share in ("ADMIN$", "C$"):
            self.assertEqual(self.status(lambda: c.connectTree(share)), 0xC0000022)
        tid = c.connectTree("IPC$")
        for p in ("samr", "lsarpc", "rpotctl.py", "rpot", "..\\rpotctl.py"):
            r = self.status(lambda: c.openFile(tid, p))
            self.assertIn(r, (0xC0000034, 0xC000003B), p)                 # NAME_NOT_FOUND / PATH_SYNTAX_BAD
        c.logoff()

    def test_query_directory_on_a_pipe_handle_is_invalid(self):
        """Even with a valid pipe handle on IPC$, a directory listing is refused."""
        c = self.conn(self.bait_user())
        tid = c.connectTree("IPC$")
        fid = c.openFile(tid, "srvsvc")
        r = self.status(lambda: c._SMBConnection.queryDirectory(tid, fid, "*"))
        self.assertEqual(r, 0xC000000D)                                    # STATUS_INVALID_PARAMETER
        c.close()

    def test_pipe_names_are_case_insensitive(self):
        c = self.conn(self.bait_user())
        tid = c.connectTree("IPC$")
        for p in ("srvsvc", "SRVSVC", "\\wkssvc", "WksSvc"):
            self.assertIsInstance(self.status(lambda: c.openFile(tid, p)), tuple, p)
        c.close()

    def test_attempts_raise_admin_share_events_at_l3(self):
        from rpot.console import scoring
        n = len(self.em.of("smb.admin_share"))
        c = self.conn()
        self.status(lambda: c.listPath("IPC$", "*"))
        self.status(lambda: c.getFile("IPC$", "rpotctl.py", lambda d: None))
        self.status(lambda: c.connectTree("C$"))
        self.status(lambda: c.connectTree("ADMIN$"))
        c.logoff()
        ev = self.em.of("smb.admin_share")[n:]
        self.assertEqual({(e["share"], e["op"]) for e in ev},
                         {("IPC$", "open"), ("C$", "tree"), ("ADMIN$", "tree")})
        self.assertIn("rpotctl.py", {e["path"] for e in ev})
        for e in ev:
            self.assertEqual(scoring.score({"type": "smb.admin_share", "data": e}), 3)
        self.assertTrue(scoring.describe({"type": "smb.admin_share", "sensor": "FS01", "data": ev[0]})
                        .startswith("Tried to"))

    def test_data_share_traversal_still_blocked(self):
        """impacket's own jail: ..\\ out of a bait share is refused (PATH_SYNTAX_BAD)."""
        c = self.conn(self.bait_user())
        for p in ("..\\..\\..\\opt-rpot\\rpotctl.py", "..\\..\\..\\..\\etc\\hostname", "..\\FS01\\x"):
            self.assertEqual(self.status(lambda: c.getFile("IT", p, lambda d: None)), 0xC000003B, p)
        c.logoff()

    def test_dc_persona_same(self):
        for user in ("", self.bait_user("DC01")):
            c = self.conn(user, self.dc_port, "DC01")
            for share in ADMIN:
                r = self.status(lambda: [f.get_longname() for f in c.listPath(share, "*")])
                self.assertIsInstance(r, int, (user, share))
                self.assertIsInstance(self.status(lambda: c.getFile(share, "rpotctl.py", lambda d: None)), int)
            c.logoff()
        self.assertTrue(self.dc_em.of("smb.admin_share"))


class TestSharePaths(IpcLab):
    def test_every_share_maps_inside_the_bait_tree_or_the_empty_ipc_dir(self):
        for name, s in self.servers.items():
            ctx = self.ctx if name == "FS01" else self.dc
            cfg = s._SimpleSMBServer__smbConfig
            root = os.path.realpath(os.path.join(ctx.bait_dir, "shares"))
            secs = [x for x in cfg.sections() if x != "global"]
            self.assertFalse({"ADMIN$", "C$"} & set(secs))
            for sec in secs:
                p = cfg.get(sec, "path")
                self.assertTrue(p and os.path.isabs(p), (sec, p))
                self.assertNotEqual(os.path.realpath(p), os.path.realpath(os.getcwd()))
                if sec == "IPC$":
                    self.assertEqual(os.path.basename(p), "smb-ipc")
                    self.assertEqual(os.listdir(p), [])
                    self.assertTrue(os.path.realpath(p).startswith(os.path.realpath(ctx.data_dir)))
                else:
                    self.assertTrue(os.path.realpath(p).startswith(root + os.sep), (sec, p))

    def test_unsafe_share_table_is_refused(self):
        import configparser
        from rpot.sensor.services.smb import _check_share_paths
        root = os.path.join(self.ctx.bait_dir, "shares")
        ipc = os.path.realpath(self.servers["FS01"]._SimpleSMBServer__smbConfig.get("IPC$", "path"))

        def cfg(**shares):
            c = configparser.ConfigParser()
            c.add_section("global")
            for k, v in shares.items():
                c.add_section(k.replace("_", "$"))
                c.set(k.replace("_", "$"), "path", v)
            return c
        _check_share_paths(cfg(IPC_=ipc, IT=os.path.join(root, "IT")), root, ipc)          # the real layout
        for bad in (cfg(IPC_=""), cfg(IPC_=os.getcwd()), cfg(IPC_=ipc, IT=self.src),
                    cfg(IPC_=ipc, IT=os.path.join(root, "..", "..")), cfg(IPC_=ipc, C_=root + "/IT"),
                    cfg(IPC_=ipc, IT="IT")):
            with self.assertRaises(RuntimeError):
                _check_share_paths(bad, root, ipc)


class TestEmptyDirs(unittest.TestCase):
    def test_empty_dir_never_reuses_a_non_empty_one(self):
        from rpot.sensor.emptydir import empty_dir
        with tempfile.TemporaryDirectory() as d:
            a = empty_dir(d, "smb-ipc")
            self.assertEqual((os.listdir(a), os.stat(a).st_mode & 0o777), ([], 0o100))
            self.assertEqual(empty_dir(d, "smb-ipc"), a)                  # restart: same dir, still empty
            os.chmod(a, 0o700)
            open(os.path.join(a, "leak"), "w").close()
            b = empty_dir(d, "smb-ipc")
            self.assertNotEqual(a, b)
            os.chmod(b, 0o700)
            self.assertEqual(os.listdir(b), [])
            os.symlink(d, os.path.join(d, "lnk"))
            self.assertNotEqual(empty_dir(d, "lnk"), os.path.realpath(d))

    def test_chdir_empty(self):
        from rpot.sensor.emptydir import chdir_empty
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            try:
                p = chdir_empty(d)
                self.assertEqual(os.getcwd(), p)
                self.assertEqual(os.path.dirname(p), os.path.realpath(d))
            finally:
                os.chdir(old)

    def test_sensor_main_chdirs_before_starting_services(self):
        """The decoy process never keeps /opt/rpot as its CWD (defence in depth for any relative open)."""
        import inspect
        from rpot.sensor import main as M
        src = inspect.getsource(M.main)
        self.assertIn("os.path.abspath(a.data)", src)
        self.assertLess(src.index("chdir_empty(a.data)"), src.index("st = _starters()"))


if __name__ == "__main__":
    unittest.main()
