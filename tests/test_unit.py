"""Unit tests: python -m unittest discover -s tests"""
import hashlib
import json
import os
import sys
import tempfile
import time
import pytest
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rpot import baits as B
from rpot.common.config import TokenIndex
from rpot.common.events import now_iso
from rpot.console import scoring
from rpot.console.engine import Engine
from rpot.sensor.services.catchers import parse_rdp_cr


def mkcfg(tmp, **over):
    cfg = {
        "company": B.make_persona("testbank.local", "bank", seed=7),
        "network": {"subnet": "172.30.0.0/24", "console_ip": "172.30.0.10"},
        "console": {"url": "http://172.30.0.10:8740", "canary_url": "http://172.30.0.10:8740",
                    "admin_token": "at", "watch_offline": False, "sensor_port": 8741, "fingerprint": "AB" * 32},
        "sensors": [{"name": "FS01", "role": "windows-file-server", "ip": "172.30.0.21",
                     "key_sha256": hashlib.sha256(b"fs01-secret").hexdigest()},
                    {"name": "WEB01", "role": "linux-web-hosting", "ip": "172.30.0.22"},
                    {"name": "BKP01", "role": "ftp-backup-server", "ip": "172.30.0.23"}],
        "allowlist": ["172.30.0.5/32"], "internal_nets": ["172.16.0.0/12", "10.0.0.0/8"],
        "alerts": {"min_level": 3}, "tokens": {},
    }
    cfg.update(over)
    B.generate(cfg, os.path.join(tmp, "baits"))
    return cfg


def datetime_now_minus(sec):
    from datetime import datetime, timezone, timedelta
    return (datetime.now(timezone.utc) - timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ev(type_, src="172.30.0.50", sensor="FS01", port=445, proto="smb", **data):
    return {"ts": now_iso(), "sensor": sensor, "role": "x", "sensor_ip": "172.30.0.21", "src_ip": src, "src_port": 50000,
            "dst_port": port, "proto": proto, "type": type_, "session": "s1", "data": data}


class TestScoring(unittest.TestCase):
    def test_ladder(self):
        self.assertEqual(scoring.score(ev("tcp.connect")), 1)
        self.assertEqual(scoring.score(ev("smb.negotiate")), 2)
        self.assertEqual(scoring.score(ev("smb.tree", share="IPC$")), 2)
        self.assertEqual(scoring.score(ev("smb.tree", share="Finance")), 3)
        self.assertEqual(scoring.score(ev("rdp.connect")), 2)
        self.assertEqual(scoring.score(ev("rdp.connect", cookie_user="bob")), 3)
        self.assertEqual(scoring.score(ev("auth.failed")), 3)
        self.assertEqual(scoring.score(ev("file.read", path="x")), 4)
        self.assertEqual(scoring.score(ev("honeytoken.used")), 5)
        self.assertEqual(scoring.score(ev("canary.hit")), 5)
        self.assertEqual(scoring.score(ev("totally.unknown")), 0)

    def test_scan_escalation(self):
        sc = scoring.Scorer()
        out = []
        for p in (21, 22, 80, 445):
            out += sc.escalations(ev("tcp.connect", port=p), now=1000)
        self.assertEqual(out, [])
        out = sc.escalations(ev("tcp.connect", port=3389), now=1001)
        self.assertEqual([o["type"] for o in out], ["scan.detected"])
        # cooldown: no repeat
        self.assertEqual(sc.escalations(ev("tcp.connect", port=139), now=1002), [])

    def test_scan_window_expires(self):
        sc = scoring.Scorer()
        for i, p in enumerate((21, 22, 80, 445)):
            sc.escalations(ev("tcp.connect", port=p), now=1000 + i)
        self.assertEqual(sc.escalations(ev("tcp.connect", port=3389), now=1000 + scoring.SCAN_WINDOW + 10), [])

    def test_spraying(self):
        sc = scoring.Scorer()
        out = []
        for i, u in enumerate(("root", "admin", "ubuntu", "test", "oracle")):
            out += sc.escalations(ev("auth.failed", port=None, username=u), now=2000 + i)
        self.assertEqual(out[-1]["type"], "auth.bruteforce")
        self.assertEqual(out[-1]["data"]["kind"], "password spraying")

    def test_404_bruteforce(self):
        sc = scoring.Scorer()
        out = []
        for i in range(scoring.NOTFOUND_N):
            out += sc.escalations(ev("http.notfound", port=None), now=3000 + i)
        self.assertEqual(out[-1]["type"], "http.bruteforce")

    def test_describe_never_crashes(self):
        for t in list(scoring.BASE) + ["x.y"]:
            self.assertIsInstance(scoring.describe(ev(t)), str)


class TestBaits(unittest.TestCase):
    def test_generate_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp)
            toks = cfg["tokens"]
            kinds = sorted(t["kind"] for t in toks.values())
            self.assertGreaterEqual(kinds.count("credential"), 8)        # full mesh FS/WEB/BKP + self crumbs
            self.assertIn("sshkey", kinds)
            self.assertEqual(kinds.count("document"), 2)
            pw = open(os.path.join(tmp, "baits/FS01/shares/IT/passwords.txt")).read()
            idx = TokenIndex(cfg)
            creds = [t for t in toks.values() if t["kind"] == "credential" and "passwords.txt" in t["planted"]]
            for c in creds:
                self.assertIn(c["password"], pw)
                tid, tok = idx.credential(c["username"].upper(), c["password"])  # usernames case-insensitive
                self.assertIsNotNone(tid)
            # passwords are unique across baits
            pws = [t["password"] for t in toks.values() if t["kind"] == "credential"]
            self.assertEqual(len(pws), len(set(pws)))
            # db dump md5 matches the admin token
            adm = next(t for t in toks.values() if t.get("username") == "admin" and t["holder"] == "BKP01")
            import glob
            dump = open(glob.glob(os.path.join(tmp, "baits/BKP01/ftp/backups/web01_portal_db_*.sql"))[0]).read()
            self.assertIn(hashlib.md5(adm["password"].encode()).hexdigest(), dump)
            self.assertTrue(idx.valid_on(adm, "web01", "http"))

    def test_docx_beacon(self):
        import zipfile, io
        blob = B.docx_with_beacon("T", ["a&b <c>"], "http://x/c/t1.png?a=1&b=2")
        z = zipfile.ZipFile(io.BytesIO(blob))
        rels = z.read("word/_rels/document.xml.rels").decode()
        self.assertIn('TargetMode="External"', rels)
        self.assertIn("http://x/c/t1.png?a=1&amp;b=2", rels)
        self.assertIn("a&amp;b &lt;c&gt;", z.read("word/document.xml").decode())


class TestPersona(unittest.TestCase):
    def test_custom_identity(self):
        p = B.make_persona("corp.araratbank.am", "bank", seed=1)
        self.assertEqual(p["netbios"], "ARARATBANK")
        self.assertEqual(p["email_domain"], "araratbank.am")
        self.assertIn(p["user_format"], B.USER_FORMATS)
        self.assertTrue(p["users"][0]["email"].endswith("@araratbank.am"))
        q = B.make_persona("acme.local", "it", seed=1)
        self.assertEqual((q["netbios"], q["email_domain"]), ("ACME", "acme.com"))

    def test_rejects_bad_values(self):
        for d in (None, "", "bad_domain", "a..b", "-x.com", "<b>x</b>.com"):
            with self.assertRaises(ValueError):
                B.make_persona(d, "it")
        self.assertEqual(B.make_persona("abcdefghijklmn-x.local", "it")["netbios"], "ABCDEFGHIJKLMNX")  # RC-27: no "-"
        self.assertTrue(B.valid_hostname("ARB-FS-02"))
        self.assertFalse(B.valid_hostname("bad name"))
        self.assertFalse(B.valid_hostname("A" * 16))

    def test_custom_hostnames_flow_into_baits(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp, sensors=[{"name": "ARB-FS-02", "role": "windows-file-server", "ip": "172.30.0.21"},
                                      {"name": "ARB-WEB-01", "role": "linux-web-hosting", "ip": "172.30.0.22"}])
            pw = open(os.path.join(tmp, "baits/ARB-FS-02/shares/IT/passwords.txt")).read()
            self.assertIn("ARB-WEB-01", pw)
            self.assertTrue(any("ARB-WEB-01:ssh" in t.get("valid_on", []) for t in cfg["tokens"].values()))


class TestHardening(unittest.TestCase):
    def test_hashed_token_index_matches(self):
        from rpot.common.config import sensor_token_view, TokenIndex
        toks = {"t1": {"kind": "credential", "username": "Deploy", "password": "S3cret!", "valid_on": ["WEB01:ssh"],
                       "planted": "\\\\FS01\\IT\\passwords.txt", "desc": "d"},
                "t2": {"kind": "document", "planted": "x", "desc": "y"},
                "t3": {"kind": "credential", "username": "svc_sql", "password": "Q", "valid_on": [], "planted": "p", "desc": "d"}}
        view = sensor_token_view(toks, "salt1", "windows-file-server")
        self.assertNotIn("S3cret!", json.dumps(view)); self.assertNotIn("t2", view)           # docs only for web
        idx = TokenIndex({"tokens": view, "company": {"token_salt": "salt1"}})
        self.assertEqual(idx.credential("deploy", "S3cret!")[0], "t1")
        self.assertEqual(idx.credential("deploy", "wrong")[0], None)
        self.assertFalse(idx.username_is_bait("DEPLOY"))     # generic wordlist name: not proof on its own
        self.assertTrue(idx.username_is_bait("SVC_SQL"))
        self.assertFalse(idx.username_is_bait("anna"))
        self.assertIn("t2", sensor_token_view(toks, "salt1", "linux-web-hosting"))

    def test_password_masking_and_control_chars(self):
        from rpot.sensor.base import _mask
        from rpot.common.events import clean
        m = _mask("MyRealPassw0rd")
        self.assertNotIn("RealPassw0rd", m)
        self.assertIn("len 14", m)
        self.assertEqual(clean({"u": "evil\r\nWhat: fake line"})["u"], "evil  What: fake line")

    def test_per_ip_limiter(self):
        from rpot.sensor.base import PerIP
        p = PerIP(2)
        self.assertTrue(p.take("1.2.3.4")); self.assertTrue(p.take("1.2.3.4")); self.assertFalse(p.take("1.2.3.4"))
        self.assertTrue(p.take("5.6.7.8"))
        p.give("1.2.3.4"); self.assertTrue(p.take("1.2.3.4"))

    def test_exploit_regex_is_linear(self):
        from rpot.sensor.services.http import EXPLOIT
        t = time.time()
        EXPLOIT.search("/a.php?" + "x" * 60000)
        self.assertLess(time.time() - t, 0.2)


class TestRpotctl(unittest.TestCase):
    @pytest.mark.slow
    def test_host_mode_one_decoy_per_interface_and_ip(self):
        """CE (D-2): host mode = each decoy on its own interface's own IP; a shared IP or interface is refused."""
        import subprocess
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as d:
            base = [sys.executable, os.path.join(repo, "rpotctl.py"), "init", "-d", d, "--force", "--domain", "x.local",
                    "--net-mode", "host", "--sensor", "FS1=windows-file-server@10.9.0.5%eth0"]
            r = subprocess.run(base + ["--sensor", "WEB1=linux-web-hosting@10.9.0.5%eth1"], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("duplicate sensor IP", r.stderr)
            r = subprocess.run(base + ["--sensor", "WEB1=linux-web-hosting@10.9.1.5%eth1"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)


class TestInstallerDryRun(unittest.TestCase):
    @pytest.mark.slow
    def test_dry_run_changes_nothing(self):
        """--dry-run writes nothing — manager only and with 3 decoys on 3 (simulated) interfaces."""
        import json
        import subprocess
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ifs = [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP", "gw": "10.0.0.1"},
               {"name": "eth1", "ip": "192.168.50.10", "prefix": 24, "state": "UP"},
               {"name": "eth2", "ip": "172.16.5.10", "prefix": 24, "state": "UP"}]
        env = dict(os.environ, RPOT_TEST_IFACES=json.dumps(ifs), RPOT_TEST_SSH_IP="10.0.0.5")
        base = [sys.executable, os.path.join(repo, "installer", "redpot_install.py"), "manager", "--dry-run", "--yes",
                "--domain", "x.example.com", "--profile", "generic", "--public-ip", "no", "--geoip", "no"]
        for extra in (["--roles", "none"],
                      ["--roles", "windows-file-server,linux-web-hosting,ftp-backup-server",
                       "--allow-ui", "10.8.0.0/24", "--allow-sensor", "10.8.0.0/24", "--allow-ssh", "10.8.0.0/24"]):
            with tempfile.TemporaryDirectory() as d:
                target = os.path.join(d, "inst")
                r = subprocess.run(base + ["--dir", target] + extra, capture_output=True, text=True, timeout=60,
                                   stdin=subprocess.DEVNULL, env=env)
                self.assertEqual(r.returncode, 0, r.stdout[-800:])
                self.assertFalse(os.path.exists(target), r.stdout[-500:])         # nothing written
                self.assertEqual(os.listdir(d), [])
            self.assertIn("[dry-run] docker pull", r.stdout)                   # prebuilt image: download only announced
            self.assertIn("[dry-run] docker run", r.stdout)
            self.assertIn("ctl init -d /d --force --domain x.example.com", r.stdout)


class TestBaitUser(unittest.TestCase):
    def test_username_only_detection_carries_token_id(self):
        """VM test v0.2.1: SMB (NTLM) bait logon raised L5 but the Deception tab counted 0 — no token id."""
        from rpot.common.config import sensor_token_view
        from rpot import baits as BB
        with tempfile.TemporaryDirectory() as tmp:
            co = BB.make_persona("corp.ararat.am", "bank", seed=2); co["token_salt"] = "s4lt"
            sensors = [{"name": "FS01", "role": "windows-file-server", "ip": "10.9.0.20"},
                       {"name": "BKP01", "role": "ftp-backup-server", "ip": "10.9.0.23"}]
            toks = BB.generate({"company": co, "console": {}, "sensors": sensors}, os.path.join(tmp, "baits"))
            view = sensor_token_view(toks, "s4lt", "windows-file-server")
            idx = TokenIndex({"tokens": view, "company": co})
            tid, tok = idx.bait_user("svc_backup")
            self.assertIsNotNone(tid)
            self.assertEqual(toks[tid]["username"], "svc_backup")
            self.assertEqual(idx.bait_user("administrator"), (None, None))       # generic names never match


class TestBaitsWithoutAllRoles(unittest.TestCase):
    def test_no_none_in_bait_texts_when_roles_are_missing(self):
        """VM test round 1: manager with FS01 only → Deception tab showed 'None deploy SSH password'."""
        from rpot import baits as BB
        with tempfile.TemporaryDirectory() as tmp:
            co = BB.make_persona("corp.ararat.am", "bank", seed=4)
            toks = BB.generate({"company": co, "console": {}, "sensors": [{"name": "FS01", "role": "windows-file-server", "ip": "10.9.0.20"}]},
                               os.path.join(tmp, "baits"))
            for t in toks.values():
                for k in ("desc", "planted"):
                    self.assertNotIn("None", str(t.get(k)), (k, t))
                self.assertFalse(any("None" in v for v in t.get("valid_on", [])), t)
                self.assertNotIn("WEB01", json.dumps(t))                 # B5: no crumbs for absent decoys


class TestIfaceIp(unittest.TestCase):
    def test_loopback_address(self):
        from rpot.sensor.main import iface_ipv4
        self.assertEqual(iface_ipv4("lo"), "127.0.0.1")
        self.assertIsNone(iface_ipv4("no-such-if0"))


class TestRdp(unittest.TestCase):
    def test_cookie(self):
        cookie = b"Cookie: mstshash=evil\r\n"
        neg = bytes([1, 0, 8, 0, 3, 0, 0, 0])
        x224 = bytes([6 + len(cookie) + len(neg), 0xE0, 0, 0, 0, 0, 0]) + cookie + neg
        pkt = bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big") + x224
        self.assertEqual(parse_rdp_cr(pkt), ("evil", 3))
        self.assertEqual(parse_rdp_cr(b"\x16\x03\x01"), (None, None))


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = mkcfg(self.tmp.name)
        self.e = Engine(self.cfg, os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_incident_grouping_and_escalation(self):
        self.e.ingest([ev("tcp.connect"), ev("smb.negotiate")])
        inc = self.e.incidents(min_level=1)
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["level"], 2)
        self.e.ingest([ev("honeytoken.used", sensor="WEB01", port=22, proto="ssh", username="deploy", desc="d", planted="p", success=True)])
        inc = self.e.incidents(min_level=1)
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["level"], 5)
        self.assertEqual(inc[0]["sensors"], ["FS01", "WEB01"])  # first-touch order
        self.assertIn("Honeytoken", inc[0]["title"])

    def test_allowlist_no_incident(self):
        self.e.ingest([ev("auth.failed", src="172.30.0.5")])
        self.assertEqual(self.e.incidents(min_level=1), [])
        h = self.e.hosts()
        self.assertTrue(h[0]["allowlisted"])

    def test_only_self_traffic_ignored(self):
        self.assertEqual(self.e.ingest([ev("tcp.connect", src="172.30.0.21")]), 0)      # decoy → itself
        self.assertGreater(self.e.ingest([ev("auth.failed", src="172.30.0.22")]), 0)   # hijacked neighbour decoy → recorded

    def test_untrusted_sensor_timestamps(self):
        from datetime import datetime, timezone
        self.e.ingest([dict(ev("auth.failed", src="172.30.0.60"), ts="9999-01-01T00:00:00.000Z"),
                       dict(ev("auth.failed", src="172.30.0.61"), ts="garbage"),
                       {"ts": "9999-01-01T00:00:00.000Z", "sensor": "FS01", "type": "sensor.heartbeat", "data": {}},
                       dict(ev("auth.failed", src="172.30.0.62"), type=123)])           # bad type: skipped, batch survives
        year = datetime.now(timezone.utc).year
        for ip in ("172.30.0.60", "172.30.0.61"):
            self.assertTrue(self.e.events(src=ip)[0]["ts"].startswith(str(year)))
        self.assertEqual(self.e.events(src="172.30.0.60")[0]["data"]["sensor_ts"], "9999-01-01T00:00:00.000Z")
        fs = [x for x in self.e.sensors() if x["name"] == "FS01"][0]
        self.assertTrue(fs["last_seen"].startswith(str(year)))

    def test_host_attribution(self):
        # B18: a username in an SMB logon is only TRIED (SMB accepts anything); only an accepted login names the host
        self.e.ingest([ev("smb.auth", user="anna.k", domain="CORP", workstation="ACC-PC-07")])
        self.assertEqual(self.e.host_label("172.30.0.50"), "172.30.0.50 ACC-PC-07")
        self.e.ingest([ev("auth.success", username="anna.k", port=22, proto="ssh")])
        self.assertEqual(self.e.host_label("172.30.0.50"), "172.30.0.50 ACC-PC-07 (anna.k)")
        g = self.e.graph(min_level=1)
        kinds = sorted(n["kind"] for n in g["nodes"])
        self.assertIn("subnet", kinds)
        self.assertIn("host", kinds)
        self.assertTrue(any(n.get("label") == "172.30.0.0/24" for n in g["nodes"]))

    def test_external_goes_to_internet(self):
        self.e.ingest([ev("auth.failed", src="203.0.113.9")])
        self.assertFalse(any(n["id"] == "n:Internet" for n in self.e.graph(min_level=1)["nodes"]))  # default: internal only
        g = self.e.graph(min_level=1, scope="all")
        self.assertTrue(any(n["id"] == "n:Internet" for n in g["nodes"]))
        self.assertNotIn("203.0.113.9", self.e._rdns_q)  # no reverse DNS for public IPs

    def test_worldmap_excludes_internal(self):
        self.e.ingest([ev("auth.failed", src="8.8.8.8"), ev("auth.failed", src="172.30.0.50")])
        ips = [p["ip"] for p in self.e.worldmap(min_level=1)["points"]]
        self.assertEqual(ips, ["8.8.8.8"])

    def test_sensor_heartbeat(self):
        self.e.ingest([{"ts": now_iso(), "sensor": "FS01", "role": "windows-file-server", "type": "sensor.heartbeat", "data": {}}])
        s = {x["name"]: x for x in self.e.sensors()}
        self.assertTrue(s["FS01"]["online"])
        self.assertFalse(s["WEB01"]["online"])

    def test_closed_incident_starts_new(self):
        self.e.ingest([ev("auth.failed")])
        iid = self.e.incidents()[0]["id"]
        self.e.set_status(iid, "closed")
        self.e.ingest([ev("auth.failed")])
        self.assertEqual(len(self.e.incidents(min_level=1)), 2)


class TestJsonLogs(unittest.TestCase):
    def test_rotation_by_day_size_gzip_and_keep(self):
        import gzip, glob
        from datetime import datetime, timezone, timedelta
        from rpot.console.logfile import JsonlLog
        with tempfile.TemporaryDirectory() as d:
            log = JsonlLog(d, "alerts", max_mb=0.001, keep=2)          # ~1 KB size limit
            day1 = datetime(2026, 11, 8, 23, 59, tzinfo=timezone.utc)
            log.write({"n": 1}, now=day1)
            log.write({"n": 2}, now=day1 + timedelta(minutes=2))         # next day → rotate
            self._wait_gz(d, 1)
            self.assertTrue(os.path.exists(os.path.join(d, "alerts-2026-11-08.json.gz")))
            with gzip.open(os.path.join(d, "alerts-2026-11-08.json.gz"), "rt") as f:
                self.assertEqual([json.loads(l) for l in f], [{"n": 1}])
            big = {"pad": "x" * 600}
            for i in range(6):                                            # size-based rotations, same day
                log.write(dict(big, i=i), now=day1 + timedelta(minutes=3 + i))
            time.sleep(1.0)
            gz = sorted(glob.glob(os.path.join(d, "alerts-*.json.gz")))
            self.assertLessEqual(len(gz), 2)                              # keep=2 prunes older archives
            with open(os.path.join(d, "alerts.json")) as f:
                lines = [json.loads(l) for l in f]
            self.assertTrue(all("pad" in l or "n" in l for l in lines))   # current file is valid JSON lines

    def _wait_gz(self, d, n):
        import glob
        for _ in range(50):
            if len(glob.glob(os.path.join(d, "*.json.gz"))) >= n:
                return
            time.sleep(0.05)

    def test_engine_writes_alert_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp)
            cfg["logs"] = {"alerts": True, "events": True}
            e = Engine(cfg, os.path.join(tmp, "t.db"), log_dir=os.path.join(tmp, "logs"))
            e.ingest([ev("tcp.connect"), ev("auth.failed", username="root"), ev("auth.failed", username="admin"),
                      ev("honeytoken.used", sensor="WEB01", port=22, proto="ssh", username="deploy", desc="d", planted="p", success=True)])
            with open(os.path.join(tmp, "logs", "alerts.json")) as f:
                alerts = [json.loads(l) for l in f]
            self.assertEqual([a["alert"]["level"] for a in alerts], [3, 5])   # only on level increase ≥ min_level
            a = alerts[-1]
            self.assertEqual(a["source"]["ip"], "172.30.0.50")
            self.assertEqual((a["src_ip"], a["dest_ip"], a["dest_port"], a["proto"]), ("172.30.0.50", "172.30.0.21", 22, "ssh"))
            self.assertTrue(a["alert"]["summary"].startswith("172.30.0.50 → WEB01 (172.30.0.21:22): "))
            self.assertTrue(a["source"]["internal"])
            self.assertEqual(a["alert"]["path"], ["FS01", "WEB01"])
            self.assertEqual(a["event"]["type"], "honeytoken.used")
            with open(os.path.join(tmp, "logs", "events.json")) as f:
                self.assertEqual(len(f.readlines()), 4)


FS = {"Authorization": "Bearer FS01:fs01-secret"}
BAD = {"Authorization": "Bearer FS01:wrong"}


class TestInternalNets(unittest.TestCase):
    def test_private_ranges_stay_internal_when_extra_nets_are_given(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp, internal_nets=["203.0.113.0/24"])
            e = Engine(cfg, os.path.join(tmp, "x.db"))
            for ip in ("172.30.50.50", "10.1.2.3", "192.168.1.5", "100.64.1.1", "203.0.113.7"):
                self.assertTrue(e.is_internal(ip), ip)
            self.assertFalse(e.is_internal("45.155.205.6"))


class TestTransport(unittest.TestCase):
    """Real TLS end to end: cheroot HTTPS server ↔ pinned sensor client."""
    @pytest.mark.slow
    def test_pinned_https_and_wrong_fingerprint(self):
        from rpot.common.tlsutil import make_cert, PinnedClient, PinError
        from rpot.console.app import create_app, create_sensor_app, serve_tls
        import socket as so
        with tempfile.TemporaryDirectory() as tmp:
            crt, key, fp = make_cert(os.path.join(tmp, "tls"), "127.0.0.1")
            cfg = mkcfg(tmp)
            cfg["console"]["fingerprint"] = fp
            app = create_app(cfg, os.path.join(tmp, "t.db"))
            s = so.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            srv = serve_tls(create_sensor_app(app.engine), "127.0.0.1", port, crt, key, "t")
            try:
                for _ in range(50):
                    try:
                        so.create_connection(("127.0.0.1", port), 0.2).close(); break
                    except OSError:
                        time.sleep(0.05)
                ok = PinnedClient(f"https://127.0.0.1:{port}", fp, auth="FS01:fs01-secret")
                st, res = ok.request("POST", "/api/ingest", {"events": [ev("tcp.connect", src="172.30.0.77")]})
                self.assertEqual(st, 200)
                self.assertEqual(res["stored"], 1)
                with self.assertRaises(PinError):
                    PinnedClient(f"https://127.0.0.1:{port}", "00" * 32, auth="FS01:fs01-secret").request("GET", "/healthz")
                # keep-alive: the second request reuses the same pinned TLS connection
                c1 = ok._conn
                self.assertIsNotNone(c1)
                ok.request("POST", "/api/ingest", {"events": [ev("tcp.connect", src="172.30.0.78")]})
                self.assertIs(ok._conn, c1)
                # a connection the server dropped is transparently re-opened (and re-pinned)
                ok._conn.sock.close()
                st, _ = ok.request("GET", "/healthz")
                self.assertEqual(st, 200)
                self.assertIsNot(ok._conn, c1)
                # big batch goes gzip-compressed and is stored completely
                big = [ev("http.request", src="172.30.0.79", path=f"/x{i}" + "a" * 200) for i in range(300)]
                st, res = ok.request("POST", "/api/ingest", {"events": big})
                self.assertEqual((st, res["stored"]), (200, 300))
                # gzip bomb (33 MB of zeros, ~33 KB compressed) is refused, not inflated
                import gzip as gz, http.client as hc, ssl as ss
                bomb = gz.compress(b"0" * (33 * 1024 * 1024))
                ctx = ss.SSLContext(ss.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ss.CERT_NONE
                h = hc.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
                h.request("POST", "/api/ingest", body=bomb, headers={"Content-Encoding": "gzip", "Content-Type": "application/json",
                                                                      "Authorization": "Bearer FS01:fs01-secret"})
                self.assertEqual(h.getresponse().status, 413)
                h.close()
            finally:
                srv.stop()

    def test_join_string(self):
        from rpot.common.tlsutil import parse_join
        self.assertEqual(parse_join("redpot://10.0.0.5:64301/abc#" + "A" * 64), ("https://10.0.0.5:64301", "abc", "A" * 64))
        for bad in ("http://x/y#z", "redpot://h:1/t#short", "redpot://h:1/#" + "A" * 64):
            with self.assertRaises(ValueError):
                parse_join(bad)

    def test_safe_extract_blocks_traversal(self):
        import io, tarfile
        from rpot.console.fleet import safe_extract
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            data = b"x"; ti = tarfile.TarInfo("../evil"); ti.size = 1; t.addfile(ti, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            safe_extract(buf.getvalue(), d)

    def test_offline_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp)
            e = Engine(cfg, os.path.join(tmp, "t.db"), log_dir=os.path.join(tmp, "logs"))
            e.ingest([{"ts": "2026-01-01T00:00:00.000Z", "sensor": "FS01", "role": "windows-file-server",
                       "sensor_ip": "172.30.0.21", "type": "sensor.heartbeat", "data": {}}])
            s = [x for x in e.sensors() if x["name"] == "FS01"][0]
            e._sensor_alert(s, "sensor.offline", "Sensor FS01 stopped reporting")
            with open(os.path.join(tmp, "logs", "alerts.json")) as f:
                a = json.loads(f.readline())
            self.assertEqual((a["alert"]["type"], a["level"], a["dest_ip"]), ("sensor.offline", 4, "172.30.0.21"))
            rows = e.db.execute("SELECT level, record FROM alert_records").fetchall()
            self.assertEqual([(r[0], json.loads(r[1])) for r in rows], [(4, a)])


class TestApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cfg = mkcfg(cls.tmp.name)
        cls.cfg["sensors"] = cls.cfg["sensors"][:2]      # CE cap (D-6): 2 local decoys leave one slot to enroll
        from rpot.console.app import create_app
        from rpot.console.app import create_sensor_app
        cls.app = create_app(cls.cfg, os.path.join(cls.tmp.name, "a.db"))
        cls.c = cls.app.test_client()
        cls.s = create_sensor_app(cls.app.engine).test_client()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_summary_lists_silent_sensors_admin_only(self):
        old = datetime_now_minus(600)                    # FS01 reported once, then went silent 10 min ago
        self.s.post("/api/ingest", json={"events": [ev("sensor.heartbeat")]}, headers=FS)
        self.app.engine.db.execute("UPDATE sensors SET last_seen=? WHERE name='FS01'", (old,))
        login = self.c.post("/login", data={"token": "at"})
        self.assertIn(login.status_code, (302, 303))
        d = self.c.get("/api/summary").get_json()
        self.assertIn("FS01", [x["name"] for x in d["sensors_offline"]])

    def test_ingest_requires_sensor_key(self):
        self.assertEqual(self.s.post("/api/ingest", json={"events": []}).status_code, 401)
        self.assertEqual(self.s.post("/api/ingest", json={"events": []}, headers=BAD).status_code, 401)
        r = self.s.post("/api/ingest", json={"events": [ev("tcp.connect")]}, headers=FS)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["version"])
        self.assertIn(self.c.post("/api/ingest", json={}).status_code, (404, 405))   # not on the UI port

    def test_sensor_cannot_speak_for_another(self):
        self.s.post("/api/ingest", json={"events": [ev("auth.failed", src="172.30.0.98", sensor="WEB01")]}, headers=FS)
        rows = self.app.engine.events(src="172.30.0.98")
        self.assertEqual({r["sensor"] for r in rows}, {"FS01"})

    def test_enrollment_flow_and_revoke(self):
        c = self.app.test_client(); c.post("/login", data={"token": "at"})
        h = {"X-Requested-With": "rpot"}
        self.assertEqual(c.post("/api/fleet/enroll", json={"name": "bad name", "role": "linux-web-hosting"}, headers=h).status_code, 400)
        self.assertEqual(c.post("/api/fleet/enroll", json={"name": "FS01", "role": "windows-file-server"}, headers=h).status_code, 400)
        r = c.post("/api/fleet/enroll", json={"name": "ARB-WEB-09", "role": "linux-web-hosting", "ip": "10.9.9.22"}, headers=h).get_json()
        from rpot.common.tlsutil import parse_join
        url, token, fp = parse_join(r["join"])
        self.assertEqual(fp, "AB" * 32)
        self.assertEqual(self.s.post("/api/enroll", json={"token": "nope"}).status_code, 403)
        v0 = self.app.engine.fleet.version()
        res = self.s.post("/api/enroll", json={"token": token, "info": {"hostname": "remote1"}})
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        key = body["sensor"]["key"]
        self.assertTrue(key.startswith("ARB-WEB-09:"))
        self.assertNotIn("admin_token", json.dumps(body))                       # no manager secrets in bundle
        blob = json.dumps(body["sensor"]["tokens"])
        for t in self.app.engine.fleet.all_tokens().values():                  # hashed view only
            if t.get("password"):
                self.assertNotIn(t["password"], blob)
            self.assertNotIn(t["planted"], blob)
        self.assertTrue(all("cred" in t for t in body["sensor"]["tokens"].values() if t["kind"] == "credential"))
        import base64, io, tarfile
        names = tarfile.open(fileobj=io.BytesIO(base64.b64decode(body["baits"])), mode="r:gz").getnames()
        self.assertIn("ARB-WEB-09/www/.env", names)
        self.assertNotEqual(self.app.engine.fleet.version(), v0)                 # existing sensors will resync
        self.assertEqual(self.s.post("/api/enroll", json={"token": token}).status_code, 403)   # one-time
        auth = {"Authorization": f"Bearer {key}"}
        self.assertEqual(self.s.get("/api/config", headers=auth).status_code, 200)
        # the decoy IP chosen in the sensor's own installer wins over the enrollment IP
        hb = dict(ev("sensor.heartbeat"), sensor_ip="10.9.9.44")
        self.assertEqual(self.s.post("/api/ingest", json={"events": [hb]}, headers=auth).status_code, 200)
        self.assertIn({"name": "ARB-WEB-09", "ip": "10.9.9.44"},
                      [{"name": x["name"], "ip": x["ip"]} for x in c.get("/api/fleet").get_json()["sensors"]])
        self.assertEqual(c.post("/api/fleet/ARB-WEB-09/revoke", headers=h).get_json(), {"ok": True})
        self.assertEqual(self.s.get("/api/config", headers=auth).status_code, 401)  # revoked
        listing = c.get("/api/fleet").get_json()
        self.assertTrue(any(x["name"] == "ARB-WEB-09" and x["revoked"] for x in listing["sensors"]))
        # a revoked decoy is gone from status / offline banner / tamper watch
        self.assertNotIn("ARB-WEB-09", [x["name"] for x in self.app.engine.sensors()])
        # user: "do we have a way to delete a sensor?" → only a REVOKED remote one; local decoys cannot be deleted
        self.assertEqual(c.post("/api/fleet/ARB-WEB-09/delete").status_code, 403)                   # CSRF header
        self.assertEqual(c.post("/api/fleet/FS01/delete", headers=h).status_code, 400)             # local decoy
        self.assertEqual(c.post("/api/fleet/ARB-WEB-09/delete", headers=h).get_json(), {"ok": True})
        self.assertNotIn("ARB-WEB-09", [x["name"] for x in c.get("/api/fleet").get_json()["sensors"]])
        # a moved (DHCP) sensor address is followed: next heartbeat with another IP updates the fleet view

    def test_ui_requires_login(self):
        c = self.app.test_client()
        self.assertEqual(c.get("/api/summary").status_code, 401)
        self.assertEqual(c.get("/static/app.js").status_code, 401)
        self.assertIn(b"Console access token", c.get("/").data)
        c.post("/login", data={"token": "wrong"})
        self.assertEqual(c.get("/api/summary").status_code, 401)
        c.post("/login", data={"token": "at"})
        self.assertEqual(c.get("/api/summary").status_code, 200)
        # forged cookie
        c2 = self.app.test_client()
        c2.set_cookie("rpot_ui", f"{int(time.time()) + 999}.deadbeef")
        self.assertEqual(c2.get("/api/summary").status_code, 401)

    def test_static_auth_bypass_and_throttles(self):
        c = self.app.test_client()
        for p in ("/static/login/../app.js", "/static/app.css/../index.html", "/static/app.js", "/static/netmap.js"):
            self.assertEqual(c.get(p).status_code, 401, p)
        self.assertEqual(c.get("/static/login.js").status_code, 200)
        self.assertEqual(c.post("/login", data={"token": "ü€\u2028"}).status_code, 302)    # non-ASCII: no 500
        self.cfg["console"]["wall_token"] = "wt"
        codes = [c.get("/wall?k=bad", environ_base={"REMOTE_ADDR": "9.9.9.9"}).status_code for _ in range(12)]
        self.assertEqual(codes[:10], [403] * 10); self.assertEqual(codes[-1], 429)
        self.cfg["console"].pop("wall_token")
        s = self.s
        self.assertEqual(s.post("/api/enroll", json=["x"]).status_code, 400)
        self.assertEqual(s.post("/api/ingest", json={"events": "x"}, headers=FS).status_code, 400)
        csp = c.get("/").headers["Content-Security-Policy"]
        self.assertIn("form-action 'self'", csp)

    def test_wall_token_is_read_only(self):
        self.cfg["console"]["wall_token"] = "wt-secret"
        c = self.app.test_client()
        self.assertEqual(c.get("/wall?k=wrong").status_code, 403)
        r = c.get("/wall?k=wt-secret")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/wall"))       # token stripped from the URL
        self.assertEqual(c.get("/wall").status_code, 200)
        self.assertEqual(json.loads(c.get("/api/whoami").data)["role"], "wall")
        self.assertEqual(c.get("/api/worldmap").status_code, 200)
        self.assertEqual(c.get("/api/summary").status_code, 200)
        for path in ("/api/incidents", "/api/tokens", "/api/hosts", "/api/events", "/api/host/1.2.3.4"):
            self.assertEqual(c.get(path).status_code, 403, path)
        self.assertEqual(c.post("/api/incident/1/status", json={"status": "closed"},
                                headers={"X-Requested-With": "rpot"}).status_code, 403)
        # the wall session must NOT turn "/" into the wall: the dashboard asks for the admin login instead
        self.assertIn(b"Console access token", c.get("/").data)
        c.post("/login", data={"token": "at"})                                  # admin login in the same browser
        self.assertIn(b"wallbar", c.get("/").data)                               # dashboard (index), not login
        self.assertEqual(json.loads(c.get("/api/whoami").data)["role"], "admin")
        self.assertIsNotNone(c.get_cookie("rpot_wall"))                          # wall session still there
        # tampering the role in the cookie breaks the signature
        ck = c.get_cookie("rpot_wall").value.replace(".wall.", ".admin.")
        c2 = self.app.test_client(); c2.set_cookie("rpot_ui", ck)
        self.assertEqual(c2.get("/api/tokens").status_code, 401)
        self.cfg["console"].pop("wall_token")
        self.assertEqual(self.app.test_client().get("/wall?k=").status_code, 403)  # disabled when unset

    def test_wall_session_bound_to_ip_and_revoked_by_new_link(self):
        """User report: 'the wall is accessible without any token'. A wall session must only work on the
        screen that opened the link, end when a new wall link is issued, and respect console.wall_allow."""
        self.cfg["console"]["wall_token"] = "wt-1"
        tv = {"REMOTE_ADDR": "10.1.1.50"}
        c = self.app.test_client()
        self.assertEqual(c.get("/wall?k=wt-1", environ_base=tv).status_code, 302)
        self.assertEqual(c.get("/wall", environ_base=tv).status_code, 200)
        self.assertIn("Max-Age=604800", "".join(c.get("/wall?k=wt-1", environ_base=tv).headers.getlist("Set-Cookie")))  # 7 days
        # the same cookie copied to another machine → login page / 401
        other = self.app.test_client()
        other.set_cookie("rpot_wall", c.get_cookie("rpot_wall").value)
        self.assertEqual(other.get("/wall", environ_base={"REMOTE_ADDR": "10.1.1.99"}).status_code, 302)
        self.assertEqual(other.get("/api/worldmap", environ_base={"REMOTE_ADDR": "10.1.1.99"}).status_code, 401)
        # new wall link (reset-token --wall) → every existing screen is logged out
        self.cfg["console"]["wall_token"] = "wt-2"
        self.assertEqual(c.get("/wall", environ_base=tv).status_code, 302)
        self.assertEqual(c.get("/wall?k=wt-1", environ_base=tv).status_code, 403)
        # allowlist of screen networks
        self.cfg["console"]["wall_allow"] = ["10.1.1.0/28"]
        from rpot.console.app import create_app
        app2 = create_app(self.cfg, os.path.join(self.tmp.name, "w2.db"))
        c3 = app2.test_client()
        self.assertEqual(c3.get("/wall?k=wt-2", environ_base={"REMOTE_ADDR": "10.1.1.50"}).status_code, 403)
        self.assertEqual(c3.get("/wall?k=wt-2", environ_base={"REMOTE_ADDR": "10.1.1.5"}).status_code, 302)
        self.cfg["console"].pop("wall_allow"); self.cfg["console"].pop("wall_token")

    def test_worldmap_notice_explains_empty_map(self):
        """User: 'show a pop-up when nothing is on the attack map'. Internal-only decoys and no GeoIP → both reasons."""
        c = self.app.test_client(); c.post("/login", data={"token": "at"})
        self.s.post("/api/ingest", json={"events": [ev("auth.failed", src="172.30.0.99")]}, headers=FS)
        n = c.get("/api/worldmap").get_json()["notice"]
        self.assertIn("internal_only", n["reasons"])
        self.assertIn("nogeo", n["reasons"])
        self.assertGreaterEqual(n["internal_sources"], 1)
        self.s.post("/api/ingest", json={"events": [ev("auth.failed", src="203.0.113.7")]}, headers=FS)
        n = c.get("/api/worldmap").get_json()["notice"]
        self.assertNotIn("internal_only", n["reasons"])            # a public attacker is on the map now
        self.assertEqual(n["reasons"], ["nogeo"])

    def test_wall_page_for_admin_without_token(self):
        anon = self.app.test_client()
        self.assertEqual(anon.get("/wall").status_code, 302)             # not logged in → login page
        c = self.app.test_client()
        c.post("/login", data={"token": "at"})
        r = c.get("/wall")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"wallbar", r.data)
        self.assertEqual(json.loads(c.get("/api/whoami").data)["role"], "admin")  # admin stays admin

    def test_status_needs_csrf_header(self):
        c = self.app.test_client()
        c.post("/login", data={"token": "at"})
        self.s.post("/api/ingest", json={"events": [ev("auth.failed", src="172.30.0.99")]}, headers=FS)
        iid = [i for i in json.loads(c.get("/api/incidents").data) if i["src_ip"] == "172.30.0.99"][0]["id"]
        self.assertEqual(c.post(f"/api/incident/{iid}/status", json={"status": "closed"}).status_code, 403)
        self.assertEqual(c.post(f"/api/incident/{iid}/status", json={"status": "closed"},
                                headers={"X-Requested-With": "rpot"}).status_code, 200)

    def test_canary_and_alerts(self):
        tid = next(k for k, t in self.cfg["tokens"].items() if t["kind"] == "document")
        r = self.c.get(f"/c/{tid}.png", environ_base={"REMOTE_ADDR": "10.9.9.9"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["Content-Type"], "image/png")
        self.assertEqual(self.c.get("/c/unknown.png").status_code, 200)  # no oracle for valid tokens
        recs = [json.loads(r[0]) for r in self.app.engine.db.execute("SELECT record FROM alert_records")]
        self.assertTrue(any(x["src_ip"] == "10.9.9.9" and x["level"] == 5 for x in recs))   # recorded locally only
        c = self.app.test_client()
        c.post("/login", data={"token": "at"})
        hosts = json.loads(c.get("/api/hosts").data)
        self.assertTrue(any(h["ip"] == "10.9.9.9" and h["max_level"] == 5 for h in hosts))


class TestConsoleRound04(unittest.TestCase):
    """v0.4 console fixes: B11 tamper incidents, B16 honeytoken KPI, B17/B18 host names, B25/B26 UI, world map."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = mkcfg(self.tmp.name)
        self.e = Engine(self.cfg, os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_b18_label_only_from_trustworthy_evidence(self):
        src = "172.30.0.77"
        self.e.ingest([ev("smb.auth", src=src, user="j.smith", domain="ARAKSBANK", workstation="TEST"),
                       ev("rdp.connect", src=src, port=3389, proto="rdp", cookie_user="nmap"),
                       ev("auth.failed", src=src, username="administrator"),
                       ev("honeytoken.used", src=src, username="svc_sql", token="x", success=False)])
        self.assertEqual(self.e.host_label(src), f"{src} TEST")             # no sprayed name, no RDP cookie
        n = self.e.host(src)["names"]
        self.assertEqual(n.get("logon"), None)
        self.assertEqual(n["tried"], ["ARAKSBANK\\j.smith", "administrator", "svc_sql"])
        self.assertIn("RDP cookie mstshash=nmap", n["client"])
        self.e.ingest([ev("honeytoken.used", src=src, username="svc_print", token="y", success=True)])
        self.assertEqual(self.e.host(src)["names"]["logon"], ["svc_print"])
        self.assertEqual(self.e.host_label(src), f"{src} TEST (svc_print)")

    def test_b16_distinct_baits_and_token_hits(self):
        toks = list(self.cfg["tokens"])[:3]
        self.e.ingest([ev("honeytoken.used", token=t, username="u", success=True) for t in toks] +
                      [ev("honeytoken.used", token=toks[0], username="u", success=True)])
        self.assertEqual(len(self.e.incidents(min_level=5)), 1)              # one attacker, one incident …
        s = self.e.summary()
        self.assertEqual(s["honeytokens"], 3)                                # … but three different baits
        self.assertEqual(s["honeytoken_incidents"], 1)
        by = {t["id"]: t for t in self.e.tokens()}
        self.assertEqual((by[toks[0]]["hits"], by[toks[1]]["hits"], by[toks[0]]["count"]), (2, 1, 2))
        self.assertTrue(all(isinstance(t["hits"], int) for t in by.values()))

    def test_b11_offline_is_an_incident_with_events(self):
        self.e.ingest([{"ts": now_iso(), "sensor": "FS01", "role": "windows-file-server", "sensor_ip": "172.30.0.21",
                        "type": "sensor.heartbeat", "data": {}}])
        s = [x for x in self.e.sensors() if x["name"] == "FS01"][0]
        self.e._sensor_alert(s, "sensor.offline", "Sensor FS01 stopped reporting 150 s ago — possible tampering")
        inc = [i for i in self.e.incidents(min_level=3, status="open") if i["kind"] == "sensor"]
        self.assertEqual(len(inc), 1)
        self.assertEqual((inc[0]["host"], inc[0]["level"], inc[0]["sensors"], inc[0]["src_ip"]), ("decoy FS01", 4, ["FS01"], None))
        evs = self.e.events(min_level=3)
        self.assertEqual([(x["type"], x["source"], x["incident_id"]) for x in evs], [("sensor.offline", "decoy FS01", inc[0]["id"])])
        self.e._sensor_alert(s, "sensor.online", "Sensor FS01 is reporting again")
        d = self.e.incident(inc[0]["id"])
        self.assertIn("reporting again", d["note"])
        self.assertEqual([x["type"] for x in d["events"]], ["sensor.offline", "sensor.online"])
        self.assertEqual(d["status"], "open")                               # the analyst closes it, not the decoy
        self.e._sensor_alert(s, "sensor.offline", "again")                   # flapping → same incident
        self.assertEqual(len([i for i in self.e.incidents(min_level=1) if i["kind"] == "sensor"]), 1)
        self.assertEqual(self.e.summary()["attackers"], 0)                  # not an attacker

    def _geo(self, table):
        self.e.geo.lookup = lambda ip: table.get(ip)

    def test_worldmap_places_each_decoy_at_its_own_ip(self):
        from rpot.console.geo import centroid
        lat, lon = centroid("US")
        self.assertTrue(30 < lat < 50 and -120 < lon < -80)
        self.assertIsNotNone(centroid("SG"))                                # small countries are in the table too
        self.cfg["sensors"][1]["ip"] = "198.51.100.7"                       # WEB01 on a US VPS (country DB only)
        self.cfg["sensors"][2]["ip"] = "192.0.2.80"                         # BKP01: city DB position
        self._geo({"198.51.100.7": {"cc": "US", "country": "United States"},
                   "192.0.2.80": {"cc": "DE", "country": "Germany", "city": "Frankfurt", "lat": 50.11, "lon": 8.68},
                   "203.0.113.9": {"cc": "CN", "country": "China"}})
        self.e.ingest([ev("auth.failed", src="203.0.113.9", sensor="WEB01", port=22, proto="ssh")])
        d = self.e.worldmap(min_level=1)
        sp = {x["name"]: x for x in d["sensors"]}
        self.assertEqual((sp["WEB01"]["from"], sp["WEB01"]["lat"], sp["WEB01"]["approx"]), ("geoip", lat, True))
        self.assertEqual((sp["BKP01"]["lat"], sp["BKP01"]["lon"], sp["BKP01"]["from"]), (50.11, 8.68, "geoip"))
        self.assertIsNone(sp["FS01"]["lat"])                                # private IP, no site: NOT Armenia
        self.assertIsNone(d["site"]["lat"])
        self.assertEqual(d["points"][0]["sensors"], ["WEB01"])              # arc goes to the decoy really attacked
        self.cfg["console"]["public_ip"] = "192.0.2.80"                     # manager public IP → fallback site
        self.assertEqual(self.e.worldmap()["site"]["from"], "manager")
        self.assertEqual({x["name"]: x["from"] for x in self.e.worldmap()["sensors"]}["FS01"], "manager")
        self.cfg["site"] = {"name": "HQ", "lat": 40.18, "lon": 44.51}       # configured site wins for private decoys
        sp = {x["name"]: x for x in self.e.worldmap()["sensors"]}
        self.assertEqual((sp["FS01"]["lat"], sp["FS01"]["from"], sp["WEB01"]["from"]), (40.18, "site", "geoip"))

    def test_worldmap_local_decoy_sharing_manager_ip_uses_public_ip(self):
        self.cfg["console"].update(mgmt_ip="10.0.0.4", public_ip="198.51.100.7")
        self.cfg["sensors"][0]["ip"] = "10.0.0.4"                           # VPS: decoy on the manager's NATed address
        self.cfg["site"] = {"name": "HQ", "lat": 40.18, "lon": 44.51}
        self._geo({"198.51.100.7": {"cc": "US"}})
        sp = {x["name"]: x for x in self.e.worldmap()["sensors"]}
        self.assertEqual((sp["FS01"]["from"], sp["FS01"]["geo_ip"]), ("geoip", "198.51.100.7"))
        self.assertEqual(sp["WEB01"]["from"], "site")


class TestConsoleRound04App(unittest.TestCase):
    def test_summary_clock_wall_privacy_and_degrading_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp)
            cfg["console"]["wall_token"] = "wt"
            from rpot.console.app import create_app
            app = create_app(cfg, os.path.join(tmp, "a.db"))
            c = app.test_client(); c.post("/login", data={"token": "at"})
            s = c.get("/api/summary").get_json()
            self.assertLess(abs(s["server_time"] - time.time()), 5)        # B26: server clock for skew detection
            self.assertIn("clock_synced", s)
            self.assertIn("honeytokens_used", s)
            self.assertIn("ip", c.get("/api/worldmap").get_json()["sensors"][0])
            w = app.test_client(); w.get("/wall?k=wt")
            self.assertNotIn("ip", w.get("/api/worldmap").get_json()["sensors"][0])   # kiosk: no decoy addresses
            page = c.get("/").data
            for el in (b'id="jserr"', b'id="clockwarn"', b'id="bootfail"', b'id="wsites"'):   # B25 banners
                self.assertIn(el, page)
            tok = c.get("/api/tokens").get_json()
            self.assertTrue(tok and all(isinstance(t["hits"], int) for t in tok))


if __name__ == "__main__":
    unittest.main()
