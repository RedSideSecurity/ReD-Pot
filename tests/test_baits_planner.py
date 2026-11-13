"""Breadcrumb planner (B5), bait realism (B23), persona-styled manager certificate (B1)."""
import gzip
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import pytest
import unittest
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from rpot import baits as B
from rpot.common.config import TokenIndex

NAMES = {"windows-file-server": "ARB-FS01", "linux-web-hosting": "ARB-WEB01", "ftp-backup-server": "ARB-BKP01",
         "windows-domain-controller": "ARB-DC01", "linux-dns-server": "ARB-DNS01"}
# every host name the old generator invented + the names of decoys a test does NOT deploy
GHOSTS = ("FS01", "WEB01", "BKP01", "DC01", "DNS01", "SQL01")


def sensors(*roles):
    return [{"name": NAMES[r], "role": r, "ip": f"10.9.0.{20 + i}"} for i, r in enumerate(roles)]


def texts(root):
    """Every text an attacker can read in a bait tree (incl. docx XML and tar members)."""
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            yield os.path.relpath(p, root), p
            with open(p, "rb") as fh:
                raw = fh.read()
            if f.endswith(".docx"):
                z = zipfile.ZipFile(io.BytesIO(raw))
                yield b"".join(z.read(n) for n in z.namelist()).decode("utf-8", "replace"), p
            elif f.endswith(".tar.gz"):
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as t:
                    yield "".join(t.extractfile(m).read().decode() + m.name for m in t.getmembers() if m.isfile()), p
            else:
                yield raw.decode("utf-8", "replace"), p


class TestPlanner(unittest.TestCase):
    co = B.make_persona("araksbank.local", "bank", seed=11)

    def gen(self, sens, tmp, tokens=None, **kw):
        cfg = {"company": self.co, "console": {"canary_url": "https://10.9.0.5:8740"}, "sensors": sens,
               "tokens": tokens if tokens is not None else {}, "bait_seed": "seed1", **kw}
        B.generate(cfg, tmp)
        return cfg

    COMBOS = [("windows-file-server",), ("linux-web-hosting",), ("ftp-backup-server",), ("windows-domain-controller",),
              ("linux-dns-server",), ("windows-domain-controller", "ftp-backup-server"),
              ("linux-web-hosting", "ftp-backup-server"), ("windows-file-server", "linux-web-hosting"), tuple(NAMES)]

    def test_crumbs_name_only_deployed_decoys(self):
        for combo in self.COMBOS:
            with self.subTest(combo=combo), tempfile.TemporaryDirectory() as tmp:
                sens = sensors(*combo)
                cfg = self.gen(sens, tmp)
                deployed = {s["name"] for s in sens}
                absent = [n for n in NAMES.values() if n not in deployed]
                bad = re.compile(r"(?<![A-Za-z0-9-])(" + "|".join(GHOSTS + tuple(absent)) + r")(?![A-Za-z0-9])", re.I)
                for txt, where in texts(tmp):
                    m = bad.search(txt)
                    self.assertIsNone(m, f"{where}: {m and m.group(0)}")
                for tid, t in cfg["tokens"].items():
                    self.assertIn(t["holder"], deployed)
                    self.assertTrue(t["planted"].lstrip("\\").upper().startswith(t["holder"]), t)
                    self.assertTrue(os.path.isdir(os.path.join(tmp, t["holder"])))
                    for v in t.get("valid_on", []):
                        self.assertIn(v.split(":")[0], deployed, t)
                    self.assertIsNone(bad.search(t["desc"] + t["planted"]), t)

    def test_every_decoy_holds_a_working_credential(self):
        for combo in self.COMBOS:
            with self.subTest(combo=combo), tempfile.TemporaryDirectory() as tmp:
                sens = sensors(*combo)
                toks = self.gen(sens, tmp)["tokens"]
                for s in sens:
                    targets = {v.split(":")[0] for t in toks.values() if t["holder"] == s["name"] for v in t.get("valid_on", [])}
                    if len(sens) == 1:
                        self.assertIn(s["name"], targets)                         # self-contained single decoy
                    else:                                                         # lateral: creds for EVERY other decoy
                        self.assertEqual({x["name"] for x in sens} - {s["name"]} - targets, set(), s["name"])
                # every planted password is really written in the holder's tree
                import hashlib
                for t in toks.values():
                    if t["kind"] == "credential":
                        blob = "".join(x for x, _ in texts(os.path.join(tmp, t["holder"])))
                        self.assertTrue(t["password"] in blob or B.gpp_cpassword(t["password"]) in blob
                                        or hashlib.md5(t["password"].encode()).hexdigest() in blob, t["planted"])

    def test_dc_and_backup_have_a_path_both_ways(self):
        """S3 of the 2026-11-11 test: DC + Backup only had no DC→Backup crumb."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.gen(sensors("windows-domain-controller", "ftp-backup-server"), tmp)
            idx = TokenIndex(cfg)
            netlogon = os.path.join(tmp, "ARB-DC01", "shares", "NETLOGON", "ftp_arb-bkp01.txt")
            user, pw = open(netlogon).read().splitlines()[:2]
            tid, tok = idx.credential(user, pw)
            self.assertTrue(idx.valid_on(tok, "ARB-BKP01", "ftp"))
            self.assertEqual(tok["planted"], "\\\\ARB-DC01\\NETLOGON\\ftp_arb-bkp01.txt")
            ps1 = open(os.path.join(tmp, "ARB-BKP01", "ftp", "configs", "backup_job.ps1")).read()
            pw = re.search(r"\$pass = '([^']+)'", ps1).group(1)
            tid, tok = idx.credential("svc_backup", pw)
            self.assertTrue(idx.valid_on(tok, "ARB-DC01", "ldap"))
            honey = json.load(open(os.path.join(tmp, "ARB-DC01", "ldap", "honey_users.json")))
            self.assertIn("svc_backup", [h["username"] for h in honey])

    def test_deterministic_and_stable_when_a_decoy_is_added(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b, tempfile.TemporaryDirectory() as c:
            two = sensors("windows-file-server", "linux-web-hosting")
            t1 = json.loads(json.dumps(self.gen(two, a)["tokens"]))
            self.assertEqual(json.loads(json.dumps(self.gen(two, b)["tokens"])), t1)        # same input → same baits
            key1 = open(os.path.join(a, "ARB-FS01", "shares", "IT", "keys", "arb-web01_deploy.key.pub")).read()
            three = two + [{"name": "ARB-DC01", "role": "windows-domain-controller", "ip": "10.9.0.30"}]
            cfg = self.gen(three, c, tokens=json.loads(json.dumps(t1)))
            t2 = cfg["tokens"]
            for tid, t in t1.items():                                  # stolen baits stay valid
                self.assertIn(tid, t2)
                for k in ("username", "password", "fingerprint", "planted"):
                    self.assertEqual(t.get(k), t2[tid].get(k), (tid, k))
                self.assertLessEqual(set(t.get("valid_on", [])), set(t2[tid].get("valid_on", [])))
            self.assertEqual(open(os.path.join(c, "ARB-FS01", "shares", "IT", "keys", "arb-web01_deploy.key.pub")).read(), key1)
            scan = next(t for t in t2.values() if t.get("username") == "svc_scan")
            self.assertIn("ARB-DC01:ldap", scan["valid_on"])            # valid_on extended to the new DC
            self.assertTrue(any(t["holder"] == "ARB-DC01" for t in t2.values()))
            self.assertTrue(any(t["holder"] == "ARB-FS01" and "ARB-DC01:ldap" in t["valid_on"] for t in t2.values()))

    def test_persona_change_rekeys(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            t1 = self.gen(sensors("linux-web-hosting"), a)["tokens"]
            cfg = {"company": dict(self.co, seed=self.co["seed"] + 1), "console": {}, "sensors": sensors("linux-web-hosting"),
                   "tokens": dict(t1), "bait_seed": "seed1"}
            self.assertFalse(set(B.generate(cfg, b)) & set(t1))

    def test_realistic_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.gen(sensors("windows-file-server", "linux-web-hosting", "ftp-backup-server"), tmp)
            bk = os.path.join(tmp, "ARB-BKP01", "ftp", "backups")
            tgz = [f for f in os.listdir(bk) if f.endswith(".tar.gz")]
            self.assertTrue(any(f.startswith("arb-web01_portal_site_") for f in tgz))
            for f in tgz:
                with open(os.path.join(bk, f), "rb") as fh:
                    raw = fh.read()
                self.assertEqual(raw[:2], b"\x1f\x8b")
                names = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz").getnames()
                self.assertTrue(names)
                if "portal_site" in f:
                    self.assertIn("portal/index.php", names)
                    self.assertIn("portal/config.php", names)
            fin = os.path.join(tmp, "ARB-FS01", "shares", "Finance")
            sizes = [os.path.getsize(os.path.join(fin, f)) for f in os.listdir(fin) if f.endswith(".csv")]
            self.assertEqual(len(sizes), len(set(sizes)), sizes)
            now = time.time()
            for d, dirs, files in os.walk(os.path.join(tmp, "ARB-FS01")):
                kids = [os.path.getmtime(os.path.join(d, x)) for x in dirs + files]
                if kids:
                    self.assertAlmostEqual(os.path.getmtime(d), max(kids), delta=1, msg=d)
                    self.assertLess(os.path.getmtime(d), now - 86400, d)           # not "created at install time"


class TestFleetEnrollUsesPlanner(unittest.TestCase):
    def test_remote_dc_gets_planned_baits_and_extends_existing_tokens(self):
        from rpot.console.fleet import Fleet
        co = B.make_persona("araksbank.local", "bank", seed=11)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {"company": co, "console": {"admin_token": "at"}, "sensors": sensors("windows-file-server"),
                   "tokens": {}, "bait_seed": "s"}
            B.generate(cfg, os.path.join(tmp, "baits"))
            local = json.loads(json.dumps(cfg["tokens"]))
            db = sqlite3.connect(":memory:", check_same_thread=False)
            db.row_factory = sqlite3.Row
            db.execute("CREATE TABLE sensors(name TEXT)")
            f = Fleet(cfg, db, threading.Lock())
            tok = f.create_enrollment("ARB-DC09", "windows-domain-controller", "10.9.0.40")
            sj, tar = f.redeem(tok, {})
            names = tarfile.open(fileobj=io.BytesIO(tar), mode="r:gz").getnames()
            self.assertIn("ARB-DC09/ldap/honey_users.json", names)
            allt = f.all_tokens()
            for tid, t in local.items():                               # local baits unchanged, only widened
                self.assertEqual(allt[tid]["password" if "password" in t else "planted"],
                                 t["password" if "password" in t else "planted"])
            scan = next(t for t in allt.values() if t.get("username") == "svc_scan")
            self.assertIn("ARB-DC09:ldap", scan["valid_on"])
            mine = [t for t in allt.values() if t.get("holder") == "ARB-DC09"]
            self.assertTrue(mine)
            self.assertTrue(all(t["planted"].lstrip("\\").startswith("ARB-DC09") for t in mine))
            gpp = next(t for t in mine if t.get("username") == "srv_localadm")
            self.assertIn("ARB-FS01:smb", gpp["valid_on"])               # remote crumbs point at the local decoy
            f.revoke("ARB-DC09"); f.delete("ARB-DC09")
            scan = next(t for t in f.all_tokens().values() if t.get("username") == "svc_scan")
            self.assertNotIn("ARB-DC09:ldap", scan["valid_on"])


class TestManagerCertificate(unittest.TestCase):
    def init(self, d, *extra):
        base = [sys.executable, os.path.join(REPO, "rpotctl.py"), "init", "-d", d, "--force",
                "--domain", "araksbank.local", "--subnet", "10.9.0.0/24"]
        r = subprocess.run(base + list(extra), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        from cryptography import x509
        with open(os.path.join(d, "tls", "manager.crt"), "rb") as f:
            pem = f.read()
        return x509.load_pem_x509_certificate(pem), json.load(open(os.path.join(d, "rpot.json")))

    @pytest.mark.slow
    def test_decoy_on_mgmt_interface_cert_looks_like_the_decoy(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.serialization import Encoding
        with tempfile.TemporaryDirectory() as d:
            crt, cfg = self.init(d, "--net-mode", "host", "--mgmt-ip", "10.9.0.7",
                                 "--sensor", "ARB-DC01=windows-domain-controller@10.9.0.7%eth1")
            self.assertEqual(crt.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "arb-dc01.araksbank.local")
            self.assertEqual(crt.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value, "Araksbank")
            self.assertEqual(crt.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "Araksbank Issuing CA")
            self.assertNotEqual(crt.issuer, crt.subject)
            der = crt.public_bytes(Encoding.DER).lower()
            for bad in (b"red-pot", b"redpot", b"rpot", b"console", b"localhost"):
                self.assertNotIn(bad, der)
            san = crt.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(sorted(map(str, (x.value for x in san))), ["10.9.0.7", "arb-dc01.araksbank.local"])
            self.assertIsNone(cfg["network"]["console_ip"])           # no lab leftover (x.x.x.10) in production
            from rpot.common.tlsutil import fingerprint_file
            self.assertEqual(cfg["console"]["fingerprint"], fingerprint_file(os.path.join(d, "tls", "manager.crt")))
            from rpot.console.app import server_header
            self.assertEqual(server_header(cfg), "Microsoft-HTTPAPI/2.0")

    @pytest.mark.slow
    def test_dedicated_mgmt_and_lab(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        with tempfile.TemporaryDirectory() as d:
            crt, cfg = self.init(d, "--net-mode", "host", "--mgmt-ip", "192.168.50.2", "--public-ip", "203.0.113.9",
                                 "--sensor", "ARB-FS01=windows-file-server@10.9.0.21%eth1")
            self.assertEqual(crt.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "araksbank-mgmt01.araksbank.local")
            san = sorted(map(str, (x.value for x in crt.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)))
            self.assertEqual(san, ["192.168.50.2", "203.0.113.9", "araksbank-mgmt01.araksbank.local"])
            from rpot.console.app import server_header
            self.assertEqual(server_header(cfg), "nginx")
        with tempfile.TemporaryDirectory() as d:                      # lab bridge keeps its console address
            crt, cfg = self.init(d, "--sensor", "FS01=windows-file-server")
            san = [str(x.value) for x in crt.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
            self.assertIn("10.9.0.10", san)

    def test_pinned_client_accepts_the_persona_cert(self):
        from rpot.common.tlsutil import make_cert, PinnedClient
        from rpot.console.app import serve_tls
        from flask import Flask
        with tempfile.TemporaryDirectory() as d:
            crt, key, fp = make_cert(d, "x.corp.local", ["127.0.0.1"], org="Corp", ca_name="Corp Issuing CA")
            app = Flask("t")
            app.add_url_rule("/healthz", "h", lambda: {"ok": True})
            import socket
            s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            srv = serve_tls(app, "127.0.0.1", port, crt, key, "t")
            try:
                time.sleep(0.3)
                st, body = PinnedClient(f"https://127.0.0.1:{port}", fp).request("GET", "/healthz")
                self.assertEqual((st, body), (200, {"ok": True}))
            finally:
                srv.stop()


if __name__ == "__main__":
    unittest.main()
