"""RC-27 / pentest F-04 + F-05: bait and directory tells.

F-04: bait mtimes / DOCX metadata dated at install time with constant seconds; a 30-object LDAP stub with
builtin groups in CN=Users and dangling memberOf; NetBIOS "REDSIDE-SECURIT"; anonymous NetShareEnum (that
one is covered in test_rc27_ipc / test_rc21_smb_loopback).
F-05: NBNS node-status MAC with a fixed virtual-NIC vendor prefix instead of the decoy NIC's MAC.
"""
import collections
import io
import os
import random
import re
import struct
import sys
import tempfile
import time
import unittest
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "installer"))

from rpot import baits as B  # noqa: E402
from test_dc_dns import DCBase, one  # noqa: E402

SENSORS = [{"name": "RS-FS-02", "role": "windows-file-server", "ip": "192.168.56.108"},
           {"name": "RS-DC-01", "role": "windows-domain-controller", "ip": "192.168.1.190"},
           {"name": "RS-BKP-03", "role": "ftp-backup-server", "ip": "192.168.1.191"},
           {"name": "RS-WEB-04", "role": "linux-web-hosting", "ip": "192.168.1.192"},
           {"name": "RS-DNS-05", "role": "linux-dns-server", "ip": "192.168.1.193"}]


def _tree(seed=5):
    tmp = tempfile.TemporaryDirectory()
    co = B.make_persona("corp.redside-security.com", "it", seed=seed)
    co["token_salt"] = "s"
    t0 = time.time()
    B.generate({"company": co, "console": {}, "sensors": SENSORS}, tmp.name)
    files = [os.path.join(r, f) for r, _, fs in os.walk(tmp.name) for f in fs]
    return tmp, co, t0, files


class TestBaitTimes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.co, cls.t0, cls.files = _tree()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_mtimes_aged_and_not_sharing_seconds(self):
        mt = [os.path.getmtime(f) for f in self.files]
        self.assertGreater(len(mt), 30)
        self.assertTrue(all(t < self.t0 - 3600 for t in mt))                    # never install time
        secs = collections.Counter(int(t) % 60 for t in mt)
        self.assertLess(secs.most_common(1)[0][1], len(mt) // 4, secs)          # was: every file at :46
        self.assertGreater(len(secs), len(mt) // 3)
        hours = [datetime.fromtimestamp(t).hour for t in mt]
        self.assertTrue(all(7 <= h <= 21 for h in hours), hours)
        self.assertGreater(sum(8 <= h <= 18 for h in hours), len(hours) * 0.75)

    def test_business_time_distribution(self):
        r, now = random.Random(1), datetime(2026, 11, 13, 14, 23, 46)
        ts = [B.aged(r, now, d) for d in range(1, 400)] * 1
        self.assertTrue(all(t < now for t in ts))
        self.assertGreater(sum(t.weekday() < 5 for t in ts), len(ts) * 0.85)
        self.assertGreater(len({t.second for t in ts}), 50)
        self.assertGreater(len({t.minute for t in ts}), 50)
        self.assertGreater(sum(9 <= t.hour <= 17 for t in ts), len(ts) * 0.7)

    def test_docx_metadata_matches_file_time(self):
        docs = [f for f in self.files if f.endswith(".docx")]
        self.assertEqual(len(docs), 2)
        staff = {u["full_name"] for u in self.co["users"]}
        seen = set()
        for p in docs:
            z = zipfile.ZipFile(p)
            self.assertEqual({i.date_time for i in z.infolist()}, {(1980, 1, 1, 0, 0, 0)})   # like Word
            core = z.read("docProps/core.xml").decode()
            cr = re.search(r"<dcterms:created [^>]*>([^<]+)<", core).group(1)
            md = re.search(r"<dcterms:modified [^>]*>([^<]+)<", core).group(1)
            self.assertTrue(cr.endswith(":00Z") and md.endswith(":00Z"))
            self.assertLessEqual(cr, md)
            mtime = datetime.fromtimestamp(os.path.getmtime(p), timezone.utc)
            self.assertEqual(md, mtime.strftime("%Y-%m-%dT%H:%M:00Z"))             # modified = the file's save time
            self.assertIn(re.search(r"<dc:creator>([^<]+)<", core).group(1), staff)
            self.assertIn(re.search(r"<cp:lastModifiedBy>([^<]+)<", core).group(1), staff)
            app = z.read("docProps/app.xml").decode()
            self.assertIn("<Application>Microsoft Office Word</Application>", app)
            self.assertIn(f"<Company>{self.co['name']}</Company>", app)
            self.assertIn("docProps/app.xml", z.read("_rels/.rels").decode())
            self.assertIn('TargetMode="External"', z.read("word/_rels/document.xml.rels").decode())   # beacon kept
            seen.add(md)
        self.assertEqual(len(seen), 2)

    def test_tar_members_vary(self):
        import tarfile
        tgz = [f for f in self.files if f.endswith(".tar.gz")]
        self.assertTrue(tgz)
        for p in tgz:
            with tarfile.open(p) as t:
                secs = {m.mtime % 86400 for m in t.getmembers()}
            self.assertGreater(len(secs), 1, p)


class TestNetbios(unittest.TestCase):
    def test_natural_names(self):
        for d, nb in (("corp.redside-security.com", "REDSIDESECURITY"), ("corp.ararat-bank.am", "ARARATBANK"),
                      ("northwind-traders-intl.com", "NORTHWIND"), ("acme.local", "ACME"),
                      ("corp.araratbank.am", "ARARATBANK"), ("ab-cdefghijklmnopq.local", "ABCDEFGHIJKLMNO")):
            self.assertEqual(B.make_persona(d, seed=1)["netbios"], nb, d)

    def test_installer_preview_parity(self):
        import redpot_install as R
        rng = random.Random(7)
        doms = ["corp.redside-security.com", "x-y-z.local", "a.b.c.d.example.com", "very-long-company-name.am"]
        for _ in range(200):
            label = "-".join("".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randrange(1, 12)))
                             for _ in range(rng.randrange(1, 4)))
            doms.append(f"{rng.choice(['corp.', 'ad.', ''])}{label}.{rng.choice(['com', 'am', 'local'])}")
        for d in doms:
            try:
                want = B.make_persona(d, seed=1)["netbios"]
            except ValueError:
                continue
            self.assertEqual(R.persona_preview(d)["netbios"], want, d)
            self.assertNotIn("-", want)
            self.assertTrue(1 <= len(want) <= 15)


class TestDirectory(DCBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from rpot.sensor.services.ldap import Directory
        cls.dir = Directory(cls.ctxs["DC01"][0])
        cls.objs = cls.dir.objects()
        cls.by = {dn.lower(): a for dn, a in cls.objs}

    def test_baseline_size(self):
        self.assertGreaterEqual(len(self.objs), 100)
        self.assertEqual(len(self.by), len(self.objs))                     # unique DNs
        cls = collections.Counter(a["objectClass"][-1] for _, a in self.objs)
        self.assertGreaterEqual(cls["group"], 45)
        self.assertGreaterEqual(cls["computer"], 10)
        self.assertGreaterEqual(cls["organizationalUnit"], 5)

    def test_builtin_container_and_default_groups(self):
        self.assertEqual(self.by[f"cn=builtin,{self.dir.base}".lower()]["objectClass"][-1], "builtinDomain")
        for g in ("Administrators", "Users", "Guests", "Backup Operators", "Remote Desktop Users", "Account Operators",
                  "Server Operators", "Print Operators", "Pre-Windows 2000 Compatible Access"):
            a = self.by.get(f"cn={g},cn=builtin,{self.dir.base}".lower())
            self.assertIsNotNone(a, g)
            self.assertEqual(a["objectSid"][:12], bytes([1, 2]) + (5).to_bytes(6, "big") + struct.pack("<I", 32))
            self.assertNotIn(f"cn={g},cn=users,{self.dir.base}".lower(), self.by)
        for g in ("Domain Admins", "Domain Users", "Domain Computers", "Domain Controllers", "Domain Guests",
                  "Enterprise Admins", "Schema Admins", "Protected Users", "Group Policy Creator Owners", "DnsAdmins"):
            self.assertIn(f"cn={g},cn=users,{self.dir.base}".lower(), self.by, g)
        for c in ("CN=Users", "CN=Computers", "OU=Domain Controllers", "CN=System", "CN=ForeignSecurityPrincipals",
                  "CN=Managed Service Accounts", "CN=Policies,CN=System"):
            self.assertIn(f"{c},{self.dir.base}".lower(), self.by, c)

    def test_builtin_accounts(self):
        u = {a["sAMAccountName"]: a for _, a in self.objs if "user" in a["objectClass"]}
        self.assertTrue(int(u["Guest"]["userAccountControl"]) & 2)
        self.assertTrue(int(u["krbtgt"]["userAccountControl"]) & 2)
        self.assertFalse(int(u["Administrator"]["userAccountControl"]) & 2)
        self.assertIn(f"CN=Administrators,CN=Builtin,{self.dir.base}", u["Administrator"]["memberOf"])

    def test_membership_is_consistent(self):
        for dn, a in self.objs:
            for g in a.get("memberOf", []):
                self.assertIn(g.lower(), self.by, (dn, g))                     # no dangling memberOf
                self.assertIn(dn, self.by[g.lower()]["member"])
            for m in a.get("member", []):
                self.assertIn(m.lower(), self.by, (dn, m))
                self.assertIn(dn, self.by[m.lower()]["memberOf"])
            pg = a.get("primaryGroupID")
            if pg:                                                            # primary group never in memberOf
                prim = next(d for d, x in self.objs if x.get("objectSid") == self.dir.sid(int(pg)))
                self.assertNotIn(prim, a.get("memberOf", []), dn)

    def test_every_object_has_a_parent_and_metadata(self):
        for dn, a in self.objs:
            if dn.lower() != self.dir.base.lower():
                self.assertIn(dn.split(",", 1)[1].lower(), self.by, dn)
            self.assertEqual(len(a["objectGUID"]), 16)
            self.assertRegex(a["whenCreated"], r"^\d{14}\.0Z$")
            self.assertLessEqual(a["whenCreated"], a["whenChanged"])
        times = collections.Counter(a["whenCreated"][8:14] for _, a in self.objs
                                    if "computer" in a["objectClass"] or a.get("primaryGroupID") == "513")
        self.assertLess(times.most_common(1)[0][1], 3)                      # no shared time of day

    def test_workstations_known_to_kdc(self):
        from rpot.sensor.services.kerberos import KDC
        from rpot.sensor.services.ldap import workstations
        kdc = KDC(self.ctxs["DC01"][0])
        ws = workstations(self.ctxs["DC01"][0])
        self.assertEqual(len(ws), len(self.co["users"]))
        for n, *_ in ws:
            self.assertIn(n.lower() + "$", kdc.users())
            self.assertIn(f"cn={n},ou=workstations,{self.dir.company_ou()}".lower(), self.by)

    def test_ldap_collection_over_the_wire(self):
        """What ldapsearch / BloodHound-style collection sees after a bait-credential bind: >= 100 objects,
        OUs, the Builtin groups (paged search, like the collectors)."""
        import ldap3
        t = self.cred("svc_print")
        c = ldap3.Connection(self.srv(), user=f"{self.co['netbios']}\\svc_print", password=t["password"])
        self.assertTrue(c.bind())
        ents = c.extend.standard.paged_search(self.dir.base, "(objectClass=*)", attributes=["objectClass", "memberOf"],
                                              paged_size=500, generator=False)
        dns = [e["dn"] for e in ents if e["type"] == "searchResEntry"]
        self.assertGreaterEqual(len(dns), 100)
        c.search(self.dir.base, "(objectCategory=organizationalUnit)", attributes=["ou"])
        self.assertGreaterEqual(len([e for e in c.response if e["type"] == "searchResEntry"]), 5)
        c.search(f"CN=Builtin,{self.dir.base}", "(objectClass=group)", search_scope=ldap3.LEVEL, attributes=["cn"])
        names = {one(e["attributes"]["cn"]) for e in c.response if e["type"] == "searchResEntry"}
        self.assertTrue({"Administrators", "Backup Operators", "Remote Desktop Users"} <= names)

    def srv(self):
        import ldap3
        return ldap3.Server("127.0.0.1", port=self.p["ldap"], connect_timeout=3)


class TestNbnsMac(unittest.TestCase):
    def sysfs(self, d, macs):
        for dev, mac in macs.items():
            os.makedirs(os.path.join(d, dev))
            with open(os.path.join(d, dev, "address"), "w") as f:
                f.write(mac + "\n")

    def ctx(self, ip="192.168.56.108"):
        return SimpleNamespace(name="RS-FS-02", netbios="REDSIDESECURITY", em=SimpleNamespace(sensor_ip=ip))

    def test_mac_of_the_decoy_interface(self):
        from rpot.sensor.services import dcudp
        with tempfile.TemporaryDirectory() as d:
            self.sysfs(d, {"enp0s3": "08:00:27:aa:bb:01", "enp0s8": "08:00:27:cc:dd:02", "lo": "00:00:00:00:00:00"})
            with mock.patch.dict(os.environ, {"RPOT_SENSOR_IFACE": "enp0s8"}, clear=False):
                os.environ.pop("RPOT_BIND_IP", None)
                self.assertEqual(dcudp.nb_mac(self.ctx(), d), bytes.fromhex("080027ccdd02"))
            with mock.patch.dict(os.environ, {"RPOT_BIND_IP": "192.168.56.108"}, clear=False), \
                    mock.patch.object(dcudp, "bind_device", lambda: "enp0s3"):
                self.assertEqual(dcudp.nb_mac(self.ctx(), d), bytes.fromhex("080027aabb01"))
            with mock.patch.object(dcudp, "bind_device", lambda: None), \
                    mock.patch.object(dcudp.socket, "if_nameindex", lambda: [(1, "lo"), (2, "enp0s3"), (3, "enp0s8")]), \
                    mock.patch.object(dcudp, "iface_ipv4", lambda n: "192.168.56.108" if n == "enp0s8" else None):
                self.assertEqual(dcudp.nb_mac(self.ctx(), d), bytes.fromhex("080027ccdd02"))   # holds the sensor IP
            with mock.patch.object(dcudp, "bind_device", lambda: "../../etc"), \
                    mock.patch.object(dcudp.socket, "if_nameindex", lambda: [(1, "lo")]):
                self.assertEqual(dcudp.nb_mac(self.ctx(), d), b"\x00" * 6)                   # nothing usable

    def test_no_fixed_vendor_prefix_in_reply(self):
        from rpot.sensor.services import dcudp
        with tempfile.TemporaryDirectory() as d:
            self.sysfs(d, {"eth0": "52:54:00:12:34:56"})
            ctx = self.ctx()
            with mock.patch.object(dcudp, "bind_device", lambda: "eth0"):
                mac = dcudp.nb_mac(ctx, d)
            ctx.emit = lambda *a, **k: None
            q = struct.pack(">HHHHHH", 7, 0, 1, 0, 0, 0) + dcudp.nb_encode("*", 0) + struct.pack(">HH", 0x21, 1)
            r = dcudp.nbns_answer(ctx, q, ("10.0.0.5", 137), 137, lambda k: True)
        self.assertEqual(mac, bytes.fromhex("525400123456"))
        self.assertIn(mac + b"\x00" * 40, r)
        self.assertNotIn(b"\x00\x15\x5d", r)

    def test_real_sysfs_lookup_is_harmless(self):
        from rpot.sensor.services import dcudp
        mac = dcudp.nb_mac(SimpleNamespace(name="X", em=SimpleNamespace(sensor_ip="203.0.113.9")))
        self.assertEqual(len(mac), 6)


if __name__ == "__main__":
    unittest.main()
