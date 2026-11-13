"""Domain Controller + DNS decoys, driven with real attacker tooling (dnspython, ldap3, impacket)."""
import os
import random
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rpot import baits as B
from rpot.common.config import TokenIndex, load_roles, sensor_token_view, zone_view
from rpot.console import scoring
from rpot.sensor.base import Ctx
from rpot.sensor.services import ber
from rpot.sensor.services.dns import parse_query, start_dns
from rpot.sensor.services.kerberos import parse_kdc_req, principal, start_kerberos
from rpot.sensor.services.ldap import start_ldap


def free_port():
    while True:
        p = random.randint(20000, 60000)
        ok = True
        for t in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            s = socket.socket(socket.AF_INET, t)
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                ok = False
            finally:
                s.close()
        if ok:
            return p


class Em:
    sensor_ip = "127.0.0.1"

    def __init__(self):
        self.events = []

    def emit(self, type_, **kw):
        self.events.append(dict(kw, type=type_))

    def types(self):
        return [e["type"] for e in self.events]

    def of(self, t):
        return [e for e in self.events if e["type"] == t]


class DCBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        co = B.make_persona("corp.ararat.am", "bank", seed=3)
        co["token_salt"] = "s4lt"
        sensors = [{"name": "FS01", "role": "windows-file-server", "ip": "10.9.0.20"},
                   {"name": "DC01", "role": "windows-domain-controller", "ip": "10.9.0.10"},
                   {"name": "DNS01", "role": "linux-dns-server", "ip": "10.9.0.11"},
                   {"name": "WEB01", "role": "linux-web-hosting", "ip": "10.9.0.22"}]
        full = {"company": co, "console": {}, "sensors": sensors}
        cls.tokens = B.generate(full, os.path.join(cls.tmp.name, "baits"))
        cls.co = co
        roles = load_roles()
        cls.ctxs = {}
        for name, role in (("DC01", "windows-domain-controller"), ("DNS01", "linux-dns-server")):
            s = next(x for x in sensors if x["name"] == name)
            cfg = {"company": co, "tokens": sensor_token_view(cls.tokens, "s4lt", role), "sensors": [s], **zone_view(sensors)}
            em = Em()
            d = os.path.join(cls.tmp.name, "data", name)
            os.makedirs(d)
            cls.ctxs[name] = (Ctx(cfg, s, roles[role], em, TokenIndex(cfg), os.path.join(cls.tmp.name, "baits", name), d), em)
        dc, _ = cls.ctxs["DC01"]
        cls.p = {k: free_port() for k in ("dns", "ldap", "ldaps", "krb")}
        start_dns(dc, {"port": cls.p["dns"]})
        start_ldap(dc, {"port": cls.p["ldap"]})
        start_ldap(dc, {"port": cls.p["ldaps"], "tls": True})
        start_kerberos(dc, {"port": cls.p["krb"]})
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def cred(self, user):
        return next(t for t in self.tokens.values() if t.get("username") == user)

    @property
    def em(self):
        return self.ctxs["DC01"][1]


class TestBER(unittest.TestCase):
    def test_roundtrip_and_hostile_input(self):
        blob = ber.seq(ber.integer(5), ber.octets("x" * 300), ber.ctx(3, ber.integer(-1)))
        tag, v = ber.one(blob)
        self.assertEqual(tag, 0x30)
        self.assertEqual(ber.as_int(v[0][1]), 5)
        self.assertEqual(len(v[1][1]), 300)
        self.assertEqual(ber.as_int(v[2][1][0][1]), -1)
        for bad in (b"\x30\x84\xff\xff\xff\xff", b"\x30\x05\x02\x01", b"\x1f\x01\x00", b"\x30\x89" + b"\x01" * 9,
                    b"\x30\x02" * 40):
            with self.assertRaises(ValueError):
                ber.decode(bad)
        deep = b"\x05\x00"
        for _ in range(40):
            deep = ber.seq(deep)
        with self.assertRaises(ValueError):
            ber.decode(deep)

    def test_fuzz_parsers_only_raise_valueerror(self):
        rng = random.Random(1)
        seeds = [ber.app(10, ber.seq(ber.ctx(1, ber.integer(5)), ber.ctx(4, ber.seq(ber.ctx(1, principal(1, "bob")))))),
                 b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"]
        for _ in range(3000):
            b = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(1, 6)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            b = bytes(b[:rng.randint(0, len(b))])
            for fn in (parse_kdc_req, parse_query):
                try:
                    fn(b)
                except ValueError:
                    pass


class TestDNS(DCBase):
    def q(self, name, rtype="A", rclass="IN", tcp=False):
        import dns.message
        import dns.query
        m = dns.message.make_query(name, rtype, rclass)
        return (dns.query.tcp if tcp else dns.query.udp)(m, "127.0.0.1", port=self.p["dns"], timeout=3)

    def test_zone_answers_and_breadcrumb_aliases(self):
        r = self.q("dc01.corp.ararat.am")
        self.assertEqual(r.rcode(), 0)
        self.assertEqual(r.answer[0][0].address, "10.9.0.10")
        self.assertEqual(self.q("files.corp.ararat.am").answer[0][0].address, "10.9.0.20")
        self.assertEqual(self.q("intranet.corp.ararat.am", tcp=True).answer[0][0].address, "10.9.0.22")
        self.assertEqual(self.q("nothere.corp.ararat.am").rcode(), 3)                # NXDOMAIN
        srv = self.q("_ldap._tcp.dc._msdcs.corp.ararat.am", "SRV").answer[0][0]
        self.assertEqual((srv.port, str(srv.target)), (389, "dc01.corp.ararat.am."))
        self.assertIn("dns.query", self.em.types())

    def test_no_recursion_axfr_and_version(self):
        self.assertEqual(self.q("google.com").rcode(), 2)        # DC = Microsoft DNS: SERVFAIL, not an open resolver
        self.assertEqual(self.q("corp.ararat.am", "AXFR", tcp=True).rcode(), 5)
        self.assertTrue(self.em.of("dns.axfr"))
        r = self.q("version.bind", "TXT", "CH")                  # B6: no BIND version on a Windows DC;
        self.assertEqual((r.rcode(), r.answer), (4, []))       # RC-23 B3: Windows default NOTIMP (not NSD's REFUSED)
        self.assertTrue(self.em.of("dns.version"))
        import dns.message                                       # the Linux DNS role keeps the BIND persona
        from rpot.sensor.services.dns import answer
        ctx, _ = self.ctxs["DNS01"]
        raw = answer(ctx, dns.message.make_query("version.bind", "TXT", "CH").to_wire(), ("10.0.0.9", 5353), 53, "dns")
        self.assertIn("9.18", dns.message.from_wire(raw).answer[0][0].to_text())
        raw = answer(ctx, dns.message.make_query("google.com", "A").to_wire(), ("10.0.0.9", 5353), 53, "dns")
        self.assertEqual(dns.message.from_wire(raw).rcode(), 5)
        self.assertEqual(scoring.score({"type": "dns.axfr"}), 3)


def one(v):
    return v[0] if isinstance(v, list) else v


class TestLDAP(DCBase):
    def srv(self, port_key="ldap", **kw):
        import ldap3
        return ldap3.Server("127.0.0.1", port=self.p[port_key], get_info=ldap3.DSA, connect_timeout=3, **kw)

    def test_rootdse_and_anonymous_search_refused(self):
        import ldap3
        c = ldap3.Connection(self.srv(), auto_bind=True)
        self.assertEqual(c.server.info.other["defaultNamingContext"][0], "DC=corp,DC=ararat,DC=am")
        self.assertEqual(c.server.info.other["dnsHostName"][0], "dc01.corp.ararat.am")
        c.search("DC=corp,DC=ararat,DC=am", "(objectClass=user)", attributes=["sAMAccountName"])
        self.assertEqual(c.result["result"], 1)
        self.assertIn("000004DC", c.result["message"])
        self.assertTrue(self.em.of("ldap.rootdse"))

    def test_wrong_password_rejected_like_ad(self):
        import ldap3
        c = ldap3.Connection(self.srv(), user="ARARAT\\a.nobody", password="Winter2025!")
        self.assertFalse(c.bind())
        self.assertEqual(c.result["result"], 49)
        self.assertIn("data 52e", c.result["message"])
        self.assertTrue(any(e.get("username") == "a.nobody" for e in self.em.of("auth.failed")))

    def test_bait_bind_then_kerberoastable_users(self):
        import ldap3
        t = self.cred("svc_print")
        c = ldap3.Connection(self.srv(), user="ARARAT\\svc_print", password=t["password"])
        self.assertTrue(c.bind())
        ht = [e for e in self.em.of("honeytoken.used") if e.get("username") == "svc_print"]
        self.assertTrue(ht and ht[-1]["success"])
        c.search("DC=corp,DC=ararat,DC=am", "(&(objectClass=user)(servicePrincipalName=*))",
                 attributes=["sAMAccountName", "servicePrincipalName", "description"])
        users = {one(e["attributes"]["sAMAccountName"]): e for e in c.response if e["type"] == "searchResEntry"}
        self.assertIn("svc_sql", users)
        self.assertNotIn("Guest", users)
        self.assertIn(self.cred("svc_sql")["password"], one(users["svc_sql"]["attributes"]["description"]))
        c.search("DC=corp,DC=ararat,DC=am", "(sAMAccountName=svc_sql)", attributes=["*"])
        self.assertEqual([one(e["attributes"]["sAMAccountName"]) for e in c.response if e["type"] == "searchResEntry"], ["svc_sql"])
        c.search("DC=corp,DC=ararat,DC=am", "(objectCategory=computer)", attributes=["dNSHostName"])
        hosts = {one(e["attributes"]["dNSHostName"]) for e in c.response if e["type"] == "searchResEntry"}
        self.assertIn("fs01.corp.ararat.am", hosts)
        self.assertFalse(c.add("CN=evil,CN=Users,DC=corp,DC=ararat,DC=am", "user"))
        self.assertTrue(self.em.of("ldap.modify"))

    def test_ldaps_and_garbage(self):
        import ldap3
        c = ldap3.Connection(self.srv("ldaps", use_ssl=True), auto_bind=True)
        self.assertEqual(c.server.info.other["dnsHostName"][0], "dc01.corp.ararat.am")
        s = socket.create_connection(("127.0.0.1", self.p["ldap"]), timeout=3)
        s.sendall(b"\x30\x84\x7f\xff\xff\xff")                     # 2 GB length claim
        self.assertEqual(s.recv(10), b"")                           # dropped, no allocation
        s.close()


class TestKerberos(DCBase):
    def kdc(self):
        """impacket hard-codes port 88 → redirect it to the test KDC."""
        from impacket.krb5 import kerberosv5
        orig = socket.getaddrinfo
        port = self.p["krb"]

        def gai(host, p, *a, **k):
            return orig(host, port if p == 88 else p, *a, **k)
        kerberosv5.socket.getaddrinfo = gai
        self.addCleanup(setattr, kerberosv5.socket, "getaddrinfo", orig)

    def tgt(self, user, password="Spring2026!"):
        from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants
        self.kdc()
        try:
            getKerberosTGT(Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value), password,
                           "CORP.ARARAT.AM", b"", b"", None, "127.0.0.1")
        except KerberosError as e:
            return e.getErrorCode()
        return None

    def test_valid_user_gets_preauth_then_wrong_password(self):
        u = self.co["users"][0]["username"]
        self.assertEqual(self.tgt(u), 24)                           # 25 (with salt) → encrypted ts → 24
        reqs = [e for e in self.em.of("kerberos.as_req") if e.get("username") == u]
        self.assertEqual([r["result"] for r in reqs[-2:]], ["PREAUTH_REQUIRED", "PREAUTH_FAILED"])

    def test_unknown_user_and_disabled(self):
        self.assertEqual(self.tgt("no.such.user"), 6)
        self.assertEqual(self.tgt("krbtgt"), 18)

    def test_bait_user_and_kerberoasting_without_secret_are_attempts(self):
        # B15: a bait NAME (user list / wrong password / TGS without a TGT) is honeytoken.attempt (L4), never L5
        used = len(self.em.of("honeytoken.used"))
        self.tgt("svc_sql")
        self.assertTrue(any(e.get("username") == "svc_sql" for e in self.em.of("honeytoken.attempt")))
        self.assertEqual(scoring.score({"type": "honeytoken.attempt"}), 4)
        realm = "CORP.ARARAT.AM"
        req = ber.app(12, ber.seq(ber.ctx(1, ber.integer(5)), ber.ctx(2, ber.integer(12)),
                                  ber.ctx(4, ber.seq(ber.ctx(0, ber.tlv(0x03, b"\x00\x40\x81\x00\x10")),
                                                     ber.ctx(2, ber.gstring(realm)),
                                                     ber.ctx(3, principal(2, "MSSQLSvc", "dc01.corp.ararat.am:1433"))))))
        s = socket.create_connection(("127.0.0.1", self.p["krb"]), timeout=3)
        s.sendall(len(req).to_bytes(4, "big") + req)
        n = int.from_bytes(s.recv(4), "big")
        tag, _ = ber.one(s.recv(n))
        self.assertEqual(tag, 0x7E)                                 # KRB-ERROR
        s.close()
        self.assertTrue(any("honey SPN" in (e.get("desc") or "") for e in self.em.of("honeytoken.attempt")))
        self.assertEqual(len(self.em.of("honeytoken.used")), used)
        self.assertTrue(self.em.of("kerberos.tgs_req"))

    def test_common_names_are_not_honeytokens(self):
        before = len(self.em.of("honeytoken.used"))
        self.tgt("administrator")
        self.tgt("admin")
        self.assertEqual(len(self.em.of("honeytoken.used")), before)


class TestFakeShell(unittest.TestCase):
    def test_head_tail_counts_and_exit_keeps_output(self):
        from rpot.sensor.services.ssh import FakeShell

        class C:
            os, name = "Ubuntu 22.04.4 LTS", "DNS01"

            def emit(self, *a, **k):
                pass
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "home", "bob"))
            with open(os.path.join(d, "home", "bob", "f"), "w") as f:
                f.write("1\n2\n3\n4\n")
            sh = FakeShell(C(), "bob", d)
            self.assertEqual(sh.run("head -2 ~/f"), "1\n2\n")
            self.assertEqual(sh.run("head -n 1 ~/f"), "1\n")
            self.assertEqual(sh.run("tail -n1 ~/f"), "4\n")
            self.assertEqual(sh.run("tail -3 ~/f"), "2\n3\n4\n")
            self.assertEqual(sh.run("cat ~/f"), "1\n2\n3\n4\n")
            out = sh.run("hostname; exit")
            self.assertEqual(out.split("\x04")[0], "dns01\n")


class TestDNSRole(DCBase):
    def test_dns_role_baits_and_zone(self):
        t = self.cred("dnsadmin")
        self.assertEqual(t["valid_on"], ["DNS01:ssh"])
        self.assertIn("dnsadmin", open(os.path.join(self.tmp.name, "baits", "FS01", "shares", "IT", "passwords.txt")).read())
        ctx, _ = self.ctxs["DNS01"]
        self.assertEqual(ctx.cfg["zone"]["DC01"], "10.9.0.10")
        roles = load_roles()
        self.assertEqual([r["id"] for r in sorted(roles.values(), key=lambda r: r.get("order", 99))][-2:],
                         ["windows-domain-controller", "linux-dns-server"])


if __name__ == "__main__":
    unittest.main()
