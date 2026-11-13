"""Domain Controller decoy: real Kerberos tickets + NTLM LDAP binds for bait accounts (B4, B15) and the DC's
UDP services / Microsoft DNS persona (B6) — driven with impacket, ldap3, dnspython and the impacket CLI tools."""
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
import pytest
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dc_dns import DCBase, free_port                                     # noqa: E402
from rpot.console import scoring                                               # noqa: E402
from rpot.sensor.services import ber                                           # noqa: E402
from rpot.sensor.services.adauth import derive_keys                            # noqa: E402
from rpot.sensor.services.dcudp import nb_encode, start_cldap, start_nbns, start_ntp   # noqa: E402
from rpot.sensor.services.ldap import Directory, match                         # noqa: E402

REALM = "CORP.ARARAT.AM"


def nthash(pw):
    from impacket.ntlm import compute_nthash
    return compute_nthash(pw)


class ADBase(DCBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        dc, _ = cls.ctxs["DC01"]
        cls.p.update({k: free_port() for k in ("cldap", "nbns", "ntp")})
        start_cldap(dc, {"port": cls.p["cldap"]})
        start_nbns(dc, {"port": cls.p["nbns"]})
        start_ntp(dc, {"port": cls.p["ntp"]})
        time.sleep(0.2)

    def kdc(self):
        from impacket.krb5 import kerberosv5
        orig, port = socket.getaddrinfo, self.p["krb"]
        kerberosv5.socket.getaddrinfo = lambda h, p, *a, **k: orig(h, port if p == 88 else p, *a, **k)
        self.addCleanup(setattr, kerberosv5.socket, "getaddrinfo", orig)

    def ldap_port(self):
        from impacket.ldap import ldap as L
        orig, port = socket.getaddrinfo, self.p["ldap"]
        L.socket.getaddrinfo = lambda h, p, *a, **k: orig(h, port if p == 389 else p, *a, **k)
        self.addCleanup(setattr, L.socket, "getaddrinfo", orig)

    def tgt(self, user, password="", nt=b""):
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal
        self.kdc()
        return getKerberosTGT(Principal(user, type=1), password, REALM, b"", nt, "", "127.0.0.1")

    def krb_code(self, fn, *a, **k):
        from impacket.krb5.kerberosv5 import KerberosError
        try:
            fn(*a, **k)
        except KerberosError as e:
            return e.getErrorCode()
        return 0

    def since(self, n, t):
        return [e for e in self.em.events[n:] if e["type"] == t]


class TestBaitKeys(ADBase):
    def test_keys_planted_without_plaintext(self):
        p = os.path.join(self.tmp.name, "baits", "DC01", "ldap", "krb_keys.json")
        raw = open(p).read()
        d = json.loads(raw)
        self.assertEqual(d["realm"], REALM)
        for user in ("svc_sql", "svc_print", "srv_localadm", "svc_scan"):
            pw = self.cred(user)["password"]
            self.assertNotIn(pw, raw)
            self.assertEqual(d["accounts"][user]["keys"], derive_keys(user, pw, REALM))
            self.assertEqual(d["accounts"][user]["keys"]["23"], nthash(pw).hex())
        # the breadcrumb planner makes every domain bait account valid on the DC (dom_on); "valid": false is still
        # supported for accounts planted elsewhere (see test_no_access_bait_is_revoked_but_l5)
        self.assertTrue(all(a["valid"] for a in d["accounts"].values()))
        self.assertTrue(all(a["token"] in self.tokens for a in d["accounts"].values()))
        # RFC 3962 test vector: our hashlib PBKDF2 path == impacket's string_to_key
        from impacket.krb5.crypto import _enctype_table
        self.assertEqual(derive_keys("svc_x", "Pässw0rd!", "EX.COM")["18"],
                         _enctype_table[18].string_to_key("Pässw0rd!", "EX.COMsvc_x", None).contents.hex())


class TestKerberosTickets(ADBase):
    def test_correct_password_gets_tgt_and_l5(self):
        n = len(self.em.events)
        tgt, cipher, key, sk = self.tgt("svc_print", self.cred("svc_print")["password"])
        self.assertEqual(cipher.enctype, 18)                            # AES256, salt REALM+user
        used = self.since(n, "honeytoken.used")
        self.assertTrue(used and used[-1]["success"] and used[-1]["username"] == "svc_print")
        self.assertTrue(self.since(n, "auth.success"))
        _, c2, _, _ = self.tgt("svc_print", nt=nthash(self.cred("svc_print")["password"]))   # pass-the-hash → RC4 TGT
        self.assertEqual(c2.enctype, 23)

    def test_wrong_password_is_auth_failed_and_attempt_not_l5(self):
        n = len(self.em.events)
        self.assertEqual(self.krb_code(self.tgt, "svc_sql", "Winter2026!"), 24)
        self.assertFalse(self.since(n, "honeytoken.used"))
        self.assertTrue(any(e["username"] == "svc_sql" for e in self.since(n, "auth.failed")))
        self.assertTrue(any(e["username"] == "svc_sql" for e in self.since(n, "honeytoken.attempt")))

    @pytest.mark.slow
    def test_spraying_over_kerberos_escalates(self):
        sc, ev = scoring.Scorer(), []
        n = len(self.em.events)
        for u in [x["username"] for x in self.co["users"][:5]]:
            self.assertEqual(self.krb_code(self.tgt, u, "Autumn2026!"), 24)
        for e in self.since(n, "auth.failed"):
            ev += sc.escalations({"ts": "t", "type": "auth.failed", "src_ip": "10.1.1.1", "data": e})
        self.assertTrue(any(x["type"] == "auth.bruteforce" and x["data"]["kind"] == "password spraying" for x in ev))

    def test_asrep_roast_user_list_is_only_attempt(self):
        """B15: GetNPUsers-style AS-REQ without pre-auth for a honey user → PREAUTH_REQUIRED, L4 at most."""
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AS_REQ, KRB_ERROR
        from impacket.krb5.kerberosv5 import sendReceive
        from impacket.krb5.types import KerberosTime, Principal
        from impacket.krb5.asn1 import seq_set, seq_set_iter
        from pyasn1.codec.der import encoder
        import datetime
        self.kdc()
        n = len(self.em.events)
        req = AS_REQ()
        req["pvno"], req["msg-type"] = 5, 10
        body = seq_set(req, "req-body")
        body["kdc-options"] = constants.encodeFlags([1, 8, 3])
        seq_set(body, "sname", Principal(f"krbtgt/{REALM}", type=2).components_to_asn1)
        seq_set(body, "cname", Principal("svc_sql", type=1).components_to_asn1)
        body["realm"] = REALM
        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        body["till"] = body["rtime"] = KerberosTime.to_asn1(now)
        body["nonce"] = 1234
        seq_set_iter(body, "etype", (23,))
        from pyasn1.codec.der import decoder
        r = sendReceive(encoder.encode(req), REALM, "127.0.0.1")       # PREAUTH_REQUIRED is returned, not raised
        self.assertEqual(int(decoder.decode(r, asn1Spec=KRB_ERROR())[0]["error-code"]), 25)
        self.assertFalse(self.since(n, "honeytoken.used"))
        att = [x for x in self.em.events if x["type"] == "honeytoken.attempt" and x["username"] == "svc_sql"]
        self.assertTrue(att)
        self.assertLessEqual(max(scoring.score(x) for x in self.em.events[n:]), 4)

    def test_no_access_bait_is_revoked_but_l5(self):
        """A bait account the DC knows but that has no access here (krb_keys "valid": false): the right password
        → KDC_ERR_CLIENT_REVOKED, still L5. The planner gives every domain account access, so mark one invalid."""
        from rpot.sensor.services import adauth
        orig = adauth.BaitKeys.get
        adauth.BaitKeys.get = lambda kb, u: (lambda a: dict(a, valid=False) if a and (u or "").lower() == "svc_scan" else a)(orig(kb, u))
        self.addCleanup(setattr, adauth.BaitKeys, "get", orig)
        n = len(self.em.events)
        self.assertEqual(self.krb_code(self.tgt, "svc_scan", self.cred("svc_scan")["password"]), 18)
        used = self.since(n, "honeytoken.used")
        self.assertTrue(used and used[-1]["success"] is False)          # right secret → L5, but no ticket

    def test_kerberoast_honey_spn_cracks_to_bait_password(self):
        from impacket.krb5.asn1 import TGS_REP
        from impacket.krb5.crypto import Key, _enctype_table
        from impacket.krb5.kerberosv5 import getKerberosTGS
        from impacket.krb5.types import Principal
        from pyasn1.codec.der import decoder
        tgt, cipher, _, sk = self.tgt("svc_print", nt=nthash(self.cred("svc_print")["password"]))
        n = len(self.em.events)
        for sp in (Principal(f"MSSQLSvc/dc01.corp.ararat.am:1433", type=2), Principal()):
            if not sp.components:                                    # GetUserSPNs: NT-ENTERPRISE DOMAIN\account
                sp.type, sp.components = 10, ["corp.ararat.am\\svc_sql"]
            r, _, _, _ = getKerberosTGS(sp, REALM, "127.0.0.1", tgt, cipher, sk)
            enc = decoder.decode(r, asn1Spec=TGS_REP())[0]["ticket"]["enc-part"]
            self.assertEqual(int(enc["etype"]), 23)                     # $krb5tgs$23$
            _enctype_table[23].decrypt(Key(23, nthash(self.cred("svc_sql")["password"])), 2, enc["cipher"].asOctets())
            with self.assertRaises(Exception):
                _enctype_table[23].decrypt(Key(23, nthash("Wrong1!")), 2, enc["cipher"].asOctets())
        used = [e for e in self.since(n, "honeytoken.used") if "Kerberoasting" in e["desc"]]
        self.assertEqual(len(used), 2)
        self.assertEqual(used[0]["username"], "svc_sql")

    def test_other_spns_and_forged_tgt(self):
        from impacket.krb5.kerberosv5 import getKerberosTGS
        from impacket.krb5.types import Principal
        tgt, cipher, _, sk = self.tgt("svc_print", self.cred("svc_print")["password"])
        code = self.krb_code(getKerberosTGS, Principal("cifs/sql99.corp.ararat.am", type=2), REALM, "127.0.0.1", tgt, cipher, sk)
        self.assertEqual(code, 7)                                       # S_PRINCIPAL_UNKNOWN
        self.assertEqual(self.krb_code(getKerberosTGS, Principal("cifs/dc01.corp.ararat.am", type=2), REALM, "127.0.0.1",
                                       tgt, cipher, sk), 0)             # decoy computer SPN: issued
        from impacket.krb5.crypto import Key
        bad = Key(sk.enctype, bytes(len(sk.contents)))                 # wrong session key → authenticator invalid
        self.assertEqual(self.krb_code(getKerberosTGS, Principal("cifs/dc01.corp.ararat.am", type=2), REALM, "127.0.0.1",
                                       tgt, cipher, bad), 41)

    def test_udp_ticket_reply_is_too_big(self):
        from rpot.sensor.services.kerberos import KDC
        dc, _ = self.ctxs["DC01"]
        kdc = KDC(dc)
        captured = []
        from impacket.krb5 import kerberosv5
        orig = kerberosv5.sendReceive

        def grab(data, *a, **k):
            captured.append(data)
            return orig(data, *a, **k)
        kerberosv5.sendReceive = grab
        self.addCleanup(setattr, kerberosv5, "sendReceive", orig)
        self.tgt("svc_print", self.cred("svc_print")["password"])
        r = kdc.handle(captured[-1], ("10.0.0.5", 1000), 88, "kerberos", udp=True)
        tag, v = ber.one(r)
        self.assertEqual(tag, 0x7E)
        self.assertEqual(ber.as_int(ber.find(v[0][1], 0xA6)[0][1]), 52)


class TestLDAPNTLM(ADBase):
    def test_impacket_sasl_sealed_bind_and_getuserspns_search(self):
        from impacket.ldap import ldap as L, ldapasn1
        self.ldap_port()
        n = len(self.em.events)
        c = L.LDAPConnection("ldap://127.0.0.1", "DC=corp,DC=ararat,DC=am")       # GSS-SPNEGO NTLM + sealing
        c.login("svc_print", self.cred("svc_print")["password"], "corp.ararat.am")
        used = self.since(n, "honeytoken.used")
        self.assertTrue(used and used[-1]["success"])
        r = c.search(searchFilter="(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)"
                                  "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))",
                     attributes=["servicePrincipalName", "sAMAccountName", "memberOf"], sizeLimit=100000)
        names = {str(e["attributes"][a]["vals"][0]) for e in r if isinstance(e, ldapasn1.SearchResultEntry)
                 for a in range(len(e["attributes"])) if str(e["attributes"][a]["type"]) == "sAMAccountName"}
        self.assertIn("svc_sql", names)
        self.assertNotIn("krbtgt", names)                               # disabled: (!(UAC:803:=2)) is honoured
        for _ in range(2):                                              # the sealed stream stays in sync
            r = c.search(searchFilter="(sAMAccountName=svc_sql)", attributes=["sAMAccountName"])
            self.assertEqual(len([e for e in r if isinstance(e, ldapasn1.SearchResultEntry)]), 1)

    def test_wrong_ntlm_password_is_invalid_credentials(self):
        from impacket.ldap import ldap as L
        self.ldap_port()
        n = len(self.em.events)
        c = L.LDAPConnection("ldap://127.0.0.1", "DC=corp,DC=ararat,DC=am")
        with self.assertRaises(L.LDAPSessionError) as e:
            c.login("svc_sql", "Winter2026!", "corp.ararat.am")
        self.assertIn("invalidCredentials", str(e.exception))
        self.assertFalse(self.since(n, "honeytoken.used"))
        self.assertTrue(self.since(n, "auth.failed") and self.since(n, "honeytoken.attempt"))

    def test_sicily_binds(self):
        import ldap3
        from impacket.ldap import ldap as L
        self.ldap_port()
        c = L.LDAPConnection("ldap://127.0.0.1", "DC=corp,DC=ararat,DC=am", signing=False)
        c.login("svc_print", self.cred("svc_print")["password"], "ARARAT", authenticationChoice="sicilyNegotiate")
        lm = "aad3b435b51404eeaad3b435b51404ee:"                       # ldap3 NTLM (NetExec): hash form, no MD4 needed
        s = ldap3.Server("127.0.0.1", port=self.p["ldap"], connect_timeout=3)
        lc = ldap3.Connection(s, user="ARARAT\\svc_sql", password=lm + nthash(self.cred("svc_sql")["password"]).hex(),
                              authentication=ldap3.NTLM)
        self.assertTrue(lc.bind())
        lc.search("DC=corp,DC=ararat,DC=am", "(&(objectClass=user)(servicePrincipalName=*))", attributes=["servicePrincipalName"])
        self.assertIn("CN=SQL Service,CN=Users,DC=corp,DC=ararat,DC=am", [e.entry_dn for e in lc.entries])
        lc = ldap3.Connection(s, user="ARARAT\\j.smith", password=lm + "00" * 16, authentication=ldap3.NTLM)
        self.assertFalse(lc.bind())
        self.assertEqual(lc.result["result"], 49)

    def test_challenge_has_persona_target_info(self):
        from impacket import ntlm
        from rpot.sensor.services.adauth import NTLMServer, BaitKeys
        dc, _ = self.ctxs["DC01"]
        neg = ntlm.getNTLMSSPType1("", "", signingRequired=True, use_ntlmv2=True)
        ch = ntlm.NTLMAuthChallenge(NTLMServer(dc, BaitKeys(dc.bait_dir)).challenge(neg.getData()))
        av = ntlm.AV_PAIRS(ch["TargetInfoFields"])
        self.assertEqual(av[ntlm.NTLMSSP_AV_HOSTNAME][1].decode("utf-16le"), "DC01")
        self.assertEqual(av[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode("utf-16le"), "ARARAT")
        self.assertEqual(av[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode("utf-16le"), "dc01.corp.ararat.am")
        self.assertEqual(ch["Version"][:4], bytes([10, 0]) + struct.pack("<H", 17763))
        for bad in (b"", b"NTLMSSP\x00\x01", os.urandom(40)):
            with self.assertRaises(ValueError):
                NTLMServer(dc, BaitKeys(dc.bait_dir)).challenge(bad)

    def test_filter_evaluation(self):
        dc, _ = self.ctxs["DC01"]
        d = Directory(dc)
        eq = lambda a, v: (0xA3, [(0x04, a.encode()), (0x04, v.encode())])
        pres = lambda a: (0x87, a.encode())
        sub = lambda a, *parts: (0xA4, [(0x04, a.encode()), (0x30, list(parts))])
        ext = lambda a, bits: (0xA9, [(0x81, b"1.2.840.113556.1.4.803"), (0x82, a.encode()), (0x83, str(bits).encode())])
        names = lambda f: {a.get("sAMAccountName") for _, a in d.search(d.base, 2, f)}
        self.assertEqual(names(eq("sAMAccountName", "SVC_SQL")), {"svc_sql"})
        self.assertEqual(names(sub("sAMAccountName", (0x80, b"svc_"), (0x82, b"l"))), {"svc_sql"})
        self.assertIn("DC01$", names(eq("objectCategory", "computer")))
        self.assertNotIn("DC01$", names(eq("objectCategory", "person")))
        self.assertIn("Guest", names(ext("userAccountControl", 2)))
        self.assertNotIn("Guest", names((0xA2, [ext("userAccountControl", 2)])))
        self.assertIn(self.co["users"][0]["username"], names((0xA0, [pres("mail"), eq("objectClass", "user")])))
        self.assertNotIn("svc_sql", names(pres("mail")))
        self.assertEqual(len(d.search(d.base, 0, pres("objectClass"))), 1)        # base scope: the domain object
        self.assertIsNone(d.search("DC=evil,DC=com", 2, pres("objectClass")))
        self.assertFalse(match((0xA0, [(0xA3, [])]), {}))                         # malformed → no match, no crash


class TestDCUDP(ADBase):
    def udp(self, port, data):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(data, ("127.0.0.1", port))
        try:
            return s.recvfrom(4096)[0]
        finally:
            s.close()

    def cldap(self, *eqs, attrs=("NetLogon",)):
        f = ber.tlv(0xA0, b"".join(ber.tlv(0xA3, ber.octets(a) + ber.octets(v)) for a, v in eqs))
        req = ber.seq(ber.integer(7), ber.app(3, ber.octets("") + ber.enum(0) + ber.enum(0) + ber.integer(0) + ber.integer(0)
                                              + ber.tlv(0x01, b"\x00") + f + ber.seq(*[ber.octets(a) for a in attrs])))
        return self.udp(self.p["cldap"], req)

    @staticmethod
    def names(buf, pos, count):
        """Decode `count` compressed DNS names from a NETLOGON structure."""
        out = []
        for _ in range(count):
            labels, p, jumped, end = [], pos, False, None
            while True:
                n = buf[p]
                if n == 0:
                    p += 1
                    break
                if n & 0xC0:
                    if not jumped:
                        end = p + 2
                    p, jumped = struct.unpack(">H", buf[p:p + 2])[0] & 0x3FFF, True
                    continue
                labels.append(buf[p + 1:p + 1 + n].decode())
                p += 1 + n
            out.append(".".join(labels))
            pos = end if jumped else p
        return out, pos

    def netlogon(self, raw):
        _, msg = ber.one(raw)
        entry = msg[1][1]
        return bytes(entry[1][1][0][1][1][1][0][1])

    def test_cldap_netlogon_ping(self):
        raw = self.cldap(("DnsDomain", b"corp.ararat.am"), ("NtVer", b"\x06\x00\x00\x00"))
        self.assertIn(b"\x84", raw[:2])                                  # Windows-style 4-byte lengths
        nl = self.netlogon(raw)
        opcode, _, flags = struct.unpack("<HHI", nl[:8])
        self.assertEqual(opcode, 23)                                     # LOGON_SAM_LOGON_RESPONSE_EX
        self.assertTrue(flags & 0x1 and flags & 0x20 and flags & 0x4)    # PDC, KDC, GC
        names, pos = self.names(nl, 24, 8)
        self.assertEqual(names, ["corp.ararat.am", "corp.ararat.am", "dc01.corp.ararat.am", "ARARAT", "DC01", "",
                                 "Default-First-Site-Name", "Default-First-Site-Name"])
        self.assertEqual(struct.unpack("<IHH", nl[pos:pos + 8]), (5, 0xFFFF, 0xFFFF))
        self.assertTrue(self.em.of("cldap.ping"))
        self.assertEqual(scoring.score({"type": "cldap.ping"}), 2)

    def test_cldap_user_enum_and_foreign_domain(self):
        nl = self.netlogon(self.cldap(("DnsDomain", b"corp.ararat.am"), ("User", b"nobody.x"), ("NtVer", b"\x06\x00\x00\x00")))
        self.assertEqual(struct.unpack("<H", nl[:2])[0], 25)             # USER_UNKNOWN_EX
        nl = self.netlogon(self.cldap(("DnsDomain", b"corp.ararat.am"), ("User", b"svc_sql"), ("NtVer", b"\x16\x00\x00\x00")))
        self.assertEqual(struct.unpack("<H", nl[:2])[0], 23)
        _, msg = ber.one(self.cldap(("DnsDomain", b"other.example"), ("NtVer", b"\x06\x00\x00\x00")))
        self.assertEqual(msg[1][0], 0x65)                                # searchResDone only
        rd = self.cldap(("objectClass", b"*"), attrs=())                 # rootDSE: capped, no amplification
        self.assertLessEqual(len(rd), 512)
        self.assertIn(b"defaultNamingContext", rd)
        self.assertEqual(ber.decode(rd)[-1][1][1][0], 0x65)

    @pytest.mark.slow
    def test_nbns_node_status_and_name_query(self):
        q = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0) + nb_encode("*", 0) + struct.pack(">HH", 0x21, 1)
        r = self.udp(self.p["nbns"], q)
        self.assertEqual(struct.unpack(">HH", r[:4]), (0x1234, 0x8400))
        rd = r[12 + 34 + 10:]
        names = [(rd[1 + i * 18:16 + i * 18].rstrip(b" ").decode(), rd[16 + i * 18]) for i in range(rd[0])]
        self.assertIn(("DC01", 0x20), names)
        self.assertIn(("ARARAT", 0x1C), names)
        from rpot.sensor.services.dcudp import nb_mac          # RC-27 F-05: the decoy NIC's MAC, no fixed prefix
        self.assertEqual(rd[1 + rd[0] * 18:7 + rd[0] * 18], nb_mac(self.ctxs["DC01"][0]))
        self.assertNotEqual(rd[1 + rd[0] * 18:4 + rd[0] * 18], b"\x00\x15\x5d")
        q = struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + nb_encode("DC01", 0x20) + struct.pack(">HH", 0x20, 1)
        r = self.udp(self.p["nbns"], q)
        self.assertEqual(r[-4:], socket.inet_aton("127.0.0.1"))
        q = struct.pack(">HHHHHH", 8, 0x0100, 1, 0, 0, 0) + nb_encode("NOTME", 0x20) + struct.pack(">HH", 0x20, 1)
        with self.assertRaises(socket.timeout):
            self.udp(self.p["nbns"], q)
        st = [e for e in self.em.of("nbns.query") if e.get("kind") == "status"]
        self.assertTrue(st)
        self.assertEqual(scoring.score({"type": "nbns.query", "data": st[0]}), 2)

    def test_ntp_server_reply(self):
        req = bytes([0x23]) + b"\x00" * 39 + b"ORIGINTS"                 # v4 client
        r = self.udp(self.p["ntp"], req)
        self.assertEqual(len(r), 48)
        self.assertEqual((r[0] & 7, (r[0] >> 3) & 7, r[1]), (4, 4, 3))  # server, v4, stratum 3
        self.assertEqual(r[24:32], b"ORIGINTS")
        t = struct.unpack(">I", r[40:44])[0] - 2208988800
        self.assertLess(abs(t - time.time()), 5)
        self.assertTrue(self.em.of("ntp.query"))

    def test_roles_list_udp_services(self):
        from rpot.common.config import load_roles
        svcs = {(s["type"], s["port"]) for s in load_roles()["windows-domain-controller"]["services"]}
        self.assertTrue({("cldap", 389), ("nbns", 137), ("ntp", 123)} <= svcs)
        from rpot.sensor.main import _starters
        self.assertTrue({"cldap", "nbns", "ntp"} <= set(_starters()))


VENV_BIN = os.path.dirname(sys.executable)


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0 and os.path.exists(os.path.join(VENV_BIN, "GetUserSPNs.py")),
                     "needs root (tools use ports 88/389) and the impacket example scripts")
class TestImpacketCLI(ADBase):
    """The real attacker command lines against the decoy on a private loopback address."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        dc, _ = cls.ctxs["DC01"]
        from rpot.sensor.services.kerberos import start_kerberos
        from rpot.sensor.services.ldap import start_ldap
        for _ in range(20):
            ip = f"127.0.{random.randint(1, 250)}.{random.randint(2, 250)}"
            try:
                for t in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    for port in (88, 389):
                        s = socket.socket(socket.AF_INET, t)
                        s.bind((ip, port))
                        s.close()
                break
            except OSError:
                continue
        cls.ip = ip
        os.environ["RPOT_BIND_IP"] = ip
        try:
            start_kerberos(dc, {"port": 88})
            start_ldap(dc, {"port": 389})
        finally:
            os.environ.pop("RPOT_BIND_IP", None)
        time.sleep(0.2)

    def run_tool(self, *args, env=None):
        r = subprocess.run([sys.executable, os.path.join(VENV_BIN, args[0])] + list(args[1:]), capture_output=True, text=True,
                           timeout=120, cwd=self.tmp.name, env=dict(os.environ, **(env or {})))
        return r.stdout + r.stderr

    @pytest.mark.slow
    def test_getuserspns_request_getadusers_gettgt_getst(self):
        pp, sp = self.cred("svc_print")["password"], self.cred("svc_sql")["password"]
        out = self.run_tool("GetUserSPNs.py", f"corp.ararat.am/svc_print:{pp}", "-dc-ip", self.ip, "-request")
        self.assertIn("MSSQLSvc/dc01.corp.ararat.am:1433", out)
        line = next(x for x in out.splitlines() if x.startswith("$krb5tgs$23$*svc_sql$"))
        from impacket.krb5.crypto import Key, _enctype_table
        p = line.split("$")
        _enctype_table[23].decrypt(Key(23, nthash(sp)), 2, bytes.fromhex(p[6]) + bytes.fromhex(p[7]))   # cracks to bait pw
        out = self.run_tool("GetADUsers.py", f"corp.ararat.am/svc_print:{pp}", "-dc-ip", self.ip, "-all")
        self.assertIn("svc_sql", out)
        self.assertIn("Saving ticket", self.run_tool("getTGT.py", f"corp.ararat.am/svc_print:{pp}", "-dc-ip", self.ip))
        out = self.run_tool("getST.py", "-k", "-no-pass", "-spn", "MSSQLSvc/dc01.corp.ararat.am:1433", "-dc-ip", self.ip,
                            "corp.ararat.am/svc_print", env={"KRB5CCNAME": os.path.join(self.tmp.name, "svc_print.ccache")})
        self.assertIn("Saving ticket", out)
        self.assertIn("PREAUTH_FAILED", self.run_tool("getTGT.py", "corp.ararat.am/svc_print:Wrong123!", "-dc-ip", self.ip))
        with open(os.path.join(self.tmp.name, "users.txt"), "w") as f:
            f.write("svc_sql\nj.nobody\n")
        out = self.run_tool("GetNPUsers.py", "corp.ararat.am/", "-usersfile", "users.txt", "-dc-ip", self.ip, "-no-pass")
        self.assertIn("doesn't have UF_DONT_REQUIRE_PREAUTH", out)


if __name__ == "__main__":
    unittest.main()
