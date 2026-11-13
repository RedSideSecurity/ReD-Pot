"""RC-29 (pentest F-03, T5-T7): the RDP decoy's TLS layer and X.224 negotiation look like Windows Server 2019.

What a real Windows Server 2019 (build 17763, default "Remote Desktop" self-signed certificate, NLA required)
shows, and where that comes from:

* X.224 negotiation, [MS-RDPBCGR] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
  - 2.2.1.1.1 RDP_NEG_REQ.requestedProtocols: PROTOCOL_RDP 0, SSL 1, HYBRID 2, RDSTLS 4, HYBRID_EX 8.
  - 2.2.1.2.1 RDP_NEG_RSP: type 0x02, flags, length 8, selectedProtocol.
  - 2.2.1.2.2 RDP_NEG_FAILURE: type 0x03, flags 0, length 8, failureCode; SSL_REQUIRED_BY_SERVER 1,
    SSL_NOT_ALLOWED_BY_SERVER 2, SSL_CERT_NOT_ON_SERVER 3, INCONSISTENT_FLAGS 4, HYBRID_REQUIRED_BY_SERVER 5,
    SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER 6. A server that requires NLA answers a client that does not offer
    CredSSP with HYBRID_REQUIRED_BY_SERVER and disconnects (3.3.5.3.1 server-side negotiation processing).
  - nmap 7.94 nmap-service-probes, probe TerminalServerCookie (requestedProtocols 3), "Windows 10" match:
    03 00 00 13 0e d0 00 00 12 34 00 02 1f 08 00 02 00 00 00 (CC, src-ref 0x1234, flags 0x1f, HYBRID).
    The same file notes "Windows RDP will handshake TLS immediately": TermService also accepts a bare TLS
    ClientHello on 3389, which is why nmap -sC shows ssl-cert / ssl-date for 3389 on real Windows hosts.
  - nmap rdp-enum-encryption.nse sends requestedProtocols 0 / 1 / 3 / 4 / 8 one by one; against an NLA-required
    Windows 10 / Server 2019 the usual output is "CredSSP (NLA): SUCCESS", "CredSSP with Early User Auth: SUCCESS",
    "RDSTLS: SUCCESS" (Native RDP and SSL fail with HYBRID_REQUIRED_BY_SERVER, shown with -d).
* TLS (Schannel on 17763):
  - Protocols: https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-
    TLS 1.0 / 1.1 / 1.2 enabled by default; TLS 1.3 first ships in Windows Server 2022 / Windows 11.
  - Cipher suites and default order:
    https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-10-v1809
    (ECDHE-ECDSA/RSA GCM, DHE-RSA GCM, ECDHE CBC SHA384/256, ECDHE CBC SHA, RSA GCM, RSA CBC SHA256, RSA CBC SHA,
    3DES), server preference, 2048-bit DHE.
* Certificate (TermService self-signed, as in public nmap ssl-cert outputs of 3389 and in the pentest's T6 row):
  subject = issuer = CN=<host FQDN> only, no SAN; RSA 2048 with sha256WithRSAEncryption; 16-byte serial;
  validity about 6 months (notAfter = notBefore + 183 days) and re-issued on expiry; extensions EKU Server
  Authentication + Key Usage Key Encipherment, Data Encipherment, nothing else.

Known residual differences (see the RC-29 report): Schannel puts the clock in the ServerHello random (nmap
ssl-date shows a time; OpenSSL's random does not), the OpenSSL build has no 3DES suite, and OpenSSL also offers the
x448 / secp521r1 groups that Schannel does not.
"""
import datetime
import os
import socket
import ssl
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from rpot import baits as B
from rpot.common import tlsutil
from rpot.sensor.services import catchers
from test_dc_dns import free_port
from test_sensor_services import ctx_for

# Connection Confirm bytes a Windows server sends (see module docstring).
CC_HYBRID_REQUIRED = bytes.fromhex("030000130ed000001234000300080005000000")
CC_SELECTED = {p: bytes.fromhex("030000130ed00000123400021f0800") + bytes([p, 0, 0, 0]) for p in (2, 4, 8)}


def load(crt):
    with open(crt, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def der_int_len(n):
    return n.bit_length() // 8 + 1        # DER INTEGER content length of a positive integer


class TestRdpCertificate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fqdn = "rs-fs-02.corp.redside-security.com"

    def test_windows_like_fields(self):
        crt, key = tlsutil.make_rdp_cert(self.tmp.name, self.fqdn)
        c = load(crt)
        cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.fqdn)])
        self.assertEqual((c.subject, c.issuer), (cn, cn))                    # CN only, self-signed
        self.assertEqual(c.version, x509.Version.v3)
        self.assertEqual(c.public_key().key_size, 2048)
        self.assertIsInstance(c.signature_hash_algorithm, hashes.SHA256)
        self.assertEqual(der_int_len(c.serial_number), 16)
        self.assertEqual(c.not_valid_after_utc - c.not_valid_before_utc, datetime.timedelta(days=183))
        now = datetime.datetime.now(datetime.timezone.utc)
        self.assertLess(c.not_valid_before_utc, now - datetime.timedelta(hours=1))   # backdated
        self.assertGreater(c.not_valid_after_utc, now)

    def test_only_eku_and_key_usage(self):
        c = load(tlsutil.make_rdp_cert(self.tmp.name, self.fqdn)[0])
        self.assertEqual([e.oid for e in c.extensions], [ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.KEY_USAGE])
        self.assertFalse(any(e.critical for e in c.extensions))
        self.assertEqual(list(c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                         [ExtendedKeyUsageOID.SERVER_AUTH])
        ku = c.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.key_encipherment and ku.data_encipherment)
        self.assertFalse(ku.digital_signature or ku.content_commitment or ku.key_agreement or ku.key_cert_sign
                         or ku.crl_sign)

    def test_per_install_key_kept_and_private(self):
        crt, key = tlsutil.make_rdp_cert(self.tmp.name, self.fqdn)
        first = load(crt)
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        self.assertEqual(load(tlsutil.make_rdp_cert(self.tmp.name, self.fqdn)[0]), first)      # reused
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        o = load(tlsutil.make_rdp_cert(other.name, self.fqdn)[0])
        self.assertNotEqual(o.public_key().public_numbers(), first.public_key().public_numbers())
        self.assertNotEqual(o.serial_number, first.serial_number)

    def test_expired_certificate_is_reissued(self):
        old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
        crt, _ = tlsutil.make_rdp_cert(self.tmp.name, self.fqdn, now=old)
        self.assertLess(load(crt).not_valid_after_utc, datetime.datetime.now(datetime.timezone.utc))
        renewed = load(tlsutil.make_rdp_cert(self.tmp.name, self.fqdn)[0])
        self.assertGreater(renewed.not_valid_after_utc, datetime.datetime.now(datetime.timezone.utc))


class TestRdpTlsContext(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ctx = tlsutil.rdp_server_context(cls.tmp.name, "rs-fs-02.corp.redside-security.com")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def handshake(self, cipher=None, version=None):
        a, b = socket.socketpair()
        a.settimeout(5)
        b.settimeout(5)
        out = {}

        def server():
            try:
                out["s"] = self.ctx.wrap_socket(a, server_side=True)
            except (ssl.SSLError, OSError) as e:
                out["err"] = e
        th = threading.Thread(target=server, daemon=True)
        th.start()
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            c.minimum_version = ssl.TLSVersion.TLSv1
            if version:
                c.minimum_version = c.maximum_version = version
        c.set_ciphers((cipher or "ALL") + ":@SECLEVEL=0")
        try:
            t = c.wrap_socket(b)
            return t.version(), t.cipher()[0]
        except (ssl.SSLError, OSError):
            return None, None
        finally:
            th.join(5)
            a.close()
            b.close()

    def test_no_tls13_max_tls12(self):
        self.assertEqual(self.handshake(version=ssl.TLSVersion.TLSv1_3), (None, None))
        self.assertEqual(self.handshake(), ("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384"))

    def test_tls10_and_11_still_offered(self):
        for v, name in ((ssl.TLSVersion.TLSv1, "TLSv1"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1")):
            got = self.handshake(version=v)
            if got == (None, None):
                self.skipTest("local OpenSSL client refuses TLS 1.0/1.1")
            self.assertEqual(got, (name, "ECDHE-RSA-AES256-SHA"))

    def test_server_preference_and_dhe(self):
        self.assertEqual(self.handshake("AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384")[1],
                         "ECDHE-RSA-AES256-GCM-SHA384")
        self.assertEqual(self.handshake("DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384")[1],
                         "DHE-RSA-AES256-GCM-SHA384")

    def test_schannel_2019_order(self):
        tls12 = [c["name"] for c in self.ctx.get_ciphers() if c["protocol"] != "TLSv1.3"]
        wanted = [n for n in tlsutil.SCHANNEL_2019_CIPHERS.split(":") if n in tls12]
        self.assertEqual(tls12, wanted)
        self.assertEqual(tls12[:6], ["ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
                                     "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
                                     "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256"])
        self.assertNotIn("ECDHE-RSA-CHACHA20-POLY1305", tls12)              # Schannel has no ChaCha20


class TestRdpSelect(unittest.TestCase):
    def test_nla_required_server_choice(self):
        sel = catchers.rdp_select
        self.assertEqual(sel(0), (None, 5))       # Standard RDP Security only
        self.assertEqual(sel(1), (None, 5))       # TLS without CredSSP
        self.assertEqual(sel(3), (2, None))       # mstsc / nmap -sV probe
        self.assertEqual(sel(0x0B), (2, None))    # nmap rdp-ntlm-info
        self.assertEqual(sel(4), (4, None))
        self.assertEqual(sel(8), (8, None))

    def test_confirm_bytes(self):
        self.assertEqual(catchers.rdp_confirm(3, 5), CC_HYBRID_REQUIRED)
        self.assertEqual(catchers.rdp_confirm(2, 2), CC_SELECTED[2])


class TestRdpWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        co = B.make_persona("corp.redside-security.com", "bank", seed=7)
        co["token_salt"] = "s4lt"
        sensors = [{"name": "RS-FS-02", "role": "windows-file-server", "ip": "10.9.0.20"}]
        tokens = B.generate({"company": co, "console": {}, "sensors": sensors}, os.path.join(cls.tmp.name, "baits"))
        cls.ctx, cls.em = ctx_for(cls.tmp.name, tokens, co, sensors, "RS-FS-02", "windows-file-server")
        cls.port = free_port()
        catchers.start_rdp(cls.ctx, {"port": cls.port})
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def cr(self, proto, cookie=b"Cookie: mstshash=nmap\r\n"):
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        body = cookie + (struct.pack("<BBHI", 1, 0, 8, proto) if proto is not None else b"")
        x224 = bytes([6 + len(body), 0xE0, 0, 0, 0, 0, 0]) + body
        s.sendall(struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224)
        return s, s.recv(64)

    def client_tls(self, s):
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        return c.wrap_socket(s)

    def test_standard_rdp_security_gets_hybrid_required_then_close(self):
        """T7: protocol 0 was closed silently ("Packet too short" in rdp-enum-encryption)."""
        for proto in (0, 1):
            s, cc = self.cr(proto)
            self.assertEqual(cc, CC_HYBRID_REQUIRED)
            self.assertEqual(s.recv(64), b"")                                  # server disconnects
            s.close()
        self.assertTrue(any(e.get("detail") == "neg.failure.hybrid_required" for e in self.em.of("proto.interaction")))

    def test_nla_rdstls_and_early_user_auth_accepted_over_tls12(self):
        for proto, sel in ((3, 2), (4, 4), (8, 8)):
            s, cc = self.cr(proto)
            self.assertEqual(cc, CC_SELECTED[sel])
            t = self.client_tls(s)
            self.assertEqual(t.version(), "TLSv1.2")                           # T5: was TLS 1.3
            t.close()
        self.assertIn("RDSTLS", self.em.of("rdp.connect")[-2]["protocols"])     # bit 4 = RDSTLS
        self.assertIn("HYBRID_EX", self.em.of("rdp.connect")[-1]["protocols"])  # bit 8 = HYBRID_EX

    def test_direct_tls_shows_windows_certificate(self):
        """T6 + nmap ssl-cert on 3389: a bare ClientHello gets the TermService-style certificate."""
        t = self.client_tls(socket.create_connection(("127.0.0.1", self.port), 5))
        c = x509.load_der_x509_certificate(t.getpeercert(binary_form=True))
        self.assertEqual(t.version(), "TLSv1.2")
        t.close()
        self.assertEqual(c.subject.rfc4514_string(), f"CN={self.ctx.fqdn}")
        self.assertEqual(der_int_len(c.serial_number), 16)
        with self.assertRaises(x509.ExtensionNotFound):
            c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertTrue(any(e.get("detail") == "tls.direct" for e in self.em.of("proto.interaction")))

    def test_no_negotiation_data_unchanged(self):
        s, cc = self.cr(None)
        self.assertEqual(cc, b"")
        s.close()


if __name__ == "__main__":
    unittest.main()
