"""RC-30 (pentest F-03 T6 class): the DC's LDAPS / GC-over-SSL and the web decoy's HTTPS look like the claimed OS.

What a real Windows Server 2019 DC shows on 636 / 3269, and where that comes from:

* Certificate: auto-enrolled from the domain's AD CS enterprise CA with the v1 "Domain Controller" template
  (MS Learn "Certificate templates" / "Domain Controller" template: subject built from the DNS name, EKU Client
  Authentication + Server Authentication, template name extension szOID_ENROLL_CERTTYPE_EXTENSION
  1.3.6.1.4.1.311.20.2 = BMPString "DomainController", SAN otherName 1.3.6.1.4.1.311.25.1 = objectGUID of the
  DC computer object + DNS name, 1-year validity, renewed by autoenrollment).
  - Default CA name when the CA role is added on the DC: "<first domain label>-<HOSTNAME>-CA", subject CN plus
    DC= components (AD CS setup wizard default; e.g. public nmap ssl-cert outputs of DC 636/3269 such as
    "Issuer: commonName=sequel-DC-CA/domainComponent=sequel",
    "Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb").
  - Default AD CS CDP/AIA: ldap:///CN=<CA>,CN=<host>,CN=CDP,CN=Public Key Services,CN=Services,<config>
    ?certificateRevocationList?base?objectClass=cRLDistributionPoint and ldap:///CN=<CA>,CN=AIA,...
    ?cACertificate?base?objectClass=certificationAuthority (MS Learn "Configure CDP and AIA extensions").
  - KB5014754 (May 2022+ CA): certificates built from AD info carry szOID_NTDS_CA_SECURITY_EXT
    1.3.6.1.4.1.311.25.2 with the account SID (otherName 1.3.6.1.4.1.311.25.2.1, OCTET STRING "S-1-5-21-...").
  - AD CS serial numbers are 19 bytes with request-ID framing; the root CA cert has szOID_CERTSRV_CA_VERSION
    1.3.6.1.4.1.311.21.1, BasicConstraints CA:TRUE critical, KeyUsage digitalSignature|keyCertSign|cRLSign.
* TLS: Schannel on 17763, the same profile as RC-29's RDP layer (TLS 1.0-1.2, no 1.3, 2019 cipher order,
  server preference, 2048-bit DHE): MS Learn "Protocols in TLS/SSL (Schannel SSP)" and
  "TLS Cipher Suites in Windows 10 v1809".
* A real DC serves both 636 (LDAPS) and 3269 (Global Catalog over SSL) with this certificate
  (MS Learn "Active Directory and Active Directory Domain Services port requirements").

The Linux web decoy (Apache/2.4.52 (Ubuntu)) keeps a Linux profile on purpose (not the DC's template):
Ubuntu 22.04 ssl-cert "snakeoil" certificate (make-ssl-cert: CN = hostname -f, SAN DNS:<name>, CA:FALSE,
openssl req -x509 -days 3650), mod_ssl defaults of the Ubuntu package (SSLCipherSuite HIGH:!aNULL,
SSLProtocol all -SSLv3, SSLHonorCipherOrder off) on OpenSSL 3.0 at SECLEVEL 2 (no TLS 1.0/1.1).
"""
import datetime
import json
import os
import socket
import ssl
import stat
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
from rpot.sensor import base
from test_dc_dns import free_port
from test_sensor_services import ctx_for

FQDN, DOMAIN, HOST = "rs-dc-01.corp.redside-security.com", "corp.redside-security.com", "RS-DC-01"
GUID = bytes(range(16))
SID = "S-1-5-21-1111111111-2222222222-3333333333-1000"
NOW = lambda: datetime.datetime.now(datetime.timezone.utc)  # noqa: E731


def load(crt):
    with open(crt, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def der_int_len(n):
    return n.bit_length() // 8 + 1


def ext(c, dotted):
    return c.extensions.get_extension_for_oid(x509.ObjectIdentifier(dotted))


class TestEnterpriseCA(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_adcs_root_ca_profile(self):
        crt, key = tlsutil.make_enterprise_ca(self.tmp.name, DOMAIN, HOST)
        c = load(crt)
        self.assertEqual(tlsutil.adcs_ca_name(DOMAIN, HOST), "corp-RS-DC-01-CA")
        self.assertEqual(c.subject.rfc4514_string(), "CN=corp-RS-DC-01-CA,DC=corp,DC=redside-security,DC=com")
        self.assertEqual(c.subject, c.issuer)
        self.assertEqual(c.public_key().key_size, 2048)
        self.assertIsInstance(c.signature_hash_algorithm, hashes.SHA256)
        self.assertEqual(der_int_len(c.serial_number), 16)
        bc = c.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(bc.critical and bc.value.ca)
        ku = c.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature and ku.key_cert_sign and ku.crl_sign)
        self.assertEqual(ext(c, tlsutil.OID_CA_VERSION).value.value, b"\x02\x01\x00")
        c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        self.assertLess(c.not_valid_before_utc, NOW() - datetime.timedelta(days=299))      # installed long ago
        self.assertGreater((c.not_valid_after_utc - c.not_valid_before_utc).days, 5 * 365 - 1)
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)

    def test_ca_kept_per_install(self):
        first = load(tlsutil.make_enterprise_ca(self.tmp.name, DOMAIN, HOST)[0])
        self.assertEqual(load(tlsutil.make_enterprise_ca(self.tmp.name, DOMAIN, HOST)[0]), first)
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        o = load(tlsutil.make_enterprise_ca(other.name, DOMAIN, HOST)[0])
        self.assertEqual(o.subject, first.subject)
        self.assertNotEqual(o.public_key().public_numbers(), first.public_key().public_numbers())


class TestDcCertificate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.crt, self.key, self.ca_crt = tlsutil.make_dc_ldaps_cert(self.tmp.name, FQDN, DOMAIN, HOST,
                                                                     object_guid=GUID, sid=SID)
        self.c, self.ca = load(self.crt), load(self.ca_crt)

    def test_issued_by_enterprise_ca(self):
        c, ca = self.c, self.ca
        self.assertEqual(c.subject, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, FQDN)]))
        self.assertEqual(c.issuer, ca.subject)
        c.verify_directly_issued_by(ca)                                             # signature + names
        self.assertEqual(c.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,
                         ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
        self.assertEqual(c.public_key().key_size, 2048)
        self.assertIsInstance(c.signature_hash_algorithm, hashes.SHA256)
        self.assertEqual(stat.S_IMODE(os.stat(self.key).st_mode), 0o600)

    def test_serial_and_validity(self):
        c = self.c
        self.assertEqual(der_int_len(c.serial_number), 19)
        raw = c.serial_number.to_bytes(19, "big")
        self.assertEqual(raw[1:4], b"\0\0\0")
        self.assertEqual(raw[14:18], b"\0\0\0\0")
        nb, na = c.not_valid_before_utc, c.not_valid_after_utc
        self.assertIn((na - nb).days, (365, 366))                                   # 1 year
        self.assertLess(nb, NOW() - datetime.timedelta(hours=1))                     # backdated
        self.assertGreater(na, NOW())
        self.assertGreater(nb, self.ca.not_valid_before_utc)
        self.assertLessEqual(na, self.ca.not_valid_after_utc)

    def test_domain_controller_template_extensions(self):
        c = self.c
        self.assertEqual([e.oid.dotted_string for e in c.extensions], [
            tlsutil.OID_TEMPLATE_NAME, ExtensionOID.EXTENDED_KEY_USAGE.dotted_string,
            ExtensionOID.KEY_USAGE.dotted_string, tlsutil.OID_SMIME_CAPS,
            ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string, ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string,
            ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string, ExtensionOID.AUTHORITY_INFORMATION_ACCESS.dotted_string,
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string, tlsutil.OID_NTDS_CA_SECURITY])
        self.assertEqual(ext(c, tlsutil.OID_TEMPLATE_NAME).value.value,
                         b"\x1e\x20" + "DomainController".encode("utf-16-be"))
        self.assertEqual(list(c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                         [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH])
        ku = c.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(ku.critical and ku.value.digital_signature and ku.value.key_encipherment)
        self.assertFalse(ku.value.data_encipherment or ku.value.key_cert_sign)
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), [FQDN])
        on = san.get_values_for_type(x509.OtherName)
        self.assertEqual([(o.type_id.dotted_string, o.value) for o in on], [(tlsutil.OID_DS_GUID, b"\x04\x10" + GUID)])
        cdp = c.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value
        self.assertEqual(cdp, "ldap:///CN=corp-RS-DC-01-CA,CN=RS-DC-01,CN=CDP,CN=Public%20Key%20Services,CN=Services,"
                              "CN=Configuration,DC=corp,DC=redside-security,DC=com?certificateRevocationList?base"
                              "?objectClass=cRLDistributionPoint")
        aia = c.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value[0]
        self.assertTrue(aia.access_location.value.startswith("ldap:///CN=corp-RS-DC-01-CA,CN=AIA,"))
        sid = ext(c, tlsutil.OID_NTDS_CA_SECURITY).value.value
        self.assertTrue(sid.startswith(bytes.fromhex("3040a03e060a2b060104018237190201a030042e")))
        self.assertTrue(sid.endswith(SID.encode()))

    def test_reused_then_reissued_on_expiry_or_rename(self):
        self.assertEqual(load(tlsutil.make_dc_ldaps_cert(self.tmp.name, FQDN, DOMAIN, HOST, GUID, SID)[0]), self.c)
        renamed = load(tlsutil.make_dc_ldaps_cert(self.tmp.name, "dc02." + DOMAIN, DOMAIN, HOST, GUID, SID)[0])
        self.assertNotEqual(renamed, self.c)
        self.assertEqual(renamed.issuer, self.ca.subject)
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        old = NOW() - datetime.timedelta(days=500)
        crt, _, ca_crt = tlsutil.make_dc_ldaps_cert(other.name, FQDN, DOMAIN, HOST, now=old)
        self.assertLess(load(crt).not_valid_after_utc, NOW())
        ca_before = load(ca_crt)
        crt, _, ca_crt = tlsutil.make_dc_ldaps_cert(other.name, FQDN, DOMAIN, HOST)
        self.assertGreater(load(crt).not_valid_after_utc, NOW())
        load(crt).verify_directly_issued_by(load(ca_crt))
        self.assertEqual(load(ca_crt).subject, ca_before.subject)

    def test_no_sid_extension_without_sid(self):
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        c = load(tlsutil.make_dc_ldaps_cert(other.name, FQDN, DOMAIN, HOST)[0])
        self.assertNotIn(tlsutil.OID_NTDS_CA_SECURITY, [e.oid.dotted_string for e in c.extensions])


class TestSnakeoil(unittest.TestCase):
    def test_ubuntu_snakeoil_profile(self):
        with tempfile.TemporaryDirectory() as d:
            fq = "rs-web-01.corp.redside-security.com"
            crt, key = tlsutil.make_snakeoil_cert(d, fq)
            c = load(crt)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fq)])
            self.assertEqual((c.subject, c.issuer), (name, name))
            self.assertLessEqual(der_int_len(c.serial_number), 20)
            self.assertEqual(c.not_valid_after_utc - c.not_valid_before_utc, datetime.timedelta(days=3650))
            self.assertLess(c.not_valid_before_utc, NOW() - datetime.timedelta(days=29))
            self.assertEqual([e.oid for e in c.extensions], [ExtensionOID.BASIC_CONSTRAINTS,
                                                             ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                                                             ExtensionOID.SUBJECT_KEY_IDENTIFIER])
            self.assertFalse(c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                             .get_values_for_type(x509.DNSName), [fq])
            self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
            self.assertEqual(load(tlsutil.make_snakeoil_cert(d, fq)[0]), c)


def handshake(ctx, cipher=None, version=None):
    a, b = socket.socketpair()
    a.settimeout(5)
    b.settimeout(5)

    def server():
        try:
            ctx.wrap_socket(a, server_side=True)
        except (ssl.SSLError, OSError):
            pass
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


class TestContexts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dc = tlsutil.dc_server_context(os.path.join(cls.tmp.name, "dc"), FQDN, DOMAIN, HOST, GUID, SID)
        cls.web = tlsutil.apache_server_context(os.path.join(cls.tmp.name, "web"), "rs-web-01." + DOMAIN)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_dc_schannel_2019(self):
        self.assertEqual(handshake(self.dc, version=ssl.TLSVersion.TLSv1_3), (None, None))
        self.assertEqual(handshake(self.dc), ("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384"))
        self.assertEqual(handshake(self.dc, "AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384")[1], "ECDHE-RSA-AES256-GCM-SHA384")
        tls12 = [c["name"] for c in self.dc.get_ciphers() if c["protocol"] != "TLSv1.3"]
        self.assertEqual(tls12, [n for n in tlsutil.SCHANNEL_2019_CIPHERS.split(":") if n in tls12])

    def test_web_apache_ubuntu(self):
        self.assertEqual(handshake(self.web, version=ssl.TLSVersion.TLSv1_1), (None, None))
        self.assertEqual(handshake(self.web, version=ssl.TLSVersion.TLSv1), (None, None))
        self.assertEqual(handshake(self.web, version=ssl.TLSVersion.TLSv1_3)[0], "TLSv1.3")
        self.assertEqual(handshake(self.web, "AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384",
                                   ssl.TLSVersion.TLSv1_2)[1], "AES128-SHA")         # client preference
        names = {c["name"] for c in self.web.get_ciphers()}
        self.assertIn("ECDHE-RSA-CHACHA20-POLY1305", names)
        self.assertFalse(any("NULL" in n or n.startswith("ADH") for n in names))


class TestServicesOnTheWire(unittest.TestCase):
    """base.tls_context picks the profile from the persona OS; real LDAPS / HTTPS listeners serve it."""

    @classmethod
    def setUpClass(cls):
        from rpot.sensor.services.http import start_http
        from rpot.sensor.services.ldap import start_ldap
        cls.tmp = tempfile.TemporaryDirectory()
        co = B.make_persona("corp.ararat.am", "bank", seed=5)
        co["token_salt"] = "s4lt"
        sensors = [{"name": "DC01", "role": "windows-domain-controller", "ip": "10.9.0.10"},
                   {"name": "WEB01", "role": "linux-web-hosting", "ip": "10.9.0.22"}]
        tokens = B.generate({"company": co, "console": {}, "sensors": sensors}, os.path.join(cls.tmp.name, "baits"))
        cls.dc, cls.dc_em = ctx_for(cls.tmp.name, tokens, co, sensors, "DC01", "windows-domain-controller")
        cls.web, _ = ctx_for(cls.tmp.name, tokens, co, sensors, "WEB01", "linux-web-hosting")
        cls.p636, cls.p3269, cls.p443 = free_port(), free_port(), free_port()
        start_ldap(cls.dc, {"port": cls.p636, "tls": True})
        start_ldap(cls.dc, {"port": cls.p3269, "tls": True})
        start_http(cls.web, {"type": "http", "port": cls.p443, "tls": True, "server": "Apache/2.4.52 (Ubuntu)"})
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def peer(self, port):
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s, c.wrap_socket(s) as t:
            return x509.load_der_x509_certificate(t.getpeercert(binary_form=True)), t.version()

    def test_dc_ldaps_and_gc_ssl_same_ca_cert(self):
        a, va = self.peer(self.p636)
        b, vb = self.peer(self.p3269)
        self.assertEqual(a, b)
        self.assertEqual((va, vb), ("TLSv1.2", "TLSv1.2"))
        self.assertEqual(a.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                         f"corp-{self.dc.name}-CA")
        self.assertEqual(a.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, self.dc.fqdn)
        sid = ext(a, tlsutil.OID_NTDS_CA_SECURITY).value.value
        self.assertRegex(sid[-60:].decode("ascii", "replace"), r"S-1-5-21-\d+-\d+-\d+-1000$")
        guid = a.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.OtherName)
        self.assertEqual(guid[0].value, b"\x04\x10" + self.dc.persona_secret("dc-object-guid")[:16])

    def test_dc_ldaps_still_answers_ldap(self):
        import ldap3
        srv = ldap3.Server("127.0.0.1", port=self.p636, use_ssl=True, get_info=ldap3.NONE,
                           tls=ldap3.Tls(validate=ssl.CERT_NONE), connect_timeout=5)
        conn = ldap3.Connection(srv, receive_timeout=5)
        self.assertTrue(conn.bind())
        self.assertTrue(conn.search("", "(objectClass=*)", search_scope=ldap3.BASE, attributes=["dnsHostName"]))
        self.assertEqual(str(conn.entries[0].dnsHostName).lower(), self.dc.fqdn)
        conn.unbind()

    def test_web_https_linux_profile(self):
        c, v = self.peer(self.p443)
        self.assertEqual(v, "TLSv1.3")
        self.assertEqual(c.subject, c.issuer)
        self.assertNotIn("-CA", c.issuer.rfc4514_string())
        self.assertEqual(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, self.web.fqdn)
        files = sorted(os.listdir(os.path.join(self.web.data_dir, "tls")))
        self.assertNotIn(tlsutil.ADCS_CA_KEY, files)                                # no AD CS on a Linux box

    def test_role_serves_ldaps_and_gc_over_ssl(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "roles", "windows-domain-controller.json")) as f:
            svcs = json.load(f)["services"]
        tls_ports = sorted(s["port"] for s in svcs if s.get("type") == "ldap" and s.get("tls"))
        self.assertEqual(tls_ports, [636, 3269])


if __name__ == "__main__":
    unittest.main()
