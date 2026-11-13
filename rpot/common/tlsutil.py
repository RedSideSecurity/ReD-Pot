"""TLS helpers shared by manager and sensors.

* make_cert(): manager certificate (RSA-2048; persona-styled leaf from an internal "<Company> CA",
  SANs = the real manager addresses only). Its SHA-256 fingerprint is embedded in join strings.
* PinnedClient: HTTPS client that accepts ONLY the manager certificate with the pinned
  fingerprint (no CA needed, immune to MITM even on a hostile LAN).
* make_rdp_cert() / rdp_server_context(): the RDP decoy's TLS layer, shaped like the self-signed
  "Remote Desktop" certificate and the Schannel defaults of Windows Server 2019 (see tests/test_rc29_rdp_tls.py
  for the sources).
* make_enterprise_ca() / make_dc_ldaps_cert() / dc_server_context(): the DC's LDAPS / GC-over-SSL layer, shaped like
  a "Domain Controller" template certificate issued by the domain's AD CS enterprise CA, served with the same
  Schannel 2019 defaults (see tests/test_rc30_ldaps_tls.py for the sources).
* make_snakeoil_cert() / apache_server_context(): the Linux web decoy's HTTPS, shaped like Apache's default-ssl site
  on Ubuntu 22.04 (ssl-cert "snakeoil" certificate, OpenSSL 3 defaults).
"""
import datetime
import gzip
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import threading
import warnings


def fingerprint_der(der):
    return hashlib.sha256(der).hexdigest().upper()


def fingerprint_file(cert_path):
    with open(cert_path, "rb") as f:
        pem = f.read().decode()
    return fingerprint_der(ssl.PEM_cert_to_DER_cert(pem))


def make_cert(directory, cn, names=(), days=3650, org=None, ca_name=None, force=False):
    """Create (once, or again with force) manager.crt/manager.key in directory; returns (crt, key, fingerprint).
    With org: a persona-styled leaf (CN=cn, O=org) issued by an internal CA named ca_name (its key is thrown
    away — sensors pin the leaf's SHA-256, nothing ever chains to the CA). Only the given names become SANs."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    os.makedirs(directory, exist_ok=True)
    crt, key = os.path.join(directory, "manager.crt"), os.path.join(directory, "manager.key")
    if force or not (os.path.exists(crt) and os.path.exists(key)):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sans, seen = [], set()
        for n in [cn, *names] + ([] if org else ["localhost", "127.0.0.1"]):
            if not n or n in seen:
                continue
            seen.add(n)
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(n)))
            except ValueError:
                sans.append(x509.DNSName(n))
        now = datetime.datetime.now(datetime.timezone.utc)
        if org:
            import secrets
            age = datetime.timedelta(days=30 + secrets.randbelow(300), hours=secrets.randbelow(24), minutes=secrets.randbelow(60))
            ck = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (ca_name or f"{org} Issuing CA")[:64]),
                                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org[:64])])
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn[:64]), x509.NameAttribute(NameOID.ORGANIZATION_NAME, org[:64])])
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(k.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - age)
                    .not_valid_after(now - age + datetime.timedelta(days=min(days, 1095)))
                    .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                                 data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                                 crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ck.public_key()), critical=False)
                    .sign(ck, hashes.SHA256()))
        else:       # legacy self-signed (tests / dev)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn[:64])])
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=days))
                    .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                    .sign(k, hashes.SHA256()))
        with open(key, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
        os.chmod(key, 0o600)
        with open(crt, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return crt, key, fingerprint_file(crt)


# ------------------------------------------------------------------------------------------ RDP (Schannel-like)
RDP_CERT_DAYS = 183         # TermService self-signed cert: ~6 months, re-issued when it expires
RDP_CRT, RDP_KEY, RDP_DH = "rdp.crt", "rdp.key", "rdp-dh.pem"

# Schannel default TLS 1.2 cipher-suite order of Windows 10 1809 / Server 2019 (enabled-by-default rows),
# OpenSSL names. ECDSA suites are listed for fidelity but never chosen (the RDP certificate is RSA).
# TLS_RSA_WITH_3DES_EDE_CBC_SHA (last in Schannel's list) is not available in the OpenSSL build we ship on.
SCHANNEL_2019_CIPHERS = ":".join([
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-SHA384", "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES256-SHA", "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA",
    "AES256-GCM-SHA384", "AES128-GCM-SHA256",
    "AES256-SHA256", "AES128-SHA256",
    "AES256-SHA", "AES128-SHA",
    "DES-CBC3-SHA",
])

# RFC 7919 ffdhe2048 (exported from OpenSSL's built-in group): 2048-bit DHE like Schannel's default.
FFDHE2048_PEM = """-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
"""


def _load_cert(crt):
    from cryptography import x509
    with open(crt, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _cert_usable(crt, key, now=None):
    """True when crt/key exist, parse, and the certificate is valid for at least another hour."""
    if not (os.path.exists(crt) and os.path.exists(key)):
        return False
    try:
        now = now or datetime.datetime.now(datetime.timezone.utc)
        return _load_cert(crt).not_valid_after_utc > now + datetime.timedelta(hours=1)
    except Exception:
        return False


_rdp_cert_usable = _cert_usable


def _write_pair(crt, key, k, cert):
    """Write key (0600, created with that mode) and certificate atomically."""
    from cryptography.hazmat.primitives import serialization
    fd = os.open(key + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()))
    os.chmod(key + ".tmp", 0o600)
    with open(crt + ".tmp", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.replace(key + ".tmp", key)
    os.replace(crt + ".tmp", crt)


def _years(t, n):
    """t + n calendar years (29 Feb -> 28 Feb), like AD CS / OpenSSL "N years" validity periods."""
    try:
        return t.replace(year=t.year + n)
    except ValueError:
        return t.replace(year=t.year + n, day=28)


def _dh_file(directory):
    dh = os.path.join(directory, RDP_DH)
    if not os.path.exists(dh):
        with open(dh, "w") as f:
            f.write(FFDHE2048_PEM)
    return dh


def make_rdp_cert(directory, fqdn, force=False, now=None):
    """Per-install RDP certificate like the one TermService creates for itself on Windows Server 2019:
    self-signed, subject = issuer = CN=<host FQDN> only, RSA-2048 / sha256WithRSAEncryption, 16-byte serial,
    validity 183 days from a notBefore backdated to a random moment of the last ~5 months, extensions
    exactly EKU serverAuth + KeyUsage keyEncipherment|dataEncipherment (both non-critical; no SAN/SKI/AKI/
    BasicConstraints). An expired one is re-issued, as TermService does. Returns (crt, key)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    import secrets
    os.makedirs(directory, exist_ok=True)
    crt, key = os.path.join(directory, RDP_CRT), os.path.join(directory, RDP_KEY)
    if not force and _rdp_cert_usable(crt, key):
        return crt, key
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
    nb = now - datetime.timedelta(days=1 + secrets.randbelow(150), seconds=secrets.randbelow(86400))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (fqdn or "localhost")[:64])])
    serial = secrets.randbits(127) | (1 << 120)      # positive, exactly 16 DER bytes (Windows style)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(serial).not_valid_before(nb).not_valid_after(nb + datetime.timedelta(days=RDP_CERT_DAYS))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=True,
                                         data_encipherment=True, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=False)
            .sign(k, hashes.SHA256()))
    _write_pair(crt, key, k, cert)
    return crt, key


def rdp_server_context(directory, fqdn):
    """Server SSLContext for the RDP decoy: the Windows-style certificate from make_rdp_cert() served with
    schannel_server_context()."""
    crt, key = make_rdp_cert(directory, fqdn)
    return schannel_server_context(directory, crt, key)


def schannel_server_context(directory, crt, key):
    """Server SSLContext with Schannel's Windows Server 2019 defaults: TLS 1.0-1.2 (Schannel on 17763 has no
    TLS 1.3), the 2019 cipher order with server preference, 2048-bit DHE."""
    dh = _dh_file(directory)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with warnings.catch_warnings():             # TLS 1.0/1.1 on purpose: Schannel 2019 enables them by default
        warnings.simplefilter("ignore", DeprecationWarning)
        c.minimum_version = ssl.TLSVersion.TLSv1
    c.maximum_version = ssl.TLSVersion.TLSv1_2
    c.options |= ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_NO_COMPRESSION
    try:
        c.set_ciphers(SCHANNEL_2019_CIPHERS + ":@SECLEVEL=0")   # SECLEVEL 0: TLS 1.0/1.1 SHA-1 signatures
    except ssl.SSLError:
        c.set_ciphers(SCHANNEL_2019_CIPHERS)
    try:
        c.load_dh_params(dh)
    except (ssl.SSLError, OSError):
        pass
    c.load_cert_chain(crt, key)
    return c


# ------------------------------------------------------------------------- DC LDAPS (AD CS enterprise CA)
ADCS_CA_CRT, ADCS_CA_KEY = "adcs-ca.crt", "adcs-ca.key"
DC_CRT, DC_KEY = "dc-ldaps.crt", "dc-ldaps.key"
OID_TEMPLATE_NAME = "1.3.6.1.4.1.311.20.2"      # szOID_ENROLL_CERTTYPE_EXTENSION (v1 template name, BMPString)
OID_CA_VERSION = "1.3.6.1.4.1.311.21.1"         # szOID_CERTSRV_CA_VERSION
OID_DS_GUID = "1.3.6.1.4.1.311.25.1"            # SAN otherName: the DC computer object's objectGUID
OID_NTDS_CA_SECURITY = "1.3.6.1.4.1.311.25.2"   # szOID_NTDS_CA_SECURITY_EXT (object SID, KB5014754)
OID_NTDS_OBJECTSID = "1.3.6.1.4.1.311.25.2.1"
OID_SMIME_CAPS = "1.2.840.113549.1.9.15"
# AD CS default S/MIME capabilities: RC2-128, RC4-128, DES-CBC, 3DES-CBC (what certutil / openssl show on DC certs)
SMIME_CAPS_DER = bytes.fromhex("3035300e06082a864886f70d030202020080300e06082a864886f70d030402020080"
                               "300706052b0e030207300a06082a864886f70d0307")


def _der(tag, body):
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


def _der_oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return _der(0x06, bytes(out))


def adcs_ca_name(domain, host):
    """Default AD CS CA common name when the CA role is added on the DC: <first domain label>-<HOST>-CA."""
    return f"{domain.split('.')[0]}-{host.upper()}-CA"[:64]


def _dc_components(domain):
    """RDNs DC=<label> in encoding order (DC=com, DC=corp, ...): Windows shows CN=x, DC=corp, DC=com."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    return [x509.NameAttribute(NameOID.DOMAIN_COMPONENT, p) for p in reversed(domain.split(".")) if p]


def make_enterprise_ca(directory, domain, host, now=None, force=False):
    """Per-install fake AD CS enterprise root CA "<domain label>-<HOST>-CA" (subject CN + DC= components),
    RSA-2048 / SHA-256, 5-year validity from a backdated install date, 16-byte serial, extensions KeyUsage
    digitalSignature|keyCertSign|cRLSign, BasicConstraints CA:TRUE (critical), SKI, CA Version 0.0.
    The key never leaves the sensor's data dir (0600). Returns (crt, key)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    import secrets
    os.makedirs(directory, exist_ok=True)
    crt, key = os.path.join(directory, ADCS_CA_CRT), os.path.join(directory, ADCS_CA_KEY)
    if not force and _cert_usable(crt, key, (now or datetime.datetime.now(datetime.timezone.utc)) + datetime.timedelta(days=400)):
        try:
            if _load_cert(crt).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == adcs_ca_name(domain, host):
                return crt, key
        except Exception:
            pass
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
    nb = now - datetime.timedelta(days=300 + secrets.randbelow(700), seconds=secrets.randbelow(86400))
    name = x509.Name(_dc_components(domain) + [x509.NameAttribute(NameOID.COMMON_NAME, adcs_ca_name(domain, host))])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(secrets.randbits(127) | (1 << 120)).not_valid_before(nb).not_valid_after(_years(nb, 5))
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
            .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_CA_VERSION), b"\x02\x01\x00"),
                           critical=False)
            .sign(k, hashes.SHA256()))
    _write_pair(crt, key, k, cert)
    return crt, key


def _adcs_serial():
    """19-byte AD CS-style serial: <xx 00 00 00> <10 random bytes> <00 00 00 00 nn> (request-ID framing)."""
    import secrets
    rid = 2 + secrets.randbelow(60)
    return int.from_bytes(bytes([0x10 + secrets.randbelow(0x70), 0, 0, 0]) + secrets.token_bytes(10)
                          + rid.to_bytes(5, "big"), "big")


def _dc_cert_ok(crt, key, ca_crt, fqdn, now):
    if not _cert_usable(crt, key, now):
        return False
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        c, ca = _load_cert(crt), _load_cert(ca_crt)
        aki = c.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        return aki == ski and c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == fqdn
    except Exception:
        return False


def make_dc_ldaps_cert(directory, fqdn, domain, host, object_guid=None, sid=None, now=None, force=False):
    """LDAPS / GC-over-SSL certificate of a Windows Server 2019 DC, as auto-enrolled from the enterprise CA with
    the "Domain Controller" (v1) template: subject CN=<DC FQDN>, issuer = make_enterprise_ca(), RSA-2048 /
    SHA-256, 19-byte AD CS-style serial, 1-year validity from a backdated issue date (autoenrollment renews it
    yearly), extensions in AD CS order: template name "DomainController", EKU clientAuth + serverAuth,
    KeyUsage digitalSignature|keyEncipherment (critical), S/MIME capabilities, SKI, AKI, LDAP CDP + AIA,
    SAN otherName DS-object-GUID + DNS:<DC FQDN>, and (CA patched for KB5014754) the NTDS CA security
    extension with the DC computer SID. Re-issued on expiry, rename or new CA. Returns (crt, key, ca_crt)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import secrets
    fqdn = fqdn.lower()
    now = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
    ca_crt, ca_key = make_enterprise_ca(directory, domain, host, now=now)
    crt, key = os.path.join(directory, DC_CRT), os.path.join(directory, DC_KEY)
    if not force and _dc_cert_ok(crt, key, ca_crt, fqdn, now):
        return crt, key, ca_crt
    ca = _load_cert(ca_crt)
    with open(ca_key, "rb") as f:
        ck = serialization.load_pem_private_key(f.read(), password=None)
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    earliest = ca.not_valid_before_utc + datetime.timedelta(days=1)
    nb = max(now - datetime.timedelta(days=1 + secrets.randbelow(290), seconds=secrets.randbelow(86400)), earliest)
    na = min(_years(nb, 1), ca.not_valid_after_utc)
    host_u = host.upper()
    ca_cn = adcs_ca_name(domain, host)
    cfg = "CN=Configuration," + ",".join(f"DC={p}" for p in domain.split(".") if p)
    pks = f"CN=Public%20Key%20Services,CN=Services,{cfg}"
    guid = object_guid or secrets.token_bytes(16)
    sans = [x509.OtherName(x509.ObjectIdentifier(OID_DS_GUID), _der(0x04, bytes(guid[:16]))), x509.DNSName(fqdn)]
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn[:64])]))
         .issuer_name(ca.subject).public_key(k.public_key())
         .serial_number(_adcs_serial()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_TEMPLATE_NAME),
                                                   _der(0x1E, "DomainController".encode("utf-16-be"))), critical=False)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
                        critical=False)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_SMIME_CAPS), SMIME_CAPS_DER),
                        critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
             ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)
         .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
             [x509.UniformResourceIdentifier(
                 f"ldap:///CN={ca_cn},CN={host_u},CN=CDP,{pks}?certificateRevocationList?base?objectClass=cRLDistributionPoint")],
             None, None, None)]), critical=False)
         .add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
             x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(
                 f"ldap:///CN={ca_cn},CN=AIA,{pks}?cACertificate?base?objectClass=certificationAuthority"))]),
             critical=False)
         .add_extension(x509.SubjectAlternativeName(sans), critical=False))
    if sid:
        inner = _der(0xA0, _der_oid(OID_NTDS_OBJECTSID) + _der(0xA0, _der(0x04, sid.encode())))
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_NTDS_CA_SECURITY), _der(0x30, inner)),
                            critical=False)
    _write_pair(crt, key, k, b.sign(ck, hashes.SHA256()))
    return crt, key, ca_crt


def dc_server_context(directory, fqdn, domain, host, object_guid=None, sid=None):
    """LDAPS server SSLContext of the DC decoy: make_dc_ldaps_cert() served with Schannel 2019 defaults."""
    crt, key, _ = make_dc_ldaps_cert(directory, fqdn, domain, host, object_guid=object_guid, sid=sid)
    return schannel_server_context(directory, crt, key)


# ---------------------------------------------------------------------- Linux web decoy (Apache on Ubuntu)
SNAKEOIL_CRT, SNAKEOIL_KEY = "ssl-cert-snakeoil.pem", "ssl-cert-snakeoil.key"
SNAKEOIL_DAYS = 3650        # make-ssl-cert generate-default-snakeoil: openssl req -x509 -days 3650


def make_snakeoil_cert(directory, fqdn, now=None, force=False):
    """Ubuntu 22.04 ssl-cert "snakeoil" certificate as used by Apache's default-ssl site: self-signed,
    subject = issuer = CN=<hostname -f>, RSA-2048 / SHA-256, 159-bit random serial (OpenSSL 3), 10-year
    validity from the OS install date, extensions BasicConstraints CA:FALSE, SAN DNS:<fqdn>, SKI. Returns (crt, key)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    import secrets
    os.makedirs(directory, exist_ok=True)
    fqdn = fqdn.lower()
    crt, key = os.path.join(directory, SNAKEOIL_CRT), os.path.join(directory, SNAKEOIL_KEY)
    if not force and _cert_usable(crt, key, now):
        try:
            if _load_cert(crt).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == fqdn[:64]:
                return crt, key
        except Exception:
            pass
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
    nb = now - datetime.timedelta(days=30 + secrets.randbelow(700), seconds=secrets.randbelow(86400))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn[:64])])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(secrets.randbits(159) or 1).not_valid_before(nb)
            .not_valid_after(nb + datetime.timedelta(days=SNAKEOIL_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn)]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
            .sign(k, hashes.SHA256()))
    _write_pair(crt, key, k, cert)
    return crt, key


# Ubuntu 22.04 /etc/apache2/mods-available/ssl.conf: SSLCipherSuite HIGH:!aNULL, SSLProtocol all -SSLv3,
# SSLHonorCipherOrder off (commented out = default off). Ubuntu's OpenSSL 3 at SECLEVEL 2 refuses TLS < 1.2.
APACHE_UBUNTU_CIPHERS = "HIGH:!aNULL"


def apache_server_context(directory, fqdn):
    """HTTPS SSLContext of the Linux web decoy: snakeoil certificate, TLS 1.2 + 1.3, HIGH:!aNULL, client cipher
    preference, 2048-bit DHE (mod_ssl picks DH parameters matching the 2048-bit key)."""
    crt, key = make_snakeoil_cert(directory, fqdn)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE
    c.options |= ssl.OP_NO_COMPRESSION
    c.set_ciphers(APACHE_UBUNTU_CIPHERS)
    try:
        c.load_dh_params(_dh_file(directory))
    except (ssl.SSLError, OSError):
        pass
    c.load_cert_chain(crt, key)
    return c


class PinError(Exception):
    pass


class PinnedClient:
    """Minimal JSON-over-HTTPS client pinned to one certificate fingerprint."""

    def __init__(self, base_url, fingerprint, auth=None, timeout=10):
        u = base_url.rstrip("/")
        if not u.startswith("https://"):
            raise ValueError("manager URL must be https://")
        hostport = u[len("https://"):].split("/", 1)[0]
        host, _, port = hostport.rpartition(":") if hostport.count(":") == 1 else (hostport, "", "443")
        self.host, self.port = (host or hostport), int(port or 443)
        self.fp = (fingerprint or "").replace(":", "").upper()
        self.auth, self.timeout = auth, timeout
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE        # trust comes from the pinned fingerprint below
        self._conn, self._lock = None, threading.Lock()

    GZIP_MIN = 1024

    def _open(self):
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.ctx)
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        if not self.fp or fingerprint_der(der) != self.fp:
            conn.close()
            raise PinError(f"manager certificate fingerprint mismatch (got {fingerprint_der(der)[:16]}…)")
        return conn

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    def request(self, method, path, body=None, extra_headers=None):
        """One JSON request over a KEPT-ALIVE pinned TLS connection (a heartbeat costs one small
        encrypted record instead of a full TCP+TLS handshake). The certificate is pinned on every
        new connection; a stale connection is retried once on a fresh, re-pinned one."""
        data = None
        headers = {"User-Agent": "redpot-sensor", "Connection": "keep-alive"}
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
            if len(data) >= self.GZIP_MIN:
                data = gzip.compress(data, 6)
                headers["Content-Encoding"] = "gzip"
        if self.auth:
            headers["Authorization"] = f"Bearer {self.auth}"
        headers.update(extra_headers or {})
        with self._lock:
            for attempt in (0, 1):
                reused = self._conn is not None
                if not reused:
                    self._conn = self._open()            # PinError propagates: never retried
                try:
                    self._conn.request(method, path, body=data, headers=headers)
                    r = self._conn.getresponse()
                    raw = r.read()
                except (http.client.HTTPException, OSError):
                    self._conn.close()
                    self._conn = None
                    if reused and attempt == 0:          # server closed an idle connection → reconnect
                        continue
                    raise
                if r.will_close:
                    self._conn.close()
                    self._conn = None
                try:
                    payload = json.loads(raw) if raw else {}
                except ValueError:
                    payload = {"raw": raw[:200].decode("latin-1")}
                return r.status, payload


def parse_join(join):
    """Join string: redpot://HOST:PORT/<token>#<FINGERPRINT>  → (url, token, fp)."""
    if not join.startswith("redpot://") or "#" not in join:
        raise ValueError("join string must look like redpot://HOST:PORT/TOKEN#FINGERPRINT")
    rest, fp = join[len("redpot://"):].split("#", 1)
    hostport, _, token = rest.partition("/")
    token = token.split("?", 1)[0]               # optional ?role=… hint (installer only)
    if not hostport or not token or len(fp.replace(":", "")) != 64:
        raise ValueError("malformed join string")
    return f"https://{hostport}", token, fp.replace(":", "").upper()


def local_ips():
    out = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in out:
                out.append(ip)
    except OSError:
        pass
    return out
