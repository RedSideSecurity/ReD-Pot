"""Bait-account secrets of the Domain Controller decoy: Kerberos keys, krbtgt key, NTLM verification.

What the sensor holds (never the plaintext bait passwords): at bait generation the manager derives the keys
a real DC stores for each bait account valid on it — AES256/AES128 (salt REALM + sAMAccountName) and RC4
(= NT hash) — and plants them in <bait dir>/ldap/krb_keys.json:
    {"realm": "CORP.EXAMPLE", "accounts": {"svc_sql": {"token": id, "valid": true, "keys": {"18": hex, "17": hex, "23": hex}}}}
Trade-off: these keys are password-EQUIVALENT for the fake domain (pass-the-hash / pass-the-key against this
decoy), but they do not reveal the plaintext, which stays on the manager; the hashed honeytoken index in
sensor.json is unchanged. Bait trees generated before 0.4 have no krb_keys.json: the KDC then never issues
tickets and NTLM binds can only fail (re-enroll / regenerate the baits to enable them).

krbtgt: a random per-install key in <data dir>/kdc.key (0600) — TGTs this KDC issues decrypt only here.
NTLM: server side of NTLMSSP (CHALLENGE with the persona's target info, NTLMv2 verification, session
security for SASL-sealed LDAP) — structures from impacket.ntlm.
"""
import hashlib
import hmac
import json
import os
import secrets
import struct
import time

AES256, AES128, RC4 = 18, 17, 23
WIN_VERSION = bytes([10, 0]) + struct.pack("<H", 17763) + b"\x00\x00\x00\x0f"     # Windows Server 2019, NTLM rev 15


def derive_keys(username, password, realm):
    """Keys a DC derives from a password (used by the manager when it plants baits)."""
    from impacket.krb5.crypto import _enctype_table
    from impacket.ntlm import compute_nthash
    salt = (realm.upper() + username).encode()
    out = {str(RC4): compute_nthash(password).hex()}
    for et in (AES256, AES128):                    # RFC 3962 string-to-key (hashlib PBKDF2: impacket's is pure Python)
        c = _enctype_table[et]
        seed = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 4096, c.seedsize)
        out[str(et)] = c.derive(c.random_to_key(seed), b"kerberos").contents.hex()
    return out


class BaitKeys:
    """krb_keys.json of this DC: sAMAccountName (lower) → {sam, token, valid, keys{etype: bytes}}."""

    def __init__(self, bait_dir):
        self.accounts = {}
        try:
            with open(os.path.join(bait_dir, "ldap", "krb_keys.json")) as f:
                d = json.load(f)
            for sam, e in list((d.get("accounts") or {}).items())[:100]:
                keys = {int(k): bytes.fromhex(v) for k, v in (e.get("keys") or {}).items() if int(k) in (AES256, AES128, RC4)}
                if keys:
                    self.accounts[sam.lower()] = {"sam": sam, "token": e.get("token"), "valid": bool(e.get("valid")), "keys": keys}
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def get(self, user):
        return self.accounts.get((user or "").lower())


def kdc_secret(data_dir):
    """Per-install random krbtgt secret (32 bytes), created on first use."""
    p = os.path.join(data_dir, "kdc.key")
    try:
        with open(p, "rb") as f:
            k = f.read()
        if len(k) == 32:
            return k
    except OSError:
        pass
    k = secrets.token_bytes(32)
    try:
        os.makedirs(data_dir, exist_ok=True)
        fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k)
        os.replace(p + ".tmp", p)
    except OSError:
        pass                                     # read-only data dir: key lives for this process only
    return k


def machine_key(secret, name):
    """Stable AES256 key of a decoy computer account (DC01$, FS01$) derived from the krbtgt secret."""
    return hmac.new(secret, b"machine:" + name.lower().encode(), hashlib.sha256).digest()


def filetime(t=None):
    return int(((t or time.time()) + 11644473600) * 10_000_000)


def _av(pairs):
    return b"".join(struct.pack("<HH", t, len(v)) + v for t, v in pairs) + b"\x00\x00\x00\x00"


class NTLMServer:
    """One server-side NTLM handshake as this DC (NEGOTIATE → CHALLENGE → AUTHENTICATE)."""

    def __init__(self, ctx, keys):
        self.ctx, self.keys = ctx, keys
        self.chal = secrets.token_bytes(8)
        self.flags = 0

    def challenge(self, negotiate):
        from impacket import ntlm as N
        neg = N.NTLMAuthNegotiate()
        try:
            neg.fromString(negotiate)
        except Exception as e:                         # impacket raises assorted errors on hostile input
            raise ValueError(str(e))
        req = neg["flags"]
        f = (N.NTLMSSP_NEGOTIATE_UNICODE | N.NTLMSSP_REQUEST_TARGET | N.NTLMSSP_NEGOTIATE_NTLM |
             N.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | N.NTLMSSP_TARGET_TYPE_DOMAIN | N.NTLMSSP_NEGOTIATE_TARGET_INFO |
             N.NTLMSSP_NEGOTIATE_VERSION)
        f |= req & (N.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | N.NTLMSSP_NEGOTIATE_128 | N.NTLMSSP_NEGOTIATE_56 |
                    N.NTLMSSP_NEGOTIATE_KEY_EXCH | N.NTLMSSP_NEGOTIATE_SIGN | N.NTLMSSP_NEGOTIATE_SEAL)
        self.flags = f
        c = self.ctx
        u = lambda s: s.encode("utf-16le")
        target = _av([(2, u(c.netbios.upper())), (1, u(c.name.upper())), (4, u(c.domain.lower())), (3, u(c.fqdn)),
                      (5, u(c.domain.lower())), (7, struct.pack("<Q", filetime()))])
        dom = u(c.netbios.upper())
        return (b"NTLMSSP\x00" + struct.pack("<I", 2) + struct.pack("<HHI", len(dom), len(dom), 56) + struct.pack("<I", f) +
                self.chal + b"\x00" * 8 + struct.pack("<HHI", len(target), len(target), 56 + len(dom)) + WIN_VERSION + dom + target)

    def authenticate(self, auth):
        """→ dict(user, domain, host, ok, account, session_key, flags) ; ValueError on garbage."""
        from impacket import ntlm as N
        a = N.NTLMAuthChallengeResponse()
        try:
            a.fromString(auth)
        except Exception as e:                         # impacket raises assorted errors on hostile input
            raise ValueError(str(e))
        flags = a["flags"]
        dec = (lambda b: b.decode("utf-16le", "replace")) if flags & N.NTLMSSP_NEGOTIATE_UNICODE else \
              (lambda b: b.decode("latin-1"))
        user, domain, host = dec(a["user_name"])[:100], dec(a["domain_name"])[:100], dec(a["host_name"])[:100]
        r = {"user": user, "domain": domain, "host": host, "ok": False, "account": None, "session_key": None, "flags": flags}
        nt = bytes(a["ntlm"])
        sam = user.split("@")[0].split("\\")[-1]
        acct = self.keys.get(sam) if sam else None
        r["account"] = acct
        if not acct or RC4 not in acct["keys"] or len(nt) <= 24:     # NTLMv1 / anonymous: never accepted
            return r
        for d in dict.fromkeys([domain, domain.upper(), self.ctx.netbios.upper(), self.ctx.domain, ""]):
            owf = N.hmac_md5(acct["keys"][RC4], user.upper().encode("utf-16le") + d.encode("utf-16le"))
            proof = N.hmac_md5(owf, self.chal + nt[16:])
            if hmac.compare_digest(proof, nt[:16]):
                base = N.hmac_md5(owf, proof)
                ek = bytes(a["session_key"] or b"")
                key = N.generateEncryptedSessionKey(base, ek) if flags & N.NTLMSSP_NEGOTIATE_KEY_EXCH and len(ek) == 16 else base
                r.update(ok=True, session_key=key)
                break
        return r


class NTLMSeal:
    """NTLM session security, server side (MS-NLMP 3.4: extended session security + key exchange) — what LDAP
    SASL GSS-SPNEGO wraps every message in after a bind that negotiated SEAL (or SIGN only: seal=False)."""

    def __init__(self, flags, session_key, seal=True):
        from impacket import ntlm as N
        from Cryptodome.Cipher import ARC4
        self.N, self.flags, self.seal = N, flags, seal
        self.s_sign = N.SIGNKEY(flags, session_key, "Server")
        self.s_seal = N.SEALKEY(flags, session_key, "Server")
        self.c_rc4 = ARC4.new(N.SEALKEY(flags, session_key, "Client")).encrypt
        self.s_rc4 = ARC4.new(self.s_seal).encrypt
        self.seq = 0

    def unwrap(self, frame):
        """16-byte signature + (sealed) data (4-byte length already stripped) → plaintext."""
        if len(frame) < 16:
            raise ValueError("short sealed frame")
        plain = self.c_rc4(frame[16:]) if self.seal else frame[16:]
        if self.flags & self.N.NTLMSSP_NEGOTIATE_KEY_EXCH:
            self.c_rc4(frame[4:12])                    # keep the RC4 stream aligned with the client's MAC
        return plain

    def wrap(self, data):
        if self.seal:
            body, sig = self.N.SEAL(self.flags, self.s_sign, self.s_seal, data, data, self.seq, self.s_rc4)
        else:
            body, sig = data, self.N.SIGN(self.flags, self.s_sign, data, self.seq, self.s_rc4)
        self.seq += 1
        out = sig.getData() + body
        return struct.pack(">I", len(out)) + out
