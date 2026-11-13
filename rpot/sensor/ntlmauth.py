"""NTLM server side shared by the SMB and RDP decoys: a Windows-persona CHALLENGE message and
verification of the client's AUTHENTICATE response against the bait credentials' NT hashes.

Policy (same for every NTLM service):
  * empty user = anonymous / null session → caller decides (SMB allows it, breadcrumb design);
  * user + response proving a bait password → honeytoken.used (L5), login succeeds only where the
    bait is valid (valid_on "NAME:service");
  * anything else → auth.failed (feeds the spraying / brute-force escalation); a bait *name* with a
    wrong password carries honey=True (scored L4 "attempt", never L5).
"""
import hashlib
import hmac
import struct
import time

from impacket import ntlm

from rpot.sensor.base import win_version

ANON = "anonymous"


def version_bytes(os_name):
    """NTLM VERSION structure (major, minor, build, NTLM revision 15) of the persona."""
    ma, mi, build = win_version(os_name)
    return struct.pack("<BBH3sB", ma, mi, build, b"\0\0\0", 15)


def challenge_message(ctx, neg_flags, server_challenge):
    """CHALLENGE (type 2) exactly like a domain-joined Windows server: target = NetBIOS domain,
    AV pairs NB domain / NB computer / DNS domain / DNS computer / DNS tree / timestamp, persona
    OS version (never impacket's 255.255 build 65535)."""
    f = 0
    for bit in (ntlm.NTLMSSP_NEGOTIATE_56, ntlm.NTLMSSP_NEGOTIATE_128, ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH,
                ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, ntlm.NTLMSSP_NEGOTIATE_UNICODE,
                ntlm.NTLMSSP_NEGOTIATE_SIGN, ntlm.NTLMSSP_NEGOTIATE_SEAL, ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN):
        if neg_flags & bit:
            f |= bit
    if not neg_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        f |= ntlm.NTLM_NEGOTIATE_OEM
    f |= (ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_DOMAIN |
          ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_REQUEST_TARGET)
    u = lambda s: str(s).encode("utf-16le")
    av = ntlm.AV_PAIRS()
    av[ntlm.NTLMSSP_AV_DOMAINNAME] = u(ctx.netbios.upper())
    av[ntlm.NTLMSSP_AV_HOSTNAME] = u(ctx.name.upper())
    av[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = u(ctx.domain.lower())
    av[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = u(ctx.fqdn.lower())
    av[ntlm.NTLMSSP_AV_DNS_TREENAME] = u(ctx.domain.lower())
    av[ntlm.NTLMSSP_AV_TIME] = struct.pack("<q", 116444736000000000 + int(time.time() * 10000000))
    target = u(ctx.netbios.upper())
    m = ntlm.NTLMAuthChallenge()
    m["flags"] = f
    m["domain_len"] = m["domain_max_len"] = len(target)
    m["domain_offset"] = 56
    m["challenge"] = server_challenge
    m["domain_name"] = target
    m["TargetInfoFields_len"] = m["TargetInfoFields_max_len"] = len(av)
    m["TargetInfoFields"] = av
    m["TargetInfoFields_offset"] = 56 + len(target)
    m["Version"] = version_bytes(ctx.os)
    m["VersionLen"] = 8
    return m


def parse_authenticate(token):
    """AUTHENTICATE (type 3) → (impacket message, user, domain, workstation)."""
    a = ntlm.NTLMAuthChallengeResponse()
    a.fromString(token)
    uni = a["flags"] & ntlm.NTLMSSP_NEGOTIATE_UNICODE
    dec = (lambda b: b.decode("utf-16le", "replace")) if uni else (lambda b: b.decode("latin-1", "replace"))
    return a, dec(a["user_name"])[:128], dec(a["domain_name"])[:128], dec(a["host_name"])[:128]


def verify(auth, user, domain, server_challenge, nt):
    """True if the response proves knowledge of the password behind NT hash `nt` (NTLMv2 or v1)."""
    resp, lm = auth["ntlm"] or b"", auth["lanman"] or b""
    if len(resp) > 24:                                                  # NTLMv2
        key = ntlm.hmac_md5(nt, (user.upper() + domain).encode("utf-16le"))
        return hmac.compare_digest(ntlm.hmac_md5(key, server_challenge + resp[16:]), resp[:16])
    if len(resp) == 24:                                                 # NTLMv1 (+ESS)
        c = server_challenge
        if auth["flags"] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and len(lm) >= 8:
            c = hashlib.md5(server_challenge + lm[:8]).digest()[:8]
        return hmac.compare_digest(ntlm.ntlmssp_DES_encrypt(nt + b"\0" * 5, c), resp)
    return False


def check(ctx, service, auth, user, domain, workstation, server_challenge, src, port, session, grant=True):
    """Apply the bait policy to a named NTLM logon → (logon ok, token id, NT hash); token id / NT hash are
    set whenever the password was right. Emits the events. grant=False: the protocol never completes a
    logon (RDP stops after NLA), so even a valid bait is reported as an attempt."""
    for tid, tok, nt in ctx.tokens.ntlm_candidates(user):
        if verify(auth, user, domain, server_challenge, nt):
            ok = grant and ctx.tokens.valid_on(tok, ctx.name, service)
            ctx.emit("honeytoken.used", src, port, service, session, token=tid, username=user, domain=domain or None,
                     workstation=workstation or None, desc=tok.get("desc") or f"bait account used for {service.upper()} logon",
                     planted=tok.get("planted"), success=ok, password_ok=True, method="ntlm")
            if ok:
                ctx.emit("auth.success", src, port, service, session, username=user, domain=domain or None, method="ntlm")
            return ok, tid, nt
    btid, _ = ctx.tokens.bait_user(user)
    honey = bool(btid or ctx.tokens.ntlm_candidates(user))
    ctx.emit("auth.failed", src, port, service, session, username=user, domain=domain or None,
             workstation=workstation or None, method="ntlm", honey=honey or None, token=btid)
    return False, None, None
