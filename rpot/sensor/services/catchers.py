"""Light protocol catchers: MSRPC (135), NetBIOS session (139), RDP (3389).

They do just enough of the protocol to look real to scanners and to extract attribution
(RDP mstshash cookie, and via CredSSP/NLA the NTLM user / domain / workstation), never more.
"""
import os
import socket
import struct

from rpot.common.tlsutil import rdp_server_context
from rpot.sensor.base import serve_tcp


def _recv(conn, n=4096):
    try:
        return conn.recv(n)
    except Exception:
        return b""


def start_msrpc(ctx, svc):
    port = svc["port"]

    def h(conn, addr, session):
        data = _recv(conn)
        if not data:
            return
        # DCE/RPC bind = version 5, ptype 11
        kind = "dcerpc.bind" if len(data) > 2 and data[0] == 5 and data[2] == 11 else "tcp.data"
        ctx.emit("proto.interaction", addr, port, "msrpc", session, detail=kind, bytes=len(data))
        # v0.2: answer epmapper binds properly; for now the connection is just closed.

    serve_tcp(ctx, port, h, "msrpc")


def start_netbios(ctx, svc):
    port = svc["port"]

    def h(conn, addr, session):
        data = _recv(conn)
        if not data:
            return
        detail = "netbios.session_request" if data[:1] == b"\x81" else ("smb.over.139" if b"SMB" in data[:12] else "tcp.data")
        ctx.emit("proto.interaction", addr, port, "netbios", session, detail=detail, bytes=len(data))
        if data[:1] == b"\x81":
            try:
                conn.sendall(b"\x82\x00\x00\x00")  # positive session response
                more = _recv(conn)
                if more:
                    ctx.emit("proto.interaction", addr, port, "netbios", session, detail="smb.over.139", bytes=len(more))
            except Exception:
                pass

    serve_tcp(ctx, port, h, "netbios")


def parse_rdp_cr(data):
    """Parse TPKT + X.224 Connection Request → (cookie_user, requested_protocols)."""
    user, req = None, None
    if len(data) < 11 or data[0] != 3:
        return user, req
    body = data[11:]
    if body.startswith(b"Cookie: mstshash="):
        end = body.find(b"\r\n")
        user = body[17:end if end > 0 else None].decode("latin-1", "replace")[:64]
        body = body[end + 2:] if end > 0 else b""
    elif body.startswith(b"Cookie:"):
        end = body.find(b"\r\n")
        body = body[end + 2:] if end > 0 else b""
    if len(body) >= 8 and body[0] == 1:  # RDP_NEG_REQ
        req = struct.unpack("<I", body[4:8])[0]
    return user, req


# MS-RDPBCGR 2.2.1.1.1 requestedProtocols / 2.2.1.2.1 selectedProtocol
PROTOCOL_RDP, PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_RDSTLS, PROTOCOL_HYBRID_EX = 0, 1, 2, 4, 8
# MS-RDPBCGR 2.2.1.2.2 RDP_NEG_FAILURE.failureCode
HYBRID_REQUIRED_BY_SERVER = 5
RDP_NEG_RSP_FLAGS = 0x1F        # EXTENDED_CLIENT_DATA | DYNVC_GFX | reserved | RESTRICTED_ADMIN | REDIRECTED_AUTH


def rdp_confirm(neg_type, value, flags=RDP_NEG_RSP_FLAGS):
    """TPKT + X.224 Connection Confirm (dst-ref 0, src-ref 0x1234, class 0, as Windows sends) carrying an
    RDP_NEG_RSP (type 2, value = selectedProtocol) or an RDP_NEG_FAILURE (type 3, flags 0, value = failureCode)."""
    neg = struct.pack("<BBHI", neg_type, flags if neg_type == 2 else 0, 8, value)
    x224 = bytes([6 + len(neg), 0xD0, 0, 0, 0x12, 0x34, 0]) + neg
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


def rdp_select(req):
    """Server choice of an NLA-required Windows Server 2019 -> (selectedProtocol, None) or (None, failureCode).
    CredSSP is required: requests offering only Standard RDP Security and/or plain TLS get
    HYBRID_REQUIRED_BY_SERVER; CredSSP (with or without Early User Auth) and RDSTLS are accepted."""
    if req & PROTOCOL_HYBRID:
        return PROTOCOL_HYBRID, None
    if req & PROTOCOL_HYBRID_EX:
        return PROTOCOL_HYBRID_EX, None
    if req & PROTOCOL_RDSTLS:
        return PROTOCOL_RDSTLS, None
    return None, HYBRID_REQUIRED_BY_SERVER


def _first_byte(conn):
    try:
        return conn.recv(1, socket.MSG_PEEK)
    except Exception:
        return b""


def start_rdp(ctx, svc):
    port = svc["port"]
    tls = rdp_server_context(os.path.join(ctx.data_dir, "tls"), ctx.fqdn)

    def h(conn, addr, session):
        if _first_byte(conn) == b"\x16":
            # A bare TLS ClientHello (nmap ssl-cert / ssl-enum-ciphers, openssl s_client): TermService
            # handshakes TLS directly on 3389, so do the same and show the certificate.
            try:
                t = tls.wrap_socket(conn, server_side=True)
            except Exception:
                return
            ctx.emit("proto.interaction", addr, port, "rdp", session, detail="tls.direct")
            try:
                t.recv(4096)
            except Exception:
                pass
            return
        data = _recv(conn)
        if not data:
            return
        user, req = parse_rdp_cr(data)
        protos = []
        if req is not None:
            protos = [n for b, n in ((PROTOCOL_SSL, "TLS"), (PROTOCOL_HYBRID, "CredSSP"), (PROTOCOL_RDSTLS, "RDSTLS"),
                                     (PROTOCOL_HYBRID_EX, "HYBRID_EX")) if req & b] or ["RDP"]
        ctx.emit("rdp.connect", addr, port, "rdp", session, cookie_user=user, protocols=protos or None)
        if req is None:
            return
        selected, failure = rdp_select(req)
        if failure is not None:
            # MS-RDPBCGR 2.2.1.2.2: Connection Confirm with RDP_NEG_FAILURE, then the server disconnects.
            try:
                conn.sendall(rdp_confirm(3, failure))
            except OSError:
                pass
            ctx.emit("proto.interaction", addr, port, "rdp", session, detail="neg.failure.hybrid_required")
            return
        conn.sendall(rdp_confirm(2, selected))
        try:
            t = tls.wrap_socket(conn, server_side=True)
        except Exception:
            return
        ctx.emit("proto.interaction", addr, port, "rdp", session, detail="tls.established")
        if selected in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
            credssp(ctx, t, addr, port, session, user)

    serve_tcp(ctx, port, h, "rdp")


# ---------------------------------------------------------------------------------------- CredSSP / NLA
STATUS_LOGON_FAILURE, STATUS_LOGON_TYPE_NOT_GRANTED = 0xC000006D, 0xC000015B


def _read_der(t, limit=65536):
    """One DER TLV (a TSRequest) from the TLS stream."""
    buf = b""
    while True:
        if len(buf) >= 2:
            n = buf[1]
            if n & 0x80:
                k = n & 0x7F
                if k == 0 or k > 3:
                    return None
                if len(buf) >= 2 + k:
                    need = 2 + k + int.from_bytes(buf[2:2 + k], "big")
                    if need > limit:
                        return None
                    if len(buf) >= need:
                        return buf[:need]
            elif len(buf) >= 2 + n:
                return buf[:2 + n]
        try:
            d = t.recv(8192)
        except Exception:
            return None
        if not d:
            return None
        buf += d


def ts_request_parse(data):
    """TSRequest → (version, negoToken bytes or None)."""
    from rpot.sensor.services import ber
    tag, els = ber.one(data)
    if tag != 0x30:
        raise ValueError("not a TSRequest")
    v = ber.find(els, 0xA0)
    ver = ber.as_int(ber.find(v, 0x02)) if v else 2
    tok = None
    nd = ber.find(els, 0xA1)
    if nd:
        first = ber.find(ber.find(nd, 0x30), 0x30)        # NegoData = SEQUENCE OF SEQUENCE { [0] OCTET STRING }
        inner = ber.find(first, 0xA0) if first else None
        tok = ber.find(inner, 0x04) if inner else None
    return ver, tok


def ts_request(version, token=None, error=None):
    from rpot.sensor.services import ber
    items = [ber.ctx(0, ber.integer(version))]
    if token is not None:
        items.append(ber.ctx(1, ber.seq(ber.seq(ber.ctx(0, ber.octets(token))))))
    if error is not None:
        items.append(ber.ctx(4, ber.integer(error - (1 << 32) if error >= 1 << 31 else error)))  # NTSTATUS as INT32
    return ber.seq(*items)


def _unwrap(tok):
    """negoToken → (raw NTLMSSP message, wrapped in SPNEGO?)"""
    from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp
    if tok[:8] == b"NTLMSSP\0":
        return tok, False
    if tok[:1] == b"\x60":
        return SPNEGO_NegTokenInit(tok)["MechToken"], True
    if tok[:1] == b"\xa1":
        return SPNEGO_NegTokenResp(tok)["ResponseToken"], True
    return None, False


def credssp(ctx, t, addr, port, session, cookie_user=None):
    """NLA far enough for attribution: NTLM NEGOTIATE → persona CHALLENGE (what rdp-ntlm-info reads) →
    AUTHENTICATE gives user / domain / workstation, verified against the bait NT hashes. The logon never
    completes: a correct bait password gets "logon type not granted" (a service account without RDP
    rights — the password is confirmed valid), anything else STATUS_LOGON_FAILURE."""
    import secrets
    from impacket import ntlm as N
    from impacket.spnego import SPNEGO_NegTokenResp, TypesMech
    from rpot.sensor import ntlmauth
    raw = _read_der(t)
    if not raw:
        return
    try:
        ver, tok = ts_request_parse(raw)
        msg, spnego = _unwrap(tok) if tok else (None, False)
    except Exception:
        msg = None
    if not msg or msg[8:12] != b"\x01\0\0\0":
        ctx.emit("proto.interaction", addr, port, "rdp", session, detail="credssp.unexpected", bytes=len(raw))
        return
    neg = N.NTLMAuthNegotiate()
    neg.fromString(msg)
    info = ntlm_from_blob(msg) or {}
    ctx.emit("rdp.ntlm", addr, port, "rdp", session, **info)
    chal = secrets.token_bytes(8)
    out = ntlmauth.challenge_message(ctx, neg["flags"], chal).getData()
    if spnego:
        r = SPNEGO_NegTokenResp()
        r["NegState"] = b"\x01"
        r["SupportedMech"] = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
        r["ResponseToken"] = out
        out = r.getData()
    sv = max(2, min(ver, 6))
    t.sendall(ts_request(sv, out))
    raw = _read_der(t)
    if not raw:
        return
    try:
        _, tok = ts_request_parse(raw)
        msg, _ = _unwrap(tok) if tok else (None, False)
        auth, user, dom, ws = ntlmauth.parse_authenticate(msg)
    except Exception:
        ctx.emit("proto.interaction", addr, port, "rdp", session, detail="credssp.bad_authenticate", bytes=len(raw))
        return
    ctx.emit("rdp.auth", addr, port, "rdp", session, username=user or None, domain=dom or None,
             workstation=ws or None, cookie_user=cookie_user, anonymous=not user)
    ok = False
    if user:
        ok = ntlmauth.check(ctx, "rdp", auth, user, dom, ws, chal, addr, port, session, grant=False)[2] is not None
    if sv >= 3:
        try:
            t.sendall(ts_request(sv, error=STATUS_LOGON_TYPE_NOT_GRANTED if ok else STATUS_LOGON_FAILURE))
        except OSError:
            pass


def ntlm_from_blob(blob):
    """Best effort: find an NTLMSSP NEGOTIATE/AUTHENTICATE inside CredSSP and pull names."""
    i = blob.find(b"NTLMSSP\x00")
    if i < 0:
        return None
    m = blob[i:]
    if len(m) < 12:
        return None
    mtype = struct.unpack("<I", m[8:12])[0]
    out = {"ntlm_type": mtype}
    if mtype == 1 and len(m) >= 32:
        dlen, _, doff = struct.unpack("<HHI", m[16:24])
        wlen, _, woff = struct.unpack("<HHI", m[24:32])
        out["domain"] = m[doff:doff + dlen].decode("latin-1", "replace") or None
        out["workstation"] = m[woff:woff + wlen].decode("latin-1", "replace") or None
    return out
