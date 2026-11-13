"""SMB file server emulator (impacket SimpleSMBServer + SMB2 command hooks + Windows persona).

Persona: SMB1 refused like a Windows Server 2019 with SMB1 disabled (only SMB 2.x answers), stable
per-install ServerGUID, persona OS version / names in the NTLM CHALLENGE, a fresh server challenge per
logon, ServerStartTime 0 (what Windows 10/2016+ send) — none of impacket's tell-tale defaults.

Auth: a null session (empty user + password) is allowed so the bait shares can be opened by name (that is
the breadcrumb), but — like Windows Server 2019 (RestrictAnonymous / no srvsvc in NullSessionPipes) — it
cannot enumerate shares (srvsvc open: ACCESS_DENIED); a named user logs on ONLY with a bait credential's correct password valid on this decoy
(NTLMv2/v1 response verified against its NT hash). Wrong/unknown → STATUS_LOGON_FAILURE + auth.failed.
Shares are served read-only from the bait tree; uploads to writable-looking shares (svc "writable",
default Public) go to the inert upload store (sha256, quota shared with FTP).

Events: smb.negotiate (2), smb.auth (2, attribution), auth.failed (3; honey=True → 4), honeytoken.used
(5, correct bait password only), auth.success (4), smb.tree (2 for IPC$, 3 for data shares),
smb.share_enum (3; denied=True for a null session), smb.list (3), file.read (4, once per open handle),
file.write (4: stored upload, denied write, or dropped over quota), smb.admin_share (3: tree connect to
ADMIN$/C$, or any non-pipe open / listing / read on IPC$).

IPC$ is pipe-only (pentest F-01): only registered named pipes open there; any other name is
OBJECT_NAME_NOT_FOUND (the share root: ACCESS_DENIED), a directory listing is INVALID_PARAMETER. As defence
in depth IPC$ is backed by an empty, dedicated directory (never "" = the process CWD), the security hooks
fail closed, and start_smb refuses a share table where any share maps outside the bait tree.
"""
import copy
import logging
import os
import random
import secrets
import socket
import struct
import threading
import time
import types

from impacket import ntlm, smb, smbserver, smb3structs as smb2, uuid as imp_uuid
from impacket.dcerpc.v5 import srvs as ms_srvs
from impacket.nt_errors import (STATUS_ACCESS_DENIED, STATUS_BAD_NETWORK_NAME, STATUS_INSUFFICIENT_RESOURCES,
                                STATUS_INVALID_PARAMETER,
                                STATUS_LOGON_FAILURE, STATUS_MORE_PROCESSING_REQUIRED,
                                STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS)
from impacket.smbserver import SimpleSMBServer
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

from rpot.common.events import new_session
from rpot.sensor import ntlmauth
from rpot.sensor.base import UploadStore, bind_ip, win_version
from rpot.sensor.emptydir import empty_dir

NTLMSSP = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
SMB2_DIALECTS = (0x0210, 0x0202)            # what we can really serve (signing = HMAC-SHA256), best first
WRITE_ACCESS = smb2.FILE_WRITE_DATA | smb2.FILE_APPEND_DATA | smb2.GENERIC_WRITE | smb2.GENERIC_ALL


def _ft(epoch):
    return int(epoch * 10000000) + 116444736000000000


# ----------------------------------------------------------------------------------------------------
# impacket patches. Each one only acts on servers carrying our persona (srv.rpot), so plain impacket
# use elsewhere in the process is unaffected.
_orig_ntlm_auth = smbserver.SMB2Commands._ntlm_auth
_orig_validate = smbserver.Ioctls.fsctlValidateNegotiateInfo


def _ntlm_auth(token, connData, smbServer, rawNTLM):
    p = getattr(smbServer, "rpot", None)
    return p.ntlm_auth(token, connData, smbServer, rawNTLM) if p else _orig_ntlm_auth(token, connData, smbServer, rawNTLM)


def _validate(connId, smbServer, ioctlRequest):
    p = getattr(smbServer, "rpot", None)
    if not p:
        return _orig_validate(connId, smbServer, ioctlRequest)
    cd = smbServer.getConnectionData(connId)
    r = smb2.VALIDATE_NEGOTIATE_INFO_RESPONSE()
    r["Capabilities"], r["Guid"], r["SecurityMode"] = p.caps(cd.get("rpot_dialect", 0x0202)), p.guid, p.sec_mode
    r["Dialect"] = cd.get("rpot_dialect", 0x0202)
    return r.getData(), STATUS_SUCCESS


smbserver.SMB2Commands._ntlm_auth = staticmethod(_ntlm_auth)
smbserver.Ioctls.fsctlValidateNegotiateInfo = staticmethod(_validate)


class _SMBServer(smbserver.SMBSERVER):
    daemon_threads, block_on_close = True, False           # an idle client must never block sensor shutdown

    def processRequest(self, connId, data):
        if data[:4] == b"\xffSMB":
            # SMB1 is disabled on the persona: only an SMB1 NEGOTIATE that offers SMB 2.x is answered (with
            # an SMB2 response, like Windows); anything else drops the connection (Windows sends a RST).
            if data[4:5] != b"\x72" or not (b"\x02SMB 2.002\x00" in data or b"\x02SMB 2.???\x00" in data):
                raise ConnectionResetError("SMB1 disabled")
        return super().processRequest(connId, data)

    def removeConnection(self, name):
        # a client that drops TCP without closing its srvsvc/wkssvc pipe must not keep the RPC socket open
        for f in list(self.getActiveConnections().get(name, {}).get("OpenedFiles", {}).values()):
            try:
                if f.get("Socket"):
                    f["Socket"].close()
                elif f.get("rpot_upload"):           # unfinished upload: discard
                    os.close(f["FileHandle"])
                    os.remove(f["FileName"])
            except (OSError, TypeError):
                pass
        _drop_pending()
        return super().removeConnection(name)


HIDDEN = {"ADMIN$": "Remote Admin", "C$": "Default share"}
PIPES = ("srvsvc", "wkssvc")                        # the only names that open on IPC$
# well-known Windows pipes we have no RPC backend for: an open is a logged pipe attempt (smb.pipe), not a disk
# access, and fails like a missing pipe
OTHER_PIPES = frozenset(("samr", "lsarpc", "lsass", "netlogon", "winreg", "svcctl", "atsvc", "spoolss", "epmapper",
                         "eventlog", "ntsvcs", "browser", "protected_storage", "scerpc", "efsrpc", "initshutdown"))
ANON_DENIED_PIPES = ("srvsvc",)                     # not in Server 2019's NullSessionPipes: no anonymous NetShareEnum
COMMENTS = {"NETLOGON": "Logon server share ", "SYSVOL": "Logon server share "}


def _windows_srvsvc(ctx, srvs, names):
    """Share enumeration + NetrServerGetInfo like Windows: ADMIN$, C$, IPC$ ("Remote IPC") first with their
    special types, then the data shares; persona OS version and server type (impacket: 6.1 workstation)."""
    data = {names.get(k, k): dict(v, **{"share type": 0, "comment": COMMENTS.get(k, v.get("comment", ""))})
            for k, v in sorted(srvs._shares.items()) if k != "IPC$"}
    # srvsvc's display table only (never used to open files): ADMIN$/C$ are not in the SMB share config at
    # all, so a tree connect can never map them to a directory
    sh = {k: {"share type": 0x80000000, "comment": c, "path": p}
          for (k, c), p in zip(HIDDEN.items(), ("C:\\Windows", "C:\\"))}
    sh["IPC$"] = {"share type": 0x80000003, "comment": "Remote IPC", "path": ""}
    sh.update(data)
    srvs._shares = sh
    srvs.processConfigFile = lambda *a, **k: None          # keep this list (addShare would rebuild it)
    ma, mi, _ = win_version(ctx.os)
    dc = "domain-controller" in str(ctx.role.get("id", ""))
    def server_info(data):
        # Our own NetrServerGetInfo (opnum 21): impacket's raises on every call (it copies the request's
        # ServerName bytes into a WSTR -> bytes.encode), which dropped the pipe — a fingerprint. Windows
        # answers with its own computer name, not the name the client asked for.
        ms_srvs.NetrServerGetInfo(data)                           # malformed request -> exception, as before
        a = ms_srvs.NetrServerGetInfoResponse()
        a["InfoStruct"]["tag"] = 101
        i = a["InfoStruct"]["ServerInfo101"]
        i["sv101_platform_id"] = 500                              # PLATFORM_ID_NT
        i["sv101_name"] = ctx.name + "\x00"
        i["sv101_version_major"], i["sv101_version_minor"] = ma, mi
        i["sv101_type"] = 0x9003 | (0x2B if dc else 0)            # workstation+server+NT(+DC, time source)
        i["sv101_comment"] = "\x00"
        a["ErrorCode"] = 0
        return a
    for iface in srvs._listenUUIDS.values():
        cb = iface.get("CallBacks", {})
        if 21 in cb:
            cb[21] = server_info


# ----------------------------------------------------------------------------------------------------
# Named pipe -> DCE/RPC transport without loopback TCP (RC-21 / B1) and without a thread (RC-31 / N-3).
# impacket registers srvsvc/wkssvc as ('127.0.0.1', <random port>) and its SMB CREATE does
# `sock = socket.socket(); sock.connect(addr)` for a pipe. On a host-mode decoy the egress guard (REDPOT-OUT:
# uid 10001 may only reply + reach the sensor API) rejects that connection, so share enumeration came back
# empty / ACCESS_DENIED. Instead each pipe open gets an in-process _SyncPipe: nothing listens, nothing is
# addressable, netfilter never sees it, and the RPC server's TCP socket is closed. The firewall keeps
# 127.0.0.1 fully closed to the decoys.
# N-3: RC-21 served every open pipe from its own thread (300 s idle), uncharged to the connection budget, so ONE
# null session opening \wkssvc 330 times pushed the decoy to its thread ceiling and every new client from every
# source was refused. A _SyncPipe answers each complete DCE/RPC request synchronously in the SMB handler thread
# that wrote it (no thread at all), and every open pipe holds a slot of the decoy-wide budget (base.take_aux,
# kind "smb-pipe": per source IP / decoy-wide / thread headroom) plus PIPES_PER_SESSION per SMB connection.

PIPES_PER_SESSION = 8           # open pipe handles per SMB connection
PIPE_IDLE_ANON = 60             # s: an unused pipe of a null session is closed after this (named logon: below)
PIPE_IDLE_NAMED = 300
PIPE_BUF_MAX = 256 * 1024       # bytes of unanswered (incomplete) RPC request data a pipe buffers
PIPE_KIND = "smb-pipe"
_pending = threading.local()    # pipe slot reserved by the CREATE hook for impacket's connect() in the same thread
_open_pipes, _open_lock = set(), threading.Lock()


class _Slot:
    """One reserved budget slot for one pipe; release() gives it back exactly once."""

    def __init__(self, budget, ip, idle):
        self.budget, self.ip, self.idle, self._held = budget, ip, idle, True
        self.lock = threading.Lock()

    def release(self):
        with self.lock:
            held, self._held = self._held, False
        if held:
            self.budget.give_aux(self.ip, PIPE_KIND)


def _drop_pending():
    """Give back a reservation impacket never adopted (its CREATE failed before the pipe connect)."""
    slot = getattr(_pending, "slot", None)
    _pending.slot = None
    if slot is not None:
        slot.release()


def _sweep(now=None):
    """Close every pipe idle for longer than its limit (frees its budget slot)."""
    now = time.monotonic() if now is None else now
    with _open_lock:
        old = [p for p in _open_pipes if now - p.last > p.slot.idle]
    for p in old:
        p.close()


def _frames_end(buf):
    """End offset of the first complete DCE/RPC request (fragments up to PFC_LAST_FRAG), None while incomplete;
    ValueError on a fragment shorter than a request header (malformed)."""
    off = 0
    while len(buf) - off >= 16:
        flen = struct.unpack_from("<H", buf, off + 8)[0]
        if flen < 24:
            raise ValueError("malformed DCE/RPC fragment")
        if len(buf) - off < flen:
            return None
        last = buf[off + 3] & 0x02
        off += flen
        if last:
            return off
    return None


class _Wire:
    """What the pipe's DCERPCServer copy uses as its client socket: recv() from the request being processed,
    send() into the pipe's answer buffer."""

    def __init__(self):
        self.rx, self.tx = bytearray(), bytearray()

    def recv(self, n):
        if not self.rx:
            raise EOFError("incomplete request")      # never reached for a framed request; never spin
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    def send(self, data):
        self.tx += data
        return len(data)

    sendall = send

    def close(self):
        pass


class _SyncPipe:
    """One open named pipe: send()/sendall() (SMB WRITE, IOCTL transceive) buffers request bytes and answers every
    complete DCE/RPC request at once with this pipe's own copy of the RPC server; recv() (SMB READ) returns the
    buffered answer (b"" = nothing pending / pipe broken). A pipe that fails (malformed RPC) breaks like the old
    serving thread ending; close() — SMB CLOSE, TCP drop, idle sweep — frees its budget slot."""

    def __init__(self, server, slot):
        self.h = copy.copy(server)
        self.wire = _Wire()
        self.h._clientSock, self.h._boundUUID, self.h._callid = self.wire, b"", 1
        self.slot, self.inb = slot, bytearray()
        self.broken = self.closed = False
        self.last = time.monotonic()
        self.lock = threading.RLock()
        with _open_lock:
            _open_pipes.add(self)

    def live(self):
        return not self.closed

    def _fresh(self):
        now = time.monotonic()
        if now - self.last > self.slot.idle:
            self.close()
        self.last = now
        return not self.closed

    def send(self, data):
        with self.lock:
            if not self._fresh() or self.broken:
                raise BrokenPipeError("pipe closed")
            self.inb += data
            try:
                if len(self.inb) > PIPE_BUF_MAX:
                    raise ValueError("pipe buffer limit")
                while True:
                    end = _frames_end(self.inb)
                    if end is None:
                        break
                    self.wire.rx[:] = self.inb[:end]
                    del self.inb[:end]
                    req = self.h.recv()
                    if req is None:
                        break
                    ans = self.h.processRequest(req)
                    if ans is not None:
                        self.h.send(ans)
            except Exception:
                self.broken = True
                self.inb.clear()
            return len(data)

    sendall = send

    def recv(self, n):
        with self.lock:
            if not self._fresh():
                return b""
            out = bytes(self.wire.tx[:n])
            del self.wire.tx[:n]
            return out

    def settimeout(self, t):
        pass

    def close(self):
        with self.lock:
            with _open_lock:
                if self.closed:
                    return
                self.closed = True
                _open_pipes.discard(self)
            self.inb, self.wire.tx = bytearray(), bytearray()
        self.slot.release()


class _LocalPipe:
    """Registered named-pipe "address": open() returns a fresh _SyncPipe holding the budget slot that the CREATE
    hook reserved for this open (in the same SMB handler thread). No reservation → the open fails (fail closed)."""

    def __init__(self, server):
        self.server = server

    def open(self):
        slot = getattr(_pending, "slot", None)
        _pending.slot = None
        if slot is None:
            raise OSError("named pipe open without a budget slot")
        return _SyncPipe(self.server, slot)

    def __repr__(self):
        return f"<local pipe {type(self.server).__name__}>"


class _PipeSocket:
    """What impacket.smbserver gets from `socket.socket()` (only called for named pipes): connect() to a
    _LocalPipe adopts a _SyncPipe; any other address is a plain TCP connect (unchanged impacket)."""

    def __init__(self):
        self._s = None

    def connect(self, addr):
        if isinstance(addr, _LocalPipe):
            self._s = addr.open()
        else:
            self._s = socket.socket()
            self._s.connect(addr)

    def close(self):
        if self._s is not None:
            self._s.close()

    def live(self):
        return isinstance(self._s, _SyncPipe) and self._s.live()

    def __getattr__(self, name):                    # send / sendall / recv / settimeout ...
        if self._s is None:
            raise OSError("pipe socket not connected")
        return getattr(self._s, name)


_smb_socket = types.ModuleType("socket")
_smb_socket.__dict__.update(socket.__dict__)
_smb_socket.socket = lambda *a, **k: _PipeSocket() if not (a or k) else socket.socket(*a, **k)
smbserver.socket = _smb_socket


class _PipeTable(dict):
    """Registered named pipes, looked up case-insensitively (Windows pipe names are; impacket compares the
    joined path exactly, so "\\SRVSVC" would otherwise fall through to a file open)."""

    def __setitem__(self, k, v):
        super().__setitem__(str(k).lower(), v)

    def __contains__(self, k):
        return super().__contains__(str(k).lower())

    def __getitem__(self, k):
        return super().__getitem__(str(k).lower())

    def __delitem__(self, k):
        super().__delitem__(str(k).lower())


def _check_share_paths(cfg, share_root, ipc_root):
    """F-01 guard: every share in the SMB config maps to the bait share tree or (IPC$) to the empty pipe
    directory — never "", the CWD, or any other real path; ADMIN$/C$ are never mapped at all."""
    root = os.path.realpath(share_root)
    for sec in cfg.sections():
        if sec == "global":
            continue
        if sec in HIDDEN:
            raise RuntimeError(f"SMB share {sec} must not be mapped to a directory")
        p = cfg.get(sec, "path", fallback="")
        real = os.path.realpath(p) if p else ""
        ok = real == ipc_root if sec == "IPC$" else (real.startswith(root + os.sep) and os.path.isdir(real))
        if not p or not os.path.isabs(p) or not ok or real == os.path.realpath(os.getcwd()):
            raise RuntimeError(f"SMB share {sec} maps to an unsafe path {p!r}")


def _local_rpc(server):
    """Detach an impacket DCERPCServer from TCP: close its 127.0.0.1 socket (bound in its __init__), make
    its thread a no-op and return the _LocalPipe to register for the pipe name."""
    if getattr(server, "_sock", None) is not None:
        server._sock.close()
        server._sock = None
    server.run = lambda: None
    return _LocalPipe(server)


class Persona:
    """Per-server SMB/NTLM persona + auth policy (attached to the impacket server as srv.rpot)."""

    def __init__(self, ctx, port, sessions_of):
        self.ctx, self.port, self.sid = ctx, port, sessions_of
        self.guid = ctx.persona_secret("smb-server-guid")[:16]
        self.dc = "domain-controller" in str(ctx.role.get("id", ""))
        self.sec_mode = 3 if self.dc else 1          # DCs require signing, member servers only enable it

    @staticmethod
    def caps(dialect):
        return 0x7 if dialect >= 0x0210 else 0x1      # DFS (+ leasing, large MTU on 2.1)

    def negotiate(self, connId, smbServer, recvPacket, isSMB1=False):
        cd = smbServer.getConnectionData(connId, checkStatus=False)
        rp = smb2.SMB2Packet()
        rp["Flags"] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        rp["Status"] = STATUS_SUCCESS
        rp["CreditRequestResponse"] = 1
        rp["Command"] = smb2.SMB2_NEGOTIATE
        rp["SessionID"] = 0
        rp["MessageID"] = 0 if isSMB1 else recvPacket["MessageID"]
        rp["TreeID"] = 0
        if isSMB1:                                    # SMB1 negotiate offering "SMB 2.???" → wildcard, client re-negotiates
            dialects = smb.SMBCommand(recvPacket["Data"][0])["Data"].split(b"\x02")
            dialect = 0x02FF if b"SMB 2.???\x00" in dialects else 0x0202
            offered = [dialect]
        else:
            d = recvPacket["Data"]
            n = struct.unpack("<H", d[2:4])[0] if len(d) >= 4 else 0
            offered = list(struct.unpack(f"<{min(n, 64)}H", d[36:36 + 2 * min(n, 64)])) if len(d) >= 36 + 2 * min(n, 64) else []
            dialect = next((x for x in SMB2_DIALECTS if x in offered), 0x0202)
        cd["rpot_dialect"] = dialect
        cd["rpot_offered"] = offered
        r = smb2.SMB2Negotiate_Response()
        r["SecurityMode"] = self.sec_mode
        r["DialectRevision"] = dialect
        r["ServerGuid"] = self.guid
        r["Capabilities"] = self.caps(dialect)
        r["MaxTransactSize"] = r["MaxReadSize"] = r["MaxWriteSize"] = 65536
        r["SystemTime"] = _ft(time.time())
        r["ServerStartTime"] = 0                      # Windows 10 / Server 2016+ always send 0 here
        r["SecurityBufferOffset"] = 0x80
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [NTLMSSP]
        r["Buffer"] = blob.getData()
        r["SecurityBufferLength"] = len(r["Buffer"])
        rp["Data"] = r
        smbServer.setConnectionData(connId, cd)
        return None, [rp], STATUS_SUCCESS

    def ntlm_auth(self, token, connData, smbServer, rawNTLM):
        ctx = self.ctx
        mtype = struct.unpack("<L", token[8:12])[0] if token[:8] == b"NTLMSSP\0" and len(token) >= 12 else 0
        resp = smb2.SMB2SessionSetup_Response()
        if mtype == 1:
            neg = ntlm.NTLMAuthNegotiate()
            neg.fromString(token)
            chal = secrets.token_bytes(8)             # fresh per logon (impacket: one per process)
            msg = ntlmauth.challenge_message(ctx, neg["flags"], chal)
            connData["NEGOTIATE_MESSAGE"], connData["CHALLENGE_MESSAGE"] = neg, msg
            connData["Uid"] = random.randint(1, 0xffffffff)
            if rawNTLM:
                tok = msg
            else:
                tok = SPNEGO_NegTokenResp()
                tok["NegState"] = b"\x01"
                tok["SupportedMech"] = NTLMSSP
                tok["ResponseToken"] = msg.getData()
            code = STATUS_MORE_PROCESSING_REQUIRED
        elif mtype == 3 and "CHALLENGE_MESSAGE" in connData:
            auth, user, dom, ws = ntlmauth.parse_authenticate(token)
            chal = connData["CHALLENGE_MESSAGE"]["challenge"]
            src = (connData.get("ClientIP"), connData.get("ClientPort"))
            sid = self.sid(src)
            anon = not user
            ctx.emit("smb.auth", src, self.port, "smb", sid, user=user or None, domain=dom or None,
                     workstation=ws or None, anonymous=anon)
            ok, key = anon, None
            if not anon:
                ok, tid, nt = ntlmauth.check(ctx, "smb", auth, user, dom, ws, chal, src, self.port, sid)
                if ok and len(auth["ntlm"]) > 24:
                    _, key = smbserver.computeNTLMv2(user.lower(), "", nt, chal, auth, connData["CHALLENGE_MESSAGE"],
                                                     connData["NEGOTIATE_MESSAGE"])
            if ok:
                connData["SignatureEnabled"] = bool(key)
                if key:
                    connData["SigningSessionKey"], connData["SignSequenceNumber"] = key, 1
                connData["AUTHENTICATE_MESSAGE"] = auth
                connData["user_domain_name"], connData["user_name"] = dom or ws, user
                tok = smb2.Empty() if rawNTLM else SPNEGO_NegTokenResp()
                if not rawNTLM:
                    tok["NegState"] = b"\x00"
                if anon:
                    resp["SessionFlags"] = 2           # SMB2_SESSION_FLAG_IS_NULL
                code = STATUS_SUCCESS
            else:
                tok = SPNEGO_NegTokenResp()
                tok["NegState"] = b"\x02"
                code = STATUS_LOGON_FAILURE
        else:
            tok = SPNEGO_NegTokenResp()
            tok["NegState"] = b"\x02"
            code = STATUS_LOGON_FAILURE
        resp["SecurityBufferOffset"] = 0x48
        resp["SecurityBufferLength"] = len(tok)
        resp["Buffer"] = tok.getData()
        return resp, code


def start_smb(ctx, svc):
    port = svc["port"]
    share_root = os.path.join(ctx.bait_dir, "shares")
    logging.getLogger("impacket").setLevel(logging.CRITICAL)
    smbserver.LOG.setLevel(logging.CRITICAL)

    s = SimpleSMBServer(listenAddress=bind_ip(), listenPort=port, smbserverclass=_SMBServer)
    cfg = s._SimpleSMBServer__smbConfig
    cfg.set("global", "server_name", ctx.name)
    cfg.set("global", "server_os", ctx.os or "Windows Server 2019 Standard")
    cfg.set("global", "server_domain", ctx.netbios)
    names = {}
    for name in svc.get("shares") or sorted(os.listdir(share_root)):
        p = os.path.join(share_root, name)
        if os.path.isdir(p):
            s.addShare(name, p, shareComment="", readOnly="yes")
            names[name.upper()] = name
    # F-01: impacket's IPC$ path is "" = the process CWD (/opt/rpot in the image: the ReD-Pot source).
    # Back it with an empty dedicated directory; impacket looks pipes up by os.path.join(path, name), so the
    # pipes are registered under that joined name (our CREATE hook only lets registered pipe names through).
    ipc_root = empty_dir(ctx.data_dir, "smb-ipc")
    cfg.set("IPC$", "path", ipc_root)
    smb_srv = s.getServer()
    smb_srv._SMBSERVER__registeredNamedPipes = _PipeTable()      # drop impacket's 127.0.0.1 registrations
    srvs = s._SimpleSMBServer__srvsServer
    rpc = {"srvsvc": _local_rpc(srvs), "wkssvc": _local_rpc(s._SimpleSMBServer__wkstServer)}
    for pipe in PIPES:
        s.registerNamedPipe(os.path.join(ipc_root, pipe), rpc[pipe])
    _check_share_paths(cfg, share_root, ipc_root)
    _windows_srvsvc(ctx, srvs, names)
    writable = {x.upper() for x in svc.get("writable", ["Public"])}
    store = UploadStore.of(ctx.data_dir)
    s.setSMB2Support(True)
    s.setSMBChallenge(secrets.token_hex(8))  # unused by our NTLM path; never leave impacket's default
    srv = s.getServer()
    srv.handle_error = lambda request, client_address: None   # malformed packets: drop quietly (no log flooding)
    # impacket's per-connection handler calls traceback.print_exc() unconditionally on malformed
    # packets; in this decoy process that is attacker-triggered log spam → make it a no-op.
    import traceback
    traceback.print_exc = lambda *a, **k: None

    sessions = {}      # (ip, port) -> session id
    seen = {}          # (connId, kind, key) dedupe
    lock = threading.Lock()

    def sid_of(src):
        with lock:
            sid = sessions.setdefault(src, new_session())
            if len(sessions) > 20000:
                sessions.clear()
        return sid

    persona = Persona(ctx, port, sid_of)
    srv.rpot = persona
    srv.hookSmb2Command(smb2.SMB2_NEGOTIATE, persona.negotiate)

    def info(connId):
        cd = srv.getConnectionData(connId, False)
        src = (cd.get("ClientIP"), cd.get("ClientPort"))
        return cd, src, sid_of(src)

    def once(connId, kind, key):
        k = (connId, kind, key)
        with lock:
            if k in seen:
                return False
            seen[k] = 1
            if len(seen) > 50000:
                seen.clear()
        return True

    def share_of(cd, tid):
        sh = cd.get("ConnectedShares", {}).get(tid) or {}
        return sh.get("shareName") or _share_name(sh.get("path", ""), share_root)

    def is_ipc(cd, tid):
        sh = cd.get("ConnectedShares", {}).get(tid) or {}
        return (sh.get("shareName") or "").upper() == "IPC$" or sh.get("path") == ipc_root

    def admin_share(src, sid, cd, share, op, path="", status=STATUS_ACCESS_DENIED):
        """F-01: an attempt to use an admin share as a disk (IPC$ file/dir, ADMIN$, C$) = L3 + the reply."""
        if once(id(cd), "admin", (share, op, path)):
            ctx.emit("smb.admin_share", src, port, "smb", sid, share=share, op=op, path=path[:200],
                     user=cd.get("user_name"))
        return ("reply", ([smb2.SMB2Error()], None, status))

    def hook(cmd, fn, fail_closed=False):
        """fn(connId, pkt, "pre") may return ("reply", result) to answer instead of impacket. A security hook
        (fail_closed) that raises answers ACCESS_DENIED instead of letting impacket serve the request."""
        orig = srv.hookSmb2Command(cmd, None)

        def wrapper(connId, smbServer, recvPacket, *extra):
            try:
                pre = fn(connId, recvPacket, "pre")
            except Exception:
                if fail_closed:
                    return [smb2.SMB2Error()], None, STATUS_ACCESS_DENIED
                pre = None
            if isinstance(pre, tuple) and pre[:1] == ("reply",):
                return pre[1]
            res = orig(connId, smbServer, recvPacket, *extra)
            try:
                fn(connId, recvPacket, ("post", pre, res))
            except Exception:
                pass
            return res
        srv.hookSmb2Command(cmd, wrapper)

    # NEGOTIATE ----------------------------------------------------------------
    def on_neg(connId, pkt, phase):
        if phase != "pre":
            cd, src, sid = info(connId)
            d = cd.get("rpot_dialect", 0x0202)
            if d != 0x02FF and once(connId, "neg", 0):        # wildcard answer: the real negotiate follows
                ctx.emit("smb.negotiate", src, port, "smb", sid, dialect=f"SMB {d >> 8}.{d & 0xff:x}",
                         offered=[f"{x:#06x}" for x in cd.get("rpot_offered", [])][:12])
    hook(smb2.SMB2_NEGOTIATE, on_neg)

    # SESSION SETUP: impacket marks the connection authenticated after ANY session setup message, even a
    # rejected one — only a successful logon may unlock tree connects.
    def on_sess(connId, pkt, phase):
        if phase != "pre" and phase[2][2] != STATUS_SUCCESS:
            cd = srv.getConnectionData(connId, False)
            cd["Authenticated"] = False
    hook(smb2.SMB2_SESSION_SETUP, on_sess)

    # TREE CONNECT ----------------------------------------------------------------
    def on_tree(connId, pkt, phase):
        if phase != "pre":
            return
        cd, src, sid = info(connId)
        req = smb2.SMB2TreeConnect(pkt["Data"])
        path = pkt.getData()[req["PathOffset"]:][:req["PathLength"]].decode("utf-16le", "replace")
        share = path.split("\\")[-1]
        if share.upper() in HIDDEN:                   # admin shares exist but need an administrator
            return admin_share(src, sid, cd, share.upper(), "tree", path)
        ctx.emit("smb.tree", src, port, "smb", sid, share=share, unc=path[:200], user=cd.get("user_name"))
        if share.upper() != "IPC$" and share.upper() not in names:
            return ("reply", ([smb2.SMB2Error()], None, STATUS_BAD_NETWORK_NAME))
    hook(smb2.SMB2_TREE_CONNECT, on_tree, fail_closed=True)

    # CREATE (open) ------------------------------------------------------------------
    def on_create(connId, pkt, phase):
        if phase != "pre":
            _drop_pending()                           # a reserved pipe slot impacket did not use
            return
        _drop_pending()
        cd, src, sid = info(connId)
        req = smb2.SMB2Create(pkt["Data"])
        name = pkt.getData()[req["NameOffset"]:][:req["NameLength"]].decode("utf-16le", "replace")
        share = share_of(cd, pkt["TreeID"])
        if is_ipc(cd, pkt["TreeID"]):
            return on_ipc_create(cd, src, sid, connId, name)
        if name.lower() in ("srvsvc", "wkssvc", "samr", "lsarpc", "winreg", "netlogon"):
            if once(connId, "pipe", name.lower()):
                ctx.emit("smb.pipe", src, port, "smb", sid, pipe=name, user=cd.get("user_name"))
            return
        return on_upload(cd, src, sid, pkt, req, name, share)
    hook(smb2.SMB2_CREATE, on_create, fail_closed=True)

    def on_ipc_create(cd, src, sid, connId, name):
        """IPC$ is pipe-only (F-01). A registered pipe is passed to impacket under its exact registered name;
        anything else never reaches the file system."""
        pipe = name.replace("/", "\\").strip("\\").lower()
        if pipe in OTHER_PIPES:
            if once(connId, "pipe", pipe):
                ctx.emit("smb.pipe", src, port, "smb", sid, pipe=pipe, user=cd.get("user_name"))
            return ("reply", ([smb2.SMB2Error()], None, STATUS_OBJECT_NAME_NOT_FOUND))
        if pipe not in PIPES:
            if not pipe:                              # the share root (smbclient `ls`, `cd \`)
                return admin_share(src, sid, cd, "IPC$", "open", "\\")
            return admin_share(src, sid, cd, "IPC$", "open", name, STATUS_OBJECT_NAME_NOT_FOUND)
        anon = not cd.get("user_name")
        if once(connId, "pipe", pipe):
            t = "smb.share_enum" if pipe == "srvsvc" else "smb.pipe"
            extra = {"denied": True} if anon and pipe in ANON_DENIED_PIPES else {}
            ctx.emit(t, src, port, "smb", sid, pipe=pipe, user=cd.get("user_name"), **extra)
        if anon and pipe in ANON_DENIED_PIPES:        # RestrictAnonymous: no NetShareEnum for a null session
            return ("reply", ([smb2.SMB2Error()], None, STATUS_ACCESS_DENIED))
        return reserve_pipe(cd, src, sid, pipe, anon)  # None: impacket opens the pipe (case-insensitive lookup)

    def reserve_pipe(cd, src, sid, pipe, anon):
        """N-3: an open pipe costs a budget slot. Over PIPES_PER_SESSION on this connection, the source's
        per-IP pipe cap, the decoy-wide pipe cap or the thread headroom → STATUS_INSUFFICIENT_RESOURCES
        (Windows' answer when the server cannot allocate an open); the source's own cap → smb.pipe_flood (L4)."""
        from rpot.sensor import base
        budget = base.BUDGET
        live = sum(1 for f in list(cd.get("OpenedFiles", {}).values())
                   if isinstance(f.get("Socket"), _PipeSocket) and f["Socket"].live())
        if live >= PIPES_PER_SESSION:
            why, limit = "per_session", PIPES_PER_SESSION
        else:
            _sweep()
            why = budget.take_aux(src[0], PIPE_KIND)
            limit = budget.aux_limit(why)
        if why is None:
            _pending.slot = _Slot(budget, src[0], PIPE_IDLE_ANON if anon else PIPE_IDLE_NAMED)
            return None
        if why in ("per_session", "per_ip"):
            base.exhaustion(ctx, src, port, "smb", "smb_pipe", why, limit, session=sid, type_="smb.pipe_flood",
                            pipe=pipe, user=cd.get("user_name"), pipes=live,
                            pipes_ip=budget.aux.get((PIPE_KIND, src[0]), 0))
        else:                                         # decoy-wide: blame the source holding all its pipe slots
            ip, held = budget.top_aux(PIPE_KIND)
            if ip is not None and held >= budget.aux_per_ip:
                base.exhaustion(ctx, (ip, None), port, "smb", "smb_pipe", why, limit, type_="smb.pipe_flood",
                                pipes_ip=held)
        return ("reply", ([smb2.SMB2Error()], None, STATUS_INSUFFICIENT_RESOURCES))

    def on_upload(cd, src, sid, pkt, req, name, share):
        """A create/overwrite with write access: writable-looking share → inert upload store (bait tree
        untouched); any other share → ACCESS_DENIED (impacket) but always a file.write event."""
        disp, opts = req["CreateDisposition"], req["CreateOptions"]
        creates = disp in (smb2.FILE_SUPERSEDE, smb2.FILE_CREATE, smb2.FILE_OVERWRITE, smb2.FILE_OVERWRITE_IF)
        if not (req["DesiredAccess"] & WRITE_ACCESS or creates):
            return None
        tree = cd.get("ConnectedShares", {}).get(pkt["TreeID"]) or {}
        base, nm = tree.get("path"), smbserver.normalize_path(name)
        if not base or not smbserver.isInFileJail(base, nm):
            return None                                   # impacket answers the bad path
        real = os.path.join(base, nm)
        exists = os.path.exists(real)
        rel = (share + "\\" + nm.replace("/", "\\")).rstrip("\\")
        is_dir = bool(opts & smb2.FILE_DIRECTORY_FILE) or (exists and os.path.isdir(real))
        if is_dir and exists and not creates:
            return None                                   # opening an existing folder
        if is_dir or (share or "").upper() not in writable:
            if once(id(cd), "deny", rel):
                ctx.emit("file.write", src, port, "smb", sid, path=rel, user=cd.get("user_name"), denied=True,
                         op="mkdir" if is_dir else "write")
            return ("reply", ([smb2.SMB2Error()], None, STATUS_ACCESS_DENIED))
        if not os.path.isdir(os.path.dirname(real)) or (not exists and disp in (smb2.FILE_OPEN, smb2.FILE_OVERWRITE)):
            return None                                   # impacket: path / file not found
        fd, part = store.new_part()
        fid = imp_uuid.generate()
        now = _ft(time.time())
        r = smb2.SMB2Create_Response()
        r["OplockLevel"] = 0
        r["CreateAction"] = 2 if not exists else 3     # FILE_CREATED / FILE_OVERWRITTEN
        r["CreationTime"] = r["LastAccessTime"] = r["LastWriteTime"] = r["ChangeTime"] = now
        r["AllocationSize"] = r["EndOfFile"] = 0
        r["FileAttributes"] = 0x20                     # ARCHIVE
        r["FileID"] = fid
        r["Buffer"] = b"\x00"
        cd["OpenedFiles"][fid] = {"FileHandle": fd, "FileName": part, "DeleteOnClose": False,
                                  "Open": {"EnumerationLocation": 0, "EnumerationSearchPattern": ""},
                                  "rpot_upload": rel, "rpot_trunc": False}
        cd["LastRequest"]["SMB2_CREATE"] = r
        return ("reply", ([r], None, STATUS_SUCCESS))

    # QUERY DIRECTORY (listing) ---------------------------------------------------------
    def on_qdir(connId, pkt, phase):
        if phase != "pre":
            return
        cd, src, sid = info(connId)
        if is_ipc(cd, pkt["TreeID"]):                 # a pipe share has no directories
            return admin_share(src, sid, cd, "IPC$", "list", "\\", STATUS_INVALID_PARAMETER)
        req = smb2.SMB2QueryDirectory(pkt["Data"])
        fid = req["FileID"].getData()
        f = cd.get("OpenedFiles", {}).get(fid) or {}
        path = _rel(f.get("FileName", ""), share_root)
        if once(connId, "list", path):
            ctx.emit("smb.list", src, port, "smb", sid, path=path, user=cd.get("user_name"))
    hook(smb2.SMB2_QUERY_DIRECTORY, on_qdir, fail_closed=True)

    def ipc_non_pipe(cd, pkt, fid):
        """On IPC$, only an open pipe handle may be read / written (defence in depth: a non-pipe handle
        cannot be opened there in the first place)."""
        if fid == b"\xff" * 16 and "SMB2_CREATE" in cd.get("LastRequest", {}):
            fid = cd["LastRequest"]["SMB2_CREATE"]["FileID"]
            fid = fid.getData() if hasattr(fid, "getData") else fid
        f = cd.get("OpenedFiles", {}).get(fid)
        return f if f is not None and not f.get("Socket") else None

    # READ -----------------------------------------------------------------------------
    def on_read(connId, pkt, phase):
        if phase != "pre":
            return
        cd, src, sid = info(connId)
        req = smb2.SMB2Read(pkt["Data"])
        fid = req["FileID"].getData()
        if is_ipc(cd, pkt["TreeID"]):
            bad = ipc_non_pipe(cd, pkt, fid)
            if bad is not None:
                return admin_share(src, sid, cd, "IPC$", "read", os.path.basename(str(bad.get("FileName", ""))))
            return  # named-pipe RPC traffic, not file access
        f = cd.get("OpenedFiles", {}).get(fid) or {}
        fn = f.get("FileName")
        if fn and not f.get("rpot_upload") and once(connId, "read", fid + fn.encode()):
            rel = _rel(fn, share_root)
            ctx.emit("file.read", src, port, "smb", sid, path=rel, user=cd.get("user_name"),
                     bait=_is_bait(rel))
    hook(smb2.SMB2_READ, on_read, fail_closed=True)

    # WRITE ----------------------------------------------------------------------------
    def on_write(connId, pkt, phase):
        if phase != "pre":
            return
        cd, src, sid = info(connId)
        req = smb2.SMB2Write(pkt["Data"])
        fid = req["FileID"].getData()
        if is_ipc(cd, pkt["TreeID"]):
            if ipc_non_pipe(cd, pkt, fid) is not None:
                return admin_share(src, sid, cd, "IPC$", "write")
            return  # named-pipe RPC traffic, not file access
        if fid == b"\xff" * 16 and "SMB2_CREATE" in cd.get("LastRequest", {}):
            fid = cd["LastRequest"]["SMB2_CREATE"]["FileID"]
            fid = fid.getData() if hasattr(fid, "getData") else fid
        f = cd.get("OpenedFiles", {}).get(fid) or {}
        if f.get("rpot_upload"):
            if req["Offset"] + req["Length"] > store.max_file:     # per-file cap: accept, don't keep
                f["rpot_trunc"] = True
                r = smb2.SMB2Write_Response()
                r["Buffer"], r["Count"], r["Remaining"] = b"\x00", req["Length"], 0
                return ("reply", ([r], None, STATUS_SUCCESS))
            return None
        if once(connId, "write", fid):
            ctx.emit("file.write", src, port, "smb", sid, path=_rel(f.get("FileName", "?"), share_root),
                     user=cd.get("user_name"), bytes=req["Length"], denied=True)
    hook(smb2.SMB2_WRITE, on_write, fail_closed=True)

    # CLOSE: a finished upload goes into the store -------------------------------------
    def on_close(connId, pkt, phase):
        cd, src, sid = info(connId)
        if phase == "pre":
            req = smb2.SMB2Close(pkt["Data"])
            f = cd.get("OpenedFiles", {}).get(req["FileID"].getData()) or {}
            return dict(f) if f.get("rpot_upload") else None
        f = phase[1]
        if not f:
            return
        part = f["FileName"]                       # impacket's close already closed the descriptor
        res = store.commit_part(part) if os.path.exists(part) else {"sha256": None, "bytes": 0, "stored": False,
                                                                       "dropped": "gone"}
        if f.get("rpot_trunc"):
            res["dropped"] = res["dropped"] or "file too large"
        ctx.emit("file.write", src, port, "smb", sid, path=f["rpot_upload"], user=cd.get("user_name"),
                 bytes=res["bytes"], sha256=res["sha256"], stored=res["stored"] and not f.get("rpot_trunc"),
                 dropped=res["dropped"])
    hook(smb2.SMB2_CLOSE, on_close)

    # tcp.connect for touch scoring: wrap process_request ---------------------------------
    orig_verify = srv.verify_request

    def verify(request, client_address):
        ctx.emit("tcp.connect", client_address, port, "smb", None)
        return orig_verify(request, client_address)
    srv.verify_request = verify

    _capped_serve(ctx, s, srv, port)
    return s


def _capped_serve(ctx, s, srv, port):
    """F-02 (RC-28): SMB under the decoy-wide connection budget + self-check (base.serve_socketserver), and an
    idle limit of IDLE_UNAUTH s (60) per read until a named user has logged on (impacket's own is 300 s)."""
    from rpot.sensor import base
    handler = srv.RequestHandlerClass

    class Capped(handler):
        @property
        def _SMBSERVERHandler__timeOut(self):            # read by impacket's handle() before every packet
            try:
                cd = self.server.getConnectionData(self._SMBSERVERHandler__connId, False)
                named = cd.get("Authenticated") and cd.get("user_name")
            except Exception:
                named = False
            return 300 if named else base.IDLE_UNAUTH

        @_SMBSERVERHandler__timeOut.setter
        def _SMBSERVERHandler__timeOut(self, v):
            pass
    srv.RequestHandlerClass = Capped
    base.serve_socketserver(ctx, srv, port, "smb", run=s.start, name=f"smb:{port}")


def _rel(fn, root):
    if not fn:
        return ""
    r = os.path.realpath(root)
    p = os.path.realpath(fn) if os.path.isabs(fn) else fn
    if p.startswith(r):
        p = p[len(r):]
    return p.replace("/", "\\").lstrip("\\")


def _share_name(path, root):
    rel = _rel(path, root)
    return rel.split("\\")[0] if rel else ""


def _is_bait(rel):
    low = rel.lower()
    return any(k in low for k in ("password", ".key", "salar", "network_overview", "backup_job"))
