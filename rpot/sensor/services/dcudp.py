"""UDP services every Windows Domain Controller answers (DC role):

* CLDAP 389/udp — the netlogon "LDAP ping" (&(DnsDomain=…)(Host=…)(NtVer=…)) used by nltest /dsgetdc, NetExec,
  domain join and DC locators → NETLOGON_SAM_LOGON_RESPONSE_EX built from the persona (MS-ADTS 6.3.3);
  a (User=…) term answers USER_UNKNOWN for names the DC does not know (CLDAP user enumeration is visible).
  Other CLDAP searches get the rootDSE (only the attributes that fit: no amplification).
* NetBIOS name service 137/udp — name queries for the DC's names and node status (nbtstat -A, nbtscan,
  nmap nbstat): DC01<00>/<20>, DOMAIN<00>/<1C> (group), DOMAIN<1B> (PDC).
* NTP 123/udp — a valid NTPv3/v4 server reply (mode 4, stratum 3) with the current time, like w32time.

Replies go through serve_udp (per-source rate limit, reply ≤ 4× request). Events are de-duplicated per
source: cldap.ping (2), nbns.query (1 name query / 2 node status), ntp.query (1).
"""
import hashlib
import os
import re
import socket
import struct
import threading
import time

from rpot.sensor.base import bind_device, iface_ipv4, serve_udp
from rpot.sensor.services import ber as B

SITE = "Default-First-Site-Name"
DS_FLAGS = 0xE001F3FD        # PDC GC LDAP DS KDC TIMESERV CLOSEST WRITABLE GOOD_TIMESERV FULL_SECRET WS DS_8-10 + DNS names
NTP_DELTA = 2208988800


class Once:
    """True the first time a key is seen within `window` seconds (bounded memory)."""

    def __init__(self, window):
        self.window, self.seen, self.lock = window, {}, threading.Lock()

    def __call__(self, key):
        now = time.time()
        with self.lock:
            if now - self.seen.get(key, 0) < self.window:
                return False
            self.seen[key] = now
            if len(self.seen) > 20000:
                self.seen.clear()
            return True


# ------------------------------------------------------------------------------------------- CLDAP
def _compress(names, start):
    """RFC 1035 names with message compression; offsets relative to the NETLOGON structure."""
    out, table = b"", {}
    for n in names:
        labels = [x for x in n.split(".") if x]
        for i in range(len(labels) + 1):
            suffix = ".".join(labels[i:]).lower()
            if i == len(labels):
                out += b"\x00"
            elif suffix in table:
                out += struct.pack(">H", 0xC000 | table[suffix])
                break
            else:
                table[suffix] = start + len(out)
                lab = labels[i].encode()[:63]
                out += bytes([len(lab)]) + lab
    return out


def domain_guid(domain):
    return hashlib.md5(b"guid:" + domain.lower().encode()).digest()


def netlogon_ex(ctx, ntver, user=None, user_known=True, ip=None):
    """NETLOGON_SAM_LOGON_RESPONSE_EX (opcode 23, or 25 = user unknown)."""
    dom = ctx.domain.lower()
    hdr = struct.pack("<HHI", 25 if user and not user_known else 23, 0, DS_FLAGS) + domain_guid(dom)
    names = _compress([dom, dom, ctx.fqdn, ctx.netbios.upper(), ctx.name.upper()], len(hdr))
    body = hdr + names + (_compress([user], len(hdr) + len(names)) if user else b"\x00")
    tail = b""
    site_off = len(body)                               # DcSiteName; ClientSiteName points at it
    lab = SITE.encode()
    body += bytes([len(lab)]) + lab + b"\x00" + struct.pack(">H", 0xC000 | site_off)
    nt = 1 | 4
    if ntver & 0x8 and ip:
        sa = struct.pack("<HH", 2, 0) + bytes(int(x) for x in ip.split(".")) + b"\x00" * 8
        tail += bytes([len(sa)]) + sa
        nt |= 8
    if ntver & 0x10:
        tail += struct.pack(">H", 0xC000 | site_off)
    return body + tail + struct.pack("<IHH", nt, 0xFFFF, 0xFFFF)


def _pairs(el, out, depth=0):
    tag, v = el
    if depth > 8 or not isinstance(v, list):
        return out
    if tag == 0xA3 and len(v) == 2:
        out[B.as_str(v[0][1]).lower()] = bytes(v[1][1])
    else:
        for c in v:
            _pairs(c, out, depth + 1)
    return out


def cldap_answer(ctx, data, src, port, once, directory=None, users=None):
    try:
        tag, msg = B.one(data)
        mid = B.as_int(msg[0][1])
        op_tag, op = msg[1]
        if op_tag != 0x63:
            return None
        base, filt = B.as_str(op[0][1]), op[6]
        want = [B.as_str(v) for _, v in (op[7][1] if len(op) > 7 else [])]
    except (ValueError, IndexError, TypeError):
        return None
    pairs = _pairs(filt, {})
    done = B.seq(B.integer(mid), B.app(5, B.enum(0) + B.octets("") + B.octets("")))
    if "ntver" in pairs or any(w.lower() == "netlogon" for w in want):
        ntver = int.from_bytes(pairs.get("ntver", b"\x06\x00\x00\x00")[:4].ljust(4, b"\x00"), "little")
        dom = pairs.get("dnsdomain", b"").decode("utf-8", "replace").rstrip(".").lower()
        user = pairs.get("user", b"").decode("utf-8", "replace")[:64] or None
        host = pairs.get("host", b"").decode("utf-8", "replace")[:64] or None
        if once((src[0], "cldap", dom, user)):
            ctx.emit("cldap.ping", src, port, "cldap", None, domain=dom or None, host=host, user=user, ntver=ntver)
        if dom and dom not in (ctx.domain.lower(), ctx.netbios.lower()):
            return done                                                   # not our domain: no entry
        known = user is None or users is None or user.lower() in users()
        nl = netlogon_ex(ctx, ntver, user, known, ctx.em.sensor_ip)
        name = next((w for w in want if w.lower() == "netlogon"), "Netlogon")
        entry = B.seq(B.integer(mid), B.app(4, B.octets("") + B.seq(B.seq(B.octets(name), B.tlv(0x31, B.octets(nl))))))
        return B.win(entry + done)
    if base == "" and directory is not None:                              # rootDSE over CLDAP
        if once((src[0], "cldap-rootdse")):
            ctx.emit("cldap.ping", src, port, "cldap", None, rootdse=True, attrs=want[:20])
        limit, attrs = max(512, len(data) * 4), []                        # serve_udp cap: never amplify
        wl = {w.lower() for w in want}
        reply = B.win(done)
        for k, v in directory.rootdse().items():
            if wl and "*" not in wl and k.lower() not in wl:
                continue
            vals = v if isinstance(v, list) else [v]
            a = attrs + [B.seq(B.octets(k), B.tlv(0x31, b"".join(B.octets(x) for x in vals)))]
            r = B.win(B.seq(B.integer(mid), B.app(4, B.octets("") + B.seq(*a))) + done)
            if len(r) <= limit:
                attrs, reply = a, r
        return reply
    return None


def start_cldap(ctx, svc):
    from rpot.sensor.services.ldap import Directory
    from rpot.sensor.services.kerberos import KDC
    port, once = svc["port"], Once(60)
    d = Directory(ctx)
    kdc = KDC(ctx)
    serve_udp(ctx, port, lambda data, addr: cldap_answer(ctx, data, addr, port, once, d, kdc.users), "cldap")


# ------------------------------------------------------------------------------------------- NBNS
def nb_encode(name, suffix):
    raw = name.upper().encode()[:15].ljust(15, b" ") + bytes([suffix]) if name != "*" else b"*" + b"\x00" * 15
    return b"\x20" + bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0xF))) + b"\x00"


def nb_decode(data, pos):
    """→ (name, suffix, end) ; ValueError on garbage."""
    if pos + 34 > len(data) or data[pos] != 0x20:
        raise ValueError("bad nb name")
    enc = data[pos + 1:pos + 33]
    if any(not 0x41 <= c <= 0x50 for c in enc):
        raise ValueError("bad nb encoding")
    raw = bytes(((enc[i] - 0x41) << 4) | (enc[i + 1] - 0x41) for i in range(0, 32, 2))
    p = pos + 33
    while p < len(data) and data[p] != 0:                                 # NetBIOS scope labels
        p += 1 + data[p]
    if p >= len(data):
        raise ValueError("bad nb scope")
    return raw[:15].rstrip(b" \x00").decode("latin-1"), raw[15], p + 1


def nb_names(ctx):
    nb, me = ctx.netbios.upper()[:15], ctx.name.upper()[:15]
    return [(me, 0x00, False), (nb, 0x00, True), (nb, 0x1C, True), (me, 0x20, False), (nb, 0x1B, False)]


SYS_NET = "/sys/class/net"


def iface_mac(dev, root=SYS_NET):
    """Hardware address of a network interface (sysfs), or None."""
    if not dev or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", dev) or dev in (".", ".."):
        return None
    try:
        with open(os.path.join(root, dev, "address")) as f:
            mac = bytes.fromhex(f.read(64).strip().replace(":", ""))
    except (OSError, ValueError):
        return None
    return mac if len(mac) == 6 and mac != b"\x00" * 6 else None


def nb_mac(ctx, root=SYS_NET):
    """Unit ID in the node-status reply = the MAC of the NIC the decoy answers on (pentest F-05: a fixed
    virtual-NIC vendor prefix on a different NIC was a tell). Host-network decoys: their interface
    (RPOT_SENSOR_IFACE / the one holding RPOT_BIND_IP), else the interface holding the sensor IP, else the first
    non-loopback NIC; none readable → all zeros (what Windows reports for an adapter without a hardware address)."""
    cached = getattr(ctx, "_nb_mac", None)
    if cached is not None:
        return cached
    devs = [bind_device()]
    ip = getattr(getattr(ctx, "em", None), "sensor_ip", None)
    try:
        names = [n for _, n in socket.if_nameindex()]
    except OSError:
        names = []
    if ip:
        devs += [n for n in names if iface_ipv4(n) == ip]
    devs += sorted(n for n in names if n != "lo")
    mac = next((m for m in (iface_mac(d, root) for d in devs) if m), b"\x00" * 6)
    try:
        ctx._nb_mac = mac
    except AttributeError:
        pass
    return mac


def nbns_answer(ctx, data, src, port, once):
    try:
        qid, flags, qd = struct.unpack(">HHH", data[:6])
        if flags & 0x8000 or (flags >> 11) & 0xF or qd != 1:                # responses / registrations: ignore
            return None
        name, suffix, end = nb_decode(data, 12)
        qtype, qclass = struct.unpack(">HH", data[end:end + 4])
    except (ValueError, struct.error):
        return None
    qname = data[12:end]
    if qtype == 0x21:                                                     # NBSTAT (node status)
        if once((src[0], "nbstat")):
            ctx.emit("nbns.query", src, port, "nbns", None, kind="status", name=name[:20] or "*")
        names = nb_names(ctx)
        rd = bytes([len(names)]) + b"".join(n.encode().ljust(15, b" ") + bytes([s]) + struct.pack(">H", (0x8000 if g else 0) | 0x0400)
                                            for n, s, g in names) + nb_mac(ctx) + b"\x00" * 40
        return struct.pack(">HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qname + struct.pack(">HHIH", 0x21, 1, 0, len(rd)) + rd
    if qtype != 0x20:
        return None
    hit = next(((n, s, g) for n, s, g in nb_names(ctx) if n == name.upper() and s == suffix), None)
    if once((src[0], "nbq", name.upper(), suffix)):
        ctx.emit("nbns.query", src, port, "nbns", None, kind="name", name=f"{name[:15]}<{suffix:02X}>", ours=bool(hit))
    if not hit:
        return None                                                       # not a WINS server: silent
    ip = bytes(int(x) for x in ctx.em.sensor_ip.split("."))
    rd = struct.pack(">H", 0x8000 if hit[2] else 0) + ip
    return struct.pack(">HHHHHH", qid, 0x8400 | (flags & 0x0100), 0, 1, 0, 0) + qname + struct.pack(">HHIH", 0x20, 1, 300000, len(rd)) + rd


def start_nbns(ctx, svc):
    port, once = svc["port"], Once(300)
    serve_udp(ctx, port, lambda data, addr: nbns_answer(ctx, data, addr, port, once), "nbns")


# ------------------------------------------------------------------------------------------- NTP
def ntp_ts(t):
    return struct.pack(">II", int(t) + NTP_DELTA, int((t % 1) * 2**32) & 0xFFFFFFFF)


def ntp_answer(ctx, data, src, port, once, now=None):
    if len(data) < 48:
        return None
    vn, mode = (data[0] >> 3) & 7, data[0] & 7
    if mode != 3 or vn not in (1, 2, 3, 4):                               # only client requests (w32time ignores mode 6/7)
        return None
    if once((src[0], "ntp")):
        ctx.emit("ntp.query", src, port, "ntp", None, version=vn)
    now = now or time.time()
    ref = now - 60 - int.from_bytes(hashlib.md5(ctx.name.encode()).digest()[:2], "big") % 900
    return (bytes([(vn << 3) | 4, 3, max(data[2], 6) if data[2] <= 17 else 10, 0xE9]) +
            struct.pack(">II", int(0.0313 * 65536), int(0.0581 * 65536)) + bytes([162, 159, 200, 123]) +
            ntp_ts(ref) + data[40:48] + ntp_ts(now) + ntp_ts(time.time()))


def start_ntp(ctx, svc):
    port, once = svc["port"], Once(600)
    serve_udp(ctx, port, lambda data, addr: ntp_answer(ctx, data, addr, port, once), "ntp")
