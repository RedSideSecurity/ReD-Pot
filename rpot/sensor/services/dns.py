"""DNS decoy (authoritative for the persona's zone; used by the DNS-server and DC roles).

* Names in the company zone resolve to the decoys (breadcrumbs: dc01 / files / backup / intranet …).
* Real zone semantics (B8, RC-24): apex SOA/NS/A, the DC's _msdcs zone and Net Logon records, empty non-terminals
  → NOERROR/NODATA, NXDOMAIN/NODATA with the zone SOA in AUTHORITY (build_zones / _lookup).
* Everything outside the zone gets REFUSED (BIND) / SERVFAIL (Microsoft DNS on the DC): no recursion → no open
  resolver, no amplification.
* Zone-transfer (AXFR/IXFR) and CHAOS version.bind fingerprinting are logged as intent. version.bind answers
  like the server the role imitates: BIND 9 on the Linux DNS role; on the DC the Windows default
  (EnableVersionQuery=0): every CHAOS query → NOTIMP, flags QR|RD only (0x8104), which nmap -sV reports as
  "Simple DNS Plus", o/Windows, like most real DCs (B3, RC-23: the old REFUSED reply, 0x8105, matched nmap's
  "NLnet Labs NSD" rule; NOTIMP with RA, 0x8184, would match "Cloudflare public DNS").
* Microsoft DNS sets RA in every other answer (a DC recurses for its clients by default) but the decoy still
  never recurses: RA is only a header bit, out-of-zone names get SERVFAIL as if the forwarders were down.
* Non-QUERY opcodes (nmap's DNSStatusRequest = STATUS) get a header-only NOTIMP, never larger than the request.

Events: dns.query (2), dns.axfr (3), dns.version (3).
"""
import hashlib
import struct
import threading
import time
import uuid

from rpot.sensor.base import serve_tcp, serve_udp, bind_ip

A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, AXFR, IXFR, ANY = 1, 2, 5, 6, 12, 15, 16, 28, 33, 252, 251, 255
QTYPE = {A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", PTR: "PTR", MX: "MX", TXT: "TXT", AAAA: "AAAA",
         SRV: "SRV", AXFR: "AXFR", IXFR: "IXFR", ANY: "ANY"}
BIND_VERSION = "9.18.28-0ubuntu0.22.04.1-Ubuntu"
RA = 0x0080



def microsoft_dns(ctx):
    """Windows roles (the DC) run Microsoft DNS; the Linux DNS role keeps the BIND persona."""
    return (ctx.role.get("id") or "").startswith("windows")


def parse_query(data):
    """→ (id, flags, qname, qtype, qclass, question_end) ; raises ValueError on garbage."""
    if len(data) < 17:
        raise ValueError("short")
    qid, flags, qd = struct.unpack(">HHH", data[:6])
    if qd != 1 or flags & 0x8000:
        raise ValueError("not a single query")
    labels, pos = [], 12
    while True:
        if pos >= len(data) or len(labels) > 64:
            raise ValueError("bad name")
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 or pos + 1 + n > len(data):
            raise ValueError("bad label")
        labels.append(data[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    if pos + 4 > len(data):
        raise ValueError("short question")
    qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
    return qid, flags, ".".join(labels).lower(), qtype, qclass, pos + 4


def _name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.rstrip(".").split(".") if p) + b"\x00"


def _rr(rtype, rdata, ttl=3600, cls=1):
    return b"\xc0\x0c" + struct.pack(">HHIH", rtype, cls, ttl, len(rdata)) + rdata


# ---- zone data -------------------------------------------------------------------------------------------------
# Windows DNS on a DC (B8, RC-24). Sources, see tests/test_rc24_dns_apex.py for the full list:
#  * SOA defaults of a new Windows zone (DNS Manager > SOA tab): refresh 15 min, retry 10 min, expire 1 day,
#    minimum (negative) TTL 1 h, SOA/NS TTL 1 h; primary = the DC that created the zone, responsible person
#    hostmaster.<domain>; the serial is a plain counter bumped by every dynamic update (not YYYYMMDDnn).
#  * Net Logon registers (netlogon.dns) the "same as parent" A record at the domain apex, the SRV records under
#    _tcp/_udp/_sites and _msdcs, <DsaGuid>._msdcs CNAME <dc fqdn>, gc._msdcs A, and DomainDnsZones /
#    ForestDnsZones A + SRV, all with Netlogon's DnsTtl default 600 s. Host A records (DNS client): 1200 s.
#  * dcpromo (2003+) puts _msdcs.<forest> in its own forest-wide zone with a delegation in the parent zone; the
#    DC hosts both, so it answers _msdcs names authoritatively from that zone.
#  * AD-integrated zones refuse zone transfers by default → AXFR/IXFR REFUSED.
WIN_SOA = (900, 600, 86400, 3600)                # refresh, retry, expire, minimum
BIND_SOA = (10800, 3600, 604800, 3600)           # the usual hand-written BIND zone: 3h 1h 1w 1h
SITE = "default-first-site-name"
T_HOST, T_NETLOGON, T_ZONE = 1200, 600, 3600


def _h(ctx, label):
    """Stable per-install bytes shared by every decoy of the install (company seed), so the DC's GUIDs and serial
    don't change between restarts and the DC / DNS decoys agree. Old configs without a seed: per-sensor secret."""
    co = ctx.cfg.get("company") or {}
    if co.get("seed") is not None:
        return hashlib.sha256(f"rpot-dns\0{co['seed']}\0{ctx.domain.lower()}\0{label}".encode()).digest()
    ps = getattr(ctx, "persona_secret", None)
    if ps:
        try:
            return ps("dns-" + label)
        except Exception:
            pass
    return hashlib.sha256(f"rpot-dns\0{ctx.domain.lower()}\0{label}".encode()).digest()


def _guid(ctx, label):
    return str(uuid.UUID(bytes=_h(ctx, label)[:16], version=4))


def _serial(ctx, ms, label, now=None):
    r = int.from_bytes(_h(ctx, "serial-" + label)[:4], "big")
    now = time.time() if now is None else now
    if ms:          # a counter bumped by dynamic updates: per-install base + one step per 6 h since 2025-01-01
        step = 21600 if label == "dom" else 86400
        return 40 + r % 2500 + max(0, int(now - 1735689600) // step)
    # BIND: YYYYMMDDnn of an edit 7..400 days ago (fixed per install, never in the future)
    day = time.gmtime(max(0, int(now) - (7 + r % 393) * 86400))
    return int(time.strftime("%Y%m%d", day)) * 100 + 1 + (r >> 16) % 4


def build_zone(ctx):
    """name → ip for the persona zone, from the decoys this sensor knows about (sensor.json 'zone')."""
    dom = ctx.domain.lower()
    z = {}
    for name, ip in (ctx.cfg.get("zone") or {}).items():
        z[f"{name.lower()}.{dom}"] = ip
    z.setdefault(f"{ctx.name.lower()}.{dom}", ctx.em.sensor_ip)
    roles = ctx.cfg.get("zone_roles") or {}
    alias = {"windows-file-server": ["files", "fileserver"], "linux-web-hosting": ["intranet", "portal", "www"],
             "ftp-backup-server": ["backup", "ftp"], "windows-domain-controller": ["dc", "ad"], "linux-dns-server": ["ns1"]}
    for host, role in roles.items():
        ip = z.get(f"{host.lower()}.{dom}")
        for a in alias.get(role, []):
            z.setdefault(f"{a}.{dom}", ip)
    dc = next((h for h, r in roles.items() if r == "windows-domain-controller"), None)
    return z, (f"{dc.lower()}.{dom}" if dc else None)


def build_zones(ctx, now=None):
    """→ {origin: {name: [(type, ttl, value)]}} — every zone this server is authoritative for.
    DC (Microsoft DNS): <domain> and the forest zone _msdcs.<domain>, Windows SOA. Linux DNS role (BIND): one
    zone <domain> (the AD locator records, if a DC exists, live inside it), BIND-style SOA, NS = itself."""
    hosts, _ = build_zone(ctx)
    dom = ctx.domain.lower()
    ms = microsoft_dns(ctx)
    roles = ctx.cfg.get("zone_roles") or {}
    dcs = sorted(h.lower() for h, r in roles.items() if r == "windows-domain-controller")
    if ms and ctx.name.lower() not in dcs:
        dcs.insert(0, ctx.name.lower())
    elif ms:
        dcs.remove(ctx.name.lower())
        dcs.insert(0, ctx.name.lower())               # this DC created the zone: SOA primary
    dcs = [(f"{d}.{dom}", hosts.get(f"{d}.{dom}")) for d in dcs]
    msdcs = "_msdcs." + dom
    z = {}

    def add(name, rtype, ttl, value):
        z.setdefault(name, []).append((rtype, ttl, value))

    for name, ip in hosts.items():
        if ip:
            add(name, A, T_HOST, ip)
        else:
            z.setdefault(name, [])                                      # known name, no address: NODATA
    for fq, ip in dcs:
        if ip:                                                          # "same as parent folder" A + partitions
            for n in (dom, "domaindnszones." + dom, "forestdnszones." + dom, "gc." + msdcs):
                add(n, A, T_NETLOGON, ip)
        srv = [("_ldap._tcp", 389), ("_kerberos._tcp", 88), ("_kerberos._udp", 88), ("_kpasswd._tcp", 464),
               ("_kpasswd._udp", 464), ("_gc._tcp", 3268), (f"_ldap._tcp.{SITE}._sites", 389),
               (f"_kerberos._tcp.{SITE}._sites", 88), (f"_gc._tcp.{SITE}._sites", 3268),
               ("_ldap._tcp.domaindnszones", 389), (f"_ldap._tcp.{SITE}._sites.domaindnszones", 389),
               ("_ldap._tcp.forestdnszones", 389), (f"_ldap._tcp.{SITE}._sites.forestdnszones", 389),
               ("_ldap._tcp.dc._msdcs", 389), ("_kerberos._tcp.dc._msdcs", 88),
               (f"_ldap._tcp.{SITE}._sites.dc._msdcs", 389), (f"_kerberos._tcp.{SITE}._sites.dc._msdcs", 88),
               ("_ldap._tcp.gc._msdcs", 3268), (f"_ldap._tcp.{SITE}._sites.gc._msdcs", 3268),
               (f"_ldap._tcp.{_guid(ctx, 'domain-guid')}.domains._msdcs", 389)]
        if fq == dcs[0][0]:
            srv.append(("_ldap._tcp.pdc._msdcs", 389))                  # PDC emulator: the first DC
        for n, port in srv:
            add(f"{n}.{dom}", SRV, T_NETLOGON, (0, 100, port, fq))
        add(f"{_guid(ctx, 'dsa-' + fq)}.{msdcs}", CNAME, T_NETLOGON, fq)
    if ms:
        ns = [fq for fq, _ in dcs]
        rname, timers = "hostmaster." + dom, WIN_SOA
    else:
        me = ctx.fqdn.lower()
        ns = ["ns1." + dom] if hosts.get(me) and hosts.get("ns1." + dom) == hosts.get(me) else [me]
        rname, timers = "hostmaster." + dom, BIND_SOA
        if dom not in z and not dcs:                                    # no AD: the apex points at the web site
            web = next((h for h, r in roles.items() if r == "linux-web-hosting"), None)
            if web and hosts.get(f"{web.lower()}.{dom}"):
                add(dom, A, T_ZONE, hosts[f"{web.lower()}.{dom}"])
    zones = {dom: {}}
    if ms and dcs:
        zones[msdcs] = {}
    for name, rrs in z.items():
        origin = msdcs if msdcs in zones and (name == msdcs or name.endswith("." + msdcs)) else dom
        zones[origin][name] = rrs
    for origin, recs in zones.items():
        recs.setdefault(origin, [])
        recs[origin][:0] = [(SOA, T_ZONE, (ns[0], rname, _serial(ctx, ms, "dom" if origin == dom else "msdcs", now))
                             + timers)] + [(NS, T_ZONE, n) for n in ns]
    if msdcs in zones:
        zones[dom].setdefault(msdcs, []).extend((NS, T_ZONE, n) for n in ns)     # delegation in the parent zone
    return zones


class _Msg:
    """Response builder with RFC 1035 name compression (keeps every reply small: no amplification)."""

    def __init__(self, data, qend):
        self.buf = bytearray(data[:qend])
        self.ptr = {}
        labels, pos = [], 12
        while pos < qend - 4 and data[pos]:
            labels.append((pos, data[pos + 1:pos + 1 + data[pos]]))
            pos += 1 + data[pos]
        if all(lb.isascii() and b"." not in lb and lb for _, lb in labels):   # plain labels only, else no pointers
            for i, (off, _) in enumerate(labels):
                self.ptr[".".join(lb.decode().lower() for _, lb in labels[i:])] = off

    def name(self, n):
        labels = [x for x in n.lower().rstrip(".").split(".") if x]
        for i, lb in enumerate(labels):
            suf = ".".join(labels[i:])
            if suf in self.ptr:
                self.buf += struct.pack(">H", 0xC000 | self.ptr[suf])
                return
            if len(self.buf) < 0x3FFF:
                self.ptr[suf] = len(self.buf)
            self.buf += bytes([len(lb)]) + lb.encode()
        self.buf += b"\0"

    def rr(self, owner, rtype, ttl, value):
        self.name(owner)
        self.buf += struct.pack(">HHI", rtype, 1, ttl)
        at = len(self.buf)
        self.buf += b"\0\0"
        if rtype == A:
            self.buf += bytes(int(x) for x in value.split("."))
        elif rtype in (NS, CNAME):
            self.name(value)
        elif rtype == SRV:
            self.buf += struct.pack(">HHH", *value[:3])
            self.name(value[3])
        elif rtype == SOA:
            self.name(value[0])
            self.name(value[1])
            self.buf += struct.pack(">IIIII", *value[2:])
        struct.pack_into(">H", self.buf, at, len(self.buf) - at - 2)


def _lookup(zones, qname, qtype, tcp):
    """Authoritative lookup → (rcode, answers, authority, additional) as lists of (owner, type, ttl, value),
    or None when the name is in none of our zones."""
    origin = max((o for o in zones if qname == o or qname.endswith("." + o)), key=len, default=None)
    if origin is None:
        return None
    recs = zones[origin]
    soa = recs[origin][0]
    neg = [(origin, SOA, min(soa[1], soa[2][6]), soa[2])]           # RFC 2308: SOA, TTL = min(SOA TTL, MINIMUM)
    rrs = recs.get(qname)
    if rrs is None:
        if any(n.endswith("." + qname) for n in recs):                   # empty non-terminal (_tcp, _sites …)
            return 0, [], neg, []
        return 3, [], neg, []                                            # NXDOMAIN
    if qtype == ANY:
        hit = rrs if tcp or not rrs else [r for r in rrs if r[0] == rrs[0][0]]   # UDP: one RRset (RFC 8482)
    else:
        hit = [r for r in rrs if r[0] == qtype]
    ans = [(qname, *r) for r in hit]
    if not ans:
        cn = [r for r in rrs if r[0] == CNAME]
        if not cn:
            return 0, [], neg, []                                        # NODATA
        ans = [(qname, *cn[0])]
        tgt = cn[0][2]
        tz = max((o for o in zones if tgt == o or tgt.endswith("." + o)), key=len, default=None)
        if tz:
            ans += [(tgt, *r) for r in zones[tz].get(tgt, []) if r[0] == qtype]
        return 0, ans, [], []
    add = []
    for _, t, _, v in ans:                                               # glue A for SRV / NS targets we host
        tgt = v[3] if t == SRV else v if t == NS else None
        if tgt:
            tz = max((o for o in zones if tgt == o or tgt.endswith("." + o)), key=len, default=None)
            for r in (zones[tz].get(tgt, []) if tz else []):
                if r[0] == A and (tgt, *r) not in add:
                    add.append((tgt, *r))
    return 0, ans, [], add


def answer(ctx, data, src, port, proto, tcp=False):
    if len(data) >= 12 and not data[2] & 0x80 and (data[2] >> 3) & 0x0F:
        # non-QUERY opcode (STATUS = nmap DNSStatusRequest, NOTIFY, UPDATE ...): header-only NOTIMP with the
        # opcode and RD echoed, like BIND and Microsoft DNS; 12 bytes, never more than the request (no amplification)
        op = (data[2] >> 3) & 0x0F
        ctx.emit("dns.query", src, port, proto, None, qname="", qtype=f"OPCODE{op}")
        flags = 0x8000 | (op << 11) | (data[2] & 0x01) << 8 | (RA if microsoft_dns(ctx) else 0) | 4
        return data[:2] + struct.pack(">HHHHH", flags, 0, 0, 0, 0)
    try:
        qid, flags, qname, qtype, qclass, qend = parse_query(data)
    except ValueError:
        return None
    rd = flags & 0x0100
    rcode, answers = 0, []
    sections = ([], [], [])
    qtn = QTYPE.get(qtype, str(qtype))
    ms = microsoft_dns(ctx)
    if qclass == 3:                                                                   # CHAOS fingerprint
        ctx.emit("dns.version", src, port, proto, None, qname=qname[:100])
        if ms:
            rcode = 4                     # Windows default: CHAOS not implemented → NOTIMP, no AA, no RA (0x8104)
        elif qname not in ("version.bind", "hostname.bind", "id.server"):
            rcode = 5
        else:
            txt = BIND_VERSION if qname == "version.bind" else ctx.fqdn
            answers.append(_rr(TXT, bytes([len(txt)]) + txt.encode(), ttl=0, cls=3))
    elif qtype in (AXFR, IXFR):
        ctx.emit("dns.axfr", src, port, proto, None, qname=qname, qtype=qtn, tcp=tcp)
        rcode = 5                                     # REFUSED: AD-integrated zones / our BIND allow no transfers
    else:
        ctx.emit("dns.query", src, port, proto, None, qname=qname[:200], qtype=qtn)
        res = _lookup(build_zones(ctx), qname, qtype, tcp)
        if res is None:
            rcode = 2 if ms else 5       # never recursion: MS DNS → SERVFAIL (forwarders down), BIND → REFUSED
        else:
            rcode, *sections = res
    aa = 0 if ms and rcode in (2, 4, 5) else 0x0400                                  # MS: refusals are not authoritative
    # MS: RA (recursion available on a DC by default; header bit only, nothing is ever resolved upstream) + CD echo,
    # except the CHAOS NOTIMP, which real Windows sends as plain QR|RD (nmap "Simple DNS Plus" needs RA clear)
    ra = RA if ms and qclass != 3 else 0
    if answers:                                                                       # CHAOS TXT (BIND role)
        hdr = struct.pack(">HHHHHH", qid, 0x8000 | aa | rd | rcode, 1, len(answers), 0, 0)
        return hdr + data[12:qend] + b"".join(answers)
    m = _Msg(data, qend)
    for sec in sections:
        for r in sec:
            m.rr(*r)
    struct.pack_into(">HHHHHH", m.buf, 0, qid, 0x8000 | aa | rd | ((ra | (flags & 0x0010)) if ms else 0) | rcode,
                     1, *(len(s) for s in sections))
    return bytes(m.buf)


def start_dns(ctx, svc):
    port = svc["port"]
    seen, lock = {}, threading.Lock()

    def emit_once(t, src, port_, proto, sess, **kw):                # query floods: one event per name / minute
        if t == "dns.query":
            k = (src[0], kw.get("qname"), kw.get("qtype"))
            now = time.time()
            with lock:
                if now - seen.get(k, 0) < 60:
                    return
                seen[k] = now
                if len(seen) > 20000:
                    seen.clear()
        ctx.emit(t, src, port_, proto, sess, **kw)

    class Q:                                                       # ctx facade with de-duplicated emit
        def __getattr__(self, a):
            return getattr(ctx, a)

        def emit(self, *a, **k):
            return emit_once(*a, **k)
    q = Q()

    # host (VPS) mode: systemd-resolved owns 127.0.0.53:53 → a wildcard bind fails; use the decoy IP
    host = bind_ip()
    try:
        serve_udp(ctx, port, lambda data, addr: answer(q, data, addr, port, "dns"), "dns", host=host)
    except OSError:
        host = ctx.em.sensor_ip
        serve_udp(ctx, port, lambda data, addr: answer(q, data, addr, port, "dns"), "dns", host=host)

    def tcp(conn, addr, session):
        for _ in range(20):                                        # a few pipelined queries per connection
            hdr = conn.recv(2)
            if len(hdr) < 2:
                return
            n = struct.unpack(">H", hdr)[0]
            data = b""
            while len(data) < n:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    return
                data += chunk
            r = answer(q, data, addr, port, "dns", tcp=True)
            if not r:
                return
            conn.sendall(struct.pack(">H", len(r)) + r)
    try:
        serve_tcp(ctx, port, tcp, "dns", host=host)
    except OSError:
        serve_tcp(ctx, port, tcp, "dns", host=ctx.em.sensor_ip)
