"""Severity engine: the ReD-Pot ladder (0-5) + behavioural escalation.

    0 noise · 1 touch · 2 interaction · 3 intent · 4 compromise · 5 honeytoken

`Scorer.score(ev)` returns the level for one event; `Scorer.escalations(ev)` returns extra
synthetic events (port scan, path brute force, password spraying) derived from the
recent history of the same source.
"""
import time
from collections import defaultdict, deque

LEVEL_NAMES = {0: "noise", 1: "touch", 2: "interaction", 3: "intent", 4: "compromise", 5: "honeytoken"}

BASE = {
    "tcp.connect": 1, "tls.failed": 1,
    "proto.interaction": 2, "smb.negotiate": 2, "smb.auth": 2, "smb.pipe": 2, "ssh.client": 2,
    "http.request": 2, "http.notfound": 2, "rdp.connect": 2, "rdp.ntlm": 2, "smb.tree": 2, "rdp.auth": 3,
    "smb.share_enum": 3, "smb.admin_share": 3, "smb.list": 3, "ftp.list": 3, "http.scanner": 3, "http.probe": 3,
    "auth.failed": 3, "scan.detected": 3, "conn.flood": 3, "http.bruteforce": 3, "auth.bruteforce": 3,
    "auth.success": 4, "file.read": 4, "file.write": 4, "cmd.exec": 4, "ssh.download": 4,
    "http.sensitive": 4, "http.admin_action": 4, "resource.exhaustion": 4, "smb.pipe_flood": 4,
    "honeytoken.used": 5, "canary.hit": 5,
    "dns.query": 2, "dns.axfr": 3, "dns.version": 3,
    "ldap.rootdse": 2, "ldap.bind": 3, "ldap.search": 3, "ldap.modify": 4,
    "kerberos.as_req": 3, "kerberos.tgs_req": 3, "kerberos.enum": 3,
    "honeytoken.attempt": 4, "cldap.ping": 2, "nbns.query": 1, "ntp.query": 1,
}

# windows (seconds) and thresholds for escalation
SCAN_WINDOW, SCAN_PORTS = 600, 5
# B4 (RC-23): a decoy role with fewer than SCAN_PORTS ports (file server: 135/139/445/3389) can never reach
# SCAN_PORTS on its own, and the host firewall rejects every other port before it reaches a decoy. So one
# source touching EVERY port its role exposes (at least SCAN_MIN_PORTS of them) in SCAN_WINDOW is a scan too.
# Normal use of a 4-port file server (SMB with the 139 fallback + RDP) touches 3 of 4 (135, the RPC endpoint
# mapper, is not needed for shares or RDP), so it stays below; 2-port roles (FTP, DNS) can't tell use from a
# sweep and keep only the global rule.
SCAN_MIN_PORTS = 3
NOTFOUND_WINDOW, NOTFOUND_N = 120, 15
AUTHFAIL_WINDOW, AUTHFAIL_N = 300, 5
COOLDOWN = 600


def score(ev):
    t = ev.get("type", "")
    d = ev.get("data") or {}
    lvl = BASE.get(t, 0)
    if t == "rdp.connect" and d.get("cookie_user"):
        lvl = 3          # a username was typed / supplied → login intent
    elif t == "smb.tree" and (d.get("share") or "").upper() not in ("IPC$", ""):
        lvl = 3          # mounting a data share on a server nobody should use
    elif t == "file.read" and d.get("bait"):
        lvl = 4
    elif t == "auth.failed" and d.get("honey"):
        lvl = 4          # a stolen bait NAME with a wrong password: attempt, never L5 (that needs the secret)
    elif t == "nbns.query" and d.get("kind") == "status":
        lvl = 2          # node status (nbtstat -A / nbtscan / nmap): host reconnaissance
    return lvl


def role_ports(roles=None):
    """role id -> number of distinct ports (TCP or UDP) the role's decoy listens on."""
    if roles is None:
        try:
            from rpot.common.config import load_roles
            roles = load_roles()
        except Exception:                    # no role catalog → global rule only
            roles = {}
    out = {}
    for rid, r in roles.items():
        ports = {s.get("port") for s in (r.get("services") or []) if isinstance(s.get("port"), int)}
        out[rid] = len(ports)
    return out


def scan_threshold(n_ports):
    """Distinct ports one source must touch on ONE decoy: min(SCAN_PORTS, all of the role's ports), never
    fewer than SCAN_MIN_PORTS. None when the role is unknown or too small for a per-decoy rule."""
    if not n_ports or n_ports < SCAN_MIN_PORTS:
        return None
    return min(SCAN_PORTS, n_ports)


class Scorer:
    def __init__(self, roles=None):
        self.role_ports = role_ports(roles)
        self.ports = defaultdict(deque)      # src -> deque[(ts, sensor:port)]
        self.notfound = defaultdict(deque)   # (src, sensor) -> deque[ts]
        self.authfail = defaultdict(deque)   # src -> deque[(ts, username)]
        self.fired = {}                      # (kind, key) -> ts

    def _cool(self, key, now):
        if now - self.fired.get(key, 0) < COOLDOWN:
            return False
        self.fired[key] = now
        return True

    def escalations(self, ev, now=None):
        now = now or time.time()
        src = ev.get("src_ip")
        if not src:
            return []
        out = []
        t = ev.get("type")
        if ev.get("dst_port"):
            q = self.ports[src]
            q.append((now, f"{ev.get('sensor')}:{ev['dst_port']}"))
            while q and now - q[0][0] > SCAN_WINDOW:
                q.popleft()
            distinct = {x[1] for x in q}
            need = scan_threshold(self.role_ports.get(ev.get("role")))
            mine = f"{ev.get('sensor')}:"
            one = {x for x in distinct if x.startswith(mine)}
            if (len(distinct) >= SCAN_PORTS or (need and len(one) >= need)) and self._cool(("scan", src), now):
                out.append(_synth(ev, "scan.detected", targets=sorted(distinct)[:40], ports=len(distinct),
                                  window_s=SCAN_WINDOW))
        if t == "http.notfound":
            k = (src, ev.get("sensor"))
            q = self.notfound[k]
            q.append(now)
            while q and now - q[0] > NOTFOUND_WINDOW:
                q.popleft()
            if len(q) >= NOTFOUND_N and self._cool(("404", k), now):
                out.append(_synth(ev, "http.bruteforce", count=len(q), window_s=NOTFOUND_WINDOW))
        if t == "auth.failed":
            q = self.authfail[src]
            q.append((now, (ev.get("data") or {}).get("username")))
            while q and now - q[0][0] > AUTHFAIL_WINDOW:
                q.popleft()
            if len(q) >= AUTHFAIL_N and self._cool(("auth", src), now):
                users = sorted({u for _, u in q if u})
                kind = "password spraying" if len(users) >= 3 else "password brute force"
                out.append(_synth(ev, "auth.bruteforce", count=len(q), usernames=users[:20], kind=kind))
        # bounded memory
        if len(self.ports) > 50000:
            self.ports.clear(); self.notfound.clear(); self.authfail.clear()
        if len(self.fired) > 50000:
            self.fired = {k: t for k, t in self.fired.items() if now - t < COOLDOWN}
        return out


def _synth(ev, type_, **data):
    return {"ts": ev["ts"], "sensor": ev.get("sensor"), "role": ev.get("role"), "sensor_ip": ev.get("sensor_ip"),
            "src_ip": ev.get("src_ip"), "src_port": None, "dst_port": ev.get("dst_port"), "proto": ev.get("proto"),
            "type": type_, "session": None, "data": dict(data, synthetic=True)}


def top_holders(d, n=3):
    """"10.0.0.5 (20 conns, 16 smb-pipe), ..." from a conn.flood's top_sources (sensor-supplied: bounded, inert)."""
    out = []
    for r in (d.get("top_sources") or [])[:n]:
        if not isinstance(r, dict):
            continue
        parts = [f"{int(v)} {k}" for k, v in list(r.items())[:6]
                 if k != "ip" and isinstance(v, int) and not isinstance(v, bool) and v]
        out.append(f"{str(r.get('ip'))[:45]} ({', '.join(p[:40] for p in parts)})")
    return "; ".join(out) or "unknown"


def describe(ev):
    """One-line human description of an event (used for incident titles, alerts, timeline)."""
    t, d, s = ev.get("type"), ev.get("data") or {}, ev.get("sensor") or "?"
    port = ev.get("dst_port")
    u = d.get("username") or d.get("user")
    if t == "honeytoken.used":
        how = "successful login" if d.get("success") else ("correct password, logon refused" if d.get("password_ok") else "attempt")
        return f"Honeytoken used on {s}/{ev.get('proto')}: {d.get('desc', '')} ({u or ''}) — {how}; planted at {d.get('planted', '?')}"
    if t == "honeytoken.attempt":
        return f"Bait account targeted on {s}/{ev.get('proto')}: {d.get('desc', '')} ({u or ''}) — no valid secret"
    if t == "cldap.ping":
        return f"CLDAP DC locator ping on {s}" + (f" for user {d['user']!r}" if d.get("user") else "") + \
            (" (rootDSE)" if d.get("rootdse") else f" ({d.get('domain') or '?'})")
    if t == "nbns.query":
        return f"NetBIOS {'node status' if d.get('kind') == 'status' else 'name'} query to {s}: {d.get('name', '')}"
    if t == "ntp.query":
        return f"NTP time query to {s}"
    if t == "canary.hit":
        return f"Bait document opened: {d.get('desc', '')} ({d.get('planted', '?')})"
    if t == "auth.success":
        return f"Successful {ev.get('proto')} login on {s} as {u}"
    if t == "cmd.exec":
        return f"Command on {s}: {d.get('cmd', '')[:120]}"
    if t == "file.read":
        return f"File read on {s}: {d.get('path', '')}"
    if t == "file.write":
        how = "Upload dropped (" + d["dropped"] + ")" if d.get("dropped") else ("Upload" if d.get("sha256") else "Write attempt")
        return f"{how} on {s}: {d.get('path', '')}"
    if t == "ssh.download":
        return f"Download attempt on {s}: {' '.join(d.get('urls') or [])[:150]}"
    if t == "http.sensitive":
        return f"Sensitive file fetched from {s}: /{d.get('file', '')}"
    if t == "http.admin_action":
        return f"Admin portal used on {s} by {u}"
    if t == "scan.detected":
        return f"Port scan: {d.get('ports')} ports/sensors in {d.get('window_s', 600) // 60} min"
    if t == "auth.bruteforce":
        return f"{d.get('kind', 'brute force').capitalize()} on {s}: {d.get('count')} failures ({', '.join(d.get('usernames') or [])[:80]})"
    if t == "http.bruteforce":
        return f"Path brute force on {s}: {d.get('count')} 404s in {d.get('window_s', 120)} s"
    if t == "auth.failed":
        return f"Failed {ev.get('proto')} login on {s} as {u!r}" + (" (bait account, wrong password)" if d.get("honey") else "")
    if t == "rdp.auth":
        who = f"{d['domain']}\\{u}" if d.get("domain") and u else (u or "anonymous")
        return f"RDP logon attempt on {s} as {who} from workstation {d.get('workstation') or '?'}"
    if t == "conn.flood":
        cap = {"per_ip": "per-source", "global": "decoy-wide", "threads": "thread"}.get(d.get("reason"), "connection")
        if d.get("reason") in ("global", "threads"):
            return f"Decoy {s} saturated ({cap} cap {d.get('limit')}) - possible DoS; top holders: {top_holders(d)}"
        return (f"Connection flood on {s}/{ev.get('proto')}: {d.get('refused', 1)} connection(s) refused "
                f"({cap} cap {d.get('limit')})")
    if t in ("resource.exhaustion", "smb.pipe_flood"):
        what = {"smb_pipe": "SMB named-pipe opens", "ssh_channel": "SSH channel opens",
                "connections": "connections"}.get(d.get("resource"), d.get("resource") or "requests")
        cap = {"per_session": "per-session", "per_connection": "per-connection", "per_ip": "per-source",
               "global": "decoy-wide", "threads": "thread"}.get(d.get("cap"), "resource")
        return (f"Decoy resource exhaustion attempt on {s}/{ev.get('proto')}: {d.get('refused', 1)} {what} refused "
                f"({cap} cap {d.get('limit')})")
    if t == "smb.share_enum":
        return f"Share enumeration on {s}"
    if t == "smb.admin_share":
        what = {"tree": "connect to", "list": "list", "read": "read from", "write": "write to"}.get(d.get("op"), "read")
        return f"Tried to {what} admin share \\\\{s}\\{d.get('share', '')}" + (f": {d['path']}" if d.get("path") else "")
    if t == "smb.list":
        return f"Directory listing on {s}: \\{d.get('path', '')}"
    if t == "ftp.list":
        return f"FTP listing on {s}: {d.get('path', '')}"
    if t == "smb.tree":
        return f"Connected to share \\\\{s}\\{d.get('share', '')}"
    if t == "http.scanner":
        return f"Scanner/exploit traffic on {s}: {', '.join(d.get('reasons') or [])} {d.get('path', '')[:80]}"
    if t == "http.probe":
        return f"Probe of sensitive path on {s}: {d.get('path', '')}"
    if t == "rdp.connect":
        return f"RDP connection to {s}" + (f" as {d['cookie_user']}" if d.get("cookie_user") else "")
    if t == "smb.auth":
        who = f"{d.get('domain') or ''}\\{d.get('user')}" if d.get("user") else "anonymous"
        return f"SMB logon to {s} as {who} from workstation {d.get('workstation') or '?'}"
    if t == "smb.negotiate":
        return f"SMB session negotiated with {s}"
    if t == "smb.pipe":
        return f"RPC pipe opened on {s}: {d.get('pipe', '')}"
    if t == "proto.interaction":
        return f"{(ev.get('proto') or '').upper()} data sent to {s}" + (f" ({d['detail']})" if d.get("detail") else "")
    if t == "rdp.ntlm":
        return f"RDP NTLM negotiate on {s} from workstation {d.get('workstation') or '?'}"
    if t == "tls.failed":
        return f"TLS handshake failed on {s}:{port}"
    if t == "dns.query":
        return f"DNS lookup on {s}: {d.get('qname', '')} {d.get('qtype', '')}"
    if t == "dns.axfr":
        return f"DNS zone transfer attempt on {s}: {d.get('qname', '')} ({d.get('qtype', 'AXFR')})"
    if t == "dns.version":
        return f"DNS server fingerprinting on {s} ({d.get('qname', '')})"
    if t == "ldap.rootdse":
        return f"LDAP rootDSE query on {s} (domain controller fingerprinting)"
    if t == "ldap.bind":
        who = u or ("anonymous" if d.get("method") == "anonymous" else "?")
        return f"LDAP {d.get('method', '')} bind to {s} as {who}"
    if t == "ldap.search":
        return f"LDAP search on {s}{' (as ' + d['bound'] + ')' if d.get('bound') else ' (not logged in)'}: {d.get('filter', '')[:100]}"
    if t == "ldap.modify":
        return f"Directory modification attempt on {s}: {d.get('op', '')}"
    if t == "kerberos.as_req":
        what = "pre-auth password guess" if d.get("preauth") else "TGT request"
        return f"Kerberos {what} on {s} for {u!r} → {d.get('result', '')}"
    if t == "kerberos.tgs_req":
        return f"Kerberos service ticket request on {s} for SPN {d.get('spn', '')} (Kerberoasting?)"
    if t == "kerberos.enum":
        return f"Kerberos user enumeration on {s}: {d.get('count')} usernames tried"
    if t == "ssh.client":
        return f"SSH client on {s}: {d.get('client_version', '')}"
    if t == "tcp.connect":
        return f"TCP connection to {s}:{port}"
    if t in ("http.request", "http.notfound"):
        return f"HTTP {d.get('method', '')} {d.get('path', '')[:80]} on {s}"
    return f"{t} on {s}" + (f":{port}" if port else "")
