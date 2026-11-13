"""Shared sensor runtime: context object, threaded TCP listener, TLS cert, safe paths."""
import ipaddress
import os
import socket
import threading
import time

from rpot.common.events import new_session


def _pids_max(path="/sys/fs/cgroup/pids.max"):
    """The container's task limit (cgroup v2), or None when unlimited / unknown."""
    try:
        with open(path) as f:
            v = f.read().strip()
        return int(v) if v.isdigit() else None
    except (OSError, ValueError):
        return None


# F-02 (RC-28): ONE connection budget per decoy, shared by every TCP listener of the role (base listeners, SMB,
# HTTP). One connection = one thread; the decoy container has pids_limit 384 (rpotctl/installer compose), so
# the budget stays well below it: 250 concurrent clients, 20 per source IP, and no new client while the process
# already runs THREAD_CEILING threads (SSH and SMB pipes use more than one thread per client).
MAX_CONN = int(os.environ.get("RPOT_MAX_CONN", "250"))      # concurrent TCP clients per decoy (all listeners)
MAX_PER_IP = int(os.environ.get("RPOT_MAX_PER_IP", "20"))   # concurrent TCP clients per source IP per decoy
_PIDS = _pids_max()
THREAD_CEILING = int(os.environ.get("RPOT_THREAD_CEILING") or (min(320, _PIDS - 64) if _PIDS and _PIDS > 128 else 320))
IDLE_UNAUTH = int(os.environ.get("RPOT_IDLE_UNAUTH", "60"))   # s: idle limit of an SMB session without a named logon
FLOOD_EVERY = 60                                            # s: at most one conn.flood event per source per window
# N-3 (RC-31): per-client extras (SMB named-pipe opens, SSH channels) are charged to the same budget, per kind:
# at most MAX_AUX_PER_IP per source IP and MAX_AUX decoy-wide, and none once the process is within AUX_HEADROOM
# threads of THREAD_CEILING - near the ceiling the extra is refused, never a new client.
MAX_AUX_PER_IP = int(os.environ.get("RPOT_MAX_AUX_PER_IP", "16"))
MAX_AUX = int(os.environ.get("RPOT_MAX_AUX", "128"))
AUX_HEADROOM = 32


class PerIP:
    """Per-source concurrency limit (one scanner can't take all MAX_CONN slots)."""

    def __init__(self, limit=MAX_PER_IP):
        self.limit, self.n, self.lock = limit, {}, threading.Lock()

    def take(self, ip):
        with self.lock:
            if self.n.get(ip, 0) >= self.limit:
                return False
            self.n[ip] = self.n.get(ip, 0) + 1
            return True

    def give(self, ip):
        with self.lock:
            c = self.n.get(ip, 1) - 1
            if c <= 0:
                self.n.pop(ip, None)
            else:
                self.n[ip] = c


class ConnBudget:
    """Decoy-wide concurrent TCP connection budget (F-02). take(ip) → None (admitted: call give(ip) when the
    client is done) or the cap that refused it: "global", "threads" or "per_ip".
    take_aux(ip, kind) / give_aux(ip, kind): the same for per-client extras (N-3: SMB pipes, SSH channels)."""

    def __init__(self, total=None, per_ip=None, threads=None, aux_total=None, aux_per_ip=None, headroom=None):
        self.total = MAX_CONN if total is None else total
        self.threads = THREAD_CEILING if threads is None else threads
        self.ips = PerIP(MAX_PER_IP if per_ip is None else per_ip)
        self.n, self.lock = 0, threading.Lock()
        self.aux_total = MAX_AUX if aux_total is None else aux_total
        self.aux_per_ip = MAX_AUX_PER_IP if aux_per_ip is None else aux_per_ip
        self.headroom = AUX_HEADROOM if headroom is None else headroom
        self.aux = {}                            # (kind, ip) -> count
        self.aux_n = {}                          # kind -> count

    def limit(self, why):
        return {"global": self.total, "threads": self.threads, "per_ip": self.ips.limit}.get(why)

    def aux_limit(self, why):
        return {"global": self.aux_total, "threads": max(1, self.threads - self.headroom),
                "per_ip": self.aux_per_ip}.get(why)

    def take_aux(self, ip, kind):
        """One more extra of `kind` for source ip → None (call give_aux) or the cap that refused it."""
        with self.lock:
            if self.aux_n.get(kind, 0) >= self.aux_total:
                return "global"
            if threading.active_count() >= self.threads - self.headroom:
                return "threads"
            k = (kind, ip)
            if self.aux.get(k, 0) >= self.aux_per_ip:
                return "per_ip"
            self.aux[k] = self.aux.get(k, 0) + 1
            self.aux_n[kind] = self.aux_n.get(kind, 0) + 1
            return None

    def give_aux(self, ip, kind):
        with self.lock:
            k = (kind, ip)
            c = self.aux.get(k, 0) - 1
            if c <= 0:
                self.aux.pop(k, None)
            else:
                self.aux[k] = c
            self.aux_n[kind] = max(0, self.aux_n.get(kind, 0) - 1)

    def top_aux(self, kind):
        """(ip, extras of `kind`) of the source holding the most of them, or (None, 0)."""
        with self.lock:
            mine = {ip: c for (k, ip), c in self.aux.items() if k == kind}
        if not mine:
            return None, 0
        ip = max(mine, key=mine.get)
        return ip, mine[ip]

    def top_sources(self, n=5):
        """The n sources holding the most slots: [{"ip", "conns", <aux kind>: count ...}], most first."""
        with self.ips.lock:
            conns = dict(self.ips.n)
        with self.lock:
            aux = dict(self.aux)
        rows = {}
        for ip, c in conns.items():
            rows.setdefault(ip, {"ip": ip, "conns": 0})["conns"] = c
        for (kind, ip), c in aux.items():
            rows.setdefault(ip, {"ip": ip, "conns": 0})[kind] = c
        key = lambda r: sum(v for k, v in r.items() if k != "ip")
        return sorted(rows.values(), key=key, reverse=True)[:n]

    def top(self):
        """(ip, connections) of the source holding the most connections, or (None, 0)."""
        with self.ips.lock:
            if not self.ips.n:
                return None, 0
            ip = max(self.ips.n, key=self.ips.n.get)
            return ip, self.ips.n[ip]

    def take(self, ip):
        with self.lock:
            if self.n >= self.total:
                return "global"
            if threading.active_count() >= self.threads:
                return "threads"
            if not self.ips.take(ip):
                return "per_ip"
            self.n += 1
            return None

    def give(self, ip):
        with self.lock:
            self.n = max(0, self.n - 1)
        self.ips.give(ip)


BUDGET = ConnBudget()


class _Every:
    """At most one report per key per `every` seconds; counts what it suppressed (bounded key set)."""

    def __init__(self, every, max_keys=10000):
        self.every, self.max_keys = every, max_keys
        self.last, self.n, self.lock = {}, {}, threading.Lock()

    def hit(self, key):
        """→ None (suppressed) or the number of hits since the last report (this one included)."""
        now = time.monotonic()
        with self.lock:
            n = self.n.get(key, 0) + 1
            t = self.last.get(key)
            if t is not None and now - t < self.every:
                self.n[key] = n
                return None
            if len(self.last) >= self.max_keys:
                self.last = {k: v for k, v in self.last.items() if now - v < self.every}
                self.n = {k: v for k, v in self.n.items() if k in self.last}
                if len(self.last) >= self.max_keys:
                    self.last.clear()
                    self.n.clear()
            self.last[key], self.n[key] = now, 0
            return n


class FloodLog:
    """Flood accounting per key (threat-hunt C3): hit(key, emit) counts one refusal. The first refusal of a flood is
    reported at once, later ones at most once per `every` s as they come, and flush() (the self-check loop, every
    30 s) reports what is still pending after every/2 s - so every refusal is in a report within 60 s. A report calls
    emit(refused=<total since the flood started>, new=<since the last report>, duration_s=<flood age>). A key quiet
    for 2*every s with nothing pending starts a new flood. Bounded key set."""

    def __init__(self, every=FLOOD_EVERY, max_keys=10000):
        self.every, self.max_keys = every, max_keys
        self.st, self.lock = {}, threading.Lock()

    def _report(self, st, now):
        st["last"], new, st["pending"] = now, st["pending"], 0
        return st["emit"], st["total"], new, round(now - st["first"], 1)

    def hit(self, key, emit):
        now = time.monotonic()
        out = None
        with self.lock:
            st = self.st.get(key)
            if st is None or (not st["pending"] and now - st["hit"] > 2 * self.every):
                if st is None and len(self.st) >= self.max_keys:
                    self.st = {k: v for k, v in self.st.items() if v["pending"] or now - v["hit"] <= 2 * self.every}
                    if len(self.st) >= self.max_keys:
                        self.st.clear()
                st = self.st[key] = {"first": now, "total": 0, "pending": 0, "last": None, "hit": now, "emit": emit}
            st["total"] += 1
            st["pending"] += 1
            st["hit"], st["emit"] = now, emit
            if st["last"] is None or now - st["last"] >= self.every:
                out = self._report(st, now)
        _call(out)
        return out is not None

    def flush(self, now=None):
        now = time.monotonic() if now is None else now
        due = []
        with self.lock:
            for k, st in list(self.st.items()):
                if st["pending"] and now - st["last"] >= self.every / 2:
                    due.append(self._report(st, now))
                elif not st["pending"] and now - st["hit"] > 2 * self.every:
                    del self.st[k]
        for d in due:
            _call(d)
        return len(due)


def _call(rep):
    if rep is None:
        return
    emit, total, new, dur = rep
    try:
        emit(refused=total, new=new, duration_s=dur)
    except Exception:
        pass


def _close(conn):
    try:
        conn.close()
    except Exception:
        pass


def _shut(s):
    """Close a listening socket so that a thread blocked in accept()/recvfrom() on it wakes up (a bare close()
    does not wake it on Linux, and the port would stay bound)."""
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    _close(s)


_FLOOD = FloodLog(FLOOD_EVERY)
_THREAD_FAIL = _Every(60)
_EXHAUST = FloodLog(FLOOD_EVERY)


def flush_floods():
    """Pending flood summaries (called by the self-check loop)."""
    for f in (_FLOOD, _EXHAUST):
        f.flush()


def exhaustion(ctx, src, port, proto, resource, cap, limit, session=None, type_="resource.exhaustion", **extra):
    """N-3 (RC-31): `resource.exhaustion` (level 4, "decoy resource exhaustion attempt"; SMB pipes: `smb.pipe_flood`)
    for a source that ran into its OWN per-source cap (pipes per session / IP, channels per connection / IP, or all
    its connection slots while the decoy-wide cap is hit). Flood-accounted per source + resource (FloodLog)."""
    threads = threading.active_count()

    def emit(**n):
        ctx.emit(type_, src, port, proto, session, resource=resource, cap=cap, limit=limit, threads=threads,
                 **extra, **n)
    _EXHAUST.hit((src[0], resource), emit)


def admit(ctx, conn, addr, port, proto, budget=None):
    """Connection cap check for one accepted client. Refused → the socket is closed and a flood-accounted
    `conn.flood` event (level 3) names the source; a decoy-wide cap (global / threads) adds top_sources = the
    sources holding the most slots (the manager raises a decoy-health incident naming them). Returns True when
    admitted (caller must budget.give())."""
    budget = budget or BUDGET
    why = budget.take(addr[0])
    if why is None:
        return True
    extra = {"top_sources": budget.top_sources()} if why in ("global", "threads") else {}

    def emit(**n):
        ctx.emit("conn.flood", addr, port, proto, None, reason=why, limit=budget.limit(why), active=budget.n,
                 **extra, **n)
    _FLOOD.hit((addr[0], why), emit)
    if why in ("global", "threads"):
        # a decoy-wide cap: the refused client may be innocent - attribute the exhaustion to the source that
        # holds all of its own connection slots (if any), not to whoever arrived last
        ip, held = budget.top()
        if ip is not None and held >= budget.ips.limit:
            exhaustion(ctx, (ip, None), port, proto, "connections", why, budget.limit(why), held=held)
    _close(conn)                             # after the events: a refused client never sees EOF before they exist
    return False


def _thread_failed(ctx, port, proto, err, fails):
    """Thread.start() failed (pids limit): report (rate-limited) and back off — never kill the listener."""
    n = _THREAD_FAIL.hit(port)
    if n:
        try:
            ctx.emit("sensor.error", None, port, proto, None, error=f"cannot start client thread: {err}"[:200],
                     refused=n, threads=threading.active_count())
        except Exception:
            pass
    time.sleep(min(0.05 * 2 ** min(fails, 5), 1.0))


class Listener:
    """One listening socket + its serving thread, kept (strong reference) for the self-check (F-02).
    start() → (socket, thread): binds a fresh socket if needed and starts the serving thread."""

    def __init__(self, kind, port, proto, start, service=None, stop=None):
        self.kind, self.port, self.proto = kind, port, proto
        self._stop = stop
        self.label = f"{proto}/{kind}:{port}" if kind == "udp" else f"{proto}/{port}"
        self.service = service or REGISTRY.current or self.label
        self._start = start
        self.sock, self.thread = start()
        if not port:                             # ephemeral (tests): label and restarts use the bound port
            try:
                self.port = self.sock.getsockname()[1]
                self.label = self.label[:-1] + str(self.port)
            except OSError:
                pass
        self.down = None                     # reason while reported down
        self.last_error = None

    def problem(self):
        """None when healthy, else why not: the serving thread died or the socket is no longer listening."""
        t, s = self.thread, self.sock
        if t is None or not t.is_alive():
            return "serving thread stopped"
        try:
            if s.fileno() == -1:
                return "socket closed"
            if self.kind == "tcp" and not s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
                return "socket not listening"
        except OSError as e:
            return f"socket error: {e}"[:120]
        return None

    def restart(self):
        old_s, old_t = self.sock, self.thread
        if self._stop:
            self._stop(old_s, old_t)
        else:
            _shut(old_s)                         # wakes a serving thread blocked in accept()/recvfrom()
            if old_t is not None and old_t.is_alive() and old_t is not threading.current_thread():
                old_t.join(1)
        self.sock, self.thread = self._start()


class Registry:
    """Every listener of this decoy process + the periodic self-check (F-02): a dead or unbound listener is
    reported as `sensor.service_down`, restarted, and reported as `sensor.service_up` once it serves again."""

    def __init__(self):
        self.items, self.lock = [], threading.Lock()
        self.current = None                  # service label ("rdp/3389") being started by main()

    def add(self, listener):
        with self.lock:
            self.items.append(listener)
        return listener

    def clear(self):
        with self.lock:
            self.items = []

    def check(self, ctx):
        """One self-check pass. Returns [(listener, problem or None)] for every listener checked."""
        out = []
        with self.lock:
            items = list(self.items)
        for li in items:
            why = li.problem()
            if why and not li.down:
                li.down = why
                ctx.emit("sensor.service_down", None, li.port, li.proto, None, service=li.service,
                         listener=li.label, reason=why)
            if why:
                try:
                    li.restart()
                    why = li.problem()
                except Exception as e:          # port taken, no thread left … → retried on the next pass
                    li.last_error = f"{type(e).__name__}: {e}"[:200]
                    why = why or "restart failed"
            if not why and li.down:
                ctx.emit("sensor.service_up", None, li.port, li.proto, None, service=li.service,
                         listener=li.label, was=li.down, restarted=True)
                li.down = None
            out.append((li, why))
        return out

    def start(self, ctx, every=30, stop=None):
        stop = stop or threading.Event()

        def loop():
            while not stop.wait(every):
                try:
                    self.check(ctx)
                except Exception:               # the watchdog itself never dies
                    pass
                try:
                    flush_floods()              # C3: pending flood summaries (every refusal reported within 60 s)
                except Exception:
                    pass
        t = threading.Thread(target=loop, name="selfcheck", daemon=True)
        t.start()
        return t


REGISTRY = Registry()


class Ctx:
    def __init__(self, cfg, sensor, role, emitter, tokens, bait_dir, data_dir):
        self.cfg, self.sensor, self.role = cfg, sensor, role
        self.name = sensor["name"].upper()
        self.em, self.tokens = emitter, tokens
        self.bait_dir, self.data_dir = bait_dir, data_dir
        co = cfg["company"]
        self.domain, self.netbios = co["domain"], co["netbios"]
        self.fqdn = f"{self.name.lower()}.{self.domain}"
        self.os = role.get("os", "")
        self._seed = None

    def persona_secret(self, label):
        """Stable per-install secret bytes for persona details that must not change between restarts
        (SMB ServerGUID, boot time) yet differ between installs. Derived from the sensor key; without
        one (dev/tests) from a random seed kept in data_dir."""
        import hashlib
        import hmac
        if self._seed is None:
            key = getattr(self.em, "key", None)
            if isinstance(key, str) and key:
                self._seed = key.encode()
            else:
                f = os.path.join(self.data_dir, "persona.seed")
                try:
                    with open(f, "rb") as fh:
                        self._seed = fh.read()
                except OSError:
                    self._seed = b""
                if len(self._seed) < 16:
                    self._seed = os.urandom(32)
                    try:
                        with open(f, "wb") as fh:
                            fh.write(self._seed)
                        os.chmod(f, 0o600)
                    except OSError:
                        pass
        return hmac.new(self._seed, f"{self.name}\0{label}".encode(), hashlib.sha256).digest()

    def boot_time(self, now=None):
        """Persona boot time (epoch): 3–38 days before now, advancing with the clock and jumping once
        per ~monthly "patch cycle" — stable across restarts, different per install."""
        import time as _t
        now = _t.time() if now is None else now
        r = int.from_bytes(self.persona_secret("boot")[:8], "big")
        period = 86400 * (28 + r % 8)
        phase = (r >> 8) % period
        return now - 3 * 86400 - ((now - phase) % period)

    def emit(self, type_, src=None, dst_port=None, proto=None, session=None, **data):
        return self.em.emit(type_, src=src, dst_port=dst_port, proto=proto, session=session, **data)

    def check_cred(self, username, password, service, src, port, session, proto=None):
        """Common auth path: honeytoken detection + success decision. Returns True if login
        should succeed."""
        tid, tok = self.tokens.credential(username, password)
        proto = proto or service
        if tid:
            ok = self.tokens.valid_on(tok, self.name, service)
            self.emit("honeytoken.used", src, port, proto, session, token=tid, username=username,
                      planted=tok.get("planted"), desc=tok.get("desc"), success=ok)
            if ok:
                self.emit("auth.success", src, port, proto, session, username=username, method="password")
            return ok
        self.emit("auth.failed", src, port, proto, session, username=username, password=_mask(password))
        return False


def _mask(p):
    """Attempted passwords are NOT stored in clear: an employee who mistypes a real password into a
    decoy must not end up in the SIEM. Keep only shape + a short hash (spot reuse across attempts)."""
    if p is None:
        return None
    import hashlib
    p = str(p)
    return f"{p[:1]}{'*' * min(len(p) - 1, 12)} (len {len(p)}, h:{hashlib.sha256(p.encode('utf-8', 'surrogatepass')).hexdigest()[:8]})"


WIN_BUILDS = (("2025", (10, 0, 26100)), ("2022", (10, 0, 20348)), ("2019", (10, 0, 17763)),
              ("2016", (10, 0, 14393)), ("2012 R2", (6, 3, 9600)), ("2012", (6, 2, 9200)), ("2008 R2", (6, 1, 7601)))


def win_version(os_name):
    """Windows (major, minor, build) of a role's persona "os" string — the one version every protocol
    (SMB/NTLM, RDP) must report. Unknown names → Server 2019; an explicit trailing build number wins."""
    import re
    s = str(os_name or "")
    ver = next((v for k, v in WIN_BUILDS if f"Server {k}" in s), (10, 0, 17763))
    m = re.search(r"\b(\d{4,5})\s*$", s)
    if m and m.group(1) not in [k for k, _ in WIN_BUILDS]:
        ver = (ver[0], ver[1], int(m.group(1)))
    return ver


class UploadStore:
    """Inert store for attacker uploads (FTP STOR, SMB put): content-addressed files, mode 0400, never
    executed or served. Bounded per sensor: total bytes + file count (env RPOT_UPLOAD_MAX_MB /
    RPOT_UPLOAD_MAX_FILES, default 200 MB / 500 files) and per-file size (RPOT_UPLOAD_MAX_FILE_MB, 20)."""
    _all = {}
    _glock = threading.Lock()

    def __init__(self, path, max_bytes=None, max_files=None, max_file=None):
        env = lambda k, d: int(os.environ.get(k) or d)
        self.path = path
        self.max_bytes = max_bytes if max_bytes is not None else env("RPOT_UPLOAD_MAX_MB", 200) * 1024 * 1024
        self.max_files = max_files if max_files is not None else env("RPOT_UPLOAD_MAX_FILES", 500)
        self.max_file = max_file if max_file is not None else env("RPOT_UPLOAD_MAX_FILE_MB", 20) * 1024 * 1024
        self.lock = threading.Lock()
        self.tmp = os.path.join(path, ".part")
        os.makedirs(self.tmp, exist_ok=True)
        for n in os.listdir(self.tmp):                   # half-written leftovers of a previous run
            try:
                os.remove(os.path.join(self.tmp, n))
            except OSError:
                pass
        self.files = {n: os.path.getsize(os.path.join(path, n)) for n in os.listdir(path)
                      if len(n) == 64 and os.path.isfile(os.path.join(path, n))}

    @classmethod
    def of(cls, data_dir):
        """The one store of this sensor (FTP and SMB share the quota)."""
        p = os.path.join(data_dir, "uploads")
        with cls._glock:
            if p not in cls._all:
                cls._all[p] = cls(p)
            return cls._all[p]

    def used(self):
        return sum(self.files.values())

    def put(self, blob):
        """Store bytes → {"sha256", "bytes", "stored": bool, "dropped": reason or None}."""
        import hashlib
        return self._commit(hashlib.sha256(blob).hexdigest(), len(blob), lambda dst: _write_ro(dst, blob))

    def new_part(self):
        """Temp file for a streamed upload (SMB): (fd, path); finish with commit_part(path)."""
        import tempfile
        return tempfile.mkstemp(dir=self.tmp)

    def commit_part(self, part):
        import hashlib
        h, n = hashlib.sha256(), 0
        try:
            with open(part, "rb") as f:
                for b in iter(lambda: f.read(1 << 16), b""):
                    h.update(b)
                    n += len(b)

            def mv(dst):
                os.replace(part, dst)
                os.chmod(dst, 0o400)
            return self._commit(h.hexdigest(), n, mv)
        finally:
            if os.path.exists(part):
                os.remove(part)

    def _commit(self, sha, size, write):
        with self.lock:
            if sha in self.files:
                return {"sha256": sha, "bytes": size, "stored": True, "dropped": None}
            why = None
            if size > self.max_file:
                why = "file too large"
            elif len(self.files) >= self.max_files:
                why = "file count quota"
            elif self.used() + size > self.max_bytes:
                why = "size quota"
            if why:
                return {"sha256": sha, "bytes": size, "stored": False, "dropped": why}
            write(os.path.join(self.path, sha))
            self.files[sha] = size
            return {"sha256": sha, "bytes": size, "stored": True, "dropped": None}


def _write_ro(dst, blob):
    with open(dst, "wb") as f:
        f.write(blob)
    os.chmod(dst, 0o400)


def iface_ipv4(name):
    """Current IPv4 address of an interface (host-network sensors), or None."""
    import fcntl
    import struct
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:
            r = fcntl.ioctl(so.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))   # SIOCGIFADDR
        return socket.inet_ntoa(r[20:24])
    except (OSError, UnicodeError):
        return None


class NoBindAddress(RuntimeError):
    """Follow mode (RPOT_SENSOR_IFACE) and the interface has no IPv4 address: refuse to listen (F8, fail closed)."""


BIND_WAIT = 10      # s: follow mode waits this long for the interface's address before failing closed


def bind_ip(wait=None, step=1.0):
    """Decoys on a host network listen ONLY on their own address — a decoy that owns a dedicated NIC's IP must
    never show its ports on the management interface. RPOT_BIND_IP: a fixed address. RPOT_SENSOR_IFACE (remote
    sensor on its manager-link interface, S-1 L14): that interface's CURRENT address; the sensor restarts when
    DHCP changes it (rpot.sensor.main). Neither (Docker-bridge lab): every address of the container.
    Follow mode NEVER falls back to 0.0.0.0 (that would expose the decoy on docker0, VPNs, lo …): it waits up
    to `wait` seconds for the lease and then raises NoBindAddress; main() exits so Docker restarts the decoy."""
    if os.environ.get("RPOT_BIND_IP"):
        return os.environ["RPOT_BIND_IP"]
    iface = os.environ.get("RPOT_SENSOR_IFACE")
    if iface:
        end = time.monotonic() + (BIND_WAIT if wait is None else wait)
        while True:
            ip = iface_ipv4(iface)
            if ip and ip != "0.0.0.0":
                return ip
            if time.monotonic() >= end:
                raise NoBindAddress(f"{iface} has no IPv4 address - not listening (never on 0.0.0.0)")
            time.sleep(step)
    return "0.0.0.0"


BROADCAST_UDP = {137, 138}     # NetBIOS name/datagram: queries arrive as broadcasts
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


def bind_device():
    """Interface of a host-network decoy: RPOT_SENSOR_IFACE, else the interface holding RPOT_BIND_IP. None in
    the Docker-bridge lab (or when it cannot be found)."""
    if os.environ.get("RPOT_SENSOR_IFACE"):
        return os.environ["RPOT_SENSOR_IFACE"]
    ip = os.environ.get("RPOT_BIND_IP")
    if not ip:
        return None
    try:
        return next((n for _, n in socket.if_nameindex() if iface_ipv4(n) == ip), None)
    except OSError:
        return None


def _bind_udp(s, host, port):
    """A socket bound to one unicast address never sees broadcasts. For NetBIOS (S-1 L14) bind the wildcard
    address but only on the decoy's interface (SO_BINDTODEVICE — allowed unprivileged since Linux 5.7);
    without the device option fall back to the unicast address (direct queries still work)."""
    if port in BROADCAST_UDP and host != "0.0.0.0":
        dev = bind_device()
        if dev:
            try:
                s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, dev.encode())
                s.bind(("0.0.0.0", port))
                return "0.0.0.0%" + dev
            except OSError:
                try:
                    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"")
                except OSError:
                    pass
    s.bind((host, port))
    return host


def serve_tcp(ctx, port, handler, proto, tls=None, name=None, host=None, budget=None):
    """Start a threaded TCP listener. handler(conn, addr, session) runs per connection.
    Emits tcp.connect for every accepted connection (level 1 = touch). Clients count against the decoy-wide
    connection budget; the accept loop survives every per-client failure, including Thread.start() errors
    when the process is out of threads (F-02)."""
    host = host or bind_ip()
    budget = budget or BUDGET

    def one(conn, addr):
        session = new_session()
        ctx.emit("tcp.connect", addr, port, proto, session)
        try:
            conn.settimeout(30)
            if tls is not None:
                try:
                    conn = tls.wrap_socket(conn, server_side=True)
                except Exception as e:
                    ctx.emit("tls.failed", addr, port, proto, session, error=str(e)[:120])
                    return
            handler(conn, addr, session)
        except Exception as e:  # never let one client kill the listener
            if not isinstance(e, (ConnectionError, socket.timeout, TimeoutError, OSError)):
                ctx.emit("sensor.error", addr, port, proto, session, error=f"{type(e).__name__}: {e}"[:200])
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def guarded(conn, addr):
        try:
            one(conn, addr)
        finally:
            budget.give(addr[0])

    def loop(s):
        fails = 0
        while s.fileno() != -1:                 # closed (stop / restart by the self-check) → this loop ends
            try:
                conn, addr = s.accept()
            except OSError:
                if s.fileno() == -1:
                    break
                time.sleep(0.01)                # EMFILE / ENOBUFS: never spin
                continue
            try:
                if not admit(ctx, conn, addr, port, proto, budget):
                    continue
                try:
                    threading.Thread(target=guarded, args=(conn, addr), daemon=True).start()
                    fails = 0
                except Exception as e:          # RuntimeError: can't start new thread (pids limit)
                    budget.give(addr[0])
                    _close(conn)
                    fails += 1
                    _thread_failed(ctx, port, proto, e, fails)
            except Exception:                   # never let the accept loop die
                _close(conn)
                time.sleep(0.01)

    bound = [port]

    def start():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, bound[0]))
            bound[0] = s.getsockname()[1]
            s.listen(128)
            t = threading.Thread(target=loop, args=(s,), name=name or f"{proto}:{port}", daemon=True)
            t.start()
        except BaseException:
            s.close()
            raise
        return s, t

    return REGISTRY.add(Listener("tcp", port, proto, start)).sock


def serve_socketserver(ctx, srv, port, proto, run=None, name=None, budget=None):
    """Put a socketserver.ThreadingMixIn server (impacket SMB, http.server) under the decoy-wide connection
    budget and the self-check: per-client admission + flood events, Thread.start() failures dropped with a
    back-off (the server keeps serving), and a registry entry that restarts serve_forever / re-binds the socket.
    run: what the serving thread runs the first time (default srv.serve_forever)."""
    budget = budget or BUDGET
    orig_request, orig_thread = srv.process_request, srv.process_request_thread
    fails = [0]

    def process_request(request, client_address):
        if not admit(ctx, request, client_address, port, proto, budget):
            return
        try:
            orig_request(request, client_address)
            fails[0] = 0
        except Exception as e:                  # Thread.start() failed: the client thread never ran
            budget.give(client_address[0])
            _close(request)
            fails[0] += 1
            _thread_failed(ctx, port, proto, e, fails[0])

    def process_request_thread(request, client_address):
        try:
            orig_thread(request, client_address)
        finally:
            budget.give(client_address[0])

    srv.process_request, srv.process_request_thread = process_request, process_request_thread
    first = [run or srv.serve_forever]

    def start():
        s = srv.socket
        try:
            ok = s.fileno() != -1 and s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        except OSError:
            ok = False
        if not ok:                              # re-bind the same address on a fresh socket
            _close(s)
            srv.socket = socket.socket(srv.address_family, srv.socket_type)
            try:
                srv.server_bind()
                srv.server_activate()
            except BaseException:
                srv.socket.close()
                raise
        t = threading.Thread(target=first.pop() if first else srv.serve_forever, name=name or f"{proto}:{port}",
                             daemon=True)
        t.start()
        return srv.socket, t

    def stop(s, t):
        if t is not None and t.is_alive():      # serving, but the socket went bad: end that loop first
            srv._BaseServer__shutdown_request = True
            _shut(s)
            t.join(2)

    REGISTRY.add(Listener("tcp", port, proto, start, stop=stop))
    return srv


class RateLimit:
    """Token bucket per source IP (UDP decoys must never become a reflection amplifier)."""

    def __init__(self, per_sec=10, burst=20):
        import time as _t
        self.t, self.rate, self.burst, self.b, self.lock = _t, per_sec, burst, {}, threading.Lock()

    def allow(self, ip):
        now = self.t.monotonic()
        with self.lock:
            tokens, last = self.b.get(ip, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self.b[ip] = (tokens - 1 if ok else tokens, now)
            if len(self.b) > 50000:
                self.b.clear()
            return ok


def serve_udp(ctx, port, handler, proto, name=None, host=None, per_sec=10):
    """UDP listener: handler(data, addr) → reply bytes or None. Replies are rate-limited per
    source and never larger than the request × 4 (no amplification)."""
    host = host or bind_ip()
    rl = RateLimit(per_sec=per_sec, burst=per_sec * 2)

    def loop(s):
        while s.fileno() != -1:
            try:
                data, addr = s.recvfrom(4096)
            except OSError:
                if s.fileno() == -1:
                    break
                time.sleep(0.01)
                continue
            try:
                if not rl.allow(addr[0]):
                    continue
                try:
                    reply = handler(data, addr)
                except Exception as e:
                    ctx.emit("sensor.error", addr, port, proto, None, error=f"{type(e).__name__}: {e}"[:200])
                    continue
                if reply:
                    try:
                        s.sendto(reply[:max(512, len(data) * 4)], addr)
                    except OSError:
                        pass
            except Exception:                   # never let the receive loop die
                time.sleep(0.01)

    bound = [port]

    def start():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _bind_udp(s, host, bound[0])
            bound[0] = s.getsockname()[1]
            t = threading.Thread(target=loop, args=(s,), name=name or f"{proto}/udp:{port}", daemon=True)
            t.start()
        except BaseException:
            s.close()
            raise
        return s, t

    return REGISTRY.add(Listener("udp", port, proto, start)).sock


def tls_context(ctx, alt_names=None):
    """Server SSLContext for a persona's TLS services, shaped like the claimed OS (RC-30, pentest F-03 T6).

    * Windows persona (the DC's LDAPS 636 / GC-over-SSL 3269): "Domain Controller" template certificate issued by
      a per-install AD CS enterprise CA "<domain label>-<HOST>-CA", Schannel Server 2019 protocols/ciphers.
    * Linux persona (the web decoy's HTTPS): Apache default-ssl on Ubuntu 22.04 (snakeoil cert, OpenSSL 3).

    alt_names is accepted for compatibility and ignored: the certificate profile fixes the SANs."""
    from rpot.common import tlsutil
    d = os.path.join(ctx.data_dir, "tls")
    if (ctx.os or "").lower().startswith("windows"):
        return tlsutil.dc_server_context(d, ctx.fqdn, ctx.domain, ctx.name,
                                         object_guid=ctx.persona_secret("dc-object-guid")[:16], sid=_dc_sid(ctx))
    return tlsutil.apache_server_context(d, ctx.fqdn)


def _dc_sid(ctx):
    """SID string of the DC's computer account as the fake directory hands it out (domain SID + RID 1000)."""
    try:
        from rpot.sensor.services.ldap import Directory
        dsid = Directory(ctx).dsid
        return "S-1-5-" + "-".join(str(x) for x in dsid) + "-1000"
    except Exception:
        return None


def safe_join(root, *parts):
    """Join untrusted path parts under root; returns None on traversal."""
    p = os.path.realpath(os.path.join(root, *[x.lstrip("/\\") for x in parts]))
    r = os.path.realpath(root)
    return p if p == r or p.startswith(r + os.sep) else None


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
