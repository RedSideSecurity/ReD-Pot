"""Event model + sensor→console transport.

Every sensor action is an event dict:
    {ts, sensor, role, sensor_ip, src_ip, src_port, dst_port, proto, type, session, data}
The console assigns the severity level (see rpot.console.scoring); sensors only describe
what happened. Delivery: background thread POSTs batches over HTTPS to the manager's sensor API
(/api/ingest), pinned to the manager certificate fingerprint and authenticated with the
sensor's own key.

Manager unreachable (Community Edition, decisions D-5/D-9): the batch in flight is retried in
memory for at most RETRY_WINDOW seconds. After that it, the in-memory queue and every event of
the outage go to a write-only local log `<data>/undelivered-<NAME>.jsonl` that this code never
reads back: nothing stored is ever sent later. On reconnect the sensor sends one
`sensor.gap {undelivered, first_ts, last_ts}` metadata event (counts and timestamps only).
The manager answers with its config version; when it changes, `on_version(v)` fires so the
sensor can pull fresh honeytokens without a restart.
"""
import json
import os
import queue
import socket
import stat
import threading
import time
import uuid
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_session():
    return uuid.uuid4().hex[:12]


_CTRL = {c: " " for c in list(range(0, 32)) + [127]}


def clean(v, depth=0):
    """Attacker-controlled strings: strip control chars (no CR/LF log or alert-line injection), cap size."""
    if isinstance(v, str):
        return v.translate(_CTRL)[:2000]
    if isinstance(v, dict) and depth < 4:
        return {str(k)[:64]: clean(x, depth + 1) for k, x in list(v.items())[:50]}
    if isinstance(v, (list, tuple)) and depth < 4:
        return [clean(x, depth + 1) for x in list(v)[:50]]
    return v


RETRY_WINDOW = 60.0       # D-9: seconds the in-flight batch is retried in memory, then it goes to the local log
QUEUE_MAX = 10000         # events held in memory (queue) at any time, retry window included; overflow → local log
HEARTBEAT = "sensor.heartbeat"
GAP = "sensor.gap"
_NOT_LOGGED = (HEARTBEAT, GAP)


def undelivered_max_bytes():
    """Local log cap from RPOT_UNDELIVERED_MAX_MB (default 50; bad values fall back to the default)."""
    try:
        mb = int(os.environ.get("RPOT_UNDELIVERED_MAX_MB", "50"))
    except ValueError:
        mb = 50
    return (mb if mb > 0 else 50) * 1024 * 1024


class Emitter:
    def __init__(self, sensor, role, console_url, key, sensor_ip=None, data_dir="/var/lib/rpot",
                 batch=50, interval=1.0, stdout=True, fingerprint=None, on_version=None, relay_socket=None,
                 queue_max=QUEUE_MAX, retry_window=RETRY_WINDOW, log_max_bytes=None,
                 clock=time.monotonic, sleep=None, start=True):
        self.sensor, self.role = sensor, role
        self.console_url = (console_url or "").rstrip("/")
        self.key = key
        self.client = None
        if relay_socket:                       # remote sensor: talk to the relay sidecar over a Unix socket
            from rpot.sensor.relay import UnixClient
            self.client = UnixClient(relay_socket, auth=key)
        elif self.console_url:
            from rpot.common.tlsutil import PinnedClient
            self.client = PinnedClient(self.console_url, fingerprint, auth=key)
        self.on_version = on_version
        self.version = None
        self.last_error = None
        self._seen = {}
        self.sensor_ip = sensor_ip or _local_ip()
        self.q = queue.Queue(maxsize=queue_max)
        self.batch, self.interval, self.stdout = batch, interval, stdout
        self.retry_window = retry_window
        self.log_max = log_max_bytes or undelivered_max_bytes()
        self._clock = clock
        self._stop = threading.Event()
        self._sleep = sleep or self._stop.wait
        try:
            os.makedirs(data_dir, exist_ok=True)
        except OSError as e:                    # disk problems never stop the decoy
            self.last_error = f"{type(e).__name__}: {e}"[:200]
        self.local_log = os.path.join(data_dir, f"undelivered-{sensor}.jsonl")
        self._lock = threading.Lock()           # local log + undelivered counters (emit() may write too)
        self.undelivered, self._first_ts, self._last_ts = 0, None, None
        self._pending = None                    # in-flight batch being retried in memory
        self._fail_since = None                 # clock() of the first failed POST of this batch
        self._backoff = 0.0
        self.down = False                       # retry window expired: everything goes to the local log
        self._next_probe = 0.0
        self._recovered = False                 # reconnect seen → next delivered POST carries sensor.gap
        self._last_gap = None
        self._last_hb = None
        self.thread = threading.Thread(target=self._run, name="emitter", daemon=True)
        if start:
            self.thread.start()

    # -- public ---------------------------------------------------------------
    def emit(self, type_, src=None, dst_port=None, proto=None, session=None, **data):
        ev = {
            "ts": now_iso(), "sensor": self.sensor, "role": self.role, "sensor_ip": self.sensor_ip,
            "src_ip": src[0] if src else None, "src_port": src[1] if src else None,
            "dst_port": dst_port, "proto": proto, "type": type_, "session": session,
            "data": clean({k: v for k, v in data.items() if v is not None}),
        }
        if type_ == "tcp.connect" and src and self._dup(src[0], dst_port):
            return ev
        if self.stdout:
            print(json.dumps(ev, ensure_ascii=False), flush=True)
        try:
            self.q.put_nowait(ev)
        except queue.Full:                      # memory cap reached: never grow, keep it locally instead
            self._log_local([ev])
        return ev

    def _dup(self, ip, port, window=60):
        """Connection floods: report a bare TCP connect once per source+port per minute."""
        now = time.time()
        k = (ip, port)
        if now - self._seen.get(k, 0) < window:
            return True
        self._seen[k] = now
        if len(self._seen) > 20000:
            self._seen = {kk: t for kk, t in self._seen.items() if now - t < window}
        return False

    def close(self, timeout=5):
        self._stop.set()
        if self.thread.is_alive():
            self.thread.join(timeout)

    # -- internals ------------------------------------------------------------
    def _run(self):
        while not self._stop.is_set() or not self.q.empty() or self._pending:
            try:
                self._step()
            except Exception as e:                      # never let the sender thread die
                self.last_error = f"{type(e).__name__}: {e}"[:200]
                self._stop.wait(1)

    def _drain(self, block):
        items = []
        try:
            items.append(self.q.get(timeout=self.interval) if block else self.q.get_nowait())
            while len(items) < self.batch:
                items.append(self.q.get_nowait())
        except queue.Empty:
            pass
        return items

    def _drain_all(self):
        items = []
        while True:
            try:
                items.append(self.q.get_nowait())
            except queue.Empty:
                return items

    def _heartbeat_due(self):
        now = self._clock()
        if self._last_hb is None or now - self._last_hb > 25 + (hash(self.sensor) % 10):   # jitter: no fixed rhythm
            self._last_hb = now
            return True
        return False

    def _heartbeat(self):
        return {"ts": now_iso(), "sensor": self.sensor, "role": self.role,
                "sensor_ip": self.sensor_ip, "type": HEARTBEAT, "data": {}}

    def _step(self):
        """One send cycle. Normal: queue → POST. Failing: retry the same batch (≤ retry_window).
        Down: queue → local log, probe the manager with a bare heartbeat until it answers."""
        if self.down:
            return self._step_down()
        if self._pending is not None:
            items = self._pending
        else:
            items = self._drain(block=True)
            if self._heartbeat_due():
                items.append(self._heartbeat())
        gap = self._gap_event()
        if not items and not (gap and self._recovered):    # after a reconnect the gap note goes out at once
            return
        if self._post(([gap] if gap else []) + items):
            if gap:
                self._gap_sent(gap)
            self._pending, self._fail_since, self._backoff = None, None, 0.0
            return
        now = self._clock()
        if self._fail_since is None:
            self._fail_since = now
        self._pending = [e for e in items if e.get("type") != HEARTBEAT]    # heartbeats are not retried
        left = self.retry_window - (now - self._fail_since)
        if left > 0 and not self._stop.is_set() and self._pending:
            self._backoff = min(max(self._backoff * 2, 1.0), 10.0)
            self._sleep(min(self._backoff, left))
            return
        if self._pending:                       # window over (or shutting down): batch + queue → local log
            self._log_local(self._pending + self._drain_all())
            self.down = True
            self._backoff = 0.0
            self._next_probe = self._clock()
        self._pending, self._fail_since = None, None

    def _step_down(self):
        items = self._drain(block=True)
        if items:                               # emitted during the outage → local log only, never sent
            self._log_local(items)
        if self._stop.is_set():
            return
        now = self._clock()
        if now < self._next_probe:
            return
        self._last_hb = now
        if self._post([self._heartbeat()]):
            self._log_local(self._drain_all())  # queued before the manager answered = outage events
            self.down, self._recovered, self._backoff = False, True, 0.0
        else:
            self._backoff = min(max(self._backoff * 2, 2.0), 30.0)
            self._next_probe = now + self._backoff

    def _gap_event(self):
        """One counts-only `sensor.gap` after a reconnect (or at most once a minute for queue overflow
        while connected). No event content: number undelivered + first/last event timestamp."""
        with self._lock:
            if not self.undelivered:
                return None
            if not self._recovered and self._last_gap is not None and self._clock() - self._last_gap < self.retry_window:
                return None
            n, first, last = self.undelivered, self._first_ts, self._last_ts
        return {"ts": now_iso(), "sensor": self.sensor, "role": self.role, "sensor_ip": self.sensor_ip,
                "type": GAP, "data": {"undelivered": n, "first_ts": first, "last_ts": last}}

    def _gap_sent(self, gap):
        with self._lock:
            self.undelivered -= gap["data"]["undelivered"]
            if self.undelivered <= 0:
                self.undelivered, self._first_ts, self._last_ts = 0, None, None
            else:                               # overflow logged during the POST: report it next time
                self._first_ts = self._last_ts
            self._recovered = False
            self._last_gap = self._clock()

    def _post(self, items):
        if not self.client:
            return False
        try:
            status, res = self.client.request("POST", "/api/ingest", {"events": items})
        except Exception as e:                      # includes PinError (wrong manager certificate)
            self.last_error = f"{type(e).__name__}: {e}"[:200]
            return False
        if status != 200:
            self.last_error = f"HTTP {status}"
            return False
        v = (res or {}).get("version") if isinstance(res, dict) else None
        if v and v != self.version:
            old, self.version = self.version, v
            if old is not None and self.on_version:
                try:
                    self.on_version(v)
                except Exception:
                    pass
        return True

    # -- local undelivered log (write-only; this code never reads it back) -----
    # O_RDWR only so _rotate can copy the newest tail of the same inode; nothing is ever parsed or sent
    _OPEN = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    _TMP = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)

    @staticmethod
    def _open_regular(path, flags):
        """O_NOFOLLOW refuses a symlink, O_NONBLOCK keeps a FIFO from hanging the sender;
        anything that is not a regular file (FIFO, device, socket) is refused after fstat."""
        fd = os.open(path, flags, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(f"{path}: not a regular file — refused")
            if stat.S_IMODE(st.st_mode) != 0o600:
                os.fchmod(fd, 0o600)
            return fd, st
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _write_all(fd, data):
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]

    def _log_local(self, items):
        items = [e for e in items if isinstance(e, dict) and e.get("type") not in _NOT_LOGGED]
        if not items:
            return
        data = b"".join(json.dumps(e, ensure_ascii=False).encode() + b"\n" for e in items)
        with self._lock:
            ts = [str(e.get("ts")) for e in items if e.get("ts")]
            self.undelivered += len(items)
            if ts:
                self._first_ts = min([self._first_ts] + ts) if self._first_ts else min(ts)
                self._last_ts = max([self._last_ts] + ts) if self._last_ts else max(ts)
            try:
                self._append(data)
            except OSError as e:                # disk full, refused path … — the decoy keeps running
                self.last_error = f"local log: {type(e).__name__}: {e}"[:200]

    def _append(self, data):
        half = self.log_max // 2
        if len(data) > half:                    # one huge batch: keep only its newest lines
            data = data[-half:].split(b"\n", 1)[-1]
        fd, st = self._open_regular(self.local_log, self._OPEN)
        try:
            if st.st_size + len(data) > self.log_max:
                fd = self._rotate(fd, st, half - len(data))
            self._write_all(fd, data)
        finally:
            os.close(fd)

    def _rotate(self, fd, st, keep):
        """Cap reached: keep the newest `keep` bytes (whole lines) via an O_EXCL temp file + os.replace.
        Returns an fd for appending to the new file; on failure the old file is left as it was."""
        keep = max(0, min(keep, st.st_size))
        tail = os.pread(fd, keep, st.st_size - keep) if keep else b""
        if keep < st.st_size:
            tail = tail.split(b"\n", 1)[-1] if b"\n" in tail else b""
        d, base = os.path.split(self.local_log)
        tmp = os.path.join(d, f".{base}.{uuid.uuid4().hex[:8]}.tmp")
        tfd, _ = self._open_regular(tmp, self._TMP)
        try:
            self._write_all(tfd, tail)
            os.replace(tmp, self.local_log)
        except BaseException:
            os.close(tfd)
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.close(fd)
        return tfd


def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
