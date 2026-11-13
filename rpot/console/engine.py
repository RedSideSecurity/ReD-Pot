"""Console engine: SQLite storage, ingest pipeline (score → escalate → incident → alert record),
host attribution and query helpers for the UI/API.

Alerts never leave the manager: each one is a line in alerts.json (if enabled) and a row in the
alert_records table (the source for Export). There is no outbound delivery of any kind."""
import ipaddress
import json
import re
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

from rpot.console.scoring import Scorer, score, describe, top_holders, LEVEL_NAMES
from rpot.console.geo import Geo
from rpot.console.logfile import JsonlLog
from rpot.console.fleet import Fleet
from rpot.common.edition import MAX_DECOYS

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts TEXT, sensor TEXT, role TEXT, sensor_ip TEXT, src_ip TEXT, src_port INT,
  dst_port INT, proto TEXT, type TEXT, session TEXT, level INT, data TEXT, incident_id INT, allowlisted INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_src ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS ev_inc ON events(incident_id);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY, src_ip TEXT, first_ts TEXT, last_ts TEXT, level INT, title TEXT,
  status TEXT DEFAULT 'open', sensors TEXT, count INT DEFAULT 0, alerted_level INT DEFAULT 0, note TEXT);
-- incidents.alerted_level: highest level already written as an alert record for this incident (dedupe
-- watermark, so a new record is written only when the incident's level rises). Not a delivery status.
CREATE INDEX IF NOT EXISTS inc_src ON incidents(src_ip, last_ts);
CREATE TABLE IF NOT EXISTS hosts(
  ip TEXT PRIMARY KEY, first_ts TEXT, last_ts TEXT, max_level INT DEFAULT 0, internal INT,
  names TEXT DEFAULT '{}', rdns TEXT);
CREATE TABLE IF NOT EXISTS sensors(
  name TEXT PRIMARY KEY, role TEXT, ip TEXT, title TEXT, os TEXT, version TEXT, services TEXT,
  last_seen TEXT, started TEXT);
CREATE TABLE IF NOT EXISTS alert_records(
  id INTEGER PRIMARY KEY, ts TEXT, incident_id INT, level INT, record TEXT);
CREATE INDEX IF NOT EXISTS ar_ts ON alert_records(ts);
"""



def ce_limit_sql(max_decoys=MAX_DECOYS):
    """D-6 layer 6: the decoy cap inside the database. ce_local(n) = local decoys in rpot.json (written at
    every start). A remote row that would exceed the cap, an un-revoke and any change of `remote` abort,
    whoever writes the row (console code, rpotctl, a hand-run sqlite3 shell)."""
    m = int(max_decoys)
    return f"""
CREATE TABLE IF NOT EXISTS ce_local(id INTEGER PRIMARY KEY CHECK (id = 1), n INT NOT NULL);
DROP TRIGGER IF EXISTS ce_limit_insert;
DROP TRIGGER IF EXISTS ce_no_unrevoke;
DROP TRIGGER IF EXISTS ce_no_remote_flip;
CREATE TRIGGER ce_limit_insert BEFORE INSERT ON fleet
WHEN NEW.remote = 1 AND NEW.revoked = 0
 AND (SELECT COUNT(*) FROM fleet WHERE remote = 1 AND revoked = 0 AND name <> NEW.name)
   + COALESCE((SELECT n FROM ce_local WHERE id = 1), {m}) >= {m}
BEGIN SELECT RAISE(ABORT, 'decoy limit'); END;
CREATE TRIGGER ce_no_unrevoke BEFORE UPDATE OF revoked ON fleet
WHEN OLD.revoked = 1 AND NEW.revoked = 0
BEGIN SELECT RAISE(ABORT, 'decoy limit: a revoked sensor cannot be restored'); END;
CREATE TRIGGER ce_no_remote_flip BEFORE UPDATE OF remote ON fleet
WHEN OLD.remote IS NOT NEW.remote
BEGIN SELECT RAISE(ABORT, 'decoy limit: remote flag is immutable'); END;
"""


INCIDENT_GAP = 3600  # seconds: same source quiet for longer → new incident
TS_PAST = timedelta(minutes=15)     # sensor timestamps older than this are restamped (CE never replays old events)
TS_FUTURE = timedelta(minutes=5)
SKEW_WARN_MAX = 1000                # bound on the "already warned" set of decoy names
GAP_WINDOW = 300                    # s: at most one sensor.gap note per decoy per window; extras are merged
GAP_STATE_MAX = 1000                # bound on the per-decoy gap-window state
NOTE_MAX_LINES = 20                 # decoy-health incident notes keep only their newest lines ...
NOTE_MAX_BYTES = 4096               # ... and at most this many characters
GAP_TS_PAST = timedelta(days=30)    # sensor.gap first_ts/last_ts outside [now-30d, now+5min] are dropped
GAP_TS_FMT = "%Y-%m-%d %H:%M:%S"
SERVICE_ALERT_WINDOW = 300          # s: at most one "decoy service down" alert record per decoy per window (F-02)
HEALTH_MAX = 64                     # bound on the per-decoy service health map
GAP_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}")


def cap_note(old, line):
    """Append `line` to an incident note and keep only the newest NOTE_MAX_LINES lines / NOTE_MAX_BYTES chars.
    O(1) in the size of `old` (only its tail is looked at), so a note can never grow without bound."""
    tail = (old or "")[-(NOTE_MAX_BYTES + 1):]
    lines = [x for x in tail.split("\n") if x]
    if old and len(old) > NOTE_MAX_BYTES and lines:
        lines = lines[1:]                   # the first piece of a cut tail is a partial line
    lines = (lines + [line])[-NOTE_MAX_LINES:]
    while len(lines) > 1 and len("\n".join(lines)) > NOTE_MAX_BYTES:
        lines = lines[1:]
    return "\n".join(lines)[-NOTE_MAX_BYTES:]


def parse_ts(s):
    try:
        return datetime.strptime(str(s)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def check_ts(ts, now):
    """Sensor clocks are not trusted. Returns (timestamp to store, restamped, skew): malformed timestamps and
    ones more than 5 min in the future or 15 min in the past become server time (restamped=True). `skew` is
    the sensor-minus-server offset in seconds when a parseable timestamp was out of that window, else None."""
    try:
        t = datetime.strptime(str(ts)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return iso(now), True, None
    if t > now + TS_FUTURE or t < now - TS_PAST:
        return iso(now), True, (t - now).total_seconds()
    return iso(t), False, None


def sane_ts(ts, now):
    return check_ts(ts, now)[0]


def sensor_subject_label(name):
    return f"decoy {name}"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Engine:
    def __init__(self, cfg, db_path, geo_dir=None, log_dir=None):
        self.cfg = cfg
        self.db_path = db_path
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self._migrate()
        self.lock = threading.RLock()
        self.scorer = Scorer()
        self._skew_warned = set()
        self._gap_state = {}            # decoy name -> [monotonic start, events.id, undelivered sum, first, last, reports]
        self._svc_alerted = {}          # decoy name -> monotonic time of its last "service down" alert record
        self._pending_lines = []        # alerts.json lines of the open ingest transaction (written after COMMIT)
        self.geo = Geo(geo_dir)
        lc = cfg.get("logs") or {}
        ldir = lc.get("dir") or log_dir
        self.alert_log = JsonlLog(ldir, "alerts", lc.get("max_mb", 50), lc.get("keep", 90)) if ldir and lc.get("alerts", True) else None
        self.event_log = JsonlLog(ldir, "events", lc.get("max_mb", 50), lc.get("keep", 90)) if ldir and lc.get("events", False) else None
        self.allow = [ipaddress.ip_network(c, strict=False) for c in cfg.get("allowlist", [])]
        self.internal = [ipaddress.ip_network(c, strict=False) for c in cfg.get("internal_nets", [])]
        self.fleet = Fleet(cfg, self.db, self.lock)
        self.db.executescript(ce_limit_sql())
        self.db.execute("INSERT OR REPLACE INTO ce_local(id, n) VALUES(1, ?)", (len(self.fleet.local_names()),))
        self.sensor_ips = self.fleet.sensor_ips() | {cfg.get("network", {}).get("console_ip")}
        # decoys with an open tamper incident are still "offline" after a console restart — otherwise the
        # watchdog would never note their return (the in-memory set used to start empty)
        self._offline = {r[0][7:] for r in self.db.execute(
            "SELECT i.subject FROM incidents i WHERE i.subject LIKE 'sensor:%' AND i.status IN ('open','ack') AND "
            "(SELECT e.type FROM events e WHERE e.incident_id = i.id ORDER BY e.id DESC LIMIT 1) = 'sensor.offline'")}
        if cfg.get("console", {}).get("watch_offline", True):
            threading.Thread(target=self._watch_sensors, daemon=True, name="sensor-watch").start()
            threading.Thread(target=self._retention, daemon=True, name="retention").start()
        self._rdns_q = set()
        for s in cfg.get("sensors", []):
            self.db.execute("INSERT OR IGNORE INTO sensors(name, role, ip) VALUES(?,?,?)", (s["name"], s["role"], s["ip"]))

    def _migrate(self):
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(incidents)")}
        if "subject" not in cols:      # 'sensor:<NAME>' for decoy-health incidents (no attacker IP)
            self.db.execute("ALTER TABLE incidents ADD COLUMN subject TEXT")
        if "health" not in {r[1] for r in self.db.execute("PRAGMA table_info(sensors)")}:
            self.db.execute("ALTER TABLE sensors ADD COLUMN health TEXT")   # per-service listener health (F-02)

    # ------------------------------------------------------------------ ingest
    def ingest(self, events):
        n = 0
        with self.lock:
            self._pending_lines = []
            self.db.execute("BEGIN")
            try:
                for ev in events:
                    n += self._one(ev)
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                self._gap_state = {}        # may point at rolled-back sensor.gap rows
                self._pending_lines = []    # their alert_records rows were rolled back too
                raise
            lines, self._pending_lines = self._pending_lines, []
            for rec in lines:
                self._write_alert_line(rec)
        return n

    def _one(self, ev):
        if not isinstance(ev.get("type"), str) or not isinstance(ev.get("data", {}), dict):
            return 0
        now = datetime.now(timezone.utc)
        orig = ev.get("ts")
        ev["ts"], restamped, skew = check_ts(orig, now)
        if restamped and orig not in (None, ""):
            ev["data"] = dict(ev.get("data") or {}, sensor_ts=str(orig)[:64])   # restamped: keep the sensor's value
        if skew is not None:
            self._warn_skew(ev.get("sensor"), skew)
        for k in ("src_ip", "sensor_ip", "proto", "session", "role"):
            if ev.get(k) is not None and not isinstance(ev[k], str):
                ev[k] = str(ev[k])[:64]
        for k in ("src_port", "dst_port"):
            if ev.get(k) is not None and not isinstance(ev[k], int):
                ev[k] = None
        t = ev.get("type", "")
        if t.startswith("sensor."):
            ev["ts"] = iso(now)               # liveness uses the manager clock, never the sensor's
            self._sensor_status(ev)
            if t == "sensor.gap":
                return self._sensor_gap(ev)
            if t in ("sensor.service_down", "sensor.service_up"):
                return self._service_health(ev)
            if t != "sensor.heartbeat":
                self._store(ev, 0, None, 0)
            return 1
        if t == "conn.flood" and (ev.get("data") or {}).get("reason") in ("global", "threads"):
            return self._saturation(ev)
        src = ev.get("src_ip")
        if src and src == ev.get("sensor_ip"):  # a decoy talking to itself — ignore (other decoys are NOT exempt:
            return 0                            # a hijacked decoy attacking its neighbours must be seen)
        d = ev.get("data") or {}
        tok = self.fleet.all_tokens().get(d.get("token")) if d.get("token") else None
        if tok:                                 # sensors only know token ids; the manager adds what/where
            d["desc"], d["planted"] = tok.get("desc"), tok.get("planted")
            ev["data"] = d
        if t == "canary.hit":                # beacon received by the web decoy → show as "Bait docs"
            ev.setdefault("data", {})["via"] = ev.get("sensor")
            ev["sensor"] = "CANARY"
        out = [ev] + (self.scorer.escalations(ev) if src else [])
        for e in out:
            lvl = score(e)
            allow = 1 if src and self._allowed(src) else 0
            inc = None
            if src and not allow and lvl >= 1:
                inc = self._incident(e, lvl)
            self._store(e, lvl, inc, allow)
            if src:
                self._host(e, lvl)
        return len(out)

    def _store(self, ev, lvl, inc, allow):
        if self.event_log and not str(ev.get("type", "")).startswith("sensor."):
            try:
                self.event_log.write(dict(ev, level=lvl, incident=inc, allowlisted=bool(allow)))
            except OSError:
                pass
        return self.db.execute(
            "INSERT INTO events(ts,sensor,role,sensor_ip,src_ip,src_port,dst_port,proto,type,session,level,data,incident_id,allowlisted)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev.get("ts"), ev.get("sensor"), ev.get("role"), ev.get("sensor_ip"), ev.get("src_ip"), ev.get("src_port"),
             ev.get("dst_port"), ev.get("proto"), ev.get("type"), ev.get("session"), lvl,
             json.dumps(ev.get("data") or {}, ensure_ascii=False), inc, allow))

    def _allowed(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.allow)

    ALWAYS_INTERNAL = [ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")]

    def is_internal(self, ip):
        """Private / CGNAT / link-local are ALWAYS internal; internal_nets adds the organisation's
        own public ranges (it never removes the private ones)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.ALWAYS_INTERNAL) or any(a in n for n in self.internal)

    def _sensor_status(self, ev):
        d = ev.get("data") or {}
        name = ev.get("sensor")
        self.db.execute("INSERT OR IGNORE INTO sensors(name, role, ip) VALUES(?,?,?)", (name, ev.get("role"), ev.get("sensor_ip")))
        self.db.execute("UPDATE sensors SET last_seen=?, role=COALESCE(role, ?) WHERE name=?", (ev["ts"], ev.get("role"), name))
        if ev["type"] == "sensor.start":
            self.db.execute("UPDATE sensors SET version=?, services=?, os=?, title=?, started=?, health=NULL WHERE name=?",
                            (d.get("version"), json.dumps(d.get("services") or []), d.get("os"), d.get("title"), ev["ts"], name))

    def _service_health(self, ev):
        """F-02 (RC-28): the decoy's self-check found a listener dead / unbound (sensor.service_down) or serving
        again (sensor.service_up, usually after its own restart). Down → L4 decoy-health incident "service down —
        possible DoS" (alert record at most once per decoy per SERVICE_ALERT_WINDOW); up → note on that incident.
        The per-service state is kept in sensors.health for /api/sensors (reset when the decoy process starts)."""
        d = ev.get("data") or {}
        name, ts = ev.get("sensor"), ev["ts"]
        sname = str(name)[:64]
        svc = str(d.get("service") or f"{ev.get('proto')}/{ev.get('dst_port')}")[:64]
        lst = str(d.get("listener") or svc)[:64]
        down = ev["type"] == "sensor.service_down"
        reason = str(d.get("reason") or "")[:120] if down else None
        row = self.db.execute("SELECT health, ip, role FROM sensors WHERE name=?", (name,)).fetchone()
        try:
            health = json.loads(row["health"] or "{}") if row else {}
        except (TypeError, ValueError):
            health = {}
        health = health if isinstance(health, dict) else {}
        h = health.get(svc) if isinstance(health.get(svc), dict) else {}
        listeners = {str(x)[:64] for x in (h.get("down") or []) if isinstance(x, str)}
        if down:
            listeners.add(lst)
        else:
            listeners.discard(lst)
        if svc in health or len(health) < HEALTH_MAX:
            ok = not listeners
            since = ts if h.get("ok", True) != ok or not h.get("since") else h["since"]    # time of the last change
            health[svc] = {"ok": ok, "down": sorted(listeners)[:16], "since": since,
                           "reason": reason if listeners else None, "checked": ts}
            self.db.execute("UPDATE sensors SET health=? WHERE name=?", (json.dumps(health), name))
        bad = sorted(k for k, v in health.items() if isinstance(v, dict) and not v.get("ok", True))
        subj = "sensor:" + sname
        when = ts[:19].replace("T", " ")
        inc = self.db.execute("SELECT * FROM incidents WHERE subject=? AND status IN ('open','ack') ORDER BY id DESC LIMIT 1",
                              (subj,)).fetchone()
        if not down:
            note = f"{when} UTC: service {svc} ({lst}) is serving again" + (
                " (restarted by the decoy self-check)" if d.get("restarted") else "")
            iid = None
            if inc:
                iid = inc["id"]
                self.db.execute("UPDATE incidents SET last_ts=?, count=count+1, note=? WHERE id=?",
                                (max(ts, inc["last_ts"]), cap_note(inc["note"], note), iid))
            self._store(ev, 1, iid, 0)
            return 1
        level = 4
        title = f"Decoy {sname}: service {', '.join(bad or [svc])[:120]} down - possible DoS"
        note = f"{when} UTC: service {svc} ({lst}) stopped: {reason or 'unknown'}; the decoy tries to restart it"
        if inc:
            iid = inc["id"]
            keep = inc["level"] >= level and not str(inc["title"] or "").startswith(f"Decoy {sname}: service ")
            self.db.execute("UPDATE incidents SET last_ts=?, level=MAX(level, ?), title=?, count=count+1, note=?, "
                            "alerted_level=MAX(alerted_level, ?) WHERE id=?",
                            (max(ts, inc["last_ts"]), level, inc["title"] if keep else title, cap_note(inc["note"], note),
                             level, iid))
        else:
            iid = self.db.execute("INSERT INTO incidents(src_ip, subject, first_ts, last_ts, level, title, sensors, count, "
                                  "alerted_level, note) VALUES(NULL,?,?,?,?,?,?,1,?,?)",
                                  (subj, ts, ts, level, title, json.dumps([sname]), level, cap_note(None, note))).lastrowid
        self._store(ev, level, iid, 0)
        mono = time.monotonic()
        last = self._svc_alerted.get(sname)
        if last is None or mono - last >= SERVICE_ALERT_WINDOW:
            if len(self._svc_alerted) >= GAP_STATE_MAX:
                self._svc_alerted = {k: v for k, v in self._svc_alerted.items() if mono - v < SERVICE_ALERT_WINDOW}
            self._svc_alerted[sname] = mono
            summary = (f"Decoy {sname}: service {svc} ({lst}) stopped ({reason or 'unknown'}) - possible DoS; "
                       "the decoy restarts it")
            rec = {"timestamp": ts, "product": "ReD-Pot", "company": self.cfg.get("company", {}).get("name"),
                   "src_ip": None, "dest_ip": ev.get("sensor_ip"), "dest_port": ev.get("dst_port"), "level": level,
                   "alert": {"incident_id": iid, "type": ev["type"], "level": level,
                             "level_name": LEVEL_NAMES.get(level), "summary": summary},
                   "source": {"label": sensor_subject_label(sname), "internal": True},
                   "target": {"sensor": sname, "role": ev.get("role"), "ip": ev.get("sensor_ip"),
                              "port": ev.get("dst_port"), "proto": ev.get("proto"), "service": svc}}
            self._record_alert(rec, iid, level)
            self._pending_lines.append(rec)
        return 1

    def _saturation(self, ev):
        """RC-31 (threat-hunt C1): a decoy-wide cap (thread ceiling / global connection cap) refused a client. That
        client may be innocent, so this is a decoy-health incident (subject sensor:<NAME>, L4, "saturated - possible
        DoS") naming the top holders the decoy reported (data.top_sources), never an incident against the refused
        source. Alert record + alerts.json line when the incident is new or its level rises, else at most once per
        decoy per SERVICE_ALERT_WINDOW."""
        d = ev.get("data") or {}
        sname, ts = str(ev.get("sensor"))[:64], ev["ts"]
        subj, level = "sensor:" + sname, 4
        title = describe(ev)[:300]
        when = ts[:19].replace("T", " ")
        note = (f"{when} UTC: {d.get('reason')} cap {d.get('limit')} reached on {ev.get('proto')}/{ev.get('dst_port')}, "
                f"{d.get('refused', 1)} client(s) refused so far (last refused: {str(ev.get('src_ip'))[:45]}); "
                f"top holders: {top_holders(d)}")
        inc = self.db.execute("SELECT * FROM incidents WHERE subject=? AND status IN ('open','ack') ORDER BY id DESC LIMIT 1",
                              (subj,)).fetchone()
        if inc:
            iid, rise = inc["id"], level > (inc["alerted_level"] or 0)
            keep = inc["level"] > level
            self.db.execute("UPDATE incidents SET last_ts=?, level=MAX(level, ?), title=?, count=count+1, note=?, "
                            "alerted_level=MAX(alerted_level, ?) WHERE id=?",
                            (max(ts, inc["last_ts"]), level, inc["title"] if keep else title, cap_note(inc["note"], note),
                             level, iid))
        else:
            rise = True
            iid = self.db.execute("INSERT INTO incidents(src_ip, subject, first_ts, last_ts, level, title, sensors, count, "
                                  "alerted_level, note) VALUES(NULL,?,?,?,?,?,?,1,?,?)",
                                  (subj, ts, ts, level, title, json.dumps([sname]), level, cap_note(None, note))).lastrowid
        self._store(ev, level, iid, 0)
        mono, key = time.monotonic(), (sname, "saturated")
        last = self._svc_alerted.get(key)
        if rise or last is None or mono - last >= SERVICE_ALERT_WINDOW:
            if len(self._svc_alerted) >= GAP_STATE_MAX:
                self._svc_alerted = {k: v for k, v in self._svc_alerted.items() if mono - v < SERVICE_ALERT_WINDOW}
            self._svc_alerted[key] = mono
            rec = {"timestamp": ts, "product": "ReD-Pot", "company": self.cfg.get("company", {}).get("name"),
                   "src_ip": None, "dest_ip": ev.get("sensor_ip"), "dest_port": ev.get("dst_port"), "level": level,
                   "alert": {"incident_id": iid, "type": "decoy.saturated", "level": level,
                             "level_name": LEVEL_NAMES.get(level), "summary": title,
                             "top_sources": [r for r in (d.get("top_sources") or []) if isinstance(r, dict)][:5],
                             "refused": d.get("refused"), "last_refused_ip": ev.get("src_ip")},
                   "source": {"label": sensor_subject_label(sname), "internal": True},
                   "target": {"sensor": sname, "role": ev.get("role"), "ip": ev.get("sensor_ip"),
                              "port": ev.get("dst_port"), "proto": ev.get("proto")},
                   "event": {"type": ev.get("type"), "data": d}}
            self._record_alert(rec, iid, level)
            self._pending_lines.append(rec)
        return 1

    def _incident(self, ev, lvl):
        src, ts = ev["src_ip"], ev["ts"]
        row = self.db.execute("SELECT * FROM incidents WHERE src_ip=? AND status='open' ORDER BY id DESC LIMIT 1", (src,)).fetchone()
        if row and (parse_ts(ts) - parse_ts(row["last_ts"])).total_seconds() <= INCIDENT_GAP:
            sensors = json.loads(row["sensors"] or "[]")   # kept in first-touch order = attack path
            if ev.get("sensor") and ev["sensor"] not in sensors:
                sensors.append(ev["sensor"])
            title, level = row["title"], row["level"]
            synthetic = (ev.get("data") or {}).get("synthetic")
            if lvl > level or (lvl == level and (synthetic or (lvl >= 4 and ev["type"] == "honeytoken.used"))):
                title, level = describe(ev), max(lvl, level)
            self.db.execute("UPDATE incidents SET last_ts=?, level=?, title=?, sensors=?, count=count+1 WHERE id=?",
                            (max(ts, row["last_ts"]), level, title, json.dumps(sensors), row["id"]))
            iid, prev_alerted = row["id"], row["alerted_level"]
        else:
            cur = self.db.execute("INSERT INTO incidents(src_ip, first_ts, last_ts, level, title, sensors, count) VALUES(?,?,?,?,?,?,1)",
                                  (src, ts, ts, lvl, describe(ev), json.dumps([ev.get("sensor")])))
            iid, level, prev_alerted = cur.lastrowid, lvl, 0
        min_level = self.cfg.get("alerts", {}).get("min_level", 3)
        if level >= min_level and level > prev_alerted:
            self.db.execute("UPDATE incidents SET alerted_level=? WHERE id=?", (level, iid))
            host = self.host_label(src)
            self._log_alert(iid, level, ev, host)
        return iid

    def _warn_skew(self, sensor, skew):
        """Once per decoy (per manager run): its clock is outside the accepted window, so its events are
        stored with manager time. The name is the authenticated sensor name; repr() keeps the line inert."""
        if sensor in self._skew_warned or len(self._skew_warned) >= SKEW_WARN_MAX:
            return
        self._skew_warned.add(sensor)
        side = "ahead of" if skew > 0 else "behind"
        print(f"[ReD-Pot manager] WARNING: decoy {str(sensor)[:64]!r} clock is {abs(int(skew))} s {side} the manager; "
              "its events are stored with manager time (original kept as data.sensor_ts). Check NTP on that host.",
              flush=True)

    def purge(self, days):
        """Delete events and alert records older than `days` (incidents/hosts keep their summary).
        alerts.json keeps its own history (rotation)."""
        cut = iso(datetime.now(timezone.utc) - timedelta(days=days))
        with self.lock:
            n = self.db.execute("DELETE FROM events WHERE ts < ?", (cut,)).rowcount
            n += self.db.execute("DELETE FROM alert_records WHERE ts < ?", (cut,)).rowcount
        return n

    def _retention(self):
        days = int(self.cfg.get("console", {}).get("retention_days", 90))
        while True:
            try:
                if self.purge(days):
                    with self.lock:
                        self.db.execute("PRAGMA incremental_vacuum")
            except Exception:
                pass
            time.sleep(6 * 3600)

    def _watch_sensors(self, every=30, grace=120):
        """A decoy that stops reporting is suspicious (someone may be disabling it) → alert once,
        and log when it comes back."""
        while True:
            time.sleep(every)
            try:
                now = datetime.now(timezone.utc)
                for s in self.sensors():
                    if not s.get("last_seen"):
                        continue
                    silent = (now - parse_ts(s["last_seen"])).total_seconds()
                    if silent > grace and s["name"] not in self._offline:
                        self._offline.add(s["name"])
                        self._sensor_alert(s, "sensor.offline", f"Sensor {s['name']} stopped reporting {int(silent)} s ago — possible tampering")
                    elif silent <= grace and s["name"] in self._offline:
                        self._offline.discard(s["name"])
                        self._sensor_alert(s, "sensor.online", f"Sensor {s['name']} is reporting again")
            except Exception:
                pass

    def _sensor_alert(self, s, type_, summary):
        ev = {"ts": iso(datetime.now(timezone.utc)), "sensor": s["name"], "role": s.get("role"), "sensor_ip": s.get("ip"),
              "src_ip": None, "src_port": None, "dst_port": None, "proto": None, "type": type_, "session": None,
              "data": {"summary": summary}}
        level = 4 if type_ == "sensor.offline" else 1
        label = sensor_subject_label(s["name"])
        with self.lock:
            iid = self._sensor_incident(s, ev, level)
            self._store(ev, level, iid, 0)
            rec = {"timestamp": ev["ts"], "product": "ReD-Pot", "company": self.cfg.get("company", {}).get("name"),
                   "src_ip": None, "dest_ip": s.get("ip"), "level": level,
                   "alert": {"incident_id": iid, "type": type_, "level": level,
                             "level_name": LEVEL_NAMES.get(level), "summary": summary},
                   "source": {"label": label, "internal": True},
                   "target": {"sensor": s["name"], "role": s.get("role"), "ip": s.get("ip")}}
            self._record_alert(rec, iid, level)       # autocommit here (not inside an ingest transaction)
            self._write_alert_line(rec)

    def _sensor_incident(self, s, ev, level):
        """Decoy health is a first-class incident keyed by the decoy (no attacker IP), shown as 'decoy FS01'.
        offline → open (or update) the decoy's incident; back online → auto-note on that incident. It stays
        open: someone may have stopped the decoy on purpose — the analyst decides."""
        subj = "sensor:" + s["name"]
        ts = ev["ts"]
        row = self.db.execute("SELECT * FROM incidents WHERE subject=? AND status IN ('open','ack') ORDER BY id DESC LIMIT 1",
                              (subj,)).fetchone()
        if ev["type"] == "sensor.online":
            if not row:
                return None
            note = f"{ts[:19].replace('T', ' ')} UTC: decoy is reporting again"
            self.db.execute("UPDATE incidents SET last_ts=?, count=count+1, note=? WHERE id=?",
                            (max(ts, row["last_ts"]), cap_note(row["note"], note), row["id"]))
            return row["id"]
        title = f"Decoy {s['name']} stopped reporting — possible tampering (stopped, isolated or unplugged)"
        if row:
            self.db.execute("UPDATE incidents SET last_ts=?, level=MAX(level, ?), title=?, count=count+1, "
                            "alerted_level=MAX(alerted_level, ?) WHERE id=?", (max(ts, row["last_ts"]), level, title, level, row["id"]))
            return row["id"]
        cur = self.db.execute("INSERT INTO incidents(src_ip, subject, first_ts, last_ts, level, title, sensors, count, alerted_level) "
                              "VALUES(NULL,?,?,?,?,?,?,1,?)", (subj, ts, ts, level, title, json.dumps([s["name"]]), level))
        return cur.lastrowid

    def _sensor_gap(self, ev):
        """D-5/D-9: after a manager outage a decoy reports, once, how many events it kept only in its local
        undelivered log (counts + timestamps, never content). Shown as a note on the decoy's open health
        incident (tamper / "reporting again"), else as a new low-level decoy incident.
        F3 (RC-18): a sensor key holder must not be able to stall ingest with a gap flood. At most one gap per
        decoy per GAP_WINDOW becomes a note line / event row; later ones inside the window are merged into that
        event row (counts summed, time span widened). The note is capped (cap_note). O(1) work per gap.
        F10: first_ts/last_ts are the SENSOR's clock (labelled so) and dropped when outside [now-30d, now+5min]."""
        d = ev.get("data") or {}
        n = d.get("undelivered")
        n = n if isinstance(n, int) and not isinstance(n, bool) and 0 <= n < 10 ** 12 else 0
        now = datetime.now(timezone.utc)
        lo, hi = (now - GAP_TS_PAST).strftime(GAP_TS_FMT), (now + TS_FUTURE).strftime(GAP_TS_FMT)

        def when(v):                        # -> "YYYY-MM-DD HH:MM:SS" (validated, re-built) or None
            if not isinstance(v, str) or not GAP_TS_RE.match(v):
                return None
            try:
                datetime.fromisoformat(v[:19])                  # real calendar date/time (cheap, C)
            except ValueError:
                return None
            t = v[:10] + " " + v[11:19]
            return t if lo <= t <= hi else None
        first, last = when(d.get("first_ts")), when(d.get("last_ts"))
        if first and last and first > last:
            first, last = last, first
        name, ts = str(ev.get("sensor"))[:64], ev["ts"]
        mono = time.monotonic()
        st = self._gap_state.get(name)
        if st and mono - st[0] < GAP_WINDOW:
            st[2] = min(st[2] + n, 10 ** 12)
            st[3] = min(x for x in (st[3], first) if x) if (st[3] or first) else None
            st[4] = max(x for x in (st[4], last) if x) if (st[4] or last) else None
            st[5] += 1
            data = {"undelivered": st[2], "first_ts": st[3], "last_ts": st[4], "reports": st[5],
                    "summary": self._gap_summary(name, st[2], st[3], st[4], st[5])}
            if self.db.execute("UPDATE events SET data=? WHERE id=? AND type='sensor.gap' AND sensor=?",
                               (json.dumps(data), st[1], ev.get("sensor"))).rowcount:
                return 1
            # the row is gone (rolled back batch / purge): fall through and start a new window
        ev["data"] = d = {"undelivered": n, "first_ts": first, "last_ts": last, "reports": 1}
        d["summary"] = self._gap_summary(name, n, first, last, 1)
        note = f"{ts[:19].replace('T', ' ')} UTC: {d['summary']}"
        subj = "sensor:" + name
        row = self.db.execute("SELECT * FROM incidents WHERE subject=? AND status IN ('open','ack') ORDER BY id DESC LIMIT 1",
                              (subj,)).fetchone()
        if row:
            iid = row["id"]
            self.db.execute("UPDATE incidents SET last_ts=?, count=count+1, note=? WHERE id=?",
                            (max(ts, row["last_ts"]), cap_note(row["note"], note), iid))
        else:
            iid = self.db.execute("INSERT INTO incidents(src_ip, subject, first_ts, last_ts, level, title, sensors, count, note) "
                                  "VALUES(NULL,?,?,?,1,?,?,1,?)", (subj, ts, ts, f"Decoy {name}: events not delivered "
                                  "(manager unreachable)", json.dumps([name]), cap_note(None, note))).lastrowid
        eid = self._store(ev, 1, iid, 0).lastrowid
        if name not in self._gap_state and len(self._gap_state) >= GAP_STATE_MAX:
            self._gap_state = {k: v for k, v in self._gap_state.items() if mono - v[0] < GAP_WINDOW}
            if len(self._gap_state) >= GAP_STATE_MAX:
                self._gap_state.pop(next(iter(self._gap_state)))
        self._gap_state[name] = [mono, eid, n, first, last, 1]
        return 1

    @staticmethod
    def _gap_summary(name, n, first, last, reports):
        span = f" (decoy clock {first} to {last} UTC, as reported by the decoy)" if first and last else ""
        more = f" [{reports} reports within {GAP_WINDOW // 60} min merged]" if reports > 1 else ""
        return (f"Decoy {name} could not reach the manager: {n} event(s){span} were not delivered and are kept "
                f"only in the decoy's local undelivered log{more}")

    def _record_alert(self, rec, iid, level):
        """alert_records row = the same JSON as the alerts.json line. Written whether or not alerts.json is on."""
        self.db.execute("INSERT INTO alert_records(ts, incident_id, level, record) VALUES(?,?,?,?)",
                        (rec["timestamp"], iid, level, json.dumps(rec, ensure_ascii=False)))

    def _write_alert_line(self, rec):
        if self.alert_log:
            try:
                self.alert_log.write(rec)
            except OSError:
                pass

    def _log_alert(self, iid, level, ev, host):
        """One alert: a row in alert_records now (same transaction as the incident) and one line in alerts.json
        (JSON Lines, rotated + gzipped) after the ingest transaction commits."""
        src = ev.get("src_ip")
        internal = self.is_internal(src)
        inc = self.db.execute("SELECT title, sensors, count, first_ts FROM incidents WHERE id=?", (iid,)).fetchone()
        dst = ev.get("sensor_ip")
        where = f"{ev.get('sensor')} ({dst}:{ev.get('dst_port')})" if dst and ev.get("dst_port") else (
            f"{ev.get('sensor')} ({dst})" if dst else str(ev.get("sensor")))
        rec = {
            "timestamp": ev.get("ts"), "product": "ReD-Pot", "company": self.cfg.get("company", {}).get("name"),
            # flat, eve.json-style fields so SIEMs index them without custom parsing
            "src_ip": src, "src_port": ev.get("src_port"), "dest_ip": dst, "dest_port": ev.get("dst_port"),
            "proto": ev.get("proto"), "level": level,
            "alert": {"incident_id": iid, "level": level, "level_name": LEVEL_NAMES.get(level),
                      "summary": f"{src} → {where}: {describe(ev)}",
                      "incident_title": inc["title"] if inc else None, "incident_first_seen": inc["first_ts"] if inc else None,
                      "incident_events": inc["count"] if inc else None,
                      "path": json.loads(inc["sensors"]) if inc and inc["sensors"] else []},
            "source": {"ip": src, "port": ev.get("src_port"), "label": host, "internal": internal,
                       "geo": None if internal else self.geo.lookup(src)},
            "target": {"sensor": ev.get("sensor"), "role": ev.get("role"), "ip": ev.get("sensor_ip"),
                       "port": ev.get("dst_port"), "proto": ev.get("proto")},
            "event": {"type": ev.get("type"), "session": ev.get("session"), "data": ev.get("data") or {}},
        }
        self._record_alert(rec, iid, level)
        self._pending_lines.append(rec)

    def _host(self, ev, lvl):
        src, ts = ev["src_ip"], ev["ts"]
        row = self.db.execute("SELECT * FROM hosts WHERE ip=?", (src,)).fetchone()
        names = json.loads(row["names"]) if row else {}
        d = ev.get("data") or {}
        def add(k, v):
            if v:
                lst = names.setdefault(k, [])
                if v not in lst:
                    lst.append(v)
                    del lst[:-(30 if k == "tried" else 8)]
        t = ev["type"]
        # Everything below is SENT BY THE CLIENT. Only a successful login (the decoy accepted the secret) proves
        # an account → 'logon'; any other username is merely 'tried' (a sprayer can type ARAKSBANK\\j.smith).
        # The RDP mstshash cookie is free text (nmap sends "nmap") → a client trait, never an identity.
        if t in ("smb.auth", "rdp.ntlm"):
            add("workstation", d.get("workstation"))
        u = d.get("username") or d.get("user")
        if isinstance(u, str) and u.strip():
            u = ((f"{d['domain']}\\" if isinstance(d.get("domain"), str) and d.get("domain") and "\\" not in u else "") + u.strip())[:80]
            if t == "auth.success" or (t == "honeytoken.used" and d.get("success") is True):
                add("logon", u)
            elif t not in ("auth.bruteforce", "kerberos.enum"):
                add("tried", u)
        for x in (d.get("usernames") or [])[:20] if t == "auth.bruteforce" else []:
            if isinstance(x, str):
                add("tried", x[:80])
        if t == "kerberos.enum" and isinstance(d.get("last"), str):
            add("tried", d["last"][:80])
        if t == "rdp.connect" and d.get("cookie_user"):
            add("client", f"RDP cookie mstshash={str(d['cookie_user'])[:40]}")
        if ev["type"] in ("ssh.client",):
            add("client", d.get("client_version"))
        if ev["type"] in ("http.request", "http.scanner", "http.notfound") and d.get("ua"):
            add("client", d["ua"][:80])
        if row:
            self.db.execute("UPDATE hosts SET last_ts=?, max_level=MAX(max_level, ?), names=? WHERE ip=?",
                            (max(ts, row["last_ts"]), lvl, json.dumps(names), src))
        else:
            self.db.execute("INSERT INTO hosts(ip, first_ts, last_ts, max_level, internal, names) VALUES(?,?,?,?,?,?)",
                            (src, ts, ts, lvl, 1 if self.is_internal(src) else 0, json.dumps(names)))
            if self.is_internal(src):
                self._rdns(src)   # never reverse-resolve public attacker IPs: their DNS server would see us

    def _rdns(self, ip):
        if ip in self._rdns_q:
            return
        self._rdns_q.add(ip)

        def work():
            socket.setdefaulttimeout(2)
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = None
            if name:
                with self.lock:
                    self.db.execute("UPDATE hosts SET rdns=? WHERE ip=?", (name, ip))
        threading.Thread(target=work, daemon=True).start()

    def host_label(self, ip):
        row = self.db.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
        if not row:
            return ip
        n = json.loads(row["names"] or "{}")
        parts = [ip]
        if n.get("workstation"):
            parts.append(n["workstation"][-1])
        elif row["rdns"]:
            parts.append(row["rdns"].split(".")[0])
        if not row["internal"]:
            g = self.geo.lookup(ip)
            if g and g.get("cc"):
                parts.append(f"[{g['cc']}{' ' + g['org'][:24] if g.get('org') else ''}]")
        who = (n.get("logon") or [None])[0]   # proven accounts only — never a name that was merely tried
        if who:
            parts.append(f"({who})")
        return " ".join(parts)

    # ------------------------------------------------------------------ queries
    def _since(self, hours):
        return iso(datetime.now(timezone.utc) - timedelta(hours=hours))

    def summary(self, hours=24):
        s = self._since(hours)
        q = lambda sql, *a: self.db.execute(sql, a).fetchone()[0]
        lv = {r[0]: r[1] for r in self.db.execute(
            "SELECT level, COUNT(*) FROM incidents WHERE last_ts>=? GROUP BY level", (s,))}
        sensors = self.sensors()
        used = self.tokens_used(s)
        return {
            "hours": hours,
            "real_incidents": sum(v for k, v in lv.items() if k >= 3),
            "critical": sum(v for k, v in lv.items() if k >= 4),
            "honeytokens": len(used),              # DISTINCT baits really used (L5) in the window, not incidents
            "honeytokens_used": sorted(used),
            "honeytoken_incidents": lv.get(5, 0),
            "touches": sum(v for k, v in lv.items() if k < 3),
            "attackers": q("SELECT COUNT(DISTINCT src_ip) FROM events WHERE ts>=? AND level>=3 AND allowlisted=0", s),
            "events": q("SELECT COUNT(*) FROM events WHERE ts>=?", s),
            "sensors_total": len(sensors), "sensors_online": sum(1 for x in sensors if x["online"]),
            "sensors_offline": [{"name": x["name"], "last_seen": x.get("last_seen"), "remote": x.get("remote")}
                                for x in sensors if not x["online"] and x.get("last_seen")],
            "by_level": {LEVEL_NAMES[k]: v for k, v in sorted(lv.items())},
        }

    def sensors(self):
        """Active decoys. Revoked ones are left out: they must not count as 'offline', keep the
        tamper banner on, or re-alert after a manager restart."""
        out = []
        now = datetime.now(timezone.utc)
        try:
            revoked = {r[0] for r in self.db.execute("SELECT name FROM fleet WHERE revoked=1")}
        except sqlite3.Error:
            revoked = set()
        for r in self.db.execute("SELECT * FROM sensors ORDER BY name"):
            d = dict(r)
            if d["name"] in revoked:
                continue
            d["services"] = json.loads(d["services"] or "[]")
            try:
                h = json.loads(d.get("health") or "{}")
            except (TypeError, ValueError):
                h = {}
            d["health"] = h if isinstance(h, dict) else {}
            # per-service health (F-02): "ok" / "down" (self-check found its listener dead) for every service
            d["service_health"] = [{"service": x, "status": "down" if not (d["health"].get(x) or {}).get("ok", True)
                                    else "ok", **({k: d["health"][x].get(k) for k in ("down", "since", "reason")}
                                                  if isinstance(d["health"].get(x), dict) else {})}
                                   for x in d["services"]]
            d["services_down"] = sorted(k for k, v in d["health"].items() if isinstance(v, dict) and not v.get("ok", True))
            d["online"] = bool(d["last_seen"]) and (now - parse_ts(d["last_seen"])).total_seconds() < 120
            out.append(d)
        return out

    def incidents(self, hours=24 * 7, min_level=1, status=None, limit=300):
        sql = "SELECT * FROM incidents WHERE last_ts>=? AND level>=?"
        a = [self._since(hours), min_level]
        if status:
            sql += " AND status=?"
            a.append(status)
        sql += " ORDER BY level DESC, last_ts DESC LIMIT ?"
        a.append(limit)
        res = []
        for r in self.db.execute(sql, a):
            res.append(self._inc_row(r))
        return res

    def _inc_row(self, r):
        d = dict(r)
        d["sensors"] = json.loads(d["sensors"] or "[]")
        if d.get("subject", "") and str(d["subject"]).startswith("sensor:"):
            d["kind"], d["host"], d["internal"] = "sensor", sensor_subject_label(d["subject"][7:]), True
        else:
            d["kind"], d["host"], d["internal"] = "attack", self.host_label(d["src_ip"]), self.is_internal(d["src_ip"])
        return d

    def incident(self, iid):
        r = self.db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        if not r:
            return None
        d = self._inc_row(r)
        d["events"] = self.events(incident=iid, limit=2000, asc=True)
        return d

    def set_status(self, iid, status, note=None):
        with self.lock:
            self.db.execute("UPDATE incidents SET status=?, note=COALESCE(?, note) WHERE id=?", (status, note, iid))

    def events(self, incident=None, src=None, hours=24, min_level=0, limit=500, asc=False, before_id=None):
        # decoy lifecycle noise stays out; offline/online (tamper watchdog) and gap notes are shown, keyed to their incident
        sql, a = "SELECT * FROM events WHERE (type NOT LIKE 'sensor.%' OR type IN ('sensor.offline','sensor.online','sensor.gap'))", []
        if incident is not None:
            sql += " AND incident_id=?"; a.append(incident)
        else:
            sql += " AND ts>=?"; a.append(self._since(hours))
        if src:
            sql += " AND src_ip=?"; a.append(src)
        if min_level:
            sql += " AND level>=?"; a.append(min_level)
        if before_id:
            sql += " AND id<?"; a.append(before_id)
        sql += f" ORDER BY id {'ASC' if asc else 'DESC'} LIMIT ?"; a.append(limit)
        res = []
        for r in self.db.execute(sql, a):
            d = dict(r)
            d["data"] = json.loads(d["data"] or "{}")
            if d["type"] in ("sensor.offline", "sensor.online", "sensor.gap"):
                d["desc"] = str(d["data"].get("summary") or describe(d))
                d["source"] = sensor_subject_label(d["sensor"])
            else:
                d["desc"] = describe(d)
            res.append(d)
        return res

    def hosts(self, hours=24 * 7):
        res = []
        for r in self.db.execute("SELECT * FROM hosts WHERE last_ts>=? ORDER BY max_level DESC, last_ts DESC", (self._since(hours),)):
            d = dict(r)
            d["names"] = json.loads(d["names"] or "{}")
            d["label"] = self.host_label(d["ip"])
            d["allowlisted"] = self._allowed(d["ip"])
            res.append(d)
        return res

    def host(self, ip):
        r = self.db.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["names"] = json.loads(d["names"] or "{}")
        d["label"] = self.host_label(ip)
        d["events"] = self.events(src=ip, hours=24 * 30, limit=1000, asc=True)
        d["path"] = self.attack_path(ip)
        d["geo"] = None if d["internal"] else self.geo.lookup(ip)
        return d

    def attack_path(self, ip, hours=24 * 30):
        """Ordered list of (sensor, first_ts, max_level, services) = the path this host walked."""
        rows = self.db.execute(
            "SELECT sensor, MIN(ts) first, MAX(level) lvl, GROUP_CONCAT(DISTINCT proto) protos FROM events "
            "WHERE src_ip=? AND ts>=? AND sensor IS NOT NULL GROUP BY sensor ORDER BY first", (ip, self._since(hours))).fetchall()
        return [dict(r) for r in rows]

    def graph(self, hours=24, min_level=1, scope="internal"):
        """Nodes: subnets, hosts, sensors (+ Internet cluster). Edges: host→sensor (max level, count, protos)."""
        s = self._since(hours)
        nodes, edges = [], []
        for x in self.sensors():
            nodes.append({"id": "s:" + x["name"], "kind": "sensor", "label": x["name"], "ip": x["ip"], "role": x["role"],
                          "title": x.get("title") or x["role"], "online": x["online"]})
        rows = self.db.execute(
            "SELECT src_ip, sensor, MAX(level) lvl, COUNT(*) n, GROUP_CONCAT(DISTINCT proto) protos, MIN(ts) first, MAX(ts) last "
            "FROM events WHERE ts>=? AND src_ip IS NOT NULL AND sensor IS NOT NULL AND allowlisted=0 "
            "GROUP BY src_ip, sensor HAVING lvl>=?", (s, min_level)).fetchall()
        hosts, subnets = {}, {}
        known = {n["id"] for n in nodes}
        if scope == "internal":
            rows = [r for r in rows if self.is_internal(r["src_ip"])]
        for r in rows:
            if "s:" + r["sensor"] not in known:
                known.add("s:" + r["sensor"])
                nodes.append({"id": "s:" + r["sensor"], "kind": "canary" if r["sensor"] == "CANARY" else "sensor",
                              "label": "Bait docs" if r["sensor"] == "CANARY" else r["sensor"], "role": "canary",
                              "title": "Canary beacons (opened bait documents)", "online": True})
            ip = r["src_ip"]
            if ip not in hosts:
                internal = self.is_internal(ip)
                net = str(ipaddress.ip_network(ip + "/24", strict=False)) if internal else "Internet"
                hosts[ip] = {"id": "h:" + ip, "kind": "host", "ip": ip, "label": self.host_label(ip), "level": 0,
                             "internal": internal, "subnet": net}
                subnets.setdefault(net, 0)
                subnets[net] += 1
            hosts[ip]["level"] = max(hosts[ip]["level"], r["lvl"])
            edges.append({"from": "h:" + ip, "to": "s:" + r["sensor"], "level": r["lvl"], "count": r["n"],
                          "protos": r["protos"], "first": r["first"], "last": r["last"]})
        for net, n in subnets.items():
            nodes.append({"id": "n:" + net, "kind": "subnet", "label": net, "hosts": n})
        for h in hosts.values():
            nodes.append(h)
            edges.append({"from": "n:" + h["subnet"], "to": h["id"], "kind": "member"})
        return {"nodes": nodes, "edges": edges, "hours": hours, "now": iso(datetime.now(timezone.utc))}

    def worldmap(self, hours=24, min_level=1):
        """Public (non-internal) sources with GeoIP, for the T-Pot-style world attack map."""
        s = self._since(hours)
        rows = self.db.execute(
            "SELECT src_ip, MAX(level) lvl, COUNT(*) n, MIN(ts) first, MAX(ts) last, GROUP_CONCAT(DISTINCT sensor) sensors, "
            "GROUP_CONCAT(DISTINCT proto) protos FROM events WHERE ts>=? AND src_ip IS NOT NULL AND allowlisted=0 "
            "GROUP BY src_ip HAVING lvl>=? ORDER BY last DESC LIMIT 5000", (s, min_level)).fetchall()
        points, countries, orgs, nogeo = [], {}, {}, 0
        for r in rows:
            ip = r["src_ip"]
            if self.is_internal(ip):
                continue
            g = self.geo.lookup(ip) or {}
            p = {"ip": ip, "level": r["lvl"], "count": r["n"], "first": r["first"], "last": r["last"],
                 "sensors": [x for x in (r["sensors"] or "").split(",") if x], "protos": r["protos"], **g}
            if not g.get("cc"):
                nogeo += 1
            points.append(p)
            k = g.get("cc") or "??"
            c = countries.setdefault(k, {"cc": k, "country": g.get("country") or "Unknown", "ips": 0, "events": 0, "level": 0, "last": ""})
            c["ips"] += 1; c["events"] += r["n"]; c["level"] = max(c["level"], r["lvl"]); c["last"] = max(c["last"], r["last"])
            if g.get("org"):
                o = orgs.setdefault(g["org"], {"org": g["org"], "asn": g.get("asn"), "ips": 0, "events": 0})
                o["ips"] += 1; o["events"] += r["n"]
        feed = []
        for e in self.db.execute(
                "SELECT * FROM events WHERE ts>=? AND src_ip IS NOT NULL AND level>=2 AND allowlisted=0 ORDER BY id DESC LIMIT 400", (s,)):
            if self.is_internal(e["src_ip"]):
                continue
            d = dict(e); d["data"] = json.loads(d["data"] or "{}"); d["desc"] = describe(d)
            g = self.geo.lookup(d["src_ip"]) or {}
            d["cc"], d["country"] = g.get("cc"), g.get("country")
            feed.append(d)
            if len(feed) >= 40:
                break
        site = self.site_place()
        return {"hours": hours, "now": iso(datetime.now(timezone.utc)), "points": points, "nogeo": nogeo, "geo_sources": self.geo.sources,
                "notice": self._worldmap_notice(points, s),
                "countries": sorted(countries.values(), key=lambda c: -c["events"])[:15],
                "orgs": sorted(orgs.values(), key=lambda o: -o["events"])[:10], "feed": feed,
                "site": site, "sensors": self.sensor_places(site)}

    def site_place(self):
        """Where the protected network is: `rpotctl.py site` if set, else the GeoIP of the manager's public_ip,
        else unknown (lat/lon None → the map says 'site not set' instead of pinning a wrong country)."""
        site = self.cfg.get("site") or {}
        out = {"name": site.get("name") or self.cfg.get("company", {}).get("name", "ReD-Pot"), "lat": None, "lon": None, "from": None}
        try:
            lat, lon = float(site.get("lat")), float(site.get("lon"))
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                out.update(lat=lat, lon=lon, **{"from": "site"})
                return out
        except (TypeError, ValueError):
            pass
        pub = (self.cfg.get("console") or {}).get("public_ip")
        g = self.geo.locate(pub) if pub else None
        if g:
            out.update(lat=g["lat"], lon=g["lon"], cc=g.get("cc"), approx=g.get("approx"), **{"from": "manager"})
        return out

    def sensor_places(self, site=None):
        """Each decoy at the GeoIP location of its OWN public address (city lat/lon, else the country centroid):
        the config IP / explicit public_ip of a local decoy (or the manager's public_ip when the decoy shares the
        manager's address), the enrolled / reported IP of a remote sensor, or the address it enrolled from.
        Decoys on private addresses sit at the site (see site_place); unknown → lat/lon None ('not placed')."""
        site = site or self.site_place()
        c = self.cfg.get("console") or {}
        pub, local = c.get("public_ip"), self.fleet.local_sensors()
        try:
            fl = {r["name"]: dict(r) for r in self.db.execute("SELECT name, ip, info FROM fleet")}
        except sqlite3.Error:
            fl = {}
        out = []
        for s in self.sensors():
            name, cand = s["name"], []
            if name in local:
                ls = local[name]
                cand += [ls.get("public_ip"), ls.get("ip"), s.get("ip")]
                if pub and ls.get("ip") and ls.get("ip") in (c.get("mgmt_ip"), pub):
                    cand.append(pub)               # decoy on the manager's own address (VPS): same public IP
            else:
                f = fl.get(name) or {}
                try:
                    info = json.loads(f.get("info") or "{}")
                except ValueError:
                    info = {}
                cand += [f.get("ip"), s.get("ip"), info.get("source_ip") if isinstance(info, dict) else None]
            p = {"name": name, "role": s.get("role"), "ip": s.get("ip"), "online": s.get("online"),
                 "lat": None, "lon": None, "from": None}
            for ip in dict.fromkeys(x for x in cand if isinstance(x, str) and x):
                g = self.geo.locate(ip)
                if g:
                    p.update(lat=g["lat"], lon=g["lon"], cc=g.get("cc"), country=g.get("country"), city=g.get("city"),
                             approx=g.get("approx"), geo_ip=ip, **{"from": "geoip"})
                    break
            else:
                if site.get("lat") is not None:
                    p.update(lat=site["lat"], lon=site["lon"], **{"from": site["from"]})
            out.append(p)
        return out

    def _worldmap_notice(self, points, since):
        """Why the world map is empty (or has no locations) — shown as a notice on the map / wall.
        The map only shows attackers with PUBLIC addresses; internal attacks live on the Overview map."""
        reasons = []
        if not self.geo.sources:
            reasons.append("nogeo")
        if not points:
            exposed = [ip for ip in self.fleet.sensor_ips() if ip and not self.is_internal(ip)]
            exposed += [s["public_ip"] for s in self.cfg.get("sensors", []) if s.get("public_ip")]   # NAT'd / VPS decoys
            if not exposed and not self.cfg.get("console", {}).get("public_ip"):
                reasons.append("internal_only")
            else:
                reasons.append("quiet")
        if not reasons:
            return None
        internal = self.db.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE ts>=? AND src_ip IS NOT NULL "
                                   "AND level>=2 AND allowlisted=0", (since,)).fetchone()[0]
        return {"reasons": reasons, "internal_sources": internal}

    def tokens_used(self, since):
        """Token ids of baits really used (L5) since `since` (allowlisted sources excluded)."""
        out = set()
        for r in self.db.execute("SELECT data FROM events WHERE ts>=? AND level>=5 AND allowlisted=0 "
                                 "AND type IN ('honeytoken.used','canary.hit')", (since,)):
            try:
                k = (json.loads(r["data"] or "{}") or {}).get("token")
            except ValueError:
                k = None
            if isinstance(k, str) and k:
                out.add(k)
        return out

    def tokens(self):
        """Every bait with its use: hits = real uses (L5), attempts = all events naming it (e.g. name-only)."""
        hits = {}
        for r in self.db.execute("SELECT data, ts, src_ip, level FROM events WHERE type IN ('honeytoken.used','canary.hit')"):
            try:
                d = json.loads(r["data"] or "{}")
            except ValueError:
                continue
            k = d.get("token")
            if not isinstance(k, str) or not k:
                continue
            h = hits.setdefault(k, {"hits": 0, "attempts": 0, "last": None, "sources": []})
            h["attempts"] += 1
            if (r["level"] or 0) >= 5:
                h["hits"] += 1
                h["last"] = max(h["last"] or "", r["ts"])
                if r["src_ip"] not in h["sources"]:
                    h["sources"].append(r["src_ip"])
        out = []
        for tid, t in self.fleet.all_tokens().items():
            h = hits.get(tid) or {"hits": 0, "attempts": 0, "last": None, "sources": []}
            out.append({"id": tid, "kind": t["kind"], "username": t.get("username"), "planted": t["planted"],
                        "desc": t["desc"], "valid_on": t.get("valid_on", []), "count": h["hits"], **h})
        return out
