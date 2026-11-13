"""JSON Export of incidents + alert records by UTC date range (D-4).

Shared by the console (`GET /api/export`) and `rpotctl.py export`. The export reads from its own
read-only SQLite connection inside one transaction (a consistent WAL snapshot), so ingest keeps
writing while an export streams.

Document shape (compact, ASCII-only JSON):
  {"meta":{product, edition, version, generated, range, counts}, "incidents":[...], "alerts":[...], "complete":true}
A stream that was cut off (byte cap or wall-time cap) has no "complete" key and is not valid JSON;
consumers must treat that as a failed export. Data is never silently dropped.
"""
import json
import math
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from datetime import date, datetime, timedelta, timezone

from rpot import VERSION
from rpot.common.edition import EDITION
from rpot.console.scoring import LEVEL_NAMES

MAX_DAYS = 366
MAX_BYTES = 200 * 2 ** 20           # hard cap on one export document (bytes on the wire)
BATCH_BYTES = 4 * 2 ** 20           # largest chunk handed to the WSGI server
FETCH_ROWS = 500
WALL_SECONDS = 600                  # HTTP exports give up (without "complete") after 10 min
MIN_DATE = date(2000, 1, 1)
TAIL = ',"complete":true}'



class ExportGate:
    """One HTTP export at a time: a non-blocking lock with an owner token. release(token) is idempotent and
    only frees the gate for its own owner. A holder older than `stale` seconds (a response the server never
    closed) is taken over, so a leaked export can block others for at most WALL_SECONDS + STALE_GRACE."""

    def __init__(self):
        self._m = threading.Lock()
        self._owner = None
        self._since = 0.0

    def acquire(self, stale=None):
        with self._m:
            now = time.monotonic()
            if self._owner is not None and not (stale is not None and now - self._since > stale):
                return None
            self._owner, self._since = object(), now
            return self._owner

    def release(self, token):
        with self._m:
            if token is not None and self._owner is token:
                self._owner = None

    def busy(self):
        with self._m:
            return self._owner is not None


STALE_GRACE = 120
GATE = ExportGate()

_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)

# Size estimate (stats). Output is json.dumps(ensure_ascii=True): any stored byte becomes at most 6 output
# bytes ("\u0001"), so 6x the byte length is a strict upper bound for free text. Alert records are stored
# JSON: re-serialising keeps ASCII as is, and a UTF-8 character of n bytes becomes 6 (n=2,3) or 12 (n=4)
# bytes, i.e. at most n + 4*(n-1); summed: B + 4*(B - C) with B bytes and C characters.
INC_COLS = ("id", "src_ip", "subject", "first_ts", "last_ts", "level", "title", "status", "sensors", "count", "note")
AR_COLS = ("id", "ts", "incident_id", "level")
INC_ROW_OVERHEAD = 320              # keys, kind, level_name, nulls, separators
AR_ROW_OVERHEAD = 128
DOC_OVERHEAD = 2048                 # meta + envelope

_DUMP = {"ensure_ascii": True, "separators": (",", ":"), "allow_nan": False}


def _blen(col):
    return f"COALESCE(LENGTH(CAST({col} AS BLOB)), 0)"


def parse_dates(frm, to, today=None):
    """Validate the two YYYY-MM-DD parameters -> (date_from, date_to). Raises ValueError(msg)."""
    today = today or datetime.now(timezone.utc).date()
    out = []
    for name, v in (("from", frm), ("to", to)):
        if not isinstance(v, str) or not v:
            raise ValueError(f"'{name}' is required (YYYY-MM-DD)")
        if len(v) > 10 or not _DATE_RE.fullmatch(v):
            raise ValueError(f"'{name}' must be a date as YYYY-MM-DD")
        try:
            out.append(datetime.strptime(v, "%Y-%m-%d").date())
        except ValueError:
            raise ValueError(f"'{name}' is not a valid date") from None
    d1, d2 = out
    if d1 < MIN_DATE:
        raise ValueError(f"'from' must be {MIN_DATE.isoformat()} or later")
    if d2 > today + timedelta(days=1):
        raise ValueError("'to' is in the future")
    if d1 > d2:
        raise ValueError("'from' is after 'to'")
    if (d2 - d1).days > MAX_DAYS:
        raise ValueError(f"the range is longer than {MAX_DAYS} days; narrow the date range")
    return d1, d2


def day_range(d1, d2):
    """UTC days [d1 00:00Z, d2+1 00:00Z) as the engine's timestamp format (text comparison)."""
    return d1.isoformat() + "T00:00:00.000Z", (d2 + timedelta(days=1)).isoformat() + "T00:00:00.000Z"


def parse_range(frm, to, today=None):
    """-> (start_iso, end_iso); raises ValueError(msg) for a bad, reversed, too long or out-of-bounds range."""
    return day_range(*parse_dates(frm, to, today))


def filename(d1, d2):
    return f"redpot-export-{d1.isoformat()}_{d2.isoformat()}.json"


def ro_uri(db_path):
    """Read-only SQLite URI with the path percent-quoted (L12): '?', '#', '%' and spaces in the path are data,
    never URI syntax. Path.as_uri() applies urllib.parse quoting (safe='/') without this module importing
    urllib (the console has no network-client imports, see test_rc7_no_outbound)."""
    return Path(os.path.abspath(db_path)).as_uri() + "?mode=ro"


def open_snapshot(db_path):
    """Separate read-only connection with an open read transaction (one consistent snapshot)."""
    conn = sqlite3.connect(ro_uri(db_path), uri=True, isolation_level=None, check_same_thread=False, timeout=10)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()     # pins the snapshot now
    except BaseException:
        conn.close()
        raise
    return conn


def stats(conn, rng):
    """Row counts and an upper-bound size estimate of the export document for `rng` (start_iso, end_iso)."""
    start, end = rng
    inc_bytes = " + ".join(_blen(c) for c in INC_COLS)
    n_inc, b_inc = conn.execute(
        f"SELECT COUNT(*), COALESCE(SUM(6 * ({inc_bytes}) + {INC_ROW_OVERHEAD}), 0) FROM incidents "
        "WHERE first_ts < ? AND last_ts >= ?", (end, start)).fetchone()
    ar_bytes = " + ".join(_blen(c) for c in AR_COLS)
    rec = (f"CASE WHEN typeof(record) = 'text' THEN {_blen('record')} + 4 * ({_blen('record')} - LENGTH(record)) "
           f"ELSE 6 * {_blen('record')} END")
    n_ar, b_ar = conn.execute(
        f"SELECT COUNT(*), COALESCE(SUM(6 * ({ar_bytes}) + {rec} + {AR_ROW_OVERHEAD}), 0) FROM alert_records "
        "WHERE ts >= ? AND ts < ?", (start, end)).fetchone()
    return {"incidents": n_inc, "alerts": n_ar, "bytes": int(b_inc) + int(b_ar) + DOC_OVERHEAD}


def build_meta(d1, d2, st):
    start, end = day_range(d1, d2)
    return {"product": "ReD-Pot", "edition": EDITION, "version": VERSION,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "range": {"from": d1.isoformat(), "to": d2.isoformat(), "start": start, "end": end},
            "counts": {"incidents": st["incidents"], "alerts": st["alerts"]}}


def _val(v):
    """DB scalar -> JSON-safe value (tampered rows may hold blobs or non-finite floats)."""
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    if isinstance(v, float) and not math.isfinite(v):
        return None
    return v


def _reject_constant(name):
    raise ValueError(name)


def _parse(text, want=None):
    """Tolerant JSON parse: the parsed value, or the raw text when it is not JSON (or not of type `want`)."""
    if text is None:
        return None
    text = _val(text)
    if not isinstance(text, str):
        return text
    try:
        v = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return text
    return v if want is None or isinstance(v, want) else text


def _dump(obj, fallback):
    try:
        return json.dumps(obj, **_DUMP)
    except (ValueError, TypeError, RecursionError):        # inf from an overflowing number, deep nesting
        return json.dumps(fallback, **_DUMP)


def incident_row(r):
    subject = _val(r["subject"])
    sensors = _parse(r["sensors"], list)
    if sensors is None:
        sensors = []
    elif not isinstance(sensors, list):
        sensors = [sensors]
    level = _val(r["level"])
    d = {"id": _val(r["id"]),
         "kind": "sensor" if isinstance(subject, str) and subject.startswith("sensor:") else "attacker",
         "src_ip": _val(r["src_ip"]), "subject": subject, "first_ts": _val(r["first_ts"]), "last_ts": _val(r["last_ts"]),
         "level": level, "level_name": LEVEL_NAMES.get(level) if isinstance(level, int) else None,
         "title": _val(r["title"]), "status": _val(r["status"]), "sensors": sensors, "count": _val(r["count"]),
         "note": _val(r["note"])}
    return _dump(d, dict(d, sensors=[str(x) for x in sensors]))


def alert_row(r):
    raw = _val(r["record"])
    d = {"id": _val(r["id"]), "ts": _val(r["ts"]), "incident_id": _val(r["incident_id"]), "level": _val(r["level"]),
         "record": _parse(raw)}
    return _dump(d, dict(d, record=raw))


def _pieces(conn, rng, meta):
    start, end = rng
    yield '{"meta":' + json.dumps(meta, **_DUMP) + ',"incidents":['
    cur = conn.execute("SELECT * FROM incidents WHERE first_ts < ? AND last_ts >= ? ORDER BY first_ts, id", (end, start))
    sep = ""
    while True:
        rows = cur.fetchmany(FETCH_ROWS)
        if not rows:
            break
        for r in rows:
            yield sep + incident_row(r)
            sep = ","
    yield '],"alerts":['
    cur = conn.execute("SELECT id, ts, incident_id, level, record FROM alert_records WHERE ts >= ? AND ts < ? "
                       "ORDER BY ts, id", (start, end))
    sep = ""
    while True:
        rows = cur.fetchmany(FETCH_ROWS)
        if not rows:
            break
        for r in rows:
            yield sep + alert_row(r)
            sep = ","
    yield "]" + TAIL


def iter_json(conn, rng, meta, max_bytes=None, deadline=None, batch_bytes=None):
    """Stream the export document as ASCII str chunks of at most `batch_bytes` (default BATCH_BYTES).
    Never yields more than `max_bytes` (default MAX_BYTES) in total: when the next piece would cross the cap,
    or time.monotonic() passes `deadline`, the stream ends early WITHOUT the closing "complete":true."""
    cap = MAX_BYTES if max_bytes is None else max_bytes
    batch = max(1, BATCH_BYTES if batch_bytes is None else batch_bytes)
    sent = 0
    buf, blen = [], 0
    src = _pieces(conn, rng, meta)
    try:
        for p in src:
            if deadline is not None and time.monotonic() > deadline:
                break
            if sent + blen + len(p) > cap:
                break
            buf.append(p)
            blen += len(p)
            if blen >= batch:
                s = "".join(buf)
                buf = []
                i = 0
                while len(s) - i >= batch:
                    yield s[i:i + batch]
                    i += batch
                sent += i
                s = s[i:]
                if s:
                    buf.append(s)
                blen = len(s)
        if buf:
            yield "".join(buf)
    finally:
        src.close()
