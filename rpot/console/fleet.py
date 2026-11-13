"""Sensor fleet management on the manager: enrollment, per-sensor keys, config bundles.

Trust model
-----------
* The manager has a persona-styled TLS certificate (private "<Company> Issuing CA"); sensors pin its SHA-256.
* A sensor proves who it is with a per-sensor secret: `Authorization: Bearer NAME:SECRET`.
  The manager stores only SHA-256(secret). Revoking a sensor = one flag.
* Local sensors (same host) get their secret from `rpotctl init` (sensor.json mounted into
  that container only). Remote sensors get it by redeeming a one-time enrollment token
  (24 h default) created in the console or with `rpotctl`/`manage sensor-add`.
* Sensors never see rpot.json (admin token, wall token, other secrets) — only their own
  sensor.json: identity, persona, honeytoken index, manager URL + fingerprint + key.
"""
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import os
import secrets
import shutil
import sqlite3
import tarfile
import tempfile
import threading
import time

from rpot.common.config import load_roles, sensor_token_view, zone_view
from rpot.common.edition import MAX_DECOYS, LimitError, limit_message
from rpot.common.events import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS fleet(
  name TEXT PRIMARY KEY, role TEXT, ip TEXT, key_hash TEXT, remote INT DEFAULT 1,
  created TEXT, enrolled TEXT, revoked INT DEFAULT 0, info TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS enrollments(
  token_hash TEXT PRIMARY KEY, name TEXT, role TEXT, ip TEXT, created TEXT, expires REAL, used TEXT);
CREATE TABLE IF NOT EXISTS extra_tokens(id TEXT PRIMARY KEY, data TEXT, sensor TEXT);
CREATE TABLE IF NOT EXISTS bundles(name TEXT PRIMARY KEY, baits BLOB);
"""


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def slot_counts(conn, local_names, now, exclude=None):
    """Community Edition decoy slots (D-6): used = local + remote + pending.
    local   = every decoy in rpot.json (a locally revoked decoy still runs, so it still counts);
    remote  = fleet rows remote=1 AND revoked=0 (revoking a remote frees its slot; there is no un-revoke);
    pending = unused, unexpired enrollments (by name), except `exclude` (the name being re-issued).
    `used` may exceed `max` after tampering or a cross-process race; callers must handle that."""
    local = len(list(local_names))
    remote = conn.execute("SELECT COUNT(*) FROM fleet WHERE remote=1 AND revoked=0").fetchone()[0]
    pending = conn.execute("SELECT COUNT(DISTINCT name) FROM enrollments WHERE used IS NULL AND expires>? AND name<>?",
                           (now, (exclude or "").upper())).fetchone()[0]
    return {"max": MAX_DECOYS, "used": local + remote + pending, "local": local, "remote": remote, "pending": pending}


def limit_error(used):
    e = LimitError(limit_message(used))
    e.used = used
    return e


def check_ip(ip):
    """Admin-chosen decoy IP of an enrollment: None/'' or a literal IPv4/IPv6 address (it flows into bait
    texts and the DNS zone, so nothing else is accepted). Returns the normalised text or None."""
    if ip is None or ip == "":
        return None
    if not isinstance(ip, str) or len(ip) > 64 or "%" in ip:      # no IPv6 scope ids ("fe80::1%eth0")
        raise ValueError("ip: not a valid IP address")
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise ValueError("ip: not a valid IP address") from None


class Fleet:
    def __init__(self, cfg, db, lock):
        self.cfg, self.db, self.lock = cfg, db, lock
        self.db.executescript(SCHEMA)

    # ------------------------------------------------------------- identity / auth
    def local_sensors(self):
        return {s["name"].upper(): s for s in self.cfg.get("sensors", [])}

    def authenticate(self, bearer):
        """'NAME:SECRET' → sensor name, or None."""
        name, _, secret = (bearer or "")[:300].partition(":")
        name = name.upper()
        if not name or not secret:
            return None
        h = hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()
        s = self.local_sensors().get(name)
        if s and s.get("key_sha256") and hmac.compare_digest(s["key_sha256"], h):
            row = self.db.execute("SELECT revoked FROM fleet WHERE name=?", (name,)).fetchone()
            return None if row and row["revoked"] else name
        row = self.db.execute("SELECT key_hash, revoked FROM fleet WHERE name=?", (name,)).fetchone()
        if row and not row["revoked"] and row["key_hash"] and hmac.compare_digest(row["key_hash"], h):
            return name
        return None

    def local_names(self):
        """Local decoys in rpot.json order (upper-case, de-duplicated)."""
        return list(dict.fromkeys(str(s["name"]).upper() for s in self.cfg.get("sensors", [])))

    def slots(self):
        with self.lock:
            return slot_counts(self.db, self.local_names(), time.time())

    def allowed_names(self):
        """Decoys that may talk to the sensor API (D-6 layer 7): local decoys in rpot.json order, then
        non-revoked fleet rows ordered by (enrolled IS NULL, enrolled, name); the first MAX_DECOYS win.
        Deterministic for any race or tampering outcome (a 4th decoy is always the newest / un-enrolled one)."""
        with self.lock:
            names = self.local_names()
            seen = set(names)
            for r in self.db.execute("SELECT name FROM fleet WHERE revoked=0 ORDER BY enrolled IS NULL, enrolled, name"):
                if r["name"] not in seen:
                    seen.add(r["name"])
                    names.append(r["name"])
        return names[:MAX_DECOYS]

    def all_names(self):
        names = set(self.local_sensors())
        names |= {r["name"] for r in self.db.execute("SELECT name FROM fleet")}
        return names

    def sensor_ips(self):
        ips = {s.get("ip") for s in self.cfg.get("sensors", [])}
        ips |= {r["ip"] for r in self.db.execute("SELECT ip FROM fleet WHERE ip IS NOT NULL")}
        return {i for i in ips if i}

    # ------------------------------------------------------------- tokens / config version
    def all_tokens(self):
        """rpot.json tokens + tokens planted on remote sensors. A row {"extends": id, "valid_on": [...]} only
        widens an existing token (a remote decoy enrolled after the bait was planted accepts it too)."""
        t, ext = dict(self.cfg.get("tokens", {})), []
        for r in self.db.execute("SELECT id, data FROM extra_tokens"):
            d = json.loads(r["data"])
            if "extends" in d:
                ext.append(d)
            else:
                t[r["id"]] = d
        for d in ext:
            b = t.get(d["extends"])
            if b:
                t[d["extends"]] = dict(b, valid_on=list(dict.fromkeys(list(b.get("valid_on", [])) + list(d.get("valid_on", [])))))
        return t

    def version(self):
        blob = json.dumps({"t": self.all_tokens(), "c": self.cfg.get("company", {}).get("seed"),
                           "z": zone_view(self.listing())}, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def role_of(self, name):
        s = self.local_sensors().get(name.upper())
        if s:
            return s["role"]
        r = self.db.execute("SELECT role FROM fleet WHERE name=?", (name.upper(),)).fetchone()
        return r["role"] if r else None

    def sensor_config(self, name, role=None):
        """What a sensor needs at runtime: persona + HASHED honeytoken view (no plaintext baits,
        no bait locations, no manager secrets)."""
        co = dict(self.cfg.get("company", {}))
        role = role or self.role_of(name)
        return {"company": co, "tokens": sensor_token_view(self.all_tokens(), co.get("token_salt", ""), role),
                "version": self.version(), **zone_view(self.listing())}

    # ------------------------------------------------------------- enrollment
    def create_enrollment(self, name, role, ip=None, ttl_hours=24):
        from rpot.baits import valid_hostname
        name = (name or "").upper()
        if not valid_hostname(name):
            raise ValueError("host name: 1-15 letters/digits/hyphen")
        if role not in load_roles():
            raise ValueError(f"unknown role {role!r}")
        ip = check_ip(ip)
        token = secrets.token_urlsafe(24)
        with self.lock:      # name check + slot count + insert are one step (no TOCTOU between parallel requests)
            if name in self.all_names():
                raise ValueError(f"sensor {name} already exists")
            c = slot_counts(self.db, self.local_names(), time.time(), exclude=name)
            if c["used"] >= MAX_DECOYS:
                raise limit_error(c["used"])
            self.db.execute("DELETE FROM enrollments WHERE name=? AND used IS NULL", (name,))
            self.db.execute("INSERT INTO enrollments(token_hash, name, role, ip, created, expires) VALUES(?,?,?,?,?,?)",
                            (sha(token), name, role, ip, now_iso(), time.time() + ttl_hours * 3600))
        return token

    def cancel_enrollment(self, name):
        """Delete the UNUSED join tokens of `name` (frees the pending slot now). True if one was deleted."""
        name = str(name or "").upper()
        with self.lock:
            return self.db.execute("DELETE FROM enrollments WHERE name=? AND used IS NULL", (name,)).rowcount > 0

    def pending(self):
        return [dict(r) for r in self.db.execute(
            "SELECT name, role, ip, created, expires FROM enrollments WHERE used IS NULL AND expires>? ORDER BY created DESC",
            (time.time(),))]

    def redeem(self, token, info):
        """One-time token → (sensor_json dict, baits tar.gz bytes); None for an invalid/used/expired token.
        Raises LimitError (token left unused) when local + enrolled remote decoys already fill the cap."""
        with self.lock:
            row = self.db.execute("SELECT * FROM enrollments WHERE token_hash=?",
                                  (hashlib.sha256(str(token or "").encode("utf-8", "surrogatepass")).hexdigest(),)).fetchone()
            if not row or row["used"] or row["expires"] < time.time():
                return None
            name, role = row["name"], row["role"]
            ip = row["ip"]          # only the admin-chosen IP; never trust a client-supplied one
            c = slot_counts(self.db, self.local_names(), time.time())
            if c["local"] + c["remote"] >= MAX_DECOYS:
                raise limit_error(c["used"])
            secret = secrets.token_urlsafe(32)
            tokens, baits = self._baits_for(name, role, ip)
            self.db.execute("SAVEPOINT redeem")
            try:
                self.db.execute("UPDATE enrollments SET used=? WHERE token_hash=?", (now_iso(), row["token_hash"]))
                for tid, t in tokens.items():
                    self.db.execute("INSERT OR REPLACE INTO extra_tokens(id, data, sensor) VALUES(?,?,?)", (tid, json.dumps(t), name))
                self.db.execute("INSERT OR REPLACE INTO fleet(name, role, ip, key_hash, remote, created, enrolled, info) VALUES(?,?,?,?,1,?,?,?)",
                                (name, role, ip, sha(secret), row["created"], now_iso(), json.dumps(info)[:2000]))
                self.db.execute("INSERT OR REPLACE INTO bundles(name, baits) VALUES(?,?)", (name, baits))
            except sqlite3.IntegrityError as e:      # the ce_limit trigger (DB layer) refused: token stays unused
                self.db.execute("ROLLBACK TO redeem")
                self.db.execute("RELEASE redeem")
                if "decoy limit" in str(e):
                    raise limit_error(slot_counts(self.db, self.local_names(), time.time())["used"]) from None
                raise
            except BaseException:
                self.db.execute("ROLLBACK TO redeem")
                self.db.execute("RELEASE redeem")
                raise
            self.db.execute("RELEASE redeem")
        return {"sensor": {"name": name, "role": role, "ip": ip}, "key": f"{name}:{secret}",
                **self.sensor_config(name, role)}, baits

    def _baits_for(self, name, role, ip):
        """Baits for ONE new sensor from the same breadcrumb planner as `rpotctl baits` (rpot.baits.plan_baits),
        over every deployed decoy (local + enrolled remote + this one). Returns (tokens to store, bait tar.gz):
        the tokens planted ON the new sensor (they name existing decoys and work there, because every sensor
        validates against the synced honeytoken index) + "extends" rows that widen valid_on of existing tokens
        the new decoy also accepts (e.g. domain accounts when a DC enrolls). Existing baits are never changed."""
        from rpot import baits as B
        tmp = tempfile.mkdtemp(prefix="rpot-enroll-")
        try:
            rev = {r["name"] for r in self.db.execute("SELECT name FROM fleet WHERE revoked=1")}
            deployed = [s for s in self.cfg.get("sensors", []) if s["name"].upper() not in rev]
            deployed += [{"name": r["name"], "role": r["role"], "ip": r["ip"]}
                         for r in self.db.execute("SELECT name, role, ip FROM fleet WHERE revoked=0 AND remote=1")]
            deployed.append({"name": name, "role": role, "ip": ip})
            prior = self.all_tokens()
            toks = B.plan_baits(self.cfg, tmp, deployed, holders=[name], prior=prior)
            mine = {k: v for k, v in toks.items() if v.get("holder") == name}
            for k, v in toks.items():
                more = [x for x in v.get("valid_on", []) if k in prior and k not in mine and x not in prior[k].get("valid_on", [])]
                if more:
                    mine[f"{k}+{name}"] = {"extends": k, "valid_on": more}
            buf = io.BytesIO()
            src = os.path.join(tmp, name)
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                if os.path.isdir(src):
                    tar.add(src, arcname=name)
            return mine, buf.getvalue()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def note_ip(self, name, ip):
        """A remote sensor reports the decoy IP chosen during ITS install (may differ from, or be missing
        in, the enrollment) → keep the fleet / DNS-zone view accurate."""
        try:
            ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return
        with self.lock:
            self.db.execute("UPDATE fleet SET ip=? WHERE name=? AND remote=1 AND revoked=0 AND (ip IS NULL OR ip<>?)",
                            (ip, name.upper(), ip))

    def revoke(self, name):
        name = name.upper()
        with self.lock:
            if self.db.execute("SELECT 1 FROM fleet WHERE name=?", (name,)).fetchone():
                self.db.execute("UPDATE fleet SET revoked=1 WHERE name=?", (name,))
            elif name in self.local_sensors():
                self.db.execute("INSERT INTO fleet(name, role, ip, remote, created, revoked) VALUES(?,?,?,0,?,1)",
                                (name, self.local_sensors()[name]["role"], self.local_sensors()[name].get("ip"), now_iso()))
            else:
                return False
        return True

    def delete(self, name):
        """Remove a REVOKED remote sensor from the list (its events/incidents stay). Local decoys are part of
        this manager's install — remove them with the installer instead."""
        name = name.upper()
        with self.lock:
            r = self.db.execute("SELECT remote, revoked FROM fleet WHERE name=?", (name,)).fetchone()
            if not r or not r["revoked"] or not r["remote"]:
                return False
            self.db.execute("DELETE FROM fleet WHERE name=?", (name,))
            self.db.execute("DELETE FROM enrollments WHERE name=?", (name,))
            self.db.execute("DELETE FROM extra_tokens WHERE sensor=?", (name,))
            self.db.execute("DELETE FROM bundles WHERE name=?", (name,))
            try:
                self.db.execute("DELETE FROM sensors WHERE name=?", (name,))
            except Exception:
                pass
        return True

    def listing(self):
        rows = {r["name"]: dict(r) for r in self.db.execute("SELECT name, role, ip, remote, enrolled, revoked FROM fleet")}
        out = []
        for n, s in self.local_sensors().items():
            r = rows.pop(n, {})
            out.append({"name": n, "role": s["role"], "ip": s.get("ip"), "remote": False, "revoked": bool(r.get("revoked"))})
        for r in rows.values():
            out.append({"name": r["name"], "role": r["role"], "ip": r["ip"], "remote": bool(r["remote"]),
                        "enrolled": r["enrolled"], "revoked": bool(r["revoked"])})
        return out


def safe_extract(tar_bytes, dest):
    """Extract a bait bundle refusing absolute paths, '..', links and device files."""
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        root = os.path.realpath(dest)
        for m in tar.getmembers():
            p = os.path.realpath(os.path.join(dest, m.name))
            if not (p == root or p.startswith(root + os.sep)) or m.issym() or m.islnk() or m.isdev():
                raise ValueError(f"unsafe path in bundle: {m.name}")
        tar.extractall(dest)
