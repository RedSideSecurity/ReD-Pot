"""ReD-Pot manager ("console").

Two HTTPS listeners share one Engine:
  * UI port     (default 8740): login, dashboard API, wall, canary beacons, fleet admin
  * sensor port (default 8741): enrollment, event ingest, config sync — sensors only
"""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Flask, Response, jsonify, request, send_from_directory, abort, make_response, redirect

from rpot import VERSION
from rpot.common.config import load_config
from rpot.common.edition import EDITION, MAX_DECOYS, LimitError, limit_message
from rpot.common.events import now_iso
from rpot.console import export as X
from rpot.console.engine import Engine, iso
from rpot.console.fleet import Fleet

HERE = os.path.dirname(os.path.abspath(__file__))
PIXEL = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")
COOKIE = "rpot_ui"          # admin session (12 h)
WALL_COOKIE = "rpot_wall"   # read-only big-screen session (console.wall_days, default 7) — separate from the admin login


_CLOCK = {"t": 0, "v": None}


def clock_synced():
    """Kernel NTP state via adjtimex(2), read-only (modes=0: no privilege needed; in a container the clock is
    the host's). True = synchronised, False = TIME_ERROR (unsynchronised), None = unknown. Cached 60 s."""
    if time.monotonic() - _CLOCK["t"] < 60 and _CLOCK["t"]:
        return _CLOCK["v"]
    v = None
    try:
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        buf = ctypes.create_string_buffer(512)            # struct timex (~208 B on 64-bit); modes (first int) = 0
        state = libc.adjtimex(buf)
        v = None if state < 0 else state != 5             # 5 = TIME_ERROR: clock not synchronised
    except (OSError, AttributeError, ValueError):
        pass
    _CLOCK.update(t=time.monotonic(), v=v)
    return v


def server_header(cfg):
    """Server header of the manager's UI + sensor API. Those ports may sit on a decoy's address (own-IP
    placement), so they answer like that host would: HTTP.sys on a Windows decoy, else nginx."""
    c = cfg.get("console") or {}
    mine = {c.get("mgmt_ip"), c.get("public_ip")} - {None, ""}
    win = any(s.get("ip") in mine and str(s.get("role", "")).startswith("windows") for s in cfg.get("sensors", []))
    return "Microsoft-HTTPAPI/2.0" if win else "nginx"


def create_app(cfg, db_path, geo_dir=None, log_dir=None):
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
    admin_token = cfg["console"]["admin_token"]
    secret = hashlib.sha256(("rpot-ui:" + admin_token).encode()).digest()
    # wall sessions: signed with the WALL token too → a new wall link (reset-token --wall) logs out every
    # screen; bound to the screen's IP → a copied cookie is useless elsewhere
    def wall_secret():
        return hashlib.sha256(("rpot-wall:" + admin_token + ":" + (cfg["console"].get("wall_token") or "")).encode()).digest()
    try:
        wall_days = max(1, min(90, int(cfg["console"].get("wall_days", 7))))
    except (TypeError, ValueError):
        wall_days = 7
    wall_allow = []
    for c in cfg["console"].get("wall_allow") or []:
        try:
            wall_allow.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            print(f"[ReD-Pot manager] console.wall_allow: ignoring invalid entry {c!r}", flush=True)

    server_hdr = server_header(cfg)

    eng = Engine(cfg, db_path, geo_dir=geo_dir, log_dir=log_dir)
    app.engine = eng
    n_local = len(cfg.get("sensors", []))
    if n_local > MAX_DECOYS:          # D-6 layer 8: only the first MAX_DECOYS may talk (sensor API, layer 7)
        print(f"[ReD-Pot manager] WARNING: rpot.json lists {n_local} local decoys; this edition allows "
              f"{MAX_DECOYS}. Decoys after the first {MAX_DECOYS} are refused by the sensor API. "
              + limit_message(n_local), flush=True)

    # ---------------------------------------------------------------- auth helpers
    def sign(exp, role="admin"):
        msg = f"{exp}.{role}"
        return f"{msg}.{hmac.new(secret, msg.encode(), 'sha256').hexdigest()}"

    def wall_sign(exp, ip):
        msg = f"{exp}.wall"
        return f"{msg}.{hmac.new(wall_secret(), (msg + '|' + ip).encode(), 'sha256').hexdigest()}"

    def wall_ip_ok(ip):
        if not wall_allow:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in wall_allow)

    def wall_cookie_valid():
        c = request.cookies.get(WALL_COOKIE, "")
        parts = c.split(".")
        ip = request.remote_addr or ""
        if len(parts) != 3 or not parts[0].isdigit() or parts[1] != "wall" or int(parts[0]) < time.time():
            return False
        return wall_ip_ok(ip) and hmac.compare_digest(c, wall_sign(int(parts[0]), ip))

    def cookie_valid(name, role):
        c = request.cookies.get(name, "")
        parts = c.split(".")
        if len(parts) != 3 or not parts[0].isdigit() or parts[1] != role or int(parts[0]) < time.time():
            return False
        return hmac.compare_digest(c, sign(int(parts[0]), role))

    def ui_role():
        """'admin' (full console), 'wall' (read-only big-screen view) or None.
        Admin and wall sessions live in different cookies, so both can exist in one browser."""
        if cookie_valid(COOKIE, "admin"):
            return "admin"
        if wall_cookie_valid():
            return "wall"
        return None

    def ui_ok():
        return ui_role() == "admin"

    deny = []
    for c in filter(None, os.environ.get("RPOT_UI_DENY_NETS", "").split(",")):
        try:
            deny.append(ipaddress.ip_network(c.strip(), strict=False))
        except ValueError:
            pass

    @app.before_request
    def deny_mgmt_network():
        """Decoys share the internal mgmt network with the manager: they may use the sensor API,
        never the UI port (a hijacked decoy must not even see the login page)."""
        if deny and request.remote_addr:
            try:
                a = ipaddress.ip_address(request.remote_addr)
            except ValueError:
                return
            if any(a in n for n in deny):
                abort(403)

    fails = defaultdict(deque)   # key -> timestamps (brute-force / abuse protection; console may be public)
    flock = threading.Lock()

    def throttled(key, limit=10, window=600, count=False):
        """True if `key` exceeded `limit` events in `window` s. count=True records this call too.
        Never sleeps in a worker thread (that would let 12 slow requests freeze the UI)."""
        now = time.time()
        with flock:
            if len(fails) > 50000:
                for k in [k for k, q in fails.items() if not q or now - q[-1] > window]:
                    del fails[k]
            q = fails[key]
            while q and now - q[0] > window:
                q.popleft()
            over = len(q) >= limit
            if count and not over:
                q.append(now)
            return over

    def same(a, b):
        return hmac.compare_digest(str(a).encode("utf-8", "surrogatepass"), str(b).encode("utf-8", "surrogatepass"))

    @app.after_request
    def headers(r):
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Referrer-Policy"] = "no-referrer"
        r.headers["X-Frame-Options"] = "DENY"
        r.headers["Server"] = server_hdr
        if request.path.startswith("/c/"):
            r.headers["Server"] = "Microsoft-IIS/10.0"
            r.headers["Cache-Control"] = "no-store"
        else:
            r.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                                    "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                                                    "form-action 'self'; base-uri 'none'; object-src 'none'")
        return r

    # ---------------------------------------------------------------- canary beacons
    @app.get("/c/<path:tok>")
    def canary(tok):
        tid = tok.split(".")[0]
        t = eng.fleet.all_tokens().get(tid)
        if t and t.get("kind") == "document" and not throttled("c:" + (request.remote_addr or "?"), 30, 600, count=True):
            src = request.remote_addr
            if cfg["console"].get("trust_xff") and request.headers.get("X-Forwarded-For"):
                cand = request.headers["X-Forwarded-For"].split(",")[0].strip()
                try:
                    src = str(ipaddress.ip_address(cand))
                except ValueError:
                    pass
            eng.ingest([{"ts": now_iso(), "sensor": "CANARY", "role": "canary", "sensor_ip": None, "src_ip": src,
                         "src_port": None, "dst_port": None, "proto": "http", "type": "canary.hit", "session": None,
                         "data": {"token": tid, "desc": t["desc"], "planted": t["planted"],
                                  "ua": (request.headers.get("User-Agent") or "")[:200]}}])
        r = make_response(PIXEL)
        r.headers["Content-Type"] = "image/png"
        return r

    # ---------------------------------------------------------------- UI auth

    @app.post("/login")
    def login():
        ip = request.remote_addr or "?"
        if throttled("login:" + ip):
            return redirect("/?locked=1"), 302
        tok = (request.form.get("token") or "").strip()[:200]
        if not same(tok, admin_token):
            throttled("login:" + ip, count=True)
            return redirect("/?bad=1")
        fails.pop("login:" + ip, None)
        r = redirect("/")
        exp = int(time.time()) + 12 * 3600
        r.set_cookie(COOKIE, sign(exp), max_age=12 * 3600, httponly=True, samesite="Strict",
                     secure=request.is_secure)
        return r

    @app.get("/wall")
    def wall():
        """Big-screen attack map.
        /wall?k=<console.wall_token> → 30-day read-only 'wall' cookie (for TVs / kiosks), then /wall.
        /wall as a logged-in admin   → same view, no token needed (opened from the console menu)."""
        k = request.args.get("k")
        if k is not None:
            wt = cfg["console"].get("wall_token") or ""
            ip = request.remote_addr or "?"
            if throttled("wall:" + ip):
                abort(429)
            if not wt or not same(k[:200], wt):
                throttled("wall:" + ip, count=True)
                print(f"[ReD-Pot manager] wall link REFUSED from {ip}: wrong token", flush=True)
                abort(403)
            if not wall_ip_ok(ip):
                print(f"[ReD-Pot manager] wall link REFUSED from {ip}: not in console.wall_allow", flush=True)
                abort(403)
            r = redirect("/wall")   # drop the token from the address bar / history
            exp = int(time.time()) + wall_days * 86400
            r.set_cookie(WALL_COOKIE, wall_sign(exp, ip), max_age=wall_days * 86400, httponly=True, samesite="Strict",
                         secure=request.is_secure)
            print(f"[ReD-Pot manager] wall screen opened from {ip} (valid {wall_days} days, this IP only)", flush=True)
            return r
        if not ui_role():
            return redirect("/")
        return send_from_directory(os.path.join(HERE, "static"), "index.html")

    @app.get("/api/whoami")
    def whoami():
        role = ui_role()
        if not role:
            abort(401)
        return jsonify(role=role)

    @app.post("/logout")
    def logout():
        r = redirect("/")
        r.delete_cookie(COOKIE)
        return r

    @app.get("/")
    def index():
        # the dashboard needs the ADMIN session; a wall-only browser gets the login page (never the wall)
        page = "index.html" if ui_role() == "admin" else "login.html"
        return send_from_directory(os.path.join(HERE, "static"), page)

    PUBLIC_STATIC = {"login.js", "app.css", "brand/rpot-logo-dark.svg", "brand/favicon.svg", "brand/rpot-icon.svg"}

    @app.get("/static/<path:p>")
    def static_files(p):
        if not ui_role() and p not in PUBLIC_STATIC:      # exact names: no '/static/login/../app.js' tricks
            abort(401)
        return send_from_directory(os.path.join(HERE, "static"), p)

    def need_ui(wall=False):
        """Admin always; the read-only wall role only where wall=True (map + counters)."""
        role = ui_role()
        if role == "admin" or (wall and role == "wall"):
            return
        abort(401 if not role else 403)

    def num(name, default, lo, hi):
        try:
            return max(lo, min(hi, float(request.args.get(name, default))))
        except ValueError:
            return default

    # ---------------------------------------------------------------- dashboard API
    @app.get("/api/summary")
    def api_summary():
        need_ui(wall=True)
        d = eng.summary(num("hours", 24, 0.25, 24 * 90))
        # server clock: the UI computes "ago" against it and warns when browser and server disagree (> 2 min)
        d.update(company=cfg["company"]["name"], domain=cfg["company"]["domain"], version=VERSION, edition=EDITION, now=now_iso(),
                 server_time=round(time.time(), 3), clock_synced=clock_synced())
        if ui_role() != "admin":                 # kiosk wall: counters only, no decoy names
            d["sensors_offline"] = len(d.get("sensors_offline") or [])
        return jsonify(d)

    @app.get("/api/graph")
    def api_graph():
        need_ui()
        return jsonify(eng.graph(num("hours", 24, 0.25, 24 * 90), int(num("min_level", 1, 0, 5)),
                                 "all" if request.args.get("scope") == "all" else "internal"))

    @app.get("/api/worldmap")
    def api_worldmap():
        need_ui(wall=True)
        d = eng.worldmap(num("hours", 24, 0.25, 24 * 90), int(num("min_level", 1, 0, 5)))
        if ui_role() != "admin":                 # kiosk wall: decoy names + positions, never their addresses
            d["sensors"] = [{k: v for k, v in x.items() if k not in ("ip", "geo_ip")} for x in d.get("sensors") or []]
        return jsonify(d)

    @app.get("/api/incidents")
    def api_incidents():
        need_ui()
        return jsonify(eng.incidents(num("hours", 24 * 7, 1, 24 * 365), int(num("min_level", 1, 0, 5)),
                                     request.args.get("status") or None))

    @app.get("/api/incident/<int:iid>")
    def api_incident(iid):
        need_ui()
        d = eng.incident(iid)
        return jsonify(d) if d else (jsonify(error="not found"), 404)

    @app.post("/api/incident/<int:iid>/status")
    def api_incident_status(iid):
        need_ui()
        if request.headers.get("X-Requested-With") != "rpot":
            abort(403)
        b = request.get_json(silent=True) or {}
        st = b.get("status")
        if st not in ("open", "ack", "closed", "false_positive"):
            abort(400)
        eng.set_status(iid, st, (b.get("note") or "")[:1000] or None)
        return jsonify(ok=True)

    @app.get("/api/events")
    def api_events():
        need_ui()
        return jsonify(eng.events(hours=num("hours", 24, 0.25, 24 * 90), min_level=int(num("min_level", 0, 0, 5)),
                                  limit=int(num("limit", 300, 1, 2000)), src=request.args.get("src") or None))

    @app.get("/api/hosts")
    def api_hosts():
        need_ui()
        return jsonify(eng.hosts(num("hours", 24 * 7, 1, 24 * 365)))

    @app.get("/api/host/<ip>")
    def api_host(ip):
        need_ui()
        d = eng.host(ip)
        return jsonify(d) if d else (jsonify(error="not found"), 404)

    @app.get("/api/sensors")
    def api_sensors():
        need_ui()
        return jsonify(eng.sensors())

    @app.get("/api/tokens")
    def api_tokens():
        need_ui()
        return jsonify(eng.tokens())

    @app.get("/api/export")
    def api_export():
        """JSON Export (D-4): incidents + alert records of UTC days [from, to]. Admin only, CSRF header,
        one export at a time, 10 per 10 min per IP, refused (413) instead of truncated when too large."""
        need_ui()
        if request.headers.get("X-Requested-With") != "rpot":
            abort(403)

        def out(r, code):
            r.status_code = code
            r.headers["Cache-Control"] = "no-store"
            return r

        try:
            d1, d2 = X.parse_dates(request.args.get("from"), request.args.get("to"))
        except ValueError as e:
            return out(jsonify(error=str(e)), 400)
        if throttled("export:" + (request.remote_addr or "?"), 10, 600, count=True):
            return out(jsonify(error="too many exports from this address; try again in a few minutes"), 429)
        token = X.GATE.acquire(stale=X.WALL_SECONDS + X.STALE_GRACE)
        if token is None:
            return out(jsonify(error="another export is running; try again when it has finished"), 429)
        held = {"conn": None, "owned_by_response": False}

        def release():                     # idempotent: response close, or this handler on any other path
            c, held["conn"] = held["conn"], None
            try:
                if c is not None:
                    c.close()
            finally:
                X.GATE.release(token)
        try:
            conn = held["conn"] = X.open_snapshot(eng.db_path)
            rng = X.day_range(d1, d2)
            st = X.stats(conn, rng)
            cap = X.MAX_BYTES
            if st["bytes"] > cap:
                return out(jsonify(error="export too large; narrow the date range", incidents=st["incidents"],
                                   alerts=st["alerts"], bytes=st["bytes"], max_bytes=cap), 413)
            gen = X.iter_json(conn, rng, X.build_meta(d1, d2, st), max_bytes=cap,
                              deadline=time.monotonic() + X.WALL_SECONDS)
            r = Response(gen, mimetype="application/json")
            r.headers["Content-Disposition"] = f'attachment; filename="{X.filename(d1, d2)}"'
            r.headers["Cache-Control"] = "no-store"
            r.call_on_close(release)
            held["owned_by_response"] = True
            return r
        finally:
            if not held["owned_by_response"]:
                release()

    # ---------------------------------------------------------------- fleet (sensor) admin
    def join_string(token, role=None):
        """redpot://HOST:PORT/TOKEN[?role=ID]#FP — the role hint lets the sensor installer plan host SSH
        before it redeems the one-time token (the token itself still decides the role)."""
        c = cfg["console"]
        host = c.get("public_ip") or c.get("advertise_host") or c.get("mgmt_ip") or request.host.split(":")[0]
        hint = f"?role={role}" if role and re.fullmatch(r"[a-z0-9-]{1,40}", str(role)) else ""
        return f"redpot://{host}:{c.get('sensor_port', 8741)}/{token}{hint}#{c.get('fingerprint', '')}"

    @app.get("/api/fleet")
    def api_fleet():
        need_ui()
        from rpot.common.config import load_roles
        lim = dict(eng.fleet.slots(), edition=EDITION)
        lim["full"] = lim["used"] >= lim["max"]                # used may be > max (tampering / race): still full
        lim["message"] = limit_message(lim["used"]) if lim["full"] else None
        return jsonify(sensors=eng.fleet.listing(), pending=eng.fleet.pending(), limit=lim,
                       roles=[{"id": r["id"], "title": r["title"]} for r in load_roles().values()])

    @app.post("/api/fleet/enroll")
    def api_fleet_enroll():
        need_ui()
        if request.headers.get("X-Requested-With") != "rpot":
            abort(403)
        b = request.get_json(silent=True) or {}
        try:
            tok = eng.fleet.create_enrollment(b.get("name"), b.get("role"), b.get("ip") or None)
        except LimitError as e:
            return jsonify(error=str(e), used=getattr(e, "used", None)), 400
        except ValueError as e:
            return jsonify(error=str(e)), 400
        j = join_string(tok, b.get("role"))
        # RC-22 / VM defect B7: the one-time join string is never part of a command line (ps shows argv, and sudo
        # keeps it for the whole install): the installer asks for it, or reads it with --join - / --join-file.
        return jsonify(join=j, command="sudo ./install.sh sensor", expires_hours=24,
                       hint="Paste the join string when the installer asks for it. Unattended installs: --join-file "
                            "FILE (root-only, chmod 600) or --join - (standard input). Never put it on the command line.")

    @app.post("/api/fleet/<name>/revoke")
    def api_fleet_revoke(name):
        need_ui()
        if request.headers.get("X-Requested-With") != "rpot":
            abort(403)
        return jsonify(ok=eng.fleet.revoke(name))

    @app.post("/api/fleet/<name>/cancel")
    def api_fleet_cancel(name):
        """Cancel a pending (unused) join command: frees its decoy slot immediately."""
        need_ui()
        if request.headers.get("X-Requested-With") != "rpot":
            abort(403)
        ok = eng.fleet.cancel_enrollment(name[:64])
        return (jsonify(ok=True), 200) if ok else (jsonify(error="no pending join for this name"), 404)

    @app.post("/api/fleet/<name>/delete")
    def api_fleet_delete(name):
        need_ui()
        if request.headers.get("X-Requested-With") != "rpot":
            abort(403)
        ok = eng.fleet.delete(name)
        return (jsonify(ok=True), 200) if ok else (jsonify(error="only a revoked remote sensor can be deleted"), 400)

    @app.get("/healthz")
    def healthz():
        return jsonify(ok=True)

    return app


def create_sensor_app(eng):
    """Sensor-facing API (separate port). Every request except enrollment needs
    `Authorization: Bearer NAME:SECRET`; events are force-stamped with the authenticated name
    so one sensor can never speak for another."""
    app = Flask("rpot-sensor-api", static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    @app.before_request
    def gunzip():
        """Sensors gzip event batches; decompress with a hard cap (no zip bombs)."""
        if request.headers.get("Content-Encoding", "").lower() != "gzip":
            return None
        import zlib
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            out = d.decompress(request.get_data(cache=False), 32 * 1024 * 1024 + 1)
        except zlib.error:
            return jsonify(error="bad gzip"), 400
        if len(out) > 32 * 1024 * 1024 or d.unconsumed_tail:
            return jsonify(error="payload too large"), 413
        request._cached_data = out
        return None
    tries = defaultdict(deque)
    lock = threading.Lock()
    over_logged = set()       # over-limit decoy names already logged (bounded)

    def who():
        h = request.headers.get("Authorization", "")
        name = eng.fleet.authenticate(h[7:]) if h.startswith("Bearer ") else None
        if not name:
            abort(401)
        if name not in eng.fleet.allowed_names():      # D-6 layer 7: authenticated but beyond the decoy cap
            with lock:
                first = name not in over_logged and len(over_logged) < 1000
                if first:
                    over_logged.add(name)
            if first:
                print(f"[ReD-Pot manager] decoy {name} refused: beyond the {EDITION} edition limit of {MAX_DECOYS} "
                      "decoys (newest / un-enrolled decoys lose). " + limit_message(eng.fleet.slots()["used"]), flush=True)
            abort(403)
        return name

    @app.after_request
    def headers(r):
        r.headers["Server"] = server_header(eng.cfg)
        r.headers["Cache-Control"] = "no-store"
        return r

    @app.post("/api/enroll")
    def enroll():
        ip = request.remote_addr or "?"
        with lock:
            q = tries[ip]
            now = time.time()
            while q and now - q[0] > 600:
                q.popleft()
            if len(q) >= 20:
                abort(429)
            q.append(now)
            if len(tries) > 20000:
                for k in [k for k, v in tries.items() if not v]:
                    del tries[k]
        b = request.get_json(silent=True)
        if not isinstance(b, dict) or not isinstance(b.get("token", ""), str):
            return jsonify(error="bad request"), 400
        raw = b.get("info") if isinstance(b.get("info"), dict) else {}
        info = {str(k)[:40]: str(v)[:200] for k, v in list(raw.items())[:20]}
        info["source_ip"] = ip
        try:
            res = eng.fleet.redeem(b.get("token", "")[:200], info)
        except LimitError as e:          # only reached with a VALID token; the token stays unused
            print(f"[ReD-Pot manager] enrollment from {ip} refused: decoy limit reached", flush=True)
            return jsonify(error="decoy limit reached", used=getattr(e, "used", None)), 409
        if not res:
            return jsonify(error="invalid, used or expired enrollment token"), 403
        sensor_json, baits = res
        sensor_json["manager"] = {"fingerprint": eng.cfg["console"].get("fingerprint")}
        return jsonify(sensor=sensor_json, baits=base64.b64encode(baits).decode())

    @app.post("/api/ingest")
    def ingest():
        name = who()
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("events", []), list):
            return jsonify(error="bad request"), 400
        evs = []
        for e in body.get("events", [])[:5000]:
            if isinstance(e, dict):
                e["sensor"] = name
                evs.append(e)
        if evs and evs[-1].get("sensor_ip"):
            eng.fleet.note_ip(name, evs[-1]["sensor_ip"])
        return jsonify(ok=True, stored=eng.ingest(evs), version=eng.fleet.version())

    @app.get("/api/config")
    def config():
        return jsonify(eng.fleet.sensor_config(who()))

    @app.get("/healthz")
    def healthz():
        return jsonify(ok=True)

    return app


def serve_tls(app, host, port, cert, key, name, keepalive=None):
    """Production WSGI server (cheroot) with TLS; plain HTTP only if no certificate is given.
    keepalive: idle seconds a connection may stay open (cheroot parks idle keep-alive sockets in a
    selector, so they cost no worker thread) — sensors reuse one connection for every heartbeat."""
    from cheroot import wsgi
    srv = wsgi.Server((host, port), app, numthreads=24, server_name=name, timeout=keepalive or 10)
    if cert and key:
        from cheroot.ssl.builtin import BuiltinSSLAdapter
        srv.ssl_adapter = BuiltinSSLAdapter(cert, key)
    t = threading.Thread(target=srv.start, name=name, daemon=True)
    t.start()
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(description="ReD-Pot manager")
    ap.add_argument("--config", default=os.environ.get("RPOT_CONFIG", "/etc/rpot/rpot.json"))
    ap.add_argument("--db", default=os.environ.get("RPOT_DB", "/var/lib/rpot/rpot.db"))
    ap.add_argument("--bind", default=os.environ.get("RPOT_BIND", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("RPOT_PORT", "8740")), help="UI port (inside the container)")
    ap.add_argument("--sensor-port", type=int, default=int(os.environ.get("RPOT_SENSOR_PORT", "8741")))
    ap.add_argument("--tls-dir", default=os.environ.get("RPOT_TLS_DIR", "/etc/rpot/tls"))
    ap.add_argument("--no-tls", action="store_true", help="dev only")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    os.makedirs(os.path.dirname(os.path.abspath(a.db)), exist_ok=True)
    dbdir = os.path.dirname(os.path.abspath(a.db))
    cert = key = None
    if not a.no_tls:
        cert, key = os.path.join(a.tls_dir, "manager.crt"), os.path.join(a.tls_dir, "manager.key")
        if not (os.path.exists(cert) and os.path.exists(key)):
            raise SystemExit(f"TLS certificate missing in {a.tls_dir} (created by rpotctl init / installer)")
        from rpot.common.tlsutil import fingerprint_file
        cfg["console"]["fingerprint"] = fingerprint_file(cert)
    app = create_app(cfg, a.db, os.environ.get("RPOT_GEOIP_DIR") or os.path.join(dbdir, "geoip"),
                     os.environ.get("RPOT_LOG_DIR") or os.path.join(dbdir, "logs"))
    sapp = create_sensor_app(app.engine)
    al = app.engine.alert_log
    print(f"[ReD-Pot manager] logs: {al.path if al else 'alerts.json disabled'}"
          f"{' + events.json' if app.engine.event_log else ''}", flush=True)
    g = app.engine.geo
    print(f"[ReD-Pot manager] GeoIP: {', '.join(g.sources) if g.sources else 'none (run rpotctl.py geoip)'}", flush=True)
    if clock_synced() is False:
        print("[ReD-Pot manager] WARNING: the system clock is NOT synchronised (NTP). Incident times, 'ago' values and "
              "login sessions depend on it - enable NTP on the host (timedatectl set-ntp true).", flush=True)
    proto = "http" if a.no_tls else "https"
    serve_tls(app, a.bind, a.port, cert, key, "ui")
    serve_tls(sapp, a.bind, a.sensor_port, cert, key, "sensor-api", keepalive=75)
    print(f"[ReD-Pot manager {VERSION}] {cfg['company']['name']}: UI {proto}://{a.bind}:{a.port}  "
          f"sensor API {proto}://{a.bind}:{a.sensor_port}  fingerprint {cfg['console'].get('fingerprint', '-')}", flush=True)
    stop = threading.Event()
    import signal
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()


if __name__ == "__main__":
    main()
