"""Sensor entrypoint: one process = one decoy role server.

  run   (default) — start the decoy from sensor.json
  join  REDPOT_JOIN_STRING — enroll at a remote manager once, save sensor.json + baits, then run

sensor.json (never the manager's rpot.json):
  {"sensor": {name, role, ip}, "company": {...persona}, "tokens": {...honeytoken index},
   "version": "...", "manager": {"url": "https://host:port", "fingerprint": "SHA256HEX", "key": "NAME:SECRET"}}

env: RPOT_SENSOR_CONFIG (default /etc/rpot/sensor.json, falls back to $RPOT_DATA/sensor.json),
     RPOT_BAITS (bait root; default $RPOT_DATA/baits), RPOT_DATA (/var/lib/rpot), RPOT_JOIN (join string).
"""
import argparse
import base64
import json
import os
import signal
import socket
import time
import sys
import threading

from rpot import VERSION
from rpot.common.config import load_roles, TokenIndex
from rpot.common.edition import MAX_DECOYS, UPGRADE_URL, limit_message
from rpot.common.events import Emitter
from rpot.sensor.base import REGISTRY, Ctx, NoBindAddress, iface_ipv4
from rpot.sensor.emptydir import chdir_empty

SELFCHECK_EVERY = int(os.environ.get("RPOT_SELFCHECK_S", "30"))   # s: listener self-check (F-02)

STARTERS = {}


def _starters():
    if STARTERS:
        return STARTERS
    from rpot.sensor.services.catchers import start_msrpc, start_netbios, start_rdp
    from rpot.sensor.services.http import start_http
    from rpot.sensor.services.ftp import start_ftp
    STARTERS.update({"msrpc": start_msrpc, "netbios": start_netbios, "rdp": start_rdp,
                     "http": start_http, "ftp": start_ftp})
    from rpot.sensor.services.dns import start_dns
    from rpot.sensor.services.ldap import start_ldap
    from rpot.sensor.services.kerberos import start_kerberos
    from rpot.sensor.services.dcudp import start_cldap, start_nbns, start_ntp
    STARTERS.update({"dns": start_dns, "ldap": start_ldap, "kerberos": start_kerberos,
                     "cldap": start_cldap, "nbns": start_nbns, "ntp": start_ntp})
    try:
        from rpot.sensor.services.ssh import start_ssh
        STARTERS["ssh"] = start_ssh
    except ImportError as e:
        print(f"[!] ssh disabled: {e}", file=sys.stderr)
    try:
        from rpot.sensor.services.smb import start_smb
        STARTERS["smb"] = start_smb
    except ImportError as e:
        print(f"[!] smb disabled: {e}", file=sys.stderr)
    return STARTERS


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def wait_iface_ip(iface, secs=60, step=2):
    """S-1 L14: a decoy on its interface's own address needs that address before it can listen."""
    end = time.monotonic() + secs
    while True:
        ip = iface_ipv4(iface)
        if ip or time.monotonic() >= end:
            return ip
        time.sleep(step)


def _follow_iface_ip(em, iface, name, every=30, on_change=None):
    """S-1 L14: the decoy listens on its interface's current address (not 0.0.0.0). When DHCP changes it, the
    new address is reported and on_change() runs — main() then stops the sensor and Docker's restart policy
    starts it again bound to the new address (every listener: TCP, UDP, SMB, HTTP, FTP passive)."""
    if not iface:
        return None

    def loop():
        while True:
            time.sleep(every)
            ip = iface_ipv4(iface)
            if ip and ip != em.sensor_ip:
                print(f"[ReD-Pot] {name}: address on {iface} is now {ip} (was {em.sensor_ip}) - rebinding", flush=True)
                em.sensor_ip = ip
                if on_change:
                    on_change()
                    return
    t = threading.Thread(target=loop, daemon=True, name="iface-ip")
    t.start()
    return t


def join(join_string, data_dir):
    """Redeem a one-time enrollment token at the manager → sensor.json + bait tree in data_dir."""
    from rpot.common.tlsutil import PinnedClient, PinError, parse_join
    from rpot.console.fleet import safe_extract
    base, _, frag = join_string.partition("#")
    url, token, fp = parse_join(base.split("?", 1)[0] + "#" + frag)    # '?role=…' = installer hint only
    info = {"hostname": socket.gethostname(), "version": VERSION}
    hostport = url.split("://", 1)[-1]
    for attempt in range(1, 7):                 # a network blip must not lose the one-time token
        try:
            client = PinnedClient(url, fp, timeout=30)
            status, res = client.request("POST", "/api/enroll", {"token": token, "info": info})
            break
        except PinError:            # not an OSError: without this a wrong fingerprint was a raw traceback (B20)
            raise SystemExit(f"[x] the manager at {hostport} presents a different certificate than the join string "
                             f"expects — refusing. Create a new join command on the right manager.")
        except OSError as e:
            if "fingerprint" in str(e).lower():
                raise SystemExit(f"[x] the manager at {hostport} presents a different certificate — refusing")
            print(f"[!] cannot reach the manager at {hostport} ({e.strerror or e}) — retry {attempt}/6 in 5 s", flush=True)
            if attempt == 6:
                raise SystemExit(f"[x] cannot reach the manager at {hostport}: {e.strerror or e}. Check the route and "
                                 f"firewall from this server to the manager (ip route get {hostport.split(':')[0]}), "
                                 f"then run the installer again — the join string is still valid.")
            time.sleep(5)
    if status == 409:                           # Community Edition decoy cap (D-6); the token stays unused
        used = res.get("used") if isinstance(res, dict) else None
        detail = limit_message(used) if isinstance(used, int) and not isinstance(used, bool) else (
            "Remove a decoy, revoke a remote sensor or cancel a pending join on the manager first, "
            f"or ask RedSide Security about ReD-Pot Enterprise: {UPGRADE_URL}")
        raise SystemExit(f"[x] enrollment refused: decoy limit reached (Community Edition: {MAX_DECOYS}) - "
                         f"{detail}. The join string was not used up: run the installer again once a slot is free.")
    if status != 200:
        raise SystemExit(f"[x] enrollment failed: HTTP {status} {res.get('error', '')}")
    sj = res["sensor"]
    sj["manager"] = {"url": url, "fingerprint": fp, "key": sj.pop("key")}
    os.makedirs(data_dir, exist_ok=True)
    baits = os.path.join(data_dir, "baits")
    os.makedirs(baits, exist_ok=True)
    safe_extract(base64.b64decode(res["baits"]), baits)
    _write_json(os.path.join(data_dir, "sensor.json"), sj)
    print(f"[+] enrolled as {sj['sensor']['name']} ({sj['sensor']['role']}) at {url}", flush=True)
    return sj


def load_sensor_json(path, data_dir):
    live = os.path.join(data_dir, "sensor-live.json")
    for p in (path, os.path.join(data_dir, "sensor.json")):
        if p and os.path.exists(p):
            with open(p) as f:
                sj = json.load(f)
            if os.path.exists(live):            # newer honeytoken index pulled from the manager
                try:
                    with open(live) as f:
                        lv = json.load(f)
                    if lv.get("sensor", {}).get("name") == sj["sensor"]["name"]:
                        sj.update({k: lv[k] for k in ("tokens", "company", "version", "zone", "zone_roles") if k in lv})
                except (OSError, ValueError):
                    pass
            return sj
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="ReD-Pot sensor")
    ap.add_argument("cmd", nargs="?", default="run", choices=["run", "join"])
    ap.add_argument("join_string", nargs="?", default=os.environ.get("RPOT_JOIN"))
    ap.add_argument("--config", default=os.environ.get("RPOT_SENSOR_CONFIG", "/etc/rpot/sensor.json"))
    ap.add_argument("--baits", default=os.environ.get("RPOT_BAITS"))
    ap.add_argument("--data", default=os.environ.get("RPOT_DATA", "/var/lib/rpot"))
    ap.add_argument("--manager-url", default=os.environ.get("RPOT_MANAGER_URL"), help="override manager URL")
    ap.add_argument("--port-offset", type=int, default=int(os.environ.get("RPOT_PORT_OFFSET", "0")),
                    help="dev only: add to every listening port (run unprivileged)")
    a = ap.parse_args(argv)
    a.data, a.baits = os.path.abspath(a.data), a.baits and os.path.abspath(a.baits)   # the CWD changes below

    if a.cmd == "join":                                   # enroll only, then exit (installer step)
        if not a.join_string:
            ap.error("join needs a join string (redpot://HOST:PORT/TOKEN#FINGERPRINT)")
        join(a.join_string, a.data)
        return
    sj = load_sensor_json(a.config, a.data)
    if sj is None and a.join_string:
        sj = join(a.join_string, a.data)
    if sj is None:
        raise SystemExit("[x] no sensor.json and no join string — run: sensor join redpot://…")

    s = sj["sensor"]
    role = load_roles()[s["role"]]
    m = sj.get("manager", {})
    cfg = {"company": sj["company"], "tokens": sj.get("tokens", {}), "sensors": [s],
           "zone": sj.get("zone") or {}, "zone_roles": sj.get("zone_roles") or {}}
    baits = a.baits or os.path.join(a.data, "baits")
    holder = {}

    def refresh(version):
        """Manager config changed (new sensor enrolled, baits rotated) → pull the new honeytoken index."""
        status, res = holder["em"].client.request("GET", "/api/config")
        if status == 200 and "tokens" in res:
            cfg["tokens"] = res["tokens"]
            cfg["company"] = res.get("company", cfg["company"])
            if "zone" in res:
                cfg["zone"], cfg["zone_roles"] = res["zone"], res.get("zone_roles") or {}
            holder["ctx"].tokens = TokenIndex(cfg)
            _write_json(os.path.join(a.data, "sensor-live.json"),
                        {"sensor": s, "tokens": res["tokens"], "company": cfg["company"], "version": res.get("version"),
                         "zone": cfg["zone"], "zone_roles": cfg["zone_roles"]})
            print(f"[ReD-Pot] {s['name']}: honeytoken index updated ({len(res['tokens'])} tokens)", flush=True)

    # S-1 L14: a decoy on its interface's own address (RPOT_SENSOR_IFACE, no fixed RPOT_BIND_IP) binds that
    # interface's current address — never 0.0.0.0 — and is restarted when DHCP changes it
    follow = os.environ.get("RPOT_SENSOR_IFACE") if not os.environ.get("RPOT_BIND_IP") else None
    sensor_ip = os.environ.get("RPOT_SENSOR_IP") or s.get("ip")
    if follow:
        sensor_ip = wait_iface_ip(follow)
        if not sensor_ip:
            raise SystemExit(f"[x] {follow} has no IPv4 address - the decoy cannot listen yet (restarting)")
    em = Emitter(s["name"].upper(), role["id"], a.manager_url or m.get("url"), m.get("key"),
                 sensor_ip=sensor_ip, data_dir=a.data, stdout=os.environ.get("RPOT_STDOUT", "1") == "1",
                 fingerprint=m.get("fingerprint"), on_version=refresh,
                 relay_socket=os.environ.get("RPOT_RELAY_SOCKET"))
    em.version = sj.get("version")
    stop, rebind = threading.Event(), threading.Event()
    _follow_iface_ip(em, follow, s["name"].upper(), on_change=lambda: (rebind.set(), stop.set()))
    ctx = Ctx(cfg, s, role, em, TokenIndex(cfg), os.path.join(baits, s["name"].upper()), a.data)
    chdir_empty(a.data)                  # F-01: the CWD is an empty dir, never the source tree (/opt/rpot)
    holder.update(em=em, ctx=ctx)
    st = _starters()
    started = []
    for svc in role["services"]:
        svc = dict(svc, port=svc["port"] + a.port_offset)
        fn = st.get(svc["type"])
        if not fn:
            print(f"[!] no emulator for {svc['type']}", file=sys.stderr)
            continue
        label = f"{svc['type']}/{svc['port']}"
        REGISTRY.current = label                # listeners opened by this starter belong to this service
        try:
            fn(ctx, svc)
        except NoBindAddress as e:          # F8: the lease vanished after wait_iface_ip - fail closed
            raise SystemExit(f"[x] {e} (restarting)")
        finally:
            REGISTRY.current = None
        started.append(label)
    em.emit("sensor.start", version=VERSION, services=started, os=role.get("os"), title=role["title"])
    print(f"[ReD-Pot] {ctx.name} ({role['title']}) up: {', '.join(started)} → manager {m.get('url')}", file=sys.stderr, flush=True)

    # F-02: every SELFCHECK_EVERY s each listener must still be bound, listening and served; a dead one is
    # reported (sensor.service_down → L4 incident on the manager) and restarted (sensor.service_up)
    REGISTRY.start(ctx, every=SELFCHECK_EVERY, stop=stop)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    em.emit("sensor.stop")
    em.close()
    if rebind.is_set():                          # restart: Docker (restart: unless-stopped) binds the new address
        raise SystemExit(75)


if __name__ == "__main__":
    main()
