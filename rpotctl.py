#!/usr/bin/env python3
"""rpotctl — create and manage an ReD-Pot deployment (Community Edition: up to 3 decoys).

  rpotctl.py roles                                  list available role servers
  rpotctl.py init -d DIR --domain corp.acmebank.com --profile bank --net-mode host --mgmt-ip 10.0.0.5 \\
             --sensor FS01=windows-file-server@10.0.0.5%eth0 --sensor WEB01=linux-web-hosting@10.0.5.7%eth1
                                                    host  = production: one decoy per interface, on its own IP
  rpotctl.py init -d DIR --domain corp.local --sensor FS01=windows-file-server [--subnet 172.30.0.0/24]
                                                    bridge (default) = isolated Docker lab
  rpotctl.py baits -d DIR                           re-plant baits (existing honeytokens keep their secrets)
  rpotctl.py tls -d DIR [--renew]                   show / re-issue the persona-styled manager certificate
  rpotctl.py compose -d DIR [--image IMG] [--ui-bind IP]
  rpotctl.py add-sensor -d DIR --sensor NAME=role@IP%IFACE   add a decoy (existing ones keep their keys)
  rpotctl.py remove-sensor -d DIR --name NAME       remove a local decoy again
  rpotctl.py show -d DIR                            print persona, sensors, tokens
  rpotctl.py wall-url -d DIR [--rotate]             read-only kiosk link for big screens (attack map wall mode)
  rpotctl.py geoip -d DIR [--city]                  download DB-IP Lite GeoIP (country+ASN, opt. city) for the world map
  rpotctl.py site -d DIR --name HQ --lat 40.18 --lon 44.51   where your network is on the world map
  rpotctl.py slots --db DB --config rpot.json       decoy slots in use (one JSON line)
  rpotctl.py export --db DB --config rpot.json --from YYYY-MM-DD --to YYYY-MM-DD   JSON export to stdout
"""
import argparse
import ipaddress
import json
import re
import os
import secrets
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rpot.common.config import (load_roles, load_config, save_config, check_version,  # noqa: E402
                                CONFIG_VERSION, NET_MODES)
from rpot.common.edition import MAX_DECOYS, LimitError, limit_message  # noqa: E402
from rpot import baits as B  # noqa: E402
from rpot import VERSION  # noqa: E402

# Interface names end up quoted in rpot.json / compose; the kernel allows far more than this (L13).
IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$")


def cmd_roles(a):
    for r in load_roles().values():
        ports = " ".join(f"{s['port']}/udp" if s.get("udp") else str(s["port"]) for s in r["services"])
        print(f"{r['id']:<22} {r['title']:<24} {r['os']:<36} ports: {ports}")


def check_sensors(sensors, network, roles):
    """Validate the complete local decoy list (new install, add-sensor or a hand-edited rpot.json).
    host mode: one decoy per interface, on that interface's own IP — iface required, ifaces and IPs distinct.
    bridge mode (isolated lab): IPs distinct, inside the lab subnet, not the manager's lab address.
    Raises LimitError (more than MAX_DECOYS) or ValueError."""
    mode = network.get("mode")
    if mode not in NET_MODES:
        raise ValueError(f"network mode {mode!r} is not supported (use {' or '.join(NET_MODES)})")
    if not isinstance(sensors, list):
        raise ValueError("sensors must be a list")
    if len(sensors) > MAX_DECOYS:
        raise LimitError(limit_message(len(sensors)))
    net = None
    if mode == "bridge":
        try:
            net = ipaddress.ip_network(network.get("subnet"))
        except (TypeError, ValueError):
            raise ValueError(f"invalid lab subnet {network.get('subnet')!r}") from None
    names, ips, ifaces = set(), set(), set()
    for s in sensors:
        s = s if isinstance(s, dict) else {}
        name, role, ip, iface = s.get("name"), s.get("role"), s.get("ip"), s.get("iface")
        if not isinstance(name, str) or not B.valid_hostname(name):
            raise ValueError(f"invalid host name {name!r}: 1-15 letters/digits/hyphen (Windows limit), e.g. ARB-FS-02")
        if not isinstance(role, str) or role not in roles:
            raise ValueError(f"{name}: unknown role {role!r}; see `rpotctl.py roles`")
        try:
            if not isinstance(ip, str):
                raise ValueError
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            raise ValueError(f"{name}: invalid IPv4 address {ip!r}") from None
        if str(addr) != ip:
            raise ValueError(f"{name}: write the address as {addr}")
        if addr.is_unspecified or addr.is_loopback or addr.is_multicast or addr.is_reserved:
            raise ValueError(f"{name}: {ip} cannot be a decoy address")
        if mode == "host":
            if not iface:
                raise ValueError(f"{name}: host mode needs the decoy's interface: NAME=role@IP%IFACE")
            if not isinstance(iface, str) or not IFACE_RE.match(iface):
                raise ValueError(f"{name}: invalid interface name {iface!r}")
            if iface in ifaces:
                raise ValueError(f"{name}: interface {iface} already has a decoy (one decoy per interface)")
            ifaces.add(iface)
        else:
            if iface is not None:
                raise ValueError(f"{name}: %IFACE is only for --net-mode host (bridge = isolated lab)")
            if addr not in net:
                raise ValueError(f"{name}: {ip} is not inside the lab subnet {net}")
            if ip == network.get("console_ip"):
                raise ValueError(f"{name}: {ip} is the manager's address on the lab network — pick another IP "
                                 f"or move the manager with --console-ip")
        if name.upper() in names:
            raise ValueError(f"duplicate sensor name: {name}")
        if ip in ips:
            raise ValueError(f"duplicate sensor IP: {name} {ip} (each decoy needs its own address)")
        names.add(name.upper()); ips.add(ip)
    return sensors


def _sensors(specs, network, roles, existing=()):
    """--sensor NAME=role@IP%IFACE (host) or NAME=role[@IP] (bridge lab; a free lab IP is picked if omitted).
    Returns the new entries; the whole list (existing + new) is validated. Exits with the error text."""
    new = []
    for spec in specs or []:
        name, _, rest = spec.partition("=")
        rest, pct, iface = rest.partition("%")
        role, _, ip = rest.partition("@")
        entry = {"name": name.upper(), "role": role, "ip": ip}
        if pct:
            entry["iface"] = iface
        new.append(entry)
    if network.get("mode") == "bridge":                # lab: fill missing IPs with free ones from .21 up
        taken = {x.get("ip") for x in list(existing) + new} | {network.get("console_ip")}
        free = (str(h) for i, h in enumerate(ipaddress.ip_network(network["subnet"]).hosts()) if i >= 20)
        for entry in new:
            if not entry["ip"]:
                entry["ip"] = next((h for h in free if h not in taken), "")
                taken.add(entry["ip"])
    try:
        check_sensors(list(existing) + new, network, roles)
    except ValueError as e:              # LimitError included: prints limit_message
        sys.exit(f"error: {e}")
    return new


def _load_v2(p):
    cfg = load_config(p)
    try:
        return check_version(cfg)
    except ValueError as e:
        sys.exit(f"error: {e}")


def cmd_init(a):
    d = os.path.abspath(a.dir)
    os.makedirs(d, exist_ok=True)
    cfgp = os.path.join(d, "rpot.json")
    if os.path.exists(cfgp) and not a.force:
        sys.exit(f"{cfgp} exists (use --force to overwrite)")
    roles = load_roles()
    if a.net_mode == "bridge":
        try:
            net = ipaddress.ip_network(a.subnet)
        except ValueError:
            sys.exit(f"error: --subnet {a.subnet!r} is not a network, e.g. 172.30.0.0/24")
        if net.version != 4 or net.prefixlen > 26:
            sys.exit(f"error: --subnet {a.subnet!r}: use an IPv4 lab network of /26 or larger")
        # console_ip = the manager's address on the LAB bridge network only (never in a production certificate)
        network = {"mode": "bridge", "subnet": str(net), "console_ip": a.console_ip or str(list(net.hosts())[9])}
    else:
        if a.console_ip:
            sys.exit("error: --console-ip is only for --net-mode bridge (the isolated lab)")
        network = {"mode": "host", "console_ip": None}
    sensors = _sensors(a.sensor, network, roles)
    console_ip = network["console_ip"]
    try:
        persona = B.make_persona(a.domain, a.profile)
    except ValueError as e:
        sys.exit(f"error: {e}")
    persona["web_theme"] = a.web_theme
    curl = f"https://{a.public_ip or a.mgmt_ip or console_ip or '127.0.0.1'}:{a.ui_port}"
    cfg = {
        "version": CONFIG_VERSION,
        "deployment": secrets.token_hex(4),
        "bait_seed": secrets.token_hex(16),          # manager-only: bait ids/secrets stay stable across regenerations
        "company": persona,
        "network": network,
        "console": {"url": curl, "canary_url": a.canary_url or curl, "admin_token": secrets.token_urlsafe(18),
                    "ui_port": a.ui_port, "sensor_port": a.sensor_port, "public_ip": a.public_ip, "mgmt_ip": a.mgmt_ip},
        "sensors": sensors,
        "allowlist": a.allow or [],
        "internal_nets": a.internal or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "logs": {"alerts": True, "events": False, "max_mb": 50, "keep": 90},
        "alerts": {"min_level": 3},                    # threshold for alerts.json (no outbound alerting in CE)
        "tokens": {},
    }
    if a.site_lat is not None and a.site_lon is not None:
        cfg["site"] = {"name": a.site_name or persona["name"], "lat": a.site_lat, "lon": a.site_lon}
    _baits(cfg, d)
    _manager_tls(cfg, d)
    _sensor_bundles(cfg, d)
    save_config(cfg, cfgp)
    print(f"[+] deployment written to {d}")
    print(f"    company  : {persona['name']} ({persona['profile']}), domain {persona['domain']} "
          f"(NetBIOS {persona['netbios']}, mail @{persona['email_domain']}, users like {persona['users'][0]['username']})")
    for s in sensors:
        print(f"    sensor   : {s['name']:<6} {roles[s['role']]['title']:<26} {s['ip']}"
              + (f" on {s['iface']}" if s.get("iface") else ""))
    print(f"    tokens   : {len(cfg['tokens'])} honeytokens planted")
    print(f"    console  : {curl}  (UI token: {cfg['console']['admin_token']})")
    if not os.environ.get("RPOT_INSTALLER"):            # the installer composes + starts everything itself
        print("    next     : rpotctl.py compose -d DIR && cd DIR && docker compose up -d")


def _baits(cfg, d):
    """(Re)plant the local decoys' baits with the breadcrumb planner (rpot.baits.generate). Deterministic:
    tokens that already exist keep id + secret, so call it again after adding a decoy to cfg['sensors'].
    Remote decoys listed in cfg['remote_sensors'] ([{name, role, ip}]) also get crumbs pointing at them."""
    cfg.setdefault("bait_seed", secrets.token_hex(16))
    out = os.path.join(d, "baits")
    if os.path.isdir(out):
        shutil.rmtree(out)
    B.generate(cfg, out)


def manager_cert_identity(cfg):
    """(CN, SANs, O, issuer CN) of the manager certificate. It is visible on the UI/sensor ports — when a decoy
    shares the management interface those sit on a decoy's address — so it looks like the company's internal PKI: CN = the decoy that
    shares the management address (else <netbios>-mgmt01.<domain>), SANs = the real manager addresses only.
    No product name, no "console" alias (sensors pin the SHA-256 and never check host names), no lab IP."""
    co, c, net = cfg["company"], cfg["console"], cfg.get("network", {})
    mine = [x for x in (c.get("mgmt_ip"), c.get("public_ip")) if x]
    twin = next((s for s in cfg.get("sensors", []) if s.get("ip") and s["ip"] in mine), None)
    cn = f"{twin['name'].lower() if twin else co['netbios'].lower() + '-mgmt01'}.{co['domain']}"
    names = [cn, *mine]
    if net.get("mode", "bridge") == "bridge" and net.get("console_ip"):
        names.append(net["console_ip"])                 # lab bridge only
    return cn, names, co["name"], f"{co['name']} Issuing CA"


def _manager_tls(cfg, d, force=False):
    from rpot.common.tlsutil import make_cert
    cn, names, org, ca = manager_cert_identity(cfg)
    _, _, fp = make_cert(os.path.join(d, "tls"), cn, names, org=org, ca_name=ca, force=force)
    cfg["console"]["fingerprint"] = fp
    return fp


def cmd_tls(a):
    """Show the manager certificate; --renew re-issues it persona-styled (installs before 0.4 had a product-named one)."""
    d = os.path.abspath(a.dir)
    p = os.path.join(d, "rpot.json")
    cfg = load_config(p)
    if a.renew:
        _manager_tls(cfg, d, force=True)
        _sensor_bundles(cfg, d)
        save_config(cfg, p)
        print("[+] certificate re-issued, local sensors re-keyed (apply: docker compose up -d --force-recreate)")
        print("    REMOTE sensors pin the old fingerprint: re-enroll them with a new join string")
    from cryptography import x509
    with open(os.path.join(d, "tls", "manager.crt"), "rb") as f:
        crt = x509.load_pem_x509_certificate(f.read())
    san = crt.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    print(f"subject : {crt.subject.rfc4514_string()}\nissuer  : {crt.issuer.rfc4514_string()}")
    print(f"SANs    : {', '.join(str(x.value) for x in san)}\nSHA-256 : {cfg['console'].get('fingerprint')}")


def _sensor_bundles(cfg, d, keep=False):
    """Per local sensor: its own key + sensor.json (never the full rpot.json). keep: reuse the key of every
    sensor that already has a bundle (adding a decoy must not invalidate the running ones)."""
    import hashlib
    base = os.path.join(d, "sensors")
    for s in cfg["sensors"]:
        sd = os.path.join(base, s["name"])
        secret = (_bundle_secret(sd, s) if keep else None) or secrets.token_urlsafe(32)
        s["key_sha256"] = hashlib.sha256(secret.encode()).hexdigest()
        os.makedirs(sd, exist_ok=True)
        from rpot.common.config import sensor_token_view, zone_view
        cfg["company"].setdefault("token_salt", secrets.token_hex(16))
        sj = {"sensor": {"name": s["name"], "role": s["role"], "ip": s["ip"]}, "company": cfg["company"],
              "tokens": sensor_token_view(cfg["tokens"], cfg["company"]["token_salt"], s["role"]), "version": None,
              "manager": {"url": (f"https://{cfg['console'].get('mgmt_ip') or '127.0.0.1'}:{cfg['console'].get('sensor_port', 8741)}"
                                  if cfg["network"].get("mode") == "host" else "https://console:8741"),
                          "fingerprint": cfg["console"]["fingerprint"],
                          "key": f"{s['name']}:{secret}"}}
        sj.update(zone_view(cfg["sensors"]))
        p = os.path.join(sd, "sensor.json")
        with open(p, "w") as f:
            json.dump(sj, f, indent=1)
        os.chmod(p, 0o600)


def _bundle_secret(sd, s):
    """The secret of an existing sensor bundle, if it still matches the key hash in rpot.json."""
    import hashlib
    try:
        name, _, secret = json.load(open(os.path.join(sd, "sensor.json")))["manager"]["key"].partition(":")
    except (OSError, ValueError, KeyError, TypeError):
        return None
    ok = name == s["name"] and secret and hashlib.sha256(secret.encode()).hexdigest() == s.get("key_sha256")
    return secret if ok else None


def cmd_baits(a):
    d = os.path.abspath(a.dir)
    cfg = load_config(os.path.join(d, "rpot.json"))
    _baits(cfg, d)
    _sensor_bundles(cfg, d)
    save_config(cfg, os.path.join(d, "rpot.json"))
    print(f"[+] {len(cfg['tokens'])} baits planted, existing honeytokens kept (restart: docker compose up -d --force-recreate)")


HARDEN = ["    read_only: true", "    tmpfs: [\"/tmp:size=16m,mode=1777\"]",
          "    logging:", "      driver: json-file", "      options: {max-size: \"10m\", max-file: \"3\"}"]


def mgmt_subnet(cfg):
    """Explicit, per-deployment internal mgmt subnet (the UI refuses requests from it)."""
    import hashlib
    n = int(hashlib.sha256(str(cfg.get("deployment", "x")).encode()).hexdigest(), 16) % 200 + 20
    return f"172.31.{n}.0/24"


def compose_text(cfg, image=f"rpot:{VERSION}", ui_bind=None, sensor_bind=None):
    """docker-compose.yml. The manager publishes the UI and sensor ports on the management IP and sits on an
    INTERNAL mgmt network (+ front for egress-free UI publishing).
    host mode (production): every decoy runs with network_mode: host, bound ONLY to its interface's own IP
    (RPOT_BIND_IP), one decoy per interface — no extra MACs or addresses on the LAN.
    bridge mode (isolated lab): decoys on an internal bridge network with fixed IPs, no egress.
    Raises LimitError for more than MAX_DECOYS local decoys and ValueError for an invalid decoy list
    (a hand-edited rpot.json must not produce a 4th container or inject into the YAML)."""
    roles = load_roles()
    net, c = cfg["network"], cfg["console"]
    check_sensors(cfg["sensors"], net, roles)
    host_mode = net["mode"] == "host"
    ui_bind = ui_bind or c.get("mgmt_ip") or "0.0.0.0"
    sensor_bind = sensor_bind or c.get("mgmt_ip") or "0.0.0.0"
    for b in (ui_bind, sensor_bind):
        ipaddress.ip_address(b)                          # ValueError: never write a non-address into the YAML
    L = ["# generated by rpotctl — ReD-Pot by RedSide Security", "services:"]
    L += ["  console:", f"    image: {image}", "    command: [\"console\"]", "    restart: unless-stopped",
          "    environment:", "      RPOT_CONFIG: /etc/rpot/rpot.json", "      RPOT_DB: /var/lib/rpot/rpot.db",
          "      RPOT_GEOIP_DIR: /geoip", "      RPOT_LOG_DIR: /logs", "      RPOT_TLS_DIR: /etc/rpot/tls",
          f"      RPOT_UI_DENY_NETS: \"{mgmt_subnet(cfg)}\"",
          "    volumes:", "      - ./rpot.json:/etc/rpot/rpot.json:ro", "      - ./tls:/etc/rpot/tls:ro",
          "      - console-data:/var/lib/rpot", "      - ./geoip:/geoip:ro", "      - ./logs:/logs",
          "    ports:", f"      - \"{ui_bind}:{int(c.get('ui_port', 8740))}:8740\"",
          f"      - \"{sensor_bind}:{int(c.get('sensor_port', 8741))}:8741\"",
          "    networks:", "      mgmt:", "        aliases: [console]", "      front: {}",
          "    mem_limit: 384m", "    pids_limit: 512", "    cap_drop: [ALL]", "    security_opt: [\"no-new-privileges:true\"]"] + HARDEN
    for s in cfg["sensors"]:
        r = roles[s["role"]]
        svc = s["name"].lower()
        env = ["      RPOT_SENSOR_CONFIG: /etc/rpot/sensor.json", "      RPOT_BAITS: /srv/rpot/baits"]
        if host_mode:
            env += ["      RPOT_PRIVDROP: \"1\"", f"      RPOT_BIND_IP: \"{s['ip']}\""]
        L += [f"  {svc}:", f"    image: {image}", "    command: [\"sensor\"]", "    restart: unless-stopped",
              f"    hostname: {svc}"] + (["    user: \"0:0\""] if host_mode else []) + [   # host: entrypoint drops to 10001
              "    environment:", *env, "      RPOT_STDOUT: \"0\"", "    volumes:",
              f"      - ./sensors/{s['name']}/sensor.json:/etc/rpot/sensor.json:ro",
              f"      - ./baits/{s['name']}:/srv/rpot/baits/{s['name']}:ro", f"      - {svc}-data:/var/lib/rpot"]
        if host_mode:
            # Listens on its interface's own IP only (RPOT_BIND_IP); reaches the manager via mgmt_ip:sensor_port.
            # F5 (RC-18): starts as root with only NET_BIND_SERVICE + SETUID + SETGID + SETPCAP and
            # no-new-privileges; the entrypoint (RPOT_PRIVDROP) drops to uid/gid 10001 with setpriv, cuts the
            # bounding set to NET_BIND_SERVICE (needs SETPCAP, R2-4) and keeps it as an ambient capability for
            # :22/:445. The namespaced sysctl used in bridge mode cannot be set on the
            # host network, hence the capability.
            L += ["    network_mode: host", "    cap_drop: [ALL]", "    cap_add: [NET_BIND_SERVICE, SETUID, SETGID, SETPCAP]"]
        else:
            L += ["    networks:", "      decoy:", f"        ipv4_address: {s['ip']}", "      mgmt: {}",
                  "    cap_drop: [ALL]", "    sysctls:", "      net.ipv4.ip_unprivileged_port_start: 0"]
        L += ["    mem_limit: 192m", "    pids_limit: 384"] + HARDEN + ["    security_opt: [\"no-new-privileges:true\"]"]
        L += ["    labels:", f"      rpot.role: {r['id']}"]
    L += ["networks:"]
    if not host_mode:
        L += ["  decoy:", "    internal: true      # lab bridge: decoys get NO internet / host egress (no pivoting)",
              "    ipam:", "      config:", f"        - subnet: {net['subnet']}"]
    L += ["  mgmt:", "    internal: true", "    ipam:", "      config:", f"        - subnet: {mgmt_subnet(cfg)}", "  front: {}"]
    L += ["volumes:", "  console-data:"] + [f"  {s['name'].lower()}-data:" for s in cfg["sensors"]]
    return "\n".join(L) + "\n"


def cmd_compose(a):
    d = os.path.abspath(a.dir)
    cfg = _load_v2(os.path.join(d, "rpot.json"))
    p = os.path.join(d, "docker-compose.yml")
    try:
        text = compose_text(cfg, a.image, a.ui_bind, a.ui_bind)
    except ValueError as e:                             # LimitError included: prints limit_message
        sys.exit(f"error: {e}")
    with open(p, "w") as f:
        f.write(text)
    for sub in ("logs", "geoip"):                       # console runs as uid 10001 and writes logs/
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    if os.geteuid() == 0:                               # containers run as uid 10001
        for root, dirs, files in os.walk(d):
            for n in dirs + files:
                try:
                    os.chown(os.path.join(root, n), 10001, 10001)
                except OSError:
                    pass
    print(f"[+] {p}")


def _token_secret(t):
    return (t.get("kind"), t.get("username"), t.get("password"), t.get("fingerprint"), t.get("url"))


def _regen_keep(cfg, d):
    """Baits for a changed sensor list. Existing honeytokens must stay valid — attackers may already hold them —
    so the bait plan must be deterministic per persona (rpot.baits); this reports any token that changed."""
    before = {k: _token_secret(v) for k, v in (cfg.get("tokens") or {}).items()}
    _baits(cfg, d)
    _sensor_bundles(cfg, d, keep=True)
    after = {k: _token_secret(v) for k, v in cfg["tokens"].items()}
    kept = [k for k in before if after.get(k) == before[k]]
    gone = [k for k in before if k not in after]            # lived on a removed decoy: expected, not a loss
    changed = [k for k in before if k in after and after[k] != before[k]]
    if gone:
        print(f"[+] {len(gone)} honeytoken(s) removed together with the decoy that held them")
    if changed:
        print(f"[!] {len(changed)} of {len(before)} existing honeytokens changed — copies planted earlier are "
              f"no longer recognised as L5")
    elif before and not gone:
        print(f"[+] all {len(before)} existing honeytokens unchanged")
    return kept


def _write_compose(d, cfg, image):
    cmd_compose(argparse.Namespace(dir=d, image=image, ui_bind=None))


def cmd_add_sensor(a):
    """Add one local decoy to an existing deployment (install.sh add-decoy). Persona and the existing
    sensors' keys stay as they are; host mode: the new decoy needs a free interface and its own IP."""
    d = os.path.abspath(a.dir)
    p = os.path.join(d, "rpot.json")
    cfg = _load_v2(p)
    roles = load_roles()
    old = cfg["sensors"]
    try:
        check_sensors(old, cfg["network"], roles)
    except ValueError as e:
        sys.exit(f"error: {e}")
    if len(old) >= MAX_DECOYS:
        sys.exit(f"error: {limit_message(len(old))}")
    new = _sensors([a.sensor], cfg["network"], roles, existing=old)[0]
    cfg["sensors"] = old + [new]
    _regen_keep(cfg, d)
    save_config(cfg, p)
    _write_compose(d, cfg, a.image)
    print(f"[+] sensor {new['name']} ({roles[new['role']]['title']}) {new['ip']}"
          + (f" on {new['iface']}" if new.get("iface") else ""))


def cmd_remove_sensor(a):
    d = os.path.abspath(a.dir)
    p = os.path.join(d, "rpot.json")
    cfg = _load_v2(p)
    name = a.name.upper()
    if not B.valid_hostname(name) or not any(x["name"] == name for x in cfg["sensors"]):
        sys.exit(f"no local sensor named {name!r} (have: {', '.join(x['name'] for x in cfg['sensors']) or 'none'})")
    cfg["sensors"] = [x for x in cfg["sensors"] if x["name"] != name]
    shutil.rmtree(os.path.join(d, "sensors", name), ignore_errors=True)
    _regen_keep(cfg, d)
    save_config(cfg, p)
    _write_compose(d, cfg, a.image)
    print(f"[+] sensor {name} removed")


def cmd_wall_url(a):
    """Create (or rotate) the read-only wall-screen token and print the kiosk URL."""
    p = os.path.join(os.path.abspath(a.dir), "rpot.json")
    cfg = load_config(p)
    if a.rotate or not cfg["console"].get("wall_token"):
        cfg["console"]["wall_token"] = secrets.token_urlsafe(24)
        save_config(cfg, p)
        print("[+] new wall token saved — restart the console to apply (old wall links stop working)")
    base = (a.base or cfg["console"]["url"]).rstrip("/")
    print(f"{base}/wall?k={cfg['console']['wall_token']}")
    print(f"    read-only: attack map + counters only; works {cfg['console'].get('wall_days', 7)} days, only on the screen "
          f"(IP) that opens it. Chrome kiosk:")
    print(f"    chrome --kiosk --noerrdialogs --disable-infobars \"{base}/wall?k=...\"")


def cmd_geoip(a):
    """DB-IP Lite databases (CC BY 4.0, monthly). Downloaded once; lookups are offline."""
    import gzip
    import urllib.request
    from datetime import date
    d = os.path.join(os.path.abspath(a.dir), "geoip")
    os.makedirs(d, exist_ok=True)
    kinds = ["country", "asn"] + (["city"] if a.city else [])
    today = date.today()
    months = [today.strftime("%Y-%m"), (today.replace(day=1) - __import__("datetime").timedelta(days=1)).strftime("%Y-%m")]
    for k in kinds:
        for m in months:
            url = f"https://download.db-ip.com/free/dbip-{k}-lite-{m}.mmdb.gz"
            try:
                print(f"[*] {url}")
                req = urllib.request.Request(url, headers={"User-Agent": "rpotctl"})
                with urllib.request.urlopen(req, timeout=120) as r, open(os.path.join(d, f"dbip-{k}-lite.mmdb.tmp"), "wb") as f:
                    with gzip.GzipFile(fileobj=r) as gz:
                        shutil.copyfileobj(gz, f)
                os.replace(os.path.join(d, f"dbip-{k}-lite.mmdb.tmp"), os.path.join(d, f"dbip-{k}-lite.mmdb"))
                break
            except Exception as e:
                print(f"    failed: {e}")
    open(os.path.join(d, "ATTRIBUTION.txt"), "w").write("IP Geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0.\n")
    print(f"[+] {d}: {', '.join(sorted(os.listdir(d)))}  — restart the console to load")


def cmd_site(a):
    p = os.path.join(os.path.abspath(a.dir), "rpot.json")
    cfg = load_config(p)
    cfg["site"] = {"name": a.name, "lat": a.lat, "lon": a.lon}
    save_config(cfg, p)
    print(f"[+] site = {cfg['site']}")


def cmd_show(a):
    cfg = load_config(os.path.join(os.path.abspath(a.dir), "rpot.json"))
    co = cfg["company"]
    print(f"{co['name']} ({co['profile']}) domain={co['domain']} netbios={co['netbios']} users={len(co['users'])}")
    for s in cfg["sensors"]:
        print(f"  {s['name']:<6} {s['role']:<22} {s['ip']}")
    print("tokens:")
    for tid, t in cfg["tokens"].items():
        what = t.get("username", "") + (" / " + t["password"] if t.get("password") else "")
        print(f"  {tid} {t['kind']:<10} {what:<34} valid_on={','.join(t.get('valid_on', [])) or '-':<18} {t['planted']}")


def _manager_cfg(path):
    """rpot.json for the read-only manager commands (slots, export): readable and schema v2, else exit 1."""
    try:
        return check_version(load_config(path))
    except (OSError, ValueError) as e:
        sys.exit(f"error: {path}: {e}")


def cmd_slots(a):
    """One JSON line {max, used, local, remote, pending} (the installer parses the LAST stdout line)."""
    import sqlite3
    import time
    from rpot.console.export import ro_uri
    from rpot.console.fleet import slot_counts
    cfg = _manager_cfg(a.config)
    try:
        local = list(dict.fromkeys(str(s["name"]).upper() for s in cfg.get("sensors", [])))   # = Fleet.local_names
    except (KeyError, TypeError):
        sys.exit(f"error: {a.config}: malformed 'sensors' list")
    try:
        conn = sqlite3.connect(ro_uri(a.db), uri=True, timeout=10)
        try:
            d = slot_counts(conn, local, time.time())
        finally:
            conn.close()
    except sqlite3.Error as e:
        sys.exit(f"error: cannot read the manager database {a.db}: {e}")
    print(json.dumps({k: d[k] for k in ("max", "used", "local", "remote", "pending")}, separators=(",", ":")))


def cmd_export(a):
    """JSON Export to stdout (same module as the console's /api/export). Exit 2 = bad range, 3 = too large."""
    import sqlite3
    from rpot.console import export as X
    _manager_cfg(a.config)
    try:
        d1, d2 = X.parse_dates(a.date_from, a.date_to)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    rng = X.day_range(d1, d2)
    try:
        conn = X.open_snapshot(a.db)
    except sqlite3.Error as e:
        sys.exit(f"error: cannot read the manager database {a.db}: {e}")
    try:
        st = X.stats(conn, rng)
        if st["bytes"] > X.MAX_BYTES:
            print(f"error: export too large ({st['incidents']} incidents, {st['alerts']} alerts, about "
                  f"{st['bytes']} bytes; the limit is {X.MAX_BYTES}): narrow the date range", file=sys.stderr)
            sys.exit(3)
        last = ""
        out = sys.stdout
        for chunk in X.iter_json(conn, rng, X.build_meta(d1, d2, st)):
            out.write(chunk)
            last = (last + chunk)[-len(X.TAIL):]
        if last != X.TAIL:
            out.flush()
            print(f"\nerror: export cut off at the {X.MAX_BYTES}-byte limit (no \"complete\"): "
                  "narrow the date range", file=sys.stderr)
            sys.exit(3)
        out.write("\n")
        out.flush()
    except sqlite3.Error as e:
        sys.exit(f"error: export failed reading {a.db}: {e}")
    except BrokenPipeError:
        sys.exit(1)
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(prog="rpotctl", description="ReD-Pot deployment tool")
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("roles").set_defaults(fn=cmd_roles)
    p = sp.add_parser("init")
    p.add_argument("-d", "--dir", required=True)
    p.add_argument("--profile", default="generic", choices=sorted(B.PROFILES))
    p.add_argument("--web-theme", default="webmail", choices=["webmail", "helpdesk", "intranet"],
                   help="front page of the web decoy (company webmail / IT service desk / intranet)")
    p.add_argument("--domain", required=True,
                   help="AD/DNS domain the decoys belong to, e.g. corp.araratbank.am "
                        "(company name, NetBIOS and mail domain are derived from it)")
    p.add_argument("--sensor", action="append",
                   help=f"host mode: HOSTNAME=role@IP%%IFACE (the interface's own IP, one decoy per interface); "
                        f"bridge lab: HOSTNAME=role[@IP]. At most {MAX_DECOYS} (Community Edition)")
    p.add_argument("--subnet", default="172.30.0.0/24", help="bridge lab only: the isolated decoy network")
    p.add_argument("--console-ip", help="bridge lab only: the manager's address on the lab network")
    p.add_argument("--canary-url", help="URL clients use to reach the console for document beacons")
    p.add_argument("--allow", action="append", help="allowlisted scanner CIDR (repeatable)")
    p.add_argument("--internal", action="append",
                   help="extra internal CIDR, e.g. your own public range (repeatable; private ranges are always internal)")
    p.add_argument("--net-mode", default="bridge", choices=list(NET_MODES),
                   help="host = production, each decoy on its interface's own IP; bridge = isolated Docker lab")
    p.add_argument("--ui-port", type=int, default=8740, help="host port of the web UI (HTTPS)")
    p.add_argument("--sensor-port", type=int, default=8741, help="host port of the sensor API (HTTPS, remote sensors)")
    p.add_argument("--public-ip", help="static public IP of this manager (remote sensors, beacons, certificate)")
    p.add_argument("--mgmt-ip", help="management interface IP (UI + sensor API are published only there)")
    p.add_argument("--site-name", help="name of the protected site on the world map")
    p.add_argument("--site-lat", type=float)
    p.add_argument("--site-lon", type=float)
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)
    p = sp.add_parser("baits"); p.add_argument("-d", "--dir", required=True); p.set_defaults(fn=cmd_baits)
    p = sp.add_parser("tls", help="show (or --renew) the manager certificate")
    p.add_argument("-d", "--dir", required=True); p.add_argument("--renew", action="store_true"); p.set_defaults(fn=cmd_tls)
    p = sp.add_parser("compose")
    p.add_argument("-d", "--dir", required=True)
    p.add_argument("--image", default=f"rpot:{VERSION}")
    p.add_argument("--ui-bind", help="host IP to publish UI + sensor ports on (default: mgmt_ip or all)")
    p.set_defaults(fn=cmd_compose)
    p = sp.add_parser("show"); p.add_argument("-d", "--dir", required=True); p.set_defaults(fn=cmd_show)
    p = sp.add_parser("add-sensor", help="add a local decoy to an existing deployment")
    p.add_argument("-d", "--dir", required=True)
    p.add_argument("--sensor", required=True, help="HOSTNAME=role@IP%%IFACE (host mode) or HOSTNAME=role[@IP] (bridge lab)")
    p.add_argument("--image", default=f"rpot:{VERSION}")
    p.set_defaults(fn=cmd_add_sensor)
    p = sp.add_parser("remove-sensor", help="remove a local decoy")
    p.add_argument("-d", "--dir", required=True); p.add_argument("--name", required=True)
    p.add_argument("--image", default=f"rpot:{VERSION}")
    p.set_defaults(fn=cmd_remove_sensor)
    p = sp.add_parser("wall-url", help="read-only kiosk link for SOC wall screens")
    p.add_argument("-d", "--dir", required=True)
    p.add_argument("--base", help="console URL as seen from the screen (default: console.url in rpot.json)")
    p.add_argument("--rotate", action="store_true", help="issue a new token (invalidates old links)")
    p.set_defaults(fn=cmd_wall_url)
    p = sp.add_parser("geoip"); p.add_argument("-d", "--dir", required=True)
    p.add_argument("--city", action="store_true", help="also fetch the ~130 MB city database (precise map points)")
    p.set_defaults(fn=cmd_geoip)
    p = sp.add_parser("site"); p.add_argument("-d", "--dir", required=True); p.add_argument("--name", required=True)
    p.add_argument("--lat", type=float, required=True); p.add_argument("--lon", type=float, required=True)
    p.set_defaults(fn=cmd_site)
    p = sp.add_parser("slots", help="decoy slots in use: one JSON line {max,used,local,remote,pending}")
    p.add_argument("--db", required=True); p.add_argument("--config", required=True)
    p.set_defaults(fn=cmd_slots)
    p = sp.add_parser("export", help="JSON export of incidents + alert records for UTC days FROM..TO to stdout")
    p.add_argument("--db", required=True); p.add_argument("--config", required=True)
    p.add_argument("--from", dest="date_from", required=True, help="YYYY-MM-DD (UTC)")
    p.add_argument("--to", dest="date_to", required=True, help="YYYY-MM-DD (UTC, inclusive)")
    p.set_defaults(fn=cmd_export)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
