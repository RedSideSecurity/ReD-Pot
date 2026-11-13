#!/usr/bin/env python3
"""ReD-Pot interactive installer (stdlib only; runs on the host as root).

  install.sh                       → menu: [1] manager + sensors  [2] sensor only
  install.sh manager [options]     → standalone manager (+ local decoys)
  install.sh sensor [--join - | --join-file FILE] [options]
                                   → remote sensor; the join string is pasted when asked, read from stdin (--join -)
                                     or from a root-only file — never put it on the command line (ps shows it)
  install.sh add-decoy [options]   → one more decoy on a free interface of an existing manager install
                                     (persona + baits kept)
  install.sh remove-decoy NAME     → remove a local decoy
  install.sh export --from D --to D [-o FILE] [--force]
                                   → JSON export of incidents + alert records (manager)

Community Edition: up to MAX_DECOYS decoys in total (this manager's + remote sensors), one decoy per
network interface, each on that interface's own IP.

Everything is asked interactively; every question also has a flag for unattended installs
(--yes accepts the defaults). --dry-run prints what would be done without changing the host.
"""
import argparse
import ipaddress
import glob
import json
import os
import random
import shlex
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_version(repo=REPO):
    """VERSION from rpot/__init__.py (the single source), read as text: the installer must not import rpot."""
    with open(os.path.join(repo, "rpot", "__init__.py"), encoding="utf-8") as f:
        m = re.search(r'^VERSION\s*=\s*["\']([0-9A-Za-z.+-]+)["\']', f.read(), re.M)
    if not m:
        raise RuntimeError("VERSION not found in rpot/__init__.py")
    return m.group(1)


VERSION = _read_version()
IMAGE = f"rpot:{VERSION}"
REGISTRY_IMAGE = "ghcr.io/redsidesecurity/red-pot:" + VERSION   # prebuilt, published with each release
SRC_PATHS = ("Dockerfile", "requirements.txt", "rpotctl.py", "deploy", "rpot", "roles")
RED, BOLD, DIM, GREEN, YEL, RST = "\033[38;5;196m", "\033[1m", "\033[2m", "\033[32m", "\033[33m", "\033[0m"
ROLE_UDP = {}   # role → ports served ONLY over UDP (DC: ntp 123, nbns 137); filled by role_catalog()
ROLE_PORTS = {"windows-file-server": {135, 139, 445, 3389}, "linux-web-hosting": {22, 80, 443}, "ftp-backup-server": {21, 22}}
ROLE_TITLE = {"windows-file-server": "Windows File Server", "linux-web-hosting": "Linux Web Hosting",
              "ftp-backup-server": "FTP / Backup Server"}
ROLE_DEFAULT = {"windows-file-server": "FS01", "linux-web-hosting": "WEB01", "ftp-backup-server": "BKP01"}
ROLE_OS = {}
A = None   # parsed args

# Community Edition decoy cap. Also in rpot/common/edition.py and the console's SQL trigger — keep them equal.
# The installer must not import the rpot package, so the constant and the message are mirrored here.
MAX_DECOYS = 3
UPGRADE_URL = "https://redsidesecurity.com"
DECOY_UID = 10001          # uid of every ReD-Pot container process (Dockerfile: useradd -u 10001 rpot)


def limit_message(used):
    """Same text as rpot.common.edition.limit_message (a test keeps them identical)."""
    return (f"ReD-Pot Community Edition supports up to {MAX_DECOYS} decoys in total "
            f"(decoys on this manager plus remote sensors); this install uses {used}. "
            "Remove a decoy, revoke a remote sensor or cancel a pending join first — "
            f"or ask RedSide Security about ReD-Pot Enterprise: {UPGRADE_URL}")


def is_windows(rid):
    return "windows" in (ROLE_OS.get(rid) or rid).lower()


# ----------------------------------------------------------------------------- helpers
def banner(t):
    print(f"\n{RED}{BOLD}── {t} {'─' * max(0, 60 - len(t))}{RST}")


def info(t):
    print(f"  {t}")


def warn(t):
    print(f"  {YEL}! {t}{RST}")


def die(t):
    print(f"\n{RED}✗ {t}{RST}")
    sys.exit(1)


READ_ONLY = ("ip", "ss", "ping", "getent", "dpkg", "apt-cache", "fuser", "systemctl is-active", "ufw status", "docker image inspect",
             "docker compose version", "sshd -t", "/usr/sbin/sshd -t", "apt-get -s")


def run(cmd, check=True, capture=False, quiet=False, env=None):
    """env: extra variables for the child (secrets go here, never into argv — ps shows argv to every user)."""
    text = " ".join(cmd) if isinstance(cmd, list) else cmd
    # --dry-run: only read-only probes really execute; anything that changes the host is printed instead
    if A and A.dry_run and not any(text.startswith(p) for p in READ_ONLY):
        print(f"  {DIM}[dry-run] {text}{RST}")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str), text=True, env=dict(os.environ, **env) if env else None,
                           stdout=subprocess.PIPE if capture or quiet else None,
                           stderr=subprocess.PIPE if capture or quiet else None)
    except FileNotFoundError:          # program not installed → a normal failure, never a traceback
        r = subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0] if isinstance(cmd, list) else cmd}: command not found")
    if check and r.returncode != 0:
        die(f"command failed ({r.returncode}): {cmd if isinstance(cmd, str) else ' '.join(cmd)}\n{(r.stderr or '')[-800:]}")
    return r


class Back(Exception):
    """User typed 'back': return to the previous step."""


BACK_WORDS = ("back", "b", "<")


def err(msg):
    print(f"    {RED}✗ {msg}{RST}")


def ask(q, default=None, check=None, flag=None, flagname=None):
    """One question. Wrong answers show a clear error and ask again; 'back' raises Back.
    `flag` answers it non-interactively (unattended installs)."""
    if flag is not None:
        v = str(flag)
        e = check(v) if check else None
        if e:
            die(f"{flagname or q}: {e}")
        print(f"  {q}: {BOLD}{v}{RST}")
        return v
    if A and A.yes:
        if default is None:
            die(f"'{q}' has no default — pass {flagname or 'it as a flag'} (see install.sh --help)")
        e = check(str(default)) if check else None      # defaults are validated like typed answers (B7)
        if e:
            die(f"unattended install (--yes): the default for '{q}' ({default}) does not work here — {e}"
                + (f"\n  Pass {flagname} to choose explicitly (see install.sh --help)." if flagname else ""))
        print(f"  {q}: {BOLD}{default}{RST}")
        return str(default)
    while True:
        hint = f" [{default}]" if default not in (None, "") else ""
        try:
            v = input(f"  {BOLD}?{RST} {q}{hint}: ").strip()
        except EOFError:
            die("input closed — run the installer in an interactive terminal, or pass every answer as a flag (--help)")
        if v.lower() in BACK_WORDS:
            raise Back()
        v = v or (str(default) if default is not None else "")
        if not v:
            err("An answer is required here.")
            continue
        e = check(v) if check else None
        if e:
            err(e)
            continue
        return v


def ask_yes(q, default=True, flag=None):
    v = ask(f"{q} (y/n)", "y" if default else "n",
            lambda x: None if x.lower() in ("y", "yes", "n", "no") else "Type y for yes or n for no.",
            flag=None if flag is None else ("y" if flag else "n"))
    return v.lower().startswith("y")


def pick(q, options, default=None, flag=None, flagname=None, numbers=None, note=None, quiet_list=False):
    """Numbered choice; the user may type the number or the value. options: [(value, label)].
    numbers: display numbers per option (keeps interface numbers identical across questions)."""
    values = [str(v) for v, _ in options]
    nums = [str(n) for n in (numbers or range(1, len(options) + 1))]
    if flag is None and not (A and A.yes):
        print(f"  {BOLD}?{RST} {q}")
        for n, (_, label) in zip(nums, options):
            if not quiet_list:
                print(f"      {RED}{n}{RST}) {label}")
        if note:
            print(f"      {DIM}{note}{RST}")
    dflt = nums[values.index(str(default))] if default is not None and str(default) in values else None
    lower = [x.lower() for x in values]

    def check(v):
        if v in nums or v.lower() in lower:
            return None
        return (f"'{v}' is not one of the choices. Type {', '.join(nums[:-1]) + ' or ' + nums[-1] if len(nums) > 1 else nums[0]}"
                + (f" or a name such as {values[0]}" if not values[0].isdigit() else "") + ".")
    v = ask("choose" if flag is None and not (A and A.yes) else q, dflt, check, flag=flag, flagname=flagname)
    if v.lower() in lower:
        return options[lower.index(v.lower())][0]
    return options[nums.index(v)][0]


def choose(q, options, default=1, flag=None):
    return pick(q, options, options[default - 1][0] if default else None, flag=flag)


# ----------------------------------------------------------------------------- host discovery
def _test_ifaces():
    t = os.environ.get("RPOT_TEST_IFACES")       # automated wizard tests only
    return json.loads(t) if t else None


SKIP_IF = r"^(lo$|docker|br-|veth|virbr|cni|flannel|cali|tun|tap|wg|tailscale|zt)"
# Interface names end up in firewall.sh, sysctl paths, compose YAML and systemd lines. The kernel allows almost
# any byte (quotes, '$', spaces): only plain names are usable; anything else is listed under "Not usable".
IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$")


def valid_iface_name(n):
    return bool(IFACE_RE.fullmatch(n or ""))


def _all_ifaces():
    """[{name, ip|None, prefix, state, carrier, badname}] for physical-ish interfaces (no lo/docker/bridges)."""
    if _test_ifaces() is not None:
        out = [dict(i) for i in _test_ifaces()]
    else:
        try:
            data = json.loads(run(["ip", "-j", "addr", "show"], capture=True).stdout or "[]")
        except ValueError:
            data = []
        out = []
        for d in data:
            n = str(d.get("ifname", ""))
            if re.match(SKIP_IF, n):
                continue
            inet = next((a for a in d.get("addr_info", []) if a.get("family") == "inet"), None)
            out.append({"name": n, "ip": inet["local"] if inet else None, "prefix": inet["prefixlen"] if inet else None,
                        "state": d.get("operstate", "?"), "carrier": "NO-CARRIER" not in d.get("flags", []),
                        "dynamic": bool(inet and inet.get("dynamic"))})
    for i in out:
        i["badname"] = not valid_iface_name(i.get("name"))
        if i["badname"]:                       # never echo raw kernel bytes to the terminal
            i["name"] = re.sub(r"[^\x21-\x7e]", "?", str(i.get("name")))[:32]
    return out


def _usable(i):
    return bool(i.get("ip")) and i.get("state") != "DOWN" and i.get("carrier", True) and not i.get("badname")


def interfaces():
    """Usable interfaces: plain name (IFACE_RE), up, carrier, IPv4 address."""
    return [i for i in _all_ifaces() if _usable(i)]


def unusable_interfaces():
    """(name, reason) for interfaces the installer cannot use — shown, never silently hidden."""
    out = []
    for i in _all_ifaces():
        if _usable(i):
            continue
        if i.get("badname"):
            why = "unusual characters in the interface name — rename it (letters, digits, _ . -; max 15)"
        elif i.get("state") == "DOWN" or not i.get("carrier", True):
            why = "DOWN (no cable / no carrier) — connect it and run the installer again"
        else:
            why = "no IPv4 address — configure it (DHCP or static) and run the installer again"
        out.append((i["name"], why))
    return out


def ssh_session_ip():
    if os.environ.get("RPOT_TEST_SSH_IP"):
        return os.environ["RPOT_TEST_SSH_IP"]
    c = os.environ.get("SSH_CONNECTION", "").split()
    if len(c) == 4:
        return c[2]
    # `sudo` drops SSH_CONNECTION: read it from the parent processes (sudo → bash → sshd session)
    pid = os.getppid()
    for _ in range(12):
        if pid <= 1:
            break
        try:
            env = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
            for e in env:
                if e.startswith(b"SSH_CONNECTION="):
                    c = e.split(b"=", 1)[1].decode().split()
                    if len(c) == 4:
                        return c[2]
            pid = int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return None


def ssh_session_addrs():
    """Local addresses that currently carry established SSH sessions (port 22)."""
    if _test_ifaces() is not None:
        return {ssh_session_ip()} - {None}
    r = run(["ss", "-Htn", "state", "established", "( sport = :22 )"], capture=True, check=False)
    out = set()
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            out.add(parts[-2].rsplit(":", 1)[0].strip("[]").removeprefix("::ffff:"))
    return out


def listening_ports():
    ports = set()
    r = run(["ss", "-Htln"], capture=True, check=False)
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) > 3:
            m = re.search(r":(\d+)$", parts[3])
            if m:
                ports.add(int(m.group(1)))
    return ports


def _unit_of(pid, addr, port):
    """systemd unit that owns a listening socket: the service from the process cgroup, or — when
    systemd itself holds it (socket activation) — the .socket unit listening there."""
    if pid == 1:
        r = run(["systemctl", "list-sockets", "--all", "--no-legend", "--no-pager"], capture=True, check=False)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].rsplit(":", 1)[-1] == str(port):
                return parts[1]
        return None
    try:
        for line in open(f"/proc/{pid}/cgroup"):
            m = re.search(r"/([^/]+\.(?:service|scope))\s*$", line.strip())
            if m and m.group(1).endswith(".service"):
                return m.group(1)
    except OSError:
        pass
    return None


SS_LOCAL = re.compile(r"^\[?(.*?)\]?(?:%([^\s:]+))?:(\d+)$")     # addr[%iface]:port, [v6][%iface]:port, *:port


def ifaces_with_addr(ip):
    """Names of the interfaces that carry `ip` (primary or secondary address), from `ip -j addr show`."""
    if _test_ifaces() is not None:
        return {i["name"] for i in _test_ifaces() if i.get("ip") == ip}
    try:
        data = json.loads(run(["ip", "-j", "addr", "show"], capture=True, check=False).stdout or "[]")
    except ValueError:
        return set()
    return {str(d.get("ifname")) for d in data if any(a.get("local") == ip for a in d.get("addr_info", []))}


def _listens_on(addr, scope, ip, here):
    """Does a socket bound to addr (scope = SO_BINDTODEVICE interface from ss's 'addr%iface', or None) answer on
    `ip`? A wildcard bound to one interface (ReD-Pot's NBNS socket: 0.0.0.0%enp0s3) only covers the addresses of
    that interface — VM defect B6: it was taken for every address. `here` = interfaces that carry `ip`."""
    if addr not in ("0.0.0.0", "*", "::", ip):
        return False
    return scope is None or scope in here


def port_owners(ip, ports, skip_ssh=True):
    """Who already listens on `ip` (or on all addresses) for any of `ports`:
    [{port, proto, proc, pid, unit, kind}] — kind: service | redpot | docker | process.
    sshd on 22 is skipped: the installer moves or pins host SSH itself. Sockets bound to one interface
    ('0.0.0.0%eth0' in ss) count only for the addresses of that interface (B6)."""
    out = []
    if _test_ifaces() is not None:
        fake = os.environ.get("RPOT_TEST_BUSY")          # tests: "80/tcp=nginx.service,53/udp=named"
        for item in (fake.split(",") if fake else []):
            pp, _, who = item.partition("=")
            port, _, proto = pp.partition("/")
            if (proto or "tcp") == "udp" and int(port) in IGNORE_UDP:
                continue
            if ports is None or int(port) in ports:
                out.append({"port": int(port), "proto": proto or "tcp", "proc": who.split(".")[0], "pid": 0,
                            "unit": who if who.endswith((".service", ".socket")) else None,
                            "kind": "service" if who.endswith((".service", ".socket")) else "process"})
        return out
    if ports is not None and not ports:
        return out
    here = None
    for proto, flag in (("tcp", "-Htlnp"), ("udp", "-Hulnp")):
        r = run(["ss", flag], capture=True, check=False)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            m = SS_LOCAL.match(parts[3])
            if not m or (ports is not None and int(m.group(3)) not in ports):
                continue
            if m.group(2) is not None and here is None:
                here = ifaces_with_addr(ip)
            if not _listens_on(m.group(1), m.group(2), ip, here or set()):
                continue
            port = int(m.group(3))
            if proto == "udp" and port in IGNORE_UDP:        # DHCP clients: not a service a scan shows
                continue
            pm = re.search(r'\(\("([^"]+)",pid=(\d+)', line)
            proc, pid = (pm.group(1), int(pm.group(2))) if pm else ("?", 0)
            if skip_ssh and proto == "tcp" and port == 22 and proc in ("sshd", "systemd", "ssh", "sshd-session"):
                continue
            kind = "redpot" if proc == "python-lowports" else "docker" if proc == "docker-proxy" else None
            unit = None if kind else _unit_of(pid, m.group(1), port)
            if unit in ("docker.service", "containerd.service"):
                kind, unit = "docker", None
            out.append({"port": port, "proto": proto, "proc": proc, "pid": pid, "unit": unit,
                        "kind": kind or ("service" if unit else "process")})
    uniq = {(o["port"], o["proto"]): o for o in out}
    return [uniq[k] for k in sorted(uniq)]


IGNORE_UDP = {68, 546}


def host_clashes(ip, ports):
    """Human-readable list of port clashes (see port_owners)."""
    return [f"{o['port']}/{o['proto']} ({o['unit'] or o['proc']})" for o in port_owners(ip, ports)]


SSHD_PROCS = ("sshd", "sshd-session", "ssh")


def closed_services(ip, keep, skip_units=()):
    """Review F4a: host services that answer on `ip` today (bound to it or to every address) and that the
    decoy-interface policy closes once a decoy shares that interface: all but host SSH (moved, still allowed), the
    `keep` ports (decoy + admin ports), DHCP clients, ReD-Pot itself, other containers' published ports (Docker
    forwards those; not closed) and units the install stops anyway. → port_owners() rows."""
    return [o for o in port_owners(ip, None) if o["port"] not in keep and o["kind"] not in ("redpot", "docker")
            and o["proc"] not in SSHD_PROCS and o["unit"] not in skip_units]


def confirm_closed_services(st, iface, ip, keep):
    """Review F4a: before anything changes, name the host services on the management interface that become
    unreachable there (a VPN server / another admin path ending on that NIC survives as a live flow, but not the
    next reconnect or reboot) and get an explicit yes — unattended: --close-other-services, otherwise stop."""
    lost = closed_services(ip, keep, st.get("stop_units") or ())
    if not lost:
        return True
    what = ", ".join(f"{o['port']}/{o['proto']} {o['unit'] or o['proc']}" for o in lost)
    warn(f"A decoy shares {iface} ({ip}). With the firewall on, {iface} answers only the decoy's ports, host SSH and "
         f"the admin ports. These host services listen there now and become UNREACHABLE on {iface} — for you too "
         f"(a VPN server or another admin path that ends on this interface stops working at the next reconnect or "
         f"reboot). They keep running and stay reachable on 127.0.0.1 and on interfaces without a decoy:")
    for o in lost:
        print(f"      {YEL}{o['port']}/{o['proto']}{RST}  {o['unit'] or o['proc']}")
    if A.yes and not A.close_other_services:
        die(f"host services on {iface} would become unreachable ({what}) — add --close-other-services to accept "
            f"that, or put the decoy on another interface")
    return ask_yes(f"Close them on {iface}?", False, flag=True if A.close_other_services else None)


def uid_conflicts(uid=None):
    """Review F7: every ReD-Pot container process runs as DECOY_UID. A host account with that uid (local or
    SSSD/LDAP) or a host process running as it would have its outgoing connections rejected by the decoy egress
    guard and would own ReD-Pot's keys. Processes in other pid namespaces (ReD-Pot's own containers) do not count."""
    uid = DECOY_UID if uid is None else uid
    if _test_ifaces() is not None:
        v = os.environ.get("RPOT_TEST_UID_USED")             # tests: "user ldapuser"
        return [v] if v else []
    out = []
    r = run(["getent", "passwd", str(uid)], check=False, capture=True)
    if r.returncode == 0 and (r.stdout or "").strip():
        out.append(f"user {_clean_text(r.stdout.split(':', 1)[0])[:32]} (getent passwd {uid})")
    try:
        mine = os.readlink("/proc/self/ns/pid")
    except OSError:
        mine = None
    procs = set()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            if os.stat(f"/proc/{pid}").st_uid != uid or os.readlink(f"/proc/{pid}/ns/pid") != mine:
                continue
            procs.add(_clean_text(open(f"/proc/{pid}/comm").read().strip())[:32])
        except OSError:
            continue
    if procs:
        out.append(f"process(es) {', '.join(sorted(procs)[:5])}")
    return out


def preflight_uid():
    used = uid_conflicts()
    if used:
        die(f"uid {DECOY_UID} is already used on this host: {'; '.join(used)}. ReD-Pot's containers run as uid "
            f"{DECOY_UID}: the decoy egress firewall would block that user's outgoing connections and they would own "
            f"ReD-Pot's keys and data. Free uid {DECOY_UID} (move that account) or use another host. Nothing was changed.")


def audit_address(st, ip, rid, ips=None):
    """Everything already listening on `ip` (the decoy interface's own address) besides the decoy's own ports
    gives the honeypot away (a "Windows DC" with MySQL on 3306?). Ports the decoy NEEDS must be free; other
    services should go too. System services: stop + disable (default yes, re-enabled by uninstall).
    Containers / hand-started programs: warn. Returns False → choose another interface.
    (`ips` is unused since CE 1.0 — one decoy per address; kept for the sensor path's call.)"""
    title = ROLE_TITLE[rid]
    need = ROLE_PORTS[rid] - {22}                       # 22: host SSH is moved / pinned by the installer
    mine = set(need)
    ours = set(st.get("admin_ports") or ())             # add-decoy: the manager's own ports on this address
    owners = [o for o in port_owners(ip, None) if o["unit"] not in (st.get("stop_units") or [])
              and not (o["port"] in ours and o["kind"] in ("redpot", "docker", "service", "process")
                       and (o["kind"] != "service" or o["proc"] in ("sshd", "ssh", "sshd-session", "systemd")))]
    if not owners:
        return True
    clash = [o for o in owners if o["port"] in need]
    extra = [o for o in owners if o["port"] not in mine]
    if not clash and not extra:
        return True
    def who(o):
        return {"service": f"service {o['unit']}", "redpot": "an existing ReD-Pot decoy",
                "docker": "a Docker container (see: docker ps)",
                "process": f"program '{o['proc']}' (pid {o['pid']}, not a service)"}[o["kind"]]
    if any(o["kind"] == "redpot" for o in owners):
        err("ReD-Pot is already installed here. Run  sudo ./install.sh uninstall  first, or choose another interface.")
        return False
    if clash:
        warn(f"{title} needs ports that are already in use on {ip}:")
        for o in clash:
            print(f"      {RED}{o['port']}/{o['proto']}{RST}  {who(o)}")
    if extra:
        warn(f"These services also answer on {ip}, next to {title}. A real server of that kind would not have them — "
             f"attackers who scan it can tell it is a honeypot:")
        for o in extra:
            print(f"      {YEL}{o['port']}/{o['proto']}{RST}  {who(o)}")
    manual_clash = [o for o in clash if o["kind"] != "service"]
    if manual_clash:
        err("Ports the decoy needs are held by something that is not a system service, so the installer cannot free "
            "them (docker stop <name> / kill <pid>). Stop them yourself, or choose another interface.")
        return False
    for o in extra:
        if o["kind"] != "service":
            warn(f"{o['port']}/{o['proto']}: {who(o)} — cannot be stopped automatically. Stop it yourself, "
                 f"or the decoy can be recognised.")
    units = sorted({o["unit"] for o in clash + extra if o["kind"] == "service"})
    if not units:
        return True
    info(f"{DIM}Stopping them: the decoy looks like a real {title}; ./install.sh uninstall turns them back on.{RST}")
    if A.yes and not A.stop_conflicting:
        if clash:
            die(f"ports busy ({', '.join(host_clashes(ip, need))}) — add --stop-conflicting to stop {', '.join(units)}, "
                f"or choose other roles/interfaces")
        warn("unattended install: leaving them running (add --stop-conflicting to stop them)")
        return True
    if ask_yes(f"Stop and disable {', '.join(units)} during the install?", True,
               flag=True if A.stop_conflicting else None):
        st["stop_units"] = sorted(set(st.get("stop_units") or []) | set(units))
        info(f"{GREEN}OK — {', '.join(units)} will be stopped when you confirm the review (nothing changed yet).{RST}")
        return True
    if clash:
        info("Then the decoy cannot have its ports on this address — choose another interface or another decoy.")
        return False
    warn(f"Leaving them running: {title} on {ip} can be recognised as a honeypot.")
    return True


STOPPED_FILE = "stopped-services.txt"


def stop_conflicting(st, d):
    units = st.get("stop_units") or []
    if not units:
        return
    banner("Freeing decoy ports")
    for u in units:
        run(["systemctl", "disable", "--now", u], check=False, quiet=True)
        if u.endswith(".service"):                      # a socket would start it again on the next connection
            run(["systemctl", "disable", "--now", u[:-8] + ".socket"], check=False, quiet=True)
        info(f"stopped + disabled {u}")
    if not A.dry_run:
        p = os.path.join(d, STOPPED_FILE)
        old = open(p).read().split() if os.path.exists(p) else []
        with open(p, "w") as f:
            f.write("".join(u + "\n" for u in old + [u for u in units if u not in old]))


def restore_stopped(d):
    p = os.path.join(d, STOPPED_FILE)
    if not os.path.exists(p):
        return
    for u in open(p).read().split():
        run(["systemctl", "enable", "--now", u], check=False, quiet=True)
        info(f"re-enabled {u} (it was stopped by the ReD-Pot installer)")


def random_ports(n, avoid):
    used = listening_ports() | set(avoid)
    out = []
    while len(out) < n:
        p = random.randint(49152, 64999)
        if p not in used and p not in out:
            out.append(p)
    return out


def valid_ip(v):
    try:
        ipaddress.ip_address(v)
        return None
    except ValueError:
        return "not a valid IP address"


# ----------------------------------------------------------------------------- docker
def ensure_docker():
    if shutil.which("docker") and run(["docker", "compose", "version"], capture=True, check=False).returncode == 0:
        return
    if A.dry_run:
        info("[dry-run] Docker / docker compose missing — would install docker.io + compose with apt")
        return
    warn("Docker (with the compose plugin) is not installed.")
    if not ask_yes("Install Docker now from the distribution packages?", True, flag=True if A.yes else None):
        die("Docker is required.")
    apt_ready()
    # third-party repos with expired keys only produce warnings; don't let them abort the install
    run("apt-get update -qq", check=False, quiet=True)
    apt = "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
    # one package at a time: a compose package name missing on this distro must not stop Docker itself
    r = None
    if not shutil.which("docker"):
        info("installing docker.io …")
        r = run(apt + "docker.io", check=False, quiet=True)
        if not shutil.which("docker"):
            die("apt could not install docker.io:\n" + ((r.stderr or "") + (r.stdout or ""))[-800:] +
                "\nInstall Docker manually (https://docs.docker.com/engine/install/) and run the installer again.")
    run(["systemctl", "enable", "--now", "docker"], check=False, quiet=True)
    if run(["docker", "compose", "version"], capture=True, check=False).returncode != 0:
        for compose_pkg in ("docker-compose-v2", "docker-compose-plugin", "docker-compose"):
            info(f"installing {compose_pkg} …")
            r = run(apt + compose_pkg, check=False, quiet=True)
            if run(["docker", "compose", "version"], capture=True, check=False).returncode == 0:
                break
        else:
            compose_binary()
    if run(["docker", "compose", "version"], capture=True, check=False).returncode != 0:
        die("Docker is installed but the 'docker compose' plugin is not:\n" + ((r.stderr or "") if r else "")[-600:] +
            "\nInstall it manually (https://docs.docker.com/compose/install/linux/) and run the installer again.")
    run(["systemctl", "enable", "--now", "docker"], check=False)


COMPOSE_VERSION = "v2.29.7"


def compose_binary():
    """Last resort: official docker compose plugin binary from GitHub, verified by its published SHA-256."""
    import hashlib
    import platform
    import urllib.request
    arch = {"x86_64": "x86_64", "aarch64": "aarch64"}.get(platform.machine())
    if not arch:
        return
    name = f"docker-compose-linux-{arch}"
    base = f"https://github.com/docker/compose/releases/download/{COMPOSE_VERSION}/"
    info(f"apt has no compose plugin — downloading the official {name} {COMPOSE_VERSION}")
    try:
        blob = urllib.request.urlopen(base + name, timeout=120).read()
        sums = urllib.request.urlopen(base + name + ".sha256", timeout=30).read().decode().split()[0]
    except Exception as e:
        warn(f"download failed: {e}")
        return
    if hashlib.sha256(blob).hexdigest() != sums:
        warn("docker compose checksum mismatch — not installed")
        return
    d = "/usr/local/lib/docker/cli-plugins"
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "docker-compose"), "wb") as f:
        f.write(blob)
    os.chmod(os.path.join(d, "docker-compose"), 0o755)


def apt_ready():
    """Real servers are often left with a half-finished package update ('dpkg was interrupted').
    Repair that first, and wait for unattended-upgrades holding the apt lock."""
    if A.dry_run:
        return
    for _ in range(60):
        if run("fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock", capture=True, check=False).returncode != 0:
            break
        info("waiting for another package manager (unattended-upgrades?) to finish…")
        time.sleep(5)
    audit = run(["dpkg", "--audit"], capture=True, check=False)
    broken = run("apt-get -s -f install 2>&1 | grep -qE 'not fully installed|Inst |Conf '", capture=True, check=False).returncode == 0
    if (audit.stdout or "").strip() or broken:
        warn("the package manager was left half-configured by an earlier update — repairing "
             "(dpkg --configure -a; apt-get -f install)")
        run("DEBIAN_FRONTEND=noninteractive dpkg --configure -a", check=False, quiet=True)
        run("apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get -f install -y -qq", check=False, quiet=True)
    repair_dpkg_lists()


DPKG_INFO = "/var/lib/dpkg/info"


def damaged_dpkg_lists(info_dir=DPKG_INFO):
    """dpkg file lists ruined by a power cut (zero-filled, foreign data, cut off). dpkg then refuses
    EVERY install with 'files list file for package X is missing final newline'."""
    bad = []
    for f in sorted(glob.glob(os.path.join(info_dir, "*.list"))):
        try:
            b = open(f, "rb").read()
        except OSError:
            continue
        if b and (not b.endswith(b"\n") or b"\0" in b or any(l and not l.startswith(b"/") for l in b.split(b"\n"))):
            bad.append(f)
    return bad


def dpkg_list_from_deb(deb):
    """The file list dpkg would have written for this .deb ('/.', '/usr', '/usr/bin/x', …)."""
    r = run(f"dpkg-deb --fsys-tarfile {shlex.quote(deb)} | tar -t", capture=True, check=False)
    out = []
    for n in (r.stdout or "").splitlines():
        n = (n[1:] if n.startswith(".") else n).rstrip("/") or "/."
        out.append(n)
    return out


def repair_dpkg_lists():
    bad = damaged_dpkg_lists()
    if not bad:
        return
    pkgs = [os.path.basename(f)[:-5] for f in bad]
    warn(f"The package database is damaged (usually after a power cut): file lists of {', '.join(pkgs)}.")
    warn("Until this is repaired, apt cannot install anything — including Docker.")
    if not ask_yes("Repair it now (rebuild the lists from the original packages, then reinstall them)?", True,
                   flag=True if A.yes else None):
        die("Repair cancelled. Fix the package database (see the message above) and run the installer again.")
    import tempfile
    tmp = tempfile.mkdtemp()
    os.chmod(tmp, 0o755)                       # apt downloads as _apt
    names = []
    for f, pkg in zip(bad, pkgs):
        name = pkg.split(":")[0]
        ver = run(["dpkg-query", "-W", "-f=${Version}", pkg], capture=True, check=False).stdout.strip()
        run(f"cd {shlex.quote(tmp)} && apt-get download -qq {shlex.quote(name + '=' + ver)}", check=False, quiet=True)
        debs = glob.glob(os.path.join(tmp, f"{name}_*.deb"))
        lst = dpkg_list_from_deb(debs[0]) if debs else []
        if not lst:
            die(f"could not download {name} {ver} to rebuild its file list — check internet/apt sources, then retry")
        shutil.copy2(f, f + ".redpot-damaged")
        with open(f, "w") as fh:
            fh.write("\n".join(lst) + "\n")
        names.append(name)
        info(f"rebuilt {os.path.basename(f)} ({len(lst)} files)")
    r = run("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall " + " ".join(map(shlex.quote, names)),
            check=False, quiet=True)
    if r.returncode != 0:
        die("reinstalling the repaired packages failed:\n" + ((r.stderr or "") + (r.stdout or ""))[-800:])
    shutil.rmtree(tmp, ignore_errors=True)
    info(f"{GREEN}package database repaired{RST}")


def src_hash(root=None):
    """SHA-256 over everything that goes into the image (same function at build time → image label).
    A downloaded image is used ONLY if it was built from exactly this code."""
    import hashlib
    root = root or REPO
    h = hashlib.sha256()
    files = []
    for p in SRC_PATHS:
        full = os.path.join(root, p)
        if os.path.isfile(full):
            files.append(p)
        for dp, dns, fns in os.walk(full):
            dns[:] = sorted(d for d in dns if d != "__pycache__")
            files += [os.path.relpath(os.path.join(dp, f), root) for f in fns if not f.endswith((".pyc", ".pyo"))]
    for rel in sorted(set(files)):
        h.update(rel.replace(os.sep, "/").encode() + b"\0")
        with open(os.path.join(root, rel), "rb") as f:
            h.update(f.read())
        h.update(b"\0")
    return h.hexdigest()


def _image_src(ref):
    r = run(["docker", "image", "inspect", "-f", '{{index .Config.Labels "io.redside.src-sha256"}}', ref],
            capture=True, check=False)
    return (r.stdout or "").strip() if r.returncode == 0 else ""


def ensure_image():
    """Prebuilt image from ghcr.io when it matches this checkout (fast, identical for every customer);
    otherwise — offline, modified code, --build — build locally from this checkout."""
    want = src_hash()
    if not A.dry_run and _image_src(IMAGE) == want:
        info(f"{DIM}ReD-Pot image {IMAGE} is up to date{RST}")
        return
    if not getattr(A, "build", False):
        banner("Downloading the ReD-Pot image")
        info(f"{DIM}{REGISTRY_IMAGE}{RST}")
        r = run(["docker", "pull", "-q", REGISTRY_IMAGE], check=False, capture=True)
        if r.returncode == 0 or A.dry_run:
            got = _image_src(REGISTRY_IMAGE)
            if A.dry_run or got == want:
                run(["docker", "tag", REGISTRY_IMAGE, IMAGE], check=False, quiet=True)
                info(f"{GREEN}prebuilt image verified (built from exactly this code){RST}")
                return
            warn("the downloaded image was built from different code than this checkout "
                 "(local changes or a newer commit) — building locally instead")
        else:
            why = (r.stderr or r.stdout or "").strip().splitlines()
            why = why[-1][-160:] if why else "no answer"
            hint = ("the image is not public (yet)" if re.search(r"denied|unauthorized|forbidden", why, re.I)
                    else "not published for this version" if re.search(r"not found|manifest unknown", why, re.I)
                    else "offline or registry unreachable")
            warn(f"could not download the prebuilt image — {hint} ({why}) — building locally")
    first = run(["docker", "image", "inspect", IMAGE], capture=True, check=False).returncode != 0
    banner("Building the ReD-Pot image" + (" (first install, a few minutes)" if first else " (cached, quick)"))
    r = run(["docker", "build", "-q", "--build-arg", f"SRC_SHA={want}", "--build-arg", f"VERSION={VERSION}", "-t", IMAGE, REPO], check=False, capture=True)
    if r.returncode != 0:
        die("docker build failed:\n" + (r.stderr or r.stdout or "")[-1200:])


def ctl(deploy_dir, *args):
    """Run rpotctl inside the image (it has all Python dependencies); show its real error on failure."""
    r = run(["docker", "run", "--rm", "--user", "0", "-e", "RPOT_INSTALLER=1", "-v", f"{deploy_dir}:/d", IMAGE, "ctl", *args],
            check=False, capture=True)
    if r.returncode != 0:
        die(f"rpotctl {args[0]} failed:\n{(r.stdout or '')[-400:]}{(r.stderr or '')[-800:]}")
    if r.stdout:
        print("\n".join("  " + l for l in r.stdout.strip().splitlines()[-6:]))
    return r


# ----------------------------------------------------------------------------- SSH move (T-Pot style)
def sshd_bin():
    return shutil.which("sshd") or "/usr/sbin/sshd"


def sshd_config_ok():
    """`sshd -t`. Ubuntu ≥ 22.10 starts sshd on demand (ssh.socket): until the first login after boot
    /run/sshd does not exist and the test fails with 'Missing privilege separation directory'."""
    if not A.dry_run:
        os.makedirs("/run/sshd", mode=0o755, exist_ok=True)
    r = run([sshd_bin(), "-t"], capture=True, check=False)
    if r.returncode != 0:
        warn("sshd -t: " + (r.stderr or r.stdout or "").strip()[-300:])
    return r.returncode == 0


def sshd_effective(key):
    """Values sshd will really use (all config files merged), e.g. key='port' → {'22', '50022'}."""
    if not A.dry_run:
        os.makedirs("/run/sshd", mode=0o755, exist_ok=True)
    r = run([sshd_bin(), "-T"], capture=True, check=False)
    return {l.split(None, 1)[1].strip() for l in (r.stdout or "").splitlines() if l.lower().startswith(key + " ")}


SSH_DROPIN_BAK = ".redpot-port.bak"


def _neutralise_other_ports(d):
    """Port lines in OTHER sshd_config.d files (cloud-init, hosting panels) add up with ours —
    sshd would keep listening on 22. Comment them out (backup kept, restored by uninstall)."""
    changed = []
    for f in sorted(glob.glob(os.path.join(d, "*.conf"))):
        if os.path.basename(f).startswith("00-redpot"):
            continue
        txt = open(f).read()
        if re.search(r"(?mi)^\s*Port\s+\d+", txt):
            shutil.copy2(f, f + SSH_DROPIN_BAK)
            open(f, "w").write(re.sub(r"(?mi)^\s*Port\s+\d+", lambda m: "#" + m.group(0) + "  # ReD-Pot", txt))
            changed.append(f)
    if changed:
        info(f"commented out Port lines in {', '.join(changed)} (backup *{SSH_DROPIN_BAK}, restored by uninstall)")
    return changed


def move_ssh(port):
    """Move the host's SSH daemon to `port`. Existing sessions stay connected. Safe order:
    listen on BOTH 22 and the new port, verify, then drop 22."""
    if A.dry_run:
        info(f"[dry-run] would move host SSH to port {port}")
        return True
    d = "/etc/ssh/sshd_config.d"
    main = "/etc/ssh/sshd_config"
    explicit = re.findall(r"(?mi)^\s*ListenAddress\s+\S+:\d+", open(main).read() + "".join(
        open(f).read() for f in glob.glob(os.path.join(d, "*.conf")) if os.path.isfile(f)))
    if explicit:
        die("sshd_config has ListenAddress lines with a port (" + "; ".join(x.strip() for x in explicit) +
            ") — those override Port, so SSH cannot be moved safely. Remove the ':port' part, then run the installer again.")
    if os.path.isdir(d):
        _neutralise_other_ports(d)
    if not os.path.isdir(d) or "Include /etc/ssh/sshd_config.d" not in open(main).read():
        # old distros: comment existing Port lines in the main file
        txt = open(main).read()
        shutil.copy2(main, main + ".redpot.bak")
        txt = re.sub(r"(?m)^\s*Port\s+\d+", lambda m: "#" + m.group(0) + "  # ReD-Pot", txt)
        open(main, "w").write(f"Port 22\nPort {port}\n" + txt)
        conf = None
    else:
        txt = open(main).read()
        if re.search(r"(?m)^\s*Port\s+\d+", txt):
            shutil.copy2(main, main + ".redpot.bak")
            open(main, "w").write(re.sub(r"(?m)^\s*Port\s+\d+", lambda m: "#" + m.group(0) + "  # ReD-Pot", txt))
        conf = os.path.join(d, "00-redpot-port.conf")
        open(conf, "w").write(f"# ReD-Pot: decoys need port 22; real SSH moved\nPort 22\nPort {port}\n")
    if not sshd_config_ok():
        if os.path.exists(main + ".redpot.bak"):          # put everything back before giving up
            shutil.copy2(main + ".redpot.bak", main)
        if conf and os.path.exists(conf):
            os.remove(conf)
        die("sshd configuration test failed — original config restored, nothing restarted.")
    _restart_ssh()
    for _ in range(20):
        if port in listening_ports():
            break
        time.sleep(0.5)
    else:
        die(f"sshd did not start listening on {port} — port 22 is still open, nothing lost. Check 'systemctl status ssh'.")
    # verified → drop 22
    if conf:
        open(conf, "w").write(f"# ReD-Pot: decoys need port 22; real SSH moved\nPort {port}\n")
    else:
        txt = open(main).read().replace("Port 22\n", "", 1)
        open(main, "w").write(txt)
    _restart_ssh()
    for _ in range(20):
        if not _ssh_on_22() and port in listening_ports():
            break
        time.sleep(0.5)
    else:
        ports = sshd_effective("port")
        die(f"host SSH still listens on 22 (sshd ports now: {', '.join(sorted(ports)) or '?'}; port {port} works). "
            f"Something else in /etc/ssh keeps port 22 — check 'sshd -T | grep -i port' and the files in {d}.")
    info(f"{GREEN}host SSH now listens on port {port} only (verified){RST}")
    if shutil.which("ufw") and "active" in run(["ufw", "status"], capture=True, check=False).stdout:
        run(["ufw", "allow", f"{port}/tcp"], check=False, quiet=True)
    return True


def mgmt_decoys(st):
    """Roles on the management interface: they share THIS server's address with SSH + web UI → SSH moves."""
    return [r for r in st.get("roles") or [] if st["role_if"].get(r) == st["mgmt"]]


def other_decoys(st):
    """Roles on another interface's own address → host SSH is pinned to the management IP."""
    return [r for r in st.get("roles") or [] if st["role_if"].get(r) != st["mgmt"]]


PIN_CONF = "/etc/ssh/sshd_config.d/00-redpot-listen.conf"


def ssh_keep_addrs(ip, decoy_ips=()):
    """Addresses host SSH keeps: management IP, loopback, and every address that carries a live
    SSH session right now (so pinning never locks the admin out) — but never a decoy-owned IP."""
    live = sorted(a for a in ssh_session_addrs()
                  if a not in (ip, "127.0.0.1") and a not in decoy_ips and valid_ip(a) is None)
    return [ip, "127.0.0.1"] + live


def pin_ssh(ip, decoy_ips=(), port=22):
    """A decoy owns a dedicated NIC's IP → host SSH must stop listening on all addresses (port 22
    on the decoy IP belongs to the decoy). Pin it to the management IP + loopback, verify, else undo."""
    banner(f"Host SSH: listen only on {ip}")
    if A.dry_run:
        info(f"[dry-run] would pin host SSH to {ip}:{port}")
        return
    d, main = os.path.dirname(PIN_CONF), "/etc/ssh/sshd_config"
    if not os.path.isdir(d) or "Include /etc/ssh/sshd_config.d" not in open(main).read():
        die("this sshd has no sshd_config.d include — add 'ListenAddress <management IP>' to sshd_config yourself, "
            "then run the installer again")
    if re.search(r"(?m)^\s*ListenAddress\s+(0\.0\.0\.0|::|\*)", open(main).read()):
        die("sshd_config has ListenAddress 0.0.0.0 — change it to the management IP first, then re-run")
    # never lock the admin out: also keep every address that carries an SSH session right now
    keep = ssh_keep_addrs(ip, decoy_ips)
    if any(a in decoy_ips for a in ssh_session_addrs()):
        warn(f"You are connected over SSH to a decoy address ({', '.join(a for a in ssh_session_addrs() if a in decoy_ips)}). "
             f"This session stays open, but next time connect to {ip}.")
    with open(PIN_CONF, "w") as f:
        f.write("# ReD-Pot: a decoy owns port 22 on the decoy interface; real SSH only on these addresses\n"
                + "".join(f"ListenAddress {a}\n" for a in keep))
    if not sshd_config_ok():
        os.remove(PIN_CONF)
        die("sshd configuration test failed — change removed, nothing restarted.")
    _restart_ssh()
    for _ in range(20):
        r = run(["ss", "-Htln", "sport", f"= :{port}"], capture=True, check=False).stdout or ""
        addrs = {l.split()[3].rsplit(":", 1)[0].strip("[]") for l in r.splitlines() if len(l.split()) > 3}
        if ip in addrs and not addrs & {"0.0.0.0", "*", "::"}:
            info(f"{GREEN}host SSH now listens on port {port} of {', '.join(keep)} only{RST}")
            return
        time.sleep(0.5)
    os.remove(PIN_CONF)
    _restart_ssh()
    die(f"sshd did not move to {ip}:{port} only (seen: {', '.join(sorted(addrs)) or 'nothing'}) — change undone. "
        f"Check other ListenAddress lines in /etc/ssh, then run the installer again.")


def unpin_ssh():
    if os.path.exists(PIN_CONF) and not A.dry_run:
        os.remove(PIN_CONF)
        _restart_ssh()
        info(f"{GREEN}host SSH listens on all addresses again{RST}")


def _ssh_on_22():
    r = run(["ss", "-Htlnp", "sport", "= :22"], capture=True, check=False)
    return any(x in (r.stdout or "") for x in ('"sshd', '"sshd-session', '"systemd"'))


def _ssh_socket_mode():
    """Ubuntu ≥ 22.10: sshd is started by ssh.socket (its generator reads Port/ListenAddress)."""
    act = run(["systemctl", "is-active", "ssh.socket"], capture=True, check=False).stdout.strip()
    ena = run(["systemctl", "is-enabled", "ssh.socket"], capture=True, check=False).stdout.strip()
    return act == "active" or (ena == "enabled" and act != "inactive") or (ena == "enabled" and
        run(["systemctl", "is-active", "ssh.service"], capture=True, check=False).stdout.strip() != "active")


def _restart_ssh():
    """Restart sshd so it picks up the new config. Several restarts in a row (move: listen on both
    ports, then drop 22) can trip systemd's start limit ('start-limit-hit') and leave SSH DOWN —
    so reset that counter first and retry once."""
    socket = _ssh_socket_mode()
    gen = any(os.path.exists(os.path.join(g, "sshd-socket-generator"))
              for g in ("/usr/lib/systemd/system-generators", "/lib/systemd/system-generators"))
    if socket and not gen:
        # Ubuntu ≤ 22.04 ships an inetd-style ssh.socket with ListenStream=22 hard-coded: it ignores
        # sshd_config. Switch to the normal ssh.service, which honours Port/ListenAddress.
        info("ssh.socket here has port 22 fixed in its unit — switching to the standard ssh.service")
        run(["systemctl", "disable", "--now", "ssh.socket"], check=False, quiet=True)
        run(["systemctl", "enable", "ssh.service"], check=False, quiet=True)
        socket = False
    units = ["ssh.socket", "ssh.service"] if socket else ["ssh.service", "sshd.service"]
    run(["systemctl", "reset-failed", *units], check=False, quiet=True)
    if socket:
        run(["systemctl", "daemon-reload"], check=False)
        for attempt in range(2):
            run(["systemctl", "stop", "ssh.service"], check=False, quiet=True)     # active listener of the old config
            r = run(["systemctl", "restart", "ssh.socket"], capture=True, check=False)
            if r.returncode == 0:
                return
            time.sleep(2)
            run(["systemctl", "reset-failed", *units], check=False, quiet=True)
        warn("ssh.socket did not restart: " + (r.stderr or "").strip()[-200:])
        return
    for unit in ("ssh", "sshd"):
        for attempt in range(2):
            r = run(["systemctl", "restart", unit], capture=True, check=False)
            if r.returncode == 0:
                return
            if "not found" in (r.stderr or "") or "not loaded" in (r.stderr or ""):
                break
            time.sleep(2)
            run(["systemctl", "reset-failed", unit], check=False, quiet=True)
    run("service ssh restart || service sshd restart || pkill -HUP -x sshd", check=False)


# ----------------------------------------------------------------------------- wizard engine
EXECUTING = False        # True once the host is being changed (Ctrl+C then says so)


def wizard(steps, st):
    """Run steps in order. 'back' in any question returns to the previous step; the review step
    may jump to any step by returning its index. Answers are kept in `st` and offered as defaults
    when a step is shown again, so going back never loses work."""
    i = 0
    total = len(steps) - 1          # the review is not counted as a question step
    while i < len(steps):
        title, fn = steps[i]
        if i < total:
            banner(f"Step {i + 1} of {total} · {title}")
            if i == 0 and not (A.yes or st.get("_hinted")):
                info(f"{DIM}Type 'back' at any question to return to the previous step · Ctrl+C quits without changes{RST}")
                st["_hinted"] = True
        try:
            r = fn(st)
        except Back:
            if i == 0:
                warn("This is the first step — there is nothing to go back to.")
            else:
                i -= 1
                st["_back"] = True          # a multi-item step resumes at its LAST item
            continue
        st["_back"] = False
        i = r if isinstance(r, int) else i + 1


def _subnet(i):
    return ipaddress.ip_network(f"{i['ip']}/{i['prefix']}", strict=False)


def _iface_label(i, sess):
    tag = f"  {DIM}← your SSH session{RST}" if i["ip"] == sess else ""
    return f"{i['name']:<10} {i['ip']}/{i['prefix']:<3} {DIM}{i['state']}{RST}{tag}"


# ----------------------------------------------------------------------------- step: network
def default_decoy_iface(st, cands):
    """A non-management interface without the internet route, else any non-management one, else management."""
    up = route_iface("1.1.1.1")
    return next((n for n in cands if n != st["mgmt"] and n != up),
                next((n for n in cands if n != st["mgmt"]), cands[0] if cands else None))


def pick_decoy_iface(st, current, flag, flagname, cands=None, tags=None):
    """Usable interfaces (`cands`, default all), numbered as in the network step; management is marked.
    Default: the previous answer, else default_decoy_iface."""
    allx = list(st["ifs"])
    cands = list(allx if cands is None else cands)
    if current not in cands:
        current = default_decoy_iface(st, cands)
    return pick("Interface for this decoy",
                [(n, f"{n:<10} {st['ifs'][n]['ip']}/{st['ifs'][n]['prefix']:<3} network {_subnet(st['ifs'][n])}"
                     + (f"   {DIM}(management — this server's address: host SSH moves){RST}" if n == st["mgmt"] else "")
                     + (f"   {DIM}{tags[n]}{RST}" if tags and tags.get(n) else "")) for n in cands],
                current, flag=flag, flagname=flagname, numbers=[allx.index(n) + 1 for n in cands])


def route_iface(ip):
    """Interface the kernel would use to reach ip (default for 'link to the manager')."""
    if _test_ifaces() is not None:
        for i in _test_ifaces():
            try:
                if ipaddress.ip_address(ip) in _subnet(i):
                    return i["name"]
            except ValueError:
                return None
        return next((i["name"] for i in _test_ifaces() if i.get("gw")), None)
    try:
        r = json.loads(run(["ip", "-j", "route", "get", ip], capture=True, check=False).stdout or "[]")
        return r[0].get("dev") if r else None
    except (ValueError, IndexError, AttributeError):
        return None


def _sensor_no_move_error(st):
    return (f"--no-ssh-move keeps host SSH on port 22 of {st['ifs'][st['mgmt']]['ip']}: a decoy on the manager-link "
            f"interface {st['mgmt']} shares that address — use another interface for the decoy or drop --no-ssh-move")


def step_sensor_network(st):
    """CE (D-2): the remote sensor's one decoy answers on its interface's OWN address. The manager link may be
    that interface too (a 1-NIC server / VPS): then host SSH moves and the decoy follows DHCP on it (S-1 L14).
    On another interface the decoy binds that address and host SSH is pinned to the manager-link address."""
    ifs = interfaces()
    bad = unusable_interfaces()
    if not ifs:
        for n, why in bad:
            info(f"   -  {n:<10} {why}")
        die("No usable network interface (up, with an IPv4 address) was found. Configure networking first.")
    sess = ssh_session_ip()
    st["ifs"] = {i["name"]: i for i in ifs}
    names = [i["name"] for i in ifs]
    mhost = st["manager"].rsplit(":", 1)[0]
    if bad:
        info("Not usable:")
        for n, why in bad:
            info(f"   -  {n:<10} {DIM}{why}{RST}")
    if len(ifs) == 1:
        info(f"This server has one usable interface: {_iface_label(ifs[0], sess)}")
        info(f"{DIM}It carries the link to the manager and the decoy, on this server's address — host SSH then "
             f"moves to a random port.{RST}")
        link = decoy = names[0]
        st["mgmt"] = link
        if A.no_ssh_move:
            die(_sensor_no_move_error(st))
    else:
        info("Interfaces on this server:")
        link = pick(f"Which interface reaches the manager ({mhost})?",
                    [(i["name"], _iface_label(i, sess)) for i in ifs],
                    st.get("mgmt") or route_iface(mhost) or next((i["name"] for i in ifs if i["ip"] == sess), names[0]),
                    flag=A.mgmt_if, flagname="--mgmt-if")
        st["mgmt"] = link
        if A.no_ssh_move and A.decoy_if == link:
            die(_sensor_no_move_error(st))
        cands = [n for n in names if not (A.no_ssh_move and n == link)]
        prev = (st.get("decoy_ifaces") or [None])[0]
        decoy = pick("Which interface should the decoy answer on? (it takes that interface's own address)",
                     [(n, _iface_label(st["ifs"][n], sess)
                       + (f"  {DIM}(same as the manager link — host SSH moves){RST}" if n == link else
                          f"  {DIM}(host SSH then listens only on {st['ifs'][link]['ip']}){RST}")) for n in cands],
                     prev if prev in cands else next((n for n in cands if n != link), cands[0]),
                     flag=A.decoy_if, flagname="--decoy-if", numbers=[names.index(n) + 1 for n in cands])
    st["decoy_ifaces"], st["single"] = [decoy], link == decoy
    # decoy address = the interface's own IP (no address question, no new IP on the LAN)
    st["role_if"], st["ips"] = {"_": decoy}, {"_": st["ifs"][decoy]["ip"]}
    info(f"The decoy will answer on {decoy}'s own address {st['ips']['_']}"
         + (" (this server's address — it follows a DHCP change)." if st["single"] else "."))
    info(f"{DIM}The decoy's role (file / web / backup server) was chosen on the manager and arrives with enrollment.{RST}")
    if st["single"]:
        # VM defect B5 (S-1 H2 for SSH on sensors): the decoy shares this interface, so the moved host SSH would be
        # open to its whole LAN — a second, real OpenSSH next to the decoy. Default: the admin's own client (/32);
        # --yes needs --allow-ssh.
        st["allow"] = ask_allowlists(st, st["ifs"][link]["ip"], True, st.get("allow"), keys=("ssh",))
    else:
        st["allow"] = {}             # host SSH listens only on the manager-link address, not on the decoy's LAN


def step_network(st):
    """Management interface first. Decoys then use usable interfaces — one decoy per interface, on that
    interface's own address; the management one included (host SSH then moves) — chosen per decoy in step 4."""
    ifs = interfaces()
    bad = unusable_interfaces()
    if not ifs:
        for n, why in bad:
            info(f"   -  {n:<10} {why}")
        die("No usable network interface (up, with an IPv4 address) was found. Configure networking first.")
    sess = ssh_session_ip()
    st["ifs"] = {i["name"]: i for i in ifs}
    names = [i["name"] for i in ifs]
    what = "your SSH and the link to the manager" if st.get("join") else "your SSH, the web UI, remote sensors"
    if len(ifs) == 1:
        info(f"This server has one usable interface: {_iface_label(ifs[0], sess)}")
        if bad:
            info("Not usable:")
            for n, why in bad:
                info(f"   -  {n:<10} {DIM}{why}{RST}")
        info(f"{DIM}It is used for management and can hold ONE decoy on this server's address (host SSH then moves).{RST}")
        st["mgmt"] = names[0]
    else:
        info("Interfaces on this server:")
        for k, i in enumerate(ifs, 1):
            print(f"      {RED}{k}{RST}) {_iface_label(i, sess)}")
        if bad:
            info("Not usable:")
            for n, why in bad:
                info(f"   -  {n:<10} {DIM}{why}{RST}")
        st["mgmt"] = pick(f"Which interface is for MANAGEMENT ({what})?",
                          [(i["name"], _iface_label(i, sess)) for i in ifs],
                          st.get("mgmt") or next((i["name"] for i in ifs if i["ip"] == sess), names[0]),
                          flag=A.mgmt_if, flagname="--mgmt-if", quiet_list=True)
        info(f"{GREEN}Management: {st['mgmt']} ({st['ifs'][st['mgmt']]['ip']}).{RST} "
             f"{DIM}One decoy per interface, on that interface's own address — this one included.{RST}")
    st["decoy_ifaces"] = names
    st["single"] = len(ifs) == 1


# ----------------------------------------------------------------------------- step: identity
CORP_PREFIXES = ("corp", "ad", "int", "internal", "office", "hq", "dc", "lan")
PROFILES = [("bank", "Bank / finance"), ("hotel", "Hotel / hospitality"), ("government", "Government"),
            ("it", "IT / software company"), ("generic", "Other / generic")]


def _core_label(domain):
    labels = domain.lower().split(".")
    if len(labels) >= 3 and labels[0] in CORP_PREFIXES:
        labels = labels[1:]                               # corp.araratbank.am → araratbank
    return labels[0]


def _check_domain(v):
    if len(v) > 253 or not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+", v.lower()):
        return "Not a valid domain. Use letters, digits and hyphens with at least one dot — for example: corp.example.com"
    if _core_label(v).startswith("xn--"):
        return ("Internationalised (xn--) names cannot be used for the company label — use the ASCII form of the "
                "name, for example corp.araratbank.am")


def _netbios_name(label):
    """Mirror of rpot.baits.netbios_name (parity test): hyphens dropped; > 15 → first word (>= 3 chars) or a cut."""
    parts = [p for p in label.split("-") if p]
    joined = "".join(parts)
    if len(joined) > 15:
        joined = parts[0][:15] if len(parts[0]) >= 3 else joined[:15]
    return joined.upper()


def persona_preview(domain):
    """Company, NetBIOS and mail domain the manager derives from the domain (D-1). A preview only: rpotctl
    (rpot.baits.make_persona / company_from_domain) is the source of truth and its values land in rpot.json."""
    core = _core_label(domain)
    company = " ".join(p.capitalize() for p in core.split("-") if p)
    labels = domain.lower().split(".")
    if len(labels) >= 3 and labels[0] in CORP_PREFIXES:
        labels = labels[1:]
    mail = ".".join(labels)
    if mail.endswith((".local", ".lan", ".internal", ".corp", ".home.arpa")):
        mail = mail.split(".")[0] + ".com"
    return {"company": company, "netbios": _netbios_name(core), "email_domain": mail}


def step_identity(st):
    """D-1: the client sets only the domain and the industry. Company name, NetBIOS name and mail domain are
    derived from the domain; user names come from the built-in pool (random per install)."""
    info(f"{DIM}Decoys must look like YOUR servers: the domain appears in banners, files and certificates. "
         f"Company name, NetBIOS name and mail domain are derived from it.{RST}")
    st["domain"] = ask("Active Directory / DNS domain (e.g. corp.example.com)", st.get("domain"), _check_domain,
                       flag=A.domain, flagname="--domain").lower()
    p = persona_preview(st["domain"])
    info(f"{DIM}→ company {p['company']} · NetBIOS {p['netbios']} · mail @{p['email_domain']}{RST}")
    st["profile"] = pick("Industry (shapes file names and departments)", PROFILES,
                         st.get("profile", "generic"), flag=A.profile, flagname="--profile")


# ----------------------------------------------------------------------------- step: roles
def role_catalog():
    """Roles come from roles/*.json, so new decoy types appear here automatically."""
    cat = []
    for f in sorted(os.listdir(os.path.join(REPO, "roles"))):
        if f.endswith(".json"):
            r = json.load(open(os.path.join(REPO, "roles", f)))
            ports = list(dict.fromkeys(x["port"] for x in r["services"]))          # 389 tcp + 389/udp: list once
            ROLE_PORTS.setdefault(r["id"], set(ports)); ROLE_TITLE.setdefault(r["id"], r["title"])
            ROLE_UDP.setdefault(r["id"], {x["port"] for x in r["services"] if x.get("udp")}
                                - {x["port"] for x in r["services"] if not x.get("udp")})
            ROLE_DEFAULT.setdefault(r["id"], r.get("default_name", r["id"][:15].upper()))
            ROLE_OS.setdefault(r["id"], r.get("os", ""))
            cat.append({"id": r["id"], "title": r["title"], "ports": ports, "desc": r.get("description", ""),
                        "order": r.get("order", 99)})
    return sorted(cat, key=lambda r: (r["order"], r["title"]))


def parse_pick(v, n):
    v = v.strip().lower()
    if v in ("none", "0", "-"):
        return []
    out = []
    for part in [p for p in re.split(r"[,\s]+", v) if p]:
        if not part.isdigit() or not 1 <= int(part) <= n:
            raise ValueError(f"'{part}' is not in the list. Type numbers from 1 to {n} separated by commas "
                             f"(for example 1,3), or 'none'.")
        if int(part) - 1 not in out:
            out.append(int(part) - 1)
    return out


def roles_cap_error(k, n_ifaces):
    """D-6 layer 1: at most MAX_DECOYS decoys, and one per usable interface. None = fine."""
    if k > MAX_DECOYS:
        return limit_message(k)
    if k > n_ifaces:
        return (f"{k} decoys need {k} network interfaces — this server has {n_ifaces} usable "
                f"interface{'s' if n_ifaces != 1 else ''} (one decoy per interface, on its own address). "
                f"Choose at most {n_ifaces}, or add a remote sensor later.")
    return None


def step_roles(st):
    cat = role_catalog()
    st["catalog"] = cat
    n_if = len(st["ifs"])
    cap = min(MAX_DECOYS, n_if)
    info("Which servers should ReD-Pot pretend to be?")
    w = max(len(r["title"]) for r in cat)
    for i, r in enumerate(cat, 1):
        print(f"      {RED}{i}{RST}) {BOLD}{r['title']:<{w}}{RST}  {DIM}ports {' '.join(map(str, r['ports']))}{RST}")
        print(f"         {' ' * w}  {DIM}{r['desc']}{RST}")
    info(f"{DIM}Pick up to {cap}: 1  ·  1,3  ·  none (manager for remote sensors only). One decoy per network "
         f"interface ({n_if} usable here); Community Edition: up to {MAX_DECOYS} decoys in total, remote sensors "
         f"included.{RST}")
    ids = [r["id"] for r in cat]
    flag = None
    if A.roles is not None:
        given = [x.strip() for x in A.roles.split(",") if x.strip()]
        bad = [x for x in given if x not in ids and x != "none"]
        if bad:
            die(f"--roles: unknown role(s) {', '.join(bad)}. Valid: {', '.join(ids)} (or none)")
        flag = ",".join(str(ids.index(x) + 1) for x in dict.fromkeys(given) if x != "none") or "none"
    prev = st.get("roles")
    default = "1" if prev is None else (",".join(str(ids.index(r) + 1) for r in prev) or "none")

    def check(v):
        try:
            return roles_cap_error(len(parse_pick(v, len(cat))), n_if)
        except ValueError as e:
            return str(e)
    v = ask("Decoys to install", default, check, flag=flag, flagname="--roles")
    st["roles"] = [ids[i] for i in parse_pick(v, len(cat))]
    if not st["roles"]:
        info("No local decoys: this server will be a manager for remote sensors only.")


# ----------------------------------------------------------------------------- step: per-role interface + name
HOSTNAME_HINT = ("Use 1–15 letters, digits or hyphens (Windows limit), not starting or ending with a hyphen — "
                 "for example ARB-FS-02.")


def _parse_pairs(v, flagname):
    out = {}
    for x in [x.strip() for x in (v or "").split(",") if x.strip()]:
        k, sep, val = x.partition("=")
        if not sep or not k or not val:
            die(f"{flagname}: '{x}' is not role=VALUE")
        out[k.strip()] = val.strip()
    return out


def step_details(st):
    """Per decoy: the interface (one decoy per interface — earlier decoys' interfaces are not offered again),
    the host name and, for the web decoy, the site theme. The address is the interface's own IP (D-2)."""
    roles = st["roles"]
    if not roles:
        st["names"], st["ips"], st["role_if"] = {}, {}, {}
        return
    names = dict(st.get("names") or {})
    role_if = dict(st.get("role_if") or {})
    given_names = _parse_pairs(A.names, "--names")
    given_if = _parse_pairs(A.role_ifaces, "--role-ifaces")
    if A.decoy_if and len(roles) == 1:
        given_if.setdefault(roles[0], A.decoy_if)
    elif A.decoy_if:
        die("--decoy-if names ONE interface — with several decoys use --role-ifaces role=IFACE,role=IFACE")
    for r, n in given_if.items():
        if r not in roles:
            die(f"--role-ifaces: {r} is not one of the chosen decoys ({', '.join(roles)})")
        if n not in st["ifs"]:
            die(f"--role-ifaces: {n} is not a usable interface here ({', '.join(st['ifs'])})")
    dup = [n for n in set(given_if.values()) if list(given_if.values()).count(n) > 1]
    if dup:
        die(f"--role-ifaces: {', '.join(dup)} given to more than one decoy — one decoy per interface")
    if A.no_ssh_move and st["mgmt"] in given_if.values():
        die(f"--no-ssh-move keeps host SSH on {st['ifs'][st['mgmt']]['ip']}: a decoy on the management interface "
            f"{st['mgmt']} needs it — use another interface or drop --no-ssh-move")
    k = len(roles) - 1 if st.get("_back") and all(r in role_if for r in roles) else 0
    while k < len(roles):
        rid = roles[k]
        print(f"\n  {RED}{BOLD}[{k + 1}/{len(roles)}] {ROLE_TITLE[rid]}{RST}")
        try:
            # interface: not one an earlier decoy uses; never management with --no-ssh-move
            taken = {role_if[r]: names.get(r, r) for r in roles[:k] if r in role_if}
            cands = [n for n in st["ifs"] if n not in taken and not (A.no_ssh_move and n == st["mgmt"])]
            if not cands:
                if A.no_ssh_move and st["mgmt"] not in taken:
                    die(f"--no-ssh-move keeps host SSH on {st['ifs'][st['mgmt']]['ip']}, and no other interface is free "
                        f"for {ROLE_TITLE[rid]} — use another interface or drop --no-ssh-move")
                die("no free interface left for this decoy (one decoy per interface)")
            flag = given_if.get(rid)
            if flag is None and A.yes:             # unattended: deterministic default among the free interfaces
                flag = default_decoy_iface(st, [n for n in cands if n not in given_if.values()] or cands)
            if flag is not None and flag in taken:
                die(f"{flag} already holds {taken[flag]} — one decoy per interface")
            if len(st["ifs"]) == 1:
                role_if[rid] = cands[0]
                info(f"Interface: {cands[0]} ({st['ifs'][cands[0]]['ip']}, this server's address — host SSH moves)")
            else:
                if taken and flag is None:
                    info(f"{DIM}Not offered (one decoy per interface): "
                         + ", ".join(f"{n} → {v}" for n, v in taken.items()) + f"{RST}")
                prev_if = role_if.get(rid) if role_if.get(rid) in cands else None
                role_if[rid] = pick_decoy_iface(st, prev_if, flag, "--role-ifaces", cands=cands)
            ip = st["ifs"][role_if[rid]]["ip"]
            # host name (unique)
            others = {r: n for r, n in names.items() if r != rid and r in roles[:k]}
            names[rid] = ask("Host name (use YOUR naming, e.g. ARB-FS-02)", names.get(rid, ROLE_DEFAULT[rid]),
                             lambda v: HOSTNAME_HINT if not re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,15}(?<!-)", v)
                             else (f"'{v.upper()}' is already used by the {ROLE_TITLE[[r for r, n in others.items() if n == v.upper()][0]]}."
                                   if v.upper() in others.values() else None),
                             flag=given_names.get(rid), flagname="--names").upper()
            if rid == "linux-web-hosting":
                st["web_theme"] = pick("What should the web site look like?", [
                    ("webmail", f"Company webmail sign-in  {DIM}(attackers love mail: default){RST}"),
                    ("helpdesk", f"IT service desk sign-in + knowledge base"),
                    ("intranet", f"Simple staff intranet with an admin portal link")],
                    st.get("web_theme", "webmail"), flag=A.web_theme, flagname="--web-theme")
            info(f"{DIM}{names[rid]} answers on {role_if[rid]}'s own address {ip}"
                 + (" — this server's address: host SSH moves to a random port" if role_if[rid] == st["mgmt"] else "")
                 + f"{RST}")
            if not audit_address(st, ip, rid):
                if flag is not None:
                    die("the decoy's ports are in use on that address (see above)")
                role_if.pop(rid, None)
                if len(cands) == 1:                 # no other interface for it: choose another decoy
                    info(f"No other interface is free for {ROLE_TITLE[rid]} — choose other decoys, or free the ports "
                         f"and run the installer again.")
                    raise Back()
                continue                            # ask this decoy's interface again
        except Back:
            if k == 0:
                raise
            k -= 1
            continue
        k += 1
    st["names"], st["role_if"] = names, role_if
    st["ips"] = {r: st["ifs"][role_if[r]]["ip"] for r in roles}


# ----------------------------------------------------------------------------- step: access
def step_access(st):
    v = ask("Does this server have a static PUBLIC IP? Enter it, or 'no'", st.get("public_ip") or "no",
            lambda x: None if x.lower() == "no" or not valid_ip(x)
            else "Type an IPv4 address such as 203.0.113.10, or 'no'.", flag=A.public_ip, flagname="--public-ip")
    st["public_ip"] = None if v.lower() == "no" else v
    st["geo"] = ask_yes("Download the free GeoIP database for the world attack map (~18 MB)?", st.get("geo", True),
                        flag=None if A.geoip is None else A.geoip == "yes")
    st["allow"] = ask_allowlists(st, st["ifs"][st["mgmt"]]["ip"], bool(mgmt_decoys(st)), st.get("allow"))


def ask_allowlists(st, mi, shared, prev=None, keys=("ui", "sensor", "ssh")):
    """Who may reach the admin ports. S-1 H2: when a decoy shares the management address, the web UI, the sensor
    API and (security review: H2 extended to SSH) the moved host SSH default to the admin's own SSH client (/32)
    instead of 'anyone' — a scan of the decoy must not show them — and an unattended install (--yes) must name all
    three lists explicitly."""
    info(f"Who may reach the admin ports on {mi}? For everyone else they look closed (the firewall answers with a "
         f"reset, like any closed port), so a scan shows only the decoy{' that shares this address' if shared else 's'}.")
    info(f"{DIM}Networks or addresses, comma separated — e.g. 10.8.0.0/24,192.168.1.10 · 0.0.0.0/0 = from anywhere. "
         f"Admin ports answer only on the management interface {st['mgmt']}.{RST}")
    allow = dict(prev or {})
    sess = ssh_session_ip_client()
    if shared and A.yes:
        missing = [f"--allow-{k}" for k, f in (("ui", A.allow_ui), ("sensor", A.allow_sensor), ("ssh", A.allow_ssh))
                   if k in keys and f is None]
        if missing:
            what = [n for k, n in (("ui", "the web UI"), ("sensor", "the sensor API"), ("ssh", "host SSH")) if k in keys]
            die(f"a decoy shares the management address {mi}: pass {' and '.join(missing)} with your admin "
                f"hosts/VPN (e.g. 10.8.0.0/24) — 0.0.0.0/0 would show {', '.join(what[:-1]) + ' and ' if len(what) > 1 else ''}"
                f"{what[-1]} next to the decoy to everyone who scans {mi}")
    for key, q, flag in (("ui", "Web UI may be opened from", A.allow_ui),
                         ("sensor", "Sensor API (remote sensors) may be reached from", A.allow_sensor),
                         ("ssh", "Host SSH may be used from", A.allow_ssh)):
        if key not in keys:
            continue
        if key == "sensor":
            info(f"{DIM}Remote sensors in other offices/VLANs must be inside this list.{RST}")
        ca = _client_addr(sess)
        if key == "ssh" and ca:
            # review F4b: true for IPv6 too — firewall_text adds the session's /128 where IPv6 SSH is filtered
            info(f"{DIM}Your current SSH client {ca} is always allowed on {st['mgmt']}"
                 + (f" (IPv6: {ca}/128)" if ca.version == 6 else "") + f", so you cannot lock yourself out.{RST}")
        dflt = ",".join(allow.get(key) or [ANY])
        if shared and not _restricted(allow.get(key)):
            dflt = f"{ca}/32" if ca and ca.version == 4 else None
            if flag is None and not A.yes:
                info(f"{DIM}A decoy shares {mi}: default = only your own address"
                     + (f" {ca}" if dflt else " (type your admin network)") + f".{RST}")
        v = ask(q, dflt, _check_allow, flag=flag, flagname=f"--allow-{key}")
        allow[key] = _parse_allow(v)
    return allow


ANY = "0.0.0.0/0"


def _parse_allow(v):
    out = []
    for x in re.split(r"[,\s]+", v.strip()):
        if not x:
            continue
        if x.lower() in ("any", "all", "*"):
            x = ANY
        out.append(str(ipaddress.ip_network(x, strict=False)))
    return [ANY] if ANY in out or not out else sorted(set(out))


def _check_allow(v):
    try:
        nets = _parse_allow(v)
    except ValueError as e:
        return f"{e}. Use networks or addresses like 10.8.0.0/24,192.168.1.10 — or 0.0.0.0/0 for anyone."
    if any(ipaddress.ip_network(n).version != 4 for n in nets):
        return "Use IPv4 networks (the admin ports listen on the management IPv4 address)."


def allow_exposure(sharers, iface, allow):
    """B9: an allowlist that is not 'anyone' but still contains the LAN of an address shared with a decoy
    (e.g. SSH from 192.168.1.0/24 = the DC decoy's own network) shows the admin ports to exactly the
    attackers the decoy is for. Returns [(service, overlapping nets, decoy LAN)]."""
    if not sharers:
        return []
    lan = _subnet(iface)
    out = []
    for key, svc in (("ui", "the web UI"), ("sensor", "the sensor API"), ("ssh", "host SSH")):
        nets = allow.get(key) or [ANY]
        if not _restricted(nets):
            continue                                  # 'anyone' is warned about separately
        hit = [n for n in nets if ipaddress.ip_network(n).overlaps(lan) and ipaddress.ip_network(n).prefixlen < 32]
        if hit:
            out.append((svc, hit, str(lan)))
    return out


def _restricted(nets):
    return bool(nets) and nets != [ANY]


def _client_addr(v):
    """The SSH client address as an ip_address (IPv4-mapped IPv6 → IPv4), None if absent or not an address."""
    try:
        a = ipaddress.ip_address((v or "").split("%", 1)[0])
    except ValueError:
        return None
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def ssh_session_ip_client():
    """Client side of the current SSH session (the admin's own address) — always allowed on SSH."""
    c = os.environ.get("SSH_CONNECTION", "").split()
    if len(c) == 4:
        return c[0]
    if os.environ.get("RPOT_TEST_SSH_CLIENT"):
        return os.environ["RPOT_TEST_SSH_CLIENT"]
    pid = os.getppid()
    for _ in range(12):
        if pid <= 1:
            break
        try:
            for e in open(f"/proc/{pid}/environ", "rb").read().split(b"\0"):
                if e.startswith(b"SSH_CONNECTION="):
                    c = e.split(b"=", 1)[1].decode().split()
                    if len(c) == 4:
                        return c[0]
            pid = int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return None


FIREWALL = "firewall.sh"


def ttl_targets(decoys):
    """Windows decoys own an address on the host network and would answer with Linux's TTL 64 — an OS fingerprint
    (B24). Every CE decoy is host-network (S-1 M4: no per-decoy host-network flag any more). Returns [(ip, ports|None)]: TTL 128
    for everything leaving that address, or — when a Linux decoy shares it — only for the Windows decoy's own
    ports. decoys: [{role, ip}]."""
    by_ip = {}
    for x in decoys:
        by_ip.setdefault(x["ip"], []).append(x["role"])
    out = []
    for ip, roles in sorted(by_ip.items()):
        win = [r for r in roles if is_windows(r)]
        if win:
            out.append((ip, None if len(win) == len(roles) else sorted(set().union(*[ROLE_PORTS[r] for r in win]))))
    return out


def _multiport(ports):
    """iptables multiport takes at most 15 ports per rule."""
    ports = sorted(ports)
    return [",".join(map(str, ports[k:k + 15])) for k in range(0, len(ports), 15)]


def _fw_check(dif, out_guard):
    """check() of firewall.sh (review F6): every REDPOT chain must really be hooked — a chain nobody jumps to is
    dead code, and the policy would fail OPEN without a word. Docker with the nftables backend has no DOCKER-USER
    hook (apply then hooks REDPOT-DOCKER into FORWARD itself); without ip6tables the IPv6 chains are missing, which is
    only fine where IPv6 is off. Prints what is missing and returns 1, so the unit does not start."""
    L = ["check() {   # are the chains in effect? (review F6: fail closed, never silently open)", '  bad=""',
         '  $IPT -C INPUT -j REDPOT-IN 2>/dev/null || bad="$bad INPUT->REDPOT-IN"',
         "  { $IPT -C DOCKER-USER -j REDPOT-DOCKER 2>/dev/null && $IPT -C FORWARD -j DOCKER-USER 2>/dev/null; } || "
         '$IPT -C FORWARD -j REDPOT-DOCKER 2>/dev/null || bad="$bad FORWARD->REDPOT-DOCKER"']
    if dif:
        L.append(f"  if v6on {' '.join(dif)}; then $IP6T -C INPUT -j REDPOT-IN6 2>/dev/null || "
                 'bad="$bad ip6tables:INPUT->REDPOT-IN6"; fi')
    if out_guard:
        L += ['  $IPT -C OUTPUT -j REDPOT-OUT 2>/dev/null || bad="$bad OUTPUT->REDPOT-OUT"',
              '  if v6on; then $IP6T -C OUTPUT -j REDPOT-OUT6 2>/dev/null || bad="$bad ip6tables:OUTPUT->REDPOT-OUT6"; fi']
    L += ['  [ -z "$bad" ] && return 0',
          '  echo "ReD-Pot firewall NOT in effect:$bad - refusing to start the decoys (fail closed). Needs iptables and'
          ' ip6tables (or IPv6 disabled on the decoy interfaces) and Docker with its iptables firewall backend or a hookable'
          ' FORWARD chain." >&2',
          "  return 1", "}"]
    return L


def firewall_text(mi, allow, ports, move_ssh, ttl=(), mgmt_if=None, decoys=(), out_guard=False, follow=False):
    """firewall.sh: applied by the redpot unit at every start, removed at stop/uninstall.

    * Admin ports: host SSH = INPUT (chain REDPOT-IN). Web UI + sensor API are Docker-published, so their packets
      pass FORWARD → DOCKER-USER after DNAT (chain REDPOT-DOCKER, matched on the ORIGINAL destination). Allowed
      sources only, and — with decoys (S-1 H1) — only arriving on the management interface `mgmt_if`.
      Forwarding (review F1): nothing NEW is forwarded from a non-management decoy interface, and NEW traffic into a
      Docker bridge from outside must be DNAT'd (a published port) — no direct route to the console's container IP.
      apply() ends with check() (review F6): a chain that is not hooked = exit 1, the unit does not start.
    * Decoy interfaces (S-1 H1, decoys=[{role, ip, iface}]): the decoy's own ports on its own IP, replies,
      DHCP; everything else on that interface is TCP-reset / ICMP port-unreachable, IPv6 TCP/UDP likewise
      (ip6tables chain REDPOT-IN6), arp_ignore=1 / arp_announce=2 (the NIC must not answer ARP for the
      management IP — that would tie the decoy to this server). Old sysctl values are restored by remove.
    * out_guard (S-1 M3): processes of uid DECOY_UID in the host network (= host-mode decoys) may only answer
      (plus NBNS answers from udp/137 to broadcast queries, which conntrack cannot pair — review F2: only out of the
      decoy's interface, to a unicast non-local host of its subnet, not to port 53, ≤600 bytes) and — on a manager —
      open NEW connections to mgmt_ip:sensor_port; everything else (web UI, 127.0.0.1, LAN, internet) is
      rejected (chains REDPOT-OUT / REDPOT-OUT6). A remote sensor passes ports without "sensor": its decoy
      reaches the manager only through the relay's Unix socket, so it may open no connection at all.
    * Remote sensor: ports = {"ssh": …} only (no web UI / sensor API on that host → no REDPOT-DOCKER rules).
      follow=True (decoy on the manager-link interface, it follows DHCP — S-1 L14): rules match the
      interface, not the address of today's lease (decoy ports, SSH, TTL via -o).
    * ttl: see ttl_targets (mangle chain REDPOT-TTL).
    Others get a TCP reset — exactly what a closed port sends — never a DROP: 'filtered' ports in a scan would
    point at the protected admin ports (B9). Every name and address here was validated (IFACE_RE, ipaddress).
    Returns (script, restricted)."""
    sshp = ports["ssh"] if move_ssh else 22
    keep, keep6 = (set() if follow else {mi}), set()      # follow: today's lease may go to another LAN host
    sess = _client_addr(ssh_session_ip_client())
    if sess is not None:
        (keep if sess.version == 4 else keep6).add(str(sess))
    keep = {k for k in keep if valid_ip(k) is None and ":" not in k}
    rej = "REJECT --reject-with tcp-reset"
    decoys = [x for x in decoys if x.get("iface")]
    for x in decoys:
        if not valid_iface_name(x["iface"]) or valid_ip(x["ip"]):
            raise ValueError(f"refusing to write firewall rules for {x['iface']!r} / {x['ip']!r}")
        if x.get("net") is not None and str(ipaddress.ip_network(x["net"])) != x["net"]:     # ValueError if not a network
            raise ValueError(f"refusing to write firewall rules for {x['net']!r}")
    if mgmt_if is not None and not valid_iface_name(mgmt_if):
        raise ValueError(f"refusing to write firewall rules for {mgmt_if!r}")
    dif = list(dict.fromkeys(x["iface"] for x in decoys))          # decoy interfaces, management possibly included
    via = f"-i {mgmt_if} " if decoys and mgmt_if else ""
    dmi = "" if follow else f"-d {mi} "                             # follow: today's lease may change
    L = ["#!/bin/sh", "# generated by the ReD-Pot installer — do not edit (re-run add-decoy / remove-decoy instead)",
         "# admin-port allowlists (everyone else: TCP reset, like a closed port), decoy-interface policy,",
         "# decoy egress guard, TTL 128 for Windows decoys",
         "IPT=$(command -v iptables || echo /usr/sbin/iptables)",
         "IP6T=$(command -v ip6tables || echo /usr/sbin/ip6tables)",
         'ARP_BAK="$(cd "$(dirname "$0")" && pwd)/arp-sysctl.bak"',
         "remove() {",
         "  $IPT -D INPUT -j REDPOT-IN 2>/dev/null; $IPT -D DOCKER-USER -j REDPOT-DOCKER 2>/dev/null",
         "  $IPT -D FORWARD -j REDPOT-DOCKER 2>/dev/null; $IPT -D OUTPUT -j REDPOT-OUT 2>/dev/null",
         "  for c in REDPOT-IN REDPOT-DOCKER REDPOT-OUT; do $IPT -F $c 2>/dev/null; $IPT -X $c 2>/dev/null; done",
         "  $IP6T -D INPUT -j REDPOT-IN6 2>/dev/null; $IP6T -D OUTPUT -j REDPOT-OUT6 2>/dev/null",
         "  for c in REDPOT-IN6 REDPOT-OUT6; do $IP6T -F $c 2>/dev/null; $IP6T -X $c 2>/dev/null; done",
         "  $IPT -t mangle -D OUTPUT -j REDPOT-TTL 2>/dev/null; $IPT -t mangle -F REDPOT-TTL 2>/dev/null",
         "  $IPT -t mangle -X REDPOT-TTL 2>/dev/null",
         '  if [ -f "$ARP_BAK" ]; then',
         '    while read -r f v; do',
         '      case "$f" in /proc/sys/net/ipv4/conf/*/arp_ignore|/proc/sys/net/ipv4/conf/*/arp_announce) ;; *) continue ;; esac',
         '      case "$v" in ""|*[!0-9]*) continue ;; esac',
         '      [ -w "$f" ] && echo "$v" > "$f"',
         '    done < "$ARP_BAK"',
         '    rm -f "$ARP_BAK"',
         "  fi",
         "  return 0", "}",
         "arp() {   # $1 = decoy interface: answer ARP only for its own address, announce only it",
         "  for k in arp_ignore:1 arp_announce:2; do",
         '    f=/proc/sys/net/ipv4/conf/$1/${k%%:*}; [ -w "$f" ] || continue',
         '    echo "$f $(cat "$f")" >> "$ARP_BAK"; echo "${k##*:}" > "$f"',
         "  done", "}",
         "v6on() {   # IPv6 enabled on any of these interfaces (no argument: on any interface but lo)?",
         '  [ $# -gt 0 ] || set -- $(ls /proc/sys/net/ipv6/conf 2>/dev/null | grep -vx "all\\|default\\|lo")',
         '  for n in "$@"; do [ "$(cat /proc/sys/net/ipv6/conf/$n/disable_ipv6 2>/dev/null)" = 0 ] && return 0; done',
         "  return 1", "}"] + _fw_check(dif, out_guard) + [
         "apply() {", "  remove", "  $IPT -N REDPOT-IN; $IPT -N REDPOT-DOCKER",
         "  $IPT -A REDPOT-IN -i lo -j RETURN",
         "  $IPT -A REDPOT-IN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
         "  $IPT -A REDPOT-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"]
    restricted = False
    # --- host SSH (INPUT)
    if _restricted(allow.get("ssh")) or decoys:
        srcs = [None]
        if _restricted(allow.get("ssh")):
            restricted = True
            srcs = sorted(set(allow["ssh"]) | {f"{k}/32" for k in keep})
        for src in srcs:
            L.append(f"  $IPT -A REDPOT-IN {via}-p tcp {dmi}--dport {sshp}" + (f" -s {src}" if src else "") + " -j RETURN")
        L.append(f"  $IPT -A REDPOT-IN -p tcp {dmi}--dport {sshp} -j {rej}")
    # --- forwarded traffic into containers (review F1). Docker <28 accepts '-d <container> ! -i br -o br --dport
    # 8740' in its DOCKER chain whatever way the packet came, ≥28 still accepts direct-routed packets to PUBLISHED
    # container ports, and dockerd turns on ip_forward: someone on a decoy LAN can 'ip route add 172.16.0.0/12 via
    # <decoy IP>' and reach the console's 8740/8741 without DNAT — no ctorigdst rule below would see it.
    # DOCKER-USER runs before Docker's own chains in both versions, so here, after the replies:
    #  1. nothing NEW is forwarded from a decoy interface (management excepted): this host never routes for a decoy LAN
    #  2. NEW traffic from outside into a Docker bridge (docker0, br-*) must have been DNAT'd = a published port;
    #     container → outside and container → container on one bridge are not affected.
    for n in dif:
        if n != mgmt_if:
            L += [f"  $IPT -A REDPOT-DOCKER -i {n} -p tcp -j {rej}",
                  f"  $IPT -A REDPOT-DOCKER -i {n} -j REJECT --reject-with icmp-port-unreachable"]
    for br in ("docker0", "br-+"):
        L += [f"  $IPT -A REDPOT-DOCKER ! -i {br} -o {br} -m conntrack ! --ctstate DNAT -p tcp -j {rej}",
              f"  $IPT -A REDPOT-DOCKER ! -i {br} -o {br} -m conntrack ! --ctstate DNAT -j REJECT --reject-with icmp-port-unreachable"]
    # --- web UI + sensor API (DOCKER-USER, original destination)
    for key, port in (("ui", ports.get("ui")), ("sensor", ports.get("sensor"))):
        if port is None or not (_restricted(allow.get(key)) or decoys):         # remote sensor: no such ports
            continue
        srcs = [None]
        if _restricted(allow.get(key)):
            restricted = True
            srcs = sorted(set(allow[key]) | {f"{mi}/32"})
        for src in srcs:
            L.append(f"  $IPT -A REDPOT-DOCKER {via}-p tcp -m conntrack --ctorigdst {mi} --ctorigdstport {port}"
                     + (f" -s {src}" if src else "") + " -j RETURN")
        L.append(f"  $IPT -A REDPOT-DOCKER -p tcp -m conntrack --ctorigdst {mi} --ctorigdstport {port} -j {rej}")
    # --- decoy interfaces (S-1 H1): the decoy's ports on its own address, nothing else
    for x in decoys:
        rp = ROLE_PORTS.get(x["role"], set())
        tcp = rp - ROLE_UDP.get(x["role"], set())
        dx = "" if follow else f"-d {x['ip']} "
        L.append(f"  # {x.get('name') or x['role']}: {x['role']} on {x['iface']} {x['ip']}" + (" (follows DHCP)" if follow else ""))
        for mp in _multiport(tcp):
            L.append(f"  $IPT -A REDPOT-IN -i {x['iface']} {dx}-p tcp -m multiport --dports {mp} -j RETURN")
        for mp in _multiport(rp):                   # services answer UDP on more ports than roles/*.json lists (dns, kerberos)
            L.append(f"  $IPT -A REDPOT-IN -i {x['iface']} {dx}-p udp -m multiport --dports {mp} -j RETURN")
        for mp in _multiport(set(rp) & {137, 138}):    # NetBIOS name queries are broadcast
            L.append(f"  $IPT -A REDPOT-IN -i {x['iface']} -p udp -m addrtype --dst-type BROADCAST -m multiport --dports {mp} -j RETURN")
    for n in dif:
        L += [f"  $IPT -A REDPOT-IN -i {n} -p udp --sport 67 --dport 68 -j RETURN",
              f"  $IPT -A REDPOT-IN -i {n} -p tcp -j {rej}",
              f"  $IPT -A REDPOT-IN -i {n} -p udp -j REJECT --reject-with icmp-port-unreachable"]
    L += ["  $IPT -I INPUT 1 -j REDPOT-IN", "  $IPT -N DOCKER-USER 2>/dev/null; $IPT -I DOCKER-USER 1 -j REDPOT-DOCKER",
          "  if ! $IPT -C FORWARD -j DOCKER-USER 2>/dev/null; then",
          "    # Docker's nftables firewall backend (or dockerd --iptables=false) does not hook DOCKER-USER: filter in FORWARD",
          "    # itself (a REJECT in any forward-hook chain is final, whichever table accepts the packet elsewhere)",
          "    echo 'ReD-Pot: DOCKER-USER is not hooked into FORWARD (Docker nftables backend?) - filtering in FORWARD' >&2",
          "    $IPT -I FORWARD 1 -j REDPOT-DOCKER", "  fi"]
    if dif:
        L += [f"  arp {n}" for n in dif]
        L += ["  # IPv6: decoys listen on IPv4 only — on decoy interfaces every IPv6 port looks closed",
              "  if $IP6T -N REDPOT-IN6 2>/dev/null; then",
              "    $IP6T -A REDPOT-IN6 -i lo -j RETURN",
              "    $IP6T -A REDPOT-IN6 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
              "    $IP6T -A REDPOT-IN6 -p ipv6-icmp -j RETURN"]
        if mgmt_if in dif and move_ssh:
            # decoy on the management interface: the MOVED host SSH stays reachable over IPv6 there (port 22 = decoy) —
            # for anyone, or (SSH allow-list, IPv4 only) for the admin's own IPv6 session (review F4b: no lockout)
            for src in ([None] if not _restricted(allow.get("ssh")) else sorted(f"{k}/128" for k in keep6)):
                L.append(f"    $IP6T -A REDPOT-IN6 -i {mgmt_if} -p tcp" + (f" -s {src}" if src else "")
                         + f" --dport {sshp} -j RETURN")
        for n in dif:
            L += [f"    $IP6T -A REDPOT-IN6 -i {n} -p udp --dport 546 -j RETURN",
                  f"    $IP6T -A REDPOT-IN6 -i {n} -p tcp -j {rej}",
                  f"    $IP6T -A REDPOT-IN6 -i {n} -p udp -j REJECT --reject-with icmp6-port-unreachable"]
        L += ["    $IP6T -I INPUT 1 -j REDPOT-IN6",
              "  else echo 'ReD-Pot: ip6tables unavailable - IPv6 on decoy interfaces cannot be filtered' >&2; fi"]
    if out_guard:
        u = f"-m owner --uid-owner {DECOY_UID}"
        sapi = ports.get("sensor")
        L += [f"  # decoys (uid {DECOY_UID}, host network) may only reply"
              + (f" and report to the sensor API {mi}:{sapi}" if sapi else " (they report through the relay's Unix socket)"),
              "  $IPT -N REDPOT-OUT",
              f"  $IPT -A REDPOT-OUT {u} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"]
        if sapi:
            L.append(f"  $IPT -A REDPOT-OUT {u} -p tcp -m conntrack --ctstate NEW --ctorigdst {mi} --ctorigdstport {sapi} -j RETURN")
        for x in decoys:
            # NBNS: the answer to a broadcast query has no conntrack entry. Review F2: only out of the decoy's own
            # interface, from its address, to a unicast, non-local host of that interface's subnet (broadcast queries
            # come only from there), never to port 53 (no DNS tunnel via the LAN resolver), small packets only.
            if 137 not in ROLE_PORTS.get(x["role"], set()):
                continue
            nb = (f"  $IPT -A REDPOT-OUT {u} -o {x['iface']} -p udp " + ("" if follow else f"-s {x['ip']} ")
                  + "--sport 137 ! --dport 53 -d {net} -m addrtype --dst-type UNICAST -m addrtype ! --dst-type LOCAL "
                  "-m length --length 0:600 -j RETURN")
            if not follow and x.get("net"):
                L.append(nb.format(net=x["net"]))
            else:                                   # follow mode (or unknown prefix): the subnet of today's lease
                L += [f"  NET=$(ip -4 -o addr show dev {x['iface']} 2>/dev/null | awk '{{print $4; exit}}')",
                      '  if [ -n "$NET" ] && [ -z "$(printf %s "$NET" | tr -d 0-9./)" ]; then',
                      "  " + nb.format(net='"$NET"'),
                      f"  else echo 'ReD-Pot: no IPv4 subnet on {x['iface']} - NBNS broadcast answers stay blocked' >&2; fi"]
        L += [f"  $IPT -A REDPOT-OUT {u} -p tcp -j {rej}",
              f"  $IPT -A REDPOT-OUT {u} -j REJECT --reject-with icmp-port-unreachable",
              "  $IPT -I OUTPUT 1 -j REDPOT-OUT",
              "  if $IP6T -N REDPOT-OUT6 2>/dev/null; then",
              f"    $IP6T -A REDPOT-OUT6 {u} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
              f"    $IP6T -A REDPOT-OUT6 {u} -p tcp -j {rej}",
              f"    $IP6T -A REDPOT-OUT6 {u} -j REJECT --reject-with icmp6-adm-prohibited",
              "    $IP6T -I OUTPUT 1 -j REDPOT-OUT6",
              "  else echo 'ReD-Pot: ip6tables unavailable - IPv6 egress of the decoys cannot be filtered' >&2; fi"]
    if ttl:
        # xt_TTL may be missing (minimal kernels): warn, never fail the service start
        L += ["  if $IPT -t mangle -N REDPOT-TTL 2>/dev/null && $IPT -t mangle -I OUTPUT 1 -j REDPOT-TTL; then"]
        by_ip = {x["ip"]: x["iface"] for x in decoys}
        for ip, sports in ttl:
            match = f" -p tcp -m multiport --sports {','.join(map(str, sports))}" if sports else ""
            src = f"-o {by_ip[ip]}" if follow and ip in by_ip else f"-s {ip}"
            L.append(f"    $IPT -t mangle -A REDPOT-TTL {src}{match} -j TTL --ttl-set 128 2>/dev/null || "
                     f"echo 'ReD-Pot: iptables TTL target (xt_TTL) unavailable - {ip} keeps TTL 64' >&2")
        L += ["  fi"]
    L += ["  check   # every chain hooked, or a non-zero exit: the unit does not start (fail closed, review F6)", "}",
          'case "$1" in apply) apply ;; remove) remove ;; check) check ;; *) echo "usage: $0 apply|remove|check"; exit 2 ;; esac']
    return "\n".join(L) + "\n", restricted


def write_firewall(d, st, decoys=None):
    """firewall.sh for the current decoy set, decoys=[{name, role, ip, iface}] (manager default: the wizard's
    choice) → full S-1 H1/M3 policy. A remote sensor (st['join']) gets the same builder: host SSH only via the
    manager-link interface, its decoy's ports only on the decoy interface (IPv6 closed, ARP restricted), decoy
    egress = replies only. Returns True if a firewall is in place."""
    mi = st["ifs"][st["mgmt"]]["ip"]
    manager = not st.get("join")
    if decoys is None:
        decoys = [{"name": st["names"][r], "role": r, "ip": st["ips"][r], "iface": st["role_if"][r]}
                  for r in st.get("roles") or []]
    ttl = ttl_targets(decoys)
    policy = []
    for x in decoys:
        if not x.get("iface"):
            continue
        i = st["ifs"].get(x["iface"]) or {}
        if i.get("ip") == x["ip"] and i.get("prefix") is not None and valid_ip(x["ip"]) is None:
            x = dict(x, net=str(ipaddress.ip_network(f"{x['ip']}/{i['prefix']}", strict=False)))   # NBNS answers (F2)
        policy.append(x)
    ports = st["ports"] if manager else {"ssh": st["ports"]["ssh"]}       # a sensor has no web UI / sensor API
    follow = not manager and bool(st.get("single"))                      # S-1 L14: decoy follows DHCP there
    text, restricted = firewall_text(mi, st["allow"], ports, st["move_ssh"], ttl, mgmt_if=st["mgmt"],
                                     decoys=policy, out_guard=bool(policy), follow=follow)
    p = os.path.join(d, FIREWALL)
    if not restricted and not ttl and not policy:
        if os.path.exists(p) and not A.dry_run:          # add/remove-decoy: nothing left to enforce
            run(["/bin/sh", p, "remove"], check=False, quiet=True)
            os.remove(p)
        return False
    if ttl:
        if not ttl_available():
            warn("the kernel has no iptables TTL target (xt_TTL): Windows decoys keep Linux's TTL 64 — an OS scan may "
                 "see Linux. Install the kernel modules package (linux-modules-extra-$(uname -r)) to fix it.")
        info(f"{DIM}TTL 128 (like Windows) for traffic from {', '.join(ip for ip, _ in ttl)}"
             + (" — this includes this server's own traffic on that shared address" if any(ip == mi and not sp for ip, sp in ttl) else "")
             + f"{RST}")
    what = (["admin-port allowlists"] if restricted else []) + \
        ([f"decoy interfaces {', '.join(dict.fromkeys(x['iface'] for x in policy))}: only each decoy's ports",
          f"admin ports only via {st['mgmt']}",
          "decoy egress only to the sensor API" if manager else "decoy egress: replies only (it reports via the relay)"]
         if policy else []) + \
        (["TTL 128 for " + ", ".join(ip for ip, _ in ttl)] if ttl else [])
    if A.dry_run:
        info(f"[dry-run] would write {d}/{FIREWALL} ({'; '.join(what)}):")
        print("\n".join(f"      {DIM}{l}{RST}" for l in text.splitlines()))
        return True
    fd = os.open(p + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(p + ".new", 0o700)
    os.replace(p + ".new", p)
    return True


FW_FIX = "Fix that (install iptables/ip6tables, or use Docker's iptables firewall backend)"


def apply_firewall(d, unit="redpot", prev=None, change=False):
    """Put firewall.sh in effect now (before the unit starts the decoys). Its check (review F6) fails when a chain is
    not hooked (Docker nftables backend without a usable FORWARD chain, no ip6tables while IPv6 is on): the rules
    are taken out again and the run stops — never decoys behind a dead policy.
    First install (change=False): nothing of ReD-Pot runs yet and the unit is not installed → "run the installer
    again". add-decoy / remove-decoy (change=True, review R2-1): the console and the decoys ARE running, so fail
    closed before die(): re-apply the previous firewall.sh text `prev` (the running containers keep the rules they
    had), and if there is none or it fails too, stop the whole stack (_stop_stack)."""
    p = os.path.join(d, FIREWALL)
    r = run(["/bin/sh", p, "apply"], check=False, capture=True)
    if r.returncode == 0:
        return True
    run(["/bin/sh", p, "remove"], check=False, quiet=True)
    why = _clean_text(r.stderr or "").strip()[-900:]
    if not change:
        die("the ReD-Pot firewall could not be put in effect, so the decoys were NOT started:\n  " + why
            + f"\n{FW_FIX}, then run the installer again (sudo ./install.sh).")
    die("the new ReD-Pot firewall could not be put in effect:\n  " + why + "\n" + _fall_back(d, unit, prev)
        + f"\n{FW_FIX}, then run  sudo systemctl restart {unit}  — until then every start of {unit} refuses to start "
          f"the containers (fail closed).")


def _fall_back(d, unit, prev):
    """R2-1: the new firewall.sh failed while the stack runs. 1) previous rules back in effect (from a temporary
    copy in the install dir, so its arp-sysctl.bak path is the same); the new decoy/change is not started, and
    firewall.sh on disk stays the NEW one, which matches the new compose — the next unit start applies it or fails
    closed. 2) otherwise: stop everything. Returns what happened, for the message."""
    if prev:
        pp = os.path.join(d, FIREWALL + ".prev")
        fd = os.open(pp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o700)
        with os.fdopen(fd, "w") as f:
            f.write(prev)
        try:
            r = run(["/bin/sh", pp, "apply"], check=False, capture=True)
            if r.returncode == 0:
                return ("The PREVIOUS firewall rules were put back in effect: the console and the existing decoys keep "
                        "running behind them. The change was NOT started.")
            run(["/bin/sh", pp, "remove"], check=False, quiet=True)
        finally:
            os.remove(pp)
    if _stop_stack(d, unit):
        return (("The previous rules could not be restored either" if prev else "There were no previous rules")
                + f", so ReD-Pot (console and every decoy) was STOPPED: nothing of it runs without its firewall.")
    return (f"{RED}{BOLD}WARNING: ReD-Pot could NOT be stopped and runs WITHOUT its firewall — stop it now: "
            f"sudo docker compose -p {unit} stop{RST}")


def _stop_stack(d, project):
    """Stop the unit (ExecStop = compose stop); if systemd cannot, compose stop directly. True = stopped."""
    if run(["systemctl", "stop", project], check=False, quiet=True).returncode == 0:
        return True
    return run(f"cd {shlex.quote(d)} && docker compose -p {shlex.quote(project)} stop", check=False,
               quiet=True).returncode == 0


def _fw_tool(name):
    """iptables / ip6tables as firewall.sh finds them (command -v, else /usr/sbin)."""
    p = shutil.which(name)
    if p:
        return p
    p = f"/usr/sbin/{name}"
    return p if os.access(p, os.X_OK) else None


def _v6_on(names=None):
    """firewall.sh v6on(): IPv6 enabled on any of `names` (None: any interface but lo)?"""
    base = "/proc/sys/net/ipv6/conf"
    if names is None:
        try:
            names = [n for n in os.listdir(base) if n not in ("all", "default", "lo")]
        except OSError:
            return False
    for n in names:
        try:
            if open(os.path.join(base, n, "disable_ipv6")).read().strip() == "0":
                return True
        except OSError:
            pass
    return False


PRE_CHAIN = "REDPOT-PRECHK"           # match test: never hooked
PRE_OUT = "REDPOT-PRECHK-OUT"          # owner match, hooked from OUTPUT for a moment (its rule is a RETURN)
PRE_FWD = "REDPOT-PRECHK-FWD"          # EMPTY, hooked from FORWARD for a moment
PRE_CHAINS = ((PRE_CHAIN, None), (PRE_OUT, "OUTPUT"), (PRE_FWD, "FORWARD"))


def _pre_cleanup(t):
    """Take every preflight chain out of `t` (iptables / ip6tables) — also what an interrupted run (or 1.0.0's
    preflight, which hooked REDPOT-PRECHK from FORWARD) left behind."""
    for c, hook in PRE_CHAINS:
        for h in ([hook] if hook else []) + (["FORWARD"] if c == PRE_CHAIN else []):
            run([t, "-D", h, "-j", c], check=False, quiet=True)
        run([t, "-F", c], check=False, quiet=True)
        run([t, "-X", c], check=False, quiet=True)


def _pre_owner(t, bad, name):
    """The egress guard's owner match where firewall.sh uses it: in a chain jumped to from OUTPUT. The kernel
    accepts '-m owner' only on the OUTPUT / POSTROUTING path (B2: a FORWARD jump to such a chain is EINVAL)."""
    if run([t, "-N", PRE_OUT], check=False, quiet=True).returncode != 0:
        bad.append(f"{name} cannot create a chain ({PRE_OUT})")
    elif run([t, "-A", PRE_OUT, "-m", "owner", "--uid-owner", str(DECOY_UID), "-j", "RETURN"],
             check=False, quiet=True).returncode != 0:
        bad.append(f"{name} refuses the rule '-m owner --uid-owner {DECOY_UID} -j RETURN' (kernel module xt_owner "
                   f"missing?)")
    elif run([t, "-I", "OUTPUT", "1", "-j", PRE_OUT], check=False, quiet=True).returncode != 0:
        bad.append(f"the {name} OUTPUT chain cannot be hooked with an owner match (decoy egress guard)")


def preflight_firewall(decoy_ifs):
    """Review R2-6: what firewall.sh apply + check will need, checked BEFORE the install changes the host (stops
    services, moves SSH, enrolls): iptables; ip6tables when IPv6 is on (the egress guard checks every interface, as
    check() does); the conntrack / addrtype / multiport matches and REJECT; the owner match in a chain hooked from
    OUTPUT; a hookable FORWARD chain. Each test uses its own throw-away chain, built the way firewall.sh uses it
    (B2 — the kernel refuses '-m owner' in a chain reachable from FORWARD/INPUT, so the owner rule never shares a
    chain with the FORWARD test):
      REDPOT-PRECHK      match rules, never hooked
      REDPOT-PRECHK-OUT  '-m owner --uid-owner 10001 -j RETURN', hooked from OUTPUT for a moment (RETURN: no effect)
      REDPOT-PRECHK-FWD  empty, hooked from FORWARD for a moment
    All three are removed again, whatever failed."""
    if A.dry_run:
        info("[dry-run] would check the firewall prerequisites (iptables, ip6tables while IPv6 is on, conntrack/owner "
             "matches, hookable OUTPUT and FORWARD chains)")
        return
    bad = []
    ipt, ip6t = _fw_tool("iptables"), _fw_tool("ip6tables")
    need6 = bool(decoy_ifs) and _v6_on()
    rules = [["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"],
             ["-p", "tcp", "-m", "conntrack", "--ctorigdstport", "8740", "-j", "REJECT", "--reject-with", "tcp-reset"]]
    if decoy_ifs:
        rules += [["-p", "udp", "-m", "addrtype", "--dst-type", "BROADCAST", "-m", "multiport", "--dports", "137,138",
                   "-j", "RETURN"]]
    for t in (ipt, ip6t if need6 else None):        # left over from an interrupted earlier run
        if t:
            _pre_cleanup(t)
    if not ipt:
        bad.append("iptables is not installed")
    else:
        try:
            if run([ipt, "-N", PRE_CHAIN], check=False, quiet=True).returncode != 0:
                bad.append(f"iptables cannot create a chain ({PRE_CHAIN})")
            else:
                for rule in rules:
                    if run([ipt, "-A", PRE_CHAIN, *rule], check=False, quiet=True).returncode != 0:
                        bad.append("iptables refuses the rule '" + " ".join(rule) + "' (kernel module missing?)")
            if decoy_ifs:
                _pre_owner(ipt, bad, "iptables")
            if run([ipt, "-N", PRE_FWD], check=False, quiet=True).returncode != 0:
                bad.append(f"iptables cannot create a chain ({PRE_FWD})")
            elif run([ipt, "-I", "FORWARD", "1", "-j", PRE_FWD], check=False, quiet=True).returncode != 0:
                bad.append("the FORWARD chain cannot be hooked")
        finally:
            _pre_cleanup(ipt)
    if need6 and not ip6t:
        bad.append("ip6tables is not installed, but IPv6 is on (install ip6tables, or disable IPv6)")
    elif need6:
        try:
            _pre_owner(ip6t, bad, "ip6tables")
        finally:
            _pre_cleanup(ip6t)
    if bad:
        die("the ReD-Pot firewall would not work on this server — nothing was changed yet (no service stopped, SSH "
            "and the firewall as they were):\n  - " + "\n  - ".join(bad)
            + f"\n{FW_FIX}, then run the installer again.")


def firewall_in_effect(d):
    """Self-test line (review F6): is every chain of firewall.sh hooked right now? None = no firewall here."""
    p = os.path.join(d or "", FIREWALL)
    if not d or not os.path.exists(p):
        return None
    if A.dry_run:
        info(f"[dry-run] would check that the firewall chains are hooked ({p} check)")
        return True
    r = run(["/bin/sh", p, "check"], check=False, capture=True)
    if r.returncode == 0:
        info(f"{GREEN}✓{RST} firewall in effect (decoy-interface policy, admin allow-lists, decoy egress guard)")
        return True
    print(f"      {RED}✗ firewall NOT in effect: {_clean_text(r.stderr or '').strip()[-600:]}{RST}")
    return False


def ttl_available():
    if _test_ifaces() is not None:
        return os.environ.get("RPOT_TEST_NO_TTL") is None
    if A.dry_run or any(os.path.isdir(f"/sys/module/{m}") for m in ("xt_TTL", "xt_HL")):
        return True
    # newer kernels (e.g. Ubuntu 26.04, 7.x) ship the TTL target inside xt_HL — there is no xt_TTL module to load
    for m in ("xt_TTL", "xt_HL"):
        if run(["modprobe", "-q", m], check=False, quiet=True).returncode == 0:
            return True
    # last resort: does iptables accept a TTL rule at all? (throw-away chain, removed again)
    ok = run(["iptables", "-t", "mangle", "-N", "REDPOT-TTLCHK"], check=False, quiet=True).returncode == 0 and \
        run(["iptables", "-t", "mangle", "-A", "REDPOT-TTLCHK", "-j", "TTL", "--ttl-set", "128"],
            check=False, quiet=True).returncode == 0
    run(["iptables", "-t", "mangle", "-F", "REDPOT-TTLCHK"], check=False, quiet=True)
    run(["iptables", "-t", "mangle", "-X", "REDPOT-TTLCHK"], check=False, quiet=True)
    return ok


# ----------------------------------------------------------------------------- step: review
def _plan_ports(st):
    if "ports" not in st:
        avoid = {22}.union(*[ROLE_PORTS[r] for r in st["roles"]]) if st["roles"] else {22}
        ui, sapi, ssh = random_ports(3, avoid)
        st["ports"] = {"ui": int(A.ui_port or ui), "sensor": int(A.sensor_port or sapi), "ssh": A.ssh_port or ssh}
    if st.get("join"):
        # remote sensor, same rules as the manager (D-2): decoy on the manager-link interface = this server's
        # address → host SSH moves; decoy on another interface's own address → SSH listens only on the link IP
        if st["single"] and A.no_ssh_move:
            die(_sensor_no_move_error(st))
        st["move_ssh"], st["pin_ssh"] = st["single"], not st["single"]
        return
    # manager: a decoy on the management interface (= this server's address) → host SSH moves (OpenSSH on 22
    # at a "Windows DC" gives it away); a decoy on another interface's own address → SSH listens only on the
    # management IP (else it is visible there too); an SSH allowlist also pins it (the firewall rules cover
    # the management IPv4 only)
    st["move_ssh"] = bool(mgmt_decoys(st))
    st["pin_ssh"] = bool(other_decoys(st)) or bool(_restricted((st.get("allow") or {}).get("ssh")))


def dhcp_bound(st):
    """Addresses ReD-Pot BINDS to that are DHCP leases: (ip, iface, what). If DHCP hands the server another
    address after a reboot, everything bound to the old one stops answering (SSH may be unreachable)."""
    out = []
    if st.get("join"):
        # sensor: on the manager-link interface the decoy follows a DHCP change (S-1 L14) and the moved SSH listens
        # on every address — nothing is bound to a lease. On another interface both addresses are bound.
        if not st["single"]:
            for key, what in (("mgmt", "manager link, host SSH"), ("_decoy", "decoy")):
                i = st["ifs"][st["mgmt"] if key == "mgmt" else st["role_if"]["_"]]
                if i.get("dynamic"):
                    out.append((i["ip"], i["name"], what))
        return out
    mi = st["ifs"][st["mgmt"]]
    if mi.get("dynamic"):
        out.append((mi["ip"], mi["name"], "management: web UI, sensor API"
                    + (", host SSH" if st.get("pin_ssh") or _restricted((st.get("allow") or {}).get("ssh")) else "")
                    + (", " + ", ".join(st["names"][r] for r in mgmt_decoys(st)) if mgmt_decoys(st) else "")))
    for r in other_decoys(st):
        i = st["ifs"][st["role_if"][r]]
        if i.get("dynamic"):
            out.append((i["ip"], i["name"], st["names"][r]))
    return out


def confirm_dhcp(st):
    """Warn about DHCP-bound addresses; interactive installs must confirm (default no)."""
    dyn = dhcp_bound(st)
    if not dyn:
        return True
    for ip, ifname, what in dyn:
        warn(f"{ip} ({ifname}) is a DHCP lease, not a static address — used for: {what}.")
    warn("If DHCP gives this server another address after a reboot, these stop answering"
         + (" and host SSH may be unreachable" if any("SSH" in w for _, _, w in dyn) else "")
         + ". Make the address static (netplan) or reserve it in your DHCP server.")
    if A.yes:
        return True
    return ask_yes("Continue with DHCP addresses anyway?", False)


def review(st, sections):
    _plan_ports(st)
    banner("Review — nothing has been changed yet")
    mi = st["ifs"][st["mgmt"]]
    bind = st["public_ip"] or mi["ip"]
    used = [st["role_if"][r] for r in st["roles"]]
    pv = persona_preview(st["domain"])
    shared = mgmt_decoys(st)
    print(f"  {RED}1{RST} {BOLD}{'Network':<10}{RST} management {st['mgmt']} ({mi['ip']})"
          + (f" · decoys on {', '.join(used)}" if used else ""))
    print(f"  {RED}2{RST} {BOLD}{'Identity':<10}{RST} {st['domain']} · {st['profile']}")
    print(f"    {DIM}derived: company {pv['company']} · NetBIOS {pv['netbios']} · mail @{pv['email_domain']} · "
          f"users from the built-in pool (random per install){RST}")
    print(f"  {RED}3{RST} {BOLD}{'Decoys':<10}{RST} " + (", ".join(ROLE_TITLE[r] for r in st["roles"]) or "none (manager only)")
          + f"  {DIM}({len(st['roles'])} of {MAX_DECOYS} — remote sensors count too){RST}")
    if st["roles"]:
        print(f"  {RED}4{RST} {BOLD}{'Interfaces':<10}{RST}")
        w = max(len(ROLE_TITLE[r]) for r in st["roles"])
        for r in st["roles"]:
            tag = "  (this server's address)" if r in shared else "  (interface's own address)"
            print(f"      {st['names'][r]:<16} {ROLE_TITLE[r]:<{w}}  {st['ips'][r]:<16} {DIM}{st['role_if'][r]}"
                  f"{tag}"
                  f"{('  · site: ' + st.get('web_theme', 'webmail')) if r == 'linux-web-hosting' else ''}{RST}")
        print(f"    {DIM}firewall: on {', '.join(used)} only each decoy's own ports answer; admin ports only via "
              f"{st['mgmt']}; decoys may only report to the sensor API{RST}")
    print(f"  {RED}5{RST} {BOLD}{'Access':<10}{RST} public IP {st['public_ip'] or 'none'} · GeoIP {'yes' if st['geo'] else 'no'}")
    al = st.get("allow") or {}
    print(f"    {DIM}admin access: web UI from {', '.join(al.get('ui') or [ANY])} · sensor API from "
          f"{', '.join(al.get('sensor') or [ANY])} · SSH from {', '.join(al.get('ssh') or [ANY])}{RST}")
    if shared and not all(_restricted(al.get(k)) for k in ("ui", "sensor", "ssh")):
        open_ = [n for k, n in (("ui", "web UI"), ("sensor", "sensor API"), ("ssh", "host SSH")) if not _restricted(al.get(k))]
        sharers = [st['names'][r] for r in shared]
        warn(f"{', '.join(open_)} {'is' if len(open_) == 1 else 'are'} reachable from anywhere on {mi['ip']}, the address "
             f"{' and '.join(sharers)} {'shares' if len(sharers) == 1 else 'share'} — a full port scan shows "
             f"{'it' if len(open_) == 1 else 'them'}. Type 5 to limit who may reach {'it' if len(open_) == 1 else 'them'}.")
    for svc, nets, lan in allow_exposure(shared, mi, al):
        sharers = " and ".join(st["names"][r] for r in shared)
        warn(f"{svc} is allowed from {', '.join(nets)}, which includes {lan} — the network {sharers} "
             f"{'lives' if len(shared) == 1 else 'live'} in. Anyone there who scans {mi['ip']} sees {svc} next "
             f"to the decoy. Type 5 and allow only your admin hosts/VPN (e.g. 10.8.0.0/24, 192.168.1.10).")
    if st.get("stop_units"):
        print(f"    {RED}will stop + disable: {', '.join(st['stop_units'])}{RST} {DIM}(re-enabled by uninstall){RST}")
    sess = ssh_session_ip()
    if sess and not st["single"] and sess != mi["ip"]:
        warn(f"You are connected over SSH to {sess}, but management is {st['mgmt']} ({mi['ip']}). The web UI "
             f"will only be on {mi['ip']}" + (" and host SSH only on the management IP" if st["pin_ssh"] else "")
             + ". Type 1 to change it if that is wrong.")
    print(f"    {DIM}Web UI https://{bind}:{st['ports']['ui']} · sensor API port {st['ports']['sensor']}{RST}")
    if st["move_ssh"]:
        who = ", ".join(st["names"][r] for r in shared)
        print(f"    {RED}host SSH MOVES to port {st['ports']['ssh']}{RST}"
              + (f" (listens only on {mi['ip']})" if st["pin_ssh"] else "")
              + f"  {DIM}({who} {'shares' if len(shared) == 1 else 'share'} {mi['ip']}: a real server of that kind has no OpenSSH on 22; "
              f"your current session stays open){RST}")
    else:
        print(f"    {DIM}host SSH stays on port 22" + (f" (listens only on {mi['ip']})" if st["pin_ssh"] else "") + f"{RST}")
    if A.yes:
        _confirm_closed_manager(st)
        return None
    while True:
        try:
            v = input(f"\n  {BOLD}?{RST} Press Enter to install · type 1–5 to change that part · q to quit: ").strip().lower()
        except EOFError:
            die("input closed — nothing was changed")
        if v in ("", "y", "yes", "i", "install"):
            if confirm_dhcp(st) and _confirm_closed_manager(st):
                return None
            info("Fix the addresses or services above (or type a number to change that part — 4: put the decoy on "
                 "another interface), then press Enter to install.")
            continue
        if v in ("q", "quit", "n", "no"):
            die("Cancelled — nothing was changed.")
        if v in BACK_WORDS:
            return sections["5"]
        if v in sections:
            return sections[v]
        err("Type a number from 1 to 5, press Enter to install, or q to quit.")


def _confirm_closed_manager(st):
    shared = mgmt_decoys(st)
    if not shared:
        return True
    keep = set().union(*[ROLE_PORTS[r] for r in shared]) | {st["ports"]["ui"], st["ports"]["sensor"], st["ports"]["ssh"]}
    return confirm_closed_services(st, st["mgmt"], st["ifs"][st["mgmt"]]["ip"], keep)


# ----------------------------------------------------------------------------- manager install
def install_manager():
    d = A.dir or "/opt/redpot/manager"
    if os.path.exists(os.path.join(d, "rpot.json")) and not A.force:
        die(f"{d} already contains an installation. To add a decoy (e.g. on a new interface) and keep every planted "
            f"bait:  sudo ./install.sh add-decoy   ·  start over: --force (new persona + baits), or --dir")
    preflight_uid()
    st = {}
    steps = [("Network", step_network), ("Your company", step_identity), ("Decoy servers", step_roles),
             ("Decoy interfaces and names", step_details), ("Access", step_access)]
    steps.append(("Review", lambda s: review(s, {"1": 0, "2": 1, "3": 2, "4": 3, "5": 4})))
    wizard(steps, st)
    execute_manager(st, d)


def init_args(st):
    """rpotctl init (CLI contract, design §5): host mode, one --sensor NAME=role@IP%IFACE per decoy."""
    mi, ports = st["ifs"][st["mgmt"]]["ip"], st["ports"]
    args = ["init", "-d", "/d", "--force", "--domain", st["domain"], "--profile", st["profile"], "--net-mode", "host",
            "--mgmt-ip", mi, "--ui-port", str(ports["ui"]), "--sensor-port", str(ports["sensor"]),
            "--web-theme", st.get("web_theme", "webmail")]
    if st.get("public_ip"):
        args += ["--public-ip", st["public_ip"]]
    for r in st["roles"]:
        args += ["--sensor", f"{st['names'][r]}={r}@{st['ips'][r]}%{st['role_if'][r]}"]
    return args


def execute_manager(st, d):
    global EXECUTING
    EXECUTING = True
    banner("Installing")
    ensure_docker()
    ensure_image()
    if not A.dry_run:
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o700)
    mi = st["ifs"][st["mgmt"]]
    bind, public_ip, ports = mi["ip"], st["public_ip"], st["ports"]
    if st["roles"] or any(_restricted(st["allow"].get(k)) for k in ("ui", "sensor", "ssh")):
        preflight_firewall(list(dict.fromkeys(st["role_if"][r] for r in st["roles"])))   # R2-6: before any host change
    ctl(d, *init_args(st))
    if st["geo"]:
        ctl(d, "geoip", "-d", "/d")
    ctl(d, "wall-url", "-d", "/d", "--base", f"https://{public_ip or bind}:{ports['ui']}")
    # admin ports exist ONLY on the management IP
    ctl(d, "compose", "-d", "/d", "--ui-bind", bind)                      # last: also hands every file to uid 10001
    stop_conflicting(st, d)
    if st["move_ssh"]:
        banner(f"Moving host SSH to port {ports['ssh']}")
        warn(f"From now on connect with:  ssh -p {ports['ssh']} <user>@{bind}   (this session stays open)")
        move_ssh(ports["ssh"])
    if st["pin_ssh"]:
        pin_ssh(bind, {st["ips"][r] for r in st["roles"]} - {bind}, ports["ssh"] if st["move_ssh"] else 22)
    for p in (ports["ui"], ports["sensor"]):
        if shutil.which("ufw") and "active" in run(["ufw", "status"], capture=True, check=False).stdout:
            run(["ufw", "allow", f"{p}/tcp"], check=False, quiet=True)
    fw = write_firewall(d, st)
    if fw:
        apply_firewall(d)
    install_service("redpot", d, "redpot", "ReD-Pot manager + decoys", firewall=fw)
    ok = wait_https(bind, ports["ui"])
    decoys_ok = self_test("redpot", [{"name": st["names"][r], "role": r, "ip": st["ips"][r], "iface": st["role_if"][r]}
                                     for r in st["roles"]], d=d if fw else None)
    cfg = {} if A.dry_run else json.load(open(os.path.join(d, "rpot.json")))
    wall = ""
    try:
        wall = f"https://{public_ip or bind}:{ports['ui']}/wall?k={cfg['console']['wall_token']}"
    except KeyError:
        pass
    summary = [
        ("Web UI", f"https://{public_ip or bind}:{ports['ui']}"),
        ("Admin token", cfg.get("console", {}).get("admin_token", "?")),
        ("Wall (read-only)", wall),
        ("Sensor API port", str(ports["sensor"])),
        ("Manager fingerprint", cfg.get("console", {}).get("fingerprint", "?")),
        ("Decoys", " · ".join(f"{st['names'][r]} {st['ips'][r]} ({st['role_if'][r]})" for r in st["roles"]) or "none"),
        ("Host SSH", f"port {ports['ssh'] if st['move_ssh'] else 22}" + (f", only on {bind}" if st["pin_ssh"] else "")
         + ("" if st["move_ssh"] or st["pin_ssh"] else " (unchanged)")),
        ("Admin access", "web UI from " + ", ".join(st["allow"]["ui"]) + " · sensor API from " + ", ".join(st["allow"]["sensor"])
         + " · SSH from " + ", ".join(st["allow"]["ssh"])),
        ("Install dir", d),
        ("Service", "systemctl status redpot   (starts on boot)"),
    ]
    save_state(d, st)
    write_info(d, "manager", summary, ok, ports["ssh"] if st["move_ssh"] else None, ports["ui"], ports["sensor"],
               decoys_ok=decoys_ok)


def _proc_listening(text, ip=None, state="0A"):
    """LISTEN ports in /proc/net/tcp{,6} text (state 0A); for /proc/net/udp{,6} pass state "07" (a bound UDP
    socket). With ip: only sockets bound to ip or the wildcard."""
    out = set()
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or f[3] != state or ":" not in f[1]:
            continue
        addr, port = f[1].rsplit(":", 1)
        if ip and addr.strip("0"):                      # bound to one address: must be the decoy's
            if len(addr) != 8 or socket.inet_ntoa(bytes.fromhex(addr)[::-1]) != ip:
                continue
        out.add(int(port, 16))
    return out


def _decoy_container(project, svc):
    r = run(["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={project}",
             "--filter", f"label=com.docker.compose.service={svc}"], capture=True, check=False)
    return ((r.stdout or "").split() or [""])[0]


def wildcard_listeners():
    """Host sockets listening on EVERY address (0.0.0.0 / [::]) — they answer on decoy interfaces too unless the
    firewall closes them there (S-1 H1). [(port, proto, process)]; docker-proxy and ReD-Pot's own are skipped."""
    out = []
    if _test_ifaces() is not None:
        fake = os.environ.get("RPOT_TEST_WILDCARD")          # tests: "631/tcp=cupsd,5353/udp=avahi-daemon"
        for item in (fake.split(",") if fake else []):
            pp, _, who = item.partition("=")
            port, _, proto = pp.partition("/")
            out.append((int(port), proto or "tcp", who or "?"))
        return out
    for proto, flag in (("tcp", "-Htlnp"), ("udp", "-Hulnp")):
        r = run(["ss", flag], capture=True, check=False)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            m = re.match(r"^\[?(.*?)\]?(?:%\S+)?:(\d+)$", parts[3])
            if not m or m.group(1) not in ("0.0.0.0", "*", "::"):
                continue
            port = int(m.group(2))
            if proto == "udp" and port in IGNORE_UDP:
                continue
            pm = re.search(r'\(\("([^"]+)",pid=(\d+)', line)
            proc = pm.group(1) if pm else "?"
            if proc in ("docker-proxy", "python-lowports"):
                continue
            out.append((port, proto, proc))
    return sorted(set(out))


def show_wildcard_listeners():
    w = wildcard_listeners()
    if not w:
        return
    info(f"{DIM}Host services listening on all addresses (the firewall closes them on decoy interfaces; stop the ones "
         f"you do not need):{RST}")
    for port, proto, proc in w:
        info(f"   {YEL}{port}/{proto}{RST}  {proc}")


def self_test(project, decoys, secs=45, d=None):
    """B21: 'ready' must mean the decoys really answer. Per decoy: container running, every role port listening
    (read from the container's own /proc/net/tcp), and a TCP connect from here — every CE decoy is on a host
    address (S-1 M4). Also lists host services on wildcard addresses (S-1 H1) and — d = install dir with a
    firewall.sh — whether every firewall chain is hooked (review F6). decoys: [{name, role, ip}]. → ok?"""
    banner("Self-test: are the decoys answering?")
    show_wildcard_listeners()
    fw_ok = firewall_in_effect(d) is not False
    if not decoys:
        info("no local decoys")
        return fw_ok
    if A.dry_run:
        info("[dry-run] would check every decoy: container running, its ports listening, reachable")
        return fw_ok
    end = time.time() + secs
    rows, ok_all = [], True
    for x in decoys:
        svc, udp = x["name"].lower(), ROLE_UDP.get(x["role"], set())
        ports = sorted(ROLE_PORTS.get(x["role"], set()) - udp)          # TCP: listening + connect test
        bind = x["ip"]
        cid, listen, ulisten = "", set(), set()
        while True:
            cid = _decoy_container(project, svc)
            if cid:
                r = run(["docker", "exec", cid, "cat", "/proc/net/tcp", "/proc/net/tcp6"], capture=True, check=False)
                listen = _proc_listening(r.stdout or "", bind)
                if udp:                                                   # UDP-only services: bound socket is enough
                    r = run(["docker", "exec", cid, "cat", "/proc/net/udp", "/proc/net/udp6"], capture=True, check=False)
                    ulisten = _proc_listening(r.stdout or "", bind, state="07")
            if (cid and set(ports) <= listen and udp <= ulisten) or time.time() > end:
                break
            time.sleep(1)
        missing = [str(p) for p in ports if p not in listen] + [f"{p}/udp" for p in sorted(udp - ulisten)]
        reach = []
        for p in ports:
            try:
                socket.create_connection((x["ip"], p), 2).close()
            except OSError:
                reach.append(p)
        reach_txt = (f"{GREEN}✓{RST}" if not reach else f"{RED}✗ no answer on {','.join(map(str, reach))}{RST}")
        good = bool(cid) and not missing and not reach
        ok_all &= good
        rows.append((x, cid, missing, reach_txt, good))
    w = max(len(x["name"]) for x, *_ in rows)
    print(f"      {'':<2} {'decoy':<{w}}  {'address':<16} {'container':<10} {'ports listening':<22} reachable")
    for x, cid, missing, reach_txt, good in rows:
        mark = f"{GREEN}✓{RST}" if good else f"{RED}✗{RST}"
        cont = f"{GREEN}running{RST}   " if cid else f"{RED}not running{RST}"
        allp = [str(p) for p in sorted(ROLE_PORTS.get(x["role"], set()) - ROLE_UDP.get(x["role"], set()))] + \
               [f"{p}/udp" for p in sorted(ROLE_UDP.get(x["role"], set()))]
        lst = (f"{GREEN}✓ {' '.join(allp)}{RST}" if not missing else f"{RED}✗ missing {' '.join(missing)}{RST}")
        print(f"      {mark}  {x['name']:<{w}}  {x['ip']:<16} {cont} {lst:<31} {reach_txt}")
    if not ok_all:
        bad = [x["name"] for x, _, _, _, good in rows if not good]
        warn(f"self-test failed for {', '.join(bad)} — see: docker compose -p {project} logs {' '.join(b.lower() for b in bad)}")
    return ok_all and fw_ok


def wait_https(host, port, secs=90):
    if A.dry_run:
        return True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for _ in range(secs):
        try:
            with socket.create_connection((host, port), 2) as s, ctx.wrap_socket(s) as t:
                t.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
                if b"200" in t.recv(64):
                    return True
        except OSError:
            pass
        time.sleep(1)
    return False


def unit_text(d, project, desc, firewall=False, pre=(), post=()):
    """The systemd unit. With a firewall (review R2-2), the FIRST step stops the project's containers: after an
    unclean shutdown dockerd restarts them itself (restart: unless-stopped) before this unit runs — they are stopped
    until firewall.sh apply (with its check) has succeeded, and stay stopped if it fails. ExecStopPost removes the
    rules also after a failed start."""
    fw = [f"ExecStartPre=-/usr/bin/docker compose -p {project} stop",
          f"ExecStartPre=/bin/sh {d}/{FIREWALL} apply"] if firewall else []
    svc = ["Type=oneshot", "RemainAfterExit=yes", f"WorkingDirectory={d}", *fw,
           *(f"ExecStartPre=-{c}" for c in pre),
           f"ExecStart=/usr/bin/docker compose -p {project} up -d --remove-orphans",
           f"ExecStop=/usr/bin/docker compose -p {project} stop",
           *([f"ExecStopPost=/bin/sh {d}/{FIREWALL} remove"] if firewall else []),
           *(f"ExecStopPost=-{c}" for c in post),
           f"ExecReload=/usr/bin/docker compose -p {project} up -d --remove-orphans", "TimeoutStartSec=300"]
    return "\n".join(["[Unit]", f"Description={desc}", "Requires=docker.service",
                      "After=docker.service network-online.target", "Wants=network-online.target", "",
                      "[Service]", *svc, "", "[Install]", "WantedBy=multi-user.target", ""])


def install_service(unit, d, project, desc, firewall=False, pre=(), post=(), start=True):
    """systemd unit: `systemctl status|stop|start|restart <unit>`; starts after Docker on every boot."""
    text = unit_text(d, project, desc, firewall, pre, post)
    if A.dry_run:
        info(f"[dry-run] would install /etc/systemd/system/{unit}.service")
        return
    with open(f"/etc/systemd/system/{unit}.service", "w") as f:
        f.write(text)
    run(["systemctl", "daemon-reload"], check=False)
    run(["systemctl", "enable", unit], check=False, quiet=True)
    if start:
        run(["systemctl", "restart", unit], check=True)


INSTALL_DIRS = ("/opt/redpot/manager", "/opt/redpot/sensor")
UNIT_DIR = "/etc/systemd/system"
MOTD = "/etc/update-motd.d/99-redpot"
SSHD_MAIN = "/etc/ssh/sshd_config"
SSHD_DIR = "/etc/ssh/sshd_config.d"


def _moved_ssh_ports():
    """Ports host SSH was moved to by ReD-Pot (PORT_CONF), ['?'] if only the old sshd_config backup exists."""
    if os.path.exists(PORT_CONF):
        return [p for p in re.findall(r"(?m)^\s*Port\s+(\d+)", open(PORT_CONF).read()) if p != "22"]
    return ["?"] if os.path.exists(SSHD_MAIN + ".redpot.bak") else []


def restore_ssh():
    """Undo move_ssh: back to port 22 — listen on 22 first, verify, then drop the moved port."""
    conf, main = PORT_CONF, SSHD_MAIN
    moved = _moved_ssh_ports()
    if not moved:
        info("host SSH was not moved by ReD-Pot — nothing to restore")
        return
    if A.dry_run:
        info("[dry-run] would restore host SSH to port 22")
        return
    if os.path.exists(conf):
        open(conf, "w").write("# ReD-Pot uninstall in progress\nPort 22\n" + "".join(f"Port {p}\n" for p in moved))
    _restart_ssh()
    for _ in range(20):
        if 22 in listening_ports():
            break
        time.sleep(0.5)
    else:
        warn("sshd did not come back on 22 — leaving the moved port active so you are not locked out")
        return
    if os.path.exists(conf):
        os.remove(conf)
    if os.path.exists(main + ".redpot.bak"):
        shutil.copy2(main + ".redpot.bak", main)
        os.remove(main + ".redpot.bak")
    for bak in glob.glob(os.path.join(SSHD_DIR, "*" + SSH_DROPIN_BAK)):
        shutil.copy2(bak, bak[:-len(SSH_DROPIN_BAK)])
        os.remove(bak)
    _restart_ssh()
    info(f"{GREEN}host SSH restored to port 22{RST}")


def _firewall_artefacts(d):
    """What `firewall.sh remove` undoes, read from the generated script: [line]."""
    p = os.path.join(d, FIREWALL)
    if not os.path.exists(p):
        return []
    txt = open(p).read()
    v4 = list(dict.fromkeys(re.findall(r"\$IPT (?:-t mangle )?-N (REDPOT-[A-Z0-9]+)", txt)))
    v6 = list(dict.fromkeys(re.findall(r"\$IP6T -N (REDPOT-[A-Z0-9]+)", txt)))
    arp = list(dict.fromkeys(re.findall(r"(?m)^  arp (\S+)$", txt)))
    out = [f"firewall ({p} remove): iptables chains {', '.join(c for c in v4 if c != 'REDPOT-TTL') or 'none'}"
           + (", mangle REDPOT-TTL (TTL 128)" if "REDPOT-TTL" in v4 else "")
           + (f"; ip6tables chains {', '.join(v6)}" if v6 else "")]
    if arp:
        out.append(f"ARP sysctls arp_ignore / arp_announce of {', '.join(arp)} restored from "
                   f"{os.path.join(d, 'arp-sysctl.bak')}")
    return out


def uninstall_plan(targets, keep, purge):
    """Every artefact a CE manager / sensor install leaves on the host, as printed lines."""
    L = []
    for unit, d, project in targets:
        if unit is None:
            L.append(f"half-finished install in {d} (enrollment never completed): the directory"
                     + (", the pinned route to the manager" if os.path.exists(os.path.join(d, ROUTE_FILE)) else ""))
            continue
        L.append(f"{'manager' if unit == 'redpot' else 'remote sensor'} in {d}:")
        L.append(f"  service {unit} stopped + disabled, {os.path.join(UNIT_DIR, unit + '.service')} deleted")
        L += ["  " + x for x in _firewall_artefacts(d)]
        rp = os.path.join(d, ROUTE_FILE)
        if os.path.exists(rp):
            try:
                L.append("  pinned route to the manager: " + " ".join(str(x) for x in json.load(open(rp))))
            except (OSError, ValueError):
                L.append(f"  pinned route to the manager ({rp} is unreadable — remove the /32 route by hand)")
        L.append(f"  Docker compose project {project} ({os.path.join(d, 'docker-compose.yml')}): containers, networks"
                 + ("" if keep else ", volumes"))
        sp = os.path.join(d, STOPPED_FILE)
        if os.path.exists(sp):
            L.append("  re-enabled: " + ", ".join(open(sp).read().split()) + " (stopped by the installer)")
        L.append(f"  directory {d}" + (" — KEPT (--keep-data)" if keep else " (configuration, database, logs, baits)"))
    moved = _moved_ssh_ports()
    if moved:
        L.append(f"host SSH back to port 22 (from {', '.join(moved)}): {PORT_CONF if os.path.exists(PORT_CONF) else ''}"
                 + (f" {SSHD_MAIN}.redpot.bak" if os.path.exists(SSHD_MAIN + ".redpot.bak") else "")
                 + "".join(f" {b}" for b in sorted(glob.glob(os.path.join(SSHD_DIR, "*" + SSH_DROPIN_BAK)))))
    if os.path.exists(PIN_CONF):
        L.append(f"host SSH listens on every address again: {PIN_CONF}")
    if os.path.exists(MOTD):
        L.append(f"login banner {MOTD}")
    if purge:
        L.append(f"Docker image {IMAGE}")
    return L


def uninstall():
    banner("Uninstall ReD-Pot")
    targets = []
    for d in ([A.dir] if A.dir else list(INSTALL_DIRS)):
        if not os.path.exists(os.path.join(d, "docker-compose.yml")):
            if os.path.isdir(os.path.join(d, "data")) or os.path.isdir(os.path.join(d, "conf")):
                targets.append((None, d, None))
            continue
        if os.path.exists(os.path.join(d, "rpot.json")):
            targets.append(("redpot", d, "redpot"))
        elif os.path.exists(os.path.join(d, "conf", "sensor.json")) or os.path.isdir(os.path.join(d, "data")):
            targets.append(("redpot-sensor", d, "redpot-sensor"))
    if not targets:
        warn("no ReD-Pot installation found (use --dir if installed elsewhere)")
    keep = A.keep_data
    plan = uninstall_plan(targets, keep, A.purge_image)
    if plan:
        info(("[dry-run] would remove / restore:" if A.dry_run else "This removes / restores:"))
        for line in plan:
            print(f"      {line}")
    if A.dry_run:
        info("[dry-run] nothing was changed")
        return
    if not ask_yes("Remove ReD-Pot" + (" (keeping data/logs)" if keep else " INCLUDING its database and logs") +
                   " and restore host SSH to port 22?", False, flag=True if A.yes else None):
        die("aborted, nothing changed")
    for unit, d, project in targets:
        if unit is None:
            remove_pinned_route(d)
            shutil.rmtree(d, ignore_errors=True)
            info(f"removed the half-finished install in {d}")
            continue
        run(["systemctl", "disable", "--now", unit], check=False, quiet=True)
        if remove_pinned_route(d):
            info("removed the pinned route to the manager")
        if os.path.exists(os.path.join(d, FIREWALL)):
            run(["/bin/sh", os.path.join(d, FIREWALL), "remove"], check=False, quiet=True)
            info("removed the ReD-Pot firewall rules (and restored the ARP settings)")
        if os.path.exists(os.path.join(UNIT_DIR, f"{unit}.service")):
            os.remove(os.path.join(UNIT_DIR, f"{unit}.service"))
        run(f"cd {shlex.quote(d)} && docker compose -p {project} down {'' if keep else '-v'} --remove-orphans",
            check=False, quiet=True)
        restore_stopped(d)
        if not keep:
            shutil.rmtree(d, ignore_errors=True)
        info(f"removed {unit}" + (f" (data kept in {d})" if keep else ""))
    run(["systemctl", "daemon-reload"], check=False, quiet=True)
    restore_ssh()                    # decoys are gone → port 22 is free again
    unpin_ssh()
    if os.path.exists(MOTD):
        os.remove(MOTD)
    if A.purge_image:
        run(["docker", "image", "rm", "-f", IMAGE], check=False, quiet=True)
    banner("ReD-Pot removed")
    info("Docker itself and any services you stopped before installing were left as they are.")


def write_info(d, kind, rows, ok, ssh_port, *ports, decoys_ok=True):
    banner("ReD-Pot is ready" if ok and decoys_ok else
           "Installed — but the service did not answer yet (check: docker compose logs)" if not ok else
           "Installed — but some decoys failed the self-test (see the table above)")
    w = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"  {BOLD}{k:<{w}}{RST}  {GREEN}{v}{RST}")
    if ssh_port:
        print(f"\n  {RED}{BOLD}IMPORTANT: host SSH is now on port {ssh_port}  →  ssh -p {ssh_port} user@host{RST}")
    print(f"\n  Saved to {d}/INSTALL-INFO.txt (root only). Port reminder added to the SSH login banner.\n")
    if A.dry_run:
        return
    p = os.path.join(d, "INSTALL-INFO.txt")
    with open(p, "w") as f:
        f.write(f"ReD-Pot {kind} — installed {time.strftime('%Y-%m-%d %H:%M')}\n\n")
        for k, v in rows:
            f.write(f"{k:<{w}}  {v}\n")
    os.chmod(p, 0o600)
    write_motd(kind, rows)


def write_motd(kind, rows):
    motd = MOTD if os.path.isdir(os.path.dirname(MOTD)) else None
    lines = [f"ReD-Pot {kind}: " + ", ".join(f"{k} {v}" for k, v in rows if k in ("Web UI", "Sensor API port", "Host SSH", "Manager"))]
    if motd and not A.dry_run:
        with open(motd, "w") as f:
            f.write("#!/bin/sh\nprintf '%s\\n' " + " ".join("'" + l.replace("'", "") + "'" for l in lines) + "\n")
        os.chmod(motd, 0o755)


# ----------------------------------------------------------------------------- sensor-only install
JOIN_RE = r"redpot://[^/\s]+:\d+/[A-Za-z0-9_\-]+(\?[A-Za-z0-9_=&.\-]*)?#[0-9A-Fa-f:]{64,95}"


def join_role_hint(v):
    """A join string may carry the enrolled role as a hint: redpot://HOST:PORT/TOKEN?role=windows-file-server#FP
    (the manager knows it when it creates the enrollment). Only the installer reads it — to decide SSH handling
    and show the role before the one-time token is redeemed. Returns (join string without the hint, role|None)."""
    base, _, fp = v.partition("#")
    base, _, q = base.partition("?")
    role = next((x.split("=", 1)[1] for x in q.split("&") if x.startswith("role=")), None)
    return f"{base}#{fp}", role


def step_join(st):
    info("In the manager open Deception → Add a sensor. It shows a one-time join string like")
    info(f"{DIM}redpot://10.10.0.5:63462/AbC…xYz#B682DD80…{RST}")
    info(f"{DIM}Paste it here (it never goes on a command line, where other users of this server could read it).{RST}")

    def check(v):
        if not re.fullmatch(JOIN_RE, v):
            return "That is not a complete join string. Copy the whole value starting with redpot:// from the manager."
        hostport, fp = v[len("redpot://"):].split("/", 1)[0], v.split("#", 1)[1].replace(":", "").upper()
        host, port = hostport.rsplit(":", 1)
        if A.dry_run:
            return None
        got = peer_fingerprint(host, int(port))
        if not got:
            return (f"Cannot reach the manager at {host}:{port}. Check that the manager is running and that this "
                    f"server can reach it (firewall?), then paste the string again.")
        if got != fp:
            return (f"The manager at {host}:{port} presents a DIFFERENT certificate than the join string expects "
                    f"(expected {fp[:16]}…, got {got[:16]}…). Refusing — create a new join command on the right manager.")
    st["join"], role = join_role_hint(ask("Join string", st.get("join"), check, flag=A.join, flagname="--join"))
    hostport = st["join"][len("redpot://"):].split("/", 1)[0]
    st["manager"] = hostport
    st["role"] = None
    if role and role in ROLE_TITLE:
        st["role"] = role
        info(f"Role chosen on the manager: {BOLD}{ROLE_TITLE[role]}{RST}")
    elif role:
        warn(f"the join string names role '{role}', which this installer does not know — it is checked after enrollment")
    if not A.dry_run:
        info(f"{GREEN}Manager {hostport} reachable, certificate fingerprint matches.{RST}")


def review_sensor(st):
    st["roles"] = []
    _plan_ports(st)
    link_ip = st["ifs"][st["mgmt"]]["ip"]
    banner("Review — nothing has been changed yet")
    print(f"  {RED}1{RST} {BOLD}{'Manager':<10}{RST} {st['manager']}  "
          f"{DIM}({'already enrolled' if st.get('resume') else 'certificate verified'}){RST}")
    print(f"  {RED}2{RST} {BOLD}{'Network':<10}{RST} manager link via {st['mgmt']} · decoy on {st['role_if']['_']}"
          + (" (same interface)" if st["single"] else ""))
    print(f"    {BOLD}{'Decoy':<10}{RST} "
          + (f"{ROLE_TITLE.get(st['role'], st['role'])} · " if st.get("role") else "")
          + f"{st['ips']['_']} on {st['role_if']['_']}"
          + ("  (this server's address)" if st["single"] else "  (the interface's own address)"))
    print(f"    {DIM}host SSH " + (f"moves to port {st['ports']['ssh']}" if st["move_ssh"] else
                                   f"stays on port 22, listens only on {link_ip}")
          + (f" · from {', '.join((st.get('allow') or {}).get('ssh') or [ANY])} (+ your current SSH client)"
             if st["single"] else "") + f"{RST}")
    if A.yes:
        _confirm_closed_sensor(st)
        return None
    while True:
        try:
            v = input(f"\n  {BOLD}?{RST} Press Enter to install · type 1–2 to change that part · q to quit: ").strip().lower()
        except EOFError:
            die("input closed — nothing was changed")
        if v in ("", "y", "yes", "i", "install"):
            if confirm_dhcp(st) and _confirm_closed_sensor(st):
                return None
            info("Fix the addresses or services above (or type a number to change that part — 2: put the decoy on "
                 "another interface), then press Enter to install.")
            continue
        if v in ("q", "quit", "n", "no"):
            die("Cancelled — nothing was changed.")
        if v in BACK_WORDS or v in ("1", "2"):
            if st.get("resume"):
                if v == "1":
                    info(f"{DIM}This install continues an existing enrollment — the manager cannot change.{RST}")
                return 0
            return 0 if v == "1" else 1
        err("Type 1 or 2 to change a part, press Enter to install, or q to quit.")


def _confirm_closed_sensor(st):
    """Decoy on the manager-link interface (st['single']): everything else on that NIC closes (S-1 H1 on sensors)."""
    if not st["single"]:
        return True
    keep = set(ROLE_PORTS.get(st.get("role"), set())) | {st["ports"]["ssh"]}
    return confirm_closed_services(st, st["mgmt"], st["ifs"][st["mgmt"]]["ip"], keep)


JOIN_MAX = 512


def _join_from_stdin():
    """--join -: the join string is the first line on stdin (`sudo ./install.sh sensor --join - < file`, or
    `printf '%s\n' 'redpot://…' | sudo ./install.sh sensor --join -` — printf is a shell builtin, not a process).
    The rest of the wizard then reads the terminal (/dev/tty) if there is one."""
    try:
        v = sys.stdin.readline(JOIN_MAX + 1).strip()
    except (OSError, ValueError):
        v = ""
    if not v:
        die("--join -: no join string on standard input")
    if not sys.stdin.isatty() and not A.yes:
        try:
            sys.stdin = open("/dev/tty")        # interactive questions after a piped join string
        except OSError:
            pass
    return v


def _join_from_file(path):
    """--join-file FILE: a regular file (no symlink) owned by root and not readable by group/others (chmod 600) —
    the one-time token must not be readable by other local users. Delete it after the install (the token is
    spent then anyway)."""
    import stat
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        die(f"--join-file {path}: {e.strerror or e} (a symlink is not accepted)")
    try:
        fs = os.fstat(fd)
        if not stat.S_ISREG(fs.st_mode):
            die(f"--join-file {path}: not a regular file")
        if fs.st_uid != os.geteuid() or fs.st_mode & 0o077:
            die(f"--join-file {path}: must be owned by root and not readable by others "
                f"(sudo chown root: {shlex.quote(path)} && sudo chmod 600 {shlex.quote(path)})")
        v = os.read(fd, JOIN_MAX + 1).decode("utf-8", "replace").strip().splitlines()
    finally:
        os.close(fd)
    if not v or not v[0].strip():
        die(f"--join-file {path}: empty")
    return v[0].strip()


def resolve_join():
    """VM defect B7: where the join string comes from. On the command line (--join 'redpot://…') every local user
    sees it in ps for the whole install (sudo keeps its argv) and could redeem it first — still accepted, with a
    warning; the safe ways are the prompt, --join - (stdin) and --join-file."""
    if A.join is not None and A.join_file:
        die("use either --join or --join-file, not both")
    if A.join_file:
        A.join = _join_from_file(A.join_file)
    elif A.join == "-":
        A.join = _join_from_stdin()
    elif A.join is not None:
        warn("the join string is on the command line: local users of this server can read it in the process list "
             "(ps) while the installer runs. Next time run  sudo ./install.sh sensor  and paste it when asked, or "
             "use --join - (standard input) or --join-file FILE (chmod 600).")


def install_sensor():
    d = A.dir or "/opt/redpot/sensor"
    role_catalog()
    resolve_join()
    preflight_uid()
    conf = os.path.join(d, "conf", "sensor.json")
    done = os.path.exists(os.path.join(d, "docker-compose.yml"))
    st = {}
    if os.path.exists(conf) and not done and not A.join:
        # enrolled, but the install stopped afterwards (busy ports, Ctrl+C): the one-time token is spent,
        # so continue with that enrollment instead of asking for a new one
        sj = json.load(open(conf))
        st.update(join="(enrolled)", resume=sj, role=sj["sensor"]["role"],
                  manager=sj["manager"]["url"].split("://", 1)[-1].split("/", 1)[0])
        banner("Continuing an unfinished sensor install")
        info(f"{d} holds the enrollment of {BOLD}{sj['sensor']['name']}{RST} ({ROLE_TITLE.get(st['role'], st['role'])}) "
             f"at {st['manager']} — no join string needed.")
        steps = [("Network", step_sensor_network), ("Review", review_sensor)]
    else:
        if os.path.exists(conf) and not A.force:
            die(f"{d} already contains a sensor (use --force or --dir)")
        steps = [("Join a manager", step_join), ("Network", step_sensor_network), ("Review", review_sensor)]
    wizard(steps, st)
    execute_sensor(st, d)


def _clean_text(t):
    """Text from a child process for the terminal: no control characters (no escape sequences)."""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", t or "")


def enroll(st, d):
    """Redeem the one-time join token (`sensor join` in the image, host network). A full Community Edition
    (manager answers 409, D-6) gets its own clear message; the token is then left unused and nothing is
    installed — the pinned route to the manager is removed again."""
    banner("Enrolling")
    info(f"{DIM}contacting the manager {st['manager']} (retries for up to 30 s if it does not answer){RST}")
    # VM defect B7: the one-time token never goes into argv (docker client + container process are visible in ps
    # to every local user): `-e RPOT_JOIN` without a value copies it from the docker client's environment (root
    # only), and `sensor join` reads RPOT_JOIN when no join string is given.
    r = run(["docker", "run", "--rm", "--network", "host", "-e", "RPOT_JOIN", "-v", f"{d}/data:/var/lib/rpot", IMAGE,
             "sensor", "join"], check=False, capture=True, env={"RPOT_JOIN": st["join"]})
    out = _clean_text((r.stdout or "") + "\n" + (r.stderr or "")).strip()
    for line in _clean_text(r.stdout).splitlines():
        if line.strip():
            info(line.strip())
    if r.returncode == 0:
        return
    remove_pinned_route(d)
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    hit = next((l for l in lines if "decoy limit reached" in l), None)
    if hit:
        die(f"the manager refused this sensor: decoy limit reached — Community Edition supports up to {MAX_DECOYS} "
            f"decoys in total.\n    {hit.removeprefix('[x] ')}\n    Nothing was installed on this server and the join "
            f"string is still valid: free a slot on the manager, then run the installer again.")
    die("enrollment failed: " + ("\n    ".join(lines[-6:]) or f"exit code {r.returncode}")
        + "\n    Nothing was installed on this server.")


def execute_sensor(st, d):
    global EXECUTING
    EXECUTING = True
    ensure_docker()
    ensure_image()
    if not A.dry_run:
        os.makedirs(os.path.join(d, "data"), exist_ok=True)
        os.chmod(d, 0o700)
    run(["chown", "-R", "10001:10001", os.path.join(d, "data")], check=False)
    preflight_firewall([st["role_if"]["_"]])    # R2-6: before enrolling (token spent) and any host change
    if os.path.exists(os.path.join(d, FIREWALL)):
        # --force over an earlier install: its egress guard (uid 10001) would block the enrollment container
        run(["/bin/sh", os.path.join(d, FIREWALL), "remove"], check=False, quiet=True)
    link_route = manager_route(st)
    if st.get("resume"):
        info(f"using the existing enrollment in {d}/conf")
    else:
        enroll(st, d)
    if not A.dry_run and not st.get("resume"):
        # identity + baits → ./conf, mounted READ-ONLY into decoy and relay: a hijacked decoy can't
        # rewrite the manager URL/fingerprint the relay uses, nor its own baits.
        os.makedirs(os.path.join(d, "conf"), exist_ok=True)
        for n in ("sensor.json", "baits"):
            src, dst = os.path.join(d, "data", n), os.path.join(d, "conf", n)
            if os.path.exists(dst):
                shutil.rmtree(dst) if os.path.isdir(dst) else os.remove(dst)
            shutil.move(src, dst)
        run(["chown", "-R", "10001:10001", os.path.join(d, "conf")], check=False)
    sj = st.get("resume") or ({"sensor": {"name": "DRYRUN", "role": st.get("role"), "ip": None}} if A.dry_run else
                               json.load(open(os.path.join(d, "conf", "sensor.json"))))
    s = sj["sensor"]
    role = s["role"]
    if role is not None and role not in ROLE_TITLE:
        die(f"the manager enrolled this sensor as an unknown role {_clean_text(str(role))[:40]!r} — update the installer")
    # dry-run: nothing is enrolled, so the role is the join string's hint or simply not known yet (B20)
    info(f"Enrolled as {BOLD}{s['name']}{RST} — " + (ROLE_TITLE[role] if role else
                                                      "role from the manager (unknown in dry-run)"))
    ip, ifname, link_ip = st["ips"]["_"], st["role_if"]["_"], st["ifs"][st["mgmt"]]["ip"]
    if st["move_ssh"] and st["ports"]["ssh"] in ROLE_PORTS.get(role, set()):
        die("internal: SSH port collides with the decoy role")
    st["stop_units"] = []
    if not role:
        info("[dry-run] busy ports on the decoy address are checked after enrollment, when the role is known")
    elif not audit_address(st, ip, role, {}):
        die(f"The decoy's ports are in use (see above). Free them, then run the installer again — the enrollment "
            f"of {s['name']} is kept, no new join command is needed.")
    stop_conflicting(st, d)
    write_sensor_compose(d, s["name"], role, ip, ifname, follow=st["single"])
    if st["move_ssh"]:
        banner(f"Moving host SSH to port {st['ports']['ssh']}")
        warn(f"From now on connect with:  ssh -p {st['ports']['ssh']} <user>@{link_ip}")
        move_ssh(st["ports"]["ssh"])
    else:
        pin_ssh(link_ip, {ip})
    decoy = {"name": s["name"], "role": role, "ip": ip, "iface": ifname}
    if role:
        fw = write_firewall(d, dict(st, allow=st.get("allow") or {}), [decoy])   # B5: SSH allow-list (shared NIC)
    else:
        fw = True
        info("[dry-run] firewall.sh (only the decoy's ports on its interface, decoy egress = replies only) is "
             "written after enrollment, when the role is known")
    if fw and role:
        apply_firewall(d, "redpot-sensor")
    install_service("redpot-sensor", d, "redpot-sensor", "ReD-Pot remote sensor", firewall=fw,
                    pre=[link_route[0]] if link_route else (), post=[link_route[1]] if link_route else ())
    write_info(d, "sensor", [("Sensor", f"{s['name']} ({ROLE_TITLE.get(role, role or 'role from the manager')})"),
                             ("Decoy IP", f"{ip} on {ifname}" + (" (follows DHCP)" if st["single"] else "")),
                             ("Manager", st["manager"]),
                             ("Host SSH", (f"port {st['ports']['ssh']}" if st["move_ssh"] else f"port 22, only on {link_ip}")
                              + (f", from {', '.join(st['allow']['ssh'])}" if _restricted((st.get("allow") or {}).get("ssh"))
                                 else "")),
                             ("Install dir", d), ("Service", "systemctl status redpot-sensor")],
               True, st["ports"]["ssh"] if st["move_ssh"] else None,
               decoys_ok=self_test("redpot-sensor", [decoy] if role else [], d=d if fw else None))


def peer_fingerprint(host, port):
    import hashlib
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), 5) as s, ctx.wrap_socket(s) as t:
            return hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest().upper()
    except OSError:
        return None


def manager_route(st):
    """The answer to "which interface reaches the manager?" must be what the kernel really uses. With two NICs
    in one subnet the kernel may pick the other one (and on a Wi-Fi bridge that one may not reach the manager at
    all). If the manager is in the chosen link's subnet but routed elsewhere, pin a /32 route through the link —
    applied now and by the service at every start, removed at stop/uninstall. Returns (add, delete) or None."""
    mhost = st["manager"].rsplit(":", 1)[0]
    link = st["ifs"][st["mgmt"]]
    try:
        in_net = ipaddress.ip_address(mhost) in _subnet(link)
    except ValueError:
        return None                              # a DNS name: leave routing to the system
    if not in_net or route_iface(mhost) == link["name"]:
        return None
    if not valid_iface_name(link["name"]) or valid_ip(link["ip"]):
        die(f"refusing to pin a route through {link['name']!r}")
    ipb = shutil.which("ip") or "/usr/sbin/ip"
    mhost = str(ipaddress.ip_address(mhost))
    add = [ipb, "route", "replace", f"{mhost}/32", "dev", link["name"], "src", link["ip"]]      # argv lists (S-1 L13)
    dele = [ipb, "route", "del", f"{mhost}/32", "dev", link["name"]]
    info(f"The kernel would reach the manager {mhost} via {route_iface(mhost)}, not {link['name']} — "
         f"pinning a route through {link['name']}")
    run(add, check=False, quiet=True)
    if not A.dry_run:
        with open(os.path.join(A.dir or "/opt/redpot/sensor", ROUTE_FILE), "w") as f:
            json.dump(dele, f)
    return " ".join(add), " ".join(dele)     # systemd Exec lines: every token validated above, no shell


ROUTE_FILE = "manager-route.txt"


def remove_pinned_route(d):
    """Undo manager_route: the saved `ip route del` argv (JSON list), checked before it runs — never a shell."""
    p = os.path.join(d, ROUTE_FILE)
    if not os.path.exists(p):
        return False
    try:
        argv = json.load(open(p))
        ok = (isinstance(argv, list) and len(argv) == 6 and all(isinstance(x, str) for x in argv)
              and os.path.basename(argv[0]) == "ip" and argv[1:3] == ["route", "del"] and argv[4] == "dev"
              and valid_ip(argv[3].removesuffix("/32")) is None and valid_iface_name(argv[5]))
    except (OSError, ValueError):
        ok = False
    if not ok:
        warn(f"{p} is not a route this installer wrote — not run (remove the /32 route to the manager by hand)")
        return False
    run(argv, check=False, quiet=True)
    return True


def sensor_compose_text(name, role, ip, iface, follow):
    """docker-compose.yml of a remote sensor (CE, D-2): the relay sidecar on a Docker bridge (the only container
    that talks to the manager) + ONE decoy on the host network, answering on its interface's own address.
    follow (decoy on the manager-link interface): RPOT_SENSOR_IFACE — the decoy binds that interface's current
    address and is restarted when DHCP changes it (S-1 L14). Otherwise RPOT_BIND_IP = the interface's address.
    No extra address and no extra MAC on the LAN. The decoy reaches the relay only over its Unix socket."""
    if not re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,15}(?<!-)", name or "") or valid_ip(ip) or not valid_iface_name(iface):
        die(f"refusing to write a compose file for {name!r} / {ip!r} / {iface!r}")
    svc = name.lower()
    L = ["# generated by the ReD-Pot installer — remote sensor", "services:",
         "  relay:", f"    image: {IMAGE}", "    command: [\"relay\"]", "    restart: unless-stopped",
         "    environment:", "      RPOT_SENSOR_JSON: /etc/rpot/sensor.json",
         "    volumes:", "      - ./conf/sensor.json:/etc/rpot/sensor.json:ro", "      - relay-sock:/run/rpot",
         "    networks: [mgmt]", "    mem_limit: 96m", "    pids_limit: 128", "    cap_drop: [ALL]", "    security_opt: [\"no-new-privileges:true\"]",
         "    read_only: true", "    tmpfs: [\"/tmp:size=8m\"]", "    logging:", "      driver: json-file", "      options: {max-size: \"10m\", max-file: \"3\"}",
         f"  {svc}:", f"    image: {IMAGE}", "    command: [\"sensor\"]", "    restart: unless-stopped",
         f"    hostname: {svc}", "    depends_on: [relay]",
         "    user: \"0:0\"",                      # RC-18 F5: the entrypoint (RPOT_PRIVDROP) drops to uid/gid 10001
         "    environment:",
         "      RPOT_DATA: /var/lib/rpot", "      RPOT_SENSOR_CONFIG: /etc/rpot/sensor.json", "      RPOT_BAITS: /srv/rpot/baits",
         "      RPOT_RELAY_SOCKET: /run/rpot/relay.sock",
         f"      RPOT_SENSOR_IP: \"{ip}\"",
         (f"      RPOT_SENSOR_IFACE: \"{iface}\"" if follow else f"      RPOT_BIND_IP: \"{ip}\""),
         "      RPOT_PRIVDROP: \"1\"",
         "      RPOT_STDOUT: \"0\"",
         "    volumes:", "      - ./conf/sensor.json:/etc/rpot/sensor.json:ro", "      - ./conf/baits:/srv/rpot/baits:ro",
         "      - ./data:/var/lib/rpot", "      - relay-sock:/run/rpot", "    mem_limit: 192m", "    pids_limit: 384",
         "    read_only: true", "    tmpfs: [\"/tmp:size=16m,mode=1777\"]", "    logging:", "      driver: json-file",
         "      options: {max-size: \"10m\", max-file: \"3\"}",
         # same hardening as rpotctl's host-mode decoys (RC-18 F5): starts as root with only NET_BIND_SERVICE +
         # SETUID + SETGID + SETPCAP under no-new-privileges; deploy/entrypoint.sh (RPOT_PRIVDROP) execs setpriv to
         # uid/gid 10001 with no groups, bounding set = NET_BIND_SERVICE (dropping it needs SETPCAP, R2-4) and
         # NET_BIND_SERVICE as an ambient capability (:445 etc.). It then writes ./data
         # (chowned to 10001 by execute_sensor) and the relay socket volume (/run/rpot, owned by 10001 in the image)
         # as uid 10001, exactly as before.
         "    network_mode: host", "    cap_drop: [ALL]", "    cap_add: [NET_BIND_SERVICE, SETUID, SETGID, SETPCAP]",
         "    security_opt: [\"no-new-privileges:true\"]",
         "    labels:", f"      rpot.role: {role or 'unknown'}",
         "networks:", "  mgmt: {}",
         "volumes:", "  relay-sock:"]
    return "\n".join(L) + "\n"


def write_sensor_compose(d, name, role, ip, iface, follow):
    text = sensor_compose_text(name, role, ip, iface, follow)
    if A.dry_run:
        info(f"[dry-run] would write {d}/docker-compose.yml:")
        print(text, end="")
        return
    p = os.path.join(d, "docker-compose.yml")
    fd = os.open(p + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(p + ".new", p)



# ----------------------------------------------------------------------------- add / remove a decoy later
STATE_FILE = "installer.json"
PORT_CONF = "/etc/ssh/sshd_config.d/00-redpot-port.conf"


def save_state(d, st):
    """What add-decoy / remove-decoy need later: management interface, admin ports, allowlists, SSH changes."""
    if A.dry_run:
        return
    keep = {k: st[k] for k in ("mgmt", "allow", "ports", "move_ssh", "pin_ssh", "public_ip") if k in st}
    keep["mgmt_ip"] = st["ifs"][st["mgmt"]]["ip"]
    p = os.path.join(d, STATE_FILE)
    with open(p, "w") as f:
        json.dump(keep, f, indent=1)
    os.chmod(p, 0o600)


def load_state(d):
    """installer.json, written by every CE install. CE 1.0 supports fresh installs only — no legacy rebuild."""
    p = os.path.join(d, STATE_FILE)
    if not os.path.exists(p):
        die(f"{p} is missing — this install was not made by the ReD-Pot 1.0 installer. Community Edition 1.0 "
            f"supports fresh installs only: sudo ./install.sh uninstall, then install again.")
    return json.load(open(p))


def _existing_manager(d):
    if not os.path.exists(os.path.join(d, "rpot.json")):
        if os.path.exists(os.path.join(d, "conf", "sensor.json")) or os.path.exists("/opt/redpot/sensor/conf/sensor.json"):
            die("this server is a remote SENSOR (one decoy). To add a decoy, install another sensor from the manager "
                "(Deception → Add a sensor), or run add-decoy on the manager.")
        die(f"no ReD-Pot manager found in {d} — install it first (sudo ./install.sh manager), or pass --dir")
    if not os.path.exists(os.path.join(d, "docker-compose.yml")):
        die(f"{d} holds an unfinished install — run  sudo ./install.sh manager --force  to finish it first")
    cfg = json.load(open(os.path.join(d, "rpot.json")))
    if cfg.get("version") != 2:
        die("this install was made by an older ReD-Pot — Community Edition 1.0 supports fresh installs only: "
            "sudo ./install.sh uninstall, then install again.")
    if (cfg.get("network") or {}).get("mode") != "host":
        die("add-decoy / remove-decoy work on a production (host-network) install; a Docker-bridge lab is managed "
            "with rpotctl add-sensor / remove-sensor.")
    for x in cfg.get("sensors") or []:
        if not valid_iface_name(x.get("iface")):
            die(f"rpot.json: decoy {x.get('name')!r} has no valid interface — refusing to change this install")
    return cfg


def _slots_ok(v):
    keys = ("max", "used", "local", "remote", "pending")
    if not isinstance(v, dict) or not all(isinstance(v.get(k), int) and not isinstance(v.get(k), bool) and v[k] >= 0
                                          for k in keys):
        raise ValueError("expected {max, used, local, remote, pending} as non-negative integers")
    return {k: v[k] for k in keys}


def decoy_slots(d, cfg=None):
    """D-6 layer 2: {max, used, local, remote, pending} as the running console counts them (`rpotctl slots`
    inside the console container: local decoys + remote sensors + pending joins). RPOT_TEST_SLOTS (JSON)
    overrides it in tests. Console not running → die: the count cannot be known."""
    t = os.environ.get("RPOT_TEST_SLOTS")
    if t:
        try:
            return _slots_ok(json.loads(t))
        except ValueError as e:
            die(f"RPOT_TEST_SLOTS: {e}")
    if A.dry_run:
        n = len((cfg or {}).get("sensors") or [])
        info(f"[dry-run] would read the decoy count from the console (rpotctl slots); counting only the {n} local "
             f"decoy{'s' if n != 1 else ''} here")
        return {"max": MAX_DECOYS, "used": n, "local": n, "remote": 0, "pending": 0}
    cid = _decoy_container("redpot", "console")
    if not cid:
        die("the ReD-Pot console is not running, so the decoy count (remote sensors and pending joins included) "
            "cannot be checked — start the manager first (sudo systemctl start redpot), then run add-decoy again")
    r = run(["docker", "exec", cid, "python", "/opt/rpot/rpotctl.py", "slots", "--db", "/var/lib/rpot/rpot.db",
             "--config", "/etc/rpot/rpot.json"], capture=True, check=False)
    lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
    try:
        if r.returncode != 0 or not lines:
            raise ValueError((r.stderr or "no output").strip()[-300:])
        return _slots_ok(json.loads(lines[-1]))
    except ValueError as e:
        die(f"could not read the decoy count from the console (rpotctl slots): {e}")


def _add_context(d, slots=True):
    cfg = _existing_manager(d)
    role_catalog()
    stt = load_state(d)
    ifs = interfaces()
    if not ifs:
        die("No usable network interface (up, with an IPv4 address) was found.")
    st = {"ifs": {i["name"]: i for i in ifs}, "cfg": cfg, "existing": list(cfg.get("sensors") or [])}
    mgmt = stt.get("mgmt") if stt.get("mgmt") in st["ifs"] and st["ifs"][stt["mgmt"]]["ip"] == stt.get("mgmt_ip") else \
        next((n for n, i in st["ifs"].items() if i["ip"] == stt.get("mgmt_ip")), None)
    if not mgmt:
        die(f"the management address {stt.get('mgmt_ip')} of this install is not on any interface any more "
            f"(DHCP gave the server another address?). Fix the address first.")
    st.update(mgmt=mgmt, allow=stt.get("allow") or {}, ports=stt["ports"], move_ssh=stt.get("move_ssh", False),
              pin_ssh=stt.get("pin_ssh", False), public_ip=stt.get("public_ip"), single=len(ifs) == 1)
    st["admin_ports"] = {st["ports"]["ui"], st["ports"]["sensor"]} | ({st["ports"]["ssh"]} if st["move_ssh"] else set())
    if slots:
        st["slots"] = sl = decoy_slots(d, cfg)
        if sl["used"] >= MAX_DECOYS:
            die(limit_message(sl["used"]))
    return st


def _decoy_rows(st):
    """Decoys as firewall / self-test / pin_ssh need them. Every CE decoy is on its interface's own address."""
    return [{"name": x["name"], "role": x["role"], "ip": x["ip"], "iface": x["iface"]} for x in st["existing"]]


def step_add_iface(st):
    """Only interfaces without a decoy are offered (one decoy per interface); the management interface is free
    while no decoy is on it. The decoy answers on the interface's own address."""
    sess = ssh_session_ip()
    on = {x["iface"]: x["name"] for x in st["existing"]}
    blocked_mgmt = A.no_ssh_move and not st["move_ssh"]       # a decoy there would have to move SSH
    free = [n for n in st["ifs"] if n not in on and not (blocked_mgmt and n == st["mgmt"])]
    for n, why in unusable_interfaces():
        info(f"   -  {n:<10} {DIM}{why}{RST}")
    if on:
        info(f"{DIM}Not offered (one decoy per interface): " + ", ".join(f"{n} → {v}" for n, v in on.items()) + f"{RST}")
    if blocked_mgmt and st["mgmt"] not in on:
        info(f"{DIM}Not offered: {st['mgmt']} (management — a decoy there moves host SSH; --no-ssh-move){RST}")
    given = A.decoy_if or (A.role_ifaces.split("=", 1)[-1] if A.role_ifaces else None)
    if given is not None and given in on:
        die(f"{given} already holds {on[given]} — one decoy per interface. Remove it first "
            f"(sudo ./install.sh remove-decoy {on[given]}) or choose a free interface.")
    if given is not None and blocked_mgmt and given == st["mgmt"]:
        die(f"--no-ssh-move: a decoy on the management interface {given} would share this server's address and move "
            f"host SSH — use another interface or drop --no-ssh-move")
    if not free:
        die("every usable interface already holds a decoy (one decoy per interface). Add a remote sensor instead "
            "(Deception → Add a sensor), or remove a decoy first.")
    allx = list(st["ifs"])
    opts = [(n, _iface_label(st["ifs"][n], sess) + (f"   {DIM}(management — this server's address: host SSH "
                                                     f"{'stays moved' if st['move_ssh'] else 'moves'}){RST}"
                                                     if n == st["mgmt"] else f"   {GREEN}(free){RST}")) for n in free]
    dflt = st.get("new_if") if st.get("new_if") in free else default_decoy_iface(st, free)
    st["new_if"] = pick("Interface for the NEW decoy", opts, dflt, flag=given, flagname="--decoy-if",
                        numbers=[allx.index(n) + 1 for n in free])
    st["new_ip"] = st["ifs"][st["new_if"]]["ip"]


def step_add_role(st):
    cat = role_catalog()
    have = {x["role"] for x in st["existing"]}
    opts = [(r["id"], f"{r['title']:<26} {DIM}ports {' '.join(map(str, r['ports']))}{RST}"
             + (f"  {DIM}(already one in this install){RST}" if r["id"] in have else "")) for r in cat]
    dflt = st.get("new_role") or next((r["id"] for r in cat if r["id"] not in have), cat[0]["id"])
    flag = A.roles
    if flag and ("," in flag or flag.lower() in ("all", "none")):
        die("--roles: add-decoy adds exactly ONE decoy — pass a single role id")
    rid = pick("Which server should the new decoy pretend to be?", opts, dflt, flag=flag, flagname="--roles")
    st["new_role"] = rid
    taken = {x["name"].upper() for x in st["existing"]}
    base = ROLE_DEFAULT[rid]
    dname = st.get("new_name") or (base if base not in taken else next(
        f"{base[:-2]}{k:02d}" for k in range(2, 99) if f"{base[:-2]}{k:02d}" not in taken))
    given = None
    if A.names:
        given = A.names.split("=", 1)[1] if "=" in A.names else A.names
    st["new_name"] = ask("Host name (use YOUR naming, e.g. ARB-FS-02)", dname,
                         lambda v: HOSTNAME_HINT if not re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,15}(?<!-)", v)
                         else (f"'{v.upper()}' is already a decoy in this install." if v.upper() in taken else None),
                         flag=given, flagname="--names").upper()
    st["stop_units"] = []
    info(f"{DIM}{st['new_name']} answers on {st['new_if']}'s own address {st['new_ip']}{RST}")
    if not audit_address(st, st["new_ip"], rid):
        if A.yes or A.decoy_if or A.role_ifaces:
            die("the decoy's ports are in use on that address (see above)")
        raise Back()                                 # choose another interface


def step_add_access(st):
    """S-1 H2 (+ SSH, security review): a decoy that joins the management address must not show the web UI, sensor
    API or the moved host SSH to whoever scans it — re-ask open allowlists (default: the admin's own client), --yes
    needs explicit --allow-ui/--allow-sensor/--allow-ssh for the ones still open."""
    if st["new_if"] != st["mgmt"]:
        info(f"{DIM}Admin access unchanged: the new decoy does not share the management address.{RST}")
        return
    keys = tuple(k for k in ("ui", "sensor", "ssh") if not _restricted(st["allow"].get(k)))
    if not keys:
        info(f"{DIM}Admin access unchanged: web UI, sensor API and host SSH are already limited.{RST}")
        return
    st["allow"] = ask_allowlists(st, st["ifs"][st["mgmt"]]["ip"], True, st["allow"], keys=keys)


def _add_plan(st):
    """SSH + firewall consequences of the new decoy (same rules as a fresh install)."""
    mi = st["ifs"][st["mgmt"]]["ip"]
    st["new_on_mgmt"] = st["new_if"] == st["mgmt"]
    st["need_move"] = st["new_on_mgmt"] and not st["move_ssh"]
    st["need_pin"] = not st["new_on_mgmt"]
    if st["need_move"]:
        if A.no_ssh_move:
            die(f"--no-ssh-move: the new decoy shares this server's address {mi}, so host SSH would have to move — "
                f"use another interface or drop --no-ssh-move")
        if "new_ssh" not in st:
            st["new_ssh"] = int(A.ssh_port or random_ports(1, set(ROLE_PORTS[st["new_role"]]) | st["admin_ports"] | {22})[0])


def _all_decoys(st):
    return _decoy_rows(st) + [{"name": st["new_name"], "role": st["new_role"], "ip": st["new_ip"], "iface": st["new_if"]}]


def review_add(st):
    _add_plan(st)
    banner("Review — nothing has been changed yet")
    mi = st["ifs"][st["mgmt"]]["ip"]
    i = st["ifs"][st["new_if"]]
    kind = "this server's address, shared with the manager" if st["new_on_mgmt"] else "the interface's own address"
    sl = st.get("slots") or {}
    print(f"  {RED}1{RST} {BOLD}{'Interface':<10}{RST} {st['new_if']} · decoy answers on {st['new_ip']}/{i['prefix']}  "
          f"{DIM}({kind}){RST}")
    print(f"  {RED}2{RST} {BOLD}{'Decoy':<10}{RST} {st['new_name']} · {ROLE_TITLE[st['new_role']]}  "
          f"{DIM}(decoys after this: {sl.get('used', len(st['existing'])) + 1} of {MAX_DECOYS}){RST}")
    al = st["allow"]
    print(f"  {RED}3{RST} {BOLD}{'Access':<10}{RST} web UI from {', '.join(al.get('ui') or [ANY])} · sensor API from "
          f"{', '.join(al.get('sensor') or [ANY])} · SSH from {', '.join(al.get('ssh') or [ANY])}")
    print(f"    {DIM}kept as they are: {', '.join(x['name'] for x in st['existing']) or 'no decoys yet'} · persona, "
          f"admin token, web UI https://{st.get('public_ip') or mi}:{st['ports']['ui']}{RST}")
    print(f"    {DIM}firewall: on {st['new_if']} only {st['new_name']}'s ports answer; admin ports only via {st['mgmt']}{RST}")
    if st.get("stop_units"):
        print(f"    {RED}will stop + disable: {', '.join(st['stop_units'])}{RST} {DIM}(re-enabled by uninstall){RST}")
    sshp = st["new_ssh"] if st["need_move"] else st["ports"]["ssh"] if st["move_ssh"] else 22
    if st["need_move"]:
        print(f"    {RED}host SSH MOVES to port {sshp}{RST}  {DIM}({st['new_name']} shares {mi}; your session stays open){RST}")
    elif st["need_pin"]:
        print(f"    {RED}host SSH listens only on {mi}{RST} (port {sshp})  {DIM}— port 22 on {st['new_ip']} "
              f"{'belongs to the decoy' if 22 in ROLE_PORTS[st['new_role']] else 'must look closed'}{RST}")
    else:
        print(f"    {DIM}host SSH unchanged (port {sshp}{', only on ' + mi if st['pin_ssh'] else ''}){RST}")
    if is_windows(st["new_role"]):
        print(f"    {DIM}TTL 128 for traffic from {st['new_ip']} (Windows-like OS fingerprint){RST}")
    if A.yes:
        _confirm_closed_add(st)
        return None
    while True:
        try:
            v = input(f"\n  {BOLD}?{RST} Press Enter to add the decoy · type 1–3 to change that part · q to quit: ").strip().lower()
        except EOFError:
            die("input closed — nothing was changed")
        if v in ("", "y", "yes", "i", "install"):
            if confirm_dhcp_one(st) and _confirm_closed_add(st):
                return None
            continue
        if v in ("q", "quit", "n", "no"):
            die("Cancelled — nothing was changed.")
        if v in BACK_WORDS:
            return 1
        if v in ("1", "2", "3"):
            return int(v) - 1
        err("Type 1, 2 or 3 to change a part, press Enter to add the decoy, or q to quit.")


def _confirm_closed_add(st):
    if not st["new_on_mgmt"]:
        return True
    sshp = st["new_ssh"] if st["need_move"] else st["ports"]["ssh"] if st["move_ssh"] else 22
    keep = set(ROLE_PORTS[st["new_role"]]) | set(st.get("admin_ports") or ()) | {sshp}
    return confirm_closed_services(st, st["mgmt"], st["ifs"][st["mgmt"]]["ip"], keep)


def confirm_dhcp_one(st):
    i = st["ifs"][st["new_if"]]
    if not i.get("dynamic"):
        return True
    warn(f"{i['ip']} ({i['name']}) is a DHCP lease, not a static address — the new decoy binds to it. If DHCP gives the "
         f"server another address after a reboot, the decoy stops answering. Make it static or reserve it.")
    return A.yes or ask_yes("Continue with the DHCP address anyway?", False)


def _ssh_text(st, mi):
    return (f"port {st['ports']['ssh'] if st['move_ssh'] else 22}" + (f", only on {mi}" if st["pin_ssh"] else "")
            + ("" if st["move_ssh"] or st["pin_ssh"] else " (unchanged)"))


def refresh_info(d, changes):
    """Update rows of INSTALL-INFO.txt (and the login banner) after add/remove-decoy."""
    p = os.path.join(d, "INSTALL-INFO.txt")
    if A.dry_run or not os.path.exists(p):
        return
    txt = open(p).read()
    for k, v in changes.items():
        if re.search(rf"(?m)^{re.escape(k)}\s", txt):
            txt = re.sub(rf"(?m)^({re.escape(k)}\s+).*$", lambda m: m.group(1) + v, txt)
        else:
            txt = txt.rstrip("\n") + f"\n{k:<20} {v}\n"
    open(p, "w").write(txt)
    rows = [tuple(x) for x in re.findall(r"(?m)^(\S[^\n]*?)\s{2,}(\S[^\n]*)$", txt)]
    write_motd("manager", rows)


def _apply_decoy_change(d, st, decoys, restart):
    """firewall.sh (allowlists, decoy-interface policy, egress guard, TTL) and the unit for the new decoy set,
    then compose up -d (new/removed containers only) and a restart of the console + the decoys whose config/baits
    were rewritten. Review R2-1: the stack is running, so a firewall that cannot be applied falls back to the
    previous rules, or stops the stack (apply_firewall change=True) — never console/decoys without a firewall."""
    p = os.path.join(d, FIREWALL)
    prev = None
    if os.path.isfile(p) and not os.path.islink(p):
        with open(p) as f:
            prev = f.read()
    fw = write_firewall(d, st, decoys)
    install_service("redpot", d, "redpot", "ReD-Pot manager + decoys", firewall=fw, start=False)
    if fw:
        apply_firewall(d, prev=prev, change=True)
    run(["systemctl", "reload", "redpot"], check=False)
    run(f"cd {shlex.quote(d)} && docker compose -p redpot restart " + " ".join(["console"] + [x.lower() for x in restart]),
        check=False, quiet=True)


def add_decoy():
    """Owner scenario: manager + a decoy on one NIC; later a second NIC gets its own decoy. Re-running the
    installer would regenerate persona + baits (every planted token invalid) — so add exactly one decoy, on a
    free interface, within the Community Edition limit."""
    d = A.dir or "/opt/redpot/manager"
    st = _add_context(d)
    banner("Add a decoy to this ReD-Pot install")
    sl = st["slots"]
    info(f"Management: {st['mgmt']} ({st['ifs'][st['mgmt']]['ip']}) · decoys now: "
         + (", ".join(f"{x['name']} ({ROLE_TITLE.get(x['role'], x['role'])}, {x['ip']} on {x['iface']})"
                      for x in st["existing"]) or "none"))
    info(f"{DIM}Decoy limit: {sl['used']} of {MAX_DECOYS} used (local {sl['local']} · remote {sl['remote']} · "
         f"pending joins {sl['pending']}){RST}")
    wizard([("Interface", step_add_iface), ("Decoy", step_add_role), ("Admin access", step_add_access),
            ("Review", review_add)], st)
    execute_add_decoy(st, d)


def execute_add_decoy(st, d):
    global EXECUTING
    EXECUTING = True
    banner("Adding the decoy")
    ensure_docker()
    ensure_image()
    mi = st["ifs"][st["mgmt"]]["ip"]
    ifname, ip = st["new_if"], st["new_ip"]
    preflight_firewall(list(dict.fromkeys([x["iface"] for x in st["existing"]] + [ifname])))   # R2-6
    stop_conflicting(st, d)
    ctl(d, "add-sensor", "-d", "/d", "--image", IMAGE, "--sensor", f"{st['new_name']}={st['new_role']}@{ip}%{ifname}")
    if st["need_move"]:
        banner(f"Moving host SSH to port {st['new_ssh']}")
        warn(f"From now on connect with:  ssh -p {st['new_ssh']} <user>@{mi}   (this session stays open)")
        move_ssh(st["new_ssh"])
        st["move_ssh"], st["ports"] = True, dict(st["ports"], ssh=st["new_ssh"])
    decoys = _all_decoys(st)
    if st["need_pin"]:
        pin_ssh(mi, {x["ip"] for x in decoys} - {mi}, st["ports"]["ssh"] if st["move_ssh"] else 22)
        st["pin_ssh"] = True
    save_state(d, st)                       # SSH moved/pinned: recorded even if the firewall step stops (R2-1)
    _apply_decoy_change(d, st, decoys, [x["name"] for x in st["existing"]])
    ok = wait_https(mi, st["ports"]["ui"])
    decoys_ok = self_test("redpot", decoys, d=d)
    refresh_info(d, {"Decoys": " · ".join(f"{x['name']} {x['ip']} ({x['iface']})" for x in decoys),
                     "Host SSH": _ssh_text(st, mi)})
    banner(f"{st['new_name']} added" if ok and decoys_ok else f"{st['new_name']} added — but see the self-test above")
    info(f"{st['new_name']} · {ROLE_TITLE[st['new_role']]} · {ip} on {ifname}")
    if st["need_move"]:
        print(f"\n  {RED}{BOLD}IMPORTANT: host SSH is now on port {st['new_ssh']}  →  ssh -p {st['new_ssh']} user@{mi}{RST}")
    info(f"{DIM}Existing decoys, persona and admin token were kept. Remove it again: sudo ./install.sh remove-decoy "
         f"{st['new_name']}{RST}\n")


def remove_decoy():
    d = A.dir or "/opt/redpot/manager"
    st = _add_context(d, slots=False)
    name = (A.target or "").upper()
    names = [x["name"] for x in st["existing"]]
    if not name:
        if A.yes or not names:
            die("name the decoy to remove: sudo ./install.sh remove-decoy NAME  (decoys: " + (", ".join(names) or "none") + ")")
        name = pick("Which decoy should be removed?", [(n, n) for n in names], names[-1])
    gone = next((x for x in st["existing"] if x["name"] == name), None)
    if not gone:
        die(f"no local decoy named {name} (decoys: {', '.join(names) or 'none'})")
    banner(f"Remove decoy {name}")
    if not ask_yes(f"Remove {name} ({ROLE_TITLE.get(gone['role'], gone['role'])}, {gone['ip']} on {gone['iface']}) and its "
                   f"data? The other decoys, persona and admin token stay; its slot is free again.", False,
                   flag=True if A.yes else None):
        die("cancelled — nothing changed")
    global EXECUTING
    EXECUTING = True
    ensure_image()
    mi = st["ifs"][st["mgmt"]]["ip"]
    ctl(d, "remove-sensor", "-d", "/d", "--image", IMAGE, "--name", name)
    st["existing"] = [x for x in st["existing"] if x["name"] != name]
    decoys = _decoy_rows(st)
    _apply_decoy_change(d, st, decoys, [x["name"] for x in st["existing"]])
    run(["docker", "volume", "rm", f"redpot_{name.lower()}-data"], check=False, quiet=True)
    if st["pin_ssh"] and not any(x["iface"] != st["mgmt"] for x in decoys) and not _restricted(st["allow"].get("ssh")):
        unpin_ssh()
        st["pin_ssh"] = False
    if st["move_ssh"] and not any(x["iface"] == st["mgmt"] for x in decoys):
        info(f"{DIM}host SSH stays on port {st['ports']['ssh']} (sudo ./install.sh uninstall restores 22){RST}")
    save_state(d, st)
    refresh_info(d, {"Decoys": " · ".join(f"{x['name']} {x['ip']} ({x['iface']})" for x in decoys) or "none",
                     "Host SSH": _ssh_text(st, mi)})
    self_test("redpot", decoys)
    banner(f"{name} removed")


# ----------------------------------------------------------------------------- GeoIP afterwards
def geoip_later():
    """Download the free DB-IP GeoIP database after the install (for the world attack map)."""
    d = A.dir or "/opt/redpot/manager"
    if not os.path.exists(os.path.join(d, "rpot.json")):
        die(f"no ReD-Pot manager found in {d} (use --dir if it is installed elsewhere)")
    banner("GeoIP database for the world attack map")
    ctl(d, "geoip", "-d", "/d")
    run(["chown", "-R", "10001:10001", os.path.join(d, "geoip")], check=False, quiet=True)
    if _test_ifaces() is None:
        run(f"cd {shlex.quote(d)} && docker compose -p redpot restart console", check=False, quiet=True)
    info(f"{GREEN}GeoIP installed — the console was restarted; the attack map can now place attackers.{RST}")


# ----------------------------------------------------------------------------- JSON export (D-4, S-1 M5)
EXPORT_MIN_DATE = (2000, 1, 1)
EXPORT_MAX_DAYS = 366
_EXPORT_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)


def export_dates(frm, to, today=None):
    """Same rule as rpot/console/export.py parse_dates (the installer stays independent of the rpot package):
    ASCII YYYY-MM-DD, 2000-01-01 <= from <= to <= today(UTC)+1, at most 366 days. -> (date, date) or ValueError."""
    import datetime as _dt
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    out = []
    for name, v in (("from", frm), ("to", to)):
        if not isinstance(v, str) or not v:
            raise ValueError(f"'--{name}' is required (YYYY-MM-DD)")
        if len(v) > 10 or not _EXPORT_DATE_RE.fullmatch(v):
            raise ValueError(f"'--{name}' must be a date as YYYY-MM-DD")
        try:
            out.append(_dt.datetime.strptime(v, "%Y-%m-%d").date())
        except ValueError:
            raise ValueError(f"'--{name}' is not a valid date") from None
    d1, d2 = out
    if d1 < _dt.date(*EXPORT_MIN_DATE):
        raise ValueError(f"'--from' must be {_dt.date(*EXPORT_MIN_DATE).isoformat()} or later")
    if d2 > today + _dt.timedelta(days=1):
        raise ValueError("'--to' is in the future")
    if d1 > d2:
        raise ValueError("'--from' is after '--to'")
    if (d2 - d1).days > EXPORT_MAX_DAYS:
        raise ValueError(f"the range is longer than {EXPORT_MAX_DAYS} days; narrow the date range")
    return d1, d2


def export_argv(d1, d2):
    """docker argv (a list, never a shell string); run with cwd = the manager directory."""
    return ["docker", "compose", "-p", "redpot", "exec", "-T", "console", "python", "/opt/rpot/rpotctl.py", "export",
            "--db", "/var/lib/rpot/rpot.db", "--config", "/etc/rpot/rpot.json",
            "--from", d1.isoformat(), "--to", d2.isoformat()]


def export_target(path, force):
    """Absolute target path, or die. Relative paths are relative to where the user ran install.sh (RPOT_CWD).
    Without --force an existing target is refused; --force only replaces a regular file owned by us with one link."""
    import stat as S
    base = os.environ.get("RPOT_CWD") or ""
    if not os.path.isabs(base) or not os.path.isdir(base):
        base = os.getcwd()
    p = os.path.normpath(os.path.join(base, path))
    parent = os.path.dirname(p) or "/"
    if not os.path.isdir(parent):
        die(f"the directory {parent} does not exist")
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return p
    if not force:
        die(f"{p} already exists — choose another file with -o FILE, or add --force to replace it")
    kind = ("a symbolic link" if S.S_ISLNK(st.st_mode) else "a directory" if S.S_ISDIR(st.st_mode)
            else "a FIFO" if S.S_ISFIFO(st.st_mode) else "a device" if S.S_ISCHR(st.st_mode) or S.S_ISBLK(st.st_mode)
            else "a socket" if S.S_ISSOCK(st.st_mode) else None if S.S_ISREG(st.st_mode) else "not a regular file")
    if kind:
        die(f"refusing to replace {p}: it is {kind} (--force only replaces a regular file)")
    if st.st_uid != os.geteuid():
        die(f"refusing to replace {p}: it belongs to uid {st.st_uid}, not to you (--force only replaces your own file)")
    if st.st_nlink != 1:
        die(f"refusing to replace {p}: it has {st.st_nlink} hard links (--force only replaces a file with one link)")
    return p


def _export_tmp(target):
    """.<name>.tmp-XXXX next to the target: O_EXCL|O_NOFOLLOW, mode 0600 -> (fd, path)."""
    d, name = os.path.split(target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    for _ in range(20):
        tmp = os.path.join(d, f".{name}.tmp-{secrets.token_hex(4)}")
        try:
            fd = os.open(tmp, flags, 0o600)
        except FileExistsError:
            continue
        os.fchmod(fd, 0o600)          # umask can only narrow it; be explicit anyway
        return fd, tmp
    die(f"could not create a temporary file in {d}")


def export_data():
    """sudo ./install.sh export --from D --to D [-o FILE] [--force]: JSON export of incidents + alert records
    (rpotctl export inside the console container), streamed into a 0600 file that appears only when complete."""
    try:
        d1, d2 = export_dates(A.date_from, A.date_to)
    except ValueError as e:
        die(f"export: {e}")
    d = A.dir or "/opt/redpot/manager"
    if not os.path.exists(os.path.join(d, "rpot.json")):
        if os.path.exists(os.path.join(d, "conf", "sensor.json")) or os.path.exists("/opt/redpot/sensor/conf/sensor.json"):
            die("this server is a remote SENSOR — run the export on the manager (or use Export in the web console)")
        die(f"no ReD-Pot manager found in {d} — install it first (sudo ./install.sh manager), or pass --dir")
    if not os.path.exists(os.path.join(d, STATE_FILE)) or not os.path.exists(os.path.join(d, "docker-compose.yml")):
        die(f"{d} is not a finished ReD-Pot 1.0 manager install ({STATE_FILE} or docker-compose.yml missing)")
    try:
        cfg = json.load(open(os.path.join(d, "rpot.json")))
    except (OSError, ValueError) as e:
        die(f"cannot read {d}/rpot.json: {e}")
    if not isinstance(cfg, dict) or cfg.get("version") != 2:
        die("this install was made by an older ReD-Pot — Community Edition 1.0 supports fresh installs only")
    target = export_target(A.output or f"redpot-export-{d1.isoformat()}_{d2.isoformat()}.json", A.force)
    argv = export_argv(d1, d2)
    banner(f"Export {d1.isoformat()} .. {d2.isoformat()} (UTC days)")
    if A.dry_run:
        print(f"  {DIM}[dry-run] (cd {shlex.quote(d)}; {shlex.join(argv)}) > {shlex.quote(target)}{RST}")
        return
    fd, tmp = _export_tmp(target)
    proc = None
    done = False
    try:
        try:
            proc = subprocess.Popen(argv, cwd=d, stdin=subprocess.DEVNULL, stdout=fd, stderr=subprocess.PIPE)
        except OSError as e:
            die(f"export failed: could not run docker ({e})")
        _, err = proc.communicate()
        msg = _clean_text((err or b"").decode("utf-8", "replace")).strip()[-800:]
        if proc.returncode == 2:
            die(f"export refused the date range: {msg or 'bad range'}")
        if proc.returncode == 3:
            die(f"export too large: {msg or 'over the size limit'}\n  Hint: narrow the date range (--from / --to).")
        if proc.returncode != 0:
            die(f"export failed (exit {proc.returncode}): {msg or 'no message'}\n  Hint: is the manager running? "
                f"sudo systemctl start redpot, then check: cd {d} && docker compose -p redpot ps")
        os.fsync(fd)
        size = os.fstat(fd).st_size
        if size == 0:
            die("export failed: the console returned no data")
        os.close(fd)
        fd = None
        os.replace(tmp, target)
        done = True
        try:
            dfd = os.open(os.path.dirname(target), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        if fd is not None:
            os.close(fd)
        if not done:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
    info(f"{GREEN}Export written:{RST} {target} ({size} bytes, mode 0600)")
    print(f"  {DIM}It holds bait user names and the passwords attackers tried — keep it private.{RST}\n")


# ----------------------------------------------------------------------------- token reset
def reset_token():
    """New web-UI admin token (and with --wall a new kiosk link). Old token and every logged-in
    browser stop working at once: session cookies are signed with a key derived from the token."""
    d = A.dir or "/opt/redpot/manager"
    p = os.path.join(d, "rpot.json")
    if not os.path.exists(p):
        die(f"no ReD-Pot manager found in {d} (use --dir if it is installed elsewhere)")
    banner("Reset web console token" + (" + wall link" if A.wall else ""))
    if not ask_yes("Create a new admin token? The old one and all logged-in browsers stop working.", True,
                   flag=True if A.yes else None):
        die("cancelled — nothing changed")
    cfg = json.load(open(p))
    tok = A.token or secrets.token_urlsafe(18)
    if len(tok) < 16 or not re.fullmatch(r"[A-Za-z0-9_\-]+", tok):
        die("--token must be at least 16 characters of letters, digits, '-' or '_'")
    cfg["console"]["admin_token"] = tok
    if A.wall:
        cfg["console"]["wall_token"] = secrets.token_urlsafe(24)
    if A.wall_allow is not None:
        if A.wall_allow.lower() in ("", "none", "any"):
            cfg["console"].pop("wall_allow", None)
        else:
            nets = [x.strip() for x in A.wall_allow.split(",") if x.strip()]
            for n in nets:
                try:
                    ipaddress.ip_network(n, strict=False)
                except ValueError:
                    die(f"--wall-allow: '{n}' is not an IP or network (e.g. 10.0.5.20 or 10.0.5.0/28)")
            cfg["console"]["wall_allow"] = nets
    st = os.stat(p)
    if not A.dry_run:
        tmp = p + ".new"
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=1)
        os.chmod(tmp, st.st_mode & 0o777)
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, p)
    if _test_ifaces() is None:
        run(f"cd {shlex.quote(d)} && docker compose -p redpot restart console", check=False, quiet=True)
    info_p = os.path.join(d, "INSTALL-INFO.txt")
    base = None
    if os.path.exists(info_p) and not A.dry_run:
        txt = open(info_p).read()
        m = re.search(r"(?m)^Web UI\s+(\S+)", txt)
        base = m.group(1) if m else None
        txt = re.sub(r"(?m)^(Admin token\s+)\S+", lambda m_: m_.group(1) + tok, txt)
        if A.wall and base:
            txt = re.sub(r"(?m)^(Wall \(read-only\)\s+)\S+", lambda m_: m_.group(1) + f"{base}/wall?k={cfg['console']['wall_token']}", txt)
        open(info_p, "w").write(txt)
    ok = base is None or _test_ifaces() is not None or wait_https(urllib_host(base), int(base.rsplit(":", 1)[1]), 60)
    print(f"\n  {BOLD}New admin token{RST}  {GREEN}{tok}{RST}")
    if cfg["console"].get("wall_allow"):
        print(f"  {BOLD}Wall screens{RST}     only from {', '.join(cfg['console']['wall_allow'])}")
    if A.wall:
        print(f"  {BOLD}New wall link{RST}    {GREEN}{(base or 'https://<manager>:<port>')}/wall?k={cfg['console']['wall_token']}{RST}")
    print(f"  {DIM}Saved in {info_p}. Console {'restarted' if ok else 'restarting (check: docker compose -p redpot ps)'}.{RST}\n")


def urllib_host(url):
    return url.split("://", 1)[-1].rsplit(":", 1)[0].strip("[]")


# ----------------------------------------------------------------------------- one installer at a time
_LOCK = None


def single_instance():
    """Two installers at once (two SSH sessions, a forgotten tmux) would build the same image and write the
    same /opt/redpot — refuse the second one."""
    global _LOCK
    import fcntl
    path = "/run/lock/redpot-install.lock" if os.path.isdir("/run/lock") else "/tmp/redpot-install.lock"
    _LOCK = open(path, "a+")
    try:
        fcntl.flock(_LOCK, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        _LOCK.seek(0)
        other = _LOCK.read().strip() or "?"
        die(f"another ReD-Pot installer is already running (pid {other}) — wait until it finishes, then try again")
    _LOCK.seek(0); _LOCK.truncate(); _LOCK.write(str(os.getpid())); _LOCK.flush()


# ----------------------------------------------------------------------------- main
def pick_mode(options):
    while True:
        try:
            return pick("What do you want to do?", options, options[0][0])
        except Back:
            warn("This is the first question — there is nothing to go back to.")


def main():
    global A
    ap = argparse.ArgumentParser(
        description="ReD-Pot installer", formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="export: sudo ./install.sh export --from YYYY-MM-DD --to YYYY-MM-DD [-o FILE] [--force]\n"
               "  JSON export of incidents + alert records for those UTC days (at most 366), from the running\n"
               "  manager. Default file ./redpot-export-FROM_TO.json, mode 0600; an existing file is kept unless\n"
               "  --force (which only replaces your own regular file). Too large: narrow the date range.")
    ap.add_argument("mode", nargs="?", choices=["manager", "sensor", "add-decoy", "remove-decoy", "uninstall",
                                                "reset-token", "geoip", "export"])
    ap.add_argument("target", nargs="?", help="remove-decoy: name of the decoy")
    ap.add_argument("--wall", action="store_true", help="reset-token: also issue a new read-only wall link")
    ap.add_argument("--token", help="reset-token: use this token instead of a random one (≥16 chars)")
    ap.add_argument("--wall-allow", help="reset-token: wall screens allowed from these IPs/networks only "
                                          "(comma separated; 'none' = any)")
    ap.add_argument("--keep-data", action="store_true", help="uninstall: keep database, logs and config")
    ap.add_argument("--purge-image", action="store_true", help="uninstall: also delete the Docker image")
    ap.add_argument("--ssh-port", type=int, help="move host SSH to this port instead of a random one")
    ap.add_argument("--dir")
    ap.add_argument("--join", help="sensor mode: join string from the manager; '-' = read it from standard input "
                                   "(a join string given here is visible to local users in ps — prefer '-', "
                                   "--join-file or pasting it when asked)")
    ap.add_argument("--join-file", metavar="FILE", help="sensor mode: read the join string from FILE (root-owned, "
                                                       "chmod 600, no symlink)")
    ap.add_argument("--mgmt-if", help="management interface (SSH, web UI, sensor API); sensor: the link to the manager")
    ap.add_argument("--decoy-if", help="interface of the decoy — it answers on that interface's own address "
                                     "(sensor: its one decoy; add-decoy: a free interface)")
    ap.add_argument("--role-ifaces", help="role=IFACE,role=IFACE — interface per decoy (one decoy per interface)")
    ap.add_argument("--domain", help="Active Directory / DNS domain, e.g. corp.example.com (required with --yes); "
                                     "company, NetBIOS and mail domain are derived from it")
    ap.add_argument("--profile", choices=["bank", "hotel", "government", "it", "generic"], help="industry")
    ap.add_argument("--web-theme", choices=["webmail", "helpdesk", "intranet"], help="web decoy front page")
    ap.add_argument("--roles", help=f"comma separated role ids or 'none' — at most {MAX_DECOYS} and one per interface "
                                    "(add-decoy: exactly one role)")
    ap.add_argument("--names", help="role=HOSTNAME,role=HOSTNAME")
    ap.add_argument("--public-ip", help="static public IP, or 'no'")
    ap.add_argument("--ui-port"); ap.add_argument("--sensor-port")
    ap.add_argument("--geoip", choices=["yes", "no"])
    ap.add_argument("--no-ssh-move", action="store_true", help="never touch the host SSH daemon")
    ap.add_argument("--allow-ui", help="networks allowed to open the web UI (comma separated; 0.0.0.0/0 = any). "
                                       "Required with --yes when a decoy is on the management interface")
    ap.add_argument("--allow-sensor", help="networks allowed to reach the sensor API (remote sensors); "
                                           "required with --yes when a decoy is on the management interface")
    ap.add_argument("--allow-ssh", help="networks allowed to use host SSH (your current client is always added); "
                                        "required with --yes when a decoy is on the management interface")
    ap.add_argument("--close-other-services", action="store_true",
                    help="unattended: accept that host services listening on the management interface become "
                         "unreachable there when a decoy shares it (they are listed first)")
    ap.add_argument("--build", action="store_true", help="build the Docker image locally instead of downloading it")
    ap.add_argument("--stop-conflicting", action="store_true",
                    help="unattended: stop + disable host services that hold decoy ports (uninstall re-enables them)")
    ap.add_argument("--yes", action="store_true", help="accept defaults (unattended)")
    ap.add_argument("--from", dest="date_from", metavar="YYYY-MM-DD", help="export: first UTC day")
    ap.add_argument("--to", dest="date_to", metavar="YYYY-MM-DD", help="export: last UTC day (inclusive)")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="export: output file (default ./redpot-export-FROM_TO.json)")
    ap.add_argument("--force", action="store_true",
                    help="manager/sensor: redo an existing install; export: replace an existing file (your own regular file only)")
    ap.add_argument("--dry-run", action="store_true", help="show what would happen; change nothing")
    A = ap.parse_intermixed_args()
    print(f"\n{RED}{BOLD}  ReD-Pot{RST} {DIM}by RedSide Security — installer{RST}")
    if os.geteuid() != 0 and not A.dry_run:
        die("run as root:  sudo ./install.sh")
    if not A.dry_run:
        single_instance()
    mode = A.mode or pick_mode([
        ("manager", "Manager + decoy sensors on this server (standalone)"),
        ("sensor", "Sensor only — join an existing ReD-Pot manager"),
        ("add-decoy", "Add a decoy on a free network interface of this install — keeps every planted bait"),
        ("reset-token", "Reset the web console admin token (lost or leaked)"),
        ("uninstall", "Uninstall ReD-Pot (restores host SSH to port 22)")])
    {"manager": install_manager, "sensor": install_sensor, "uninstall": uninstall, "reset-token": reset_token,
     "geoip": geoip_later, "add-decoy": add_decoy, "remove-decoy": remove_decoy, "export": export_data}[mode]()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if EXECUTING:
            print(f"\n{RED}✗ Interrupted during installation.{RST} Run the installer again to finish, "
                  f"or 'sudo ./install.sh uninstall' to remove what was set up.")
        else:
            print(f"\n  Cancelled — nothing was changed.")
        sys.exit(130)
    except Back:
        print("\n  Cancelled — nothing was changed.")
        sys.exit(130)
