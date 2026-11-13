"""RC-22: installer defects found on the VMs (RC-16, ce-main 19f9360). Stubbed run(): no iptables, Docker or ss
is touched on this host.
B2 (critical): the firewall preflight hooked a chain holding '-m owner' from FORWARD → EINVAL on every install with a
    decoy. tests/iptables_model.py enforces the kernel's per-hook rules; the preflight (test_rc19_r2_fixes) and every
    generated firewall.sh apply() run through it here.
B5 (high): remote sensor whose decoy shares the manager-link interface → moved host SSH open to the decoy LAN.
B6 (medium): ss '0.0.0.0%enp0s3' (SO_BINDTODEVICE) taken for a listener on every address.
B7 (low): one-time join token in argv (ps) during the sensor install."""
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iptables_model import IptModel  # noqa: E402
from test_installer_wizard import (INSTALLER, JOIN, JOIN_FS, ONE, THREE, ANSI, _mod, _rules,  # noqa: E402
                                   _verdict, run as wizard_run)

NET = "192.168.50.0/24"


def apply_commands(txt):
    """The $IPT / $IP6T commands of firewall.sh's apply(), in order, as (tool, argv). Control flow is ignored on
    purpose: every command runs, so REDPOT-DOCKER is hooked from DOCKER-USER AND (nft fallback) from FORWARD — the
    union of both Docker backends, which is the stricter test of where each chain may be reached from."""
    body = txt.split("\napply() {\n", 1)[1].split("\n}\ncase", 1)[0]
    out = []
    for line in body.splitlines():
        for m in re.finditer(r"\$(IPT|IP6T) ((?:(?!;|\|\||&&|\bthen\b|2>).)*)", line):
            argv = shlex.split(m.group(2).replace('"$NET"', NET))
            out.append(("iptables" if m.group(1) == "IPT" else "ip6tables", argv))
    return out


def check_commands(txt):
    body = txt.split("\ncheck() {", 1)[1].split("\n}\n", 1)[0]
    return [("iptables" if t == "IPT" else "ip6tables", shlex.split(a))
            for t, a in re.findall(r"\$(IPT|IP6T) (-C [^2;|]*?)\s*2>", body)]


TOLERATED = (["-N", "DOCKER-USER"],)            # '2>/dev/null' in the script: exists already with Docker's backend


def apply_on_model(txt, docker):
    m = IptModel(docker=docker)
    errors = []
    for tool, argv in apply_commands(txt):
        rc, err = m.ipt(tool, argv)
        if rc and argv[0] != "-C" and argv not in TOLERATED:
            errors.append((tool, " ".join(argv), rc, err))
    return m, errors


class TestFirewallScriptOnTheKernelModel(unittest.TestCase):
    """B2 class of bugs in firewall.sh itself: every rule must be valid in every hook its chain is reached from."""
    PORTS = {"ui": 50000, "sensor": 50001, "ssh": 50022}

    def scripts(self):
        r = _mod()
        any3 = {"ui": [r.ANY], "sensor": [r.ANY], "ssh": [r.ANY]}
        lim = {"ui": ["10.8.0.0/24"], "sensor": ["10.8.0.0/24"], "ssh": ["10.8.0.0/24"]}
        three = [{"name": "DC01", "role": "windows-domain-controller", "ip": "10.0.0.5", "iface": "eth0", "net": "10.0.0.0/24"},
                 {"name": "FS01", "role": "windows-file-server", "ip": "192.168.50.10", "iface": "eth1"},
                 {"name": "WEB01", "role": "linux-web-hosting", "ip": "172.16.5.10", "iface": "eth2"}]
        dc_elsewhere = [{"name": "DC01", "role": "windows-domain-controller", "ip": "192.168.50.10", "iface": "eth1"}]
        out = {
            "manager 3 decoys, DC on mgmt": r.firewall_text("10.0.0.5", lim, self.PORTS, True, r.ttl_targets(three),
                                                            mgmt_if="eth0", decoys=three, out_guard=True)[0],
            "manager, decoy elsewhere": r.firewall_text("10.0.0.5", any3, self.PORTS, False, r.ttl_targets(dc_elsewhere),
                                                        mgmt_if="eth0", decoys=dc_elsewhere, out_guard=True)[0],
            "manager, no decoy": r.firewall_text("10.0.0.5", lim, self.PORTS, False)[0],
            "sensor follow mode DC": r.firewall_text("203.0.113.20", {"ssh": ["10.8.0.0/24"]}, {"ssh": 52187}, True,
                                                     [("203.0.113.20", None)], mgmt_if="ens3",
                                                     decoys=[{"name": "S", "role": "windows-domain-controller",
                                                              "ip": "203.0.113.20", "iface": "ens3"}],
                                                     out_guard=True, follow=True)[0],
        }
        return out

    def test_every_generated_rule_is_valid_where_it_is_hooked(self):
        for name, txt in self.scripts().items():
            for docker in ("iptables", "nftables"):
                m, errors = apply_on_model(txt, docker)
                self.assertEqual(errors, [], (name, docker))
                for tool, argv in check_commands(txt):                 # check() would pass: every chain hooked
                    if tool == "ip6tables" or "DOCKER-USER" in argv and docker == "nftables":
                        continue
                    self.assertEqual(m.ipt(tool, argv)[0], 0, (name, docker, argv))
                if "$IPT -N REDPOT-OUT" in txt:
                    self.assertTrue(m.hooked("REDPOT-OUT", "OUTPUT"))
                    self.assertTrue(m.hooked("REDPOT-OUT6", "OUTPUT", "ip6tables"))
                self.assertTrue(m.hooked("REDPOT-DOCKER", "FORWARD") or m.hooked("REDPOT-DOCKER", "DOCKER-USER"))

    def test_owner_only_in_the_output_path(self):
        """Owner matches exist only in REDPOT-OUT / REDPOT-OUT6 (hooked from OUTPUT) — never in a chain that INPUT,
        FORWARD or DOCKER-USER jump to."""
        for name, txt in self.scripts().items():
            for tool, argv in apply_commands(txt):
                if "owner" in argv:
                    self.assertIn(argv[1], ("REDPOT-OUT", "REDPOT-OUT6"), (name, argv))

    def test_the_audit_catches_a_misplaced_owner_match(self):
        """The model is not a rubber stamp: an owner rule in REDPOT-DOCKER (FORWARD/DOCKER-USER) or REDPOT-IN
        (INPUT) is EINVAL, like on the VM."""
        txt = self.scripts()["manager 3 decoys, DC on mgmt"]
        for chain in ("REDPOT-DOCKER", "REDPOT-IN"):
            bad = txt.replace("  $IPT -A REDPOT-IN -i lo -j RETURN\n",
                              f"  $IPT -A REDPOT-IN -i lo -j RETURN\n  $IPT -A {chain} -m owner --uid-owner 10001 -j RETURN\n")
            for docker in ("iptables", "nftables"):
                _, errors = apply_on_model(bad, docker)
                self.assertTrue(errors, (chain, docker))
                self.assertTrue(any(e[2] == 4 and "Invalid argument" in e[3] for e in errors), errors)

    def test_extractor_sees_every_rule(self):
        txt = self.scripts()["manager 3 decoys, DC on mgmt"]
        n = len(re.findall(r"\$(?:IPT|IP6T) ", txt.split("\napply() {\n", 1)[1].split("\n}\ncase", 1)[0]))
        self.assertEqual(len(apply_commands(txt)), n)
        self.assertGreater(n, 40)


class TestSensorSshAllowlistB5(unittest.TestCase):
    """S-1 H2 for SSH on remote sensors: decoy on the manager-link interface → the moved host SSH answers only the
    allow-list + the admin's own client; --yes requires --allow-ssh. Decoy on another interface: no question."""

    def test_unattended_needs_allow_ssh_when_the_decoy_shares_the_link(self):
        rc, out, _ = wizard_run([], ONE, "--yes", "--join", JOIN_FS, mode="sensor")
        self.assertNotEqual(rc, 0)
        self.assertIn("pass --allow-ssh", out)
        self.assertIn("would show host SSH next to the decoy", out)
        self.assertNotIn("sensor join", out)                          # stopped before anything happened
        rc, out, _ = wizard_run([], ONE, "--yes", "--join", JOIN_FS, "--allow-ssh", "192.168.1.136/32", mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        lines = [l.strip() for l in out.splitlines() if "-A REDPOT-IN " in l and "--dport" in l]
        sshp = re.search(r"move host SSH to port (\d+)", out).group(1)
        ssh = [l for l in lines if f"-p tcp --dport {sshp} " in l]
        self.assertTrue(any("-s 192.168.1.136/32 -j RETURN" in l for l in ssh), ssh)
        self.assertTrue(any("-s 10.99.0.7/32 -j RETURN" in l for l in ssh), ssh)        # the admin's session
        self.assertFalse([l for l in ssh if l.endswith("-j RETURN") and " -s " not in l], ssh)   # no open RETURN
        self.assertFalse([l for l in ssh if "-s 203.0.113.20/32" in l], ssh)   # follow mode: not today's lease
        self.assertIn("Host SSH may be used from: 192.168.1.136/32", out)

    def test_decoy_on_another_interface_asks_nothing(self):
        rc, out, _ = wizard_run([], THREE, "--yes", "--join", JOIN_FS, "--mgmt-if", "eth0", "--decoy-if", "eth2",
                                mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertNotIn("Host SSH may be used from", out)

    def test_evaluator_ssh_from_the_decoy_lan(self):
        """Rule level, like the VM repro: vm1 (not allow-listed) → sensor's moved SSH = RST; admin → open."""
        r = _mod()
        old = os.environ.get("RPOT_TEST_IFACES")
        os.environ["RPOT_TEST_IFACES"] = "[]"
        try:
            with tempfile.TemporaryDirectory() as d, \
                    mock.patch.dict(os.environ, {"SSH_CONNECTION": "192.168.1.136 50000 192.168.1.126 50952"}):
                r.A.dry_run = False
                ifs = [{"name": "enp0s3", "ip": "192.168.1.126", "prefix": 24, "state": "UP"}]
                st = {"join": JOIN, "ifs": {i["name"]: i for i in ifs}, "mgmt": "enp0s3", "single": True,
                      "allow": {"ssh": ["10.8.0.0/24"]}, "ports": {"ssh": 50952}, "move_ssh": True}
                self.assertTrue(r.write_firewall(d, st, [{"name": "RS-WEB-03", "role": "linux-web-hosting",
                                                          "ip": "192.168.1.126", "iface": "enp0s3"}]))
                txt = open(os.path.join(d, r.FIREWALL)).read()
        finally:
            r.A.dry_run = True
            os.environ.pop("RPOT_TEST_IFACES", None) if old is None else os.environ.__setitem__("RPOT_TEST_IFACES", old)
        rin = _rules(txt, "REDPOT-IN")
        for ip in ("192.168.1.126", "192.168.1.77"):                       # today's lease and after a DHCP change
            self.assertEqual(_verdict(rin, "enp0s3", ip, "tcp", 50952, src="192.168.1.190"), "closed")   # vm1
            self.assertEqual(_verdict(rin, "enp0s3", ip, "tcp", 50952, src="192.168.1.136"), "open")     # session
            self.assertEqual(_verdict(rin, "enp0s3", ip, "tcp", 50952, src="10.8.0.20"), "open")         # allow-list
            self.assertEqual(_verdict(rin, "enp0s3", ip, "tcp", 22, src="192.168.1.190"), "open")        # decoy SSH
        r6 = _rules(txt, "REDPOT-IN6", "$IP6T")
        self.assertEqual(_verdict(r6, "enp0s3", "2001:db8::5", "tcp", 50952, src="2001:db8::99"), "closed")
        m, errors = apply_on_model(txt, "iptables")
        self.assertEqual(errors, [])


SS_TCP = """LISTEN 0      4096   192.168.1.190:53       0.0.0.0:*    users:(("python-lowports",pid=2101,fd=9))
LISTEN 0      4096   192.168.1.190:445      0.0.0.0:*    users:(("python-lowports",pid=2101,fd=7))
LISTEN 0      4096   192.168.1.190:54559    0.0.0.0:*    users:(("sshd",pid=900,fd=3))
LISTEN 0      4096       127.0.0.1:54559    0.0.0.0:*    users:(("sshd",pid=900,fd=4))
"""
SS_UDP = """UNCONN 0      0      0.0.0.0%enp0s3:137      0.0.0.0:*    users:(("python-lowports",pid=2101,fd=12))
UNCONN 0      0      0.0.0.0%enp0s3:138      0.0.0.0:*    users:(("python-lowports",pid=2101,fd=13))
UNCONN 0      0       192.168.1.190:88       0.0.0.0:*    users:(("python-lowports",pid=2101,fd=10))
UNCONN 0      0      0.0.0.0%enp0s8:5353     0.0.0.0:*    users:(("avahi-daemon",pid=700,fd=12))
UNCONN 0      0       [fe80::a00:27ff:fe00:1]%enp0s8:546 [::]:*    users:(("systemd-network",pid=600,fd=20))
"""
IP_ADDR = [{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
           {"ifname": "enp0s3", "addr_info": [{"family": "inet", "local": "192.168.1.190"}]},
           {"ifname": "enp0s8", "addr_info": [{"family": "inet", "local": "192.168.56.108"},
                                              {"family": "inet6", "local": "fe80::a00:27ff:fe00:1"}]}]


class TestScopedListenersB6(unittest.TestCase):
    """VM vm1: DC decoy on enp0s3 (its NBNS socket = 0.0.0.0%enp0s3:137), FS removed from enp0s8; add-decoy on
    enp0s8 said 'ReD-Pot is already installed here'. The ss lines are the VM's format (ss -Hulnp)."""

    def owners(self, ip, ports=None):
        r = _mod()

        def fake(cmd, **k):
            if cmd[:2] == ["ss", "-Htlnp"]:
                return subprocess.CompletedProcess(cmd, 0, SS_TCP, "")
            if cmd[:2] == ["ss", "-Hulnp"]:
                return subprocess.CompletedProcess(cmd, 0, SS_UDP, "")
            if cmd[:3] == ["ip", "-j", "addr"]:
                return subprocess.CompletedProcess(cmd, 0, json.dumps(IP_ADDR), "")
            raise AssertionError(cmd)
        env = {k: v for k, v in os.environ.items() if k not in ("RPOT_TEST_IFACES", "RPOT_TEST_BUSY")}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(r, "run", fake), \
                mock.patch.object(r, "_unit_of", lambda pid, a, p: {700: "avahi-daemon.service"}.get(pid)):
            return {(o["port"], o["proto"]): o for o in r.port_owners(ip, ports)}

    def test_free_interface_next_to_a_dc_decoy(self):
        o = self.owners("192.168.56.108")
        self.assertNotIn((137, "udp"), o)                 # the DC's NBNS is bound to enp0s3 only
        self.assertNotIn((138, "udp"), o)
        self.assertFalse([x for x in o.values() if x["kind"] == "redpot"], o)
        self.assertEqual(o[(5353, "udp")]["unit"], "avahi-daemon.service")    # bound to enp0s8: it does answer there

    def test_add_decoy_audit_accepts_the_free_interface(self):
        r = _mod()
        rows = list(self.owners("192.168.56.108").values())
        with mock.patch.object(r, "port_owners", lambda ip, ports: rows), \
                mock.patch("builtins.print") as pr:
            r.A.stop_conflicting = False
            ok = r.audit_address({}, "192.168.56.108", "windows-file-server")
        text = " ".join(str(a) for c in pr.call_args_list for a in c.args)
        self.assertNotIn("ReD-Pot is already installed here", text)
        self.assertTrue(ok)                               # avahi on 5353: a warning, not a refusal (--yes)

    def test_the_dc_address_still_shows_its_decoy(self):
        o = self.owners("192.168.1.190")
        self.assertEqual(o[(137, "udp")]["kind"], "redpot")         # scoped to enp0s3, which carries .190
        self.assertEqual(o[(445, "tcp")]["kind"], "redpot")
        self.assertNotIn((5353, "udp"), o)                          # avahi is bound to enp0s8
        self.assertNotIn((54559, "tcp"), {k: v for k, v in o.items() if k[0] == 54559 and v["pid"] != 900})

    def test_ss_local_address_forms(self):
        r = _mod()
        for text, want in (("0.0.0.0%enp0s3:137", ("0.0.0.0", "enp0s3", "137")), ("*:22", ("*", None, "22")),
                           ("[::]:22", ("::", None, "22")), ("192.168.1.5:445", ("192.168.1.5", None, "445")),
                           ("[fe80::1]%eth0:546", ("fe80::1", "eth0", "546")), ("*%eth1:5353", ("*", "eth1", "5353"))):
            self.assertEqual(r.SS_LOCAL.match(text).groups(), want, text)
        self.assertTrue(r._listens_on("0.0.0.0", None, "10.0.0.5", set()))
        self.assertFalse(r._listens_on("0.0.0.0", "eth9", "10.0.0.5", {"eth0"}))
        self.assertTrue(r._listens_on("0.0.0.0", "eth0", "10.0.0.5", {"eth0"}))
        self.assertFalse(r._listens_on("10.0.0.6", None, "10.0.0.5", {"eth0"}))


class TestJoinTokenNotInArgvB7(unittest.TestCase):
    def test_join_step_asks_and_a_pasted_string_works(self):
        """The dashboard now shows only 'sudo ./install.sh sensor': the wizard's Join step must ask for the string and
        accept a paste (surrounding blanks, as terminals often add), with no --join on the command line."""
        rc, out, _ = wizard_run(["  " + JOIN_FS + "  ", "", "", ""], THREE, mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("? Join string", out)
        self.assertIn("Paste it here", out)
        self.assertIn("Role chosen on the manager: Windows File Server", out)
        self.assertNotIn("on the command line: local users", out)          # no argv warning for a paste
        self.assertIn("-e RPOT_JOIN", out)

    def test_enrollment_container_gets_the_token_from_the_environment(self):
        r = _mod()
        seen = {}

        def fake(cmd, **k):
            seen["argv"], seen["env"] = cmd, k.get("env")
            return subprocess.CompletedProcess(cmd, 0, "[+] enrolled as X (linux-web-hosting) at https://h\n", "")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(r, "run", fake), mock.patch("builtins.print"):
            r.enroll({"manager": "10.0.0.99:63462", "join": JOIN}, d)
        token = JOIN.split("/")[3].split("#")[0]
        self.assertFalse([a for a in seen["argv"] if token in a], seen["argv"])
        self.assertEqual(seen["argv"][-2:], ["sensor", "join"])
        self.assertIn("RPOT_JOIN", seen["argv"])                        # '-e RPOT_JOIN' = value from the environment
        self.assertEqual(seen["argv"][seen["argv"].index("RPOT_JOIN") - 1], "-e")
        self.assertEqual(seen["env"], {"RPOT_JOIN": JOIN})

    def test_run_passes_env_to_the_child_only(self):
        r = _mod()
        r.A.dry_run = False
        try:
            p = r.run([sys.executable, "-c", "import os,sys; sys.stdout.write(os.environ.get('RPOT_JOIN', ''))"],
                      capture=True, env={"RPOT_JOIN": "x-secret"})
        finally:
            r.A.dry_run = True
        self.assertEqual(p.stdout, "x-secret")
        self.assertNotIn("RPOT_JOIN", os.environ)

    def test_sensor_main_reads_rpot_join(self):
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from rpot.sensor import main as sm
        with mock.patch.dict(os.environ, {"RPOT_JOIN": JOIN}), mock.patch.object(sm, "join") as j:
            sm.main(["join", "--data", "/nonexistent-rpot-test"])
        self.assertEqual(j.call_args.args[0], JOIN)

    def run_installer(self, *args, stdin=""):
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, RPOT_TEST_IFACES=json.dumps(THREE), RPOT_TEST_SSH_IP=THREE[0]["ip"],
                       SSH_CONNECTION=f"10.99.0.7 50000 {THREE[0]['ip']} 22")
            cmd = [sys.executable, INSTALLER, "sensor", "--dry-run", "--dir", os.path.join(d, "x"), "--yes",
                   "--mgmt-if", "eth0", "--decoy-if", "eth2", *[a.replace("@D", d) for a in args]]
            if any("@D" in a for a in args):
                p0 = os.path.join(d, "join.txt")
                fd = os.open(p0, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, (JOIN_FS + "\n").encode())
                os.close(fd)
                if "loose" in args:
                    os.chmod(p0, 0o644)
            p = subprocess.run([a for a in cmd if a != "loose"], input=stdin, capture_output=True, text=True, env=env,
                               timeout=60)
        return p.returncode, ANSI.sub("", p.stdout + p.stderr)

    def test_join_from_stdin_file_and_argv_warning(self):
        rc, out = self.run_installer("--join", "-", stdin=JOIN_FS + "\n")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("Role chosen on the manager: Windows File Server", out)
        self.assertIn("-e RPOT_JOIN", out)
        self.assertNotIn("on the command line", out)
        rc, out = self.run_installer("--join-file", "@D/join.txt")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("Role chosen on the manager: Windows File Server", out)
        rc, out = self.run_installer("--join-file", "@D/join.txt", "loose")
        self.assertNotEqual(rc, 0)
        self.assertIn("not readable by others", out)
        rc, out = self.run_installer("--join-file", "@D/missing.txt")
        self.assertNotEqual(rc, 0)
        rc, out = self.run_installer("--join", "-", stdin="")
        self.assertNotEqual(rc, 0)
        self.assertIn("no join string on standard input", out)
        rc, out = self.run_installer("--join", JOIN_FS)
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("the join string is on the command line", out)
        docker = [l for l in out.splitlines() if "docker run" in l and "sensor join" in l]
        self.assertEqual(len(docker), 1, out[-2000:])
        self.assertNotIn("AbCdEf123_-x", docker[0])


if __name__ == "__main__":
    unittest.main()
