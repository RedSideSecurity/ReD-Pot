"""Drive the interactive installer like a person: wrong answers, 'back', review edits.
Runs the real installer in --dry-run with simulated network interfaces (RPOT_TEST_IFACES),
so nothing on the host is touched."""
import json
import os
import re
import subprocess
import sys
import tempfile
import pytest
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(REPO, "installer", "redpot_install.py")
ANSI = re.compile(r"\x1b\[[0-9;]*m")

THREE = [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP", "gw": "10.0.0.1"},
         {"name": "eth1", "ip": "192.168.50.10", "prefix": 24, "state": "UP", "gw": "192.168.50.1"},
         {"name": "eth2", "ip": "172.16.5.10", "prefix": 24, "state": "UP"}]
TWO_AND_DOWN = [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP", "gw": "10.0.0.1"},
                {"name": "eth1", "ip": "192.168.50.10", "prefix": 24, "state": "UP"},
                {"name": "eth2", "ip": None, "prefix": None, "state": "DOWN", "carrier": False}]
ONE = [{"name": "ens3", "ip": "203.0.113.20", "prefix": 24, "state": "UP", "gw": "203.0.113.1"}]
JOIN = "redpot://10.0.0.99:63462/AbCdEf123_-x#" + "B6" * 32
JOIN_FS = "redpot://10.0.0.99:63462/AbCdEf123_-x?role=windows-file-server#" + "B6" * 32
JOIN_WEB = "redpot://10.0.0.99:63462/AbCdEf123_-x?role=linux-web-hosting#" + "B6" * 32


def run(inputs, ifaces, *args, mode="manager", busy=None):
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, RPOT_TEST_IFACES=json.dumps(ifaces), RPOT_TEST_SSH_IP=ifaces[0]["ip"],
                   SSH_CONNECTION=f"10.99.0.7 50000 {ifaces[0]['ip']} 22")
        if busy:
            env["RPOT_TEST_BUSY"] = busy
        theme = [] if "--web-theme" in args or "ask-theme" in args else ["--web-theme", "webmail"]
        allow = [] if "ask-allow" in args or mode == "sensor" else \
            ["--allow-ui", "0.0.0.0/0", "--allow-sensor", "0.0.0.0/0", "--allow-ssh", "0.0.0.0/0"]
        args = [x for x in args if x not in ("ask-theme", "ask-allow")]
        cmd = [sys.executable, INSTALLER] + ([mode] if mode else []) + ["--dry-run", "--dir", os.path.join(d, "x"), *theme, *allow, *args]
        p = subprocess.run(cmd, input="\n".join(inputs) + "\n", capture_output=True, text=True, env=env, timeout=60)
        out = ANSI.sub("", p.stdout + p.stderr)
        return p.returncode, out, os.path.exists(os.path.join(d, "x"))


DOM = "corp.ararat-bank.am"


class TestManagerWizard(unittest.TestCase):
    """CE 1.0 (D-1, D-2, D-6): domain + industry only; one decoy per interface on its own address; ≤ 3 decoys."""

    def test_three_nics_three_roles_with_every_error(self):
        rc, out, wrote = run([
            "eth9", "1",                                   # mgmt: unknown, then eth0
            "notadomain", DOM,                             # domain (no company question any more)
            "9", "1",                                      # industry
            "9", "all", "1,2,3,4", "1,2,4",                # roles: unknown, 'all' gone, 4 > limit, then FS+WEB+DC
            "eth9", "2",                                   # FS interface: unknown, then eth1
            "bad name", "ARB-FS-01",                       # FS host name
            "2", "3",                                      # WEB: eth1 is taken (not offered), then eth2
            "arb-fs-01", "ARB-WEB-01",                     # duplicate name, then ok
            "", "",                                        # DC: the only free interface left (eth0), name DC01
            "abc", "no",                                   # public IP
            "maybe", "n",                                  # GeoIP
            "7", "",                                       # review: invalid, then install
        ], THREE, mode="manager")
        self.assertEqual(rc, 0, out[-2500:])
        for msg in ("'eth9' is not one of the choices",
                    "Not a valid domain",
                    "'9' is not one of the choices",
                    "'9' is not in the list",
                    "'all' is not in the list",
                    "supports up to 3 decoys in total",
                    "Use 1–15 letters, digits or hyphens",
                    "'2' is not one of the choices",
                    "Not offered (one decoy per interface): eth1 → ARB-FS-01",
                    "'ARB-FS-01' is already used by the Windows File Server",
                    "Type an IPv4 address such as",
                    "Type y for yes or n for no",
                    "Type a number from 1 to 5"):
            self.assertIn(msg, out, msg)
        self.assertNotIn("? Company name", out)
        self.assertIn("derived: company Ararat Bank · NetBIOS ARARATBANK · mail @ararat-bank.am", out)
        self.assertIn("ctl init -d /d --force --domain corp.ararat-bank.am --profile bank --net-mode host --mgmt-ip 10.0.0.5", out)
        self.assertIn("--sensor ARB-FS-01=windows-file-server@192.168.50.10%eth1", out)
        self.assertIn("--sensor ARB-WEB-01=linux-web-hosting@172.16.5.10%eth2", out)
        self.assertIn("--sensor DC01=windows-domain-controller@10.0.0.5%eth0", out)
        self.assertIn("--ui-bind 10.0.0.5", out)                  # admin ports only on management
        for gone in ("--company", "macvlan", "--decoy-net", "--own-ip", "--subnet", "mac_address", "Address on"):
            self.assertNotIn(gone, out, gone)
        self.assertRegex(out, r"host SSH MOVES to port \d+ \(listens only on 10\.0\.0\.5\)")
        self.assertFalse(wrote, "dry-run must not create the install directory")

    def test_one_nic_allows_one_decoy_and_moves_ssh(self):
        rc, out, wrote = run(["x.example.com", "", "1,2", "2", "", "no", "n", ""], ONE)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("2 decoys need 2 network interfaces — this server has 1 usable interface", out)
        self.assertIn("Pick up to 1:", out)
        self.assertIn("--sensor WEB01=linux-web-hosting@203.0.113.20%ens3", out)
        self.assertIn("host SSH MOVES to port", out)
        self.assertIn("would move host SSH", out)
        self.assertNotIn("would pin host SSH", out)
        self.assertFalse(wrote)

    def test_four_roles_rejected_with_the_limit_message(self):
        sys.path.insert(0, REPO)
        from rpot.common.edition import limit_message
        four = THREE + [{"name": "eth3", "ip": "10.1.0.5", "prefix": 24, "state": "UP"}]
        rc, out, _ = run([], four, "--yes", "--domain", "x.example.com", "--public-ip", "no", "--geoip", "no",
                         "--roles", "windows-file-server,linux-web-hosting,ftp-backup-server,linux-dns-server")
        self.assertNotEqual(rc, 0)
        self.assertIn(limit_message(4), " ".join(out.split()))
        self.assertNotIn("ctl init", out)

    def test_more_roles_than_interfaces_is_a_hard_error_with_yes(self):
        rc, out, _ = run([], TWO_AND_DOWN, "--yes", "--domain", "x.example.com", "--public-ip", "no", "--geoip", "no",
                         "--roles", "windows-file-server,linux-web-hosting,ftp-backup-server")
        self.assertNotEqual(rc, 0)
        self.assertIn("3 decoys need 3 network interfaces — this server has 2 usable interfaces", out)

    @pytest.mark.slow
    def test_decoy_on_other_nic_pins_ssh(self):
        """A decoy on another interface's own address pins SSH to the management IP — also a file server without
        port 22 (OpenSSH visible on a "Windows" address gives it away)."""
        for roles, name in (("2", "WEB01"), ("1", "FS01")):
            rc, out, _ = run(["1", "x.example.com", "1", roles, "2", name, "no", "n", ""], TWO_AND_DOWN)
            self.assertEqual(rc, 0, out[-1500:])
            self.assertIn("Not usable:", out)
            self.assertIn("eth2       DOWN (no cable / no carrier)", out)
            self.assertIn("host SSH stays on port 22 (listens only on 10.0.0.5)", out)
            self.assertIn("would pin host SSH to 10.0.0.5:22", out)
            self.assertIn(f"--sensor {name}=", out)
            self.assertIn("@192.168.50.10%eth1", out)

    @pytest.mark.slow
    def test_no_ssh_move_with_a_decoy_on_management_is_an_error(self):
        rc, out, _ = run([], THREE, "--yes", "--no-ssh-move", "--domain", "x.example.com", "--roles", "windows-file-server",
                         "--role-ifaces", "windows-file-server=eth0", "--public-ip", "no", "--geoip", "no")
        self.assertNotEqual(rc, 0)
        self.assertIn("use another interface or drop --no-ssh-move", out)
        rc, out, _ = run([], ONE, "--yes", "--no-ssh-move", "--domain", "x.example.com", "--roles", "windows-file-server",
                         "--public-ip", "no", "--geoip", "no")
        self.assertNotEqual(rc, 0)
        self.assertIn("use another interface or drop --no-ssh-move", out)
        # interactive: the management interface is simply not offered
        rc, out, _ = run(["1", "x.example.com", "", "1", "", "", "no", "n", ""], THREE, "--no-ssh-move")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertNotIn("(management — this server's address", out)
        self.assertNotIn("would move host SSH", out)

    def test_back_navigation_and_review_edit(self):
        rc, out, _ = run([
            "",                     # mgmt default (eth0, the SSH session)
            "back",                 # at domain → back to network
            "",                     # network again
            "x.example.com", "",    # domain, industry
            "back",                 # at roles → back to identity
            "", "",                 # identity again (previous answers kept)
            "2",                    # roles: web only
            "",                     # interface (default eth1)
            "back",                 # at the host name → back to roles
            "",                     # roles default = previous "2"
            "", "",                 # interface, name for web
            "", "",                 # public IP no, GeoIP yes
            "3",                    # review: change decoys
            "1,2",                  # file + web
            "", "",                 # FS: interface (eth1), name
            "", "",                 # web: interface (eth2 — eth1 is taken), name
            "", "",                 # access again
            "",                     # review → install
        ], THREE)
        self.assertEqual(rc, 0, out[-1500:])
        self.assertGreaterEqual(out.count("Step 1 of 5 · Network"), 2)
        self.assertGreaterEqual(out.count("Step 2 of 5 · Your company"), 2)
        self.assertGreaterEqual(out.count("Review — nothing has been changed yet"), 2)
        self.assertIn("--sensor FS01=windows-file-server@192.168.50.10%eth1", out)
        self.assertIn("--sensor WEB01=linux-web-hosting@172.16.5.10%eth2", out)

    def test_back_into_step4_resumes_at_last_decoy(self):
        rc, out, _ = run(["", "x.example.com", "", "1,2", "", "", "", "",   # through step 4 with defaults
                          "back",                                         # at public IP → back
                          "", "",                                         # only decoy 2/2 is asked again
                          "", "", ""], THREE)
        self.assertEqual(rc, 0, out[-1500:])
        tail = out.split("Step 5 of 5 · Access")[1]
        self.assertIn("[2/2] Linux Web Hosting", tail)
        self.assertNotIn("[1/2] Windows File Server", tail.split("Step 5 of 5")[0])

    def test_first_step_back_and_closed_input(self):
        rc, out, wrote = run(["back"], THREE)
        self.assertIn("This is the first step — there is nothing to go back to.", out)
        self.assertEqual(rc, 1)
        self.assertIn("input closed", out)
        self.assertFalse(wrote)

    def test_review_quit_changes_nothing(self):
        rc, out, wrote = run(["", "x.example.com", "", "none", "", "", "q"], THREE)
        self.assertIn("No local decoys", out)
        self.assertIn("Cancelled — nothing was changed.", out)
        self.assertNotIn("[dry-run] docker", out)
        self.assertFalse(wrote)

    @pytest.mark.slow
    def test_unattended_flags(self):
        rc, out, wrote = run([], THREE, "--yes", "--mgmt-if", "eth0", "--domain", "x.example.com",
                             "--profile", "it", "--roles", "windows-file-server,linux-web-hosting",
                             "--role-ifaces", "windows-file-server=eth2,linux-web-hosting=eth1",
                             "--public-ip", "no", "--geoip", "no")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("--sensor FS01=windows-file-server@172.16.5.10%eth2", out)
        self.assertIn("--sensor WEB01=linux-web-hosting@192.168.50.10%eth1", out)
        self.assertIn("host SSH stays on port 22 (listens only on 10.0.0.5)", out)
        self.assertFalse(wrote)
        # defaults without --role-ifaces: non-management interfaces first, management last
        rc, out, _ = run([], THREE, "--yes", "--domain", "x.example.com", "--public-ip", "no", "--geoip", "no",
                         "--roles", "windows-file-server,linux-web-hosting,ftp-backup-server")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("--sensor FS01=windows-file-server@192.168.50.10%eth1", out)
        self.assertIn("--sensor WEB01=linux-web-hosting@172.16.5.10%eth2", out)
        self.assertIn("--sensor BKP01=ftp-backup-server@10.0.0.5%eth0", out)
        self.assertIn("host SSH MOVES to port", out)
        rc, out, _ = run([], THREE, "--yes", "--domain", "x.example.com", "--public-ip", "no", "--geoip", "no",
                         "--roles", "windows-file-server,linux-web-hosting",
                         "--role-ifaces", "windows-file-server=eth1,linux-web-hosting=eth1")
        self.assertNotEqual(rc, 0)
        self.assertIn("one decoy per interface", out)

    def test_yes_without_domain_dies(self):
        rc, out, wrote = run([], THREE, "--yes", "--roles", "none", "--public-ip", "no", "--geoip", "no")
        self.assertNotEqual(rc, 0)
        self.assertIn("pass --domain", out)
        self.assertFalse(wrote)
        rc, out, _ = run([], THREE, "--yes", "--domain", "corp.xn--80ak6aa92e.am", "--roles", "none")
        self.assertNotEqual(rc, 0)
        self.assertIn("Internationalised (xn--)", out)

    @pytest.mark.slow
    def test_removed_flags(self):
        """D-1/D-2: the flags are gone for every mode (RC-6 removed the last users: the remote-sensor wizard)."""
        for args in (["--company", "X"], ["--nics", "1"], ["--placement", "host"], ["--decoy-ips", "10.0.0.9"]):
            rc, out, _ = run([], THREE, "--yes", "--domain", "x.example.com", *args)
            self.assertEqual(rc, 2, out[-500:])                   # argparse: unrecognized
            self.assertIn("unrecognized arguments", out)
        for args in (["--placement", "macvlan"], ["--decoy-ips", "10.0.0.9"]):
            rc, out, _ = run([], THREE, "--yes", "--join", JOIN, *args, mode="sensor")
            self.assertEqual(rc, 2, out[-500:])

    @pytest.mark.slow
    def test_interface_names_outside_the_whitelist_are_not_usable(self):
        odd = [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP"},
               {"name": 'ev"il', "ip": "192.168.9.9", "prefix": 24, "state": "UP"},
               {"name": "a$(id)", "ip": "192.168.8.8", "prefix": 24, "state": "UP"}]
        rc, out, _ = run([], odd, "--yes", "--domain", "x.example.com", "--roles", "windows-file-server",
                         "--public-ip", "no", "--geoip", "no")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("This server has one usable interface", out)
        self.assertEqual(out.count("unusual characters in the interface name"), 2)
        self.assertIn("--sensor FS01=windows-file-server@10.0.0.5%eth0", out)
        self.assertNotIn("-i ev", out)
        self.assertNotIn("-i a$", out)
        rc, out, _ = run([], odd, "--yes", "--domain", "x.example.com", "--roles", "windows-file-server",
                         "--role-ifaces", 'windows-file-server=ev"il', "--public-ip", "no", "--geoip", "no")
        self.assertNotEqual(rc, 0)
        self.assertIn("is not a usable interface here", out)

    def test_main_menu_rejects_garbage(self):
        rc, out, _ = run(["back", "zz", "3", "y"], THREE, mode=None)
        self.assertIn("This is the first question", out)
        self.assertIn("'zz' is not one of the choices", out)
        self.assertIn("Uninstall ReD-Pot", out)


class TestAdminAllowlistsH2(unittest.TestCase):
    """S-1 H2: a decoy on the management interface → web UI / sensor API default to the admin's own client."""

    def test_interactive_defaults_to_the_ssh_client(self):
        rc, out, _ = run(["x.example.com", "", "1", "", "no", "n", "", "", "", ""], ONE, "ask-allow")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("Web UI may be opened from [10.99.0.7/32]", out)
        self.assertIn("Sensor API (remote sensors) may be reached from [10.99.0.7/32]", out)
        self.assertIn("Host SSH may be used from [10.99.0.7/32]", out)          # H2 extended to SSH (review)
        self.assertIn("admin access: web UI from 10.99.0.7/32 · sensor API from 10.99.0.7/32 · SSH from 10.99.0.7/32", out)
        self.assertNotIn("another address", out)
        self.assertNotIn("free address", out)

    @pytest.mark.slow
    def test_yes_requires_explicit_allowlists(self):
        base = ["--yes", "--domain", "x.example.com", "--roles", "windows-file-server", "--public-ip", "no",
                "--geoip", "no", "ask-allow"]
        rc, out, _ = run([], ONE, *base)
        self.assertNotEqual(rc, 0)
        self.assertIn("pass --allow-ui and --allow-sensor and --allow-ssh", out)
        self.assertNotIn("ctl init", out)
        rc, out, _ = run([], ONE, *base, "--allow-ui", "10.8.0.0/24")
        self.assertNotEqual(rc, 0)
        self.assertIn("pass --allow-sensor and --allow-ssh", out)
        rc, out, _ = run([], ONE, *base, "--allow-ui", "10.8.0.0/24", "--allow-sensor", "10.8.0.0/24,172.20.0.0/16")
        self.assertNotEqual(rc, 0)
        self.assertIn("pass --allow-ssh", out)
        rc, out, _ = run([], ONE, *base, "--allow-ui", "10.8.0.0/24", "--allow-sensor", "10.8.0.0/24,172.20.0.0/16",
                         "--allow-ssh", "10.8.0.0/24")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("-i ens3 -p tcp -m conntrack --ctorigdst 203.0.113.20 --ctorigdstport", out)

    def test_decoy_elsewhere_keeps_open_defaults(self):
        rc, out, _ = run([], THREE, "--yes", "--domain", "x.example.com", "--roles", "windows-file-server",
                         "--role-ifaces", "windows-file-server=eth1", "--public-ip", "no", "--geoip", "no", "ask-allow")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("web UI from 0.0.0.0/0 · sensor API from 0.0.0.0/0", out)

    def test_allowlist_questions_and_firewall(self):
        rc, out, _ = run(["1", "x.example.com", "1", "4", "1", "DC01",       # DC shares 10.0.0.5
                          "no", "n",
                          "bad/99", "10.8.0.0/24, 192.168.50.7",                # web UI
                          "0.0.0.0/0",                                          # sensor API: anyone (explicit)
                          "10.8.0.0/24",                                        # SSH
                          ""], TWO_AND_DOWN, "ask-allow")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("Use networks or addresses like 10.8.0.0/24", out)
        self.assertIn("Your current SSH client 10.99.0.7 is always allowed", out)
        self.assertIn("admin access: web UI from 10.8.0.0/24, 192.168.50.7/32 · sensor API from 0.0.0.0/0 · SSH from 10.8.0.0/24", out)
        self.assertIn("sensor API is reachable from anywhere on 10.0.0.5", out)
        self.assertIn("would write", out)
        self.assertIn("firewall.sh", out)


class TestSharedInterfaceServicesF4(unittest.TestCase):
    """Review F4a: a decoy on the management interface closes every other host service there — list them first."""
    BASE = ["--yes", "--domain", "x.example.com", "--roles", "windows-file-server", "--public-ip", "no", "--geoip", "no"]

    def test_yes_needs_close_other_services(self):
        rc, out, _ = run([], ONE, *self.BASE, busy="1194/udp=openvpn-server@srv.service,8443/tcp=myadmin,22/tcp=sshd")
        self.assertNotEqual(rc, 0)
        self.assertIn("1194/udp  openvpn-server@srv.service", out)
        self.assertIn("8443/tcp  myadmin", out)
        self.assertNotIn("22/tcp  sshd", out)                                  # host SSH is moved, not closed
        self.assertIn("add --close-other-services", out)
        self.assertNotIn("ctl init", out)                                       # nothing done
        rc, out, _ = run([], ONE, *self.BASE, "--close-other-services", busy="1194/udp=openvpn-server@srv.service")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("become UNREACHABLE on ens3", out)

    def test_interactive_no_goes_back_and_other_nic_needs_nothing(self):
        rc, out, _ = run(["x.example.com", "", "1", "",
                          "n",                  # audit: do not stop the VPN server
                          "no", "n", "",        # public IP, GeoIP, review: Enter
                          "n", "q"], ONE,       # close it on ens3? no → back to the review → quit
                         busy="1194/udp=openvpn-server@srv.service")
        self.assertNotEqual(rc, 0)
        self.assertIn("Close them on ens3? (y/n) [n]", out)
        self.assertIn("Fix the addresses or services above", out)
        self.assertNotIn("ctl init", out)
        rc, out, _ = run([], THREE, *self.BASE, "--role-ifaces", "windows-file-server=eth1",
                         busy="1194/udp=openvpn-server@srv.service")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertNotIn("UNREACHABLE", out)

    def test_uid_10001_in_use_is_refused(self):
        """Review F7."""
        for mode, args in (("manager", self.BASE), ("sensor", ["--yes", "--join", JOIN])):
            with tempfile.TemporaryDirectory() as d:
                env = dict(os.environ, RPOT_TEST_IFACES=json.dumps(THREE), RPOT_TEST_UID_USED="user jdoe (getent passwd 10001)")
                p = subprocess.run([sys.executable, INSTALLER, mode, "--dry-run", "--dir", os.path.join(d, "x"), *args],
                                   capture_output=True, text=True, env=env, timeout=60)
            out = ANSI.sub("", p.stdout + p.stderr)
            self.assertNotEqual(p.returncode, 0, mode)
            self.assertIn("uid 10001 is already used on this host: user jdoe", out)
            self.assertIn("Nothing was changed", out)


class TestSensorWizard(unittest.TestCase):
    """CE 1.0 (D-2, RC-6): the remote sensor's decoy answers on the chosen interface's OWN address — no address
    question, no extra IP or MAC. Same interface as the manager link → host SSH moves and the decoy follows DHCP
    (RPOT_SENSOR_IFACE); another interface → RPOT_BIND_IP + host SSH pinned to the link address."""

    def _no_extra_addresses(self, out):
        for bad in ("macvlan", "mac_address", "ipv4_address", "parent:", "IP address of the decoy", "free address"):
            self.assertNotIn(bad, out)
        self.assertIn("network_mode: host", out)

    def test_sensor_errors_back_and_interface_choice(self):
        rc, out, _ = run([
            "http://nope",                  # not a join string
            JOIN,
            "",                             # manager link: default = route to 10.0.0.99 → eth0
            "eth5", "eth2",                 # decoy interface: unknown, then eth2
            "3",                            # review: not a section
            "2",                            # review: change the network
            "", "eth1",                     # network again → decoy on eth1
            "",                             # install
        ], THREE, mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("That is not a complete join string", out)
        self.assertIn("'eth5' is not one of the choices", out)
        self.assertIn("Type 1 or 2 to change a part", out)
        self.assertIn("Which interface reaches the manager (10.0.0.99)?", out)
        self.assertIn("decoy will answer on eth2's own address 172.16.5.10", out)
        self.assertIn("manager link via eth0 · decoy on eth1", out)
        self.assertIn("-e RPOT_JOIN", out)
        self.assertNotIn("sensor join " + JOIN, out)                  # B7: the token is never in argv
        self.assertIn('RPOT_BIND_IP: "192.168.50.10"', out)
        self.assertIn('RPOT_SENSOR_IP: "192.168.50.10"', out)
        self.assertNotIn("RPOT_SENSOR_IFACE", out)
        self.assertIn("stays on port 22, listens only on 10.0.0.5", out)
        self.assertIn("would pin host SSH to 10.0.0.5:22", out)
        self.assertNotIn("Moving host SSH", out)
        self._no_extra_addresses(out)

    def test_sensor_one_nic_moves_ssh_and_follows_dhcp(self):
        one_dhcp = [dict(ONE[0], dynamic=True)]
        rc, out, _ = run([JOIN, "", ""], one_dhcp, mode="sensor")  # SSH allow-list (B5: default = own client), review
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("Host SSH may be used from [10.99.0.7/32]", out)
        self.assertIn("host SSH moves to port", out)
        self.assertRegex(out, r"host SSH moves to port \d+ · from 10\.99\.0\.7/32")
        self.assertIn("one usable interface", out)
        self.assertIn("decoy on ens3 (same interface)", out)
        self.assertIn("203.0.113.20 on ens3  (this server's address)", out)
        self.assertIn("host SSH moves to port", out)
        self.assertIn("would move host SSH to port", out)
        self.assertIn('RPOT_SENSOR_IFACE: "ens3"', out)
        self.assertNotIn("RPOT_BIND_IP", out)
        self.assertNotIn("would pin host SSH", out)
        self.assertNotIn("DHCP lease", out)                         # the decoy follows the lease (S-1 L14)
        self._no_extra_addresses(out)

    @pytest.mark.slow
    def test_sensor_same_interface_on_multi_nic(self):
        rc, out, _ = run([JOIN, "eth1", "eth1", "10.8.0.0/24", ""], THREE, mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("(same as the manager link — host SSH moves)", out)
        self.assertIn("· from 10.8.0.0/24 (+ your current SSH client)", out)
        self.assertIn("manager link via eth1 · decoy on eth1 (same interface)", out)
        self.assertIn('RPOT_SENSOR_IFACE: "eth1"', out)
        self.assertIn('RPOT_SENSOR_IP: "192.168.50.10"', out)
        self.assertIn("host SSH moves to port", out)
        self._no_extra_addresses(out)

    @pytest.mark.slow
    def test_no_ssh_move(self):
        rc, out, _ = run([JOIN], ONE, "--no-ssh-move", mode="sensor")
        self.assertNotEqual(rc, 0)
        self.assertIn("use another interface for the decoy or drop --no-ssh-move", out)
        self.assertNotIn("sensor join", out)
        rc, out, _ = run([], THREE, "--yes", "--join", JOIN, "--mgmt-if", "eth0", "--decoy-if", "eth0", "--no-ssh-move",
                         mode="sensor")
        self.assertNotEqual(rc, 0)
        self.assertIn("use another interface for the decoy or drop --no-ssh-move", out)
        rc, out, _ = run([JOIN, "", "eth0", "", ""], THREE, "--no-ssh-move", mode="sensor")   # link not offered
        self.assertIn("'eth0' is not one of the choices", out)
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("stays on port 22, listens only on 10.0.0.5", out)

    @pytest.mark.slow
    def test_unattended(self):
        rc, out, _ = run([], THREE, "--yes", "--join", JOIN_FS, "--mgmt-if", "eth0", "--decoy-if", "eth2", mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn('RPOT_BIND_IP: "172.16.5.10"', out)
        self.assertIn("rpot.role: windows-file-server", out)
        self.assertIn("would install /etc/systemd/system/redpot-sensor.service", out)
        self.assertRegex(out, r"\[dry-run\] chown -R 10001:10001 \S+/data")      # decoy runs as 10001 after privdrop
        self.assertIn('RPOT_PRIVDROP: "1"', out)

    def test_dhcp_on_another_interface_is_warned(self):
        dyn = [dict(THREE[0], dynamic=True), dict(THREE[1], dynamic=True)]
        rc, out, _ = run([JOIN, "", "", "", "y"], dyn, mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("10.0.0.5 (eth0) is a DHCP lease, not a static address — used for: manager link, host SSH", out)
        self.assertIn("192.168.50.10 (eth1) is a DHCP lease, not a static address — used for: decoy", out)


if __name__ == "__main__":
    unittest.main()


class TestRunMissingProgram(unittest.TestCase):
    def test_missing_program_is_a_failure_not_a_traceback(self):
        """Bug from a fresh VM: `docker` absent after a failed apt install → FileNotFoundError traceback."""
        import types
        sys.path.insert(0, os.path.join(REPO, "installer"))
        import redpot_install as r
        r.A = types.SimpleNamespace(dry_run=False, yes=True)
        res = r.run(["definitely-not-installed-xyz", "version"], capture=True, check=False)
        self.assertEqual(res.returncode, 127)
        self.assertIn("command not found", res.stderr)


class TestDamagedDpkg(unittest.TestCase):
    def test_power_cut_damaged_lists_are_found(self):
        """Bug from a test VM: systemd.list zero-filled, vim.list holding foreign data."""
        sys.path.insert(0, os.path.join(REPO, "installer"))
        import redpot_install as r
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "ok.list"), "w").write("/.\n/usr\n/usr/bin/ok\n")
            open(os.path.join(d, "systemd.list"), "wb").write(b"\0" * 4096)
            open(os.path.join(d, "vim.list"), "w").write("/.\n/usr\nhi def link povInclude")
            open(os.path.join(d, "cut.list"), "w").write("/.\n/usr/bin/x")
            bad = sorted(os.path.basename(f) for f in r.damaged_dpkg_lists(d))
        self.assertEqual(bad, ["cut.list", "systemd.list", "vim.list"])


class TestSshPinKeepsSession(unittest.TestCase):
    def test_live_session_address_is_kept_but_never_a_decoy_ip(self):
        """Bug on a test VM: session IP was dropped (valid_ip() returns None when VALID) → lock-out."""
        sys.path.insert(0, os.path.join(REPO, "installer"))
        import redpot_install as r
        old = os.environ.get("RPOT_TEST_IFACES"), os.environ.get("RPOT_TEST_SSH_IP")
        os.environ["RPOT_TEST_IFACES"] = "[]"
        try:
            os.environ["RPOT_TEST_SSH_IP"] = "10.20.0.5"
            self.assertEqual(r.ssh_keep_addrs("10.30.0.11", {"10.30.0.13"}),
                             ["10.30.0.11", "127.0.0.1", "10.20.0.5"])
            os.environ["RPOT_TEST_SSH_IP"] = "10.30.0.13"          # connected to the decoy IP
            self.assertEqual(r.ssh_keep_addrs("10.30.0.11", {"10.30.0.13"}),
                             ["10.30.0.11", "127.0.0.1"])
        finally:
            for k, v in zip(("RPOT_TEST_IFACES", "RPOT_TEST_SSH_IP"), old):
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class TestDhcpWarning(unittest.TestCase):
    @pytest.mark.slow
    def test_dhcp_management_address_needs_confirmation(self):
        dyn = [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP", "gw": "10.0.0.1", "dynamic": True},
               {"name": "eth1", "ip": "192.168.50.10", "prefix": 24, "state": "UP", "dynamic": True}]
        rc, out, _ = run(["1", "x.example.com", "1", "1", "2", "FS01", "no", "n",
                          "",          # review: Enter → DHCP warning
                          "",          # confirm? Enter = no → back to the review
                          "",          # review: Enter again → warning
                          "y"], dyn)   # confirm: yes → install
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("10.0.0.5 (eth0) is a DHCP lease, not a static address — used for: management: web UI, sensor API, host SSH", out)
        self.assertIn("192.168.50.10 (eth1) is a DHCP lease, not a static address — used for: FS01", out)
        self.assertIn("host SSH may be unreachable", out)
        self.assertIn("Continue with DHCP addresses anyway? (y/n) [n]", out)
        self.assertIn("Fix the addresses or services above", out)
        self.assertIn("would install /etc/systemd/system/redpot.service", out)    # installed after 'y'


class TestSensorManagerRoute(unittest.TestCase):
    def test_link_interface_is_enforced_with_a_pinned_route(self):
        """VM test round 1: 2 NICs in one subnet, the kernel used the other one (no route over the Wi-Fi bridge)
        → enrollment 'No route to host'. The chosen manager link must be enforced."""
        two_same = [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP", "gw": "10.0.0.1"},
                    {"name": "eth1", "ip": "10.0.0.6", "prefix": 24, "state": "UP"}]
        rc, out, _ = run(["2", "1", ""], two_same, "--join", JOIN, mode="sensor")     # link eth1, decoy eth0
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("pinning a route through eth1", out)
        self.assertIn("ip route replace 10.0.0.99/32 dev eth1 src 10.0.0.6", out)
        rc, out, _ = run(["1", "2", ""], two_same, "--join", JOIN, mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertNotIn("pinning a route", out)                # kernel already uses eth0


class TestBusyPorts(unittest.TestCase):
    def test_own_ip_busy_port_refused_then_another_interface(self):
        rc, out, _ = run([
            "1", DOM, "1", "2",                                        # web role
            "2", "WEB01", "n",                                         # eth1: port 80 busy → refuse stopping
            "3", "", "y",                                              # asked again: eth2 (busy too here) → stop
            "no", "n", "",
        ], THREE, busy="80/tcp=apache2.service")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("80/tcp  service apache2.service", out)
        self.assertIn("choose another interface or another decoy", out)
        self.assertIn("--sensor WEB01=linux-web-hosting@172.16.5.10%eth2", out)
        self.assertIn("will stop + disable: apache2.service", out)
        self.assertNotIn("free address", out)

    def test_extra_services_on_decoy_address_are_flagged(self):
        """Other open ports next to a decoy reveal the honeypot → offer to stop (default yes), warn about programs
        that are not services; DHCP client noise is ignored."""
        rc, out, _ = run([
            "1", DOM, "1", "4",                                        # DC
            "eth1", "DC01", "",                                        # own address → extra services → Enter = yes
            "no", "n", "",
        ], THREE, busy="3306/tcp=mysql.service,9090/tcp=cockpit.socket,5000/tcp=python3,68/udp=systemd-networkd")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("These services also answer on 192.168.50.10, next to Windows Domain Controller", out)
        self.assertIn("3306/tcp  service mysql.service", out)
        self.assertIn("5000/tcp: program 'python3'", out)
        self.assertIn("cannot be stopped automatically", out)
        self.assertNotIn("68/udp", out)
        self.assertIn("Stop and disable cockpit.socket, mysql.service during the install? (y/n) [y]", out)
        self.assertIn("will stop + disable: cockpit.socket, mysql.service", out)

    def test_own_ip_busy_port_stop_shown_in_review_and_executed(self):
        rc, out, _ = run([
            "1", DOM, "1", "2",
            "eth1", "WEB01", "y",                                      # accept stopping apache2
            "no", "n", "",
        ], THREE, busy="80/tcp=apache2.service,443/tcp=apache2.service")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("will stop + disable: apache2.service", out)
        self.assertIn("systemctl disable --now apache2.service", out)

    @pytest.mark.slow
    def test_only_interface_busy_goes_back_to_the_roles(self):
        rc, out, _ = run([
            DOM, "",
            "2", "",                                                   # web on the only NIC: 80 held by a program
            "3", "",                                                   # → back to the roles: backup server instead
            "no", "n", "",
            "y",                                                       # review F4a: myapp on ens3 becomes unreachable
        ], ONE, busy="80/tcp=myapp")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("These host services listen there now and become UNREACHABLE on ens3", out)
        self.assertIn("Close them on ens3? (y/n) [n]", out)
        self.assertIn("program 'myapp'", out)
        self.assertIn("cannot free them", out)
        self.assertIn("No other interface is free for Linux Web Hosting", out)
        self.assertIn("--sensor BKP01=ftp-backup-server@203.0.113.20%ens3", out)

    def test_unattended_busy_needs_flag(self):
        rc, out, _ = run([], ONE, "--yes", "--roles", "linux-web-hosting", "--domain", "x.example.com",
                         "--profile", "generic", "--public-ip", "no", "--geoip", "no", busy="80/tcp=nginx.service")
        self.assertNotEqual(rc, 0)
        self.assertIn("--stop-conflicting", out)


class TestResetToken(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, "reset-token runs without --dry-run and the installer exits 'run as root' for non-root (e.g. labrun uid 10001)")
    def test_reset_admin_and_wall_token(self):
        with tempfile.TemporaryDirectory() as d:
            json.dump({"console": {"admin_token": "OLDTOKEN1234567890", "wall_token": "OLDWALL"}}, open(os.path.join(d, "rpot.json"), "w"))
            open(os.path.join(d, "INSTALL-INFO.txt"), "w").write(
                "Web UI               https://10.0.0.5:50000\nAdmin token          OLDTOKEN1234567890\n"
                "Wall (read-only)     https://10.0.0.5:50000/wall?k=OLDWALL\n")
            env = dict(os.environ, RPOT_TEST_IFACES="[]")
            p = subprocess.run([sys.executable, INSTALLER, "reset-token", "--wall", "--yes", "--dir", d],
                               capture_output=True, text=True, env=env, timeout=60)
            out = ANSI.sub("", p.stdout + p.stderr)
            self.assertEqual(p.returncode, 0, out)
            cfg = json.load(open(os.path.join(d, "rpot.json")))
            self.assertNotEqual(cfg["console"]["admin_token"], "OLDTOKEN1234567890")
            self.assertNotEqual(cfg["console"]["wall_token"], "OLDWALL")
            info = open(os.path.join(d, "INSTALL-INFO.txt")).read()
            self.assertIn(cfg["console"]["admin_token"], info)
            self.assertIn("wall?k=" + cfg["console"]["wall_token"], info)
            self.assertIn("New admin token", out)
            p = subprocess.run([sys.executable, INSTALLER, "reset-token", "--yes", "--dir", d, "--wall-allow", "10.0.5.20,10.0.6.0/28"],
                               capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(json.load(open(os.path.join(d, "rpot.json")))["console"]["wall_allow"], ["10.0.5.20", "10.0.6.0/28"])
            p = subprocess.run([sys.executable, INSTALLER, "reset-token", "--yes", "--dir", d, "--wall-allow", "bad"],
                               capture_output=True, text=True, env=env, timeout=60)
            self.assertNotEqual(p.returncode, 0)
            p = subprocess.run([sys.executable, INSTALLER, "reset-token", "--yes", "--dir", d, "--token", "short"],
                               capture_output=True, text=True, env=env, timeout=60)
            self.assertNotEqual(p.returncode, 0)


def _mod():
    import types
    sys.path.insert(0, os.path.join(REPO, "installer"))
    import redpot_install as r
    r.A = types.SimpleNamespace(dry_run=True, yes=True, no_ssh_move=False, dir=None, keep_data=False, purge_image=False)
    r.role_catalog()
    return r


class TestUnattendedValidation(unittest.TestCase):
    def test_yes_defaults_are_validated(self):
        """B7 in CE terms: --yes with more decoys than interfaces must stop before anything happens."""
        rc, out, _ = run([], ONE, "--yes", "--domain", "x.example.com",
                         "--roles", "windows-file-server,windows-domain-controller", "--public-ip", "no", "--geoip", "no")
        self.assertNotEqual(rc, 0)
        self.assertIn("2 decoys need 2 network interfaces", out)
        self.assertNotIn("would install /etc/systemd", out)

    def test_roles_all_is_gone(self):
        rc, out, _ = run([], THREE, "--yes", "--domain", "x.example.com", "--roles", "all", "--public-ip", "no",
                         "--geoip", "no")
        self.assertNotEqual(rc, 0)
        self.assertIn("--roles: unknown role(s) all", out)

    @pytest.mark.slow
    def test_rpotctl_init_hint_hidden_for_the_installer(self):
        ctl = os.path.join(REPO, "rpotctl.py")
        for quiet in (False, True):
            with tempfile.TemporaryDirectory() as d:
                e = dict(os.environ)
                e.pop("RPOT_INSTALLER", None)
                if quiet:
                    e["RPOT_INSTALLER"] = "1"
                p = subprocess.run([sys.executable, ctl, "init", "-d", d, "--domain", "x.local", "--sensor",
                                    "FS01=windows-file-server"], capture_output=True, text=True, env=e, timeout=120)
                self.assertEqual(p.returncode, 0, p.stderr[-800:])
                self.assertEqual("next     : rpotctl.py compose" in p.stdout, not quiet)


def _rules(txt, chain, cmd="$IPT"):
    """Rules of one chain in a generated firewall.sh, as token lists after '-A CHAIN'."""
    out = []
    for line in txt.splitlines():
        t = line.split()
        if len(t) > 3 and t[0] == cmd and t[1] == "-A" and t[2] == chain:
            out.append(t[3:])
    return out


def _verdict(rules, iface=None, dst=None, proto="tcp", port=None, src="203.0.113.99", sport=40000, state="NEW",
             bcast=False, uid=None, origdst=None, origport=None, oface=None, dnat=None, length=100,
             local=("10.0.0.5", "192.168.50.10", "172.16.5.10")):
    """Tiny iptables evaluator for the generated chains: first matching rule wins; RETURN = let it through,
    REJECT = closed; no match = let it through (chain end). Enough to 'port scan' the rules in a unit test.
    A forwarded packet: iface = where it arrived, oface = where it is routed to (docker0 / br-xxxx for a container),
    dst = its destination now; origdst/origport = the destination before DNAT. dnat defaults to "was DNAT'd"
    (origdst given and different from dst), which conntrack shows as the virtual state DNAT. '!' negates the
    next match; interface names ending in '+' are prefixes, like iptables. Addresses in `local` (+127/8) are
    --dst-type LOCAL."""
    import ipaddress
    if dnat is None:
        dnat = origdst is not None and origdst != dst

    def ifmatch(name, v):
        return name is not None and (name.startswith(v[:-1]) if v.endswith("+") else name == v)

    def addr_in(a, net):
        try:
            return a is not None and ipaddress.ip_address(a) in ipaddress.ip_network(net, strict=False)
        except (TypeError, ValueError):
            return False

    def dst_types():
        a = ipaddress.ip_address(dst)
        if bcast:
            return {"BROADCAST"}
        if a.is_loopback or dst in local:
            return {"LOCAL"}
        return {"MULTICAST"} if a.is_multicast else {"UNICAST"}

    for r in rules:
        k, ok, target, neg = 0, True, None, False
        while k < len(r):
            o = r[k]
            v = r[k + 1] if k + 1 < len(r) else None
            if o == "-j":
                target = v
                break
            if o == "!":
                neg = True
                k += 1
                continue
            if o == "-m":
                k += 2
                continue
            if o == "-i":
                m = ifmatch(iface, v)
            elif o == "-o":
                m = ifmatch(oface, v)
            elif o == "-d":
                m = addr_in(dst, v)
            elif o == "-s":
                m = addr_in(src, v)
            elif o == "-p":
                m = proto == v
            elif o == "--dport":
                m = port == int(v)
            elif o == "--sport":
                m = sport == int(v)
            elif o == "--dports":
                m = port in {int(x) for x in v.split(",")}
            elif o == "--ctstate":
                m = bool(({state} | ({"DNAT"} if dnat else set())) & set(v.split(",")))
            elif o == "--ctorigdst":
                m = (origdst or dst) == v
            elif o == "--ctorigdstport":
                m = (origport or port) == int(v)
            elif o == "--dst-type":
                m = bool(dst_types() & set(v.split(",")))
            elif o == "--uid-owner":
                m = uid == int(v)
            elif o == "--length":
                lo, _, hi = v.partition(":")
                m = int(lo) <= length <= int(hi or lo)
            else:
                raise AssertionError(f"evaluator does not know {o} in {r}")
            ok &= (not m) if neg else m
            neg = False
            k += 2
        if ok:
            return "open" if target == "RETURN" else "closed"
    return "open"


class TestFirewall(unittest.TestCase):
    PORTS = {"ui": 50000, "sensor": 50001, "ssh": 50022}

    def test_reject_not_drop_and_ttl(self):
        """B9: protected admin ports answer like closed ports (RST), never 'filtered'. B24: TTL 128 for Windows."""
        r = _mod()
        txt, restricted = r.firewall_text("10.0.0.5", {"ui": ["10.8.0.0/24"], "sensor": [r.ANY], "ssh": ["10.8.0.0/24"]},
                                          self.PORTS, True, [("10.0.0.5", None)])
        self.assertTrue(restricted)
        self.assertNotIn("DROP", txt)
        self.assertIn("--dport 50022 -j REJECT --reject-with tcp-reset", txt)
        self.assertIn("--ctorigdstport 50000 -j REJECT --reject-with tcp-reset", txt)
        self.assertIn("-t mangle -A REDPOT-TTL -s 10.0.0.5 -j TTL --ttl-set 128", txt)
        self.assertIn("-t mangle -X REDPOT-TTL", txt.split("apply()")[0])          # removed again on stop/uninstall

    def test_ttl_targets_every_decoy_is_host_network(self):
        """S-1 M4: no per-decoy host-network flag — every CE decoy owns a host address."""
        r = _mod()
        self.assertEqual(r.ttl_targets([{"role": "windows-file-server", "ip": "1.1.1.1"},
                                        {"role": "windows-domain-controller", "ip": "2.2.2.2"},
                                        {"role": "linux-web-hosting", "ip": "3.3.3.3"}]),
                         [("1.1.1.1", None), ("2.2.2.2", None)])
        self.assertEqual(r.ttl_targets([{"role": "windows-file-server", "ip": "1.1.1.1"},
                                        {"role": "linux-web-hosting", "ip": "1.1.1.1"}]),
                         [("1.1.1.1", [135, 139, 445, 3389])])

    def _three(self, r, allow=None, move=True):
        decoys = [{"name": "DC01", "role": "windows-domain-controller", "ip": "10.0.0.5", "iface": "eth0"},
                  {"name": "FS01", "role": "windows-file-server", "ip": "192.168.50.10", "iface": "eth1"},
                  {"name": "WEB01", "role": "linux-web-hosting", "ip": "172.16.5.10", "iface": "eth2"}]
        txt, _ = r.firewall_text("10.0.0.5", allow or {"ui": [r.ANY], "sensor": [r.ANY], "ssh": [r.ANY]}, self.PORTS,
                                 move, r.ttl_targets(decoys), mgmt_if="eth0", decoys=decoys, out_guard=True)
        return txt

    def test_scan_of_each_decoy_ip_shows_exactly_the_role_ports(self):
        """S-1 H1 acceptance at rule level: a full TCP scan of a decoy IP from its LAN sees only the role's ports."""
        r = _mod()
        txt = self._three(r, {"ui": ["10.8.0.0/24"], "sensor": ["10.8.0.0/24"], "ssh": ["10.8.0.0/24"]})
        rin = _rules(txt, "REDPOT-IN")
        # every port number that appears in a rule, plus probes: a port no rule names behaves like any other
        # unnamed port, so this is the same as scanning 1-65535 (and 1000× faster)
        scan = {int(t) for r_ in rin for t in re.split(r"[,\s]", " ".join(r_)) if t.isdigit() and 0 < int(t) < 65536}
        scan |= {1, 7, 23, 1023, 3306, 5985, 8080, 49999, 65535}
        for iface, ip, role in (("eth0", "10.0.0.5", "windows-domain-controller"),
                                ("eth1", "192.168.50.10", "windows-file-server"),
                                ("eth2", "172.16.5.10", "linux-web-hosting")):
            want = r.ROLE_PORTS[role] - r.ROLE_UDP[role]
            self.assertLessEqual(want, scan)
            seen = {p for p in scan if _verdict(rin, iface, ip, "tcp", p) == "open"}
            self.assertEqual(seen, want, (iface, role))
            udp = {p for p in scan if _verdict(rin, iface, ip, "udp", p) == "open"}
            self.assertLessEqual(udp, r.ROLE_PORTS[role])
            self.assertEqual(_verdict(rin, iface, ip, "tcp", 4444, state="ESTABLISHED"), "open")   # replies
        self.assertEqual(_verdict(rin, "eth0", "10.0.0.255", "udp", 137, bcast=True), "open")    # NBNS broadcast
        self.assertEqual(_verdict(rin, "eth1", "192.168.50.255", "udp", 137, bcast=True), "closed")
        self.assertEqual(_verdict(rin, "eth1", "192.168.50.10", "udp", 68, sport=67), "open")    # DHCP lease renewals

    def test_admin_ports_only_on_the_management_interface(self):
        r = _mod()
        txt = self._three(r)                                       # allowlists open: 'anyone' — but only via eth0
        rin, rdk = _rules(txt, "REDPOT-IN"), _rules(txt, "REDPOT-DOCKER")
        self.assertEqual(_verdict(rin, "eth0", "10.0.0.5", "tcp", 50022), "open")
        for iface in ("eth1", "eth2"):                             # weak host model: mgmt IP reached via a decoy NIC
            self.assertEqual(_verdict(rin, iface, "10.0.0.5", "tcp", 50022), "closed")
            for p in (50000, 50001):
                self.assertEqual(_verdict(rdk, iface, "172.18.0.2", "tcp", 8740, origdst="10.0.0.5", origport=p), "closed")
        for p in (50000, 50001):
            self.assertEqual(_verdict(rdk, "eth0", "172.18.0.2", "tcp", 8740, origdst="10.0.0.5", origport=p), "open")
        from unittest import mock
        with mock.patch.object(r, "ssh_session_ip_client", lambda: "10.99.0.7"):     # the admin's live SSH client
            txt = self._three(r, {"ui": ["10.8.0.0/24"], "sensor": ["10.8.0.0/24"], "ssh": ["10.8.0.0/24"]})
        rin, rdk = _rules(txt, "REDPOT-IN"), _rules(txt, "REDPOT-DOCKER")
        self.assertEqual(_verdict(rin, "eth0", "10.0.0.5", "tcp", 50022, src="10.8.0.9"), "open")
        self.assertEqual(_verdict(rin, "eth0", "10.0.0.5", "tcp", 50022, src="10.99.0.7"), "open")    # admin session
        self.assertEqual(_verdict(rin, "eth0", "10.0.0.5", "tcp", 50022), "closed")
        self.assertEqual(_verdict(rdk, "eth0", "172.18.0.2", "tcp", 8740, origdst="10.0.0.5", origport=50000), "closed")
        self.assertEqual(_verdict(rdk, "eth1", "172.18.0.2", "tcp", 8740, src="10.8.0.9", origdst="10.0.0.5",
                                  origport=50000), "closed")

    def test_ipv6_and_arp_on_decoy_interfaces(self):
        r = _mod()
        txt = self._three(r)
        r6 = _rules(txt, "REDPOT-IN6", "$IP6T")
        for n in ("eth0", "eth1", "eth2"):
            self.assertIn(f"  arp {n}", txt)
            self.assertEqual(_verdict(r6, n, "fe80::1", "tcp", 22), "closed")
            self.assertEqual(_verdict(r6, n, "fe80::1", "udp", 53), "closed")
        self.assertIn("arp_ignore:1 arp_announce:2", txt)
        self.assertIn('rm -f "$ARP_BAK"', txt.split("apply()")[0])                # old values restored on remove
        self.assertIn("$IP6T -X $c", txt.split("apply()")[0])

    def test_decoy_egress_guard(self):
        """S-1 M3: a decoy (uid 10001) reaches only the sensor API on the management IP; replies are fine."""
        r = _mod()
        rout = _rules(self._three(r), "REDPOT-OUT")
        u = 10001
        self.assertEqual(_verdict(rout, None, "172.18.0.2", "tcp", 8741, uid=u, origdst="10.0.0.5", origport=50001), "open")
        self.assertEqual(_verdict(rout, None, "172.18.0.2", "tcp", 8740, uid=u, origdst="10.0.0.5", origport=50000), "closed")
        for dst, port in (("127.0.0.1", 50001), ("127.0.0.1", 22), ("10.0.0.1", 445), ("1.1.1.1", 443), ("10.0.0.5", 50022)):
            self.assertEqual(_verdict(rout, None, dst, "tcp", port, uid=u), "closed", (dst, port))
        self.assertEqual(_verdict(rout, None, "8.8.8.8", "udp", 53, uid=u), "closed")
        self.assertEqual(_verdict(rout, None, "203.0.113.99", "tcp", 51515, uid=u, state="ESTABLISHED"), "open")
        self.assertEqual(_verdict(rout, None, "1.1.1.1", "tcp", 443, uid=0), "open")                    # host itself
        r6 = _rules(self._three(r), "REDPOT-OUT6", "$IP6T")
        self.assertEqual(_verdict(r6, None, "::1", "tcp", 50001, uid=u), "closed")

    def test_decoy_egress_guard_has_no_loopback_exception(self):
        """RC-21 / B1: SMB named pipes reach their RPC servers in-process (socketpair), so REDPOT-OUT needs no
        loopback hole: host services on 127.0.0.0/8 (moved sshd, docker-proxy, resolved 127.0.0.53) and any
        ephemeral port stay closed to the decoys, TCP and UDP, including out of 'lo'."""
        r = _mod()
        txt = self._three(r)
        rout, r6 = _rules(txt, "REDPOT-OUT"), _rules(txt, "REDPOT-OUT6", "$IP6T")
        for rule in rout + r6:
            self.assertNotIn("lo", [rule[i + 1] for i, t in enumerate(rule[:-1]) if t == "-o"], rule)
            self.assertFalse(any(t.startswith(("127.", "::1")) for t in rule), rule)
        u = 10001
        for dst, proto, port in (("127.0.0.1", "tcp", 22), ("127.0.0.1", "tcp", 52043), ("127.0.0.1", "tcp", 2375),
                                 ("127.0.0.53", "udp", 53), ("127.0.0.53", "tcp", 53), ("127.0.0.1", "tcp", 8740),
                                 *(("127.0.0.1", "tcp", p) for p in range(32768, 61000, 997))):
            self.assertEqual(_verdict(rout, None, dst, proto, port, uid=u, oface="lo"), "closed", (dst, proto, port))
        self.assertEqual(_verdict(r6, None, "::1", "tcp", 445, uid=u, oface="lo"), "closed")

    # ---- security review RC-16 (RC-17)
    BR = "br-0a1b2c3d4e5f"                                          # a compose network bridge

    def test_direct_route_to_the_console_container_is_rejected(self):
        """Review F1: Docker <28 accepts '-d <container> --dport 8740' in its DOCKER chain however the packet came,
        ≥28 still accepts direct-routed packets to published ports. An attacker on a decoy LAN routes 172.16/12 via
        the decoy IP: the packet arrives on eth1, is NOT DNAT'd (origdst = the container IP) and is forwarded to the
        compose bridge. DOCKER-USER (→ REDPOT-DOCKER) runs before Docker's chains in both, so it must say no."""
        r = _mod()
        from unittest import mock
        with mock.patch.object(r, "ssh_session_ip_client", lambda: "10.99.0.7"):
            for allow in ({"ui": [r.ANY], "sensor": [r.ANY], "ssh": [r.ANY]},
                          {"ui": ["10.8.0.0/24"], "sensor": ["10.8.0.0/24"], "ssh": ["10.8.0.0/24"]}):
                rdk = _rules(self._three(r, allow), "REDPOT-DOCKER")
                for cport in (8740, 8741):
                    for iface in ("eth1", "eth2"):                  # decoy LANs, routed straight to the container
                        for br in (self.BR, "docker0"):
                            self.assertEqual(_verdict(rdk, iface, "172.18.0.2", "tcp", cport, oface=br), "closed")
                            self.assertEqual(_verdict(rdk, iface, "172.18.0.2", "tcp", cport, oface=br,
                                                      src="10.8.0.9"), "closed")             # even 'allowed' sources
                        # published port, but via a decoy NIC (weak host model): DNAT'd and still closed
                        self.assertEqual(_verdict(rdk, iface, "172.18.0.2", "tcp", cport, oface=self.BR, src="10.8.0.9",
                                                  origdst="10.0.0.5", origport=50000), "closed")
                    # the management interface (shared with the DC decoy) and any other NIC (VPN): no DNAT, no entry
                    for iface in ("eth0", "wg0"):
                        self.assertEqual(_verdict(rdk, iface, "172.18.0.2", "tcp", cport, oface=self.BR,
                                                  src="10.8.0.9"), "closed")
                        self.assertEqual(_verdict(rdk, iface, "172.18.0.2", "udp", cport, oface=self.BR,
                                                  src="10.8.0.9"), "closed")
                    self.assertEqual(_verdict(rdk, "eth1", "172.18.0.2", "udp", 53, oface=self.BR), "closed")
                # the host never routes for a decoy LAN (eth1 → management LAN, internet)
                self.assertEqual(_verdict(rdk, "eth1", "10.0.0.20", "tcp", 445, oface="eth0"), "closed")
                # published ports: DNAT'd on the management interface from an allowed source still pass
                for p in (50000, 50001):
                    self.assertEqual(_verdict(rdk, "eth0", "172.18.0.2", "tcp", 8740 if p == 50000 else 8741,
                                              oface=self.BR, src="10.8.0.9", origdst="10.0.0.5", origport=p), "open")
                # container → outside (GeoIP download, DNS) and its replies — on any NIC, decoy ones too
                for out_if in ("eth0", "eth1"):
                    self.assertEqual(_verdict(rdk, self.BR, "1.1.1.1", "tcp", 443, src="172.18.0.2", oface=out_if), "open")
                    self.assertEqual(_verdict(rdk, out_if, "172.18.0.2", "tcp", 40000, src="1.1.1.1", oface=self.BR,
                                              state="ESTABLISHED"), "open")
                    self.assertEqual(_verdict(rdk, out_if, "172.18.0.2", "icmp", None, src="1.1.1.1", oface=self.BR,
                                              state="RELATED"), "open")
                # container ↔ container on one compose network; a user's own bridge (br0, virbr0) is not Docker's
                self.assertEqual(_verdict(rdk, self.BR, "172.18.0.3", "tcp", 8741, src="172.18.0.2", oface=self.BR), "open")
                self.assertEqual(_verdict(rdk, "wg0", "192.168.122.5", "tcp", 22, oface="virbr0"), "open")
            # allow-lists still apply to DNAT'd traffic on the management interface
            rdk = _rules(self._three(r, {"ui": ["10.8.0.0/24"], "sensor": ["10.8.0.0/24"], "ssh": ["10.8.0.0/24"]}),
                         "REDPOT-DOCKER")
            self.assertEqual(_verdict(rdk, "eth0", "172.18.0.2", "tcp", 8740, oface=self.BR, src="198.51.100.4",
                                      origdst="10.0.0.5", origport=50000), "closed")
        # no decoys, allow-lists only: direct routing is closed as well (it would bypass the allow-list)
        rdk = _rules(r.firewall_text("10.0.0.5", {"ui": ["10.8.0.0/24"], "sensor": [r.ANY], "ssh": [r.ANY]},
                                     self.PORTS, False)[0], "REDPOT-DOCKER")
        self.assertEqual(_verdict(rdk, "eth0", "172.18.0.2", "tcp", 8740, oface="docker0", src="10.8.0.9"), "closed")
        self.assertEqual(_verdict(rdk, "eth0", "172.18.0.2", "tcp", 8740, oface="docker0", src="10.8.0.9",
                                  origdst="10.0.0.5", origport=50000), "open")

    def test_nbns_egress_is_narrow(self):
        """Review F2: the NBNS exception (uid 10001, udp sport 137) is no general UDP channel any more."""
        r = _mod()
        decoys = [{"name": "DC01", "role": "windows-domain-controller", "ip": "192.168.50.10", "iface": "eth1",
                   "net": "192.168.50.0/24"}]
        txt, _ = r.firewall_text("10.0.0.5", {"ui": [r.ANY], "sensor": [r.ANY], "ssh": [r.ANY]}, self.PORTS, False,
                                 mgmt_if="eth0", decoys=decoys, out_guard=True)
        rout = _rules(txt, "REDPOT-OUT")
        u, nb = 10001, dict(uid=10001, src="192.168.50.10", sport=137, oface="eth1")
        self.assertEqual(_verdict(rout, None, "192.168.50.77", "udp", 137, **nb), "open")      # answer to a query
        self.assertEqual(_verdict(rout, None, "192.168.50.77", "udp", 61000, **nb), "open")
        for dst, port, kw in (("127.0.0.53", 53, {}), ("127.0.0.53", 53, {"oface": "lo"}),     # systemd-resolved
                              ("8.8.8.8", 53, {}), ("1.1.1.1", 443, {}),                       # internet
                              ("192.168.50.1", 53, {}),                                        # LAN resolver: no DNS tunnel
                              ("10.0.0.20", 137, {"oface": "eth0"}),                           # another interface
                              ("10.0.0.5", 137, {"oface": "eth0"}),                            # the host itself
                              ("192.168.50.10", 137, {}),                                      # its own (local) address
                              ("192.168.50.255", 137, {"bcast": True}),                        # broadcast
                              ("192.168.50.77", 137, {"length": 1400}),                        # bulk data
                              ("192.168.50.77", 137, {"src": "10.0.0.5"})):                    # another source
            self.assertEqual(_verdict(rout, None, dst, "udp", port, **dict(nb, **kw)), "closed", (dst, port, kw))
        self.assertEqual(_verdict(rout, None, "192.168.50.77", "udp", 137, uid=u, src="192.168.50.10", sport=138,
                                  oface="eth1"), "closed")
        # follow mode (sensor, DHCP): the interface and today's subnet, read when the firewall is applied
        txt, _ = r.firewall_text("10.0.0.7", {}, {"ssh": 52187}, True, mgmt_if="eth0", out_guard=True, follow=True,
                                 decoys=[{"name": "DC01", "role": "windows-domain-controller", "ip": "10.0.0.7",
                                          "iface": "eth0"}])
        self.assertIn("NET=$(ip -4 -o addr show dev eth0 2>/dev/null | awk '{print $4; exit}')", txt)
        self.assertIn("NBNS broadcast answers stay blocked", txt)
        rout = _rules(txt.replace('"$NET"', "10.0.0.0/24"), "REDPOT-OUT")
        nb = dict(uid=10001, src="10.0.0.7", sport=137, oface="eth0", local=("10.0.0.7",))
        self.assertEqual(_verdict(rout, None, "10.0.0.77", "udp", 137, **nb), "open")
        for dst, port in (("127.0.0.53", 53), ("8.8.8.8", 53), ("10.0.0.1", 53), ("10.1.0.77", 137), ("10.0.0.7", 137)):
            self.assertEqual(_verdict(rout, None, dst, "udp", port, **nb), "closed", dst)

    def test_ipv6_admin_session_keeps_ssh_with_an_allowlist(self):
        """Review F4b: decoy on mgmt + IPv4 SSH allow-list must not lock out the admin's IPv6 session."""
        r = _mod()
        from unittest import mock
        allow = {"ui": ["10.8.0.0/24"], "sensor": ["10.8.0.0/24"], "ssh": ["10.8.0.0/24"]}
        with mock.patch.object(r, "ssh_session_ip_client", lambda: "2001:db8::7"):
            txt = self._three(r, allow)
        r6 = _rules(txt, "REDPOT-IN6", "$IP6T")
        self.assertEqual(_verdict(r6, "eth0", "2001:db8::5", "tcp", 50022, src="2001:db8::7"), "open")
        self.assertEqual(_verdict(r6, "eth0", "2001:db8::5", "tcp", 50022, src="2001:db8::8"), "closed")
        self.assertEqual(_verdict(r6, "eth1", "2001:db8::5", "tcp", 50022, src="2001:db8::7"), "closed")
        self.assertNotIn("2001:db8::7", "".join(" ".join(x) for x in _rules(txt, "REDPOT-IN")))   # no v6 in iptables
        with mock.patch.object(r, "ssh_session_ip_client", lambda: "::ffff:10.99.0.7"):           # v4-mapped
            rin = _rules(self._three(r, allow), "REDPOT-IN")
        self.assertEqual(_verdict(rin, "eth0", "10.0.0.5", "tcp", 50022, src="10.99.0.7"), "open")
        rc, out, _ = run(["x.example.com", "", "1", "", "no", "n", "", "", "10.8.0.0/24", ""], ONE, "ask-allow")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("Your current SSH client 10.99.0.7 is always allowed on ens3", out)

    def test_script_syntax_and_check_fails_closed(self):
        """Review F6: apply ends with check(); a chain nobody jumps to (Docker nftables backend: no DOCKER-USER
        hook; no ip6tables while IPv6 is on) makes it exit non-zero with a message, so the unit does not start."""
        r = _mod()
        txt = self._three(r)
        p = subprocess.run(["/bin/sh", "-n"], input=txt, capture_output=True, text=True, timeout=30)   # parse only
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("  check   # every chain hooked", txt.split("apply() {")[1])
        self.assertIn("$IPT -I FORWARD 1 -j REDPOT-DOCKER", txt)                  # nft backend: hook FORWARD directly
        self.assertIn("$IPT -D FORWARD -j REDPOT-DOCKER", txt.split("apply()")[0])
        body = txt[txt.index("check() {"):]
        body = body[:body.index("\n}\n") + 3]
        # pure-shell stubs: nothing on the host is read or changed. HOOKS = "CHAIN>TARGET …" that exist
        stub = ('ipt() { case " $HOOKS " in *" $2>$4 "*) return 0 ;; esac; return 1; }\n'
                'ip6t() { [ -n "$NO6" ] && return 127; case " $HOOKS6 " in *" $2>$4 "*) return 0 ;; esac; return 1; }\n'
                'v6on() { [ -n "$V6" ]; }\nIPT=ipt; IP6T=ip6t\n')
        full4 = "INPUT>REDPOT-IN DOCKER-USER>REDPOT-DOCKER FORWARD>DOCKER-USER OUTPUT>REDPOT-OUT"
        full6 = "INPUT>REDPOT-IN6 OUTPUT>REDPOT-OUT6"

        def check(**env):
            e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOOKS": full4, "HOOKS6": full6, "V6": "1"}
            e.update(env)
            return subprocess.run(["/bin/sh", "-c", stub + body + "check"], capture_output=True, text=True, env=e,
                                  timeout=30)
        self.assertEqual(check().returncode, 0)                                   # docker iptables backend
        p = check(HOOKS="INPUT>REDPOT-IN DOCKER-USER>REDPOT-DOCKER OUTPUT>REDPOT-OUT")   # nftables backend, no hook
        self.assertEqual(p.returncode, 1)
        self.assertIn("NOT in effect: FORWARD->REDPOT-DOCKER", p.stderr)
        self.assertEqual(check(HOOKS="INPUT>REDPOT-IN FORWARD>REDPOT-DOCKER OUTPUT>REDPOT-OUT").returncode, 0)  # fallback
        p = check(HOOKS="DOCKER-USER>REDPOT-DOCKER FORWARD>DOCKER-USER")
        self.assertIn("INPUT->REDPOT-IN", p.stderr)
        self.assertIn("OUTPUT->REDPOT-OUT", p.stderr)
        p = check(NO6="1")                                                        # no ip6tables, IPv6 on
        self.assertEqual(p.returncode, 1)
        self.assertIn("ip6tables:INPUT->REDPOT-IN6 ip6tables:OUTPUT->REDPOT-OUT6", p.stderr)
        self.assertEqual(check(NO6="1", V6="").returncode, 0)                     # IPv6 off: nothing to filter

    def test_apply_failure_stops_the_install_with_the_message(self):
        """Review F6, installer side: a failing apply is removed again and ends the install loudly."""
        r = _mod()
        from unittest import mock
        calls = []

        def fake_run(cmd, check=True, capture=False, quiet=False):
            calls.append(cmd[-1])
            return subprocess.CompletedProcess(cmd, 1 if cmd[-1] == "apply" else 0, "",
                                               "ReD-Pot firewall NOT in effect: FORWARD->REDPOT-DOCKER\x1b[2J")
        with mock.patch.object(r, "run", fake_run), mock.patch("builtins.print") as pr:
            with self.assertRaises(SystemExit):
                r.apply_firewall("/opt/redpot/manager")
        self.assertEqual(calls, ["apply", "remove"])
        msg = " ".join(str(a) for c in pr.call_args_list for a in c.args)
        self.assertIn("decoys were NOT started", msg)
        self.assertIn("FORWARD->REDPOT-DOCKER", msg)
        self.assertNotIn("\x1b[2J", msg)


    def test_unsafe_names_never_reach_the_script(self):
        r = _mod()
        for bad in ({"role": "windows-file-server", "ip": "10.0.0.9", "iface": "eth0;reboot"},
                    {"role": "windows-file-server", "ip": "10.0.0.9 -j ACCEPT", "iface": "eth1"}):
            with self.assertRaises(ValueError):
                r.firewall_text("10.0.0.5", {}, self.PORTS, False, mgmt_if="eth0", decoys=[bad])
        with self.assertRaises(ValueError):
            r.firewall_text("10.0.0.5", {}, self.PORTS, False, mgmt_if="e$(x)",
                            decoys=[{"role": "windows-file-server", "ip": "10.0.0.9", "iface": "eth1"}])

    def test_wizard_writes_ttl_firewall_for_windows_on_own_address(self):
        rc, out, _ = run(["1", "x.example.com", "1", "4", "2", "DC01", "no", "n", ""], TWO_AND_DOWN)
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("TTL 128 (like Windows) for traffic from 192.168.50.10", out)
        self.assertIn("TTL 128 for 192.168.50.10):", out)
        self.assertIn("decoy interfaces eth1: only each decoy's ports; admin ports only via eth0", out)

    def test_allowlist_containing_the_decoy_lan_is_flagged(self):
        """B9/S3: SSH allowed from the DC decoy's own LAN → OpenSSH visible on the 'DC'."""
        rc, out, _ = run(["1", "x.example.com", "1", "4", "1", "DC01", "no", "n",
                          "10.8.0.0/24", "10.8.0.0/24", "10.0.0.0/16", ""], TWO_AND_DOWN, "ask-allow")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("host SSH is allowed from 10.0.0.0/16, which includes 10.0.0.0/24 — the network DC01 lives in", out)
        self.assertNotIn("the web UI is allowed from", out)


class TestReviewKeepsPorts(unittest.TestCase):
    def test_jumping_back_keeps_the_random_ports(self):
        """B22: the UI/sensor/SSH ports shown in the review must not change when a section is edited."""
        rc, out, _ = run(["1", "x.example.com", "1", "4", "1", "DC01", "no", "n",
                          "5", "", "",                          # access again → review 2
                          "4", "", "", "", "",                  # decoy interface + name + access → review 3
                          "3", "", "", "", "", "",              # roles + details + access → review 4
                          "q"], TWO_AND_DOWN)
        seen = re.findall(r"Web UI https://\S+:(\d+) · sensor API port (\d+)", out)
        moved = re.findall(r"host SSH MOVES to port (\d+)", out)
        self.assertEqual(len(seen), 4, out[-2000:])
        self.assertEqual(len(set(seen)), 1)
        self.assertEqual(len(set(moved)), 1)


class TestWebTheme(unittest.TestCase):
    def test_web_theme_question_and_review(self):
        rc, out, _ = run(["1", "x.example.com", "1", "2",
                          "eth1", "WEB01", "x", "2",                # theme: invalid, then helpdesk
                          "no", "n", ""], THREE, "ask-theme")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("What should the web site look like?", out)
        self.assertIn("site: helpdesk", out)
        self.assertIn("--web-theme helpdesk", out)


class TestCeUnits(unittest.TestCase):
    """Installer pieces other tasks rely on (design §5): MAX_DECOYS, limit text, decoy_slots(), interfaces()."""

    def setUp(self):
        self.r = _mod()
        self.env = {k: os.environ.get(k) for k in ("RPOT_TEST_SLOTS", "RPOT_TEST_IFACES", "RPOT_TEST_WILDCARD")}

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        self.r.A.dry_run = True

    def _dies(self, fn, *a):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            fn(*a)
        return ANSI.sub("", buf.getvalue())

    def test_limit_matches_the_edition_module(self):
        sys.path.insert(0, REPO)
        from rpot.common import edition
        self.assertEqual(self.r.MAX_DECOYS, edition.MAX_DECOYS)
        for n in range(6):
            self.assertEqual(self.r.limit_message(n), edition.limit_message(n))

    def test_decoy_slots(self):
        from unittest import mock
        r = self.r
        os.environ["RPOT_TEST_SLOTS"] = '{"max": 3, "used": 2, "local": 1, "remote": 1, "pending": 0}'
        self.assertEqual(r.decoy_slots("/nonexistent")["used"], 2)
        os.environ["RPOT_TEST_SLOTS"] = '{"max": 3, "used": "x"}'
        self.assertIn("RPOT_TEST_SLOTS", self._dies(r.decoy_slots, "/nonexistent"))
        del os.environ["RPOT_TEST_SLOTS"]
        self.assertEqual(r.decoy_slots("/nonexistent", {"sensors": [{}, {}]})["used"], 2)    # dry-run: local only
        r.A.dry_run = False
        with mock.patch.object(r, "_decoy_container", lambda p, s: ""):
            self.assertIn("start the manager first", self._dies(r.decoy_slots, "/nonexistent"))
        calls = []

        def fake(cmd, **k):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, 'noise\n{"max":3,"used":1,"local":1,"remote":0,"pending":0}\n', "")
        with mock.patch.object(r, "_decoy_container", lambda p, s: "cid1"), mock.patch.object(r, "run", fake):
            self.assertEqual(r.decoy_slots("/nonexistent"), {"max": 3, "used": 1, "local": 1, "remote": 0, "pending": 0})
        self.assertEqual(calls[0][:5], ["docker", "exec", "cid1", "python", "/opt/rpot/rpotctl.py"])
        self.assertIn("slots", calls[0])
        with mock.patch.object(r, "_decoy_container", lambda p, s: "cid1"), \
                mock.patch.object(r, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, "", "boom")):
            self.assertIn("could not read the decoy count", self._dies(r.decoy_slots, "/nonexistent"))

    def test_interface_name_whitelist(self):
        r = self.r
        for ok in ("eth0", "enp0s31f6", "eth0.10", "wlan0", "br_x", "ens3-1", "a" * 15):
            self.assertTrue(r.valid_iface_name(ok), ok)
        for bad in ('a"b', "a b", "$(id)", "-eth", ".x", "a" * 16, "", "eth0;x", "eth0@if3", None):
            self.assertFalse(r.valid_iface_name(bad), bad)
        os.environ["RPOT_TEST_IFACES"] = json.dumps(
            [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP"},
             {"name": "x\x1b[31m", "ip": "10.0.1.5", "prefix": 24, "state": "UP"}])
        self.assertEqual([i["name"] for i in r.interfaces()], ["eth0"])
        bad = r.unusable_interfaces()
        self.assertEqual(len(bad), 1)
        self.assertNotIn("\x1b", bad[0][0])
        self.assertIn("unusual characters", bad[0][1])

    def test_persona_preview(self):
        r = self.r
        self.assertEqual(r.persona_preview("corp.ararat-bank.am"),
                         {"company": "Ararat Bank", "netbios": "ARARATBANK", "email_domain": "ararat-bank.am"})
        self.assertEqual(r.persona_preview("corp.araratbank.am")["company"], "Araratbank")
        self.assertEqual(r.persona_preview("acme.local"),
                         {"company": "Acme", "netbios": "ACME", "email_domain": "acme.com"})
        sys.path.insert(0, REPO)
        from rpot import baits
        if not hasattr(baits, "company_from_domain"):
            self.skipTest("rpot.baits.company_from_domain arrives with RC-3 (T2)")
        for d in ("corp.ararat-bank.am", "corp.araratbank.am", "acme.local", "123.com"):
            self.assertEqual(r.persona_preview(d)["company"], baits.company_from_domain(d), d)
        # review F10: a 15-char cut that ends in '-' is stripped like make_persona does
        # RC-27 F-04: natural NetBIOS names (no hyphen, no 15-char cut artefact) - same rule in both places
        for d in ("corp.abcdefghijklmn-op.am", "abcdefghijklmn-x.local", "corp.ararat-bank.am",
                  "corp.redside-security.com", "northwind-traders-intl.com", "ab-cdefghijklmnopqrs.local",
                  "a-b.local", "x.local", "abcdefghijklmnopqrstu.com", "corp.my-bank.am"):
            self.assertNotIn("-", r.persona_preview(d)["netbios"], d)
            self.assertLessEqual(len(r.persona_preview(d)["netbios"]), 15, d)
            self.assertFalse(r.persona_preview(d)["netbios"].endswith("-"), d)
            self.assertEqual(r.persona_preview(d)["netbios"], baits.make_persona(d, seed=1)["netbios"], d)

    def test_wildcard_listeners_are_listed(self):
        import contextlib
        import io
        r = self.r
        os.environ["RPOT_TEST_IFACES"] = "[]"
        os.environ["RPOT_TEST_WILDCARD"] = "631/tcp=cupsd,5353/udp=avahi-daemon"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertTrue(r.self_test("redpot", []))
        out = ANSI.sub("", buf.getvalue())
        self.assertIn("Host services listening on all addresses", out)
        self.assertIn("631/tcp  cupsd", out)
        self.assertIn("5353/udp  avahi-daemon", out)


class TestRoutesAreArgv(unittest.TestCase):
    """S-1 L13: the pinned manager route is run and undone as argv lists — never through a shell."""

    def test_route_pin_and_removal(self):
        from unittest import mock
        r = _mod()
        two_same = [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP", "gw": "10.0.0.1"},
                    {"name": "eth1", "ip": "10.0.0.6", "prefix": 24, "state": "UP"}]
        calls = []
        old = os.environ.get("RPOT_TEST_IFACES")
        os.environ["RPOT_TEST_IFACES"] = json.dumps(two_same)
        try:
            with tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(r, "run", lambda cmd, **k: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", "")):
                r.A.dry_run, r.A.dir = False, d
                st = {"manager": "10.0.0.99:63462", "mgmt": "eth1", "ifs": {i["name"]: i for i in two_same}}
                add, dele = r.manager_route(st)
                self.assertIsInstance(calls[0], list)
                self.assertEqual(calls[0][1:], ["route", "replace", "10.0.0.99/32", "dev", "eth1", "src", "10.0.0.6"])
                saved = json.load(open(os.path.join(d, r.ROUTE_FILE)))
                self.assertEqual(saved[1:], ["route", "del", "10.0.0.99/32", "dev", "eth1"])
                self.assertTrue(r.remove_pinned_route(d))
                self.assertEqual(calls[-1], saved)
                n = len(calls)
                for evil in ('"ip route del 1.2.3.4/32 dev eth0; reboot"', "ip route del 10.0.0.99/32 dev eth1",
                             json.dumps(["/bin/sh", "-c", "reboot", "x", "dev", "eth0"]),
                             json.dumps(["ip", "route", "del", "10.0.0.99/32", "dev", "eth0;reboot"])):
                    open(os.path.join(d, r.ROUTE_FILE), "w").write(evil)
                    self.assertFalse(r.remove_pinned_route(d))
                self.assertEqual(len(calls), n)
        finally:
            r.A.dry_run, r.A.dir = True, None
            os.environ.pop("RPOT_TEST_IFACES", None) if old is None else os.environ.__setitem__("RPOT_TEST_IFACES", old)




class TestSensorRole(unittest.TestCase):
    """B20: the enrolled role is only known after the one-time token is redeemed; the join string may carry it
    as a hint (never sent to the manager)."""

    def test_dry_run_does_not_invent_a_role(self):
        rc, out, _ = run([JOIN, "", "", ""], THREE, mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("role from the manager (unknown in dry-run)", out)
        self.assertIn("firewall.sh (only the decoy's ports on its interface, decoy egress = replies only) is written "
                      "after enrollment", out)
        self.assertNotIn("Linux Web Hosting", out)

    def test_role_hint_is_shown_and_never_sent(self):
        rc, out, _ = run(["", "", ""], THREE, "--join", JOIN_FS, mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("Role chosen on the manager: Windows File Server", out)
        self.assertIn("Windows File Server · 192.168.50.10 on eth1", out)
        self.assertRegex(out, r"-e RPOT_JOIN -v \S+ rpot:\S+ sensor join\n")    # B7: token not in argv
        self.assertIn("TTL 128 (like Windows) for traffic from 192.168.50.10", out)
        self.assertIn("decoy interfaces eth1: only each decoy's ports; admin ports only via eth0; decoy egress: "
                      "replies only", out)
        self.assertIn("rpot.role: windows-file-server", out)

    def test_unfinished_enrollment_is_resumed_without_a_join_string(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "conf"))
            json.dump({"sensor": {"name": "BR-WEB-01", "role": "linux-web-hosting", "ip": None},
                       "manager": {"url": "https://10.0.0.99:63462", "fingerprint": "B6" * 32, "key": "x:y"}},
                      open(os.path.join(d, "conf", "sensor.json"), "w"))
            env = dict(os.environ, RPOT_TEST_IFACES=json.dumps(THREE), RPOT_TEST_SSH_IP="10.0.0.5")
            p = subprocess.run([sys.executable, INSTALLER, "sensor", "--dry-run", "--dir", d],
                               input="\n\n1\n\n\n\n", capture_output=True, text=True, env=env, timeout=60)
            out = ANSI.sub("", p.stdout + p.stderr)
        self.assertEqual(p.returncode, 0, out[-1500:])
        self.assertIn("holds the enrollment of BR-WEB-01 (Linux Web Hosting)", out)
        self.assertIn("the manager cannot change", out)
        self.assertIn("using the existing enrollment", out)
        self.assertNotIn("Join string", out)
        self.assertNotIn("sensor join", out)
        self.assertIn("hostname: br-web-01", out)
        self.assertIn("rpot.role: linux-web-hosting", out)

    def test_wrong_pin_is_a_clear_message_not_a_traceback(self):
        from unittest import mock
        sys.path.insert(0, REPO)
        from rpot.common import tlsutil
        from rpot.sensor import main as sm

        class Bad:
            def __init__(self, *a, **k):
                pass

            def request(self, *a, **k):
                raise tlsutil.PinError("manager certificate fingerprint mismatch")
        with mock.patch.object(tlsutil, "PinnedClient", Bad), tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit) as cm:
                sm.join(JOIN_FS, d)
        self.assertIn("presents a different certificate", str(cm.exception.code))


class TestSensorEnrollLimit(unittest.TestCase):
    """D-6 layer 5: the manager answers a valid join with 409 when the Community Edition is full. The sensor CLI
    prints the limit message; the installer must show it plainly (not 'command failed: docker run …'), keep the
    join string usable and leave nothing behind (the pinned route is removed again)."""

    def _sensor_says(self, used=3):
        from unittest import mock
        sys.path.insert(0, REPO)
        from rpot.common import tlsutil
        from rpot.sensor import main as sm

        class Full:
            def __init__(self, *a, **k):
                pass

            def request(self, *a, **k):
                return 409, {"error": "decoy limit reached", "used": used}
        with mock.patch.object(tlsutil, "PinnedClient", Full), tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit) as cm:
                sm.join(JOIN, d)
            self.assertEqual(os.listdir(d), [])                     # nothing written
        return str(cm.exception.code)

    def _enroll(self, rc, stdout, stderr):
        import contextlib
        import io
        from unittest import mock
        r = _mod()
        routes = []
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(r, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, rc, stdout, stderr)), \
                mock.patch.object(r, "remove_pinned_route", lambda dd: routes.append(dd)), \
                contextlib.redirect_stdout(buf):
            try:
                r.enroll({"manager": "10.0.0.99:63462", "join": JOIN}, d)
                died = False
            except SystemExit:
                died = True
        return died, ANSI.sub("", buf.getvalue()), routes

    def test_limit_message_reaches_the_admin(self):
        sys.path.insert(0, REPO)
        from rpot.common import edition
        said = self._sensor_says(3)
        self.assertIn("decoy limit reached", said)
        died, out, routes = self._enroll(1, "", said + "\n\x1b[31mnoise\x1b[0m\n")
        self.assertTrue(died)
        self.assertIn("the manager refused this sensor: decoy limit reached — Community Edition supports up to 3", out)
        self.assertIn(edition.limit_message(3), out)
        self.assertIn("Nothing was installed on this server and the join string is still valid", out)
        self.assertNotIn("command failed", out)
        self.assertNotIn("\x1b", out)
        self.assertEqual(len(routes), 1)

    def test_other_failures_and_success(self):
        died, out, routes = self._enroll(1, "[!] cannot reach the manager - retry 1/6 in 5 s\n",
                                         "[x] enrollment failed: HTTP 403 invalid or used token\n")
        self.assertTrue(died)
        self.assertIn("enrollment failed: [!] cannot reach the manager", out)
        self.assertIn("HTTP 403 invalid or used token", out)
        self.assertEqual(len(routes), 1)
        died, out, routes = self._enroll(0, "[+] enrolled as BR-FS-01 (windows-file-server) at https://10.0.0.99:63462\n", "")
        self.assertFalse(died)
        self.assertIn("[+] enrolled as BR-FS-01", out)
        self.assertEqual(routes, [])


class TestSelfTest(unittest.TestCase):
    """B21: 'ReD-Pot is ready' was printed while decoys were dark."""
    TCP = ("  sl  local_address rem_address   st\n"
           "   0: 00000000:01BD 00000000:0000 0A\n"          # 0.0.0.0:445
           "   1: 0A00000A:0016 00000000:0000 0A\n"          # 10.0.0.10:22
           "   2: 0500000A:0050 00000000:0000 0A\n"          # 10.0.0.5:80
           "   3: 0500000A:0051 00000000:0000 01\n")         # established, not a listener

    def test_proc_listening(self):
        r = _mod()
        self.assertEqual(r._proc_listening(self.TCP), {445, 22, 80})
        self.assertEqual(r._proc_listening(self.TCP, "10.0.0.5"), {445, 80})

    def test_table_connects_to_every_decoy(self):
        """S-1 M4: every CE decoy is on a host address → always a connect test (no 'test from another host')."""
        import contextlib
        import io
        from unittest import mock
        r = _mod()
        r.A.dry_run = False
        listen = "".join(f"   0: 00000000:{p:04X} 00000000:0000 0A\n" for p in (135, 139, 445, 3389))
        tried = []

        def connect(addr, timeout):
            tried.append(addr)
            if addr[0] != "10.0.0.50":
                raise OSError("refused")
            return mock.Mock()
        buf = io.StringIO()
        with mock.patch.object(r, "_decoy_container", lambda proj, svc: "abc" if svc == "fs01" else ""), \
                mock.patch.object(r, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, listen, "")), \
                mock.patch.object(r, "wildcard_listeners", lambda: []), \
                mock.patch.object(r.socket, "create_connection", connect), \
                contextlib.redirect_stdout(buf):
            ok = r.self_test("redpot", [{"name": "FS01", "role": "windows-file-server", "ip": "10.0.0.50"},
                                        {"name": "WEB01", "role": "linux-web-hosting", "ip": "10.0.0.51"}], secs=0)
        r.A.dry_run = True
        out = ANSI.sub("", buf.getvalue())
        self.assertFalse(ok)
        self.assertRegex(out, r"✓  FS01 +10\.0\.0\.50 +running +✓ 135 139 445 3389 +✓")
        self.assertRegex(out, r"✗  WEB01 +10\.0\.0\.51 +not running +✗ missing 22 80 443 +✗ no answer on 22,80,443")
        self.assertIn(("10.0.0.51", 22), tried)
        self.assertNotIn("test from another host", out)
        self.assertNotIn("promiscuous", out)
        self.assertIn("self-test failed for WEB01", out)

    def test_sensor_decoy_connect_test_and_udp(self):
        """RC-6: a remote sensor's decoy is host-network too — the same connect test, from this host, for every TCP
        port; UDP-only ports (DC: 123, 137 bound 0.0.0.0 on the decoy interface) count as listening when bound."""
        import contextlib
        import io
        from unittest import mock
        r = _mod()
        r.A.dry_run = False
        role = "windows-domain-controller"
        tcp = sorted(r.ROLE_PORTS[role] - r.ROLE_UDP[role])
        ip_hex = "0A32A8C0"                                                   # 192.168.50.10
        tlisten = "".join(f"   0: {ip_hex}:{p:04X} 00000000:0000 0A\n" for p in tcp)
        ulisten = "".join(f"   0: {'00000000' if p == 137 else ip_hex}:{p:04X} 00000000:0000 07\n"
                          for p in sorted(r.ROLE_UDP[role]))
        tried = []

        def fake_run(cmd, **k):
            return subprocess.CompletedProcess(cmd, 0, ulisten if "/proc/net/udp" in cmd else tlisten, "")
        buf = io.StringIO()
        with mock.patch.object(r, "_decoy_container", lambda proj, svc: "cid" if (proj, svc) == ("redpot-sensor", "br-dc-01") else ""), \
                mock.patch.object(r, "run", fake_run), mock.patch.object(r, "wildcard_listeners", lambda: []), \
                mock.patch.object(r.socket, "create_connection", lambda addr, t: tried.append(addr) or mock.Mock()), \
                contextlib.redirect_stdout(buf):
            ok = r.self_test("redpot-sensor", [{"name": "BR-DC-01", "role": role, "ip": "192.168.50.10", "iface": "eth1"}],
                             secs=0)
        r.A.dry_run = True
        out = ANSI.sub("", buf.getvalue())
        self.assertTrue(ok, out)
        self.assertEqual(sorted(p for _, p in tried), tcp)
        self.assertEqual({a for a, _ in tried}, {"192.168.50.10"})
        for hint in ("macvlan", "promiscuous", "another host"):
            self.assertNotIn(hint, out)


class TestSensorFirewall(unittest.TestCase):
    """S-1 H1 / M3 on a remote sensor host, with RC-5's builder and rule evaluator: a scan of the decoy address
    shows exactly the role's ports; host SSH only via the manager link; IPv6 closed and ARP restricted on the decoy
    interface; the decoy (uid 10001) may open NO connection — it reports through the relay's Unix socket."""

    def setUp(self):
        self.r = _mod()
        self.old = os.environ.get("RPOT_TEST_IFACES")
        os.environ["RPOT_TEST_IFACES"] = "[]"                      # ttl_available(): no modprobe in a unit test
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()
        self.r.A.dry_run = True
        os.environ.pop("RPOT_TEST_IFACES", None) if self.old is None else os.environ.__setitem__("RPOT_TEST_IFACES", self.old)

    def _write(self, ifs, mgmt, decoy, single, ssh):
        r = self.r
        r.A.dry_run = False
        st = {"join": JOIN, "ifs": {i["name"]: i for i in ifs}, "mgmt": mgmt, "single": single, "allow": {},
              "ports": {"ui": 50000, "sensor": 50001, "ssh": ssh}, "move_ssh": single}
        self.assertTrue(r.write_firewall(self.tmp.name, st, [decoy]))
        return open(os.path.join(self.tmp.name, r.FIREWALL)).read()

    @staticmethod
    def _scan_ports(rin):
        scan = {int(t) for r_ in rin for t in re.split(r"[,\s]", " ".join(r_)) if t.isdigit() and 0 < int(t) < 65536}
        return scan | {1, 7, 22, 23, 1023, 3306, 5985, 8080, 49999, 50000, 50001, 65535}

    def test_decoy_on_another_interface(self):
        r = self.r
        role = "windows-domain-controller"
        txt = self._write(THREE[:2], "eth0", {"name": "BR-DC-01", "role": role, "ip": "192.168.50.10", "iface": "eth1"},
                          False, 22)
        rin = _rules(txt, "REDPOT-IN")
        scan = self._scan_ports(rin)
        want = r.ROLE_PORTS[role] - r.ROLE_UDP[role]
        self.assertEqual({p for p in scan if _verdict(rin, "eth1", "192.168.50.10", "tcp", p) == "open"}, want)
        self.assertLessEqual({p for p in scan if _verdict(rin, "eth1", "192.168.50.10", "udp", p) == "open"},
                             r.ROLE_PORTS[role])
        self.assertEqual(_verdict(rin, "eth1", "192.168.50.255", "udp", 137, bcast=True), "open")    # NBNS broadcast
        self.assertEqual(_verdict(rin, "eth1", "192.168.50.10", "udp", 68, sport=67), "open")         # DHCP renewals
        self.assertEqual(_verdict(rin, "eth0", "10.0.0.5", "tcp", 22), "open")                         # host SSH: link
        self.assertEqual(_verdict(rin, "eth1", "10.0.0.5", "tcp", 22), "closed")                       # weak host model
        self.assertEqual(_verdict(rin, "eth1", "192.168.50.10", "tcp", 22), "closed")
        self.assertEqual(_verdict(rin, "eth1", "192.168.50.10", "tcp", 4444, state="ESTABLISHED"), "open")
        rdk = _rules(txt, "REDPOT-DOCKER")                       # review F1: no forwarding for the decoy LAN
        self.assertEqual(_verdict(rdk, "eth1", "172.18.0.2", "tcp", 8740, oface="br-0a1b2c3d4e5f"), "closed")
        self.assertEqual(_verdict(rdk, "eth1", "10.0.0.7", "udp", 53, oface="eth0"), "closed")         # no routing
        self.assertEqual(_verdict(rdk, "eth0", "172.18.0.2", "tcp", 1234, oface="br-0a1b2c3d4e5f"), "closed")
        self.assertEqual(_verdict(rdk, "br-0a1b2c3d4e5f", "10.0.0.99", "tcp", 63462, oface="eth0"), "open")  # relay
        self.assertEqual(_verdict(rdk, "eth0", "172.18.0.2", "tcp", 40000, oface="br-0a1b2c3d4e5f",
                                  state="ESTABLISHED"), "open")                                # manager's replies
        self.assertNotIn("50000", txt)                                                         # no web UI / sensor API
        self.assertNotIn("50001", txt)
        r6 = _rules(txt, "REDPOT-IN6", "$IP6T")
        for proto, port in (("tcp", 445), ("tcp", 22), ("udp", 53)):
            self.assertEqual(_verdict(r6, "eth1", "fe80::1", proto, port), "closed")
        self.assertIn("  arp eth1", txt)
        self.assertNotIn("  arp eth0", txt)
        rout = _rules(txt, "REDPOT-OUT")
        u = 10001
        for dst, proto, port in (("10.0.0.99", "tcp", 63462), ("127.0.0.1", "tcp", 22), ("127.0.0.1", "tcp", 50000),
                                 ("10.0.0.1", "tcp", 445), ("1.1.1.1", "tcp", 443), ("8.8.8.8", "udp", 53)):
            self.assertEqual(_verdict(rout, None, dst, proto, port, uid=u, src="192.168.50.10"), "closed", (dst, port))
        self.assertEqual(_verdict(rout, None, "192.168.50.77", "tcp", 51515, uid=u, state="ESTABLISHED"), "open")
        self.assertEqual(_verdict(rout, None, "192.168.50.77", "udp", 40000, uid=u, src="192.168.50.10", sport=137,
                                  oface="eth1"), "open")                                       # NBNS answer
        self.assertEqual(_verdict(rout, None, "192.168.50.77", "udp", 40000, uid=u, src="192.168.50.10", sport=53,
                                  oface="eth1"), "closed")
        self.assertEqual(_verdict(rout, None, "10.0.0.77", "udp", 40000, uid=u, src="192.168.50.10", sport=137,
                                  oface="eth0"), "closed")                                     # F2: other interface
        self.assertEqual(_verdict(rout, None, "10.0.0.99", "tcp", 63462, uid=0), "open")      # relay / host itself
        self.assertEqual(_verdict(_rules(txt, "REDPOT-OUT6", "$IP6T"), None, "::1", "tcp", 22, uid=u), "closed")
        self.assertIn("-t mangle -A REDPOT-TTL -s 192.168.50.10 -j TTL", txt)

    def test_decoy_on_the_manager_link_follows_dhcp(self):
        r = self.r
        role = "windows-file-server"
        txt = self._write(ONE, "ens3", {"name": "BR-FS-01", "role": role, "ip": "203.0.113.20", "iface": "ens3"}, True, 52187)
        rin = _rules(txt, "REDPOT-IN")
        self.assertFalse([x for x in rin if "-d" in x], "rules must not pin today's DHCP lease")
        scan = self._scan_ports(rin)
        want = (r.ROLE_PORTS[role] - r.ROLE_UDP[role]) | {52187}                             # + the moved host SSH
        for ip in ("203.0.113.20", "203.0.113.77"):                                          # after a DHCP change too
            self.assertEqual({p for p in scan if _verdict(rin, "ens3", ip, "tcp", p) == "open"}, want, ip)
            self.assertEqual(_verdict(rin, "ens3", ip, "tcp", 22), "closed")
        r6 = _rules(txt, "REDPOT-IN6", "$IP6T")
        self.assertEqual(_verdict(r6, "ens3", "2001:db8::5", "tcp", 52187), "open")         # admin over IPv6 kept
        self.assertEqual(_verdict(r6, "ens3", "2001:db8::5", "tcp", 445), "closed")
        self.assertEqual(_verdict(r6, "ens3", "2001:db8::5", "tcp", 22), "closed")
        self.assertIn("-t mangle -A REDPOT-TTL -o ens3 -j TTL", txt)
        self.assertNotIn("--sport 137", txt)                                                 # FS role: no NBNS/udp
        rout = _rules(txt, "REDPOT-OUT")
        self.assertEqual(_verdict(rout, None, "10.0.0.99", "tcp", 63462, uid=10001), "closed")


class TestSensorCompose(unittest.TestCase):
    def test_host_mode_only(self):
        r = _mod()
        for follow, env, other in ((True, 'RPOT_SENSOR_IFACE: "eth1"', "RPOT_BIND_IP"),
                                   (False, 'RPOT_BIND_IP: "192.168.50.10"', "RPOT_SENSOR_IFACE")):
            t = r.sensor_compose_text("BR-FS-01", "windows-file-server", "192.168.50.10", "eth1", follow)
            for bad in ("macvlan", "mac_address", "ipv4_address", "parent:", "ipam", other):
                self.assertNotIn(bad, t)
            self.assertIn(env, t)
            # RC-18 F5 hardening, same as rpotctl host mode: root start, setpriv drop to 10001, no-new-privileges
            dec = t.split("  br-fs-01:\n", 1)[1].split("\nnetworks:", 1)[0]
            self.assertIn('    user: "0:0"', dec)
            self.assertIn('RPOT_PRIVDROP: "1"', dec)
            self.assertNotIn("RPOT_LOWPORTS", t)
            self.assertIn("    network_mode: host\n    cap_drop: [ALL]\n    cap_add: [NET_BIND_SERVICE, SETUID, SETGID, SETPCAP]\n"
                          '    security_opt: ["no-new-privileges:true"]', dec)
            self.assertNotIn("privileged", t)
            self.assertNotIn("seccomp", t)
            rel = t.split("  relay:\n", 1)[1].split("  br-fs-01:\n", 1)[0]          # relay: image user 10001, no caps
            self.assertNotIn("user:", rel)
            self.assertNotIn("PRIVDROP", rel)
            self.assertIn("cap_drop: [ALL]", rel)
            self.assertIn('security_opt: ["no-new-privileges:true"]', rel)
            self.assertIn("      - ./data:/var/lib/rpot\n      - relay-sock:/run/rpot", dec)
            self.assertIn("RPOT_RELAY_SOCKET: /run/rpot/relay.sock", t)
            self.assertIn("networks: [mgmt]", t)                                        # only the relay is on a bridge
            self.assertEqual(t.count("network_mode: host"), 1)
        for bad in (("BR FS", "192.168.50.10", "eth1"), ("BR-FS-01", "192.168.50.10\n  x: y", "eth1"),
                    ("BR-FS-01", "192.168.50.10", 'eth1"')):
            with self.assertRaises(SystemExit):
                r.sensor_compose_text(bad[0], "windows-file-server", bad[1], bad[2], True)


class TestUninstallDryRun(unittest.TestCase):
    """RC-6: `uninstall --dry-run` lists every artefact of a CE manager and a CE remote-sensor install and
    changes nothing."""

    def _fake_installs(self, root, r):
        man, sen = os.path.join(root, "manager"), os.path.join(root, "sensor")
        os.makedirs(os.path.join(sen, "conf"))
        os.makedirs(man)
        for d in (man, sen):
            open(os.path.join(d, "docker-compose.yml"), "w").write("services: {}\n")
        open(os.path.join(man, "rpot.json"), "w").write('{"version": 2}')
        decoys = [{"name": "DC01", "role": "windows-domain-controller", "ip": "10.0.0.5", "iface": "eth0"},
                  {"name": "FS01", "role": "windows-file-server", "ip": "192.168.50.10", "iface": "eth1"}]
        txt, _ = r.firewall_text("10.0.0.5", {}, {"ui": 50000, "sensor": 50001, "ssh": 50022}, True,
                                 r.ttl_targets(decoys), mgmt_if="eth0", decoys=decoys, out_guard=True)
        open(os.path.join(man, r.FIREWALL), "w").write(txt)
        open(os.path.join(man, "arp-sysctl.bak"), "w").write("/proc/sys/net/ipv4/conf/eth1/arp_ignore 0\n")
        open(os.path.join(man, r.STOPPED_FILE), "w").write("apache2.service\n")
        sd = [{"name": "BR-FS-01", "role": "windows-file-server", "ip": "172.16.5.10", "iface": "eth2"}]
        txt, _ = r.firewall_text("10.0.0.6", {}, {"ssh": 22}, False, r.ttl_targets(sd), mgmt_if="eth3", decoys=sd,
                                 out_guard=True)
        open(os.path.join(sen, r.FIREWALL), "w").write(txt)
        open(os.path.join(sen, "conf", "sensor.json"), "w").write("{}")
        json.dump(["ip", "route", "del", "10.0.0.99/32", "dev", "eth3"], open(os.path.join(sen, r.ROUTE_FILE), "w"))
        etc = os.path.join(root, "etc")
        os.makedirs(os.path.join(etc, "systemd"))
        os.makedirs(os.path.join(etc, "sshd_config.d"))
        for u in ("redpot", "redpot-sensor"):
            open(os.path.join(etc, "systemd", u + ".service"), "w").write("[Unit]\n")
        open(os.path.join(etc, "sshd_config.d", "00-redpot-port.conf"), "w").write("Port 50022\n")
        open(os.path.join(etc, "sshd_config.d", "50-cloud.conf" + r.SSH_DROPIN_BAK), "w").write("Port 22\n")
        open(os.path.join(etc, "sshd_config.d", "00-redpot-listen.conf"), "w").write("ListenAddress 10.0.0.5\n")
        open(os.path.join(etc, "motd"), "w").write("#!/bin/sh\n")
        return man, sen, etc

    def test_every_artefact_is_listed_and_nothing_changes(self):
        import contextlib
        import io
        from unittest import mock
        r = _mod()
        with tempfile.TemporaryDirectory() as root:
            man, sen, etc = self._fake_installs(root, r)
            before = sorted(os.path.relpath(os.path.join(a, f), root) for a, _, fs in os.walk(root) for f in fs)

            def no_run(cmd, **k):
                raise AssertionError(f"dry-run must not run {cmd}")
            buf = io.StringIO()
            with mock.patch.multiple(r, INSTALL_DIRS=(man, sen), UNIT_DIR=os.path.join(etc, "systemd"),
                                     MOTD=os.path.join(etc, "motd"), SSHD_MAIN=os.path.join(etc, "sshd_config"),
                                     SSHD_DIR=os.path.join(etc, "sshd_config.d"),
                                     PORT_CONF=os.path.join(etc, "sshd_config.d", "00-redpot-port.conf"),
                                     PIN_CONF=os.path.join(etc, "sshd_config.d", "00-redpot-listen.conf"), run=no_run), \
                    contextlib.redirect_stdout(buf):
                r.A.purge_image = True
                try:
                    r.uninstall()
                finally:
                    r.A.purge_image = False
            after = sorted(os.path.relpath(os.path.join(a, f), root) for a, _, fs in os.walk(root) for f in fs)
        out = ANSI.sub("", buf.getvalue())
        self.assertEqual(before, after)
        self.assertIn("[dry-run] nothing was changed", out)
        for want in (
                f"manager in {man}:", "service redpot stopped + disabled", "systemd/redpot.service deleted",
                "iptables chains REDPOT-IN, REDPOT-DOCKER, REDPOT-OUT, mangle REDPOT-TTL (TTL 128); "
                "ip6tables chains REDPOT-IN6, REDPOT-OUT6",
                f"ARP sysctls arp_ignore / arp_announce of eth0, eth1 restored from {man}/arp-sysctl.bak",
                f"Docker compose project redpot ({man}/docker-compose.yml): containers, networks, volumes",
                "re-enabled: apache2.service", f"directory {man} (configuration, database, logs, baits)",
                f"remote sensor in {sen}:", "service redpot-sensor stopped + disabled",
                "ip6tables chains REDPOT-IN6, REDPOT-OUT6", f"ARP sysctls arp_ignore / arp_announce of eth2 restored",
                "pinned route to the manager: ip route del 10.0.0.99/32 dev eth3",
                f"Docker compose project redpot-sensor ({sen}/docker-compose.yml)", f"directory {sen}",
                "host SSH back to port 22 (from 50022)", "50-cloud.conf" + r.SSH_DROPIN_BAK,
                "host SSH listens on every address again", f"login banner {etc}/motd", f"Docker image {r.IMAGE}"):
            self.assertIn(want, out)
        sensor_part = out.split(f"remote sensor in {sen}:")[1]
        self.assertIn("iptables chains REDPOT-IN, REDPOT-DOCKER, REDPOT-OUT, mangle REDPOT-TTL", sensor_part)

    def test_half_finished_and_keep_data(self):
        import contextlib
        import io
        from unittest import mock
        r = _mod()
        with tempfile.TemporaryDirectory() as root:
            man, sen, etc = self._fake_installs(root, r)
            os.remove(os.path.join(sen, "docker-compose.yml"))              # enrolled, never finished
            buf = io.StringIO()
            with mock.patch.multiple(r, INSTALL_DIRS=(man, sen), UNIT_DIR=os.path.join(etc, "systemd"),
                                     MOTD=os.path.join(etc, "nomotd"), SSHD_MAIN=os.path.join(etc, "sshd_config"),
                                     SSHD_DIR=os.path.join(etc, "none"), PORT_CONF=os.path.join(etc, "none", "x"),
                                     PIN_CONF=os.path.join(etc, "none", "y")), contextlib.redirect_stdout(buf):
                r.A.keep_data = True
                try:
                    r.uninstall()
                finally:
                    r.A.keep_data = False
            self.assertTrue(os.path.isdir(sen))
        out = ANSI.sub("", buf.getvalue())
        self.assertIn(f"half-finished install in {sen} (enrollment never completed): the directory, the pinned route", out)
        self.assertIn(f"directory {man} — KEPT (--keep-data)", out)
        self.assertIn(f"({man}/docker-compose.yml): containers, networks\n", out)
        for absent in ("host SSH back to port 22", "listens on every address again", "login banner"):
            self.assertNotIn(absent, out)


def run_add(inputs, ifaces, *args, mode="add-decoy", existing=None, state=None, busy=None, install=True, slots=None,
            cfg_extra=None, no_state=False):
    """add-decoy / remove-decoy against a fake existing CE manager install (dry-run: nothing is changed).
    slots: RPOT_TEST_SLOTS (the console's `rpotctl slots` answer); default = only the local decoys."""
    existing = existing if existing is not None else [
        {"name": "FS01", "role": "windows-file-server", "ip": "10.0.0.5", "iface": "eth0"}]
    with tempfile.TemporaryDirectory() as d:
        if install:
            cfg = {"version": 2, "console": {"mgmt_ip": "10.0.0.5", "ui_port": 50000, "sensor_port": 50001, "public_ip": None},
                   "network": {"mode": "host"}, "sensors": existing, "tokens": {}}
            cfg.update(cfg_extra or {})
            json.dump(cfg, open(os.path.join(d, "rpot.json"), "w"))
            open(os.path.join(d, "docker-compose.yml"), "w").write("services: {}\n")
            if not no_state:
                json.dump(state or {"mgmt": "eth0", "mgmt_ip": "10.0.0.5", "ports": {"ui": 50000, "sensor": 50001, "ssh": 50022},
                                    "move_ssh": True, "pin_ssh": False, "public_ip": None,
                                    "allow": {"ui": ["0.0.0.0/0"], "sensor": ["0.0.0.0/0"], "ssh": ["0.0.0.0/0"]}},
                          open(os.path.join(d, "installer.json"), "w"))
        env = dict(os.environ, RPOT_TEST_IFACES=json.dumps(ifaces), RPOT_TEST_SSH_IP="10.0.0.5",
                   SSH_CONNECTION="10.99.0.7 50000 10.0.0.5 22")
        n = len(existing)
        env["RPOT_TEST_SLOTS"] = json.dumps(slots or {"max": 3, "used": n, "local": n, "remote": 0, "pending": 0})
        if busy:
            env["RPOT_TEST_BUSY"] = busy
        p = subprocess.run([sys.executable, INSTALLER, mode, "--dry-run", "--dir", d, *args],
                           input="\n".join(inputs) + "\n", capture_output=True, text=True, env=env, timeout=60)
        left = set(os.listdir(d))
        out = ANSI.sub("", p.stdout + p.stderr)
        if install:                                  # --dry-run never writes into the install directory
            assert left == {"docker-compose.yml", "rpot.json"} | (set() if no_state else {"installer.json"}), left
        return p.returncode, out


TWO = [{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "state": "UP", "gw": "10.0.0.1"},
       {"name": "eth1", "ip": "192.168.50.10", "prefix": 24, "state": "UP"}]


class TestAddDecoy(unittest.TestCase):
    """Owner scenario: manager + FS01 on the management NIC (SSH moved); later a second NIC gets its own decoy —
    without reinstalling (which would regenerate persona + baits and invalidate every planted token)."""

    def test_second_nic_gets_a_decoy_on_its_own_address(self):
        """Also S-1 M4: a Windows decoy on NIC2 gets the TTL 128 rule and pins SSH; FS01 keeps its rules."""
        rc, out = run_add(["", "windows-domain-controller", "", ""], TWO)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("Not offered (one decoy per interface): eth0 → FS01", out)
        self.assertRegex(out, r"2\) eth1 .*\(free\)")
        self.assertIn("DC01 answers on eth1's own address 192.168.50.10", out)
        self.assertIn("host SSH listens only on 10.0.0.5 (port 50022)", out)
        self.assertIn("ctl add-sensor -d /d --image rpot:", out)
        self.assertIn("--sensor DC01=windows-domain-controller@192.168.50.10%eth1", out)
        for gone in ("--decoy-net", "--own-ip", "macvlan", "Address on"):
            self.assertNotIn(gone, out)
        self.assertIn("would pin host SSH to 10.0.0.5:50022", out)
        self.assertIn("TTL 128 (like Windows) for traffic from 10.0.0.5, 192.168.50.10", out)
        self.assertIn("-t mangle -A REDPOT-TTL -s 192.168.50.10 -j TTL --ttl-set 128", out)
        self.assertIn("-t mangle -A REDPOT-TTL -s 10.0.0.5 -j TTL --ttl-set 128", out)
        self.assertIn("$IPT -A REDPOT-IN -i eth1 -d 192.168.50.10 -p tcp -m multiport --dports", out)
        self.assertIn("$IPT -A REDPOT-IN -i eth0 -d 10.0.0.5 -p tcp -m multiport --dports 135,139,445,3389 -j RETURN", out)
        self.assertIn("$IPT -A REDPOT-IN -i eth0 -p tcp -d 10.0.0.5 --dport 50022 -j RETURN", out)
        self.assertIn("systemctl reload redpot", out)
        self.assertIn("docker compose -p redpot restart console fs01", out)
        self.assertNotIn("would move host SSH", out)                     # already moved by the first install
        self.assertNotIn("ctl init", out)                                # persona + baits are NOT regenerated

    def test_used_interface_is_never_offered(self):
        rc, out = run_add([], TWO, "--yes", "--decoy-if", "eth0", "--roles", "linux-web-hosting")
        self.assertNotEqual(rc, 0)
        self.assertIn("eth0 already holds FS01 — one decoy per interface", out)
        rc, out = run_add(["1", "eth0", "2", "linux-web-hosting", "", ""], TWO)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("'1' is not one of the choices. Type 2", out)
        self.assertIn("'eth0' is not one of the choices", out)
        self.assertNotRegex(out, r"1\) eth0")
        self.assertIn("--sensor WEB01=linux-web-hosting@192.168.50.10%eth1", out)

    def test_every_interface_used(self):
        existing = [{"name": "FS01", "role": "windows-file-server", "ip": "10.0.0.5", "iface": "eth0"},
                    {"name": "DC01", "role": "windows-domain-controller", "ip": "192.168.50.10", "iface": "eth1"}]
        rc, out = run_add([], TWO, "--yes", "--roles", "linux-web-hosting", existing=existing)
        self.assertNotEqual(rc, 0)
        self.assertIn("every usable interface already holds a decoy", out)
        self.assertNotIn("ctl add-sensor", out)

    def test_limit_reached_dies_with_the_message(self):
        sys.path.insert(0, REPO)
        from rpot.common.edition import limit_message
        rc, out = run_add([], THREE, "--yes", "--roles", "linux-web-hosting",
                          slots={"max": 3, "used": 3, "local": 1, "remote": 1, "pending": 1})
        self.assertNotEqual(rc, 0)
        self.assertIn(limit_message(3), " ".join(out.split()))
        self.assertNotIn("Interface for the NEW decoy", out)
        self.assertNotIn("ctl add-sensor", out)

    def test_remote_sensors_and_pending_joins_count(self):
        rc, out = run_add([], THREE, "--yes", "--roles", "linux-web-hosting",
                          slots={"max": 3, "used": 2, "local": 1, "remote": 0, "pending": 1})
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("Decoy limit: 2 of 3 used (local 1 · remote 0 · pending joins 1)", out)
        self.assertIn("decoys after this: 3 of 3", out)

    def test_unattended_flags_and_one_role_only(self):
        rc, out = run_add([], TWO, "--yes", "--decoy-if", "eth1", "--roles", "linux-web-hosting", "--names", "BR-WEB-01")
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("--sensor BR-WEB-01=linux-web-hosting@192.168.50.10%eth1", out)
        self.assertIn("would pin host SSH to 10.0.0.5:50022", out)
        rc, out = run_add([], TWO, "--yes", "--decoy-if", "eth1", "--roles", "linux-web-hosting,ftp-backup-server")
        self.assertNotEqual(rc, 0)
        self.assertIn("exactly ONE decoy", out)
        rc, out = run_add([], TWO, "--yes", "--decoy-if", "eth1", "--roles", "linux-web-hosting", "--decoy-ips", "1.2.3.4")
        self.assertEqual(rc, 2)                                    # removed flag: argparse refuses it

    @pytest.mark.slow
    def test_decoy_on_management_moves_ssh_and_needs_allowlists(self):
        """S-1 H2 for add-decoy: joining the management address re-asks open admin allowlists."""
        state = {"mgmt": "eth0", "mgmt_ip": "10.0.0.5", "ports": {"ui": 50000, "sensor": 50001, "ssh": 22},
                 "move_ssh": False, "pin_ssh": True, "allow": {}}
        existing = [{"name": "FS01", "role": "windows-file-server", "ip": "192.168.50.10", "iface": "eth1"}]
        rc, out = run_add([], TWO, "--yes", "--decoy-if", "eth0", "--roles", "linux-web-hosting",
                          existing=existing, state=state)
        self.assertNotEqual(rc, 0)
        self.assertIn("pass --allow-ui and --allow-sensor and --allow-ssh", out)
        rc, out = run_add([], TWO, "--yes", "--decoy-if", "eth0", "--roles", "linux-web-hosting", "--allow-ui",
                          "10.8.0.0/24", "--allow-sensor", "10.8.0.0/24", "--allow-ssh", "10.8.0.0/24",
                          existing=existing, state=state)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertRegex(out, r"host SSH MOVES to port \d{5}")
        self.assertIn("would move host SSH", out)
        self.assertIn("--sensor WEB01=linux-web-hosting@10.0.0.5%eth0", out)
        self.assertIn("--ctorigdstport 50000 -s 10.8.0.0/24 -j RETURN", out)
        rc, out = run_add(["1", "linux-web-hosting", "", "", "", "", ""], TWO, existing=existing, state=state)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("Web UI may be opened from [10.99.0.7/32]", out)
        self.assertIn("Host SSH may be used from [10.99.0.7/32]", out)
        self.assertIn("web UI from 10.99.0.7/32 · sensor API from 10.99.0.7/32 · SSH from 10.99.0.7/32", out)
        self.assertNotIn("another address", out)
        rc, out = run_add([], TWO, "--yes", "--no-ssh-move", "--decoy-if", "eth0", "--roles", "linux-web-hosting",
                          existing=existing, state=state)
        self.assertNotEqual(rc, 0)
        self.assertIn("use another interface or drop --no-ssh-move", out)

    def test_running_decoy_and_admin_ports_are_not_foreign_services(self):
        """The audit must not offer to stop the manager's own (docker-proxy / moved sshd) ports."""
        existing = [{"name": "FS01", "role": "windows-file-server", "ip": "192.168.50.10", "iface": "eth1"}]
        rc, out = run_add(["1", "linux-web-hosting", "", "", "", "", "", ""], TWO, existing=existing,
                          busy="50000/tcp=docker-proxy,50022/tcp=ssh.service,3306/tcp=mysql.service")
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("3306/tcp  service mysql.service", out)
        self.assertNotIn("50022/tcp", out)
        self.assertNotIn("ssh.service", out)
        self.assertIn("will stop + disable: mysql.service", out)

    @pytest.mark.slow
    def test_no_install_and_old_installs_refused(self):
        rc, out = run_add([], TWO, "--yes", install=False)
        self.assertNotEqual(rc, 0)
        self.assertIn("no ReD-Pot manager found", out)
        rc, out = run_add([], TWO, "--yes", cfg_extra={"version": 1})
        self.assertNotEqual(rc, 0)
        self.assertIn("supports fresh installs only", out)
        rc, out = run_add([], TWO, "--yes", no_state=True)
        self.assertNotEqual(rc, 0)
        self.assertIn("installer.json is missing", out)
        rc, out = run_add([], TWO, "--yes", cfg_extra={"network": {"mode": "bridge"}})
        self.assertNotEqual(rc, 0)
        self.assertIn("Docker-bridge lab", out)

    def test_remove_decoy_keeps_the_others(self):
        """S-1 M4: removing WEB01 (eth2) keeps FS01/DC01's TTL rules, decoy policy and the SSH pin rules."""
        existing = [{"name": "FS01", "role": "windows-file-server", "ip": "10.0.0.5", "iface": "eth0"},
                    {"name": "DC01", "role": "windows-domain-controller", "ip": "192.168.50.10", "iface": "eth1"},
                    {"name": "WEB01", "role": "linux-web-hosting", "ip": "172.16.5.10", "iface": "eth2"}]
        state = {"mgmt": "eth0", "mgmt_ip": "10.0.0.5", "ports": {"ui": 50000, "sensor": 50001, "ssh": 50022},
                 "move_ssh": True, "pin_ssh": True, "allow": {}}
        rc, out = run_add([], THREE, "WEB01", "--yes", mode="remove-decoy", existing=existing, state=state)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("ctl remove-sensor -d /d --image", out)
        self.assertIn("--name WEB01", out)
        self.assertIn("docker volume rm redpot_web01-data", out)
        self.assertIn("TTL 128 for 10.0.0.5, 192.168.50.10)", out)
        self.assertIn("$IPT -A REDPOT-IN -i eth1 -d 192.168.50.10 -p tcp", out)
        self.assertIn("$IPT -A REDPOT-IN -i eth0 -p tcp -d 10.0.0.5 --dport 50022 -j RETURN", out)
        self.assertNotIn("-i eth2", out)
        self.assertNotIn("rpotctl slots", out)                   # removing never needs the slot check
        rc, out = run_add([], THREE, "NOPE", "--yes", mode="remove-decoy", existing=existing, state=state)
        self.assertNotEqual(rc, 0)
        self.assertIn("no local decoy named NOPE (decoys: FS01, DC01, WEB01)", out)

    def test_removing_the_last_decoy_removes_the_policy(self):
        rc, out = run_add([], TWO, "FS01", "--yes", mode="remove-decoy",
                          state={"mgmt": "eth0", "mgmt_ip": "10.0.0.5", "ports": {"ui": 50000, "sensor": 50001, "ssh": 50022},
                                 "move_ssh": True, "pin_ssh": False, "allow": {}})
        self.assertEqual(rc, 0, out[-2000:])
        self.assertNotIn("would write", out)
        self.assertIn("host SSH stays on port 50022", out)


class TestRpotctlAddSensor(unittest.TestCase):
    """add-decoy runs `rpotctl add-sensor` in the image: the running decoys keep their key and compose entry;
    CE host mode: the new decoy takes a free interface and that interface's own IP."""

    @pytest.mark.slow
    def test_add_and_remove_keep_the_running_decoys(self):
        ctl = os.path.join(REPO, "rpotctl.py")

        def c(*a):
            p = subprocess.run([sys.executable, ctl, *a], capture_output=True, text=True, timeout=180,
                               env=dict(os.environ, RPOT_INSTALLER="1"))
            self.assertEqual(p.returncode, 0, p.stdout[-500:] + p.stderr[-1500:])
            return p.stdout
        with tempfile.TemporaryDirectory() as d:
            c("init", "-d", d, "--domain", "acme.local", "--net-mode", "host", "--mgmt-ip", "10.0.0.5",
              "--sensor", "FS01=windows-file-server@10.0.0.5%eth0", "--sensor", "WEB01=linux-web-hosting@10.0.5.60%eth2")
            c("compose", "-d", d, "--ui-bind", "10.0.0.5")
            before = open(os.path.join(d, "docker-compose.yml")).read()
            key = json.load(open(os.path.join(d, "sensors", "FS01", "sensor.json")))["manager"]["key"]
            out = c("add-sensor", "-d", d, "--sensor", "DC01=windows-domain-controller@192.168.50.10%eth1")
            self.assertIn("sensor DC01 (Windows Domain Controller) 192.168.50.10 on eth1", out)
            self.assertRegex(out, r"existing honeytokens")                  # token stability is reported
            after = open(os.path.join(d, "docker-compose.yml")).read()
            self.assertIn(before.split("networks:\n  mgmt:")[0].split("  web01:")[0], after)   # running entries unchanged
            self.assertIn("RPOT_BIND_IP: \"192.168.50.10\"", after)
            self.assertEqual(json.load(open(os.path.join(d, "sensors", "FS01", "sensor.json")))["manager"]["key"], key)
            cfg = json.load(open(os.path.join(d, "rpot.json")))
            self.assertEqual([x["name"] for x in cfg["sensors"]], ["FS01", "WEB01", "DC01"])
            self.assertTrue(os.path.isdir(os.path.join(d, "baits", "DC01")))
            c("remove-sensor", "-d", d, "--name", "web01")
            for bad in ("FS01=windows-file-server@10.0.6.70%eth3",           # duplicate name
                        "FS02=windows-file-server@10.0.6.70%eth0",           # interface already has a decoy
                        "FS02=windows-file-server@10.0.0.5%eth3"):          # address already used
                p = subprocess.run([sys.executable, ctl, "add-sensor", "-d", d, "--sensor", bad],
                                   capture_output=True, text=True, timeout=180)
                self.assertNotEqual(p.returncode, 0, bad)
            c("remove-sensor", "-d", d, "--name", "dc01")
            c("add-sensor", "-d", d, "--sensor", "WEB01=linux-web-hosting@10.0.5.60%eth2")
            self.assertEqual(open(os.path.join(d, "docker-compose.yml")).read(), before)
            self.assertFalse(os.path.isdir(os.path.join(d, "sensors", "DC01")))
