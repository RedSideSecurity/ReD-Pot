"""CE 1.0.0 rpotctl (design T3: D-2 host/bridge modes, D-4 alerts config, D-6 local decoy cap, rpot.json v2).
Every acceptance criterion is checked through the real CLI (subprocess), the way the installer calls it."""
import json
import os
import re
import subprocess
import sys
import tempfile
import pytest
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from rpot.common.edition import MAX_DECOYS, limit_message  # noqa: E402

CTL = os.path.join(REPO, "rpotctl.py")
REFUSED = "CE 1.0 supports fresh installs only"
HOST3 = ["--net-mode", "host", "--mgmt-ip", "10.0.0.5",
         "--sensor", "ARB-FS01=windows-file-server@10.0.0.5%eth0",
         "--sensor", "ARB-WEB01=linux-web-hosting@10.0.5.7%eth1",
         "--sensor", "ARB-DC01=windows-domain-controller@192.168.50.10%ens19"]


def ctl(*args):
    return subprocess.run([sys.executable, CTL, *args], capture_output=True, text=True, timeout=120,
                          env=dict(os.environ, RPOT_INSTALLER="1"), stdin=subprocess.DEVNULL)


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def init(self, *extra, ok=True):
        p = ctl("init", "-d", self.d, "--force", "--domain", "corp.araratbank.am", *extra)
        if ok:
            self.assertEqual(p.returncode, 0, p.stdout[-500:] + p.stderr[-1500:])
        return p

    def ok(self, *args):
        p = ctl(*args)
        self.assertEqual(p.returncode, 0, p.stdout[-500:] + p.stderr[-1500:])
        return p

    def cfg(self):
        with open(os.path.join(self.d, "rpot.json")) as f:
            return json.load(f)

    def put_cfg(self, cfg):
        with open(os.path.join(self.d, "rpot.json"), "w") as f:
            json.dump(cfg, f)

    def compose(self):
        self.ok("compose", "-d", self.d)
        with open(os.path.join(self.d, "docker-compose.yml")) as f:
            return f.read()

    def assertRefused(self, p, text):
        self.assertNotEqual(p.returncode, 0, p.stdout[-500:])
        self.assertIn(text, p.stderr)


def services(yml):
    """{service: its YAML block} of a generated compose file."""
    body = yml.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    return dict(re.findall(r"(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", body + "\n"))


class TestHostModeTopology(Base):
    """AC: host mode rejects a duplicate interface or IP and a missing interface."""

    @pytest.mark.slow
    def test_three_decoys_on_three_interfaces(self):
        self.init(*HOST3)
        c = self.cfg()
        self.assertEqual(c["network"], {"mode": "host", "console_ip": None})
        self.assertEqual([(s["name"], s["ip"], s["iface"]) for s in c["sensors"]],
                         [("ARB-FS01", "10.0.0.5", "eth0"), ("ARB-WEB01", "10.0.5.7", "eth1"),
                          ("ARB-DC01", "192.168.50.10", "ens19")])
        for s in c["sensors"]:
            self.assertEqual(set(s), {"name", "role", "ip", "iface", "key_sha256"})
        with open(os.path.join(self.d, "sensors", "ARB-WEB01", "sensor.json")) as f:
            self.assertEqual(json.load(f)["manager"]["url"], "https://10.0.0.5:8741")   # via the mgmt IP

    def test_duplicate_interface_refused(self):
        p = self.init("--net-mode", "host", "--sensor", "FS01=windows-file-server@10.0.0.5%eth0",
                      "--sensor", "WEB01=linux-web-hosting@10.0.0.6%eth0", ok=False)
        self.assertRefused(p, "interface eth0 already has a decoy")
        self.assertFalse(os.path.exists(os.path.join(self.d, "rpot.json")))

    def test_duplicate_ip_refused(self):
        p = self.init("--net-mode", "host", "--sensor", "FS01=windows-file-server@10.0.0.5%eth0",
                      "--sensor", "WEB01=linux-web-hosting@10.0.0.5%eth1", ok=False)
        self.assertRefused(p, "duplicate sensor IP")

    def test_missing_interface_refused(self):
        for spec in ("FS01=windows-file-server@10.0.0.5", "FS01=windows-file-server@10.0.0.5%"):
            p = self.init("--net-mode", "host", "--sensor", spec, ok=False)
            self.assertRefused(p, "host mode needs the decoy's interface")

    @pytest.mark.slow
    def test_bad_values_refused(self):
        for spec, why in (("FS01=windows-file-server%eth0", "invalid IPv4"),
                          ("FS01=windows-file-server@0.0.0.0%eth0", "cannot be a decoy address"),
                          ("FS01=windows-file-server@127.0.0.1%eth0", "cannot be a decoy address"),
                          ("FS01=windows-file-server@10.0.0.5%eth\"0", "invalid interface name"),
                          ("FS01=windows-file-server@10.0.0.5%-eth0", "invalid interface name"),
                          ("FS01=windows-file-server@10.0.0.5%averyveryverylongif", "invalid interface name"),
                          ("FS01=nope@10.0.0.5%eth0", "unknown role"),
                          ("F_S=windows-file-server@10.0.0.5%eth0", "invalid host name")):
            p = self.init("--net-mode", "host", "--sensor", spec, ok=False)
            self.assertRefused(p, why)

    def test_vlan_and_wifi_interface_names(self):
        self.init("--net-mode", "host", "--sensor", "FS01=windows-file-server@10.0.0.5%eth0.20",
                  "--sensor", "WEB01=linux-web-hosting@10.0.1.5%wlp2s0")

    @pytest.mark.slow
    def test_add_sensor_needs_free_interface(self):
        self.init("--net-mode", "host", "--mgmt-ip", "10.0.0.5", "--sensor", "FS01=windows-file-server@10.0.0.5%eth0")
        self.assertRefused(ctl("add-sensor", "-d", self.d, "--sensor", "WEB01=linux-web-hosting@10.0.0.9%eth0"),
                           "interface eth0 already has a decoy")
        self.assertRefused(ctl("add-sensor", "-d", self.d, "--sensor", "WEB01=linux-web-hosting@10.0.0.5%eth1"),
                           "duplicate sensor IP")
        self.assertRefused(ctl("add-sensor", "-d", self.d, "--sensor", "WEB01=linux-web-hosting@10.0.0.9"),
                           "host mode needs the decoy's interface")
        self.assertEqual(len(self.cfg()["sensors"]), 1)                       # nothing written on refusal
        self.ok("add-sensor", "-d", self.d, "--sensor", "WEB01=linux-web-hosting@10.0.1.9%eth1")
        self.assertEqual(self.cfg()["sensors"][1]["iface"], "eth1")

    @pytest.mark.slow
    def test_removed_flags_and_modes(self):
        for extra in (["--net-mode", "macvlan"], ["--decoy-net", "eth1=10.0.0.0/24"], ["--own-ip", "eth1=10.0.0.5"],
                      ["--public-url", "http://x"], ["--gateway", "10.0.0.1"], ["--company", "X"]):
            p = self.init(*extra, ok=False)
            self.assertEqual(p.returncode, 2, extra)                         # argparse: unknown argument
        self.init()
        for extra in (["--macvlan", "eth0"], ["--host-network"], ["--gateway", "10.0.0.1"]):
            self.assertEqual(ctl("compose", "-d", self.d, *extra).returncode, 2, extra)
        for extra in (["--decoy-net", "eth1=10.0.0.0/24"], ["--own-ip", "eth1=10.0.0.5"]):
            self.assertEqual(ctl("add-sensor", "-d", self.d, "--sensor", "X1=linux-web-hosting", *extra).returncode, 2)


class TestBridgeLab(Base):
    def test_lab_ips_distinct_and_auto_filled(self):
        self.init("--subnet", "10.9.0.0/24", "--sensor", "A=windows-file-server",
                  "--sensor", "B=linux-web-hosting@10.9.0.21", "--sensor", "C=ftp-backup-server")
        c = self.cfg()
        self.assertEqual(c["network"], {"mode": "bridge", "subnet": "10.9.0.0/24", "console_ip": "10.9.0.10"})
        self.assertEqual([s["ip"] for s in c["sensors"]], ["10.9.0.22", "10.9.0.21", "10.9.0.23"])
        self.assertTrue(all("iface" not in s for s in c["sensors"]))
        with open(os.path.join(self.d, "sensors", "A", "sensor.json")) as f:
            self.assertEqual(json.load(f)["manager"]["url"], "https://console:8741")

    def test_lab_refusals(self):
        for extra, why in ((["--sensor", "A=windows-file-server@10.9.0.30", "--sensor", "B=linux-web-hosting@10.9.0.30"],
                            "duplicate sensor IP"),
                           (["--sensor", "A=windows-file-server@10.9.0.10"], "manager's address on the lab network"),
                           (["--sensor", "A=windows-file-server@10.8.0.30"], "not inside the lab subnet"),
                           (["--sensor", "A=windows-file-server@10.9.0.30%eth0"], "only for --net-mode host"),
                           (["--console-ip", "10.9.0.2", "--net-mode", "host"], "only for --net-mode bridge")):
            self.assertRefused(self.init("--subnet", "10.9.0.0/24", *extra, ok=False), why)

    def test_lab_compose(self):
        self.init("--sensor", "A=windows-file-server", "--sensor", "B=linux-web-hosting")
        y = self.compose()
        sv = services(y)
        for n in ("a", "b"):
            self.assertIn("      decoy:\n        ipv4_address: 172.30.0.", sv[n])
            self.assertIn("no-new-privileges:true", sv[n])
            self.assertNotIn("network_mode", sv[n])
            self.assertNotIn("RPOT_BIND_IP", sv[n])
            self.assertNotIn("user:", sv[n])                 # bridge decoys stay uid 10001 from the image (USER rpot)
            self.assertNotIn("RPOT_PRIVDROP", sv[n])
            self.assertIn("    cap_drop: [ALL]\n", sv[n])
            self.assertNotIn("cap_add", sv[n])
        self.assertIn("  decoy:\n    internal: true", y)
        self.assertNotRegex(y, r"macvlan|mac_address")


class TestHostCompose(Base):
    """AC: no mac_address/macvlan in generated compose; every host-mode decoy has RPOT_BIND_IP."""

    @pytest.mark.slow
    def test_every_decoy_on_host_network_bound_to_its_ip(self):
        self.init(*HOST3)
        y = self.compose()
        self.assertNotRegex(y.lower(), r"macvlan|mac_address|parent:")
        sv = services(y)
        self.assertEqual(sorted(sv), ["arb-dc01", "arb-fs01", "arb-web01", "console"])
        for s in self.cfg()["sensors"]:
            b = sv[s["name"].lower()]
            self.assertIn("    network_mode: host\n", b)
            self.assertIn(f'      RPOT_BIND_IP: "{s["ip"]}"\n', b)
            # F5 (RC-18): root start + setpriv drop to 10001 (entrypoint RPOT_PRIVDROP), NNP on, ambient NBS
            self.assertIn('      RPOT_PRIVDROP: "1"\n', b)
            self.assertNotIn("RPOT_LOWPORTS", b)
            self.assertIn('    hostname: ' + s["name"].lower() + '\n    user: "0:0"\n', b)
            self.assertIn("    cap_drop: [ALL]\n    cap_add: [NET_BIND_SERVICE, SETUID, SETGID, SETPCAP]\n", b)
            self.assertIn("    read_only: true\n", b)
            self.assertNotIn("networks:", b)
            self.assertIn('    security_opt: ["no-new-privileges:true"]\n', b)
            self.assertNotIn("seccomp", b)               # F5(iii): Docker's default seccomp profile stays
            self.assertNotIn("privileged", b)
        con = sv["console"]
        self.assertIn("      mgmt:\n        aliases: [console]\n      front: {}\n", con)
        self.assertIn('      - "10.0.0.5:8740:8740"', con)
        self.assertIn("no-new-privileges:true", con)
        self.assertNotIn("user:", con)
        self.assertNotIn("cap_add", con)
        self.assertNotIn("seccomp", y)
        nets = y.split("\nnetworks:\n", 1)[1]
        self.assertIn("  mgmt:\n    internal: true", nets)
        self.assertIn("  front: {}", nets)
        self.assertNotIn("  decoy:", nets)

    def test_hand_edited_values_cannot_reach_the_yaml(self):
        self.init(*HOST3[:6])
        good = self.cfg()
        c = json.loads(json.dumps(good))
        c["sensors"][0]["ip"] = '10.0.0.5"\n  evil:\n    image: x'
        self.put_cfg(c)
        self.assertRefused(ctl("compose", "-d", self.d), "invalid IPv4 address")   # one real CLI refusal ...
        import rpotctl                                       # ... and the same check on every field in-process
        for field, value in (("iface", 'eth0"x'), ("ip", 7), ("ip", "10.0.0.05"), ("name", "../../x"),
                             ("iface", None), ("role", "x\n  evil:")):
            c = json.loads(json.dumps(good))
            c["sensors"][0][field] = value
            with self.assertRaises(ValueError, msg=(field, value)):
                rpotctl.compose_text(c)
        with self.assertRaises(ValueError):
            rpotctl.compose_text(good, ui_bind='0.0.0.0"\n  evil:')
        self.assertIn("arb-fs01:", rpotctl.compose_text(good))


class TestDecoyCap(Base):
    """AC: a 4th sensor in init, add-sensor or compose fails with limit_message."""
    FOURTH = "ARB-DNS01=linux-dns-server@10.0.9.9%eth3"

    def test_init_refuses_a_fourth(self):
        p = self.init(*HOST3, "--sensor", self.FOURTH, ok=False)
        self.assertRefused(p, limit_message(4))
        self.assertFalse(os.path.exists(os.path.join(self.d, "rpot.json")))
        p = self.init("--sensor", "A=windows-file-server", "--sensor", "B=linux-web-hosting",
                      "--sensor", "C=ftp-backup-server", "--sensor", "D=linux-dns-server", ok=False)    # bridge lab too
        self.assertRefused(p, limit_message(4))

    @pytest.mark.slow
    def test_add_sensor_refuses_a_fourth(self):
        self.init(*HOST3)
        before = self.cfg()
        self.assertRefused(ctl("add-sensor", "-d", self.d, "--sensor", self.FOURTH), limit_message(MAX_DECOYS))
        self.assertEqual(self.cfg(), before)
        self.ok("remove-sensor", "-d", self.d, "--name", "arb-web01")              # remove-decoy frees the slot
        self.ok("add-sensor", "-d", self.d, "--sensor", self.FOURTH)

    @pytest.mark.slow
    def test_compose_refuses_a_hand_edited_fourth(self):
        self.init(*HOST3)
        c = self.cfg()
        c["sensors"].append({"name": "ARB-DNS01", "role": "linux-dns-server", "ip": "10.0.9.9", "iface": "eth3"})
        self.put_cfg(c)
        self.assertRefused(ctl("compose", "-d", self.d), limit_message(4))
        self.assertFalse(os.path.exists(os.path.join(self.d, "docker-compose.yml")))
        self.assertRefused(ctl("add-sensor", "-d", self.d, "--sensor", "X1=linux-web-hosting@10.0.8.8%eth4"),
                           limit_message(4))
        import rpotctl
        from rpot.common.edition import LimitError
        with self.assertRaises(LimitError):
            rpotctl.compose_text(c)


class TestAlertsConfig(Base):
    """AC: alerts == {"min_level": 3}; no outbound-alerting keys; wall-url uses console.url."""

    @pytest.mark.slow
    def test_alerts_block(self):
        self.init(*HOST3, "--public-ip", "203.0.113.9")
        c = self.cfg()
        self.assertEqual(c["alerts"], {"min_level": 3})
        raw = json.dumps(c).lower()
        for bad in ("telegram", "webhook", "public_url", "decoy_nets", "hostnet", "mac_address"):
            self.assertNotIn(f'"{bad}', raw)
        self.assertEqual(c["version"], 2)
        p = self.ok("wall-url", "-d", self.d)
        tok = self.cfg()["console"]["wall_token"]
        self.assertIn(f"https://203.0.113.9:8740/wall?k={tok}", p.stdout)
        p = self.ok("wall-url", "-d", self.d, "--base", "https://10.0.0.5:8740/")
        self.assertIn(f"https://10.0.0.5:8740/wall?k={tok}", p.stdout)


class TestConfigVersion(Base):
    """AC: version != 2 is refused by add-sensor, remove-sensor and compose."""

    @pytest.mark.slow
    def test_old_or_missing_version_refused(self):
        self.init(*HOST3[:6])
        for v in (1, None):                                 # other values: test_check_version_helper
            c = self.cfg()
            if v is None:
                c.pop("version")
            else:
                c["version"] = v
            self.put_cfg(c)
            with open(os.path.join(self.d, "rpot.json")) as f:
                raw = f.read()
            for args in (["add-sensor", "-d", self.d, "--sensor", "X1=linux-web-hosting@10.0.8.8%eth4"],
                         ["remove-sensor", "-d", self.d, "--name", "ARB-FS01"], ["compose", "-d", self.d]):
                self.assertRefused(ctl(*args), REFUSED)
            with open(os.path.join(self.d, "rpot.json")) as f:
                self.assertEqual(f.read(), raw)                                    # untouched
            self.assertFalse(os.path.exists(os.path.join(self.d, "docker-compose.yml")))

    def test_check_version_helper(self):
        from rpot.common.config import check_version, CONFIG_VERSION
        self.assertEqual(CONFIG_VERSION, 2)
        self.assertEqual(check_version({"version": 2}), {"version": 2})
        for bad in ({"version": 1}, {"version": "2"}, {"version": 3}, {}, [], None):
            with self.assertRaisesRegex(ValueError, REFUSED):
                check_version(bad)


class TestRemovedCode(unittest.TestCase):
    def test_gate_words_absent_from_rpotctl(self):
        with open(CTL) as f:
            src = f.read()
        for word in (r"macvlan", r"mac_address", r"\bOUI\b", r"hostnet", r"decoy_nets", r"own-ip", r"--macvlan",
                     r"--host-network", r"public_url", r"telegram", r"webhook", r"compose_macs", r"_netname"):
            self.assertIsNone(re.search(word, src, re.I), word)


if __name__ == "__main__":
    unittest.main()
