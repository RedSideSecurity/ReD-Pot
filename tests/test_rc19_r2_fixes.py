"""RC-19: security review round 2 fixes in the installer (stubbed run(): no iptables, Docker or systemd is touched).
R2-1: add-decoy / remove-decoy fail closed when the new firewall cannot be applied (previous rules back, else stop).
R2-2: the unit stops its containers before it applies the firewall.
R2-6: firewall prerequisites are checked before any host change.
(R2-4 / R2-5 entrypoint: tests/test_rc18_hardening.py TestEntrypoint.)"""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_installer_wizard import ONE, THREE, JOIN_FS, _mod, run as wizard_run  # noqa: E402
from iptables_model import IptModel  # noqa: E402


def _msg(pr):
    return " ".join(str(a) for c in pr.call_args_list for a in c.args)


class FakeRun:
    """run() stub: records argv/str, fails the commands for which fail(text) is true."""

    def __init__(self, fail=lambda t: False):
        self.calls, self.fail = [], fail

    def __call__(self, cmd, check=True, capture=False, quiet=False):
        t = cmd if isinstance(cmd, str) else " ".join(cmd)
        self.calls.append(t)
        return subprocess.CompletedProcess(cmd, 1 if self.fail(t) else 0, "", "NOT in effect: ip6tables:INPUT->REDPOT-IN6")


class TestUnitText(unittest.TestCase):
    def test_compose_stop_is_the_first_step_with_a_firewall(self):
        r = _mod()
        t = r.unit_text("/opt/redpot/manager", "redpot", "ReD-Pot manager + decoys", True)
        svc = t.split("[Service]\n")[1].split("\n\n")[0].splitlines()
        steps = [x for x in svc if x.startswith("Exec")]
        self.assertEqual(steps[:3], ["ExecStartPre=-/usr/bin/docker compose -p redpot stop",
                                     "ExecStartPre=/bin/sh /opt/redpot/manager/firewall.sh apply",
                                     "ExecStart=/usr/bin/docker compose -p redpot up -d --remove-orphans"])
        self.assertIn("ExecStopPost=/bin/sh /opt/redpot/manager/firewall.sh remove", steps)
        self.assertIn("WorkingDirectory=/opt/redpot/manager", svc)          # compose stop finds the project file

    def test_sensor_unit_order_and_no_firewall(self):
        r = _mod()
        t = r.unit_text("/opt/redpot/sensor", "redpot-sensor", "s", True, pre=["/sbin/ip route replace x"],
                        post=["/sbin/ip route del x"])
        pre = [x for x in t.splitlines() if x.startswith("ExecStartPre")]
        self.assertEqual(pre, ["ExecStartPre=-/usr/bin/docker compose -p redpot-sensor stop",
                               "ExecStartPre=/bin/sh /opt/redpot/sensor/firewall.sh apply",
                               "ExecStartPre=-/sbin/ip route replace x"])
        t = r.unit_text("/opt/redpot/manager", "redpot", "x", False)
        self.assertNotIn("ExecStartPre", t)                                  # nothing to wait for
        self.assertNotIn("firewall.sh", t)


class TestApplyFailClosed(unittest.TestCase):
    """R2-1 with a stubbed run(): which commands run, and what the message says."""

    def setUp(self):
        self.r = _mod()
        self.td = tempfile.TemporaryDirectory()
        self.d = self.td.name
        self.addCleanup(self.td.cleanup)

    def go(self, fail, prev="#!/bin/sh\n# OLD\n", change=True):
        fr = FakeRun(fail)
        with mock.patch.object(self.r, "run", fr), mock.patch("builtins.print") as pr:
            with self.assertRaises(SystemExit):
                self.r.apply_firewall(self.d, prev=prev, change=change)
        self.assertFalse(os.path.exists(os.path.join(self.d, "firewall.sh.prev")))   # temporary copy removed
        return fr.calls, _msg(pr)

    def fw(self, name="firewall.sh"):
        return os.path.join(self.d, name)

    def test_previous_rules_restored(self):
        calls, msg = self.go(lambda t: t == f"/bin/sh {self.fw()} apply")
        self.assertEqual(calls, [f"/bin/sh {self.fw()} apply", f"/bin/sh {self.fw()} remove",
                                 f"/bin/sh {self.fw('firewall.sh.prev')} apply"])
        self.assertIn("PREVIOUS firewall rules were put back", msg)
        self.assertIn("The change was NOT started", msg)
        self.assertIn("ip6tables:INPUT->REDPOT-IN6", msg)
        self.assertIn("sudo systemctl restart redpot", msg)

    def test_previous_rules_fail_too_stack_stopped(self):
        calls, msg = self.go(lambda t: t.endswith(" apply"))
        self.assertEqual(calls, [f"/bin/sh {self.fw()} apply", f"/bin/sh {self.fw()} remove",
                                 f"/bin/sh {self.fw('firewall.sh.prev')} apply",
                                 f"/bin/sh {self.fw('firewall.sh.prev')} remove", "systemctl stop redpot"])
        self.assertIn("previous rules could not be restored either", msg)
        self.assertIn("was STOPPED", msg)

    def test_no_previous_rules_stack_stopped(self):
        calls, msg = self.go(lambda t: t.endswith(" apply"), prev=None)
        self.assertEqual(calls, [f"/bin/sh {self.fw()} apply", f"/bin/sh {self.fw()} remove", "systemctl stop redpot"])
        self.assertIn("There were no previous rules", msg)
        self.assertIn("was STOPPED", msg)

    def test_systemctl_fails_compose_stop(self):
        calls, msg = self.go(lambda t: t.endswith(" apply") or t.startswith("systemctl stop"), prev=None)
        self.assertEqual(calls[-1], f"cd {self.d} && docker compose -p redpot stop")
        self.assertIn("was STOPPED", msg)
        calls, msg = self.go(lambda t: t.endswith(" apply") or "stop" in t, prev=None)
        self.assertIn("could NOT be stopped", msg)
        self.assertIn("WITHOUT its firewall", msg)

    def test_first_install_says_run_the_installer_again(self):
        calls, msg = self.go(lambda t: t.endswith(" apply"), prev=None, change=False)
        self.assertEqual(calls, [f"/bin/sh {self.fw()} apply", f"/bin/sh {self.fw()} remove"])
        self.assertIn("decoys were NOT started", msg)
        self.assertIn("run the installer again", msg)
        self.assertNotIn("systemctl restart", msg)                   # the unit does not exist yet (R2-6 hint)

    def test_success_changes_nothing_else(self):
        fr = FakeRun()
        with mock.patch.object(self.r, "run", fr):
            self.assertTrue(self.r.apply_firewall(self.d, prev="x", change=True))
        self.assertEqual(fr.calls, [f"/bin/sh {self.fw()} apply"])


class TestDecoyChangeFailClosed(unittest.TestCase):
    """_apply_decoy_change: the previous firewall.sh text is the fallback; on failure no reload/restart happens and
    firewall.sh on disk is the NEW one (matches the new compose: the next unit start applies it or stays down)."""

    def test_add_decoy_failure_path(self):
        r = _mod()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "firewall.sh")
            with open(p, "w") as f:
                f.write("#!/bin/sh\n# OLD\n")

            def new_fw(d_, st, decoys=None):
                with open(p, "w") as f:
                    f.write("#!/bin/sh\n# NEW\n")
                return True
            seen = {}

            def fake(cmd, check=True, capture=False, quiet=False):
                t = cmd if isinstance(cmd, str) else " ".join(cmd)
                if t.endswith("firewall.sh.prev apply"):
                    seen["prev"] = open(cmd[-2]).read()
                return subprocess.CompletedProcess(cmd, 1 if t == f"/bin/sh {p} apply" else 0, "", "boom")
            fr = mock.Mock(side_effect=fake)
            r.A.dry_run = False
            with mock.patch.object(r, "write_firewall", new_fw), mock.patch.object(r, "install_service") as svc, \
                    mock.patch.object(r, "run", fr), mock.patch("builtins.print") as pr:
                with self.assertRaises(SystemExit):
                    r._apply_decoy_change(d, {}, [], ["FS01"])
            self.assertEqual(seen["prev"], "#!/bin/sh\n# OLD\n")
            self.assertEqual(open(p).read(), "#!/bin/sh\n# NEW\n")
            self.assertEqual(svc.call_args.kwargs.get("start"), False)
            texts = [c.args[0] if isinstance(c.args[0], str) else " ".join(c.args[0]) for c in fr.call_args_list]
            self.assertFalse(any("reload" in t or "restart" in t for t in texts), texts)
            self.assertIn("PREVIOUS firewall rules", _msg(pr))

    def test_add_decoy_order(self):
        """R2-6 preflight before stop_conflicting / ctl / SSH move; state saved before the firewall step."""
        r = _mod()
        order = mock.Mock()
        st = {"ifs": {"eth0": {"ip": "10.0.0.5"}, "eth1": {"ip": "192.168.50.10"}}, "mgmt": "eth0",
              "new_if": "eth0", "new_ip": "10.0.0.5", "new_name": "FS02", "new_role": "windows-file-server",
              "existing": [{"name": "DC01", "role": "windows-domain-controller", "ip": "192.168.50.10", "iface": "eth1"}],
              "need_move": True, "need_pin": False, "new_ssh": 40022, "move_ssh": False, "pin_ssh": True,
              "ports": {"ssh": 22, "ui": 1, "sensor": 2}, "allow": {}}
        with mock.patch.multiple(r, ensure_docker=mock.DEFAULT, ensure_image=mock.DEFAULT, banner=mock.DEFAULT,
                                 warn=mock.DEFAULT) as _, \
                mock.patch.object(r, "preflight_firewall", order.preflight), \
                mock.patch.object(r, "stop_conflicting", order.stop_conflicting), \
                mock.patch.object(r, "ctl", order.ctl), mock.patch.object(r, "move_ssh", order.move_ssh), \
                mock.patch.object(r, "save_state", order.save_state), \
                mock.patch.object(r, "_apply_decoy_change", mock.Mock(side_effect=SystemExit(1))):
            with self.assertRaises(SystemExit):
                r.execute_add_decoy(st, "/nonexistent")
        names = [c[0] for c in order.mock_calls]
        self.assertEqual(names, ["preflight", "stop_conflicting", "ctl", "move_ssh", "save_state"])
        self.assertEqual(order.preflight.call_args.args[0], ["eth1", "eth0"])
        self.assertTrue(order.save_state.call_args.args[1]["move_ssh"])


class TestPreflight(unittest.TestCase):
    """R2-6: prerequisites checked with throw-away chains; every failure is named, nothing else is left behind.
    RC-22 (VM defect B2): run against IptModel, which enforces the kernel's 'owner match only on the OUTPUT /
    POSTROUTING path' rule (rc 4 like iptables-nft) — 19f9360 put the owner rule in the chain it hooked from FORWARD."""

    def go(self, fail=lambda t: False, tools=("iptables", "ip6tables"), v6=True, ifs=("eth1",), docker="iptables"):
        r = _mod()
        r.A.dry_run = False
        m = IptModel(docker=docker, fail=fail, tools=tools)
        tool = {n: f"/usr/sbin/{n}" for n in tools}
        with mock.patch.object(r, "run", m), mock.patch.object(r, "_fw_tool", tool.get), \
                mock.patch.object(r, "_v6_on", lambda names=None: v6), mock.patch("builtins.print") as pr:
            try:
                r.preflight_firewall(list(ifs))
                died = False
            except SystemExit:
                died = True
        self.model = m
        return died, m.calls, _msg(pr)

    def assertClean(self, m):
        for tool in m.tools:
            self.assertEqual(m.user_chains(tool), set(), tool)            # every REDPOT-PRECHK* chain is gone
            for b in ("INPUT", "FORWARD", "OUTPUT"):
                self.assertFalse([x for x in m.chains(tool)[b] if "PRECHK" in " ".join(x)], (tool, b))

    def test_all_present(self):
        for docker in ("iptables", "nftables", None):
            died, calls, msg = self.go(docker=docker)
            self.assertFalse(died, msg)
            self.assertClean(self.model)
        ipt = [c for c in calls if c.startswith("/usr/sbin/iptables")]
        self.assertIn("/usr/sbin/iptables -A REDPOT-PRECHK-OUT -m owner --uid-owner 10001 -j RETURN", ipt)
        self.assertIn("/usr/sbin/iptables -I OUTPUT 1 -j REDPOT-PRECHK-OUT", ipt)     # owner: OUTPUT path only
        self.assertIn("/usr/sbin/iptables -I FORWARD 1 -j REDPOT-PRECHK-FWD", ipt)
        self.assertTrue(any("--ctstate ESTABLISHED,RELATED" in c for c in ipt))
        self.assertFalse(any(c.startswith("/usr/sbin/iptables -A REDPOT-PRECHK-FWD") for c in ipt))   # stays EMPTY
        self.assertFalse(any("-I FORWARD 1 -j REDPOT-PRECHK" == c[len("/usr/sbin/iptables "):] for c in ipt))
        self.assertIn("/usr/sbin/ip6tables -I OUTPUT 1 -j REDPOT-PRECHK-OUT", calls)
        self.assertEqual(calls[-1], "/usr/sbin/ip6tables -X REDPOT-PRECHK-FWD")
        for c in calls:                                       # only the throw-away chains, never REDPOT-IN etc.
            self.assertIn("REDPOT-PRECHK", c)
        self.assertEqual([e for e in self.model.errors if e[1] == 4], [])

    def test_model_rejects_the_19f9360_sequence(self):
        """The stub itself: an owner rule in a chain jumped to from FORWARD/INPUT is EINVAL (rc 4), also when the
        rule is added after the jump; from OUTPUT it is fine. B2 cannot come back unnoticed."""
        m = IptModel(docker="iptables")
        for argv, rc in ((["-N", "QA-PRE"], 0), (["-A", "QA-PRE", "-m", "owner", "--uid-owner", "10001", "-j", "RETURN"], 0),
                         (["-I", "FORWARD", "1", "-j", "QA-PRE"], 4), (["-I", "INPUT", "1", "-j", "QA-PRE"], 4),
                         (["-I", "OUTPUT", "1", "-j", "QA-PRE"], 0), (["-N", "QA-E"], 0),
                         (["-I", "FORWARD", "1", "-j", "QA-E"], 0),
                         (["-A", "QA-E", "-m", "owner", "--uid-owner", "1", "-j", "RETURN"], 4),
                         (["-A", "QA-E", "-j", "QA-PRE"], 4),                        # indirect: FORWARD→QA-E→QA-PRE
                         (["-A", "DOCKER-USER", "-m", "owner", "--uid-owner", "1", "-j", "RETURN"], 4)):
            got, err = m.ipt("iptables", argv)
            self.assertEqual(got, rc, (argv, err))
            if rc == 4:
                self.assertIn("RULE_INSERT failed (Invalid argument)", err)
        self.assertEqual(m.chains()["QA-E"], [])                   # a refused rule changes nothing
        self.assertFalse(m.hooked("QA-PRE", "FORWARD"))
        died, _, msg = self.go_old()
        self.assertTrue(died)
        self.assertIn("the FORWARD chain cannot be hooked", msg)

    def go_old(self):
        """The 19f9360 preflight sequence (owner rule + FORWARD hook in one chain) replayed on the model."""
        m = IptModel(docker="iptables")
        bad = []
        for argv in (["-N", "REDPOT-PRECHK"], ["-A", "REDPOT-PRECHK", "-m", "owner", "--uid-owner", "10001", "-j", "RETURN"]):
            m.ipt("iptables", argv)
        if m.ipt("iptables", ["-I", "FORWARD", "1", "-j", "REDPOT-PRECHK"])[0] != 0:
            bad.append("the FORWARD chain cannot be hooked")
        return bool(bad), [], " ".join(bad)

    def test_missing_tools_and_modules(self):
        died, calls, msg = self.go(tools=("iptables",))
        self.assertTrue(died)
        self.assertIn("ip6tables is not installed, but IPv6 is on", msg)
        self.assertIn("nothing was changed", msg)
        self.assertFalse(self.go(tools=("iptables",), v6=False)[0])           # IPv6 off: ip6tables not needed
        died, calls, msg = self.go(tools=())
        self.assertTrue(died)
        self.assertIn("iptables is not installed", msg)
        died, _, msg = self.go(fail=lambda t: "--uid-owner" in t and "/iptables " in t)
        self.assertTrue(died)
        self.assertIn("refuses the rule '-m owner --uid-owner 10001 -j RETURN'", msg)
        self.assertClean(self.model)
        died, calls, msg = self.go(fail=lambda t: "-I OUTPUT" in t and "/ip6tables " in t)
        self.assertIn("ip6tables OUTPUT chain cannot be hooked with an owner match", msg)
        self.assertClean(self.model)
        died, _, msg = self.go(fail=lambda t: "-I FORWARD" in t)
        self.assertIn("FORWARD chain cannot be hooked", msg)
        self.assertClean(self.model)
        died, calls, msg = self.go(fail=lambda t: t == "/usr/sbin/iptables -N REDPOT-PRECHK")
        self.assertIn("cannot create a chain (REDPOT-PRECHK)", msg)
        self.assertIn("/usr/sbin/iptables -I FORWARD 1 -j REDPOT-PRECHK-FWD", calls)   # the other tests still run
        self.assertClean(self.model)

    def test_leftovers_of_an_interrupted_run_are_removed(self):
        """Also 1.0.0-rc's REDPOT-PRECHK hooked from FORWARD (an empty one could be hooked there)."""
        r = _mod()
        r.A.dry_run = False
        m = IptModel(docker="iptables")
        for argv in (["-N", "REDPOT-PRECHK"], ["-I", "FORWARD", "1", "-j", "REDPOT-PRECHK"], ["-N", "REDPOT-PRECHK-OUT"],
                     ["-A", "REDPOT-PRECHK-OUT", "-m", "owner", "--uid-owner", "10001", "-j", "RETURN"],
                     ["-I", "OUTPUT", "1", "-j", "REDPOT-PRECHK-OUT"], ["-N", "REDPOT-PRECHK-FWD"],
                     ["-I", "FORWARD", "1", "-j", "REDPOT-PRECHK-FWD"]):
            self.assertEqual(m.ipt("iptables", argv)[0], 0, argv)
        with mock.patch.object(r, "run", m), mock.patch.object(r, "_fw_tool", lambda n: f"/usr/sbin/{n}"), \
                mock.patch.object(r, "_v6_on", lambda names=None: False), mock.patch("builtins.print"):
            r.preflight_firewall(["eth1"])
        self.model = m
        self.assertClean(m)
        self.assertEqual(m.chains()["FORWARD"], [["-j", "DOCKER-USER"]])              # Docker's own jump kept

    def test_no_decoys_needs_no_owner_match_or_ip6tables(self):
        died, calls, _ = self.go(tools=("iptables",), ifs=())
        self.assertFalse(died)
        self.assertFalse(any("--uid-owner" in c for c in calls))
        self.assertClean(self.model)

    def test_v6_on_reads_disable_ipv6(self):
        r = _mod()
        self.assertIsInstance(r._v6_on(["no-such-if0"]), bool)
        self.assertFalse(r._v6_on(["no-such-if0"]))


class TestPreflightBeforeHostChanges(unittest.TestCase):
    """Dry-run wizard: the prerequisite check is printed before services are stopped, SSH moves or enrollment."""

    def test_manager_one_nic(self):
        rc, out, _ = wizard_run([], ONE, "--yes", "--domain", "x.example.com", "--roles", "windows-file-server",
                                "--public-ip", "no", "--geoip", "no")
        self.assertEqual(rc, 0, out[-1500:])
        i = out.index("would check the firewall prerequisites")
        self.assertLess(i, out.index("Moving host SSH"))
        self.assertLess(i, out.index("rpotctl") if "rpotctl" in out else len(out))

    def test_manager_three_nics(self):
        rc, out, _ = wizard_run([], THREE, "--yes", "--domain", "x.example.com", "--roles", "windows-file-server",
                                "--public-ip", "no", "--geoip", "no")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertIn("would check the firewall prerequisites", out)

    def test_sensor(self):
        rc, out, _ = wizard_run([], THREE, "--yes", "--join", JOIN_FS, mode="sensor")
        self.assertEqual(rc, 0, out[-1500:])
        self.assertLess(out.index("would check the firewall prerequisites"), out.index("Enrolling"))


if __name__ == "__main__":
    unittest.main()
