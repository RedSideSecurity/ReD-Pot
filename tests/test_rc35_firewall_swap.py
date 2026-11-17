"""RC-35 M2 (security review): firewall.sh apply is make-before-break.

The generated script runs for real (/bin/sh) against fake `iptables` / `ip6tables` programs on PATH that keep the
ruleset in tests/iptables_model.IptModel (state in a temp file). Nothing on the host is changed: the test first checks
that `command -v iptables` resolves to the fake, and the decoy interface name does not exist on any host, so arp()
never touches /proc. Every command is logged with the ruleset after it, so the test can check the invariant at EVERY
step: INPUT / DOCKER-USER / OUTPUT (and ip6tables INPUT / OUTPUT) always jump to a COMPLETE generation of the chain.
"""
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import unittest

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from iptables_model import IptModel  # noqa: E402
from test_installer_wizard import _mod  # noqa: E402

IFACE = "rpt9zz"                 # never a real interface: arp() skips it (no /proc write)
PORTS = {"ui": 50000, "sensor": 50001, "ssh": 50022}

FAKE = r'''
import json, os, signal, sys
sys.path.insert(0, os.environ["RPOT_TEST_MODEL_DIR"])
from iptables_model import IptModel
tool, argv = sys.argv[1], sys.argv[2:]
p = os.environ["RPOT_TEST_STATE"]
m = IptModel()
with open(p) as f:
    m.state = json.load(f)
text = " ".join(argv)
sig = os.environ.get("RPOT_TEST_SIGNAL", "")          # "<substring>|<signal number>": signal the script there
if sig and sig.split("|")[0] in text and argv[0] != "-C":
    os.kill(os.getppid(), int(sig.split("|")[1]))
fail = os.environ.get("RPOT_TEST_FAIL", "")
rc, err = (1, "injected failure") if fail and fail in text else m.ipt(tool, argv)
sys.stdout.write(getattr(m, "out", "") if not rc else "")
with open(p, "w") as f:
    json.dump(m.state, f)
with open(os.environ["RPOT_TEST_LOG"], "a") as f:
    f.write(json.dumps({"tool": tool, "argv": argv, "rc": rc, "state": m.state}) + "\n")
if err and rc:
    sys.stderr.write(err + "\n")
sys.exit(rc)
'''


def script(r, allow=None):
    decoys = [{"name": "DC01", "role": "windows-domain-controller", "ip": "192.168.50.10", "iface": IFACE,
               "net": "192.168.50.0/24"}]
    txt, _ = r.firewall_text("10.0.0.5", allow or {"ui": ["10.8.0.0/24"], "sensor": ["10.8.0.0/24"],
                                                   "ssh": ["10.8.0.0/24"]},
                             PORTS, True, [("192.168.50.10", None)], mgmt_if="eth0", decoys=decoys, out_guard=True)
    return txt


class Lab:
    def __init__(self, tc):
        self.td = tempfile.TemporaryDirectory()
        tc.addCleanup(self.td.cleanup)
        self.d = self.td.name
        self.bin = os.path.join(self.d, "bin")
        os.mkdir(self.bin)
        helper = os.path.join(self.d, "fake_ipt.py")
        with open(helper, "w") as f:
            f.write(FAKE)
        for tool in ("iptables", "ip6tables"):
            p = os.path.join(self.bin, tool)
            with open(p, "w") as f:
                f.write(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -I {shlex.quote(helper)} {tool} \"$@\"\n")
            os.chmod(p, 0o755)
        self.state, self.log = os.path.join(self.d, "state.json"), os.path.join(self.d, "log.jsonl")
        with open(self.state, "w") as f:
            json.dump(IptModel(docker="iptables").state, f)
        self.env = {"PATH": self.bin + ":/usr/bin:/bin", "RPOT_TEST_MODEL_DIR": HERE, "RPOT_TEST_STATE": self.state,
                    "RPOT_TEST_LOG": self.log}
        for tool in ("iptables", "ip6tables"):          # safety: the fakes, never the host's iptables
            p = subprocess.run(["/bin/sh", "-c", f"command -v {tool}"], env=self.env, capture_output=True, text=True)
            tc.assertEqual(p.stdout.strip(), os.path.join(self.bin, tool))
        self.fw = os.path.join(self.d, "firewall.sh")

    def write(self, txt):
        with open(self.fw, "w") as f:
            f.write(txt)

    def run(self, cmd="apply", **extra):
        open(self.log, "w").close()
        return subprocess.run(["/bin/sh", self.fw, cmd], env=dict(self.env, **extra), capture_output=True, text=True,
                              timeout=120)

    def steps(self):
        with open(self.log) as f:
            return [json.loads(x) for x in f if x.strip()]

    def model(self):
        m = IptModel()
        with open(self.state) as f:
            m.state = json.load(f)
        return m


HOOKS = (("iptables", "INPUT", "REDPOT-IN"), ("iptables", "DOCKER-USER", "REDPOT-DOCKER"),
         ("iptables", "OUTPUT", "REDPOT-OUT"), ("ip6tables", "INPUT", "REDPOT-IN6"), ("ip6tables", "OUTPUT", "REDPOT-OUT6"))


def effective(state, tool, hook, base):
    """Rules of the FIRST generation of `base` that `hook` jumps to (None if none)."""
    f = state[tool]["filter"]
    for rule in f.get(hook, []):
        if rule[:1] == ["-j"] and rule[1] in (base, base + "-B"):
            return f.get(rule[1])
    return None


@pytest.mark.slow       # ~10 s per test: every iptables call of the real script goes through the model
class TestMakeBeforeBreak(unittest.TestCase):
    def setUp(self):
        self.r = _mod()
        self.lab = Lab(self)
        self.lab.write(script(self.r))
        p = self.lab.run()                                  # boot: nothing in effect yet → generation REDPOT-*
        self.assertEqual(p.returncode, 0, p.stderr)
        st = self.lab.model().state
        self.full = {b: effective(st, t, h, b) for t, h, b in HOOKS}
        for b, rules in self.full.items():
            self.assertTrue(rules, b)                       # every chain hooked and filled
        self.assertFalse([c for c in st["iptables"]["filter"] if c.endswith("-B")])

    def assert_always_complete(self, steps, full=None):
        full = full or self.full
        for i, s in enumerate(steps):
            for t, h, b in HOOKS:
                self.assertEqual(effective(s["state"], t, h, b), full[b],
                                 f"step {i} ({s['tool']} {' '.join(s['argv'])}): {h} -> {b} not complete")

    def test_reapply_swaps_generations_without_a_gap(self):
        p = self.lab.run()
        self.assertEqual(p.returncode, 0, p.stderr)
        steps = self.lab.steps()
        self.assert_always_complete(steps)
        st = self.lab.model().state
        self.assertTrue(st["iptables"]["filter"]["INPUT"].count(["-j", "REDPOT-IN-B"]) == 1)
        self.assertNotIn("REDPOT-IN", st["iptables"]["filter"])          # old generation deleted
        texts = [" ".join(s["argv"]) for s in steps]
        first_unhook = min(i for i, t in enumerate(texts) if t.startswith("-D ") and "-B" not in t
                           and s_ok(steps[i]))
        last_hook = max(i for i, t in enumerate(texts) if t.startswith("-I ") and t.endswith("-B")
                        or t.startswith("-t mangle -I OUTPUT 1 -j REDPOT-TTL-B"))
        self.assertLess(last_hook, first_unhook)                         # every new hook before any old unhook
        self.assertTrue(texts[first_unhook].startswith("-D INPUT -j REDPOT-IN"))   # INPUT is unhooked first
        p = self.lab.run()                                               # and back again
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_always_complete(self.lab.steps())
        self.assertNotIn("REDPOT-IN-B", self.lab.model().state["iptables"]["filter"])
        self.assertEqual(self.lab.run("check").returncode, 0)

    def test_new_rules_take_effect(self):
        self.lab.write(script(self.r, {"ui": ["10.9.0.0/24"], "sensor": ["10.8.0.0/24"], "ssh": ["10.8.0.0/24"]}))
        p = self.lab.run()
        self.assertEqual(p.returncode, 0, p.stderr)
        rules = effective(self.lab.model().state, "iptables", "DOCKER-USER", "REDPOT-DOCKER")
        flat = [" ".join(x) for x in rules]
        self.assertTrue(any("-s 10.9.0.0/24" in x for x in flat))
        self.assertFalse(any("--ctorigdstport 50000 -s 10.8.0.0/24" in x for x in flat))
        steps = self.lab.steps()
        for s in steps:                                  # in between: old or new chain complete, never a gap
            for t, h, b in HOOKS:
                self.assertIsNotNone(effective(s["state"], t, h, b))

    def test_failure_in_the_middle_keeps_the_rules_in_effect(self):
        before = self.lab.model().state
        p = self.lab.run(RPOT_TEST_FAIL="-A REDPOT-OUT-B")             # a rule of the new generation fails
        self.assertEqual(p.returncode, 1)
        self.assertIn("building the new firewall rules failed", p.stderr)
        self.assertIn("the rules in effect before stay in effect", p.stderr)
        self.assert_always_complete(self.lab.steps())
        after = self.lab.model().state
        self.assertEqual(after["iptables"]["filter"], before["iptables"]["filter"])   # new generation dropped again
        self.assertEqual(after["ip6tables"]["filter"], before["ip6tables"]["filter"])

    def test_killed_halfway_then_reapplied(self):
        """SIGKILL (power cut, kill -9) in the middle of the swap: a complete generation is still in effect, and the
        next apply cleans up the leftovers."""
        p = self.lab.run(RPOT_TEST_SIGNAL=f"-D OUTPUT -j REDPOT-OUT|{int(signal.SIGKILL)}")
        self.assertNotEqual(p.returncode, 0)
        self.assert_always_complete(self.lab.steps())
        p = self.lab.run()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_always_complete(self.lab.steps())
        f = self.lab.model().state["iptables"]["filter"]
        self.assertEqual(sum(c.startswith("REDPOT-IN") and c != "REDPOT-IN6" for c in f), 1)   # one generation left
        self.assertEqual(self.lab.run("check").returncode, 0)

    def test_sighup_and_sigint_do_not_stop_the_swap(self):
        for sig in (signal.SIGHUP, signal.SIGINT):
            p = self.lab.run(RPOT_TEST_SIGNAL=f"-I INPUT 1 -j REDPOT-IN|{int(sig)}")
            self.assertEqual(p.returncode, 0, (sig, p.stderr))
            self.assert_always_complete(self.lab.steps())

    def test_remove_takes_out_both_generations(self):
        self.lab.run(RPOT_TEST_SIGNAL=f"-D OUTPUT -j REDPOT-OUT|{int(signal.SIGKILL)}")   # leave both behind
        p = self.lab.run("remove")
        self.assertEqual(p.returncode, 0, p.stderr)
        st = self.lab.model().state
        for tool in ("iptables", "ip6tables"):
            self.assertFalse([c for c in st[tool]["filter"] if c.startswith("REDPOT")], tool)
            self.assertFalse([c for c in st[tool]["mangle"] if c.startswith("REDPOT")], tool)
        self.assertEqual(st["iptables"]["filter"]["INPUT"], [])

    def test_kill_while_both_inputs_hooked_then_apply(self):
        """Security re-review R2-M1 (probe2): -B in effect, the next run (building '') is killed at '-N DOCKER-USER',
        i.e. right after its REDPOT-IN is hooked in front. The following apply must keep the complete -B generation
        until the new one is complete — at EVERY command."""
        self.assertEqual(self.lab.run().returncode, 0)                    # now -B is in effect
        p = self.lab.run(RPOT_TEST_SIGNAL=f"-N DOCKER-USER|{int(signal.SIGKILL)}")
        self.assertNotEqual(p.returncode, 0)
        f = self.lab.model().state["iptables"]["filter"]
        self.assertEqual(f["INPUT"][:2], [["-j", "REDPOT-IN"], ["-j", "REDPOT-IN-B"]])   # both hooked, '' in front
        self.assert_always_complete(self.lab.steps())
        p = self.lab.run()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_always_complete(self.lab.steps())
        self.assertEqual(self.lab.run("check").returncode, 0)

    def test_kill_then_failing_apply_tells_the_truth(self):
        """R2-M1 (probe): kill at '-N REDPOT-OUT' of the third run, then an apply whose build fails: the complete
        generation stays in effect at every command, and 'stay in effect' is printed only because check() passes."""
        self.assertEqual(self.lab.run().returncode, 0)
        self.lab.run(RPOT_TEST_SIGNAL=f"-N REDPOT-OUT|{int(signal.SIGKILL)}")
        p = self.lab.run(RPOT_TEST_FAIL="-A REDPOT-OUT-B")
        steps = self.lab.steps()
        self.assert_always_complete(steps)
        if p.returncode:                                                  # the build of -B failed
            self.assertIn("the rules in effect before stay in effect", p.stderr)
        self.assertEqual(self.lab.run("check").returncode, 0)

    def test_failing_apply_on_broken_rules_says_unprotected(self):
        """If the rules in effect are not complete either (here: someone removed the OUTPUT hook), a failed build
        must not claim the previous rules stay: it says the host is NOT protected and what to do."""
        env = dict(self.lab.env)
        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "REDPOT-OUT"], env=env, check=True, capture_output=True)
        p = self.lab.run(RPOT_TEST_FAIL="-A REDPOT-IN-B")
        self.assertEqual(p.returncode, 1)
        self.assertIn("this host is NOT protected by the ReD-Pot firewall now", p.stderr)
        self.assertIn("systemctl stop redpot", p.stderr)
        self.assertNotIn("stay in effect", p.stderr)

    def test_term_is_ignored_during_the_swap(self):
        p = self.lab.run(RPOT_TEST_SIGNAL=f"-I INPUT 1 -j REDPOT-IN|{int(signal.SIGTERM)}")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_always_complete(self.lab.steps())

    def test_first_apply_failure_leaves_nothing_hooked(self):
        lab = Lab(self)
        lab.write(script(self.r))
        p = lab.run(RPOT_TEST_FAIL="-A REDPOT-IN ")
        self.assertEqual(p.returncode, 1)
        f = lab.model().state["iptables"]["filter"]
        self.assertFalse([c for c in f if c.startswith("REDPOT")])


def s_ok(step):
    return step["rc"] == 0


if __name__ == "__main__":
    unittest.main()


@pytest.mark.slow
class TestIPv6FailuresOnlyWhereIPv6IsOn(unittest.TestCase):
    """Re-review I10: an ip6tables rule that fails does not stop apply when the config has no decoy interface (V6
    stays 0, as the installer preflight does not require ip6tables then); with decoy interfaces it counts only
    where IPv6 is on."""

    def test_ip6_failure_ignored_without_decoy_interfaces(self):
        r = _mod()
        lab = Lab(self)
        txt, _ = r.firewall_text("10.0.0.5", {"ui": ["10.8.0.0/24"], "sensor": ["10.8.0.0/24"], "ssh": ["10.8.0.0/24"]},
                                 PORTS, True, [], mgmt_if="eth0", decoys=[], out_guard=True)
        self.assertIn("V6=0", txt)
        self.assertNotIn("then V6=1", txt)
        lab.write(txt)
        p = lab.run(RPOT_TEST_FAIL="-A REDPOT-OUT6 -m owner")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("building the new firewall rules failed", p.stderr)

    def test_ip6_failure_counts_with_decoys_when_ipv6_is_on(self):
        r = _mod()
        lab = Lab(self)
        lab.write(script(r))
        self.assertIn("if v6on; then V6=1; fi", script(r))
        p = lab.run(RPOT_TEST_FAIL="-A REDPOT-IN6 -i lo")
        if r._v6_on():
            self.assertEqual(p.returncode, 1)
            self.assertIn("building the new firewall rules failed", p.stderr)
        else:
            self.assertEqual(p.returncode, 0, p.stderr)


class TestInstallerSideM2(unittest.TestCase):
    """The installer ignores SIGINT / SIGHUP / SIGTERM while it applies (and falls back), runs firewall.sh in its own
    session, and restores the handlers afterwards."""

    def test_signals_ignored_during_apply_and_restored(self):
        from unittest import mock
        r = _mod()
        seen = []

        def fake_run(cmd, check=True, capture=False, quiet=False, new_session=False):
            seen.append((cmd[-1], new_session, [signal.getsignal(s) for s in (signal.SIGINT, signal.SIGHUP,
                                                                              signal.SIGTERM)]))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        before = [signal.getsignal(s) for s in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)]
        with mock.patch.object(r, "run", fake_run):
            self.assertTrue(r.apply_firewall("/nonexistent", prev="x", change=True))
        self.assertEqual(seen, [("apply", True, [signal.SIG_IGN] * 3)])
        self.assertEqual([signal.getsignal(s) for s in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)], before)

    def test_signals_ignored_from_writing_firewall_sh_to_applying_it(self):
        """Re-review minor: Ctrl-C between write_firewall and apply_firewall must not leave a new, unapplied
        firewall.sh behind (set-access and add/remove-decoy)."""
        from unittest import mock
        r = _mod()
        seen = []

        def probe(*a, **k):
            seen.append(signal.getsignal(signal.SIGINT))
            return True
        with tempfile.TemporaryDirectory() as d, mock.patch.object(r, "write_firewall", probe), \
                mock.patch.object(r, "install_service", probe), mock.patch.object(r, "apply_firewall", probe), \
                mock.patch.object(r, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "", "")):
            r._apply_access(d, {}, [])
            r._apply_decoy_change(d, {}, [], [])
        self.assertEqual(seen, [signal.SIG_IGN] * 6)
        self.assertNotEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)

    def test_run_passes_new_session(self):
        from unittest import mock
        r = _mod()
        with mock.patch.object(r.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as sp, \
                mock.patch.object(r, "A", None):
            r.run(["/bin/true"], new_session=True)
        self.assertTrue(sp.call_args.kwargs["start_new_session"])
