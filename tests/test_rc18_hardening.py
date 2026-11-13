"""RC-18 fixes from security review 1.
F3/F10: sensor.gap is O(1) per event (one note line per decoy per 5 min, extras merged, note capped), and its
        first/last timestamps are labelled as the decoy's clock and dropped outside [now-30d, now+5min].
F5:     no setuid/setgid files in the image; host-network decoys start as root and drop with setpriv to 10001
        keeping only ambient NET_BIND_SERVICE, under no-new-privileges (entrypoint logic tested with stubs;
        the real image/kernel behaviour must be checked on the VM).
F8:     follow mode (RPOT_SENSOR_IFACE) never binds 0.0.0.0."""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.console import engine as E  # noqa: E402
from rpot.sensor import base  # noqa: E402


def _ts(minutes_ago):
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def gap(n=3, sensor="FS01", first=None, last=None):
    return {"ts": _ts(0), "sensor": sensor, "type": "sensor.gap",
            "data": {"undelivered": n, "first_ts": first if first is not None else _ts(60),
                     "last_ts": last if last is not None else _ts(30)}}


class EngCase(unittest.TestCase):
    def setUp(self):
        from test_unit import mkcfg
        self._td = tempfile.TemporaryDirectory()
        self.eng = E.Engine(mkcfg(self._td.name), os.path.join(self._td.name, "x.db"))

    def tearDown(self):
        self.eng.db.close()
        self._td.cleanup()

    def note(self, sensor="FS01"):
        return self.eng.db.execute("SELECT note FROM incidents WHERE subject=?", ("sensor:" + sensor,)).fetchone()[0]

    def gap_rows(self):
        return [json.loads(r[0]) for r in self.eng.db.execute("SELECT data FROM events WHERE type='sensor.gap' ORDER BY id")]


class TestCapNote(unittest.TestCase):
    def test_keeps_newest_lines_and_bytes(self):
        n = None
        for i in range(100):
            n = E.cap_note(n, f"line {i}")
        self.assertEqual(n.split("\n"), [f"line {i}" for i in range(80, 100)])
        big = E.cap_note(None, "x" * 10000)
        self.assertLessEqual(len(big), E.NOTE_MAX_BYTES)
        n = E.cap_note("a" * 3000 + "\n" + "b" * 3000, "c" * 100)
        self.assertEqual(n, "b" * 3000 + "\n" + "c" * 100)

    def test_huge_old_note_is_only_tail_read(self):
        old = "\n".join(f"old {i}" for i in range(500000))          # ~5.7 MB note left by an older version
        t = time.process_time()
        n = E.cap_note(old, "new")
        self.assertLess(time.process_time() - t, 0.5)                 # O(1): only the last 4 KB is looked at
        self.assertTrue(n.endswith("old 499999\nnew"))
        self.assertLessEqual(len(n.split("\n")), E.NOTE_MAX_LINES)
        self.assertLessEqual(len(n), E.NOTE_MAX_BYTES)
        self.assertTrue(all(x.startswith(("old ", "new")) for x in n.split("\n")))   # no partial first line


class TestGapRateLimit(EngCase):
    def test_flood_in_one_batch_is_one_note_line_and_one_row(self):
        stmts = []
        self.eng.db.set_trace_callback(stmts.append)
        self.assertEqual(self.eng.ingest([gap(2) for _ in range(1000)]), 1000)
        self.eng.db.set_trace_callback(None)
        inc_writes = [s for s in stmts if re.match(r"\s*(UPDATE|INSERT INTO) incidents", s)]
        self.assertEqual(len(inc_writes), 1)                          # the incident/note is written once
        self.assertLess(len(stmts), 1000 * 6)                         # O(1) statements per gap
        rows = self.gap_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["undelivered"], 2000)                # counts summed
        self.assertEqual(rows[0]["reports"], 1000)
        self.assertIn("2000 event(s)", rows[0]["summary"])
        self.assertIn("1000 reports within 5 min merged", rows[0]["summary"])
        self.assertEqual(self.note().count("\n"), 0)
        ev = self.eng.events(hours=24)
        self.assertIn("2000 event(s)", [e for e in ev if e["type"] == "sensor.gap"][0]["desc"])

    @pytest.mark.slow
    def test_10k_gaps_in_one_batch_fast_and_capped(self):
        # before RC-18: ~113 s CPU and a 2.1 MB note for this batch (quadratic); after: ~2 s, linear
        t = time.process_time()
        self.eng.ingest([gap(1) for _ in range(10000)])
        cpu = time.process_time() - t
        self.assertLess(cpu, 15.0, cpu)                               # >5x margin over ~2-3 s on the dev box
        self.assertLessEqual(len(self.note()), E.NOTE_MAX_BYTES)
        self.assertEqual(len(self.gap_rows()), 1)
        self.assertEqual(self.gap_rows()[0]["undelivered"], 10000)

    def test_merge_widens_span(self):
        self.eng.ingest([gap(1, first=_ts(50), last=_ts(40)), gap(1, first=_ts(90), last=_ts(45)),
                         gap(1, first="junk", last=_ts(10))])
        r = self.gap_rows()[0]
        self.assertEqual(r["first_ts"], _ts(90)[:19].replace("T", " "))
        self.assertEqual(r["last_ts"], _ts(10)[:19].replace("T", " "))

    def test_new_window_after_5_minutes(self):
        clock = [1000.0]
        with mock.patch.object(E.time, "monotonic", lambda: clock[0]):
            self.eng.ingest([gap(1), gap(1)])
            clock[0] += E.GAP_WINDOW - 1
            self.eng.ingest([gap(1)])
            self.assertEqual(len(self.gap_rows()), 1)
            clock[0] += 2
            self.eng.ingest([gap(5)])
        rows = self.gap_rows()
        self.assertEqual([r["undelivered"] for r in rows], [3, 5])
        self.assertEqual(self.note().count("\n"), 1)                  # one note line per window

    def test_windows_are_per_decoy(self):
        self.eng.ingest([gap(1, "FS01"), gap(2, "DC01"), gap(4, "FS01")])
        self.assertEqual(sorted(r["undelivered"] for r in self.gap_rows()), [2, 5])

    def test_note_capped_across_windows(self):
        clock = [1000.0]
        with mock.patch.object(E.time, "monotonic", lambda: clock[0]):
            for _ in range(60):
                self.eng.ingest([gap(1)])
                clock[0] += E.GAP_WINDOW + 1
        n = self.note()
        self.assertTrue(10 <= len(n.split("\n")) <= E.NOTE_MAX_LINES, n)   # ~210-char lines: the 4 KB cap binds
        self.assertLessEqual(len(n), E.NOTE_MAX_BYTES)
        self.assertEqual(self.eng.db.execute("SELECT count FROM incidents").fetchone()[0], 60)

    def test_rollback_does_not_merge_into_a_lost_row(self):
        with mock.patch.object(self.eng, "_host", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.eng.ingest([gap(7), {"ts": _ts(0), "sensor": "FS01", "type": "smb.login", "src_ip": "10.0.0.9",
                                          "data": {}}])
        self.assertEqual(self.gap_rows(), [])
        self.eng.ingest([gap(3)])
        self.assertEqual([r["undelivered"] for r in self.gap_rows()], [3])

    def test_state_is_bounded(self):
        with mock.patch.object(E, "GAP_STATE_MAX", 5):
            self.eng.ingest([gap(1, f"S{i}") for i in range(20)])
            self.assertLessEqual(len(self.eng._gap_state), 5)


class TestGapTimestamps(EngCase):
    """F10: first/last_ts are the decoy's clock: labelled so, and only kept inside [now-30d, now+5min]."""

    def one(self, first, last, sensor="FS01"):
        self.eng.ingest([gap(1, sensor, first=first, last=last)])
        return [r for r in self.eng.events(hours=24) if r["type"] == "sensor.gap" and r["sensor"] == sensor][0]["data"]

    def test_label_and_window(self):
        r = self.one(_ts(120), _ts(60))
        self.assertIn("decoy clock", r["summary"])
        self.assertIn(_ts(120)[:19].replace("T", " "), r["summary"])

    def test_out_of_window_dropped(self):
        for i, (first, last) in enumerate(((_ts(60 * 24 * 31), _ts(60)), (_ts(60), _ts(-60)),
                                           ("2026-13-40T99:00:00Z", _ts(1)),
                                           ("1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z"))):
            r = self.one(first, last, sensor=f"S{i}")              # own decoy each: no merge window
            self.assertTrue(r["first_ts"] is None or r["last_ts"] is None, (first, last, r))
            self.assertNotIn("decoy clock", r["summary"])

    def test_swapped_order_is_fixed(self):
        r = self.one(_ts(10), _ts(100))
        self.assertLess(r["first_ts"], r["last_ts"])


class _Env(unittest.TestCase):
    KEYS = ("RPOT_BIND_IP", "RPOT_SENSOR_IFACE")

    def setUp(self):
        self.saved = {k: os.environ.pop(k, None) for k in self.KEYS}

    def tearDown(self):
        for k, v in self.saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class TestBindFailClosed(_Env):
    """F8: follow mode never binds 0.0.0.0."""

    def test_no_address_raises_after_waiting(self):
        os.environ["RPOT_SENSOR_IFACE"] = "eth9"
        sleeps = []
        with mock.patch.object(base, "iface_ipv4", return_value=None), \
                mock.patch.object(base.time, "sleep", sleeps.append):
            with self.assertRaises(base.NoBindAddress):
                base.bind_ip(wait=0.05, step=0.01)
            with mock.patch.object(base.time, "monotonic", side_effect=[0.0, 0.0, 5.0, 11.0]):
                with self.assertRaises(base.NoBindAddress):
                    base.bind_ip()
        self.assertTrue(sleeps)

    def test_retry_picks_up_late_lease(self):
        os.environ["RPOT_SENSOR_IFACE"] = "eth9"
        with mock.patch.object(base, "iface_ipv4", side_effect=[None, None, "192.0.2.7"]), \
                mock.patch.object(base.time, "sleep", lambda s: None):
            self.assertEqual(base.bind_ip(wait=60), "192.0.2.7")

    def test_listeners_refuse_instead_of_wildcard(self):
        os.environ["RPOT_SENSOR_IFACE"] = "eth9"
        opened = []
        real = socket.socket

        def track(*a, **k):
            s = real(*a, **k)
            opened.append(s)
            return s
        with mock.patch.object(base, "iface_ipv4", return_value=None), mock.patch.object(base, "BIND_WAIT", 0), \
                mock.patch.object(base.socket, "socket", side_effect=track):
            with self.assertRaises(base.NoBindAddress):
                base.serve_tcp(mock.Mock(), 0, lambda *a: None, "test")
            with self.assertRaises(base.NoBindAddress):
                base.serve_udp(mock.Mock(), 0, lambda *a: None, "test")
        for s in opened:
            try:
                self.assertEqual(s.getsockname(), ("0.0.0.0", 0), "a socket was bound")   # never bound at all
            finally:
                s.close()

    def test_fixed_and_lab_modes_unchanged(self):
        self.assertEqual(base.bind_ip(), "0.0.0.0")                   # Docker-bridge lab
        os.environ["RPOT_BIND_IP"] = "10.9.9.9"
        os.environ["RPOT_SENSOR_IFACE"] = "eth9"
        self.assertEqual(base.bind_ip(), "10.9.9.9")

    def test_main_turns_it_into_a_restart_exit(self):
        src = open(os.path.join(REPO, "rpot", "sensor", "main.py")).read()
        self.assertRegex(src, r"except NoBindAddress as e:[^\n]*\n\s+raise SystemExit\(")


ENTRY = os.path.join(REPO, "deploy", "entrypoint.sh")


class TestEntrypoint(unittest.TestCase):
    """F5 entrypoint logic with stub id/setpriv/python on PATH (absolute /usr/local/bin paths are only argv)."""

    def run_ep(self, uid, *args, **env):
        with tempfile.TemporaryDirectory() as d:
            # sed = the real sed on a fake /proc/self/status (R2-4 CapEff read); default CapEff 0x5c0 =
            # NET_BIND_SERVICE + SETUID + SETGID + SETPCAP, as the container starts
            status = os.path.join(d, "status")
            with open(status, "w") as f:
                f.write("Name:\tsh\nCapInh:\t0000000000000000\nCapEff:\t"
                        + env.pop("STUB_CAPEFF", "00000000000005c0") + "\nNoNewPrivs:\t1\n")
            real_sed = shutil.which("sed")
            for name, body in (("id", f'echo {uid}'), ("setpriv", 'echo "SETPRIV $*"'), ("python", 'echo "PYTHON $*"'),
                               ("sed", f'[ "$3" = /proc/self/status ] || exit 99; exec {real_sed} "$1" "$2" {status}')):
                p = os.path.join(d, name)
                with open(p, "w") as f:
                    f.write(f"#!/bin/sh\n{body}\n")
                os.chmod(p, 0o755)
            e = {"PATH": d + ":/usr/bin:/bin", **env}
            return subprocess.run(["sh", ENTRY, *args], capture_output=True, text=True, env=e, timeout=30)

    def test_syntax(self):
        for sh in ("sh", "dash", "bash"):
            if shutil.which(sh):
                r = subprocess.run([sh, "-n", ENTRY], capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 0, (sh, r.stderr))

    def test_privdrop_sensor(self):
        r = self.run_ep(0, "sensor", "--x", "1", RPOT_PRIVDROP="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(),
                         "SETPRIV --reuid 10001 --regid 10001 --clear-groups --bounding-set -all,+net_bind_service "
                         "--inh-caps -all,+net_bind_service "
                         "--ambient-caps +net_bind_service --no-new-privs -- /usr/local/bin/python-lowports "
                         "-m rpot.sensor.main --x 1")

    def test_privdrop_fails_closed(self):
        r = self.run_ep(10001, "sensor", RPOT_PRIVDROP="1")
        self.assertEqual(r.returncode, 78)
        self.assertIn("needs the container to start as root", r.stderr)
        self.assertNotIn("PYTHON", r.stdout)
        for role in ("console", "relay", "ctl", "sh"):
            r = self.run_ep(0, role, RPOT_PRIVDROP="1")
            self.assertEqual(r.returncode, 78, role)
            self.assertEqual(r.stdout, "")

    def test_privdrop_needs_setpcap_for_the_bounding_set(self):
        """R2-4: setpriv --bounding-set needs CAP_SETPCAP (util-linux: 'apply bounding set: Operation not
        permitted'); without it the entrypoint refuses with a clear message instead of a setpriv error."""
        for capeff in ("00000000000004c0", "", "zz", "1$(reboot)"):  # no SETPCAP in compose, unreadable, garbage
            r = self.run_ep(0, "sensor", RPOT_PRIVDROP="1", STUB_CAPEFF=capeff)
            self.assertEqual(r.returncode, 78, capeff)
            self.assertIn("needs CAP_SETPCAP", r.stderr)
            self.assertEqual(r.stdout, "")
        r = self.run_ep(0, "sensor", RPOT_PRIVDROP="1", STUB_CAPEFF="0000000000000100")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--bounding-set -all,+net_bind_service", r.stdout)

    def test_root_without_privdrop_fails_closed(self):
        """R2-5: a compose with user "0:0" but no RPOT_PRIVDROP=1 must not run a service role as uid 0."""
        for role in ("console", "sensor", "relay"):
            for env in ({}, {"RPOT_PRIVDROP": "0"}, {"RPOT_LOWPORTS": "1"}):
                r = self.run_ep(0, role, **env)
                self.assertEqual(r.returncode, 78, (role, env))
                self.assertIn("refusing to run the " + role + " role as root", r.stderr)
                self.assertEqual(r.stdout, "")
        self.assertEqual(self.run_ep(0, "ctl", "slots").stdout.strip(),                   # installer: docker run --user 0 ctl
                         "PYTHON /opt/rpot/rpotctl.py slots")

    def test_entrypoint_text_has_the_flags(self):
        with open(ENTRY) as f:
            t = f.read()
        self.assertIn("--bounding-set -all,+net_bind_service", t)
        self.assertIn("/proc/self/status", t)

    def test_other_modes_unchanged(self):
        self.assertEqual(self.run_ep(10001, "console").stdout.strip(), "PYTHON -m rpot.console.app")
        self.assertEqual(self.run_ep(10001, "relay").stdout.strip(), "PYTHON -m rpot.sensor.relay")
        self.assertEqual(self.run_ep(10001, "sensor").stdout.strip(), "PYTHON -m rpot.sensor.main")
        if not os.path.exists("/usr/local/bin/python-lowports"):       # installer remote-sensor compose (unchanged)
            r = self.run_ep(10001, "sensor", RPOT_LOWPORTS="1")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("python-lowports", r.stderr)                   # it tried to exec the file-cap copy
            self.assertNotIn("SETPRIV", r.stdout)


class TestDockerfile(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(REPO, "Dockerfile")) as f:
            self.df = f.read()

    def test_setuid_setgid_strip_after_last_file_change(self):
        lines = [x.strip() for x in self.df.splitlines()]
        strip = next(i for i, x in enumerate(lines) if "find / -xdev -perm /6000 -type f -exec chmod a-s {} +" in x)
        self.assertTrue(lines[strip].startswith("RUN "))
        self.assertIn('test -z "$(find / -xdev -perm /6000 -type f)"', self.df)   # build fails if any remain
        last_change = max(i for i, x in enumerate(lines) if x.startswith(("COPY ", "ADD ", "RUN ")) and i != strip
                          and "find / -xdev" not in x)
        self.assertGreater(strip, last_change)
        self.assertGreater(lines.index("USER rpot"), strip)

    def test_setpriv_required(self):
        self.assertIn("command -v setpriv", self.df)
        self.assertNotRegex(self.df, r"apt-get (remove|purge)[^\n]*util-linux")


if __name__ == "__main__":
    unittest.main()
