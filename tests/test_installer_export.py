"""RC-11 / T10 + S-1 M5: `install.sh export` writes the rpotctl export into a 0600 file that appears only when
complete. docker is never run: subprocess.Popen is replaced by a fake that writes to the fd it is given."""
import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import date
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(REPO, "installer", "redpot_install.py")
sys.path.insert(0, os.path.join(REPO, "installer"))
import redpot_install as r  # noqa: E402

DOC = b'{"meta":{},"incidents":[],"alerts":[],"complete":true}\n'


class FakePopen:
    """Stands in for docker: writes `out` to the stdout fd, exits with `rc`, optional KeyboardInterrupt."""
    calls = []

    def __init__(self, out=DOC, rc=0, err=b"", interrupt=False):
        self.out, self.rc, self.err, self.interrupt = out, rc, err, interrupt
        self.killed = False

    def __call__(self, argv, **kw):
        FakePopen.calls.append((argv, kw))
        self.argv, self.kw = argv, kw
        self.returncode = None
        return self

    def communicate(self):
        os.write(self.kw["stdout"], self.out)
        if self.interrupt:
            raise KeyboardInterrupt
        self.returncode = self.rc
        return None, self.err

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self):
        return self.returncode


class ExportBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mgr = os.path.join(self.tmp.name, "mgr")
        os.mkdir(self.mgr)
        json.dump({"version": 2, "network": {"mode": "host"}, "sensors": []}, open(os.path.join(self.mgr, "rpot.json"), "w"))
        json.dump({"mgmt": "eth0"}, open(os.path.join(self.mgr, "installer.json"), "w"))
        open(os.path.join(self.mgr, "docker-compose.yml"), "w").write("services: {}\n")
        self.out = os.path.join(self.tmp.name, "out")
        os.mkdir(self.out)
        env = mock.patch.dict(os.environ, {"RPOT_CWD": self.out})
        env.start()
        self.addCleanup(env.stop)
        FakePopen.calls = []

    def args(self, frm="2026-11-01", to="2026-11-02", output=None, force=False, dry_run=False):
        r.A = types.SimpleNamespace(date_from=frm, date_to=to, output=output, force=force, dry_run=dry_run,
                                    dir=self.mgr)

    def export(self, fake=None, **kw):
        """-> (exit code or None, printed text, fake)"""
        self.args(**kw)
        fake = fake or FakePopen()
        buf = io.StringIO()
        code = None
        with mock.patch.object(r.subprocess, "Popen", fake), contextlib.redirect_stdout(buf):
            try:
                r.export_data()
            except SystemExit as e:
                code = e.code
        return code, buf.getvalue(), fake

    def leftovers(self):
        return [n for n in os.listdir(self.out) if ".tmp-" in n]

    def default(self):
        return os.path.join(self.out, "redpot-export-2026-11-01_2026-11-02.json")


class TestExportWrite(ExportBase):
    def test_writes_0600_file_with_full_output(self):
        code, out, fake = self.export()
        self.assertIsNone(code, out)
        p = self.default()
        self.assertEqual(open(p, "rb").read(), DOC)
        self.assertEqual(stat.S_IMODE(os.lstat(p).st_mode), 0o600)
        self.assertEqual(self.leftovers(), [])
        self.assertIn("Export written", out)

    def test_argv_list_no_shell(self):
        self.export()
        (argv, kw), = FakePopen.calls
        self.assertIsInstance(argv, list)
        self.assertNotIn("shell", kw)
        self.assertEqual(argv, ["docker", "compose", "-p", "redpot", "exec", "-T", "console", "python",
                                "/opt/rpot/rpotctl.py", "export", "--db", "/var/lib/rpot/rpot.db",
                                "--config", "/etc/rpot/rpot.json", "--from", "2026-11-01", "--to", "2026-11-02"])
        self.assertEqual(kw["cwd"], self.mgr)
        self.assertIsInstance(kw["stdout"], int)          # streamed into the temp file's fd, not captured

    def test_temp_is_o_excl_nofollow_0600_in_target_dir(self):
        real_open = os.open
        seen = []

        def spy(path, flags, mode=0o777, **kw):
            seen.append((path, flags, mode))
            return real_open(path, flags, mode, **kw)
        with mock.patch.object(r.os, "open", spy):
            code, out, _ = self.export(output="x.json")
        self.assertIsNone(code, out)
        path, flags, mode = seen[0]
        self.assertEqual(os.path.dirname(path), self.out)
        self.assertTrue(os.path.basename(path).startswith(".x.json.tmp-"))
        for f in (os.O_WRONLY, os.O_CREAT, os.O_EXCL, os.O_NOFOLLOW):
            self.assertTrue(flags & f, f)
        self.assertEqual(mode, 0o600)

    def test_temp_never_follows_or_clobbers(self):
        """O_EXCL|O_NOFOLLOW: a planted name is skipped, not opened."""
        fd, tmp = r._export_tmp(os.path.join(self.out, "y.json"))
        os.close(fd)
        self.assertEqual(stat.S_IMODE(os.lstat(tmp).st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

    def test_relative_output_is_relative_to_caller_cwd(self):
        os.mkdir(os.path.join(self.out, "sub"))
        code, out, _ = self.export(output="sub/e.json")
        self.assertIsNone(code, out)
        self.assertTrue(os.path.isfile(os.path.join(self.out, "sub", "e.json")))

    def test_existing_file_refused_without_force(self):
        open(self.default(), "w").write("keep")
        code, out, _ = self.export()
        self.assertEqual(code, 1)
        self.assertIn("already exists", out)
        self.assertEqual(open(self.default()).read(), "keep")
        self.assertEqual(FakePopen.calls, [])

    def test_force_replaces_own_regular_file(self):
        open(self.default(), "w").write("old")
        os.chmod(self.default(), 0o644)
        code, out, _ = self.export(force=True)
        self.assertIsNone(code, out)
        self.assertEqual(open(self.default(), "rb").read(), DOC)
        self.assertEqual(stat.S_IMODE(os.lstat(self.default()).st_mode), 0o600)

    def test_dry_run_writes_nothing(self):
        code, out, _ = self.export(dry_run=True)
        self.assertIsNone(code, out)
        self.assertEqual(os.listdir(self.out), [])
        self.assertEqual(FakePopen.calls, [])
        self.assertIn("docker compose -p redpot exec -T console", out)


class TestForceRefuses(ExportBase):
    """--force only replaces a regular file owned by euid with one link (lstat; nothing is opened)."""

    def refused(self, why):
        code, out, _ = self.export(force=True)
        self.assertEqual(code, 1, out)
        self.assertIn(why, out)
        self.assertEqual(FakePopen.calls, [])
        self.assertEqual(self.leftovers(), [])

    def test_symlink(self):
        victim = os.path.join(self.tmp.name, "victim")
        open(victim, "w").write("v")
        os.symlink(victim, self.default())
        self.refused("symbolic link")
        self.assertEqual(open(victim).read(), "v")
        self.assertTrue(os.path.islink(self.default()))

    def test_dangling_symlink(self):
        os.symlink(os.path.join(self.tmp.name, "nowhere"), self.default())
        self.refused("symbolic link")
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "nowhere")))

    def test_fifo_without_blocking(self):
        os.mkfifo(self.default())
        self.refused("FIFO")          # would hang here if the FIFO were opened

    def test_device(self):
        real = os.lstat
        dev = os.stat_result((stat.S_IFCHR | 0o666, 1, 1, 1, os.geteuid(), 0, 0, 0, 0, 0))
        with mock.patch.object(r.os, "lstat", lambda p: dev if p == self.default() else real(p)):
            self.refused("device")

    def test_directory(self):
        os.mkdir(self.default())
        self.refused("directory")

    def test_hard_link(self):
        open(self.default(), "w").write("x")
        os.link(self.default(), os.path.join(self.tmp.name, "other"))
        self.refused("hard links")

    def test_foreign_owner(self):
        open(self.default(), "w").write("x")
        uid = os.lstat(self.default()).st_uid
        with mock.patch.object(r.os, "geteuid", lambda: uid + 1):
            self.refused("belongs to uid")
        self.assertEqual(open(self.default()).read(), "x")


class TestFailuresLeaveNothing(ExportBase):
    def check_clean(self, code, out):
        self.assertEqual(code, 1, out)
        self.assertEqual(os.listdir(self.out), [])

    def test_exit_2_bad_range(self):
        code, out, _ = self.export(FakePopen(out=b"", rc=2, err=b"error: 'to' is in the future\n"))
        self.check_clean(code, out)
        self.assertIn("'to' is in the future", out)

    def test_exit_3_too_large_hints_narrowing(self):
        code, out, _ = self.export(FakePopen(out=b'{"meta":{},"incidents":[', rc=3,
                                             err=b"\nerror: export cut off at the 209715200-byte limit\n"))
        self.check_clean(code, out)
        self.assertIn("cut off", out)
        self.assertIn("narrow the date range", out)

    def test_docker_failure(self):
        code, out, _ = self.export(FakePopen(out=b"", rc=1, err=b"service \"console\" is not running\x1b[31m\n"))
        self.check_clean(code, out)
        self.assertIn("is not running", out)
        self.assertNotIn("\x1b[31m", out)
        self.assertIn("systemctl start redpot", out)

    def test_docker_missing(self):
        def boom(argv, **kw):
            raise FileNotFoundError(2, "No such file or directory", "docker")
        code, out, _ = self.export(boom)
        self.check_clean(code, out)
        self.assertIn("could not run docker", out)

    def test_empty_output(self):
        code, out, _ = self.export(FakePopen(out=b""))
        self.check_clean(code, out)

    def test_keyboard_interrupt(self):
        fake = FakePopen(out=b'{"meta":', interrupt=True)
        self.args()
        with mock.patch.object(r.subprocess, "Popen", fake), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                r.export_data()
        self.assertEqual(os.listdir(self.out), [])
        self.assertTrue(fake.killed)

    def test_failure_with_force_keeps_old_file(self):
        open(self.default(), "w").write("old")
        code, out, _ = self.export(FakePopen(out=b"partial", rc=3, err=b"too large"), force=True)
        self.assertEqual(code, 1)
        self.assertEqual(os.listdir(self.out), [os.path.basename(self.default())])
        self.assertEqual(open(self.default()).read(), "old")


class TestValidationBeforeDocker(ExportBase):
    def test_bad_dates_refused_before_docker(self):
        for frm, to in [("2026-11-1", "2026-11-02"), ("２０２６-11-01", "2026-11-02"), ("2026-13-01", "2026-11-02"),
                        ("2026-11-03", "2026-11-02"), ("1999-12-31", "2000-01-01"), ("2024-01-01", "2026-01-01"),
                        ("2026-11-01", "2999-01-01"), (None, "2026-11-02"), ("2026-11-01\n", "2026-11-02")]:
            FakePopen.calls = []
            code, out, _ = self.export(frm=frm, to=to)
            self.assertEqual(code, 1, (frm, to, out))
            self.assertIn("export:", out)
            self.assertEqual(FakePopen.calls, [], (frm, to))
            self.assertEqual(os.listdir(self.out), [])

    def test_same_rule_as_console_parse_dates(self):
        from rpot.console import export as X
        today = date(2026, 11, 13)
        for frm, to in [("2026-11-01", "2026-11-14"), ("2026-11-01", "2026-11-15"), ("2000-01-01", "2000-12-31"),
                        ("2000-01-01", "2001-01-01"), ("2000-01-01", "2001-01-02"), ("1999-12-31", "2000-01-01"),
                        ("2026-02-29", "2026-03-01"), ("2024-02-29", "2024-03-01"), ("2026-1-01", "2026-11-01"),
                        ("2026-11-02", "2026-11-01"), ("", "2026-11-01"), ("2026-11-01x", "2026-11-02")]:
            try:
                want = X.parse_dates(frm, to, today)
            except ValueError:
                want = None
            try:
                got = r.export_dates(frm, to, today)
            except ValueError:
                got = None
            self.assertEqual(got, want, (frm, to))

    def test_no_manager_install(self):
        for missing in ("installer.json", "rpot.json", "docker-compose.yml"):
            with self.subTest(missing=missing):
                p = os.path.join(self.mgr, missing)
                saved = open(p).read()
                os.unlink(p)
                code, out, _ = self.export()
                self.assertEqual(code, 1, out)
                self.assertEqual(FakePopen.calls, [])
                open(p, "w").write(saved)

    def test_old_config_version_refused(self):
        json.dump({"version": 1}, open(os.path.join(self.mgr, "rpot.json"), "w"))
        code, out, _ = self.export()
        self.assertEqual(code, 1)
        self.assertIn("fresh installs only", out)
        self.assertEqual(FakePopen.calls, [])

    def test_missing_target_dir(self):
        code, out, _ = self.export(output="nodir/x.json")
        self.assertEqual(code, 1)
        self.assertIn("does not exist", out)


class TestCli(unittest.TestCase):
    def test_help_documents_export(self):
        p = subprocess.run([sys.executable, INSTALLER, "--help"], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0)
        for s in ("export", "--from", "--to", "--output", "0600", "narrow the date range"):
            self.assertIn(s, p.stdout)

    def test_must_be_root(self):
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["redpot_install.py", "export", "--from", "2026-11-01", "--to",
                                             "2026-11-02"]), \
                mock.patch.object(r.os, "geteuid", lambda: 1000), \
                mock.patch.object(r, "export_data", side_effect=AssertionError("ran without root")), \
                contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                r.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("run as root", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
