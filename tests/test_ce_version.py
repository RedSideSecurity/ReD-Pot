"""CE 1.0.0: single version source (rpot/__init__.py) and the edition module."""
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "installer"))

import rpot  # noqa: E402
import redpot_install as R  # noqa: E402
from rpot.common import edition  # noqa: E402


class TestVersion(unittest.TestCase):
    def test_single_source(self):
        self.assertEqual(rpot.VERSION, "1.0.0")

    def test_installer_image_derived_from_package(self):
        self.assertEqual(R.VERSION, rpot.VERSION)
        self.assertEqual(R.IMAGE, "rpot:1.0.0")
        self.assertEqual(R.REGISTRY_IMAGE, "ghcr.io/redsidesecurity/red-pot:1.0.0")

    def test_installer_reads_version_as_text(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "rpot"))
            with open(os.path.join(d, "rpot", "__init__.py"), "w") as f:
                f.write('"""doc"""\nVERSION = "9.8.7"   # comment\n')
            self.assertEqual(R._read_version(d), "9.8.7")
            with open(os.path.join(d, "rpot", "__init__.py"), "w") as f:
                f.write('"""no version here"""\n')
            with self.assertRaises(RuntimeError):
                R._read_version(d)

    def test_installer_importable_without_rpot_package(self):
        """The installer runs on the bare host; it must not import the rpot package."""
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import redpot_install as R; "
                "assert 'rpot' not in sys.modules, 'rpot imported'; print(R.IMAGE)")
        p = subprocess.run([sys.executable, "-I", "-c", code, os.path.join(REPO, "installer")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "rpot:1.0.0")

    def test_ensure_image_build_passes_version_build_arg(self):
        calls = []

        def fake_run(cmd, check=True, capture=False, quiet=False):
            calls.append(cmd)
            return types.SimpleNamespace(returncode=1 if cmd[:3] == ["docker", "image", "inspect"] else 0,
                                         stdout="", stderr="")
        with mock.patch.object(R, "A", types.SimpleNamespace(dry_run=False, build=True)), \
                mock.patch.object(R, "run", fake_run), mock.patch.object(R, "src_hash", lambda *a: "abc"), \
                mock.patch.object(R, "banner", lambda *a: None):
            R.ensure_image()
        build = [c for c in calls if c[:2] == ["docker", "build"]]
        self.assertEqual(len(build), 1)
        cmd = build[0]
        self.assertIn("VERSION=1.0.0", [cmd[i + 1] for i, a in enumerate(cmd) if a == "--build-arg"])
        self.assertEqual(cmd[cmd.index("-t") + 1], "rpot:1.0.0")

    def test_dockerfile_declares_version_arg(self):
        with open(os.path.join(REPO, "Dockerfile")) as f:
            self.assertRegex(f.read(), r"(?m)^ARG VERSION\b")

    def test_rpotctl_image_defaults(self):
        import rpotctl
        self.assertEqual(rpotctl.compose_text.__defaults__[0], "rpot:1.0.0")
        with open(os.path.join(REPO, "rpotctl.py")) as f:
            src = f.read()
        self.assertNotRegex(src, r'"rpot:\d')


class TestEdition(unittest.TestCase):
    def test_names_and_values(self):
        self.assertEqual(edition.EDITION, "community")
        self.assertEqual(edition.MAX_DECOYS, 3)
        self.assertEqual(edition.UPGRADE_URL, "https://redsidesecurity.com")
        self.assertTrue(issubclass(edition.LimitError, ValueError))

    def test_limit_message_exact(self):
        self.assertEqual(
            edition.limit_message(4),
            "ReD-Pot Community Edition supports up to 3 decoys in total (decoys on this manager plus remote "
            "sensors); this install uses 4. Remove a decoy, revoke a remote sensor or cancel a pending join "
            "first — or ask RedSide Security about ReD-Pot Enterprise: https://redsidesecurity.com")

    def test_limit_message_uses_constants(self):
        with mock.patch.object(edition, "MAX_DECOYS", 7):
            msg = edition.limit_message(11)
        self.assertIn("up to 7 decoys", msg)
        self.assertIn("this install uses 11.", msg)
        self.assertIn(edition.UPGRADE_URL, msg)


if __name__ == "__main__":
    unittest.main()
