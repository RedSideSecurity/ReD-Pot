"""RC-33: the release workflow and the installer must agree on the image and its source hash.

The installer accepts ghcr.io/redsidesecurity/red-pot:<VERSION> only if the label io.redside.src-sha256 equals
src_hash() of the checkout. The release workflow therefore computes SRC_SHA by importing the installer and calling
src_hash() itself. These tests check that statically (no second hash implementation, build-args wired to that
output) and run the workflow's own meta / notes scripts against this checkout. Text-based on purpose: PyYAML is not
a project dependency.
"""
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(REPO, ".github", "workflows")
sys.path.insert(0, os.path.join(REPO, "installer"))

import redpot_install as R  # noqa: E402

LABEL = "io.redside.src-sha256"


def _read(*p):
    with open(os.path.join(*p), encoding="utf-8") as f:
        return f.read()


def _step_script(wf_text, step_id):
    """The python heredoc of the step with `id: <step_id>`, dedented as the YAML block scalar would be."""
    m = re.search(rf"^\s+id: {re.escape(step_id)}\n(.*?)^\s+python3 -I - <<'PY'\n(.*?)^\s+PY\n", wf_text, re.M | re.S)
    assert m, f"step {step_id} with a python heredoc not found"
    assert "\n      - " not in m.group(1), f"heredoc does not belong to step {step_id}"
    return textwrap.dedent(m.group(2))


def _run_script(script, env_extra):
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "github_output")
        open(out, "w").close()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GITHUB_WORKSPACE": REPO, "GITHUB_OUTPUT": out}
        env.update(env_extra)
        p = subprocess.run([sys.executable, "-I", "-"], input=script, capture_output=True, text=True,
                           cwd=REPO, env=env, timeout=60)
        return p, _read(out)


class TestReleaseWorkflowStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rel = _read(WF, "release.yml")
        cls.ci = _read(WF, "ci.yml")

    def test_src_sha_comes_from_installer_src_hash(self):
        meta = _step_script(self.rel, "meta")
        self.assertIn("import redpot_install as inst", meta)
        self.assertRegex(meta, r"src_sha = inst\.src_hash\(\)")
        self.assertIn("ref = inst.REGISTRY_IMAGE", meta)
        self.assertIn('"v" + version', meta)
        self.assertIn("version = os.environ[\"TAG\"], inst.VERSION", meta)
        self.assertIn("src_sha: ${{ steps.meta.outputs.src_sha }}", self.rel)

    def test_no_second_hash_implementation(self):
        for needle in ("hashlib", "sha256sum", "os.walk", "SRC_PATHS", "shasum", "openssl dgst"):
            self.assertNotIn(needle, self.rel, f"release.yml must not hash the source itself ({needle})")
        self.assertEqual(self.rel.count("inst.src_hash()"), 2)   # meta + build-context re-check

    def test_build_args_and_tag_wired_to_meta(self):
        self.assertIn("SRC_SHA=${{ needs.meta.outputs.src_sha }}", self.rel)
        self.assertIn("VERSION=${{ needs.meta.outputs.version }}", self.rel)
        self.assertIn("tags: ${{ needs.meta.outputs.ref }}", self.rel)
        self.assertIn("platforms: linux/amd64,linux/arm64", self.rel)
        self.assertIn("context: .", self.rel)
        self.assertNotRegex(self.rel, r"(?m)^[^#\n]*:latest")   # no :latest outside comments

    def test_label_name_matches_dockerfile_and_installer(self):
        self.assertIn(f'{LABEL}="${{SRC_SHA}}"', _read(REPO, "Dockerfile"))
        self.assertIn(f'.Config.Labels "{LABEL}"', _read(REPO, "installer", "redpot_install.py"))
        self.assertIn(f'.Config.Labels "{LABEL}"', self.rel)
        self.assertIn(f'labels.get("{LABEL}")', self.rel)

    def test_tag_trigger(self):
        self.assertRegex(self.rel, r'on:\n  push:\n    tags: \["v\*\.\*\.\*"\]')

    def test_actions_pinned_by_sha(self):
        for name in sorted(os.listdir(WF)):
            text = _read(WF, name)
            for line in re.findall(r"^\s*(?:- )?uses: (.+)$", text, re.M):
                if line.startswith("./"):
                    continue
                self.assertRegex(line, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$", f"{name}: {line}")

    def test_least_privilege_and_no_extra_secrets(self):
        self.assertRegex(self.rel, r"(?m)^permissions: \{\}$")
        self.assertRegex(self.ci, r"(?m)^permissions:\n  contents: read$")
        for name, text in (("release.yml", self.rel), ("ci.yml", self.ci)):
            self.assertEqual(set(re.findall(r"\$\{\{\s*secrets\.(\w+)", text)) - {"GITHUB_TOKEN"}, set(), name)
            self.assertNotIn("write-all", text, name)
        self.assertEqual(self.rel.count("packages: write"), 1)
        self.assertEqual(self.rel.count("contents: write"), 1)


class TestReleaseWorkflowScripts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rel = _read(WF, "release.yml")

    def test_meta_script_matches_installer(self):
        p, out = _run_script(_step_script(self.rel, "meta"), {"TAG": "v" + R.VERSION, "OWNER": "RedSideSecurity"})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        got = dict(line.split("=", 1) for line in out.splitlines())
        self.assertEqual(got["src_sha"], R.src_hash())
        self.assertEqual(got["version"], R.VERSION)
        self.assertEqual(got["ref"], R.REGISTRY_IMAGE)
        self.assertEqual(got["image"], "ghcr.io/redsidesecurity/red-pot")
        self.assertEqual(got["prerelease"], "false")

    def test_meta_script_refuses_wrong_tag_or_owner(self):
        p, out = _run_script(_step_script(self.rel, "meta"), {"TAG": "v0.0.1", "OWNER": "RedSideSecurity"})
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("does not match", p.stdout)
        self.assertEqual(out, "")
        p, out = _run_script(_step_script(self.rel, "meta"), {"TAG": "v" + R.VERSION, "OWNER": "someone-else"})
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(out, "")

    def test_notes_script_extracts_changelog_section(self):
        p, out = _run_script(_step_script(self.rel, "notes"), {"VERSION": R.VERSION})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        m = re.fullmatch(r"notes<<(EOF_[0-9a-f]{32})\n(.*)\n\1\n", out, re.S)
        self.assertTrue(m, out[:200])
        self.assertIn("Community Edition", m.group(2))
        self.assertNotIn(f"## {R.VERSION}", m.group(2))
        p, out = _run_script(_step_script(self.rel, "notes"), {"VERSION": "9.9.9"})
        self.assertNotEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
