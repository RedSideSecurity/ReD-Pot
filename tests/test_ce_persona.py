"""CE 1.0.0 persona (D-1/D-3/D-8, design T2 + addendum L15): the client sets only the domain and
the industry profile; company, NetBIOS, mail domain, users and username format are derived."""
import inspect
import itertools
import json
import os
import random
import re
import statistics
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from rpot import baits as B  # noqa: E402

CTL = os.path.join(REPO, "rpotctl.py")
KEYS = {"name", "word", "profile", "domain", "netbios", "email_domain", "user_format", "users", "seed"}
FORMAT_RE = {"f.last": r"^[a-z]\.[a-z]+$", "first.last": r"^[a-z]+\.[a-z]+$",
             "flast": r"^[a-z]+$", "first_l": r"^[a-z]+_[a-z]$"}


def ctl(*args):
    return subprocess.run([sys.executable, CTL, *args], capture_output=True, text=True, timeout=120,
                          env=dict(os.environ, RPOT_INSTALLER="1"), stdin=subprocess.DEVNULL)


class TestSignature(unittest.TestCase):
    def test_signature_and_keys(self):
        sig = inspect.signature(B.make_persona)
        self.assertEqual(list(sig.parameters), ["domain", "profile", "seed", "n_users"])
        self.assertEqual(sig.parameters["profile"].default, "generic")
        self.assertIsNone(sig.parameters["seed"].default)
        self.assertEqual(sig.parameters["n_users"].default, 14)
        p = B.make_persona("corp.araratbank.am", "bank", seed=1)
        self.assertEqual(set(p), KEYS)
        self.assertEqual(len(p["users"]), 14)
        self.assertEqual(len(B.make_persona("x.local", seed=1, n_users=3)["users"]), 3)

    def test_unknown_profile_falls_back_to_generic(self):
        self.assertEqual(B.make_persona("x.local", "nope", seed=1)["profile"], "generic")
        self.assertEqual(B.make_persona("x.local", "hotel", seed=1)["profile"], "hotel")


class TestDerivation(unittest.TestCase):
    def test_company_from_domain(self):
        cases = {"ararat-bank.am": "Ararat Bank", "corp.araratbank.am": "Araratbank",
                 "ad.acme-corp.example.com": "Acme Corp", "corp.com": "Corp", "123.com": "123",
                 "a--b.local": "A B", "Corp.ARARAT-Bank.AM": "Ararat Bank"}
        for dom, want in cases.items():
            self.assertEqual(B.company_from_domain(dom), want, dom)
        long_label = "a" * 63 + ".com"
        self.assertTrue(B.valid_company(B.company_from_domain(long_label)))

    def test_persona_fields(self):
        p = B.make_persona("corp.ararat-bank.am", "bank", seed=3)
        self.assertEqual((p["name"], p["word"], p["domain"], p["netbios"], p["email_domain"]),
                         ("Ararat Bank", "Ararat", "corp.ararat-bank.am", "ARARATBANK", "ararat-bank.am"))
        q = B.make_persona("Acme.LOCAL", "it", seed=3)
        self.assertEqual((q["name"], q["domain"], q["netbios"], q["email_domain"]),
                         ("Acme", "acme.local", "ACME", "acme.com"))
        for u in p["users"]:
            self.assertTrue(u["email"].endswith("@ararat-bank.am"))
            self.assertIn(u["dept"], B.PROFILES["bank"]["depts"])

    def test_xn_core_label_rejected_with_hint(self):
        for dom in ("xn--80ak6aa92e.com", "corp.xn--80ak6aa92e.am", "XN--80AK6AA92E.am"):
            for fn in (B.company_from_domain, B.make_persona):
                with self.assertRaises(ValueError) as cm:
                    fn(dom)
                self.assertIn("ASCII", str(cm.exception))
        self.assertEqual(B.make_persona("example.xn--p1ai", seed=1)["name"], "Example")   # only the core label matters

    def test_invalid_domains(self):
        for dom in (None, "", "local", "bad_domain.com", "a..b", "-x.com", "x-.com", "a.b.", "<b>.com", 5):
            with self.assertRaises(ValueError, msg=repr(dom)):
                B.make_persona(dom)
            with self.assertRaises(ValueError, msg=repr(dom)):
                B.company_from_domain(dom)


class TestUserPool(unittest.TestCase):
    def test_pool_size_and_shape(self):
        self.assertGreaterEqual(len(B.FIRST), 60)
        self.assertGreaterEqual(len(B.LAST), 60)
        self.assertEqual(len(set(B.FIRST)), len(B.FIRST))
        self.assertEqual(len(set(B.LAST)), len(B.LAST))
        for n in B.FIRST + B.LAST:
            self.assertRegex(n, r"^[A-Z][a-z]+$")

    def test_format_derived_from_seed(self):
        seen = set()
        for seed in range(1, 201):
            p = B.make_persona("corp.example.com", "generic", seed=seed)
            self.assertEqual(p["user_format"], random.Random(seed).choice(sorted(B.USER_FORMATS)))
            self.assertEqual(p, B.make_persona("corp.example.com", "generic", seed=seed))     # deterministic
            for u in p["users"]:
                self.assertRegex(u["username"], FORMAT_RE[p["user_format"]])
            self.assertEqual(len({u["username"] for u in p["users"]}), 14)
            seen.add(p["user_format"])
        self.assertEqual(seen, set(B.USER_FORMATS))                    # installs differ in format

    def test_median_pairwise_overlap(self):
        sets = [{u["full_name"] for u in B.make_persona("corp.example.com", seed=s)["users"]} for s in range(1, 201)]
        overlaps = [len(a & b) for a, b in itertools.combinations(sets, 2)]
        self.assertLessEqual(statistics.median(overlaps), 1)

    def test_random_seed_without_argument(self):
        a, b = B.make_persona("x.local"), B.make_persona("x.local")
        self.assertNotEqual([u["full_name"] for u in a["users"]], [u["full_name"] for u in b["users"]])


class TestRpotctlInit(unittest.TestCase):
    def test_init_requires_domain(self):
        with tempfile.TemporaryDirectory() as d:
            r = ctl("init", "-d", d, "--sensor", "FS01=windows-file-server")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--domain", r.stderr)
            self.assertFalse(os.path.exists(os.path.join(d, "rpot.json")))

    def test_removed_persona_flags_fail(self):
        with tempfile.TemporaryDirectory() as d:
            for flag, val in (("--company", "X Corp"), ("--netbios", "XC"), ("--email-domain", "x.com"),
                              ("--user-format", "flast")):
                r = ctl("init", "-d", d, "--domain", "x.local", flag, val, "--sensor", "FS01=windows-file-server")
                self.assertNotEqual(r.returncode, 0, flag)
                self.assertIn("unrecognized arguments", r.stderr)
                self.assertFalse(os.path.exists(os.path.join(d, "rpot.json")))

    def test_init_xn_domain_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            r = ctl("init", "-d", d, "--domain", "corp.xn--80ak6aa92e.am", "--sensor", "FS01=windows-file-server")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("ASCII", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_init_derives_persona(self):
        with tempfile.TemporaryDirectory() as d:
            r = ctl("init", "-d", d, "--domain", "corp.ararat-bank.am", "--profile", "bank",
                    "--sensor", "FS01=windows-file-server")
            self.assertEqual(r.returncode, 0, r.stderr[-800:])
            with open(os.path.join(d, "rpot.json")) as f:
                co = json.load(f)["company"]
            self.assertEqual((co["name"], co["netbios"], co["email_domain"], co["profile"]),
                             ("Ararat Bank", "ARARATBANK", "ararat-bank.am", "bank"))
            self.assertIn(co["user_format"], B.USER_FORMATS)

    def test_persona_and_setup_subcommands_gone(self):
        for sub in ("persona", "setup"):
            r = ctl(sub, "-d", "x")
            self.assertEqual(r.returncode, 2, sub)
            self.assertIn("invalid choice", r.stderr)
        src = open(CTL).read()
        for name in ("cmd_persona", "cmd_setup", "def _ask", "def _num", "def _is_net", "def _in(", "input("):
            self.assertNotIn(name, src)
        self.assertIsNone(re.search(r"--(company|netbios|email-domain|user-format)\b", src))


if __name__ == "__main__":
    unittest.main()
