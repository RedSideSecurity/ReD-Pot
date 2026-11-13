"""CE 1.0 removed-features gate (design T12 + addendum S-1 L16, decisions D-1..D-9).

Features removed from the Community Edition live only in the Enterprise repo. This gate scans every
shipped path for traces of them, and checks that the D-6 decoy cap (MAX_DECOYS + limit_message) is the
same everywhere it is enforced.

Hits are reported per term with file:line. A hit is either
  * EXEMPT  - legitimate CE code that happens to match (listed below with the reason), or
  * KNOWN   - a real leftover already reported on RC-13 (finding id G<n>); the test is marked xfail so the
              gate is green-but-visible until the product fix lands. Any NEW hit fails the test.
`incidents.alerted_level` is allowed (documented in rpot/console/engine.py: dedupe of alert records on disk).
"""
import ast
import os
import re
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "installer"))

SHIPPED = ("rpot", "rpotctl.py", "installer", "install.sh", "deploy", "roles", "Dockerfile", "requirements.txt")
SKIP_DIRS = {"__pycache__", ".pytest_cache"}
SKIP_EXT = {".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".mmdb", ".zip"}

I = re.IGNORECASE
# (id, regex, flags). Word-bounded / case rules chosen so CE text does not trip them
# (e.g. the bait text "Print spooler" must not match the spool term).
TERMS = [
    ("telegram", r"telegram", I),                                   # also covers api.telegram.org
    ("api.telegram.org", r"api\.telegram\.org", I),
    ("webhook", r"webhook", I),
    ("macvlan", r"macvlan", I),                                     # also covers --macvlan
    ("--macvlan", r"--macvlan", I),
    ("mac_address", r"mac_address", I),
    ("OUI", r"\bOUI\b", 0),
    ("hostnet", r"hostnet", I),
    ("decoy_nets", r"decoy_nets", I),
    ("own-ip flag", r"--own[-_]ip\b|\bown_ip\b", I),               # prose "own-IP" (the CE topology) is fine
    ("spool", r"\bspool\b|_spool", I),
    ("SPOOL", r"SPOOL", 0),                                         # also covers RPOT_SPOOL_MAX_MB
    ("RPOT_SPOOL_MAX_MB", r"RPOT_SPOOL_MAX_MB", 0),
    ("_replay", r"_replay", I),
    ("user-format", r"user[-_]format", 0),                          # USER_FORMATS (D-8 built-in table) is fine
    ("--placement", r"--placement\b", I),
    ("--decoy-ips", r"--decoy-ips\b", I),
    ("--company", r"--company\b", I),
    ("--netbios", r"--netbios\b", I),
    ("--email-domain", r"--email-domain\b", I),
    ("--public-url", r"--public-url\b", I),
    ("public_url", r"public_url", I),
    ("--host-network", r"--host-network\b", I),
    ("MAX_PER_HOUR", r"MAX_PER_HOUR", 0),
    ("/api/alerts", r"/api/alerts\b", I),
    ("Alerter", r"\bAlerter\b", I),
    ("cmd_persona", r"\bcmd_persona\b", 0),
    ("cmd_setup", r"\bcmd_setup\b", 0),
]

# Legitimate matches: (term id, relpath, regex the stripped line must match, reason).
EXEMPT = [
    ("user-format", "rpot/baits.py", r"^user_format = rng\.choice\(sorted\(USER_FORMATS\)\)",
     "make_persona: username format picked from the install seed (D-8), not client-selectable"),
    ("user-format", "rpot/baits.py", r"^u = USER_FORMATS\[user_format\]\(f, l\)\.lower\(\)",
     "make_persona: applies the seed-picked format"),
    ("user-format", "rpot/baits.py", r'"user_format": user_format,',
     "make_persona: persona dict key user_format (read-only result, not a flag)"),
]

# Real leftovers found on ce-main @b35b62b, reported on RC-13. Remove an entry once the fix is merged.
KNOWN = []


def _shipped_files():
    for top in SHIPPED:
        p = os.path.join(REPO, top)
        if os.path.isfile(p):
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for f in sorted(files):
                if os.path.splitext(f)[1].lower() not in SKIP_EXT:
                    yield os.path.join(root, f)


def _corpus():
    out = []
    for path in _shipped_files():
        with open(path, "rb") as fh:
            raw = fh.read()
        if b"\0" in raw[:4096]:
            continue                                                # binary
        rel = os.path.relpath(path, REPO).replace(os.sep, "/")
        out.append((rel, raw.decode("utf-8", "replace").splitlines()))
    return out


CORPUS = _corpus()


def _hits(term_id):
    _, rx, flags = next(t for t in TERMS if t[0] == term_id)
    rx = re.compile(rx, flags)
    found = []
    for rel, lines in CORPUS:
        if rx.search(rel):
            found.append((rel, 0, "<file name>"))
        for n, line in enumerate(lines, 1):
            if rx.search(line):
                found.append((rel, n, line.strip()))
    return found


def _match(table, term_id, hit):
    rel, _, text = hit
    for t, f, rx, reason in table:
        if t == term_id and f == rel and re.search(rx, text):
            return reason
    return None


def test_corpus_covers_shipped_paths():
    rels = {r for r, _ in CORPUS}
    for must in ("rpotctl.py", "install.sh", "Dockerfile", "requirements.txt", "installer/redpot_install.py",
                 "deploy/entrypoint.sh", "rpot/console/app.py", "rpot/baits.py"):
        assert must in rels, f"gate does not scan {must}"
    assert len(rels) > 40


def test_print_spooler_bait_does_not_trip_spool_term():
    assert any("Print spooler" in ln for _, lines in CORPUS for ln in lines), "bait text moved? update this check"
    assert not re.search(TERMS[[t[0] for t in TERMS].index("spool")][1], "Print spooler account", I)


@pytest.mark.parametrize("term_id", [t[0] for t in TERMS])
def test_removed_feature_absent(term_id):
    hits = [h for h in _hits(term_id) if not _match(EXEMPT, term_id, h)]
    new = [h for h in hits if not _match(KNOWN, term_id, h)]
    assert not new, f"removed-feature term {term_id!r} found in shipped code:\n" + "\n".join(
        f"  {r}:{n}: {t}" for r, n, t in new)
    if hits:
        pytest.xfail("; ".join(sorted({_match(KNOWN, term_id, h) for h in hits})))


def test_exemptions_and_known_findings_are_not_stale():
    """Every EXEMPT/KNOWN entry must still match something, so the allow-lists cannot silently widen."""
    for table in (EXEMPT, KNOWN):
        for term_id, rel, rx, reason in table:
            assert any(f == rel and re.search(rx, t) for f, _, t in _hits(term_id)), \
                f"stale entry ({term_id}, {rel}): {reason}"


def test_user_format_is_persona_output_not_input():
    """The exempted user_format is a result of make_persona (seed-picked), never an argument."""
    import inspect
    from rpot import baits
    params = inspect.signature(baits.make_persona).parameters
    assert not any("format" in p for p in params)
    p = baits.make_persona("corp.example.com", "generic", seed=7)
    assert p["user_format"] in baits.USER_FORMATS
    assert p == baits.make_persona("corp.example.com", "generic", seed=7)


def test_alerted_level_is_documented():
    from rpot.console import engine
    src = open(engine.__file__, encoding="utf-8").read()
    assert "-- incidents.alerted_level:" in src


# ---------------------------------------------------------------- D-6 cap consistency
def test_max_decoys_equal_everywhere():
    from rpot.common import edition
    from rpot.console.engine import ce_limit_sql
    import redpot_install as R
    assert edition.MAX_DECOYS == 3
    assert R.MAX_DECOYS == edition.MAX_DECOYS
    sql = ce_limit_sql()
    assert set(int(x) for x in re.findall(r">= (\d+)", sql)) == {edition.MAX_DECOYS}
    assert f"ce_local WHERE id = 1), {edition.MAX_DECOYS})" in sql


def _imports_from_edition(relpath):
    tree = ast.parse(open(os.path.join(REPO, relpath), encoding="utf-8").read())
    names, local_defs = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "rpot.common.edition":
            names |= {a.name for a in node.names}
        if isinstance(node, ast.FunctionDef):
            local_defs.add(node.name)
    return names, local_defs


@pytest.mark.parametrize("relpath", ["rpotctl.py", "rpot/console/fleet.py", "rpot/console/app.py"])
def test_limit_message_imported_not_copied(relpath):
    names, local_defs = _imports_from_edition(relpath)
    assert "limit_message" in names, f"{relpath} must import limit_message from rpot.common.edition"
    assert "limit_message" not in local_defs and "MAX_DECOYS" not in local_defs


def test_installer_limit_message_copy_is_identical():
    """The installer must not import rpot, so it mirrors the message; the text must stay identical."""
    from rpot.common import edition
    import redpot_install as R
    names, _ = _imports_from_edition("installer/redpot_install.py")
    assert not names
    assert R.UPGRADE_URL == edition.UPGRADE_URL
    for used in (0, 1, 3, 4, 17):
        assert R.limit_message(used) == edition.limit_message(used)
