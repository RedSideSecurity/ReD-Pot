"""RC-12 (design T11): console UI for CE 1.0 (JSON export toolbar, decoy slots, edition label).

No headless browser is available on the build box, so these are JS-free checks: the served page has the
new elements, the scripts stay CSP-clean (no inline scripts/handlers), server text goes through esc() or
textContent, requests carry the CSRF header, and nothing of the removed alert delivery is left in the UI."""
import contextlib
import io
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.console.app import create_app  # noqa: E402
from test_unit import mkcfg  # noqa: E402

STATIC = os.path.join(ROOT, "rpot", "console", "static")


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as f:
        return f.read()


def js_balanced(src):
    """Small JS lexer: checks (), [], {} and template-literal nesting, skipping strings, comments and
    regex literals. Not a parser; it catches the typical broken-edit mistakes without a JS engine."""
    stack, i, n, prev = [], 0, len(src), ""
    pairs = {")": "(", "]": "[", "}": "{"}
    regex_ok = set("(,=:[!&|?{};+-*%<>~^") | {""}
    while i < n:
        c = src[i]
        if c in " \t\r\n":
            i += 1
            continue
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            assert j >= 0, "unterminated comment"
            i = j + 2
            continue
        if c in "'\"":
            j = i + 1
            while src[j] != c:
                assert src[j] != "\n", f"newline in string at {i}"
                j += 2 if src[j] == "\\" else 1
            i, prev = j + 1, "s"
            continue
        if c == "`" or (c == "}" and stack and stack[-1] == "${"):
            if c == "}":
                stack.pop()
            j = i + 1
            while True:
                assert j < n, "unterminated template"
                if src[j] == "\\":
                    j += 2
                elif src[j] == "`":
                    i, prev = j + 1, "s"
                    break
                elif src.startswith("${", j):
                    stack.append("${")
                    i, prev = j + 2, "("
                    break
                else:
                    j += 1
            continue
        if c == "/" and (prev in regex_ok or prev in ("return", "typeof")):
            j, cls = i + 1, False
            while cls or src[j] != "/":
                assert src[j] != "\n", f"unterminated regex at {i}"
                if src[j] == "\\":
                    j += 1
                elif src[j] == "[":
                    cls = True
                elif src[j] == "]":
                    cls = False
                j += 1
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            i, prev = j, "s"
            continue
        if c in "([{":
            stack.append(c)
        elif c in ")]}":
            assert stack and stack[-1] == pairs[c], f"unbalanced {c!r} at offset {i}: {src[max(0, i - 60):i + 1]!r}"
            stack.pop()
        m = re.match(r"[A-Za-z_$][\w$]*", src[i:])
        if m:
            prev = m.group(0)
            i += len(prev)
            continue
        prev = c
        i += 1
    assert not stack, f"unclosed {stack}"
    return True


class TestServedConsole(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        cfg = mkcfg(self._tmp.name)
        with contextlib.redirect_stdout(io.StringIO()):
            self.app = create_app(cfg, os.path.join(self._tmp.name, "c.db"))
        self.c = self.app.test_client()
        self.c.post("/login", data={"token": "at"})

    def tearDown(self):
        self.app.engine.db.close()
        self._tmp.cleanup()

    def test_index_has_new_elements_under_strict_csp(self):
        r = self.c.get("/")
        html = r.get_data(as_text=True)
        for el in ('id="edition"', 'id="xfrom"', 'id="xto"', 'id="xbtn"', 'id="xerr"', 'id="fslots"', 'id="ffull"', 'id="fadd"'):
            self.assertIn(el, html)
        self.assertEqual(len(re.findall(r'type="date"', html)), 2)
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self';", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp.split("script-src")[1].split(";")[0])
        self.assertEqual(self.c.get("/static/app.js").status_code, 200)

    def test_summary_and_fleet_fields_the_ui_reads(self):
        self.assertEqual(self.c.get("/api/summary").get_json()["edition"], "community")
        lim = self.c.get("/api/fleet").get_json()["limit"]
        for k in ("max", "used", "full", "message", "edition", "local", "remote", "pending"):
            self.assertIn(k, lim)


    def test_join_string_is_never_in_the_command(self):
        """RC-22 / VM defect B7: the command to run is 'sudo ./install.sh sensor' with no token; the one-time join
        string comes separately, for pasting into the installer's Join step (or --join-file / --join -)."""
        from test_ce_limits import local
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp, sensors=[local(0)])                       # one local decoy: slots free
            with contextlib.redirect_stdout(io.StringIO()):
                app = create_app(cfg, os.path.join(tmp, "c.db"))
            try:
                c = app.test_client()
                c.post("/login", data={"token": "at"})
                r = c.post("/api/fleet/enroll", json={"name": "RS-WEB-09", "role": "linux-web-hosting"},
                           headers={"X-Requested-With": "rpot"})
                body = r.get_data(as_text=True)
            finally:
                app.engine.db.close()
        self.assertEqual(r.status_code, 200, body)
        d = r.get_json()
        self.assertEqual(d["command"], "sudo ./install.sh sensor")
        self.assertTrue(d["join"].startswith("redpot://"))
        token = d["join"].split("/")[3].split("?")[0].split("#")[0]
        self.assertGreater(len(token), 8)
        for k, v in d.items():
            if k != "join":
                self.assertNotIn(token, str(v), k)
        self.assertIn("--join-file", d["hint"])
        self.assertIn("--join -", d["hint"])
        html = self.c.get("/").get_data(as_text=True)
        for el in ('id="fcmd"', 'id="fjoinstr"', 'id="fcopy"', 'id="fcopyjoin"', 'id="fjoinhint"'):
            self.assertIn(el, html)


class TestStaticSources(unittest.TestCase):
    def test_join_ui_uses_text_content_and_no_join_flag(self):
        js = read("app.js")
        add = js[js.index('$("#fadd").onclick'):js.index("/* ---------------- JSON export")]
        self.assertIn('$("#fcmd").textContent = String(d.command', add)
        self.assertIn('$("#fjoinstr").textContent = String(d.join', add)
        self.assertIn('$("#fjoinhint").textContent = String(d.hint)', add)
        self.assertNotIn("innerHTML", add)
        self.assertIn('copyFrom("#fjoinstr", "#fcopyjoin")', add)
        for name in ("app.js", "index.html"):
            self.assertNotIn("--join '", read(name), name)
            self.assertNotIn("--join ${", read(name), name)
        html = read("index.html")
        self.assertIn("Paste it when the installer asks; or use --join-file / --join - for unattended installs", html)

    def test_no_inline_script_or_handlers(self):
        html = read("index.html")
        for tag in re.findall(r"<script\b[^>]*>", html):
            self.assertIn("src=", tag)
        self.assertFalse(re.search(r"<script\b[^>]*>\s*\S", html.replace("</script>", "")) and
                         re.search(r"<script(?![^>]*src=)[^>]*>", html))
        for name in ("index.html", "app.js", "login.html", "wall.js", "netmap.js", "worldmap.js"):
            src = read(name)
            self.assertIsNone(re.search(r"\son[a-z]+\s*=\s*[\"'`$]", src), f"inline handler in {name}")
            self.assertNotIn("javascript:", src.lower(), name)
            self.assertIsNone(re.search(r"\beval\s*\(|new Function\s*\(", src), name)

    def test_assets_are_local(self):
        html = read("index.html")
        for ref in re.findall(r'(?:src|href)="([^"]+)"', html):
            self.assertTrue(ref.startswith("/") and not ref.startswith("//"), ref)

    def test_js_is_balanced(self):
        for name in ("app.js", "login.js", "wall.js", "netmap.js", "worldmap.js", "icons.js"):
            with self.subTest(name=name):
                self.assertTrue(js_balanced(read(name)))

    def test_export_and_fleet_requests(self):
        js = read("app.js")
        exp = js[js.index("async function exportJson"):js.index("/* ---------------- wiring")]
        self.assertIn('fetch(`/api/export?from=${encodeURIComponent(frm)}&to=${encodeURIComponent(to)}`', exp)
        self.assertIn('"X-Requested-With": "rpot"', exp)
        self.assertIn("r.blob()", exp)
        self.assertIn("a.download = cdFilename(", exp)
        self.assertIn("btn.disabled = true", exp)
        self.assertIn("btn.disabled = false", exp)      # in finally
        for code in ("413", "429", "403"):
            self.assertIn(f"status === {code}", js)
        post = js[js.index("async function fleetPost"):js.index("async function loadFleet")]
        self.assertIn('"X-Requested-With": "rpot"', post)
        fl = js[js.index("async function loadFleet"):js.index('$("#fadd").onclick')]
        self.assertIn('st.role === "admin"', fl)
        self.assertIn("data-cancel", fl)
        self.assertIn("confirm(`Cancel the pending join", fl)
        self.assertIn("remove-decoy", js)

    def test_server_text_is_escaped(self):
        """New fleet/export code: every ${...} inside an HTML template is esc()'d, a number, or a fixed literal;
        free text (limit.message, error bodies, edition) only ever goes into textContent."""
        js = read("app.js")
        fl = js[js.index("async function loadFleet"):js.index('$("#fadd").onclick')]
        html_part = fl[:fl.index('$$("#fleet [data-delete]")')]
        for expr in re.findall(r"\$\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", html_part):
            e = expr.strip()
            ok = (e.startswith("esc(") or e in ("rows",) or e.startswith("s.revoked ?") or e.startswith("s.remote ?")
                  or e.startswith("admin") or e.startswith("hasLocal ?"))
            self.assertTrue(ok, f"unescaped interpolation in fleet HTML: ${{{e}}}")
        for fn in ("renderSlots", "exportJson", "exportError"):
            body = js[js.index(f"function {fn}"):]
            body = body[:body.index("\n}\n")]
            self.assertNotIn("innerHTML", body, fn)
        self.assertIn("msg.textContent = full ? String(lim.message", js)
        self.assertIn("ed.textContent = t", js)

    def test_no_alert_delivery_leftovers(self):
        for name in os.listdir(STATIC):
            p = os.path.join(STATIC, name)
            if os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as f:
                    txt = f.read().lower()
                for word in ("telegram", "webhook", "/api/alerts", "alert delivery", "delivery log"):
                    self.assertNotIn(word, txt, f"{word!r} in {name}")


if __name__ == "__main__":
    unittest.main()
