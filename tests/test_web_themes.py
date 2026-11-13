"""Web decoy front pages (webmail / helpdesk / intranet): page renders with the client's identity,
failed logins are logged, a stolen bait credential opens the mailbox/queue and raises a honeytoken."""
import http.client
import os
import socket
import sys
import tempfile
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rpot import baits as B                                                  # noqa: E402
from rpot.common.config import TokenIndex, load_roles, sensor_token_view     # noqa: E402
from rpot.sensor.base import Ctx                                             # noqa: E402
from rpot.sensor.services.http import start_http                             # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Em:
    def __init__(self):
        self.events = []

    def emit(self, type_, **kw):
        self.events.append(dict(kw, type=type_))


class TestWebThemes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.co = B.make_persona("corp.ararat.am", "bank", seed=5)
        cls.co["token_salt"] = "s4lt"
        cls.sensors = [{"name": "WEB01", "role": "linux-web-hosting", "ip": "10.9.0.22"},
                       {"name": "BKP01", "role": "ftp-backup-server", "ip": "10.9.0.23"}]
        cls.tokens = B.generate({"company": cls.co, "console": {}, "sensors": cls.sensors}, os.path.join(cls.tmp.name, "baits"))
        cls.admin = next(t for t in cls.tokens.values() if t.get("username") == "admin")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def serve(self, theme):
        co = dict(self.co, web_theme=theme)
        s = self.sensors[0]
        cfg = {"company": co, "tokens": sensor_token_view(self.tokens, "s4lt", s["role"]), "sensors": [s]}
        em = Em()
        d = tempfile.mkdtemp(dir=self.tmp.name)
        ctx = Ctx(cfg, s, load_roles()[s["role"]], em, TokenIndex(cfg), os.path.join(self.tmp.name, "baits", "WEB01"), d)
        port = free_port()
        start_http(ctx, {"port": port})
        time.sleep(0.2)
        return port, em

    def req(self, port, method, path, body=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        h = {"Content-Type": "application/x-www-form-urlencoded"} if body else {}
        if cookie:
            h["Cookie"] = cookie
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read().decode()

    def login(self, port, user, pw):
        return self.req(port, "POST", "/login", urllib.parse.urlencode({"user": user, "pass": pw}))

    def test_webmail(self):
        port, em = self.serve("webmail")
        st, h, body = self.req(port, "GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("Ararat Webmail :: Welcome", body)
        self.assertIn(f"name@{self.co['email_domain']}", body)
        self.assertIn("Apache", h.get("Server", ""))
        st, _, body = self.login(port, f"j.doe@{self.co['email_domain']}", "Summer2025!")
        self.assertIn("Login failed", body)
        self.assertIn(f"j.doe@{self.co['email_domain']}", body)             # user kept in the form
        st, h, _ = self.login(port, f"admin@{self.co['email_domain']}", self.admin["password"])
        self.assertEqual(st, 302)
        st, _, body = self.req(port, "GET", "/", cookie=h["Set-Cookie"].split(";")[0])
        self.assertIn("Webmail :: Inbox", body)
        self.assertIn(self.co["users"][0]["full_name"], body)
        st, _, body = self.req(port, "GET", "/?_action=reset")
        self.assertIn("Reset password", body)
        types = [e["type"] for e in em.events]
        self.assertIn("auth.failed", types)
        self.assertIn("honeytoken.used", types)

    def test_helpdesk(self):
        port, em = self.serve("helpdesk")
        _, _, body = self.req(port, "GET", "/")
        self.assertIn("IT Service Desk", body)
        self.assertIn(self.co["netbios"] + "\\username", body)
        _, _, body = self.req(port, "GET", "/kb/kb-0102")
        self.assertIn("Please sign in to read this article", body)
        st, h, _ = self.login(port, self.co["netbios"] + "\\admin", self.admin["password"])
        self.assertEqual(st, 302)
        _, _, body = self.req(port, "GET", "/", cookie=h["Set-Cookie"].split(";")[0])
        self.assertIn("INC-", body)
        self.assertIn("honeytoken.used", [e["type"] for e in em.events])

    def test_intranet_and_admin_portal_unchanged(self):
        port, _ = self.serve("intranet")
        _, _, body = self.req(port, "GET", "/")
        self.assertIn("Welcome to the Ararat intranet", body)
        for theme in ("webmail", "helpdesk"):
            p, _ = self.serve(theme)
            _, _, body = self.req(p, "GET", "/admin/")
            self.assertIn("Administration", body)                        # bait chain target still there
            _, _, body = self.req(p, "GET", "/.env")
            self.assertIn("DB_PASSWORD=", body)

    def test_wordpress_paths_are_404_on_a_non_wordpress_site(self):
        """B23: a 403 for wp-config.php.bak on a PHP portal that is not WordPress gives the decoy away."""
        port, _ = self.serve("webmail")
        self.assertEqual(self.req(port, "GET", "/wp-config.php.bak")[0], 404)
        self.assertEqual(self.req(port, "GET", "/.git/config")[0], 403)


if __name__ == "__main__":
    unittest.main()
