"""RC-32 (pentest N-4): the web decoy answers unusual and malformed requests like Apache 2.4.52 on Ubuntu 22.04,
not with Python http.server pages ("Error response", "Bad request syntax ('GARBAGE')", 501 for TRACE/PROPFIND).

The pentest requests are replayed as raw bytes (like curl / nc) and the answers are compared byte for byte.

Sources (read 2026-11-13; quoted behaviour, not memory):
  httpd tag 2.4.52, https://github.com/apache/httpd/tree/2.4.52
  - modules/http/http_protocol.c: status_lines[] (reason phrases, e.g. "414 Request-URI Too Long");
    get_canned_error_string() (body text per status; 400/403/414/501 take optional "error-notes";
    405 "The requested method X is not allowed for this URL."; 501 "X not supported for current URL.<br />";
    505 has no entry and falls to the 500 default text); ap_send_error_response() (DOCTYPE HTML 2.0 page,
    title "<code> <reason>", h1 = reason, Content-Type "text/html; charset=iso-8859-1", Allow only on 405/501,
    no body for HEAD); make_allow() + ap_method_registry_init() (HEAD is registered as M_GET, so GET|POST|OPTIONS
    gives four names; order = APR hash order); ap_set_keepalive() (Keep-Alive/Connection only when the client
    sent "keep-alive", "Connection: close" whenever the connection is dropped).
  - include/httpd.h: ap_status_drops_connection() = 400 408 411 413 414 500 503 501;
    DEFAULT_LIMIT_REQUEST_LINE / _FIELDSIZE 8190, _FIELDS 100, DEFAULT_LIMIT_BLANK_LINES 10.
  - modules/http/http_filters.c: ap_http_header_filter() / basic_http_header(): Date and Server first, then
    the header table in insertion order (Allow, Content-Length, Keep-Alive, Connection), Content-Type set last;
    a HEAD response with Content-Length 0 loses the header. ap_send_http_trace(): TraceEnable Off returns
    405 from a map_to_storage hook, before any handler set allowed methods, hence "Allow: " is empty.
  - modules/http/http_core.c: http_send_options(): "OPTIONS *" answers 200 without an Allow header.
  - server/protocol.c: read_request_line() (Strict: bare LF is EINVAL -> 400; overlong line -> 414; a timeout
    on the request line closes without a response), ap_parse_request_line() (default HttpProtocolOptions
    Strict LenientMethods Allow0.9: "GARBAGE" -> 400, "http/1.1" -> 400, "HTTP/9.9" accepted, "GET /" is a
    HTTP/0.9 simple request answered with the body only, "HEAD /" in 0.9 -> 400), ap_get_mime_headers_core()
    (oversized field -> 400 "Size of a request header field exceeds server limit."; more than 100 fields ->
    400 "The number of request header fields exceeds this server's limit."; field name not a token -> 400),
    ap_check_request_header() (HTTP/1.1 without Host -> 400), ap_read_request() (no 505 anywhere in core).
  - server/core.c: default_handler() (GET/POST on a missing file -> 404; OPTIONS -> 200 + Allow even for a
    missing file; method not in the registry (M_INVALID) -> 501; any other method -> 405; POST to a static
    file -> 405); ap_psignature() + ap_get_server_name()/ap_get_server_port() with UseCanonicalName Off:
    footer "<banner> Server at <Host header host> Port <Host header port, else 80/443>".
  - server/vhost.c: fix_hostname() + strict_hostname_check() (lower-case, strip port/trailing dot, reject
    "/", "\\", "..", non dotted-quad numeric hosts, numeric TLDs).
  Ubuntu jammy apache2 2.4.52-1ubuntu4.x, https://git.launchpad.net/ubuntu/+source/apache2 (ubuntu/jammy-updates)
  - debian/config-dir/conf-available/security.conf: "ServerTokens OS", "ServerSignature On", "TraceEnable Off".
  - debian/config-dir/apache2.conf.in: KeepAlive On, MaxKeepAliveRequests 100, KeepAliveTimeout 5.
  - debian/config-dir/sites-available/000-default.conf: no ServerName, ServerAdmin webmaster@localhost.
  php-src tag php-8.1.2, sapi/apache2handler/sapi_apache2.c php_handler(): no request-method check, so every
  method except TRACE runs the script (OPTIONS/PROPFIND on a PHP page return the page with PHP headers), and a
  missing *.php script is a 404 for every method.
  APR 1.7.0 tables/apr_hash.c apr_hash_make(): the hash seed mixes the start time, so the Allow order changes
  between Apache starts (one order per process; the decoy picks one per sensor process).
"""
import os
import re
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rpot import baits as B                                                  # noqa: E402
from rpot.common.config import TokenIndex, load_roles, sensor_token_view     # noqa: E402
from rpot.sensor.base import Ctx                                             # noqa: E402
from rpot.sensor.services import http as HT                                  # noqa: E402

BANNER = "Apache/2.4.52 (Ubuntu)"
UA = b"User-Agent: curl/7.81.0\r\nAccept: */*\r\n"


def page(code, reason, inner, host, port=80):
    """Apache's error document, written out from ap_send_error_response() independently of the decoy code."""
    return ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
            f"<title>{code} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n{inner}"
            f"<hr>\n<address>{BANNER} Server at {host} Port {port}</address>\n</body></html>\n").encode()


P400 = "<p>Your browser sent a request that this server could not understand.<br />\n</p>\n"
P403 = "<p>You don't have permission to access this resource.</p>\n"
P404 = "<p>The requested URL was not found on this server.</p>\n"
P414 = "<p>The requested URL's length exceeds the capacity\nlimit for this server.<br />\n</p>\n"


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


class Resp:
    def __init__(self, raw, head=False):
        self.raw = raw
        hdr, _, self.body = raw.partition(b"\r\n\r\n")
        lines = hdr.decode("latin-1").split("\r\n")
        self.status_line = lines[0]
        self.status = int(lines[0].split()[1])
        self.headers = [tuple(x.split(": ", 1)) if ": " in x else (x.rstrip(":"), "") for x in lines[1:]]
        self.names = [k for k, _ in self.headers]
        self.h = {k.lower(): v for k, v in self.headers}


class TestApacheErrors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        co = B.make_persona("corp.ararat.am", "bank", seed=5)
        co["token_salt"] = "s4lt"
        sensors = [{"name": "WEB01", "role": "linux-web-hosting", "ip": "10.9.0.22"}]
        toks = B.generate({"company": co, "console": {}, "sensors": sensors}, os.path.join(cls.tmp.name, "baits"))
        s = sensors[0]
        cfg = {"company": co, "tokens": sensor_token_view(toks, "s4lt", s["role"]), "sensors": [s]}
        cls.em = Em()
        cls.ctx = Ctx(cfg, s, load_roles()[s["role"]], cls.em, TokenIndex(cfg),
                      os.path.join(cls.tmp.name, "baits", "WEB01"), cls.tmp.name)
        cls.port = free_port()
        role_svc = next(x for x in load_roles()[s["role"]]["services"] if x["type"] == "http" and not x.get("tls"))
        HT.start_http(cls.ctx, dict(role_svc, port=cls.port))
        cls.fqdn = cls.ctx.fqdn
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # -- raw client ---------------------------------------------------------------------------------------
    def conn(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(s.close)
        return s

    def read_resp(self, s, head=False):
        data = b""
        while b"\r\n\r\n" not in data:
            c = s.recv(65536)
            if not c:
                return Resp(data) if data else None
            data += c
        hdr, _, body = data.partition(b"\r\n\r\n")
        m = re.search(rb"\r\nContent-Length: (\d+)", hdr)
        if head or (m is None and b"Connection: close" not in hdr):
            return Resp(data)
        need = int(m.group(1)) if m else None
        while need is None or len(body) < need:
            c = s.recv(65536)
            if not c:
                break
            body += c
        return Resp(hdr + b"\r\n\r\n" + body)

    def raw(self, data, head=False):
        # one connection per request, closed at once: the decoy-wide budget allows 20 per source IP
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(data)
            return self.read_resp(s, head)

    def req(self, line, extra=b"", host=b"127.0.0.1", head=False):
        hh = b"Host: " + host + b"\r\n" if host is not None else b""
        return self.raw(line + b"\r\n" + hh + UA + extra + b"\r\n", head)

    def assertClosed(self, s):
        s.settimeout(3)
        self.assertEqual(s.recv(10), b"")

    # -- the pentest requests (RC-25 round 2, N-4) ---------------------------------------------------------
    def test_trace_is_405_with_empty_allow(self):
        r = self.req(b"TRACE / HTTP/1.1")
        self.assertEqual(r.status_line, "HTTP/1.1 405 Method Not Allowed")
        self.assertEqual(r.names, ["Date", "Server", "Allow", "Content-Length", "Content-Type"])
        self.assertEqual(r.h["allow"], "")
        self.assertEqual(r.h["server"], BANNER)
        self.assertEqual(r.h["content-type"], "text/html; charset=iso-8859-1")
        self.assertEqual(r.body, page(405, "Method Not Allowed",
                                      "<p>The requested method TRACE is not allowed for this URL.</p>\n", "127.0.0.1"))
        self.assertEqual(int(r.h["content-length"]), len(r.body))
        self.assertIn(("http.scanner", ["method-trace"]),
                      [(e["type"], e.get("reasons")) for e in self.em.events])

    def test_garbage_request_line_is_apache_400_without_echo(self):
        s = self.conn()
        s.sendall(b"GARBAGE\r\n\r\n")
        r = self.read_resp(s)
        self.assertEqual(r.status_line, "HTTP/1.1 400 Bad Request")
        self.assertEqual(r.names, ["Date", "Server", "Content-Length", "Connection", "Content-Type"])
        self.assertEqual(r.h["connection"], "close")
        self.assertEqual(r.body, page(400, "Bad Request", P400, self.fqdn))   # no Host parsed: server name
        self.assertNotIn(b"GARBAGE", r.raw)
        self.assertClosed(s)

    def test_propfind_and_unknown_methods(self):
        r = self.req(b"PROPFIND /nope HTTP/1.1")                 # registered method, default_handler -> 405
        self.assertEqual(r.status, 405)
        self.assertEqual(r.names, ["Date", "Server", "Allow", "Content-Length", "Content-Type"])
        self.assertEqual(set(r.h["allow"].split(",")), {"GET", "HEAD", "POST", "OPTIONS"})
        self.assertEqual(r.h["allow"], HT.ALLOW_METHODS)
        self.assertEqual(r.body, page(405, "Method Not Allowed",
                                      "<p>The requested method PROPFIND is not allowed for this URL.</p>\n", "127.0.0.1"))
        r = self.req(b"FOO /nope HTTP/1.1")                      # not registered (M_INVALID) -> 501, drops conn
        self.assertEqual(r.status_line, "HTTP/1.1 501 Not Implemented")
        self.assertEqual(r.names, ["Date", "Server", "Allow", "Content-Length", "Connection", "Content-Type"])
        self.assertEqual(r.body, page(501, "Not Implemented", "<p>FOO not supported for current URL.<br />\n</p>\n",
                                      "127.0.0.1"))
        for m in (b"PUT", b"DELETE", b"PATCH", b"MKCOL"):
            self.assertEqual(self.req(m + b" /x.txt HTTP/1.1", b"Content-Length: 0\r\n").status, 405, m)
        self.assertEqual(self.req(b"POST /robots.txt HTTP/1.1", b"Content-Length: 0\r\n").status, 405)
        # mod_php runs the script for every method: PROPFIND on the PHP front page is the page, not an error
        r = self.req(b"PROPFIND / HTTP/1.1")
        self.assertEqual(r.status, 200)
        self.assertIn("x-powered-by", r.h)
        self.assertEqual(self.req(b"PROPFIND /missing.php HTTP/1.1").status, 404)   # PHP handler 404

    def test_options(self):
        r = self.req(b"OPTIONS /nope HTTP/1.1")
        self.assertEqual(r.status_line, "HTTP/1.1 200 OK")
        self.assertEqual(r.names, ["Date", "Server", "Allow", "Content-Length"])   # no PHP headers, no type
        self.assertEqual(r.h["allow"], HT.ALLOW_METHODS)
        self.assertEqual(r.h["content-length"], "0")
        r = self.req(b"OPTIONS /robots.txt HTTP/1.1")
        self.assertEqual(r.names, ["Date", "Server", "Allow", "Content-Length", "Content-Type"])
        self.assertEqual(r.h["content-type"], "text/plain")
        r = self.req(b"OPTIONS * HTTP/1.1")
        self.assertEqual(r.names, ["Date", "Server", "Content-Length"])           # "HTTP pong" without Allow

    def test_403_and_404_pages(self):
        r = self.req(b"GET /.git/config HTTP/1.1")
        self.assertEqual(r.status_line, "HTTP/1.1 403 Forbidden")
        self.assertEqual(r.names, ["Date", "Server", "Content-Length", "Content-Type"])
        self.assertEqual(r.body, page(403, "Forbidden", P403, "127.0.0.1"))
        r = self.req(b"GET /nope HTTP/1.1")
        self.assertEqual(r.names, ["Date", "Server", "Content-Length", "Content-Type"])
        self.assertEqual(r.body, page(404, "Not Found", P404, "127.0.0.1"))
        r = self.req(b"HEAD /nope HTTP/1.1", head=True)                  # header_only: no length, no body
        self.assertEqual(r.names, ["Date", "Server", "Content-Type"])
        self.assertEqual(r.body, b"")
        r = self.req(b"GET /nope HTTP/1.1", host=b"WWW.Example.COM.:8080")
        self.assertEqual(r.body, page(404, "Not Found", P404, "www.example.com", 8080))

    def test_keepalive_headers_like_apache(self):
        s = self.conn()
        rq = b"GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"
        s.sendall(rq)
        r = self.read_resp(s)
        self.assertEqual(r.names, ["Date", "Server", "Content-Length", "Keep-Alive", "Connection", "Content-Type"])
        self.assertEqual((r.h["keep-alive"], r.h["connection"]), ("timeout=5, max=100", "Keep-Alive"))
        s.sendall(rq)
        self.assertEqual(self.read_resp(s).h["keep-alive"], "timeout=5, max=99")
        r = self.raw(b"GET /nope HTTP/1.0\r\n\r\n")                     # 1.0 without keep-alive: close
        self.assertEqual(r.h["connection"], "close")
        self.assertEqual(r.body, page(404, "Not Found", P404, self.fqdn))

    def test_long_url_is_414(self):
        s = self.conn()
        s.sendall(b"GET /" + b"A" * 9000 + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n" + UA + b"\r\n")
        r = self.read_resp(s)
        self.assertEqual(r.status_line, "HTTP/1.1 414 Request-URI Too Long")
        self.assertEqual(r.names, ["Date", "Server", "Content-Length", "Connection", "Content-Type"])
        self.assertEqual(r.body, page(414, "Request-URI Too Long", P414, self.fqdn))
        self.assertClosed(s)
        self.assertEqual(self.req(b"GET /" + b"A" * 8000 + b" HTTP/1.1").status, 404)   # under LimitRequestLine

    # -- protocol corner cases -------------------------------------------------------------------------------
    def test_versions_and_request_line_errors(self):
        self.assertEqual(self.req(b"GET /nope HTTP/9.9").status, 404)        # accepted, no 505 in core
        self.assertEqual(self.req(b"GET /nope HTTP/1.1").status_line, "HTTP/1.1 404 Not Found")
        for bad in (b"GET /nope http/1.1", b"GET  /nope HTTP/1.1", b"GET /nope HTTP/1.1 x", b"GET nope HTTP/1.1",
                    b"GET /nope HTTP/0.9", b"GET /a#b HTTP/1.1", b"G<T /nope HTTP/1.1", b"PRI * HTTP/2.0"):
            r = self.req(bad)
            self.assertEqual((r.status, r.body), (400, page(400, "Bad Request", P400, self.fqdn)), bad)
        r = self.raw(b"GET /nope HTTP/1.1\nHost: 127.0.0.1\n\n")             # bare LF: Strict -> 400
        self.assertEqual(r.status, 400)
        r = self.raw(b"GET /nope HTTP/1.1\r\n\r\n")                         # HTTP/1.1 without Host
        self.assertEqual((r.status, r.h["connection"]), (400, "close"))
        for host in (b"a/b", b"1.2.3", b"8080", b"foo.123", b"[zz::1]", b"a, b"):
            self.assertEqual(self.req(b"GET /nope HTTP/1.1", host=host).status, 400, host)
        self.assertEqual(self.req(b"GET /nope HTTP/1.1", host=b"[::1]:81").body, page(404, "Not Found", P404, "::1", 81))
        self.assertEqual(self.req(b"GET http://Web01.Example/nope HTTP/1.1").body,
                         page(404, "Not Found", P404, "web01.example"))      # absolute-form host wins

    def test_http09_simple_request(self):
        s = self.conn()
        s.sendall(b"GET /nope\r\n")
        data = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
        self.assertEqual(data, page(404, "Not Found", P404, self.fqdn))       # body only, no status line
        r = self.raw(b"HEAD /nope\r\n")                                      # only GET in 0.9 -> 400 with 1.x
        self.assertEqual((r.status_line, r.h["connection"]), ("HTTP/1.1 400 Bad Request", "close"))

    def test_header_limits(self):
        r = self.req(b"GET / HTTP/1.1", b"X-A: " + b"B" * 9000 + b"\r\n")
        self.assertEqual(r.body, page(400, "Bad Request", "<p>Your browser sent a request that this server could "
                                      "not understand.<br />\nSize of a request header field exceeds server "
                                      "limit.</p>\n", self.fqdn))
        r = self.req(b"GET / HTTP/1.1", b"".join(b"X-%d: 1\r\n" % i for i in range(101)))
        self.assertIn(b"<br />\nThe number of request header fields exceeds this server's limit.</p>\n", r.body)
        self.assertEqual(self.req(b"GET / HTTP/1.1", b"BadHeader\r\n").status, 400)
        self.assertEqual(self.req(b"GET / HTTP/1.1", b"Bad Name: x\r\n").status, 400)
        self.assertEqual(self.req(b"GET / HTTP/1.1", b"Content-Length: -1\r\n").status, 400)
        self.assertEqual(self.req(b"GET / HTTP/1.1", b"Transfer-Encoding: gzip\r\n").status, 400)
        r = self.req(b"GET /nope HTTP/1.1", b"Expect: magic\r\n")
        self.assertEqual(r.status_line, "HTTP/1.1 417 Expectation Failed")
        self.assertIn(b"The client sent<pre>\n    Expect: magic\n</pre>\n</p><p>Only the 100-continue", r.body)

    def test_request_header_timeout_is_408(self):
        old = HT.HEADER_DEADLINE
        HT.HEADER_DEADLINE = 0.3
        self.addCleanup(setattr, HT, "HEADER_DEADLINE", old)
        s = self.conn()
        s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        time.sleep(0.5)
        s.sendall(b"X-Slow: 1\r\n")
        r = self.read_resp(s)
        self.assertEqual((r.status_line, r.h["connection"]), ("HTTP/1.1 408 Request Timeout", "close"))
        self.assertEqual(r.body, page(408, "Request Timeout",
                                      "<p>Server timeout waiting for the HTTP request from the client.</p>\n", self.fqdn))

    def test_no_python_http_server_tells(self):
        """None of the probes may show http.server's page, reason phrases or header style."""
        probes = [b"TRACE / HTTP/1.1\r\nHost: x.example\r\n\r\n", b"GARBAGE\r\n\r\n", b"PROPFIND /x HTTP/1.1\r\n\r\n",
                  b"FOO /x HTTP/1.1\r\nHost: x.example\r\n\r\n", b"GET / HTTP/2.0\r\n\r\n", b"\x16\x03\x01\x00\x05hello\r\n\r\n",
                  b"GET /" + b"%" * 70000 + b" HTTP/1.1\r\n\r\n", b"GET / HTTP/1.1\r\nHost: x.example\r\nA\r\n\r\n"]
        for p in probes:
            r = self.raw(p)
            self.assertIsNotNone(r, p[:20])
            low = r.raw.lower()
            for tell in (b"error response", b"error code", b"bad request syntax", b"unsupported method",
                         b"text/html;charset=utf-8", b"python", b"basehttp"):
                self.assertNotIn(tell, low, (p[:20], tell))
            self.assertTrue(r.raw.startswith(b"HTTP/1.1 "), p[:20])
            self.assertEqual(r.names[:2], ["Date", "Server"], p[:20])

    def test_static_file_has_no_php_headers(self):
        r = self.req(b"GET /robots.txt HTTP/1.1")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.names, ["Date", "Server", "Last-Modified", "ETag", "Accept-Ranges", "Content-Length",
                                   "Content-Type"])
        self.assertEqual(r.h["content-type"], "text/plain")
        self.assertRegex(r.h["etag"], r'^"[0-9a-f]+-[0-9a-f]+"$')
        r = self.req(b"GET / HTTP/1.1")                                      # the PHP page keeps its PHP headers
        self.assertEqual(r.names[:3], ["Date", "Server", "X-Powered-By"])
        self.assertEqual(r.names[-1], "Content-Type")


class TestCannedPages(unittest.TestCase):
    """Every status the brief lists has Apache's text (no network)."""

    def test_pages(self):
        want = {400: ("Bad Request", P400),
                403: ("Forbidden", P403),
                404: ("Not Found", P404),
                405: ("Method Not Allowed", "<p>The requested method GET is not allowed for this URL.</p>\n"),
                408: ("Request Timeout", "<p>Server timeout waiting for the HTTP request from the client.</p>\n"),
                413: ("Request Entity Too Large", "The requested resource does not allow request data with GET "
                      "requests, or the amount of data provided in\nthe request exceeds the capacity limit.\n"),
                414: ("Request-URI Too Long", P414),
                431: ("Request Header Fields Too Large",
                      "<p>The server refused this request because\nthe request header fields are too large.</p>\n"),
                501: ("Not Implemented", "<p>GET not supported for current URL.<br />\n</p>\n")}
        for code, (reason, inner) in want.items():
            self.assertEqual(HT.apache_error_page(code, BANNER, "h.example", 443, "GET").encode(),
                             page(code, reason, inner, "h.example", 443), code)
        internal = ("<p>The server encountered an internal error or\nmisconfiguration and was unable to complete\n"
                    "your request.</p>\n<p>Please contact the server administrator at \n webmaster@localhost to "
                    "inform them of the time this error occurred,\n and the actions you performed just before this "
                    "error.</p>\n<p>More information about this error may be available\nin the server error log.</p>\n")
        self.assertEqual(HT.apache_error_page(500, BANNER, "h", 80).encode(),
                         page(500, "Internal Server Error", internal, "h"))
        self.assertEqual(HT.apache_error_page(505, BANNER, "h", 80).encode(),   # no canned text: default branch
                         page(505, "HTTP Version Not Supported", internal, "h"))
        self.assertIn("&lt;x&gt;", HT.apache_error_page(501, BANNER, "h", 80, "<x>"))


if __name__ == "__main__":
    unittest.main()
