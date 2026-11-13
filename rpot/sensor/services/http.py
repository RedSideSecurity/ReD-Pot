"""HTTP/HTTPS emulator: company portal + admin login + juicy files from the bait web root.

Events: http.request (2), http.notfound (2; console escalates path brute force),
http.scanner (3: scanner UA / exploit pattern), http.sensitive (4: bait file fetched),
auth.failed / auth.success / honeytoken.used for the login form.
"""
import email.utils
import html
import http.client
import io
import ipaddress
import mimetypes
import os
import random
import re
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket

import base64

from rpot.common.events import new_session

PIXEL = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")
from rpot.sensor.base import tls_context, safe_join, bind_ip, serve_socketserver
from rpot.sensor.services import webthemes as W

SCANNER_UA = re.compile(r"nmap|nikto|sqlmap|gobuster|dirbuster|dirb|feroxbuster|ffuf|wfuzz|nuclei|wpscan|"
                        r"masscan|zgrab|acunetix|nessus|openvas|burp|hydra|whatweb|httpx|curl/|python-requests|"
                        r"go-http-client|wget/", re.I)
EXPLOIT = re.compile(r"\.\./|%2e%2e|union(\s|%20|\+)+select|<script|%3cscript|\$\{jndi|/etc/passwd|cmd\.exe|"
                     r"powershell|;\s*(id|whoami|uname)|\|\s*(id|whoami)|sleep\(|benchmark\(|' or '1'='1|"
                     r"/cgi-bin/|\.php\?[^=]{0,200}=(http|https|ftp)://|eval\(|base64_decode", re.I)
LOGIN_PATHS = ("/admin", "/admin/", "/admin/login", "/login", "/wp-login.php", "/phpmyadmin", "/phpmyadmin/",
               "/administrator", "/user/login")

# ----------------------------------------------------------------------------------------------------------
# Apache 2.4.52 on Ubuntu 22.04 (apache2 2.4.52-1ubuntu4.x, mod_php 8.1) protocol and error behaviour (RC-32).
# This is ported from the httpd 2.4.52 source, not from Python http.server. The source of each rule is cited
# in tests/test_rc32_apache_errors.py. Short version:
#   - error pages: http_protocol.c ap_send_error_response() + get_canned_error_string(), status_lines[]
#   - header order: Date, Server, handler headers, Content-Length, Keep-Alive, Connection, Content-Type
#     (http_filters.c ap_http_header_filter, http_protocol.c ap_set_keepalive)
#   - request line and headers: protocol.c (HttpProtocolOptions Strict LenientMethods Allow0.9 defaults)
#   - Host header: vhost.c fix_hostname() strict mode; footer host and port from core.c ap_psignature()
#   - methods: core.c default_handler(); TRACE is denied by Ubuntu security.conf "TraceEnable Off"
APACHE_REASON = {200: "OK", 301: "Moved Permanently", 302: "Found", 304: "Not Modified", 400: "Bad Request",
                 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
                 408: "Request Timeout", 411: "Length Required", 413: "Request Entity Too Large",
                 414: "Request-URI Too Long", 417: "Expectation Failed", 431: "Request Header Fields Too Large",
                 500: "Internal Server Error", 501: "Not Implemented", 503: "Service Unavailable",
                 505: "HTTP Version Not Supported"}
DOCTYPE_HTML_2_0 = '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
ERROR_CTYPE = "text/html; charset=iso-8859-1"
DROPS_CONNECTION = frozenset((400, 408, 411, 413, 414, 500, 503, 501))   # httpd.h ap_status_drops_connection
LIMIT_REQUEST_LINE = 8190            # LimitRequestLine; ap_rgetline buffer is limit + 2
LIMIT_REQUEST_FIELDSIZE = 8190       # LimitRequestFieldSize
LIMIT_REQUEST_FIELDS = 100           # LimitRequestFields
KEEPALIVE_TIMEOUT = 5                # Ubuntu apache2.conf: KeepAliveTimeout 5
KEEPALIVE_MAX = 100                  # Ubuntu apache2.conf: MaxKeepAliveRequests 100
HEADER_DEADLINE = 40                 # Ubuntu reqtimeout.conf: RequestReadTimeout header=20-40,MinRate=500
SERVER_ADMIN = "webmaster@localhost"  # 000-default.conf ServerAdmin
# Methods registered in http_protocol.c ap_method_registry_init(). Any other token is M_INVALID (501).
KNOWN_METHODS = frozenset(("GET", "HEAD", "PUT", "POST", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
                           "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "VERSION-CONTROL",
                           "CHECKOUT", "UNCHECKOUT", "CHECKIN", "UPDATE", "LABEL", "REPORT", "MKWORKSPACE",
                           "MKACTIVITY", "BASELINE-CONTROL", "MERGE"))
# default_handler allows GET, OPTIONS, POST; make_allow() walks the method registry (HEAD maps to M_GET) in APR
# hash order. APR seeds that hash per process start, so the order differs between Apache starts but stays the
# same for one server (shared by its :80 and :443 vhosts). One order per sensor process here.
ALLOW_METHODS = ",".join(random.SystemRandom().sample(["GET", "HEAD", "POST", "OPTIONS"], 4))
_WS = frozenset(b" \t\n\v\f\r")
_TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _vchar(c):
    return 0x21 <= c <= 0x7e or c >= 0x80


def apache_escape(s):
    """ap_escape_html(): & < > " only (not the apostrophe)."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def apache_canned(status, method="", notes=None, expect=None):
    """get_canned_error_string() of httpd 2.4.52 for the statuses the decoy can produce."""
    m, n = apache_escape(method or ""), notes or ""
    if status == 400:
        return "<p>Your browser sent a request that this server could not understand.<br />\n" + n + "</p>\n"
    if status == 401:
        return ("<p>This server could not verify that you\nare authorized to access the document\nrequested.  "
                "Either you supplied the wrong\ncredentials (e.g., bad password), or your\nbrowser doesn't "
                "understand how to supply\nthe credentials required.</p>\n")
    if status == 403:
        return "<p>You don't have permission to access this resource." + n + "</p>\n"
    if status == 404:
        return "<p>The requested URL was not found on this server.</p>\n"
    if status == 405:
        return f"<p>The requested method {m} is not allowed for this URL.</p>\n"
    if status == 408:
        return "<p>Server timeout waiting for the HTTP request from the client.</p>\n"
    if status == 411:
        return f"<p>A request of the requested method {m} requires a valid Content-length.<br />\n{n}</p>\n"
    if status == 413:
        return (f"The requested resource does not allow request data with {m} requests, or the amount of data "
                "provided in\nthe request exceeds the capacity limit.\n")
    if status == 414:
        return "<p>The requested URL's length exceeds the capacity\nlimit for this server.<br />\n" + n + "</p>\n"
    if status == 417:
        s1 = ("<p>The expectation given in the Expect request-header\nfield could not be met by this server.\n"
              f"The client sent<pre>\n    Expect: {apache_escape(expect)}\n</pre>\n") if expect else \
             ("<p>No expectation was seen, the Expect request-header \nfield was not presented by the client.\n")
        return s1 + n + "</p><p>Only the 100-continue expectation is supported.</p>\n"
    if status == 431:
        return "<p>The server refused this request because\nthe request header fields are too large.</p>\n"
    if status == 501:
        return f"<p>{m} not supported for current URL.<br />\n{n}</p>\n"
    if status == 503:
        return ("<p>The server is temporarily unable to service your\nrequest due to maintenance downtime or "
                "capacity\nproblems. Please try again later.</p>\n")
    # default branch (500 and anything without its own text, e.g. 505)
    return ("<p>The server encountered an internal error or\nmisconfiguration and was unable to complete\n"
            f"your request.</p>\n<p>Please contact the server administrator at \n {SERVER_ADMIN} to inform them "
            "of the time this error occurred,\n and the actions you performed just before this error.</p>\n"
            "<p>More information about this error may be available\nin the server error log.</p>\n")


def apache_error_page(status, banner, host, port, method="", notes=None, expect=None):
    """ap_send_error_response() body with ServerSignature On (Ubuntu security.conf)."""
    reason = APACHE_REASON.get(status, "Internal Server Error")
    return (f"{DOCTYPE_HTML_2_0}<html><head>\n<title>{status} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n"
            f"{apache_canned(status, method, notes, expect)}"
            f"<hr>\n<address>{banner} Server at {apache_escape(host)} Port {port}</address>\n</body></html>\n")


class RequestLine:
    __slots__ = ("ok", "method", "uri", "protocol", "proto", "http09")


def apache_parse_request_line(line):
    """protocol.c ap_parse_request_line() with the 2.4.52 defaults (Strict, LenientMethods, Allow0.9).
    line: request line without CRLF (bytes). Returns a RequestLine; .ok False means 400 Bad Request."""
    n, i, err = len(line), 0, None
    if i < n and line[i] in _WS:
        err = "badwhitespace"
        while i < n and line[i] in _WS:
            i += 1
    j = i
    while j < n and line[j] in _TCHAR:
        j += 1
    ll = j
    if (j == i or (j < n and line[j] not in _WS)) and err is None:
        err = "badmethod"
        ll = next((k for k in range(j, n) if line[k] in _WS), None)
    uri = protocol = b""
    if ll is None:
        err = err or "missinguri"
        method = line[i:]
    else:
        method = line[i:ll]
        if ll + 1 < n and line[ll + 1] in _WS and err is None:
            err = "excesswhitespace"
        u = ll
        while u < n and line[u] in _WS:
            if line[u] != 0x20 and err is None:
                err = "badwhitespace"
            u += 1
        if u >= n and err is None:
            err = "missinguri"
        e = u
        while e < n and _vchar(line[e]):
            e += 1
        ll = e
        if e == u or (e < n and line[e] not in _WS):
            err = "baduri"
            ll = next((k for k in range(e, n) if line[k] in _WS), None)
        if ll is None:
            uri = line[u:]
        else:
            uri = line[u:ll]
            if ll + 1 < n and line[ll + 1] in _WS and err is None:
                err = "excesswhitespace"
            p = ll
            while p < n and line[p] in _WS:
                if line[p] != 0x20 and err is None:
                    err = "badwhitespace"
                p += 1
            e = p
            while e < n and _vchar(line[e]):
                e += 1
            protocol = line[p:e]
            if e < n:
                err = "badprotocol" if line[e] not in _WS else "excesswhitespace"
    r = RequestLine()
    r.http09 = False
    pr = protocol
    if (len(pr) == 8 and pr[:4].upper() == b"HTTP" and pr[4:5] == b"/" and chr(pr[5]).isdigit()
            and pr[6:7] == b"." and chr(pr[7]).isdigit() and pr[5:6] != b"0"):
        r.proto = (pr[5] - 48, pr[7] - 48)
        if pr[:4] != b"HTTP" and err is None:          # lower-case "http/1.1" is an error in Strict mode
            err = "badprotocol"
    elif pr:
        r.proto = (0, 9)
        err = err or "badprotocol"
    else:
        r.proto, r.http09 = (0, 9), True
    r.method = method.decode("latin-1")
    r.uri = uri.decode("latin-1")
    r.protocol = pr.decode("latin-1") if pr else "HTTP/0.9"
    if (r.uri[:1] != "/" and not (r.method == "OPTIONS" and r.uri == "*")
            and not re.match(r"(?i)https?://", r.uri)):
        err = err or "baduri"                           # request-target must be origin-form (or absolute)
    if "#" in r.uri:
        err = err or "fragment"
    if r.http09 and err is None and r.method != "GET":   # HTTP/0.9 allows GET only (HEAD is header_only)
        err = "badmethod09"
    r.ok = err is None
    if not r.ok and r.proto == (0, 9):                  # rrl_failed: answer errors with 1.x behaviour
        r.http09, r.proto, r.protocol = False, (1, 0), "HTTP/1.0"
    return r


def apache_fix_host(value):
    """vhost.c fix_hostname() + strict_hostname_check(): Host header -> (host, port or None), or None when
    Apache answers 400. A blank Host is allowed and leaves the host unset ("", None)."""
    if value == "":
        return "", None
    if value.isascii() and value.isdigit():
        return None                                     # purely numeric host names not allowed
    k = len(value)
    while k > 0 and value[k - 1] in "0123456789":
        k -= 1
    port = None
    addr = value
    if k < len(value) and k > 0 and value[k - 1] == ":":
        port = int(value[k:])
        if not 0 < port < 65536:
            return None
        addr = value[:k - 1]
    if not addr:
        return None
    if addr.startswith("["):
        inner = addr[1:-1] if addr.endswith("]") else None
        if not inner or "%" in inner:
            return None
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return None
        return inner.lower(), port
    host = addr.lower()
    if "/" in host or "\\" in host or ".." in host:
        return None
    if host.endswith("."):
        host = host[:-1]
    dotted, dots, lead0 = True, 0, False
    for idx, ch in enumerate(host):
        if (ch.isascii() and ch.isalpha()) or ch in "-_":
            dotted = False
        elif ch == ".":
            dots += 1
            if host[idx + 1:idx + 2] == "0" and host[idx + 2:idx + 3].isdigit():
                lead0 = True
        elif not (ch.isascii() and ch.isdigit()):
            return None
    if dotted:
        if host[:1] == "." or (host[:1] == "0" and host[1:2].isdigit()) or lead0 or dots != 3:
            return None
    else:
        tld = host.rsplit(".", 1)
        if len(tld) == 2 and tld[1] and not (tld[1][0].isascii() and tld[1][0].isalpha()):
            return None
    return host, port


CSS = """body{font-family:Segoe UI,Arial,sans-serif;background:#f4f5f7;margin:0;color:#222}
header{background:#1f3a5f;color:#fff;padding:14px 28px;font-size:18px}
main{max-width:860px;margin:30px auto;background:#fff;padding:28px;border-radius:6px;box-shadow:0 1px 3px #0002}
.login{max-width:340px;margin:60px auto;background:#fff;padding:28px;border-radius:6px;box-shadow:0 1px 3px #0002}
input{width:100%;padding:8px;margin:6px 0 14px;border:1px solid #bbb;border-radius:4px;box-sizing:border-box}
button{background:#1f3a5f;color:#fff;border:0;padding:9px 18px;border-radius:4px;cursor:pointer}
.err{color:#b00020;font-size:14px}footer{text-align:center;color:#888;font-size:12px;margin:30px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #eee;padding:6px;text-align:left}"""


def start_http(ctx, svc):
    port = svc["port"]
    tls = tls_context(ctx) if svc.get("tls") else None
    server_hdr = svc.get("server", "Apache/2.4.52 (Ubuntu)")
    powered = svc.get("powered_by")
    proto = "https" if tls else "http"
    www = os.path.join(ctx.bait_dir, "www")
    company = ctx.cfg["company"]["name"]
    theme = ctx.cfg["company"].get("web_theme") or "webmail"
    theme = theme if theme in W.THEMES else "webmail"
    mail_domain = ctx.cfg["company"].get("email_domain") or ctx.cfg["company"].get("domain", "example.com")
    netbios = ctx.cfg["company"].get("netbios", "CORP")
    wordpress = ctx.cfg["company"].get("cms") == "wordpress"   # no WordPress persona → WP paths are plain 404s
    sessions = {}  # cookie -> username (successful admin logins)
    lock = threading.Lock()

    default_port = 443 if tls else 80          # ap_default_port(); Ubuntu vhosts have no ServerName port
    server_name = svc.get("server_name") or ctx.fqdn   # footer host when the request carries no usable Host
    mimetypes.guess_type("x.txt")              # load the system mime.types once (Apache uses the same file)

    class H(BaseHTTPRequestHandler):
        server_version = server_hdr
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = 20

        def log_message(self, *a):
            pass

        def version_string(self):
            return server_hdr

        # -- Apache 2.4.52 protocol layer (RC-32): replaces http.server parsing and error pages ------------
        def setup(self):
            super().setup()
            self._keepalives = 0
            self._drain = False

        def _reset(self):
            self.command, self.path, self.request_version, self.requestline = "", "", "HTTP/1.0", ""
            self.headers = http.client.HTTPMessage()
            self._proto = (1, 0)
            self._host = self._host_port = None
            self._conn_tokens = ()
            self._force_close = self._expect100 = False
            self.close_connection = True

        def _readline(self, limit):
            """ap_rgetline() in Strict mode: (line without CRLF, None) or (data, "nospc" | "einval" | "eof").
            The buffer is limit + 2, and a CRLF that overruns it by the LF only is still accepted."""
            raw = self.rfile.readline(limit + 3)
            if not raw.endswith(b"\n"):
                return raw, ("nospc" if len(raw) >= limit + 3 else "eof")
            if not raw.endswith(b"\r\n"):
                return raw, "einval"                     # bare LF is a 400 in Strict mode
            return raw[:-2], None

        def handle_one_request(self):
            self._reset()
            try:
                self.connection.settimeout(KEEPALIVE_TIMEOUT if self._keepalives else self.timeout)
                for _ in range(11):                      # read_request_line() skips up to 10 empty lines
                    line, err = self._readline(LIMIT_REQUEST_LINE)
                    if err or line:
                        break
                self.connection.settimeout(self.timeout)
            except OSError:                              # timeout or reset before a request line: no answer
                return
            self.raw_requestline = line
            self.requestline = line[:300].decode("latin-1")
            if err == "eof":
                return                                   # EOF mid-line: Apache closes without a response
            if err:
                self.path = self.requestline
                return self._die(414 if err == "nospc" else 400)
            rl = apache_parse_request_line(line)
            self.command, self.path, self.request_version, self._proto = rl.method, rl.uri, rl.protocol, rl.proto
            if not rl.ok:
                return self._die(400)
            if rl.http09:                                # Allow0.9: body only, no status line or headers
                self.request_version = "HTTP/0.9"
                self._dispatch()
                self.wfile.flush()
                self.close_connection = True
                return
            try:
                status, notes = self._read_headers()
            except OSError:
                return
            if status:
                return self._die(status, notes)
            status = self._check_request()
            if status:
                return self._die(status) if status != 417 else self.apache_error(417)
            self._dispatch()
            self.wfile.flush()

        def _read_headers(self):
            """ap_get_mime_headers_core() in Strict mode. Returns (status, error-notes), (0, None) when done."""
            size_note = "Size of a request header field exceeds server limit."
            deadline = time.monotonic() + HEADER_DEADLINE
            fields, last = [], None
            while True:
                if time.monotonic() > deadline:
                    return 408, None
                try:
                    line, err = self._readline(LIMIT_REQUEST_FIELDSIZE)
                except TimeoutError:
                    return 408, None
                if err == "nospc":
                    return 400, size_note
                if err:
                    return (400, None) if err == "einval" else (-1, None)
                while len(line) > 1 and line[-1:] in (b" ", b"\t"):
                    line = line[:-1]
                if line[:1] in (b" ", b"\t"):          # obs-fold continuation line
                    if last is None or len(line) == 1:
                        return 400, None
                    rest = line[1:].lstrip(b" \t")
                    if len(last) + len(rest) + 2 >= LIMIT_REQUEST_FIELDSIZE:
                        return 400, size_note
                    last = last + b" " + rest
                    continue
                if last is not None:
                    if len(fields) + 1 > LIMIT_REQUEST_FIELDS:
                        return 400, "The number of request header fields exceeds this server's limit."
                    k = 0
                    while k < len(last) and last[k] in _TCHAR:
                        k += 1
                    if k == 0 or last[k:k + 1] != b":":
                        return 400, None                 # field name not a token or no ':'
                    value = last[k + 1:].lstrip(b" \t")
                    if any((c < 0x20 and c != 9) or c == 0x7f for c in value):
                        return 400, None
                    fields.append((last[:k], value))
                if not line:
                    break
                last = line
            merged = {}
            for name, value in fields:                   # apr_table_compress(MERGE), then the length check
                key = name.lower()
                merged[key] = merged[key] + b", " + value if key in merged else value
            if any(len(v) > LIMIT_REQUEST_FIELDSIZE for v in merged.values()):
                return 400, size_note
            raw = b"".join(n + b": " + v + b"\r\n" for n, v in fields) + b"\r\n"
            self.headers = http.client.parse_headers(io.BytesIO(raw))
            return 0, None

        def _check_request(self):
            """ap_read_request() after the headers + ap_check_request_header(): Content-Length,
            Transfer-Encoding, Host (strict fix_hostname), HTTP/1.1 Host requirement, Expect."""
            h = self.headers
            cls = h.get_all("Content-Length") or []
            if len(cls) > 1 or (cls and not (cls[0].isascii() and cls[0].isdigit())):
                return 400
            te = h.get_all("Transfer-Encoding")
            if te:
                if ",".join(te).split(",")[-1].strip().lower() != "chunked":
                    return 400
                self._force_close = True                 # the decoy does not decode chunked bodies
            hosts = h.get_all("Host") or []
            m = re.match(r"(?i)(https?)://([^/?#]*)(.*)", self.path)
            if m:                                        # absolute-form: the URI's host wins over Host:
                if "@" in m.group(2):
                    return 400
                rest = m.group(3) or "/"
                self.path = rest if rest.startswith("/") else "/" + rest
                if m.group(1).lower() == proto:
                    fixed = apache_fix_host(m.group(2))
                    if fixed is None:
                        return 400
                    self._host, self._host_port = fixed[0] or None, fixed[1]
            if self._host is None and hosts:
                fixed = apache_fix_host(", ".join(hosts)) if len(hosts) == 1 else None
                if fixed is None:
                    return 400
                self._host, self._host_port = fixed[0] or None, fixed[1]
            if (self._host is None and self._proto >= (1, 1)) or (self._proto == (1, 1) and not hosts):
                return 400                               # HTTP/1.1 request without hostname
            self._conn_tokens = tuple(t.strip().lower() for t in (h.get("Connection") or "").split(","))
            expect = h.get("Expect")
            if expect:
                if expect.lower() != "100-continue":
                    return 417
                self._expect100 = self._proto >= (1, 1)
            return 0

        def _die(self, status, notes=None):
            """ap_die() for unusable input: Apache's error page, then close (lingering)."""
            if status == -1:
                return
            if status in (400, 414):
                self.ev("http.scanner", reasons=["malformed-request" if status == 400 else "oversized-request-line"])
            self._force_close = True
            self.apache_error(status, notes=notes)

        def _conn_headers(self, status):
            """ap_set_keepalive(): Keep-Alive/Connection response headers; decides whether the socket stays."""
            if self.request_version == "HTTP/0.9":
                self.close_connection = True
                return []
            left = KEEPALIVE_MAX - self._keepalives
            ka_sent = "keep-alive" in self._conn_tokens
            if (not self._force_close and left > 0 and status not in DROPS_CONNECTION
                    and "close" not in self._conn_tokens and (ka_sent or self._proto >= (1, 1))):
                self._keepalives += 1
                self.close_connection = False
                if ka_sent:
                    return [("Keep-Alive", f"timeout={KEEPALIVE_TIMEOUT}, max={left}"), ("Connection", "Keep-Alive")]
                return []
            self.close_connection = self._drain = True
            return [("Connection", "close")]

        def finish(self):
            super().finish()
            if self._drain:                              # ap_lingering_close(): avoid an RST eating the reply
                s = self.connection
                try:
                    s.shutdown(socket.SHUT_WR)
                    s.settimeout(0.5)
                    end, got = time.monotonic() + 2, 0
                    while time.monotonic() < end and got < (1 << 20):
                        d = s.recv(65536)
                        if not d:
                            break
                        got += len(d)
                except OSError:
                    pass

        def send_response(self, code, message=None):
            """Apache status line (its reason phrases), then Date before Server like basic_http_header()."""
            self.log_request(code)
            self.send_response_only(code, APACHE_REASON.get(code, message))
            self.send_header("Date", self.date_time_string())
            self.send_header("Server", server_hdr)

        def send_error(self, code, message=None, explain=None):
            self.apache_error(code)

        def apache_error(self, status, notes=None, allow=None):
            """ap_send_error_response(): canned body, Allow on 405/501, no body or length for HEAD."""
            body = apache_error_page(status, server_hdr, self._host or server_name, self._host_port or default_port,
                                     self.command, notes, self.headers.get("Expect")).encode("latin-1", "replace")
            head = self.command == "HEAD"
            self.send_response(status)
            if status in (405, 501):
                self.send_header("Allow", ALLOW_METHODS if allow is None else allow)
            if not head:
                self.send_header("Content-Length", str(len(body)))
            for k, v in self._conn_headers(status):
                self.send_header(k, v)
            self.send_header("Content-Type", ERROR_CTYPE)
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _continue(self):
            if self._expect100:                          # 100-continue only once the handler reads the body
                self._expect100 = False
                self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                self.wfile.flush()

        def read_body(self, cap=65536):
            """Read up to cap bytes of a Content-Length body; anything we cannot consume closes the socket."""
            n = int(self.headers.get("Content-Length") or 0)
            if n > cap:
                self._force_close = True
            n = min(n, cap)
            if not n:
                return b""
            self._continue()
            try:
                return self.rfile.read(n)
            except OSError:
                self._force_close = True
                return b""

        def forbidden(self, path):
            return path in ("/.git/config", "/.git/HEAD", "/server-status", "/backup/") or \
                (path == "/wp-config.php.bak" and wordpress)

        def kind(self, path):
            """Which Apache handler serves this path on the persona: "php" (mod_php scripts: index.php front
            controller, login pages), "file" (static file under DocumentRoot), "deny" (403 before any handler),
            "php404" (missing *.php: the PHP handler 404s every method), "none" (missing, default_handler)."""
            m = re.fullmatch(r"/assets/(t[0-9a-f]{12})\.png", path)
            if m:
                t = ctx.tokens.tokens.get(m.group(1))
                return "file" if t and t.get("kind") == "document" else "none"
            if theme != "intranet" and path in ("/logout", "/", "/index.php", "/index.html", "/login"):
                return "php"
            if (theme == "helpdesk" and path.startswith("/kb/")) or path in ("/", "/index.php", "/index.html"):
                return "php"
            if path in LOGIN_PATHS or path.startswith("/phpmyadmin"):
                return "php"
            if path.startswith("/admin/") and self.cookie() in sessions:
                return "php"
            rel = path.lstrip("/")
            fp = safe_join(www, rel) if rel else None
            if fp and os.path.isfile(fp):
                return "file"
            if self.forbidden(path):
                return "deny"
            if re.search(r".\.ph(ar|p|tml)$", path):     # Ubuntu php8.1.conf FilesMatch
                return "php404"
            return "none"

        def _dispatch(self):
            """Method handling of Ubuntu Apache 2.4.52 + mod_php 8.1 (core.c default_handler, sapi_apache2.c)."""
            m = self.command
            if m not in ("GET", "HEAD", "POST", "OPTIONS"):
                self.ev("http.scanner", reasons=["method-" + m.lower()[:24]])
            if m == "TRACE":                             # TraceEnable Off: refused at map_to_storage, empty Allow
                return self.apache_error(405, allow="")
            if m == "OPTIONS" and self.path == "*":      # http_send_options(): pong without Allow
                self.read_body()
                return self.bare(200)
            path = urllib.parse.urlsplit(self.path).path
            k = self.kind(path)
            if k == "deny":
                self.read_body()
                self.ev("http.probe", detail="sensitive-path")
                return self.apache_error(403)
            if k == "php404":
                self.read_body()
                return self.not_found()
            if k == "php":                               # PHP runs the script whatever the method
                if m == "POST":
                    return self.do_POST()
                self.read_body()
                return self.do_GET()
            if m in ("GET", "HEAD"):
                return self.do_GET()
            if m == "POST" and k == "none":
                return self.do_POST()
            if m not in KNOWN_METHODS:                   # M_INVALID
                return self.apache_error(501)
            self.read_body()
            if m == "OPTIONS":
                self.ev("http.request", detail="options")
                return self.bare(200, allow=ALLOW_METHODS, ctype=mimetypes.guess_type(path)[0])
            return self.apache_error(405)                # PUT, DELETE, PROPFIND, POST to a static file, ...

        def bare(self, code, allow=None, ctype=None):
            """Empty-bodied Apache response (OPTIONS): Date, Server, [Allow], Content-Length: 0, conn, [type]."""
            self.send_response(code)
            if allow is not None:
                self.send_header("Allow", allow)
            self.send_header("Content-Length", "0")
            for k, v in self._conn_headers(code):
                self.send_header(k, v)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.end_headers()

        # -- helpers ---------------------------------------------------------
        @property
        def sess(self):
            if not hasattr(self, "_s"):
                self._s = new_session()
            return self._s

        def ev(self, t, **kw):
            ctx.emit(t, self.client_address, port, proto, self.sess, method=self.command,
                     path=self.path[:300], ua=(self.headers.get("User-Agent") or "")[:200], **kw)

        def send(self, code, body, ctype="text/html; charset=UTF-8", headers=None, php=True):
            """Handler response in Apache header order: Date, Server, handler headers, Content-Length,
            Keep-Alive/Connection, Content-Type. PHP output on HEAD has no Content-Length (http_filters.c)."""
            b = body.encode() if isinstance(body, str) else body
            head = self.command == "HEAD"
            self.send_response(code)
            if powered and php:
                self.send_header("X-Powered-By", powered)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if not (head and php):
                self.send_header("Content-Length", str(len(b)))
            for k, v in self._conn_headers(code):
                self.send_header(k, v)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.end_headers()
            if not head:
                self.wfile.write(b)

        def static_file(self, fp, data):
            """default_handler() for a file: Last-Modified, ETag (FileETag MTime Size), Accept-Ranges, type from
            mime.types without a charset (AddDefaultCharset is off on Ubuntu), no PHP headers."""
            st = os.stat(fp)
            return self.send(200, data, mimetypes.guess_type(fp)[0], php=False, headers={
                "Last-Modified": email.utils.formatdate(st.st_mtime, usegmt=True),
                "ETag": f'"{st.st_size:x}-{st.st_mtime_ns // 1000:x}"', "Accept-Ranges": "bytes"})

        def page(self, title, inner):
            return (f"<!doctype html><html><head><meta charset=utf-8><title>{html.escape(title)}</title>"
                    f"<style>{CSS}</style></head><body><header>{html.escape(company)}</header>{inner}"
                    f"<footer>&copy; {html.escape(company)} &middot; Internal use only</footer></body></html>")

        def not_found(self):
            self.ev("http.notfound")
            self.apache_error(404)

        def login_form(self, err=""):
            e = f'<p class=err>{html.escape(err)}</p>' if err else ""
            return self.page("Portal administration - Sign in",
                             f'<div class=login><h2>Administration</h2>{e}<form method=post action="/admin/login">'
                             f'<label>Username</label><input name=username autocomplete=username>'
                             f'<label>Password</label><input name=password type=password>'
                             f'<button type=submit>Sign in</button></form></div>')

        def theme_login(self, err="", user=""):
            if theme == "webmail":
                return W.webmail_login(company, mail_domain, err, user)
            return W.helpdesk_login(company, netbios, err, user)

        def triage(self):
            ua = (self.headers.get("User-Agent") or "")[:512]
            if len(self.path) > 4096:               # long paths are themselves an attack signal; cap regex input
                self.ev("http.scanner", reasons=["oversized-path"])
                return
            raw = urllib.parse.unquote_plus(self.path)
            hit = []
            if SCANNER_UA.search(ua):
                hit.append("scanner-ua")
            if EXPLOIT.search(self.path) or EXPLOIT.search(raw):
                hit.append("exploit-pattern")
            if hit:
                self.ev("http.scanner", reasons=hit)

        # -- verbs -----------------------------------------------------------
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            self.triage()
            path = urllib.parse.urlsplit(self.path).path
            ck = self.cookie()
            m = re.fullmatch(r"/assets/(t[0-9a-f]{12})\.png", path)
            if m:   # bait-document beacon: someone opened a planted Word file
                t = ctx.tokens.tokens.get(m.group(1))
                if t and t.get("kind") == "document":
                    ctx.emit("canary.hit", self.client_address, port, proto, self.sess, token=m.group(1),
                             desc=t.get("desc"), planted=t.get("planted"), ua=(self.headers.get("User-Agent") or "")[:200])
                    return self.send(200, PIXEL, "image/png", {"Cache-Control": "no-store"}, php=False)
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if theme != "intranet" and path == "/logout":
                self.ev("http.request", detail="logout")
                return self.send(302, "", headers={"Location": "/", "Set-Cookie": "PHPSESSID=deleted; Path=/; Max-Age=0"})
            if theme != "intranet" and path in ("/", "/index.php", "/index.html", "/login"):
                if ck and ck in sessions:
                    self.ev("http.admin_action", username=sessions[ck], detail=f"{theme}-home")
                    users = ctx.cfg["company"].get("users", [])
                    return self.send(200, W.webmail_inbox(company, mail_domain, sessions[ck], users) if theme == "webmail"
                                     else W.helpdesk_tickets(company, sessions[ck], users))
                if theme == "webmail" and q.get("_action", [""])[0] == "reset":
                    self.ev("http.request", detail="password-reset")
                    return self.send(200, W.webmail_reset(company, mail_domain))
                self.ev("http.request", detail=f"{theme}-login")
                return self.send(200, self.theme_login(), headers={"Cache-Control": "no-store"})
            if theme == "helpdesk" and path.startswith("/kb/"):
                self.ev("http.request", detail="kb-article")
                return self.send(200, W.helpdesk_login(company, netbios, "Please sign in to read this article."))
            if path in ("/", "/index.php", "/index.html"):
                self.ev("http.request")
                return self.send(200, self.page(f"{company} Intranet",
                                                f"<main><h2>Welcome to the {html.escape(company)} intranet</h2>"
                                                f"<p>Staff portal. Use your domain account to sign in to internal apps.</p>"
                                                f"<ul><li><a href='/admin/'>Portal administration</a></li>"
                                                f"<li>Helpdesk: ext. 200</li></ul></main>"))
            if path in LOGIN_PATHS or path.startswith("/phpmyadmin"):
                self.ev("http.request", detail="login-page")
                if ck and ck in sessions and path.startswith("/admin"):
                    return self.dashboard(sessions[ck])
                return self.send(200, self.login_form())
            if path.startswith("/admin/") and ck in sessions:
                self.ev("http.admin_action", username=sessions[ck])
                return self.dashboard(sessions[ck])
            # sensitive bait files from the web root
            rel = path.lstrip("/")
            fp = safe_join(www, rel) if rel else None
            if fp and os.path.isfile(fp):
                data = open(fp, "rb").read()
                if rel in ("robots.txt",):
                    self.ev("http.request")
                else:
                    self.ev("http.sensitive", file=rel, bytes=len(data))
                return self.static_file(fp, data)
            if self.forbidden(path):
                self.ev("http.probe", detail="sensitive-path")
                return self.apache_error(403)
            self.not_found()

        def do_POST(self):
            self.triage()
            raw_body = self.read_body()
            n = len(raw_body)
            body = raw_body.decode("utf-8", "replace")
            path = urllib.parse.urlsplit(self.path).path
            if theme != "intranet" and path in ("/login", "/"):
                f = urllib.parse.parse_qs(body)
                raw = (f.get("user") or f.get("username") or [""])[0][:128]
                pw = (f.get("pass") or f.get("password") or [""])[0][:128]
                user = raw.split("\\")[-1].split("@")[0]        # ARARAT\j.smith / j.smith@ararat.am → j.smith
                ok = ctx.check_cred(user, pw, "http", self.client_address, port, self.sess, proto)
                if ok:
                    ck = secrets.token_hex(16)
                    with lock:
                        sessions[ck] = raw or user
                    return self.send(302, "", headers={"Location": "/", "Set-Cookie": f"PHPSESSID={ck}; Path=/; HttpOnly"})
                return self.send(200, self.theme_login("Login failed. Check your email address and password."
                                                       if theme == "webmail" else "Incorrect username or password.", raw))
            if path in LOGIN_PATHS or path.startswith("/phpmyadmin"):
                f = urllib.parse.parse_qs(body)
                user = (f.get("username") or f.get("log") or f.get("pma_username") or f.get("user") or [""])[0][:128]
                pw = (f.get("password") or f.get("pwd") or f.get("pma_password") or f.get("pass") or [""])[0][:128]
                ok = ctx.check_cred(user, pw, "http", self.client_address, port, self.sess, proto)
                if ok:
                    ck = secrets.token_hex(16)
                    with lock:
                        sessions[ck] = user
                    self.send(302, "", headers={"Location": "/admin/", "Set-Cookie": f"PHPSESSID={ck}; Path=/; HttpOnly"})
                else:
                    self.send(200, self.login_form("Invalid username or password."))
                return
            self.ev("http.request", detail="post", bytes=n)
            self.not_found()

        def cookie(self):
            c = self.headers.get("Cookie") or ""
            m = re.search(r"PHPSESSID=([0-9a-f]{32})", c)
            return m.group(1) if m else None

        def dashboard(self, user):
            users = ctx.cfg["company"]["users"]
            rows = "".join(f"<tr><td>{html.escape(u['username'])}</td><td>{html.escape(u['full_name'])}</td>"
                           f"<td>{html.escape(u['dept'])}</td></tr>" for u in users)
            return self.send(200, self.page("Portal administration",
                                            f"<main><h2>Administration</h2><p>Signed in as <b>{html.escape(user)}</b></p>"
                                            f"<h3>Portal users</h3><table><tr><th>User</th><th>Name</th><th>Dept</th></tr>{rows}</table></main>"))

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True
        request_queue_size = 128

        def get_request(self):
            conn, addr = self.socket.accept()      # accept loop only accepts — never blocks on a client
            return conn, addr

        def process_request_thread(self, request, client_address):
            ctx.emit("tcp.connect", client_address, port, proto, None)
            if tls:                                # TLS handshake in the per-client thread (slowloris-safe)
                request.settimeout(15)
                try:
                    request = tls.wrap_socket(request, server_side=True)
                except Exception as e:
                    ctx.emit("tls.failed", client_address, port, proto, None, error=str(e)[:120])
                    request.close()
                    return
            super().process_request_thread(request, client_address)

        def handle_error(self, request, client_address):
            pass

    srv = Server((bind_ip(), port), H)
    # decoy-wide connection budget (F-02, RC-28) + self-check; the serving thread runs serve_forever
    return serve_socketserver(ctx, srv, port, proto, name=f"http:{port}")
