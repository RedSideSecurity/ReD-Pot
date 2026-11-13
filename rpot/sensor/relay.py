"""Relay sidecar for REMOTE sensors.

Why: a remote decoy container only has the decoy LAN interface (its default route must go
via the decoy gateway so it can answer attackers in other subnets). Management traffic must
not leave from the decoy's IP, so the decoy talks HTTP over a Unix socket (shared volume) to
this relay; the relay lives on a normal host network and forwards to the manager over HTTPS
pinned to the manager fingerprint. The decoy IP never contacts the manager.

  rpot relay  --socket /run/rpot/relay.sock --sensor-json /var/lib/rpot/sensor.json
"""
import argparse
import http.client
import json
import os
import socket
import socketserver
import sys
import time
from http.server import BaseHTTPRequestHandler

from rpot.common.tlsutil import PinnedClient

ALLOWED = {("POST", "/api/ingest"), ("GET", "/api/config")}


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=10):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.path)
        self.sock = s


class UnixClient:
    """Same interface as PinnedClient, used by the decoy when RPOT_RELAY_SOCKET is set."""

    def __init__(self, path, auth=None, timeout=10):
        self.path, self.auth, self.timeout = path, auth, timeout

    def request(self, method, path, body=None, extra_headers=None):
        c = UnixHTTPConnection(self.path, self.timeout)
        try:
            headers = {"Content-Type": "application/json"}
            if self.auth:
                headers["Authorization"] = f"Bearer {self.auth}"
            c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
            r = c.getresponse()
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
        finally:
            c.close()


def serve(sock_path, url, fingerprint):
    upstream = PinnedClient(url, fingerprint, timeout=15)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _fwd(self):
            if (self.command, self.path) not in ALLOWED:
                return self._send(404, {"error": "not allowed"})
            n = min(int(self.headers.get("Content-Length") or 0), 16 * 1024 * 1024)
            body = json.loads(self.rfile.read(n) or b"null") if n else None
            upstream.auth = (self.headers.get("Authorization") or "")[7:] or None
            try:
                status, res = upstream.request(self.command, self.path, body)
            except Exception as e:
                return self._send(502, {"error": f"{type(e).__name__}: {e}"[:200]})
            self._send(status, res)

        do_GET = do_POST = _fwd

        def _send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    if os.path.exists(sock_path):
        os.remove(sock_path)
    os.makedirs(os.path.dirname(sock_path), exist_ok=True)
    srv = S(sock_path, H)
    os.chmod(sock_path, 0o660)
    print(f"[ReD-Pot relay] {sock_path} → {url}", flush=True)
    srv.serve_forever()


def main(argv=None):
    ap = argparse.ArgumentParser(description="ReD-Pot sensor relay")
    ap.add_argument("--socket", default=os.environ.get("RPOT_RELAY_SOCKET", "/run/rpot/relay.sock"))
    ap.add_argument("--sensor-json", default=os.environ.get("RPOT_SENSOR_JSON", "/var/lib/rpot/sensor.json"))
    a = ap.parse_args(argv)
    for _ in range(600):                      # wait until the sensor has enrolled (sensor.json exists)
        if os.path.exists(a.sensor_json):
            break
        time.sleep(1)
    with open(a.sensor_json) as f:
        m = json.load(f)["manager"]
    serve(a.socket, m["url"], m["fingerprint"])


if __name__ == "__main__":
    sys.exit(main())
