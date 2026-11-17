"""QA Q3 (1.0.1 VM test): while the manager is unreachable the sensor relay printed full Python tracebacks
(OSError: No route to host -> BrokenPipeError when the sensor had already given up). Now: one line per kind per
minute, never a traceback."""
import contextlib
import io
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rpot.sensor import relay  # noqa: E402


class FakeUpstream:
    def __init__(self, *a, **k):
        self.auth = None

    def request(self, method, path, body=None):
        time.sleep(0.4)                       # slower than the client below waits
        raise OSError(113, "No route to host")


class TestRelayQuiet(unittest.TestCase):
    def test_unreachable_manager_gives_one_line_not_tracebacks(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            sock = os.path.join(d, "r", "relay.sock")
            notes = relay.Notes(out=out)
            with mock.patch.object(relay, "PinnedClient", FakeUpstream), contextlib.redirect_stderr(err), \
                    contextlib.redirect_stdout(io.StringIO()):
                t = threading.Thread(target=relay.serve, args=(sock, "https://192.0.2.1:1", "AB" * 32, notes),
                                     daemon=True)
                t.start()
                for _ in range(100):
                    if os.path.exists(sock):
                        break
                    time.sleep(0.05)
                # 1) the sensor hangs up before the answer (broken pipe on the relay side)
                for _ in range(3):
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.connect(sock)
                    s.sendall(b"POST /api/ingest HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
                    s.close()
                time.sleep(1.5)
                # 2) a sensor that waits gets a 502 with the reason
                c = relay.UnixClient(sock, timeout=10)
                status, body = c.request("POST", "/api/ingest", {"events": []})
        self.assertEqual(status, 502)
        self.assertIn("No route to host", body["error"])
        log = out.getvalue()
        self.assertNotIn("Traceback", err.getvalue() + log)
        self.assertEqual(log.count("manager unreachable"), 1)          # rate-limited: one line, not four
        self.assertLessEqual(log.count("closed the connection"), 1)

    def test_notes_rate_limit_and_count(self):
        now = [0.0]
        out = io.StringIO()
        n = relay.Notes(every=60, clock=lambda: now[0], out=out)
        self.assertTrue(n("upstream", "manager unreachable: x"))
        self.assertFalse(n("upstream", "manager unreachable: x"))
        self.assertFalse(n("upstream", "manager unreachable: x"))
        self.assertTrue(n("client", "other kind"))
        now[0] = 61
        self.assertTrue(n("upstream", "manager unreachable: y"))
        self.assertIn("manager unreachable: y (2 more since the last note)", out.getvalue())


if __name__ == "__main__":
    unittest.main()
