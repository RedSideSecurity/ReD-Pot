"""RC-23: B3 DC DNS fingerprint (nmap -sV said "NLnet Labs NSD") and B4 scan detection on small decoys."""
import os
import re
import socket
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.console import scoring
from rpot.sensor.services.dns import answer
from test_dc_dns import DCBase

# Probes and match lines copied verbatim from /usr/share/nmap/nmap-service-probes,
# Nmap 7.94SVN (Debian/Ubuntu package nmap-common 7.94+git20230807.3be01efb1+dfsg-3build2).
# Probe UDP DNSVersionBindReq      (line 12445)
VERSION_BIND_UDP = b"\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03"
# Probe TCP DNSVersionBindReqTCP   (line 12617)
VERSION_BIND_TCP = b"\0\x1E\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03"
# Probe UDP DNSStatusRequest       (line 12771)
STATUS_UDP = b"\0\0\x10\0\0\0\0\0\0\0\0\0"
# Probe TCP DNSStatusRequestTCP    (line 12818)
STATUS_TCP = b"\0\x0C\0\0\x10\0\0\0\0\0\0\0\0\0"

# match domain ... p/Simple DNS Plus/ o/Windows/                             (line 12567)
# = what nmap -sV reports for a real Windows DC with the default EnableVersionQuery=0 (CHAOS → NOTIMP, 0x8104)
SIMPLE_DNS_PLUS = rb"^(?:..)?\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03"
# Lines the DC must NOT hit: NSD (12571, the B3 result: REFUSED 0x8105), Unbound (12566: REFUSED+RA 0x8185),
# Cloudflare (12568: NOTIMP+RA 0x8184 — why RA stays clear on this reply), ISC BIND on Ubuntu (12463), and the
# generic "unknown banner" softmatch (12575: any CHAOS TXT version answer).
WRONG = {
    "NLnet Labs NSD": rb"^(?:..)?\0\x06\x81\x05\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03",
    "Unbound": rb"^(?:..)?\0\x06\x81\x85\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03",
    "Cloudflare public DNS": rb"^(?:..)?\0\x06\x81\x84\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03",
    "ISC BIND Ubuntu": rb"\x07version\x04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03.{7}(\d[-\w.+]*?)-[Uu]buntu",
    "unknown banner": rb"\x07version\x04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03.{7}([^\0\xc0\x0c]+)",
}
# DNSStatusRequest has no Microsoft DNS line; the generic NOTIMP softmatch (line 12782) is what applies.
STATUS_NOTIMP = rb"^(?:..)?..\x90[\x04\x84\x94]\0\0\0\0\0\0\0\0$"


def m(rx, data):
    return re.search(rx, data, re.S)


class TestDNSFingerprint(DCBase):
    def udp(self, payload):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(payload, ("127.0.0.1", self.p["dns"]))
            return s.recv(4096)
        finally:
            s.close()

    def tcp(self, payload):
        s = socket.create_connection(("127.0.0.1", self.p["dns"]), timeout=3)
        try:
            s.sendall(payload)
            hdr = s.recv(2)
            n = struct.unpack(">H", hdr)[0]
            body = b""
            while len(body) < n:
                body += s.recv(n - len(body))
            return hdr + body                     # nmap matches the TCP reply with its 2-byte length prefix
        finally:
            s.close()

    def test_version_bind_matches_simple_dns_plus_udp_and_tcp(self):
        for r in (self.udp(VERSION_BIND_UDP), self.tcp(VERSION_BIND_TCP)):
            self.assertTrue(m(SIMPLE_DNS_PLUS, r), r)
            for name, rx in WRONG.items():
                self.assertIsNone(m(rx, r), name)
        r = self.udp(VERSION_BIND_UDP)
        self.assertEqual(struct.unpack(">HHHHH", r[2:12]), (0x8104, 1, 0, 0, 0))   # QR|RD, NOTIMP, no AA/RA
        self.assertEqual(len(r), len(VERSION_BIND_UDP))                            # question only, no amplification
        self.assertTrue(self.em.of("dns.version"))
        import dns.message                                                          # RA on every other DC answer
        r = dns.message.from_wire(self.udp(dns.message.make_query("dc01.corp.ararat.am", "A").to_wire()))
        self.assertTrue(r.flags & dns.flags.RA)

    def test_status_request_is_header_only_notimp(self):
        for req, r in ((STATUS_UDP, self.udp(STATUS_UDP)), (STATUS_TCP, self.tcp(STATUS_TCP))):
            self.assertTrue(m(STATUS_NOTIMP, r), r)
            self.assertLessEqual(len(r), len(req))               # never an amplifier
            self.assertEqual(struct.unpack(">H", r[-10:-8])[0], 0x9084)   # QR | opcode STATUS | RA | NOTIMP
        self.assertTrue(any(e.get("qtype") == "OPCODE2" for e in self.em.of("dns.query")))

    def test_ra_bit_never_means_recursion(self):
        """Out-of-zone names: SERVFAIL, no answer, RA set; nothing is resolved upstream."""
        import dns.message
        ctx, _ = self.ctxs["DC01"]

        def boom(*a, **k):
            raise AssertionError("the DNS decoy must never open a socket to resolve a name")
        with mock.patch.object(socket, "getaddrinfo", boom), mock.patch.object(socket, "create_connection", boom), \
                mock.patch.object(socket, "gethostbyname", boom):
            for name in ("google.com", "example.org", "version.bind"):
                q = dns.message.make_query(name, "A")
                q.flags |= dns.flags.RD
                r = dns.message.from_wire(answer(ctx, q.to_wire(), ("10.0.0.9", 5353), 53, "dns"))
                self.assertEqual((r.rcode(), r.answer), (2, []), name)
                self.assertTrue(r.flags & dns.flags.RA)
                self.assertFalse(r.flags & dns.flags.AA)
            for name in ("version.bind", "hostname.bind", "id.server"):   # every CHAOS name: NOTIMP, no data
                r = dns.message.from_wire(answer(ctx, dns.message.make_query(name, "TXT", "CH").to_wire(),
                                                 ("10.0.0.9", 5353), 53, "dns"))
                self.assertEqual((r.rcode(), r.answer), (4, []), name)
                self.assertFalse(r.flags & (dns.flags.RA | dns.flags.AA))

    def test_bind_role_unchanged(self):
        import dns.message
        ctx, _ = self.ctxs["DNS01"]
        r = answer(ctx, VERSION_BIND_UDP, ("10.0.0.9", 5353), 53, "dns")
        self.assertIn(b"9.18", r)
        self.assertTrue(m(WRONG["ISC BIND Ubuntu"], r))                 # the Linux DNS role stays ISC BIND
        self.assertIsNone(m(SIMPLE_DNS_PLUS, r))
        r = answer(ctx, STATUS_UDP, ("10.0.0.9", 5353), 53, "dns")
        self.assertEqual(r, b"\0\0\x90\x04" + b"\0" * 8)          # BIND: NOTIMP, no RA
        r = dns.message.from_wire(answer(ctx, dns.message.make_query("google.com", "A").to_wire(),
                                         ("10.0.0.9", 5353), 53, "dns"))
        self.assertEqual(r.rcode(), 5)
        self.assertFalse(r.flags & dns.flags.RA)

    def test_hostile_headers(self):
        ctx, _ = self.ctxs["DC01"]
        for data in (b"", b"\0" * 11, b"\x80" * 12, b"\x00\x01\x81\x00" + b"\0" * 8, STATUS_UDP[:11]):
            r = answer(ctx, data, ("10.0.0.9", 5353), 53, "dns")
            self.assertTrue(r is None or len(r) <= max(len(data), 12), data)
        for op in range(1, 16):                                   # every non-QUERY opcode: 12-byte NOTIMP
            r = answer(ctx, bytes([0, 1, op << 3, 0]) + b"\0\x05" * 4 + b"x" * 40, ("10.0.0.9", 5353), 53, "dns")
            self.assertEqual((len(r), r[3] & 0x0F, (r[2] >> 3) & 0x0F), (12, 4, op))


def sev(sensor, role, port, src="10.0.0.66"):
    return {"ts": "2026-11-13T10:00:00Z", "sensor": sensor, "role": role, "sensor_ip": "10.9.0.20", "src_ip": src,
            "src_port": 40000, "dst_port": port, "proto": "tcp", "type": "tcp.connect", "session": None, "data": {}}


class TestScanSmallDecoys(unittest.TestCase):
    FS = "windows-file-server"

    def run_ports(self, sc, sensor, role, ports, t0=1000, step=1, src="10.0.0.66"):
        out = []
        for i, p in enumerate(ports):
            out += sc.escalations(sev(sensor, role, p, src), now=t0 + i * step)
        return [o for o in out if o["type"] == "scan.detected"]

    def test_role_port_counts_from_catalog(self):
        rp = scoring.role_ports()
        self.assertEqual(rp[self.FS], 4)
        self.assertEqual(rp["linux-web-hosting"], 3)
        self.assertEqual(rp["ftp-backup-server"], 2)
        self.assertGreaterEqual(rp["windows-domain-controller"], 5)
        self.assertEqual([scoring.scan_threshold(n) for n in (None, 0, 2, 3, 4, 5, 12)], [None, None, None, 3, 4, 5, 5])

    def test_full_sweep_of_file_server_is_a_scan(self):
        """VM B4: nmap -sT -p- of the FS decoy reaches only 135/139/445/3389 (host firewall rejects the rest)."""
        sc = scoring.Scorer()
        out = self.run_ports(sc, "FS01", self.FS, [135, 139, 445, 3389])
        self.assertEqual(len(out), 1)
        self.assertEqual(scoring.score(out[0]), 3)
        self.assertEqual(out[0]["data"]["ports"], 4)
        self.assertEqual(self.run_ports(sc, "FS01", self.FS, [135, 445], t0=1010), [])     # cooldown

    def test_slow_sweep_inside_window_and_expiry(self):
        sc = scoring.Scorer()
        self.assertEqual(len(self.run_ports(sc, "FS01", self.FS, [135, 139, 445, 3389], step=150)), 1)  # 450 s < 600
        sc = scoring.Scorer()
        self.assertEqual(self.run_ports(sc, "FS01", self.FS, [135, 139, 445, 3389], step=scoring.SCAN_WINDOW // 3 + 1), [])

    def test_smb_and_rdp_client_is_not_a_scan(self):
        sc = scoring.Scorer()
        # a Windows client: SMB on 445 with the parallel 139 attempt, then RDP; repeated touches don't add ports
        self.assertEqual(self.run_ports(sc, "FS01", self.FS, [445, 139, 445, 3389, 445, 3389, 139]), [])

    def test_ports_spread_over_two_file_servers_need_the_global_rule(self):
        sc = scoring.Scorer()
        self.assertEqual(self.run_ports(sc, "FS01", self.FS, [445, 3389]) +
                         self.run_ports(sc, "FS02", self.FS, [445, 139], t0=1002), [])  # 4 distinct sensor:port < 5
        self.assertEqual(len(self.run_ports(sc, "FS02", self.FS, [3389], t0=1004)), 1)  # 5th → global rule

    def test_small_and_unknown_roles(self):
        sc = scoring.Scorer()
        self.assertEqual(len(self.run_ports(sc, "WEB01", "linux-web-hosting", [22, 80, 443])), 1)
        sc = scoring.Scorer()
        self.assertEqual(self.run_ports(sc, "BKP01", "ftp-backup-server", [21, 22]), [])       # 2 ports: no rule
        sc = scoring.Scorer()
        self.assertEqual(self.run_ports(sc, "X1", "no-such-role", [1, 2, 3, 4]), [])           # unknown: needs 5
        self.assertEqual(len(self.run_ports(sc, "X1", "no-such-role", [5], t0=1005)), 1)
        sc = scoring.Scorer(roles={})                                                        # no catalog
        self.assertEqual(self.run_ports(sc, "FS01", self.FS, [135, 139, 445, 3389]), [])

    def test_engine_raises_incident_for_fs_sweep(self):
        import tempfile
        from rpot.console.engine import Engine
        from test_unit import mkcfg
        with tempfile.TemporaryDirectory() as d:
            e = Engine(mkcfg(d), os.path.join(d, "t.db"))
            e.ingest([dict(sev("FS01", self.FS, p, src="10.0.0.77"), sensor_ip="172.30.0.21", ts=None)
                      for p in (135, 139, 445, 3389)])
            n = e.db.execute("SELECT COUNT(*) FROM events WHERE type='scan.detected' AND src_ip='10.0.0.77'").fetchone()[0]
            self.assertEqual(n, 1)
            inc = e.incidents(min_level=1)
            self.assertEqual([i["level"] for i in inc], [3])
            e.db.close()

if __name__ == "__main__":
    unittest.main()
