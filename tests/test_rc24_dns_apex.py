"""RC-24 / VM finding B8: the DC decoy's DNS had no zone apex (SOA/NS/A → NXDOMAIN), _msdcs / _tcp → NXDOMAIN while
names below them resolved, and negative answers carried no SOA.

What a real Windows Server DC answers, and where the expected values come from:
  * Microsoft Learn, "How DNS Support for Active Directory Works" (Windows Server 2003 Technical Reference,
    cc759550(v=ws.10); still the reference for the Net Logon record set): the _msdcs subdomain, the SRV records
    Net Logon registers (_ldap/_kerberos/_kpasswd/_gc under _tcp/_udp, the <site>._sites variants, dc/gc/pdc and
    <DomainGuid>.domains under _msdcs) and <DsaGuid>._msdcs.<forest> (CNAME to the DC's FQDN).
  * Microsoft Learn KB 816587, "How to verify that SRV DNS records have been created for a domain controller":
    the _msdcs/dc/_tcp and _msdcs/dc/_sites/Default-First-Site-Name/_tcp layout, netlogon.dns.
  * Windows DNS defaults for a new zone (DNS Manager > Start of Authority tab, also what dcpromo creates): primary
    server = the DC, responsible person hostmaster.<domain>, refresh 15 min (900), retry 10 min (600), expire
    1 day (86400), minimum TTL 1 h (3600), SOA/NS TTL 1 h; serial is a counter bumped by dynamic updates.
    Netlogon's DnsTtl default 600 s (SRV, "same as parent folder" A, CNAME); DNS-client host A records 1200 s.
    Since Windows Server 2003 dcpromo puts _msdcs.<forest root> in its own forest-wide zone, delegated from the
    domain zone; AD-integrated zones allow no zone transfers by default (AXFR/IXFR → REFUSED). These values are
    from the product defaults as documented by Microsoft (and seen on real DCs), not re-measured on a Windows VM
    in this task.
  * RFC 2308 §3/§5: NXDOMAIN and NODATA carry the zone SOA in AUTHORITY, TTL = min(SOA TTL, SOA MINIMUM).
  * RFC 8020: NXDOMAIN means nothing exists below the name, so an empty non-terminal (_tcp, _sites, …) must be
    NOERROR/NODATA (RFC 4592 §2.2.2 defines empty non-terminals).
  * RFC 8482: a server may answer ANY with one RRset; the decoy does so over UDP to stay a non-amplifier.
  * nmap 7.94 /usr/share/nmap/scripts/dns-srv-enum.nse lines 143-150: the SRV names it asks for.
"""
import os
import re
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dns.flags                      # noqa: E402
import dns.message                    # noqa: E402
import dns.query                      # noqa: E402
import dns.rcode                      # noqa: E402
import dns.rdatatype as T             # noqa: E402

from rpot.sensor.services import dns as D       # noqa: E402
from test_dc_dns import DCBase                  # noqa: E402

DOM = "corp.ararat.am"
DC = "dc01.corp.ararat.am."
SRC = ("10.0.0.9", 5353)


class Base(DCBase):
    def q(self, name, rtype="A", tcp=True):
        # TCP by default: the UDP listener rate-limits each source (10/s, burst 20, rpot/sensor/base.py serve_udp)
        m = dns.message.make_query(name, rtype)
        return (dns.query.tcp if tcp else dns.query.udp)(m, "127.0.0.1", port=self.p["dns"], timeout=3)

    def direct(self, sensor, name, rtype="A", tcp=False):
        ctx, _ = self.ctxs[sensor]
        raw = D.answer(ctx, dns.message.make_query(name, rtype).to_wire(), SRC, 53, "dns", tcp=tcp)
        return dns.message.from_wire(raw)

    def soa_auth(self, r, origin):
        self.assertEqual(len(r.authority), 1, r)
        rr = r.authority[0]
        self.assertEqual((str(rr.name), rr.rdtype), (origin + ".", T.SOA))
        self.assertEqual(rr.ttl, rr[0].minimum)                           # RFC 2308: TTL = MINIMUM (= SOA TTL)
        return rr[0]


class TestDCApex(Base):
    def test_apex_soa_ns_a(self):
        for tcp in (False, True):
            r = self.q(DOM, "SOA", tcp=tcp)                               # UDP + TCP
            self.assertEqual(r.rcode(), 0)
            self.assertTrue(r.flags & dns.flags.AA and r.flags & dns.flags.RA)
            soa = r.answer[0]
            self.assertEqual(soa.ttl, 3600)
            s = soa[0]
            self.assertEqual((str(s.mname), str(s.rname)), (DC, "hostmaster.corp.ararat.am."))
            self.assertEqual((s.refresh, s.retry, s.expire, s.minimum), (900, 600, 86400, 3600))
            self.assertTrue(40 <= s.serial < 10 ** 6)                     # a Windows counter, not YYYYMMDDnn
        r = self.q(DOM, "NS")
        self.assertEqual([str(x.target) for x in r.answer[0]], [DC])
        self.assertEqual(r.answer[0].ttl, 3600)
        self.assertEqual(r.additional[0][0].address, "10.9.0.10")         # glue
        r = self.q(DOM, "A")
        self.assertEqual(([x.address for x in r.answer[0]], r.answer[0].ttl), (["10.9.0.10"], 600))

    def test_serial_stable_and_monotonic(self):
        ctx, _ = self.ctxs["DC01"]
        now = 1_790_000_000
        a = D.build_zones(ctx, now)[DOM][DOM][0][2][2]
        self.assertEqual(a, D.build_zones(ctx, now)[DOM][DOM][0][2][2])  # same across restarts
        self.assertEqual(D._serial(ctx, True, "dom", now + 21600), a + 1)
        self.assertGreater(D._serial(ctx, True, "dom", now + 86400 * 30), a)

    def test_msdcs_zone(self):
        r = self.q("_msdcs." + DOM, "SOA", tcp=False)
        self.assertEqual(r.rcode(), 0)
        self.assertEqual((str(r.answer[0].name), str(r.answer[0][0].mname)), ("_msdcs.corp.ararat.am.", DC))
        self.assertEqual(r.answer[0][0].minimum, 3600)
        self.assertEqual([str(x.target) for x in self.q("_msdcs." + DOM, "NS").answer[0]], [DC])
        r = self.q("_msdcs." + DOM, "A")                                  # NODATA from the _msdcs zone
        self.assertEqual((r.rcode(), r.answer), (0, []))
        self.soa_auth(r, "_msdcs." + DOM)
        for name, port in (("_ldap._tcp.dc._msdcs", 389), ("_kerberos._tcp.dc._msdcs", 88),
                           ("_ldap._tcp.gc._msdcs", 3268), ("_ldap._tcp.pdc._msdcs", 389),
                           ("_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs", 389),
                           ("_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs", 88)):
            r = self.q(f"{name}.{DOM}", "SRV")
            srv = r.answer[0]
            self.assertEqual((srv[0].port, str(srv[0].target), srv.ttl, srv[0].priority, srv[0].weight),
                             (port, DC, 600, 0, 100), name)
            self.assertEqual(r.additional[0][0].address, "10.9.0.10")
        self.assertEqual(self.q("gc._msdcs." + DOM).answer[0][0].address, "10.9.0.10")

    def test_guid_records(self):
        ctx, _ = self.ctxs["DC01"]
        z = D.build_zones(ctx)["_msdcs." + DOM]
        guid_rx = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
        cn = [n for n, rrs in z.items() if any(r[0] == D.CNAME for r in rrs)]
        self.assertEqual(len(cn), 1)
        self.assertRegex(cn[0], rf"^{guid_rx}\._msdcs\.{re.escape(DOM)}$")
        r = self.q(cn[0], "A")                                            # CNAME chased inside our zones
        self.assertEqual([(x.rdtype, x.ttl) for x in r.answer], [(T.CNAME, 600), (T.A, 1200)])
        self.assertEqual((str(r.answer[0][0].target), r.answer[1][0].address), (DC, "10.9.0.10"))
        dom_srv = [n for n in z if n.endswith(".domains._msdcs." + DOM)]
        self.assertEqual(len(dom_srv), 1)
        self.assertRegex(dom_srv[0], rf"^_ldap\._tcp\.{guid_rx}\.domains\._msdcs\.")
        self.assertEqual(self.q(dom_srv[0], "SRV").answer[0][0].port, 389)
        self.assertEqual(sorted(D.build_zones(ctx)["_msdcs." + DOM]), sorted(z))       # stable
        co = dict(ctx.cfg["company"], seed=ctx.cfg["company"]["seed"] + 1)          # differs per install
        other = type(ctx).__new__(type(ctx))
        other.__dict__.update(ctx.__dict__, cfg=dict(ctx.cfg, company=co))
        self.assertNotIn(cn[0], D.build_zones(other)["_msdcs." + DOM])

    def test_empty_non_terminals_are_nodata(self):
        for name, origin in (("_tcp", DOM), ("_udp", DOM), ("_sites", DOM), ("Default-First-Site-Name._sites", DOM),
                             ("_tcp.Default-First-Site-Name._sites", DOM), ("_tcp.DomainDnsZones", DOM),
                             ("dc._msdcs", "_msdcs." + DOM), ("_tcp.dc._msdcs", "_msdcs." + DOM),
                             ("domains._msdcs", "_msdcs." + DOM), ("gc._msdcs", "_msdcs." + DOM)):
            r = self.q(f"{name}.{DOM}", "SRV")
            self.assertEqual((r.rcode(), r.answer), (0, []), name)
            self.assertTrue(r.flags & dns.flags.AA)
            self.soa_auth(r, origin)
        for name in ("DomainDnsZones", "ForestDnsZones"):          # Net Logon registers A records for these
            self.assertEqual(self.q(f"{name}.{DOM}").answer[0][0].address, "10.9.0.10")
            self.assertEqual(self.q(f"_ldap._tcp.{name}.{DOM}", "SRV").answer[0][0].port, 389)

    def test_nxdomain_with_soa(self):
        for name, origin in (("nothere." + DOM, DOM), ("x.nothere." + DOM, DOM), ("_ldap._tcp.bogus." + DOM, DOM),
                             ("nothere._msdcs." + DOM, "_msdcs." + DOM)):
            r = self.q(name, tcp=False)
            self.assertEqual((r.rcode(), r.answer), (3, []), name)
            self.assertTrue(r.flags & dns.flags.AA)
            s = self.soa_auth(r, origin)
            self.assertEqual(str(s.mname), DC)
        r = self.q("dc01." + DOM, "MX")                                   # NODATA on an existing host
        self.assertEqual((r.rcode(), r.answer), (0, []))
        self.soa_auth(r, DOM)

    def test_nmap_dns_srv_enum_names(self):
        """The queries of nmap's dns-srv-enum (it asks the system resolver, so it can't be pointed at a test port)."""
        want = {"_gc._tcp": 3268, "_kerberos._tcp": 88, "_kerberos._udp": 88, "_kpasswd._tcp": 464,
                "_kpasswd._udp": 464, "_ldap._tcp": 389}
        for name in list(want) + ["_autodiscover._tcp", "_sip._udp", "_sip._tcp", "_xmpp-server._tcp",
                                  "_xmpp-client._tcp"]:
            r = self.q(f"{name}.{DOM}", "SRV")
            if name in want:
                self.assertEqual([(x.port, str(x.target)) for x in r.answer[0]], [(want[name], DC)], name)
            else:
                self.assertEqual(r.rcode(), 3, name)
                self.soa_auth(r, DOM)

    def test_axfr_ixfr_refused_and_no_recursion(self):
        for rtype, tcp in (("AXFR", True), ("IXFR", True), ("IXFR", False)):
            for zone in (DOM, "_msdcs." + DOM):
                r = self.q(zone, rtype, tcp=tcp)
                self.assertEqual((r.rcode(), r.answer, r.authority), (5, [], []), (zone, rtype))
        for name in ("google.com", "am", "ararat.am", "xcorp.ararat.am"):
            r = self.q(name)
            self.assertEqual((r.rcode(), r.answer, r.authority, r.additional), (2, [], [], []), name)
            self.assertFalse(r.flags & dns.flags.AA)

    def test_any_is_not_an_amplifier(self):
        r = self.q(DOM, "ANY", tcp=False)
        self.assertEqual([x.rdtype for x in r.answer], [T.SOA])          # UDP: one RRset
        r = self.q(DOM, "ANY", tcp=True)
        self.assertEqual([x.rdtype for x in r.answer], [T.SOA, T.NS, T.A])
        ctx, _ = self.ctxs["DC01"]
        names = [DOM, "_msdcs." + DOM, "_tcp." + DOM, "a." + DOM, "dc01." + DOM, "_ldap._tcp.dc._msdcs." + DOM,
                 "gc._msdcs." + DOM, "x" * 63 + "." + "y" * 63 + "." + DOM, "google.com"]
        names += [n for n in D.build_zones(ctx)["_msdcs." + DOM] if "-" in n.split(".")[0]]
        worst = 0
        for n in names:
            for t in ("A", "NS", "SOA", "SRV", "ANY", "CNAME", "TXT", "MX", "AAAA"):
                q = dns.message.make_query(n, t, use_edns=False).to_wire()
                r = D.answer(ctx, q, SRC, 53, "dns")
                dns.message.from_wire(r)
                worst = max(worst, len(r) - len(q))
                self.assertLessEqual(len(r), 512)
        self.assertLessEqual(worst, 64)                                    # SOA/SRV+glue, compressed

    def test_compression_with_odd_labels(self):
        """Labels with '.' or non-ASCII bytes in the question must never become compression targets."""
        ctx, _ = self.ctxs["DC01"]
        dom = b"".join(bytes([len(p)]) + p.encode() for p in DOM.split("."))
        for label in (b"a.b", b"\xff\xfe", b"CORP"):
            q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + bytes([len(label)]) + label + dom + b"\0\0\x01\0\x01"
            r = dns.message.from_wire(D.answer(ctx, q, SRC, 53, "dns"))
            self.assertEqual(r.rcode(), 3)
            self.assertEqual(str(r.authority[0].name), DOM + ".")
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04corp\x07ARA.RAT\x02am\0\0\x06\0\x01"
        r = dns.message.from_wire(D.answer(ctx, q, SRC, 53, "dns"))    # "corp.ara.rat.am" as a string, not ours
        self.assertEqual(r.rcode(), 2)

    def test_fuzzed_queries_never_crash(self):
        import random
        ctx, _ = self.ctxs["DC01"]
        rng = random.Random(24)
        seeds = [dns.message.make_query(n, t).to_wire() for n, t in
                 ((DOM, "SOA"), ("_ldap._tcp.dc._msdcs." + DOM, "SRV"), ("_tcp." + DOM, "A"))]
        for _ in range(1500):
            b = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(1, 4)):
                b[rng.randrange(12, len(b))] = rng.randrange(256)
            r = D.answer(ctx, bytes(b), SRC, 53, "dns")
            if r is not None:
                self.assertLessEqual(len(r), 512)
                self.assertEqual(r[:2], bytes(b[:2]))


class TestBindRoleApex(Base):
    def test_apex_and_negative_answers(self):
        r = self.direct("DNS01", DOM, "SOA")
        s = r.answer[0][0]
        self.assertEqual((str(s.mname), str(s.rname)), ("ns1.corp.ararat.am.", "hostmaster.corp.ararat.am."))
        self.assertEqual((s.refresh, s.retry, s.expire, s.minimum), (10800, 3600, 604800, 3600))
        day = time.strptime(str(s.serial)[:8], "%Y%m%d")                  # YYYYMMDDnn, in the past
        self.assertLess(time.mktime(day), time.time())
        self.assertTrue(1 <= s.serial % 100 <= 4)
        r = self.direct("DNS01", DOM, "NS")
        self.assertEqual(([str(x.target) for x in r.answer[0]], r.additional[0][0].address),
                         (["ns1.corp.ararat.am."], "10.9.0.11"))
        self.assertEqual(self.direct("DNS01", DOM).answer[0][0].address, "10.9.0.10")   # AD domain: apex = DC
        for name, rc in (("nothere." + DOM, 3), ("_tcp." + DOM, 0), ("_msdcs." + DOM, 0)):
            r = self.direct("DNS01", name, "SRV")
            self.assertEqual((r.rcode(), r.answer), (rc, []), name)
            self.soa_auth(r, DOM)
        self.assertEqual(self.direct("DNS01", "_ldap._tcp.dc._msdcs." + DOM, "SRV").answer[0][0].port, 389)
        r = self.direct("DNS01", DOM, "AXFR", tcp=True)
        self.assertEqual((r.rcode(), r.answer), (5, []))
        r = self.direct("DNS01", "google.com")
        self.assertEqual((r.rcode(), r.answer, r.authority), (5, [], []))
        self.assertFalse(r.flags & dns.flags.RA)

    def test_no_dc_apex_points_at_web_and_old_config_without_seed(self):
        ctx, _ = self.ctxs["DNS01"]
        roles = {k: v for k, v in ctx.cfg["zone_roles"].items() if v != "windows-domain-controller"}
        co = {k: v for k, v in ctx.cfg["company"].items() if k != "seed"}
        other = type(ctx).__new__(type(ctx))
        other.__dict__.update(ctx.__dict__, cfg=dict(ctx.cfg, zone_roles=roles, company=co))
        z = D.build_zones(other)[DOM]
        self.assertEqual([r for r in z[DOM] if r[0] == D.A], [(D.A, 3600, "10.9.0.22")])
        self.assertFalse(any(n.startswith("_") for n in z))
        self.assertEqual(D.build_zones(other)[DOM][DOM][0], z[DOM][0])     # persona_secret fallback is stable


if __name__ == "__main__":
    unittest.main()
