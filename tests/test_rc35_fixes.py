"""RC-35 (CE 1.0.1): fixes from the 1.0.0 live test (2026-11-16).

  * B2: "Live external activity" (worldmap feed) lost L4 events: internal noise used up the 400-row window
    before the internal filter, L2/L3 noise pushed L4/L5 out of the newest 40, and min_level was ignored.
  * B4: IPv4-mapped IPv6 (::ffff:a.b.c.d) was classified as external / never matched IPv4 allow-lists.
"""
import os
import sqlite3
import sys
import tempfile
import unittest

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.common.events import Emitter, now_iso  # noqa: E402
from rpot.common.iputil import ip_obj, norm_ip  # noqa: E402
from rpot.console.engine import Engine  # noqa: E402
from test_unit import mkcfg  # noqa: E402

EXT_L4 = "185.220.101.7"


def ev(type_, src, port=80, proto="http", sensor="WEB01", **data):
    return {"ts": now_iso(), "sensor": sensor, "role": "linux-web-hosting", "sensor_ip": "172.30.0.22", "src_ip": src,
            "src_port": 50000, "dst_port": port, "proto": proto, "type": type_, "session": None, "data": data}


class _Eng(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = Engine(mkcfg(self.tmp.name), os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.e.db.close()
        self.tmp.cleanup()

    def feed(self, **kw):
        return self.e.worldmap(**kw)["feed"]

    def l4_shown(self, **kw):
        return any(f["src_ip"] == EXT_L4 and f["level"] == 4 for f in self.feed(**kw))


class TestB2WorldmapFeed(_Eng):
    def test_baseline_external_l4_shown(self):
        self.e.ingest([ev("http.sensitive", EXT_L4, path="/.env")])
        self.assertTrue(self.l4_shown())

    def test_internal_noise_does_not_empty_feed(self):
        # was: 400 newer internal L2 events used the whole LIMIT 400 window → feed empty
        self.e.ingest([ev("http.sensitive", EXT_L4, path="/.env")])
        self.e.ingest([ev("http.request", "192.168.1.181", path=f"/i{i}") for i in range(450)])
        f = self.feed()
        self.assertEqual([x["src_ip"] for x in f], [EXT_L4])
        self.assertTrue(self.l4_shown())

    def test_external_l2_l3_noise_does_not_push_out_l4(self):
        # was: 40 newer external L2/L3 events pushed the L4 out of the newest-40 window
        self.e.ingest([ev("http.sensitive", EXT_L4, path="/.env")])
        self.e.ingest([ev("http.request" if i % 2 else "http.scanner", f"45.95.0.{i + 1}", path=f"/x{i}")
                       for i in range(60)])
        f = self.feed()
        self.assertEqual(len(f), Engine.FEED_SIZE)
        self.assertTrue(self.l4_shown())
        ids = [x["id"] for x in f]
        self.assertEqual(ids, sorted(ids, reverse=True))           # still newest first after the merge
        self.assertEqual(f[0]["src_ip"], "45.95.0.60")             # the newest noise is still there

    def test_l4_reserve_keeps_newest_high_events(self):
        old = [f"203.0.113.{i}" for i in range(1, 16)]             # 15 external L4s, then lots of L2 noise
        self.e.ingest([ev("http.sensitive", ip, path="/.git/config") for ip in old])
        self.e.ingest([ev("http.request", f"45.95.1.{i + 1}", path=f"/y{i}") for i in range(80)])
        f = self.feed()
        high = [x["src_ip"] for x in f if x["level"] >= 4]
        self.assertEqual(high, old[::-1][:Engine.FEED_HIGH])       # newest FEED_HIGH L4s, newest first
        self.assertEqual(len(f), Engine.FEED_SIZE)

    def test_min_level_is_respected(self):
        # was: map filter L4+ showed only the L2 noise and not the L4
        self.e.ingest([ev("http.sensitive", EXT_L4, path="/.env")])
        self.e.ingest([ev("http.request", f"45.95.2.{i + 1}", path=f"/z{i}") for i in range(40)])
        f = self.feed(min_level=4)
        self.assertEqual([(x["src_ip"], x["level"]) for x in f], [(EXT_L4, 4)])
        self.assertEqual(self.e.worldmap(min_level=4)["feed_level"], 4)
        f3 = self.feed(min_level=3)
        self.assertTrue(f3 and all(x["level"] >= 3 for x in f3))

    def test_feed_never_below_l2(self):
        self.e.ingest([ev("tcp.connect", "45.95.3.1"), ev("http.request", "45.95.3.2", path="/")])
        for lvl in (0, 1, 2):
            self.assertEqual([x["src_ip"] for x in self.feed(min_level=lvl)], ["45.95.3.2"])
        self.assertEqual(self.e.worldmap(min_level=1)["feed_level"], 2)

    def test_allowlisted_and_internal_nets_still_hidden(self):
        self.e.ingest([ev("http.sensitive", "10.9.9.9", path="/.env"),        # internal_nets
                       ev("http.sensitive", "172.30.0.5", path="/.env"),      # allowlist
                       ev("http.sensitive", EXT_L4, path="/.env")])
        self.assertEqual([x["src_ip"] for x in self.feed()], [EXT_L4])

    def test_client_scenario(self):
        """Client report: an external L4 happened minutes ago, then an internal vulnerability scan (500 L2+ from
        one host) and internet scanners (50 L2/L3 from public IPs) — and the user selects L4+ on the map."""
        self.e.ingest([ev("http.sensitive", EXT_L4, path="/.env")])
        self.e.ingest([ev("http.request", "192.168.1.181", path=f"/vuln{i}") for i in range(500)])
        self.e.ingest([ev("http.scanner", f"45.95.4.{i + 1}", path=f"/s{i}") for i in range(50)])
        self.assertTrue(self.l4_shown())
        self.assertTrue(self.l4_shown(min_level=4))
        self.assertTrue(self.l4_shown(hours=0.25))
        f = self.feed()
        self.assertFalse(any(x["src_ip"] == "192.168.1.181" for x in f))
        self.assertTrue(f[0]["desc"] and isinstance(f[0]["data"], dict))   # rows keep the shape the UI uses

    def test_empty_and_internal_only(self):
        self.assertEqual(self.feed(), [])
        self.e.ingest([ev("http.sensitive", "192.168.1.181", path="/.env")])
        self.assertEqual(self.feed(), [])

    def _selects(self):
        """Count the feed's page queries (sqlite trace callback)."""
        n = []
        self.e.db.set_trace_callback(lambda q: n.append(q) if q.startswith("SELECT * FROM events WHERE id>=")
                                     and "ORDER BY id DESC LIMIT" in q else None)
        return n

    def _bulk(self, rows):
        self.e.db.execute("BEGIN")
        self.e.db.executemany("INSERT INTO events(ts,sensor,role,sensor_ip,src_ip,src_port,dst_port,proto,type,session,"
                              "level,data,incident_id,allowlisted) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        self.e.db.execute("COMMIT")

    @staticmethod
    def _row(src, level=2, typ="http.request"):
        return (now_iso(), "WEB01", "x", "172.30.0.22", src, 1, 80, "http", typ, None, level, "{}", None, 0)

    def test_feed_scan_is_newest_first_without_sort(self):
        """Security review L4 + re-review R2-L2: pages in primary-key order (no temp B-tree sort, no GROUP BY), bounded
        BELOW by the range start id (found with one ts-index seek), so an empty L4+ scan never walks the table."""
        plan = lambda sql, args: " | ".join(r[3] for r in self.e.db.execute("EXPLAIN QUERY PLAN " + sql, args))  # noqa: E731
        p0 = plan("SELECT MIN(id) FROM events INDEXED BY ev_ts WHERE ts>=?", ("2000",))
        self.assertRegex(p0, r"USING (COVERING )?INDEX ev_ts", p0)
        self.assertNotIn("TEMP B-TREE", p0, p0)
        for sql, args in (("SELECT * FROM events WHERE id>=? AND ts>=? AND level>=? AND allowlisted=0 AND src_ip IS NOT "
                           "NULL ORDER BY id DESC LIMIT ?", (1, "2000", 2, 500)),
                          ("SELECT * FROM events WHERE id>=? AND ts>=? AND level>=? AND allowlisted=0 AND src_ip IS NOT "
                           "NULL AND id<? ORDER BY id DESC LIMIT ?", (1, "2000", 2, 99, 500))):
            p = plan(sql, args)
            self.assertRegex(p, r"SEARCH events USING INTEGER PRIMARY KEY \(rowid>\?", p)
            self.assertNotIn("TEMP B-TREE", p, p)
            self.assertNotIn("GROUP", p, p)

    def test_feed_scan_stops_at_the_range_start(self):
        """Every page query carries the range start id as its lower bound, so rows older than the range are never
        visited (the plan test above shows it is a rowid range search)."""
        old = "2000-01-01T00:00:00.000Z"
        self._bulk([(old, "WEB01", "x", "172.30.0.22", "45.97.0.1", 1, 80, "http", "http.request", None, 2, "{}", None, 0)
                    for _ in range(2000)])
        self._bulk([self._row("45.97.0.2")])
        since = "2001-01-01T00:00:00.000Z"
        lo = self.e._range_start_id(since)
        self.assertEqual(lo, 2001)
        seen = []
        self.e.db.set_trace_callback(seen.append)
        f = self.e._worldmap_feed(since)
        self.e.db.set_trace_callback(None)
        self.assertEqual([x["src_ip"] for x in f], ["45.97.0.2"])
        self.assertTrue(all("id>=2001" in q for q in seen if "ORDER BY id DESC" in q), seen)
        self.assertIsNone(self.e._range_start_id("2999-01-01T00:00:00.000Z"))

    def test_feed_scan_stops_when_full(self):
        self._bulk([self._row(f"45.96.{i // 256}.{i % 256}") for i in range(1, 3001)])
        self.e.FEED_PAGE = 100
        n = self._selects()
        f = self.e._worldmap_feed("2000-01-01T00:00:00Z")
        self.assertEqual(len(f), Engine.FEED_SIZE)
        self.e.db.set_trace_callback(None)
        self.assertEqual(len(n), 2)            # one page for the 40 rows, one for the (empty) L4+ reserve scan

    def test_late_timestamped_event_does_not_hide_the_feed(self):
        """Final review R3-L2: 10 events in the range, then one that ARRIVES last but carries the earliest timestamp
        (a sensor minutes behind): the lower bound is MIN(id) of the range, so all 11 are still in the feed."""
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"   # noqa: E731
        since = fmt(now - timedelta(minutes=15))
        rows = [(fmt(now - timedelta(minutes=5) + timedelta(seconds=i)), "WEB01", "x", "172.30.0.22", f"45.98.0.{i + 1}",
                 1, 80, "http", "http.request", None, 2, "{}", None, 0) for i in range(10)]
        rows.append((fmt(now - timedelta(minutes=14)), "WEB01", "x", "172.30.0.22", "45.98.0.99", 1, 80, "http",
                     "http.request", None, 2, "{}", None, 0))
        self._bulk(rows)
        self.assertEqual(self.e._range_start_id(since), 1)
        self.assertEqual(len(self.e._worldmap_feed(since)), 11)

    def test_feed_scan_has_a_hard_cap(self):
        """An internal flood larger than the cap: the refresh stays cheap; the L4+ reserve scan is separate."""
        self._bulk([self._row(EXT_L4, 4, "http.sensitive"), self._row("45.95.9.9")]
                   + [self._row("192.168.1.181") for _ in range(1000)])
        self.e.FEED_PAGE, self.e.FEED_SCAN_MAX = 100, 300
        n = self._selects()
        f = self.e._worldmap_feed("2000-01-01T00:00:00Z")
        self.e.db.set_trace_callback(None)
        self.assertEqual([x["src_ip"] for x in f], [EXT_L4])          # older L2 beyond the cap is not reached
        self.assertEqual(len(n), 3 + 2)       # general: 3 pages (cap 300 rows) · L4+: 1 row, then an empty page

    @pytest.mark.slow
    def test_many_external_sources(self):
        # many distinct public sources: cost depends on the feed size, not on the number of sources
        rows = [(now_iso(), "WEB01", "x", "172.30.0.22", f"45.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}", 1, 80,
                 "http", "http.request", None, 2, "{}", None, 0) for i in range(1, 33001)]
        self.e.db.execute("BEGIN")                                   # one transaction: no fsync per row
        self.e.db.executemany("INSERT INTO events(ts,sensor,role,sensor_ip,src_ip,src_port,dst_port,proto,type,session,"
                              "level,data,incident_id,allowlisted) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        self.e.db.execute("COMMIT")
        f = self.e._worldmap_feed("2000-01-01T00:00:00Z")
        self.assertEqual(len(f), Engine.FEED_SIZE)
        self.assertEqual(f[0]["src_ip"], rows[-1][4])


class TestB4MappedIPv6(_Eng):
    def test_helpers(self):
        self.assertEqual(norm_ip("::ffff:192.168.1.181"), "192.168.1.181")
        self.assertEqual(norm_ip("::FFFF:8.8.8.8"), "8.8.8.8")
        self.assertEqual(norm_ip("2001:db8::1"), "2001:db8::1")
        self.assertEqual(norm_ip("not-an-ip"), "not-an-ip")
        self.assertIsNone(norm_ip(None))
        self.assertIsNone(ip_obj("garbage"))
        self.assertEqual(str(ip_obj(" 10.0.0.1 ")), "10.0.0.1")

    def test_is_internal_and_allowlist(self):
        self.assertTrue(self.e.is_internal("::ffff:192.168.1.181"))
        self.assertTrue(self.e.is_internal("::ffff:10.1.2.3"))           # internal_nets
        self.assertFalse(self.e.is_internal("::ffff:8.8.8.8"))
        self.assertTrue(self.e._allowed("::ffff:172.30.0.5"))           # allowlist 172.30.0.5/32
        self.assertFalse(self.e._allowed("::ffff:172.30.0.6"))

    def test_is_internal_cache_is_a_bounded_lru(self):
        self.e.INT_CACHE = 3
        for ip in ("8.8.8.1", "8.8.8.2", "8.8.8.3"):
            self.e.is_internal(ip)
        self.e.is_internal("8.8.8.1")                       # hit: now the most recently used
        self.e.is_internal("8.8.8.4")                       # evicts the least recently used (8.8.8.2) only
        self.assertEqual(list(self.e._int_cache), ["8.8.8.3", "8.8.8.1", "8.8.8.4"])

    def test_is_internal_cache_exists_before_first_call(self):
        e = self.e
        self.assertIsNotNone(e._int_lock)
        self.assertEqual(len(e._int_cache), 0)

    def test_is_internal_cache_follows_internal_nets(self):
        import ipaddress
        self.assertFalse(self.e.is_internal("198.51.100.7"))
        self.e.internal = self.e.internal + [ipaddress.ip_network("198.51.100.0/24")]
        self.assertTrue(self.e.is_internal("198.51.100.7"))
        self.assertTrue(self.e.is_internal("::ffff:198.51.100.7"))

    def test_ingest_stores_plain_ipv4(self):
        self.e.ingest([dict(ev("http.sensitive", "::ffff:192.168.1.181", path="/.env"), sensor_ip="::ffff:172.30.0.22")])
        r = self.e.db.execute("SELECT src_ip, sensor_ip FROM events").fetchone()
        self.assertEqual((r["src_ip"], r["sensor_ip"]), ("192.168.1.181", "172.30.0.22"))
        self.assertEqual(self.e.incidents()[0]["src_ip"], "192.168.1.181")
        self.assertEqual(self.feed(), [])                                   # internal → not on the world map
        self.assertEqual(self.e.worldmap()["points"], [])

    def test_ingest_allowlisted_mapped(self):
        self.e.ingest([ev("auth.failed", "::ffff:172.30.0.5", port=22, proto="ssh")])
        r = self.e.db.execute("SELECT src_ip, allowlisted FROM events").fetchone()
        self.assertEqual((r["src_ip"], r["allowlisted"]), ("172.30.0.5", 1))

    def test_decoy_talking_to_itself_mapped(self):
        self.assertEqual(self.e.ingest([dict(ev("http.request", "::ffff:172.30.0.22", path="/"))]), 0)

    def test_emitter_normalises_src(self):
        em = Emitter("WEB01", "linux-web-hosting", None, None, stdout=False, start=False,
                     data_dir=self.tmp.name)
        e = em.emit("http.request", src=("::ffff:192.168.1.181", 50000), dst_port=80, proto="http")
        self.assertEqual(e["src_ip"], "192.168.1.181")

    def test_sensor_is_private(self):
        from rpot.sensor.base import is_private
        self.assertTrue(is_private("::ffff:192.168.1.1"))
        self.assertFalse(is_private("::ffff:8.8.8.8"))
        self.assertFalse(is_private("nope"))
        self.assertFalse(is_private(None))


class TestB6ClockJump(_Eng):
    """A wall-clock jump on the manager must not look like every decoy going silent (false L4 tamper incidents)."""

    def beat(self, name="FS01"):
        self.e.ingest([{"ts": now_iso(), "sensor": name, "role": "windows-file-server", "type": "sensor.heartbeat",
                        "data": {}}])

    def offline_incidents(self):
        return [i for i in self.e.incidents() if (i.get("subject") or "").startswith("sensor:")]

    def check(self, wall_shift=0.0, mono_shift=0.0):
        from datetime import datetime, timedelta, timezone
        import time as _t
        self.e._check_sensors(now=datetime.now(timezone.utc) + timedelta(seconds=wall_shift),
                              mono=_t.monotonic() + mono_shift)

    def test_forward_jump_raises_no_tamper_incident(self):
        self.beat("FS01"); self.beat("WEB01")
        self.check()
        self.check(wall_shift=575182, mono_shift=30)            # 6.7 days forward in 30 real seconds
        self.assertEqual(self.offline_incidents(), [])
        self.assertEqual(self.e._offline, set())

    def test_backward_jump_raises_no_tamper_incident(self):
        self.beat()
        self.check()
        self.check(wall_shift=-86400, mono_shift=30)
        self.assertEqual(self.offline_incidents(), [])

    def test_real_silence_still_alerts_after_a_jump(self):
        self.beat()
        self.check(wall_shift=575182, mono_shift=30)
        self.assertEqual(self.offline_incidents(), [])
        self.check(wall_shift=575182 + 200, mono_shift=230)     # then really silent for 230 s
        inc = self.offline_incidents()
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["level"], 4)
        self.assertIn("FS01", self.e._offline)
        self.beat()                                              # reports again (at the shifted monotonic time)
        self.e._seen_mono["FS01"] += 235
        self.check(wall_shift=575182 + 210, mono_shift=240)
        self.assertNotIn("FS01", self.e._offline)

    def test_no_monotonic_baseline_yet_uses_grace_on_jump(self):
        """After a console restart the decoy has no monotonic baseline; a jump at that point starts the grace."""
        self.beat()
        self.e._seen_mono.clear()
        self.check(wall_shift=575182, mono_shift=30)
        self.assertEqual(self.offline_incidents(), [])
        self.check(wall_shift=575182 + 60, mono_shift=90)        # 60 s into the grace period: still fine
        self.assertEqual(self.offline_incidents(), [])

    def test_restart_baseline_from_stored_last_seen(self):
        """No jump: a decoy last seen long ago (stored wall clock) is still reported as silent."""
        self.beat()
        self.e.db.execute("UPDATE sensors SET last_seen=? WHERE name='FS01'", ("2026-01-01T00:00:00.000Z",))
        self.e._seen_mono.clear()
        self.check()
        self.assertEqual(len(self.offline_incidents()), 1)

    def test_remote_sensor_offline_mentions_set_access(self):
        self.beat("RS01")                                        # not in rpot.json → a remote sensor
        self.beat("FS01")
        self.check(mono_shift=300)
        evs = {e["sensor"]: e for e in self.e.events(min_level=4) if e["type"] == "sensor.offline"}
        self.assertIn("sudo ./install.sh set-access", evs["RS01"]["data"]["summary"])
        self.assertNotIn("set-access", evs["FS01"]["data"]["summary"])


class TestB4ConsoleApp(unittest.TestCase):
    def test_canary_hit_from_mapped_peer_is_internal(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from rpot.console.app import create_app
        app = create_app(mkcfg(tmp.name), os.path.join(tmp.name, "t.db"))
        tok = next(k for k, t in app.engine.fleet.all_tokens().items() if t.get("kind") == "document")
        c = app.test_client()
        c.get(f"/c/{tok}.png", environ_base={"REMOTE_ADDR": "::ffff:192.168.1.181"})
        db = sqlite3.connect(os.path.join(tmp.name, "t.db"))
        self.addCleanup(db.close)
        self.assertEqual(db.execute("SELECT src_ip FROM events WHERE type='canary.hit'").fetchone()[0], "192.168.1.181")



class TestL5TrustXff(unittest.TestCase):
    """Security review L5: with console.trust_xff the RIGHTMOST X-Forwarded-For entry (added by the trusted proxy)
    is the source; a client-supplied entry on the left (e.g. an allow-listed address) must not mute the bait alert."""

    def hit(self, headers, trust=True, peer="10.20.0.2", proxies=("10.20.0.0/24",)):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from rpot.console.app import create_app
        cfg = mkcfg(tmp.name)
        cfg["console"]["trust_xff"] = trust
        if proxies is not None:
            cfg["console"]["trusted_proxies"] = list(proxies)
        self.incidents = lambda: sqlite3.connect(os.path.join(tmp.name, "t.db")).execute(
            "SELECT COUNT(*) FROM incidents WHERE src_ip IS NOT NULL").fetchone()[0]
        app = create_app(cfg, os.path.join(tmp.name, "t.db"))
        tok = next(k for k, t in app.engine.fleet.all_tokens().items() if t.get("kind") == "document")
        app.test_client().get(f"/c/{tok}.png", headers=headers, environ_base={"REMOTE_ADDR": peer})
        db = sqlite3.connect(os.path.join(tmp.name, "t.db"))
        self.addCleanup(db.close)
        r = db.execute("SELECT src_ip, allowlisted, data FROM events WHERE type='canary.hit'").fetchone()
        import json as _j
        return r[0], r[1], _j.loads(r[2])

    def test_rightmost_entry_is_the_source(self):
        src, allow, data = self.hit({"X-Forwarded-For": "172.30.0.5, 203.0.113.50"})   # 172.30.0.5 is allow-listed
        self.assertEqual((src, allow), ("203.0.113.50", 0))
        self.assertEqual(data["via_proxy"], "10.20.0.2")

    def test_several_headers_the_last_entry_counts(self):
        src, allow, _ = self.hit([("X-Forwarded-For", "172.30.0.5"), ("X-Forwarded-For", "198.51.100.9")])
        self.assertEqual((src, allow), ("198.51.100.9", 0))      # several headers: the last one counts

    def test_without_trust_the_peer_is_the_source(self):
        src, _, data = self.hit({"X-Forwarded-For": "203.0.113.50"}, trust=False)
        self.assertEqual(src, "10.20.0.2")
        self.assertNotIn("via_proxy", data)

    def test_no_trusted_proxies_means_never(self):
        """Re-review R2-L4: trust_xff alone is not enough; the peer must be a configured trusted proxy."""
        src, _, data = self.hit({"X-Forwarded-For": "203.0.113.50"}, proxies=None)
        self.assertEqual(src, "10.20.0.2")
        self.assertNotIn("via_proxy", data)
        src, _, _ = self.hit({"X-Forwarded-For": "203.0.113.50"}, peer="198.51.100.77")   # direct client, not a proxy
        self.assertEqual(src, "198.51.100.77")

    def test_xff_source_is_never_allowlisted(self):
        """Even through the trusted proxy, an XFF-derived address is a claim: it never mutes the alert."""
        src, allow, data = self.hit({"X-Forwarded-For": "172.30.0.5"})          # 172.30.0.5 is allow-listed
        self.assertEqual((src, allow), ("172.30.0.5", 0))
        self.assertEqual(data["via_proxy"], "10.20.0.2")
        self.assertEqual(self.incidents(), 1)

    def test_peer_allowlisted_still_works_without_xff(self):
        src, allow, _ = self.hit({}, peer="172.30.0.5")
        self.assertEqual((src, allow), ("172.30.0.5", 1))

    def test_garbage_xff_keeps_the_peer(self):
        src, _, data = self.hit({"X-Forwarded-For": "1.2.3.4, not-an-ip"})
        self.assertEqual(src, "10.20.0.2")
        self.assertNotIn("via_proxy", data)


if __name__ == "__main__":
    unittest.main()
