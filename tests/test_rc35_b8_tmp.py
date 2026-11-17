"""RC-35 B8 (QA on vm1, client load): /api/graph?hours=24 → 500 "database or disk is full". SQLite sorted the 24 h
GROUP BY src_ip, sensor through a temp file (~19 MB at 350k events) in the console's 16 MB /tmp tmpfs.
Fix: the image points SQLITE_TMPDIR at the data volume (/var/lib/rpot/tmp, same path as the 1.0.0 hotfix). P-1: the
graph stays one SQL GROUP BY (the hotfix's shape; Python aggregation was 3-4x slower), bounded by LIMIT."""
import os
import random
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rpot.common.events import now_iso  # noqa: E402
from rpot.console.engine import Engine  # noqa: E402
from test_unit import mkcfg  # noqa: E402

OLD_SQL = ("SELECT src_ip, sensor, MAX(level) lvl, COUNT(*) n, GROUP_CONCAT(DISTINCT proto) protos, MIN(ts) first, "
           "MAX(ts) last FROM events WHERE ts>=? AND src_ip IS NOT NULL AND sensor IS NOT NULL AND allowlisted=0 "
           "GROUP BY src_ip, sensor HAVING lvl>=?")


class TestGraphWithoutSort(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = Engine(mkcfg(self.tmp.name), os.path.join(self.tmp.name, "t.db"))
        random.seed(3)
        rows = [(now_iso(), random.choice(["FS01", "WEB01", None]), "x", "172.30.0.22",
                 random.choice([None, "45.1.1.1", "45.1.1.2", "192.168.1.5", "10.9.9.9"]), 1, 80,
                 random.choice(["smb", "http", None]), "t", None, random.randint(0, 5), "{}", None,
                 random.choice([0, 0, 0, 1])) for _ in range(3000)]
        self.e.db.execute("BEGIN")
        self.e.db.executemany("INSERT INTO events(ts,sensor,role,sensor_ip,src_ip,src_port,dst_port,proto,type,session,"
                              "level,data,incident_id,allowlisted) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        self.e.db.execute("COMMIT")

    def tearDown(self):
        self.e.db.close()
        self.tmp.cleanup()

    def test_same_result_as_the_sql_group_by(self):
        since = "2000-01-01T00:00:00.000Z"
        for lvl in (0, 1, 3, 5):
            old = {(r["src_ip"], r["sensor"]): (r["lvl"], r["n"], frozenset((r["protos"] or "").split(",")) - {""},
                                                 r["first"], r["last"])
                   for r in self.e.db.execute(OLD_SQL, (since, lvl))}
            new = {(r["src_ip"], r["sensor"]): (r["lvl"], r["n"], frozenset((r["protos"] or "").split(",")) - {""},
                                                 r["first"], r["last"])
                   for r in self.e._graph_edges(since, lvl)[0]}
            self.assertEqual(new, old, lvl)
        self.assertTrue(self.e.graph(24, 1, "all")["edges"])

    def test_internal_scope_filtered_while_reading(self):
        """R4-L1: scope=internal never keeps state for external sources."""
        since = "2000-01-01T00:00:00.000Z"
        rows, truncated = self.e._graph_edges(since, 0, "internal")
        self.assertFalse(truncated)
        self.assertEqual({r["src_ip"] for r in rows}, {"192.168.1.5", "10.9.9.9"})
        self.assertFalse(self.e.graph(24, 0, "internal")["truncated"])

    def test_group_cap_sets_truncated(self):
        self.e.GRAPH_MAX_GROUPS = 3
        rows, truncated = self.e._graph_edges("2000-01-01T00:00:00.000Z", 0, "all")
        self.assertTrue(truncated)
        self.assertEqual(len(rows), 3)
        self.assertTrue(self.e.graph(24, 0, "all")["truncated"])

    def test_single_proto_stays_a_string(self):
        self.e.db.execute("INSERT INTO events(ts,sensor,src_ip,proto,type,level,data,allowlisted) "
                          "VALUES(?,?,?,?,?,?,?,0)", (now_iso(), "BKP01", "45.7.7.7", "ftp", "t", 3, "{}"))
        rows, _ = self.e._graph_edges("2000-01-01T00:00:00.000Z", 0, "all")
        r = [x for x in rows if x["src_ip"] == "45.7.7.7"][0]
        self.assertEqual(r["protos"], "ftp")

    def test_graph_is_one_sql_group_by_not_python_aggregation(self):
        """P-1 (QA vm1): aggregating every row in Python made the map 3-4x slower than the hotfix's SQL GROUP BY.
        The graph must not stream the range into Python; its SQL is a bounded GROUP BY over the ts index."""
        def no_stream(*a, **k):
            raise AssertionError("graph streamed the whole range into Python")
        self.e.db.iter_read = no_stream
        seen = []
        self.e.db.set_trace_callback(seen.append)
        g = self.e.graph(24, 1, "all")
        self.e.db.set_trace_callback(None)
        self.assertTrue(g["edges"])
        q = [x for x in seen if "GROUP BY src_ip, sensor" in x]
        self.assertEqual(len(q), 1, seen)
        self.assertIn("ORDER BY last DESC LIMIT 20001", q[0])
        sql = q[0]
        plan = " | ".join(r[3] for r in self.e.db.execute("EXPLAIN QUERY PLAN " + sql))
        self.assertIn("ev_ts", plan)

    def test_internal_scope_prefilter_in_sql(self):
        globs = self.e._internal_globs()
        for p in ("10.*", "172.*", "192.168.*", "100.*", "169.254.*", "fc*", "fd*", "fe8*"):
            self.assertIn(p, globs)
        seen = []
        self.e.db.set_trace_callback(seen.append)
        rows, _ = self.e._graph_edges("2000-01-01T00:00:00.000Z", 0, "internal")
        self.e.db.set_trace_callback(None)
        self.assertTrue(any("src_ip GLOB '192.168.*'" in x for x in seen), seen)
        self.assertEqual({r["src_ip"] for r in rows}, {"192.168.1.5", "10.9.9.9"})
        import ipaddress
        self.e.internal = self.e.internal + [ipaddress.ip_network("2001:db8::/32")]
        self.assertIsNone(self.e._internal_globs())                   # IPv6 internal_nets: no SQL pre-filter ...
        rows, _ = self.e._graph_edges("2000-01-01T00:00:00.000Z", 0, "internal")
        self.assertEqual({r["src_ip"] for r in rows}, {"192.168.1.5", "10.9.9.9"})   # ... same result

    def test_streamed_as_tuples(self):
        it = self.e.db.iter_read("SELECT id, level FROM events WHERE id<=3 ORDER BY id")
        self.assertFalse(isinstance(it, list))
        self.assertEqual([type(r) for r in it], [tuple] * 3)
        with self.e.lock:                                         # inside this thread's own transaction: still works
            self.e.db.execute("BEGIN")
            self.e.db.execute("INSERT INTO sensors(name, role, ip) VALUES('B8', 'x', '1.2.3.4')")
            self.assertEqual(list(self.e.db.iter_read("SELECT name FROM sensors WHERE name='B8'")), [("B8",)])
            self.e.db.execute("ROLLBACK")


class TestSqliteTmpdir(unittest.TestCase):
    def test_image_sets_sqlite_tmpdir_on_the_data_volume(self):
        with open(os.path.join(REPO, "Dockerfile")) as f:
            self.assertRegex(f.read(), r"(?m)^ENV .*\bSQLITE_TMPDIR=/var/lib/rpot/tmp\b")

    def test_console_creates_the_dir_and_sqlite_uses_it(self):
        """In a fresh process (SQLite reads SQLITE_TMPDIR once, at start): the engine creates the directory, and a
        query that must spill puts its temp file there, not in /tmp."""
        with tempfile.TemporaryDirectory() as d:
            tmpd = os.path.join(d, "data", "tmp")
            code = r"""
import os, sys, sqlite3
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, os.path.join(sys.argv[1], "tests"))
from test_unit import mkcfg
from rpot.console.engine import Engine
d = sys.argv[2]
os.makedirs(os.path.join(d, "data"))
e = Engine(mkcfg(d), os.path.join(d, "data", "t.db"))
assert os.path.isdir(os.environ["SQLITE_TMPDIR"]), "dir not created"
c = sqlite3.connect(":memory:")
c.execute("PRAGMA temp_store=FILE"); c.execute("PRAGMA cache_size=-64")
c.execute("CREATE TABLE t(a, b)")
c.executemany("INSERT INTO t VALUES(?, ?)", ((i % 997, "x" * 200) for i in range(30000)))
seen = []
cur = c.execute("SELECT a, b FROM t ORDER BY b, a")
cur.fetchone()                                   # the sorter has spilled by now
for fd in os.listdir("/proc/self/fd"):
    try:
        t = os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        continue
    if "etilqs_" in t:
        seen.append(t)
assert seen and all(t.startswith(os.environ["SQLITE_TMPDIR"]) for t in seen), seen
print("ok", len(seen))
"""
            p = subprocess.run([sys.executable, "-c", code, REPO, d], capture_output=True, text=True, timeout=120,
                               env=dict(os.environ, SQLITE_TMPDIR=tmpd))
            self.assertEqual(p.returncode, 0, p.stderr[-1500:])
            self.assertTrue(p.stdout.startswith("ok"), p.stdout)


if __name__ == "__main__":
    unittest.main()
