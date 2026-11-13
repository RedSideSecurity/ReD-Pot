"""RC-8 (design T7, D-6 + addendum L11): manager-side Community Edition decoy cap.

used = local decoys (rpot.json) + non-revoked remote sensors + pending unexpired joins, max MAX_DECOYS."""
import contextlib
import hashlib
import io
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rpot.common.edition import EDITION, MAX_DECOYS, LimitError, limit_message  # noqa: E402
from rpot.console.app import create_app, create_sensor_app  # noqa: E402
from rpot.console.engine import ce_limit_sql  # noqa: E402
from rpot.console.fleet import slot_counts  # noqa: E402
from test_unit import ev, mkcfg  # noqa: E402

H = {"X-Requested-With": "rpot"}
ROLES = ["windows-file-server", "linux-web-hosting", "ftp-backup-server", "linux-web-hosting", "windows-file-server"]


def local(i):
    return {"name": f"LOC{i}", "role": ROLES[i], "ip": f"172.30.0.{21 + i}",
            "key_sha256": hashlib.sha256(f"loc{i}-secret".encode()).hexdigest()}


def auth(name, secret):
    return {"Authorization": f"Bearer {name}:{secret}"}


def local_auth(i):
    return auth(f"LOC{i}", f"loc{i}-secret")


class Base(unittest.TestCase):
    n_local = 2

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.cfg = mkcfg(self.tmp, sensors=[local(i) for i in range(self.n_local)])
        self.out = io.StringIO()
        with contextlib.redirect_stdout(self.out):
            self.app = create_app(self.cfg, os.path.join(self.tmp, "c.db"))
        self.eng = self.app.engine
        self.db = self.eng.db
        self.fleet = self.eng.fleet
        self.c = self.app.test_client()
        self.c.post("/login", data={"token": "at"})
        self.s = create_sensor_app(self.eng).test_client()

    def tearDown(self):
        self.db.close()
        self._tmp.cleanup()

    def enroll(self, name, role="linux-web-hosting", ip=None, client=None):
        b = {"name": name, "role": role}
        if ip is not None:
            b["ip"] = ip
        return (client or self.c).post("/api/fleet/enroll", json=b, headers=H)

    def token_of(self, r):
        from rpot.common.tlsutil import parse_join
        return parse_join(r.get_json()["join"])[1]

    def redeem(self, token):
        with contextlib.redirect_stdout(self.out):
            return self.s.post("/api/enroll", json={"token": token, "info": {"hostname": "r"}})

    def add_remote(self, name):
        """Enroll + redeem one remote sensor through the APIs; returns its auth header."""
        r = self.enroll(name)
        self.assertEqual(r.status_code, 200, r.get_json())
        res = self.redeem(self.token_of(r))
        self.assertEqual(res.status_code, 200, res.get_json())
        return {"Authorization": f"Bearer {res.get_json()['sensor']['key']}"}

    def limit(self):
        return self.c.get("/api/fleet").get_json()["limit"]

    def ingest(self, hdr):
        with contextlib.redirect_stdout(self.out):
            return self.s.post("/api/ingest", json={"events": [ev("sensor.heartbeat")]}, headers=hdr)

    def config(self, hdr):
        with contextlib.redirect_stdout(self.out):
            return self.s.get("/api/config", headers=hdr)


class TestEditionConstant(unittest.TestCase):
    def test_trigger_text_is_built_from_max_decoys(self):
        sql = ce_limit_sql()
        self.assertEqual(set(int(x) for x in re.findall(r">= (\d+)", sql)), {MAX_DECOYS})
        self.assertIn(f"ce_local WHERE id = 1), {MAX_DECOYS})", sql)
        self.assertIn(">= 7", ce_limit_sql(7))

    def test_installed_trigger_matches_edition(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mkcfg(tmp, sensors=[local(0)])
            app = create_app(cfg, os.path.join(tmp, "c.db"))
            sql = app.engine.db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='ce_limit_insert'").fetchone()[0]
            self.assertEqual(set(int(x) for x in re.findall(r">= (\d+)", sql)), {MAX_DECOYS})
            names = {r[0] for r in app.engine.db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
            self.assertTrue({"ce_limit_insert", "ce_no_unrevoke", "ce_no_remote_flip"} <= names)
            self.assertEqual(app.engine.db.execute("SELECT n FROM ce_local WHERE id=1").fetchone()[0], 1)
            app.engine.db.close()

    def test_limit_error_is_value_error(self):
        self.assertTrue(issubclass(LimitError, ValueError))


class TestIssue(Base):
    def test_two_local_plus_one_pending_blocks_new_enrollment(self):
        self.assertEqual(self.enroll("REM1").status_code, 200)
        r = self.enroll("REM2")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["error"], limit_message(3))
        self.assertEqual(r.get_json()["used"], 3)
        self.assertEqual(len(self.fleet.pending()), 1)

    def test_reissue_of_the_pending_name_is_allowed(self):
        self.assertEqual(self.enroll("REM1").status_code, 200)
        self.assertEqual(self.enroll("REM1").status_code, 200)         # replaces its own pending join
        self.assertEqual(len(self.fleet.pending()), 1)
        self.assertEqual(self.limit()["used"], 3)

    def test_cancel_frees_a_slot(self):
        self.assertEqual(self.enroll("REM1").status_code, 200)
        self.assertEqual(self.enroll("REM2").status_code, 400)
        self.assertEqual(self.c.post("/api/fleet/REM1/cancel").status_code, 403)              # CSRF header
        self.assertEqual(self.c.post("/api/fleet/rem1/cancel", headers=H).get_json(), {"ok": True})
        self.assertEqual(self.c.post("/api/fleet/REM1/cancel", headers=H).status_code, 404)   # nothing pending
        self.assertEqual(self.enroll("REM2").status_code, 200)

    def test_cancel_never_touches_used_rows_or_locals(self):
        hdr = self.add_remote("REM1")
        self.assertEqual(self.c.post("/api/fleet/REM1/cancel", headers=H).status_code, 404)
        self.assertEqual(self.c.post("/api/fleet/LOC0/cancel", headers=H).status_code, 404)
        self.assertEqual(self.ingest(hdr).status_code, 200)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM enrollments WHERE name='REM1'").fetchone()[0], 1)

    def test_expired_pending_frees_its_slot(self):
        self.assertEqual(self.enroll("REM1").status_code, 200)
        self.db.execute("UPDATE enrollments SET expires=? WHERE name='REM1'", (time.time() - 1,))
        self.assertEqual(self.limit()["pending"], 0)
        self.assertEqual(self.enroll("REM2").status_code, 200)

    def test_revoking_a_remote_frees_a_slot(self):
        self.add_remote("REM1")
        self.assertEqual(self.enroll("REM2").status_code, 400)
        self.assertEqual(self.c.post("/api/fleet/REM1/revoke", headers=H).get_json(), {"ok": True})
        self.assertEqual(self.limit()["remote"], 0)
        self.assertEqual(self.enroll("REM2").status_code, 200)

    def test_revoking_a_local_does_not_free_a_slot(self):
        self.assertEqual(self.c.post("/api/fleet/LOC1/revoke", headers=H).get_json(), {"ok": True})
        lim = self.limit()
        self.assertEqual((lim["local"], lim["used"]), (2, 2))
        self.assertEqual(self.enroll("REM1").status_code, 200)
        self.assertEqual(self.enroll("REM2").status_code, 400)

    def test_invalid_ip_is_400(self):
        for ip in ("10.0.0.300", "1.2.3.4; rm -rf /", "evil\n10.0.0.1", "host.example", 123, ["10.0.0.1"], "x" * 500, "fe80::1%eth0"):
            r = self.enroll("REM1", ip=ip)
            self.assertEqual(r.status_code, 400, ip)
            self.assertIn("ip", r.get_json()["error"])
        self.assertEqual(self.fleet.pending(), [])
        self.assertEqual(self.enroll("REM1", ip="fe80:0:0::1").status_code, 200)
        self.assertEqual(self.fleet.pending()[0]["ip"], "fe80::1")                   # stored normalised

    def test_fleet_limit_object_and_summary_edition(self):
        lim = self.limit()
        self.assertEqual(lim, {"max": MAX_DECOYS, "used": 2, "local": 2, "remote": 0, "pending": 0,
                               "edition": EDITION, "full": False, "message": None})
        self.add_remote("REM1")
        lim = self.limit()
        self.assertEqual((lim["used"], lim["remote"], lim["full"]), (3, 1, True))
        self.assertEqual(lim["message"], limit_message(3))
        self.assertEqual(self.c.get("/api/summary").get_json()["edition"], "community")

    def test_wall_role_cannot_cancel_or_see_fleet(self):
        self.assertEqual(self.enroll("REM1").status_code, 200)
        self.cfg["console"]["wall_token"] = "wt"
        w = self.app.test_client()
        self.assertEqual(w.get("/wall?k=wt").status_code, 302)
        self.assertEqual(w.post("/api/fleet/REM1/cancel", headers=H).status_code, 403)
        self.assertEqual(w.get("/api/fleet").status_code, 403)
        self.assertEqual(self.app.test_client().post("/api/fleet/REM1/cancel", headers=H).status_code, 401)
        self.assertEqual(len(self.fleet.pending()), 1)
        self.assertEqual(w.get("/api/summary").get_json()["edition"], "community")


class TestRedeem(Base):
    def test_redeem_when_full_is_409_and_token_stays_unused(self):
        tok = self.token_of(self.enroll("REM1"))
        # a remote appears between issue and redeem (e.g. written by another process)
        self.db.execute("INSERT INTO fleet(name, role, remote, created, enrolled) VALUES('OTHER','linux-web-hosting',1,'x','x')")
        r = self.redeem(tok)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.get_json(), {"error": "decoy limit reached", "used": 4})   # used > max is reported as is
        row = self.db.execute("SELECT used FROM enrollments WHERE name='REM1'").fetchone()
        self.assertIsNone(row[0])
        self.assertIsNone(self.db.execute("SELECT 1 FROM fleet WHERE name='REM1'").fetchone())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM extra_tokens WHERE sensor='REM1'").fetchone()[0], 0)
        lim = self.limit()
        self.assertEqual((lim["used"], lim["full"]), (4, True))
        self.assertIn("this install uses 4", lim["message"])
        self.fleet.revoke("OTHER")
        self.assertEqual(self.redeem(tok).status_code, 200)                       # same token works afterwards

    def test_db_trigger_backstop_keeps_token_unused(self):
        tok = self.token_of(self.enroll("REM1"))
        self.db.execute("UPDATE ce_local SET n=3")      # DB says full, code check passes: trigger refuses
        r = self.redeem(tok)
        self.assertEqual(r.status_code, 409)
        self.assertIsNone(self.db.execute("SELECT used FROM enrollments WHERE name='REM1'").fetchone()[0])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM extra_tokens WHERE sensor='REM1'").fetchone()[0], 0)
        self.assertIsNone(self.db.execute("SELECT 1 FROM fleet WHERE name='REM1'").fetchone())

    def test_fleet_redeem_raises_limit_error(self):
        tok = self.fleet.create_enrollment("REM1", "linux-web-hosting")
        self.db.execute("INSERT INTO fleet(name, role, remote, created, enrolled) VALUES('OTHER','linux-web-hosting',1,'x','x')")
        with self.assertRaises(LimitError):
            self.fleet.redeem(tok, {})
        self.assertIsNone(self.fleet.redeem("bogus", {}))

    def test_limit_never_shown_without_a_valid_token(self):
        self.token_of(self.enroll("REM1"))
        self.db.execute("INSERT INTO fleet(name, role, remote, created, enrolled) VALUES('OTHER','linux-web-hosting',1,'x','x')")
        r = self.redeem("not-a-token")
        self.assertEqual(r.status_code, 403)
        body = r.get_data(as_text=True).lower()
        for w in ("limit", "community", "decoys", str(MAX_DECOYS) + " "):
            self.assertNotIn(w, body)


class TestTriggers(Base):
    n_local = 1

    def ins(self, name, remote=1, revoked=0):
        self.db.execute("INSERT INTO fleet(name, role, remote, revoked, created, enrolled) VALUES(?,?,?,?,'x','x')",
                        (name, "linux-web-hosting", remote, revoked))

    def test_raw_insert_of_a_fourth_remote_is_aborted(self):
        self.ins("R1")
        self.ins("R2")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decoy limit"):
            self.ins("R3")
        self.ins("R3", revoked=1)                         # revoked rows never count
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decoy limit"):
            self.db.execute("INSERT OR REPLACE INTO fleet(name, role, remote, created) VALUES('R3','x',1,'x')")
        self.ins("L9", remote=0, revoked=1)               # what revoke() of a local decoy writes
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM fleet WHERE remote=1 AND revoked=0").fetchone()[0], 2)

    def test_replace_of_an_existing_remote_is_allowed(self):
        self.ins("R1")
        self.ins("R2")
        self.db.execute("INSERT OR REPLACE INTO fleet(name, role, remote, created) VALUES('R2','x',1,'y')")

    def test_unrevoke_is_aborted(self):
        self.ins("R1", revoked=1)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decoy limit"):
            self.db.execute("UPDATE fleet SET revoked=0 WHERE name='R1'")
        self.c.post("/api/fleet/LOC0/revoke", headers=H)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decoy limit"):
            self.db.execute("UPDATE fleet SET revoked=0 WHERE name='LOC0'")

    def test_remote_flip_is_aborted(self):
        self.ins("R1")
        self.ins("L5", remote=0, revoked=1)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decoy limit"):
            self.db.execute("UPDATE fleet SET remote=0 WHERE name='R1'")     # would hide it from the count
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decoy limit"):
            self.db.execute("UPDATE fleet SET remote=1 WHERE name='L5'")
        self.db.execute("UPDATE fleet SET remote=1 WHERE name='R1'")         # no change: fine
        self.db.execute("UPDATE fleet SET ip='10.0.0.9' WHERE name='R1'")    # note_ip still works

    def test_missing_ce_local_row_fails_closed(self):
        self.db.execute("DELETE FROM ce_local")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decoy limit"):
            self.ins("R1")

    def test_engine_restart_rewrites_ce_local_and_triggers(self):
        self.db.execute("DROP TRIGGER ce_limit_insert")
        self.db.execute("UPDATE ce_local SET n=0")
        app2 = create_app(self.cfg, os.path.join(self.tmp, "c.db"))
        db2 = app2.engine.db
        self.assertEqual(db2.execute("SELECT n FROM ce_local").fetchone()[0], 1)
        db2.execute("INSERT INTO fleet(name, role, remote, created) VALUES('R1','x',1,'x')")
        db2.execute("INSERT INTO fleet(name, role, remote, created) VALUES('R2','x',1,'x')")
        with self.assertRaises(sqlite3.IntegrityError):
            db2.execute("INSERT INTO fleet(name, role, remote, created) VALUES('R3','x',1,'x')")
        db2.close()


class TestSensorApiOverLimit(Base):
    n_local = 4

    def test_tampered_cfg_fourth_local_gets_403(self):
        self.assertIn("WARNING: rpot.json lists 4 local decoys", self.out.getvalue())
        for i in range(3):
            self.assertEqual(self.ingest(local_auth(i)).status_code, 200, i)
            self.assertEqual(self.config(local_auth(i)).status_code, 200, i)
        before = self.out.getvalue().count("decoy LOC3 refused")
        r = self.ingest(local_auth(3))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.config(local_auth(3)).status_code, 403)
        self.assertEqual(self.ingest(local_auth(3)).status_code, 403)
        self.assertEqual(self.out.getvalue().count("decoy LOC3 refused") - before, 1)     # logged once per name
        for w in ("limit", "community", "decoys"):
            self.assertNotIn(w, r.get_data(as_text=True).lower())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM events WHERE sensor='LOC3'").fetchone()[0], 0)
        self.assertEqual(self.ingest(auth("LOC3", "wrong")).status_code, 401)            # auth comes first

    def test_used_above_max_is_reported_and_blocks_issue(self):
        lim = self.limit()
        self.assertEqual((lim["used"], lim["local"], lim["full"]), (4, 4, True))
        self.assertIn("this install uses 4", lim["message"])
        r = self.enroll("REM1")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["error"], limit_message(4))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decoy limit"):
            self.db.execute("INSERT INTO fleet(name, role, remote, created) VALUES('R1','x',1,'x')")


class TestTamperedDb(Base):
    n_local = 2

    def raw_remote(self, name, secret, enrolled="2026-01-01T00:00:00Z", remote=1):
        self.db.execute("INSERT INTO fleet(name, role, key_hash, remote, created, enrolled) VALUES(?,?,?,?,?,?)",
                        (name, "linux-web-hosting", hashlib.sha256(secret.encode()).hexdigest(), remote, "x", enrolled))
        return auth(name, secret)

    def test_tampered_db_fourth_remote_gets_403(self):
        old = self.add_remote("REM1")
        self.db.execute("UPDATE ce_local SET n=0")                          # attacker-of-the-licence disables layer 6
        new = self.raw_remote("ZZ9", "s3cret", enrolled="2099-01-01T00:00:00Z")
        self.assertEqual(self.ingest(old).status_code, 200)
        self.assertEqual(self.ingest(new).status_code, 403)
        self.assertEqual(self.config(new).status_code, 403)
        for i in range(2):
            self.assertEqual(self.ingest(local_auth(i)).status_code, 200)

    def test_unenrolled_and_fake_local_rows_lose(self):
        self.db.execute("UPDATE ce_local SET n=0")
        fake_local = self.raw_remote("AAA", "a", enrolled=None, remote=0)   # remote=0 but not in rpot.json
        first = self.raw_remote("BBB", "b")
        self.assertEqual(self.fleet.allowed_names(), ["LOC0", "LOC1", "BBB"])
        self.assertEqual(self.ingest(first).status_code, 200)
        self.assertEqual(self.ingest(fake_local).status_code, 403)

    def test_cross_process_overshoot_local_wins(self):
        """Installer add-decoy (3rd local) races a browser enrollment: after the console restart the
        local decoys win and the newest remote gets 403 + one log line."""
        rem = self.add_remote("REM1")
        self.cfg["sensors"].append(local(2))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            app2 = create_app(self.cfg, os.path.join(self.tmp, "c.db"))
            s2 = create_sensor_app(app2.engine).test_client()
            self.assertEqual(s2.post("/api/ingest", json={"events": []}, headers=rem).status_code, 403)
            for i in range(3):
                self.assertEqual(s2.post("/api/ingest", json={"events": []}, headers=local_auth(i)).status_code, 200)
        self.assertEqual(out.getvalue().count("decoy REM1 refused"), 1)
        self.assertEqual(slot_counts(app2.engine.db, ["LOC0", "LOC1", "LOC2"], time.time())["used"], 4)
        app2.engine.db.close()


class TestRace(Base):
    n_local = 1

    def test_twenty_threads_issue_exactly_the_free_slots(self):
        free = MAX_DECOYS - self.fleet.slots()["used"]
        barrier = threading.Barrier(20)
        ok, limited, other = [], [], []

        def go(i):
            barrier.wait()
            try:
                ok.append(self.fleet.create_enrollment(f"RACE{i}", "linux-web-hosting"))
            except LimitError:
                limited.append(i)
            except Exception as e:   # pragma: no cover - reported below
                other.append(repr(e))

        ts = [threading.Thread(target=go, args=(i,)) for i in range(20)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        self.assertEqual(other, [])
        self.assertEqual(len(ok), free)
        self.assertEqual(len(limited), 20 - free)
        self.assertEqual(self.fleet.slots()["used"], MAX_DECOYS)

    def test_twenty_threads_same_name_and_http(self):
        barrier = threading.Barrier(20)
        codes = []

        def go(i):
            c = self.app.test_client()
            c.post("/login", data={"token": "at"})
            barrier.wait()
            codes.append(self.enroll(f"WEB{i % 4}", client=c).status_code)

        ts = [threading.Thread(target=go, args=(i,)) for i in range(20)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        self.assertEqual(len(codes), 20)
        self.assertEqual(set(codes) <= {200, 400}, True)
        lim = self.limit()
        self.assertEqual((lim["used"], lim["pending"]), (MAX_DECOYS, MAX_DECOYS - 1))


if __name__ == "__main__":
    unittest.main()
