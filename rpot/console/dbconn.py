"""Thread-safe access to the console database (B7, CE 1.0.1).

The console used ONE sqlite3 connection for every thread (check_same_thread=False). Ingest held the engine lock
and an explicit BEGIN/COMMIT, but the API read paths (graph, world map, summary, incidents ...) ran on the same
connection without it. Concurrent use of one connection gives sqlite3.InterfaceError "bad parameter or other API
misuse", half-read rows (IndexError), reads inside another thread's open transaction, and failed ingest batches
(UNIQUE constraint, rolled back).

SharedDB wraps that connection; Engine.db and Fleet use it unchanged (execute / executemany / executescript,
iteration, fetchone / fetchall, lastrowid, rowcount):

* Every statement that may write (and BEGIN / COMMIT / PRAGMA / EXPLAIN ...) runs on the single write connection
  under the engine's RLock, and its rows are fetched completely inside the lock, so no cursor is ever stepped by
  two threads. Ingest holds the same RLock for its whole transaction, so nothing else touches the connection
  between its BEGIN and COMMIT.
* SELECT / WITH statements run on a per-thread READ-ONLY connection (mode=ro, query_only) without the lock — the
  database is in WAL mode, so readers see the latest committed state and never block the writer. Exception: while
  the write connection has an open transaction (the thread inside ingest, which must see its own uncommitted rows),
  SELECTs of the thread holding that transaction take the locked write connection too.
"""
import os
import re
import sqlite3
import threading
from pathlib import Path

_READ = re.compile(r"\s*(SELECT|WITH)\b", re.IGNORECASE)


class Result:
    """Fully fetched result of one statement: iterable like a cursor."""
    __slots__ = ("rows", "lastrowid", "rowcount", "description", "_i")

    def __init__(self, rows, lastrowid=None, rowcount=-1, description=None):
        self.rows, self.lastrowid, self.rowcount, self.description, self._i = rows, lastrowid, rowcount, description, 0

    def __iter__(self):
        while self._i < len(self.rows):
            self._i += 1
            yield self.rows[self._i - 1]

    def fetchone(self):
        if self._i >= len(self.rows):
            return None
        self._i += 1
        return self.rows[self._i - 1]

    def fetchall(self):
        out, self._i = self.rows[self._i:], len(self.rows)
        return out

    def fetchmany(self, n=1):
        out = self.rows[self._i:self._i + n]
        self._i += len(out)
        return out


def _run(conn, sql, params):
    cur = conn.execute(sql, params)
    return Result(cur.fetchall() if cur.description else [], cur.lastrowid, cur.rowcount, cur.description)


class SharedDB:
    def __init__(self, conn, lock, path):
        self._conn, self._lock, self._tl, self._trace = conn, lock, threading.local(), None
        self._ro_uri = None
        if path and path != ":memory:" and not str(path).startswith("file:"):
            # percent-quoted like export.ro_uri (no urllib import in the console: test_rc7_no_outbound)
            self._ro_uri = Path(os.path.abspath(str(path))).as_uri() + "?mode=ro"

    # ------------------------------------------------------------------ read-only connections
    def _reader(self):
        c = getattr(self._tl, "conn", None)
        if c is None:
            if self._ro_uri is None:
                return None
            try:
                c = sqlite3.connect(self._ro_uri, uri=True, isolation_level=None, check_same_thread=False, timeout=10)
                c.row_factory = self._conn.row_factory
                c.execute("PRAGMA query_only=ON")
            except sqlite3.Error:
                return None
            self._tl.conn, self._tl.trace = c, None
        if self._tl.trace is not self._trace:
            c.set_trace_callback(self._trace)
            self._tl.trace = self._trace
        return c

    # ------------------------------------------------------------------ cursor-like API
    def _mine(self):
        """Does THIS thread hold the engine lock with a transaction open (i.e. it is inside ingest)? Then its reads
        must see its own uncommitted rows (write connection). Other threads' transactions do not matter: a
        read-only connection sees the last committed state (WAL)."""
        if not self._conn.in_transaction:
            return False
        owned = getattr(self._lock, "_is_owned", None)
        return owned() if owned else True

    def execute(self, sql, params=()):
        if _READ.match(sql) and not self._mine():
            c = self._reader()
            if c is not None:
                return _run(c, sql, params)
        with self._lock:
            return _run(self._conn, sql, params)

    def iter_read(self, sql, params=()):
        """B8: a large read STREAMED as plain tuples from this thread's read-only connection (nothing held in memory
        but the current row). Falls back to the locked write connection (materialised) inside this thread's own
        transaction or without a read-only connection."""
        if not self._mine():
            c = self._reader()
            if c is not None:
                cur = c.cursor()
                cur.row_factory = None
                yield from cur.execute(sql, params)
                return
        with self._lock:
            cur = self._conn.cursor()
            cur.row_factory = None
            rows = cur.execute(sql, params).fetchall()
        yield from rows

    def executemany(self, sql, seq):
        with self._lock:
            cur = self._conn.executemany(sql, seq)
            return Result([], cur.lastrowid, cur.rowcount)

    def executescript(self, script):
        with self._lock:
            self._conn.executescript(script)
            return Result([])

    def commit(self):
        with self._lock:
            self._conn.commit()

    def rollback(self):
        with self._lock:
            self._conn.rollback()

    def set_trace_callback(self, cb):
        """Applies to the write connection and to every read-only connection (tests count statements)."""
        self._trace = cb
        with self._lock:
            self._conn.set_trace_callback(cb)

    def close(self):
        with self._lock:
            self._conn.close()
        c = getattr(self._tl, "conn", None)
        if c is not None:
            c.close()
            self._tl.conn = None

    @property
    def in_transaction(self):
        return self._conn.in_transaction

    @property
    def row_factory(self):
        return self._conn.row_factory

    @row_factory.setter
    def row_factory(self, f):
        self._conn.row_factory = f

    def __getattr__(self, name):          # anything else (rare): the write connection, under the lock
        attr = getattr(self._conn, name)
        if not callable(attr):
            return attr

        def locked(*a, **k):
            with self._lock:
                return attr(*a, **k)
        return locked
