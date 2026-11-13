"""Append-only JSON Lines logs with rotation + gzip (alerts.json, optional events.json).

One JSON object per line (like Suricata eve.json) so Wazuh / Filebeat / Splunk forwarders can
tail it. Rotation happens at local midnight (UTC date change) or when the file exceeds max_mb;
the closed file becomes <name>-YYYY-MM-DD[-N].json.gz and only the newest `keep` archives stay.
"""
import glob
import gzip
import json
import os
import shutil
import threading
from datetime import datetime, timezone


class JsonlLog:
    def __init__(self, directory, name, max_mb=50, keep=90):
        self.dir, self.name = directory, name
        self.max_bytes = int(max_mb * 1024 * 1024)
        self.keep = keep
        self.path = os.path.join(directory, f"{name}.json")
        self.lock = threading.Lock()
        os.makedirs(directory, exist_ok=True)
        self.day = self._file_day()

    def _file_day(self):
        try:
            return datetime.fromtimestamp(os.path.getmtime(self.path), timezone.utc).strftime("%Y-%m-%d")
        except OSError:
            return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def write(self, record, now=None):
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
        now = now or datetime.now(timezone.utc)
        today = now.strftime("%Y-%m-%d")
        with self.lock:
            try:
                size = os.path.getsize(self.path)
            except OSError:
                size = 0
            if size and (today != self.day or size + len(line) > self.max_bytes):
                self._rotate()
            self.day = today
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)

    def _rotate(self):
        base = os.path.join(self.dir, f"{self.name}-{self.day}")
        dst, n = base + ".json", 1
        while os.path.exists(dst) or os.path.exists(dst + ".gz"):
            dst = f"{base}-{n}.json"; n += 1
        os.replace(self.path, dst)
        threading.Thread(target=self._compress_and_prune, args=(dst,), daemon=True).start()

    def _compress_and_prune(self, path):
        try:
            # write to a temp name, then rename: a log shipper never sees a half-written archive
            with open(path, "rb") as src, gzip.open(path + ".gz.part", "wb", compresslevel=6) as gz:
                shutil.copyfileobj(src, gz)
            os.replace(path + ".gz.part", path + ".gz")
            os.remove(path)
        except OSError:
            return
        with self.lock:
            archives = sorted(glob.glob(os.path.join(self.dir, f"{self.name}-*.json.gz")), key=os.path.getmtime)
            for old in archives[:-self.keep] if self.keep > 0 else []:
                try:
                    os.remove(old)
                except OSError:
                    pass

    def flush_rotation_for_tests(self):
        """Wait for background compression threads (tests only)."""
        for t in threading.enumerate():
            if t is not threading.current_thread() and t.daemon and t.name.startswith("Thread"):
                t.join(2)
