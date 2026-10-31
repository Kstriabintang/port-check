"""Treat Proxy.txt as a work queue: checked proxies are removed from the file.

As the scan progresses, the file is rewritten to contain only the proxies that
have NOT been checked yet. If the run is stopped, re-running continues from the
remaining lines. Rewrites happen in batches (and once at the end) and are atomic
(write to a temp file, then replace) so the queue file can't be left corrupt.
"""
import os
import threading

from . import parsing
from .parsing import _normalize


class ProxyQueue:
    """Tracks which original lines remain and rewrites the queue file atomically.

    Only active when proxies were read from the file (not from CLI args).
    """

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.active = path is not None
        self.key_to_line = {}   # (host, port) -> original line text
        self.remaining = {}     # (host, port) -> original line text (not yet done)
        self.order = []         # keys in first-seen order
        if self.active:
            self._load()

    def _load(self):
        with open(self.path) as f:
            for raw in f.read().splitlines():
                key = _normalize(raw)
                if key is None:
                    continue
                if key not in self.key_to_line:
                    self.key_to_line[key] = raw.strip()
                    self.remaining[key] = raw.strip()
                    self.order.append(key)

    def mark_done(self, host, port):
        """Mark one proxy as checked (remove it from the remaining set)."""
        if not self.active:
            return
        with self.lock:
            self.remaining.pop((host, port), None)

    def _write_locked(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for key in self.order:
                if key in self.remaining:
                    f.write(self.remaining[key] + "\n")
        os.replace(tmp, self.path)  # atomic on the same filesystem

    def flush(self):
        """Rewrite the queue file with only the proxies still pending."""
        if not self.active:
            return
        with self.lock:
            self._write_locked()

    def pending_count(self):
        with self.lock:
            return len(self.remaining)
