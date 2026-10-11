"""SQLite persistence for events and alerts (WAL mode, bounded retention).

All access is serialised with a lock because FastAPI runs sync endpoints in a
thread pool. All SQL uses bound parameters.
"""
from __future__ import annotations

import json
import sqlite3
import threading

from .models import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invocation_id TEXT, ts REAL NOT NULL, function_name TEXT NOT NULL,
    caller TEXT, source_ip TEXT, status_code INTEGER,
    duration_ms REAL, payload_size_bytes INTEGER,
    flagged INTEGER NOT NULL DEFAULT 0, risk_score INTEGER NOT NULL DEFAULT 0,
    rules TEXT NOT NULL DEFAULT '[]', ml_score REAL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_flagged ON events(flagged, ts);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, ts REAL NOT NULL, function_name TEXT NOT NULL,
    rule TEXT NOT NULL, rules TEXT NOT NULL, severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL, source_ip TEXT, caller TEXT,
    message TEXT, invocation_id TEXT, suppressed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""


class Store:
    def __init__(self, path: str = "ssmf.db", max_events: int = 200_000) -> None:
        self.path = path
        self.max_events = max_events
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._since_prune = 0

    # -- writes ----------------------------------------------------------
    def insert_detections(self, dets: list) -> None:
        rows = [(
            d.event.invocation_id, d.event.timestamp, d.event.function_name, d.event.caller,
            d.event.source_ip, d.event.status_code, d.event.duration_ms, d.event.payload_size_bytes,
            int(d.flagged), d.risk_score, json.dumps(d.rule_names), d.ml_score,
        ) for d in dets]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO events (invocation_id, ts, function_name, caller, source_ip, status_code,"
                " duration_ms, payload_size_bytes, flagged, risk_score, rules, ml_score)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self._conn.commit()
            self._since_prune += len(rows)
            if self._since_prune >= 1000:
                self._prune_locked()

    def insert_alert(self, a: Alert) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (a.alert_id, a.timestamp, a.function_name, a.rule, json.dumps(a.rules), a.severity,
                 a.risk_score, a.source_ip, a.caller, a.message, a.invocation_id, a.suppressed))
            self._conn.commit()

    def _prune_locked(self) -> None:
        self._since_prune = 0
        total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if total > self.max_events:
            self._conn.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?)",
                (total - self.max_events,))
            self._conn.commit()

    def reset(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.execute("DELETE FROM alerts")
            self._conn.commit()

    # -- reads -----------------------------------------------------------
    def recent_alerts(self, limit: int = 50, severity: str | None = None) -> list:
        sql, args = "SELECT * FROM alerts", []
        if severity:
            sql += " WHERE severity = ?"
            args.append(severity)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["rules"] = json.loads(d["rules"])
            out.append(d)
        return out

    def recent_events(self, limit: int = 100, flagged_only: bool = False) -> list:
        sql = "SELECT * FROM events" + (" WHERE flagged = 1" if flagged_only else "") + " ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (max(1, min(limit, 1000)),)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["rules"] = json.loads(d["rules"])
            d["flagged"] = bool(d["flagged"])
            out.append(d)
        return out

    def stats(self, bucket_seconds: int = 10, buckets: int = 60) -> dict:
        with self._lock:
            c = self._conn
            total, flagged = c.execute("SELECT COUNT(*), COALESCE(SUM(flagged),0) FROM events").fetchone()
            latest = c.execute("SELECT MAX(ts) FROM events").fetchone()[0]
            by_fn = [dict(r) for r in c.execute(
                "SELECT function_name, COUNT(*) AS total, COALESCE(SUM(flagged),0) AS flagged,"
                " ROUND(AVG(duration_ms),1) AS avg_ms FROM events GROUP BY function_name ORDER BY total DESC")]
            by_rule = [dict(r) for r in c.execute(
                "SELECT rule, COUNT(*) AS count FROM alerts GROUP BY rule ORDER BY count DESC")]
            by_sev = {r["severity"]: r["count"] for r in c.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity")}
            alert_total = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            series = []
            if latest is not None:
                since = latest - bucket_seconds * buckets
                series = [dict(r) for r in c.execute(
                    "SELECT CAST(ts / ? AS INTEGER) * ? AS t, COUNT(*) AS events,"
                    " COALESCE(SUM(flagged),0) AS flagged FROM events WHERE ts >= ? GROUP BY t ORDER BY t",
                    (bucket_seconds, bucket_seconds, since))]
        return {
            "total_events": total, "flagged_events": flagged, "total_alerts": alert_total,
            "latest_event_ts": latest, "by_function": by_fn, "by_rule": by_rule,
            "by_severity": by_sev, "timeseries": series, "bucket_seconds": bucket_seconds,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
