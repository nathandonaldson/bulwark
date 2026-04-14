"""SQLite event storage for Bulwark Dashboard."""
import sqlite3
import json
import time
import threading
from pathlib import Path
from typing import Optional

# Relative path — resolves against CWD. In Docker with WORKDIR /app, this is /app/bulwark-dashboard.db.
# Ephemeral in Docker (no volume mount in Approach A). Container restarts lose event history.
DB_PATH = Path("bulwark-dashboard.db")


class EventDB:
    def __init__(self, path: str = None):
        self._path = path or str(DB_PATH)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = sqlite3.connect(self._path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                layer TEXT NOT NULL,
                verdict TEXT NOT NULL,
                source_id TEXT DEFAULT '',
                detail TEXT DEFAULT '',
                duration_ms REAL DEFAULT 0,
                metadata TEXT DEFAULT '{}',
                created_at REAL DEFAULT (strftime('%s', 'now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_layer ON events(layer)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict)")
        conn.commit()
        conn.close()

    def insert(self, event: dict) -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO events (timestamp, layer, verdict, source_id, detail, duration_ms, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event["timestamp"], event["layer"], event["verdict"],
             event.get("source_id", ""), event.get("detail", ""),
             event.get("duration_ms", 0), json.dumps(event.get("metadata", {})))
        )
        conn.commit()
        return cur.lastrowid

    def insert_batch(self, events: list[dict]) -> int:
        conn = self._get_conn()
        conn.executemany(
            "INSERT INTO events (timestamp, layer, verdict, source_id, detail, duration_ms, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(e["timestamp"], e["layer"], e["verdict"],
              e.get("source_id", ""), e.get("detail", ""),
              e.get("duration_ms", 0), json.dumps(e.get("metadata", {})))
             for e in events]
        )
        conn.commit()
        return len(events)

    def query(self, layer: str = None, verdict: str = None,
              since: float = None, until: float = None,
              limit: int = 100, offset: int = 0) -> list[dict]:
        conn = self._get_conn()
        sql = "SELECT * FROM events WHERE 1=1"
        params = []
        if layer:
            sql += " AND layer = ?"
            params.append(layer)
        if verdict:
            sql += " AND verdict = ?"
            params.append(verdict)
        if since:
            sql += " AND timestamp >= ?"
            params.append(since)
        if until:
            sql += " AND timestamp <= ?"
            params.append(until)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def metrics(self, hours: int = 24) -> dict:
        conn = self._get_conn()
        since = time.time() - (hours * 3600)

        # Total counts
        total = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)).fetchone()[0]

        # By layer
        by_layer = {}
        for row in conn.execute("SELECT layer, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY layer", (since,)):
            by_layer[row[0]] = row[1]

        # By verdict
        by_verdict = {}
        for row in conn.execute("SELECT verdict, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY verdict", (since,)):
            by_verdict[row[0]] = row[1]

        # Blocked count
        blocked = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND verdict = 'blocked'", (since,)).fetchone()[0]

        return {
            "hours": hours,
            "total": total,
            "blocked": blocked,
            "by_layer": by_layer,
            "by_verdict": by_verdict,
        }

    def timeseries(self, hours: int = 24, buckets: int = 24, layer: str = None) -> dict:
        """Event counts bucketed over time for sparkline charts."""
        conn = self._get_conn()
        now = time.time()
        since = now - (hours * 3600)
        bucket_size = (hours * 3600) / buckets

        result_buckets = []
        for i in range(buckets):
            bucket_start = since + (i * bucket_size)
            bucket_end = bucket_start + bucket_size

            sql = (
                "SELECT COUNT(*) as total, "
                "SUM(CASE WHEN verdict='blocked' THEN 1 ELSE 0 END) as blocked, "
                "SUM(CASE WHEN verdict='modified' THEN 1 ELSE 0 END) as modified "
                "FROM events WHERE timestamp >= ? AND timestamp < ?"
            )
            params: list = [bucket_start, bucket_end]
            if layer:
                sql += " AND layer = ?"
                params.append(layer)

            row = conn.execute(sql, params).fetchone()
            result_buckets.append({
                "t": round(bucket_start),
                "total": row[0] or 0,
                "blocked": row[1] or 0,
                "modified": row[2] or 0,
            })

        return {
            "hours": hours,
            "buckets": buckets,
            "layer": layer,
            "data": result_buckets,
        }

    def prune(self, days: int = 30) -> int:
        conn = self._get_conn()
        cutoff = time.time() - (days * 86400)
        cur = conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        conn.commit()
        return cur.rowcount

    @staticmethod
    def _row_to_dict(row) -> dict:
        d = dict(row)
        d["metadata"] = json.loads(d.get("metadata", "{}"))
        return d
