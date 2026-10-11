import sqlite3
import json
from datetime import datetime
from pathlib import Path


class Storage:
    def __init__(self, db_path="siem.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT,
                host TEXT,
                log_type TEXT,
            severity TEXT DEFAULT 'info',
                raw TEXT,
                parsed TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                rule_name TEXT,
                severity TEXT,
                message TEXT,
                matched_events TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                description TEXT,
                severity TEXT DEFAULT 'medium',
                condition_type TEXT,
                pattern TEXT,
                threshold INTEGER DEFAULT 1,
                window_seconds INTEGER DEFAULT 300,
                enabled INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );
        """)
        self.conn.commit()

    def insert_event(self, timestamp, source, host, log_type, severity, raw, parsed=None):
        self.conn.execute(
            "INSERT INTO events (timestamp, source, host, log_type, severity, raw, parsed) VALUES (?,?,?,?,?,?,?)",
            (timestamp, source, host, log_type, severity, raw, json.dumps(parsed) if parsed else None),
        )
        self.conn.commit()

    def search_events(self, query=None, source=None, severity=None, log_type=None,
                      start_time=None, end_time=None, limit=100, offset=0):
        sql = "SELECT * FROM events WHERE 1=1"
        params = []
        if query:
            sql += " AND (raw LIKE ? OR parsed LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])
        if source:
            sql += " AND source = ?"
            params.append(source)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if log_type:
            sql += " AND log_type = ?"
            params.append(log_type)
        if start_time:
            sql += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            sql += " AND timestamp <= ?"
            params.append(end_time)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self.conn.execute(sql, params).fetchall()
        columns = [d[0] for d in self.conn.execute("PRAGMA table_info(events)").fetchall()]
        return [dict(zip(columns, r)) for r in rows]

    def stats(self):
        total = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_source = self.conn.execute(
            "SELECT source, COUNT(*) as cnt FROM events WHERE source IS NOT NULL GROUP BY source ORDER BY cnt DESC"
        ).fetchall()
        by_severity = self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity ORDER BY cnt DESC"
        ).fetchall()
        by_type = self.conn.execute(
            "SELECT log_type, COUNT(*) as cnt FROM events WHERE log_type IS NOT NULL GROUP BY log_type ORDER BY cnt DESC"
        ).fetchall()
        return {"total": total, "by_source": by_source, "by_severity": by_severity, "by_type": by_type}

    def insert_rule(self, name, description, severity, condition_type, pattern, threshold=1, window_seconds=300):
        try:
            self.conn.execute(
                "INSERT INTO rules (name, description, severity, condition_type, pattern, threshold, window_seconds) VALUES (?,?,?,?,?,?,?)",
                (name, description, severity, condition_type, pattern, threshold, window_seconds),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_rules(self, enabled_only=True):
        sql = "SELECT * FROM rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        rows = self.conn.execute(sql).fetchall()
        columns = [d[0] for d in self.conn.execute("PRAGMA table_info(rules)").fetchall()]
        return [dict(zip(columns, r)) for r in rows]

    def insert_alert(self, rule_id, rule_name, severity, message, matched_events):
        self.conn.execute(
            "INSERT INTO alerts (rule_id, rule_name, severity, message, matched_events) VALUES (?,?,?,?,?)",
            (rule_id, rule_name, severity, message, json.dumps(matched_events)),
        )
        self.conn.commit()

    def get_alerts(self, limit=50):
        rows = self.conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        columns = [d[0] for d in self.conn.execute("PRAGMA table_info(alerts)").fetchall()]
        return [dict(zip(columns, r)) for r in rows]

    def close(self):
        self.conn.close()
