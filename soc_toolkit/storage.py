"""Versioned SQLite storage for local events, detections, alerts, and incidents."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Iterator
import uuid

from .models import DetectionResult, Incident, InvestigationNote, NormalizedEvent, SecurityAlert


SCHEMA_VERSION = 1
ALERT_STATUSES = {"open", "investigating", "resolved", "false_positive"}


class Storage:
    def __init__(self, path: str | Path = "soc_data/soc_toolkit.sqlite3") -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            self.connection.execute("PRAGMA journal_mode = WAL")
        self.initialize()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            with self._lock:
                with self.connection:
                    yield self.connection
        except sqlite3.Error:
            raise

    def initialize(self) -> None:
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"Database schema {version} is newer than supported {SCHEMA_VERSION}")
        with self.transaction() as db:
            db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL,
                    source TEXT NOT NULL, event_type TEXT NOT NULL, severity TEXT NOT NULL,
                    host TEXT, username TEXT, source_ip TEXT, destination_ip TEXT,
                    message TEXT NOT NULL, evidence_ref TEXT NOT NULL, raw_fields_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL, severity TEXT NOT NULL, reason TEXT NOT NULL,
                    event_refs_json TEXT NOT NULL, evidence_summary TEXT NOT NULL, steps_json TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, severity TEXT NOT NULL,
                    source TEXT NOT NULL, message TEXT NOT NULL, reason TEXT NOT NULL,
                    rule_id TEXT, status TEXT NOT NULL, evidence_refs_json TEXT NOT NULL,
                    steps_json TEXT NOT NULL, dedupe_key TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts(status, severity);
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY, title TEXT NOT NULL, created_at TEXT NOT NULL,
                    status TEXT NOT NULL, alert_ids_json TEXT NOT NULL, event_refs_json TEXT NOT NULL,
                    findings TEXT NOT NULL, recommendations TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS investigation_notes (
                    note_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    created_at TEXT NOT NULL, author TEXT NOT NULL, category TEXT NOT NULL, content TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS status_changes (
                    change_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
                    old_status TEXT, new_status TEXT NOT NULL, changed_at TEXT NOT NULL
                );
                PRAGMA user_version = 1;
                COMMIT;
            """)

    @staticmethod
    def _safe_text(value: str) -> str:
        value = re.sub(r"(?i)\b(user|username|account|password|token|secret|credential|api[_-]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", value)
        value = re.sub(r"(?i)(failed password|accepted password) for (?:invalid user )?\S+", r"\1 for [REDACTED]", value)
        value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", value)
        value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", value)
        value = re.sub(r"(?i)(\\users\\)[^\\\s]+", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)(/home/)[^/\s]+", r"\1[REDACTED]", value)
        return value[:2000]

    @staticmethod
    def _event_key(event: NormalizedEvent) -> str:
        parts = (event.timestamp, event.source, event.event_type, event.host or "", event.username or "",
                 event.source_ip or "", Storage._safe_text(event.message))
        return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()

    @staticmethod
    def _alert_key(alert: SecurityAlert) -> str:
        try:
            created = datetime.fromisoformat(alert.created_at.replace("Z", "+00:00"))
            bucket = str(int(created.timestamp()) // 300)
        except ValueError:
            bucket = alert.created_at
        parts = (alert.source, alert.rule_id or "", alert.message, bucket)
        return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()

    def save_event(self, event: NormalizedEvent) -> bool:
        with self.transaction() as db:
            safe_ref = self._safe_text(event.evidence_ref)
            cursor = db.execute("""INSERT OR IGNORE INTO events VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event.event_id, self._event_key(event), event.timestamp, self._safe_text(event.source), event.event_type,
                 event.severity, event.host, event.username, event.source_ip, event.destination_ip,
                 self._safe_text(event.message), safe_ref, "{}"))
            return cursor.rowcount == 1

    def save_events(self, events: list[NormalizedEvent]) -> int:
        return sum(self.save_event(event) for event in events)

    def list_events(self, limit: int = 500, source_ip: str | None = None,
                    host: str | None = None) -> list[NormalizedEvent]:
        clauses, params = [], []
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if host:
            clauses.append("host = ?")
            params.append(host)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            rows = self.connection.execute(f"SELECT * FROM events{where} ORDER BY timestamp DESC LIMIT ?",
                                           (*params, max(0, limit))).fetchall()
        return [NormalizedEvent(row["timestamp"], row["source"], row["event_type"], row["severity"],
                                row["message"], row["host"], row["username"], row["source_ip"],
                                row["destination_ip"], row["evidence_ref"], row["event_id"],
                                json.loads(row["raw_fields_json"])) for row in rows]

    def count_events(self) -> int:
        """Return the exact number of locally stored normalized events."""
        with self._lock:
            return int(self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def save_detection(self, detection: DetectionResult) -> bool:
        dedupe = hashlib.sha256("\0".join((detection.rule_id, ",".join(detection.event_refs))).encode()).hexdigest()
        with self.transaction() as db:
            cursor = db.execute("INSERT OR IGNORE INTO detections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (detection.detection_id, detection.rule_id, detection.rule_name, detection.timestamp,
                 detection.severity, self._safe_text(detection.reason), json.dumps(detection.event_refs),
                 self._safe_text(detection.evidence_summary),
                 json.dumps([self._safe_text(step) for step in detection.recommended_steps]), dedupe))
            return cursor.rowcount == 1

    def save_alert(self, alert: SecurityAlert) -> bool:
        safe_source = self._safe_text(alert.source)
        safe_message = self._safe_text(alert.message)
        safe_reason = self._safe_text(alert.reason)
        with self.transaction() as db:
            try:
                created = datetime.fromisoformat(alert.created_at.replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                cutoff = (created - timedelta(seconds=300)).isoformat(timespec="seconds")
                duplicate = db.execute("""SELECT 1 FROM alerts WHERE source = ? AND rule_id IS ?
                    AND message = ? AND created_at >= ? LIMIT 1""",
                    (safe_source, alert.rule_id, safe_message, cutoff)).fetchone()
                if duplicate:
                    return False
            except ValueError:
                pass
            cursor = db.execute("INSERT OR IGNORE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (alert.alert_id, alert.created_at, alert.severity, safe_source, safe_message, safe_reason,
                 alert.rule_id, alert.status, json.dumps([self._safe_text(ref) for ref in alert.evidence_refs]),
                 json.dumps([self._safe_text(step) for step in alert.recommended_steps]),
                 self._alert_key(SecurityAlert(alert.created_at, alert.severity, safe_source, safe_message,
                    safe_reason, alert.rule_id, alert.alert_id, alert.status,
                    tuple(self._safe_text(ref) for ref in alert.evidence_refs),
                    tuple(self._safe_text(step) for step in alert.recommended_steps)))))
            return cursor.rowcount == 1

    @staticmethod
    def _alert(row: sqlite3.Row) -> SecurityAlert:
        return SecurityAlert(row["created_at"], row["severity"], row["source"], row["message"],
                             row["reason"], row["rule_id"], row["alert_id"], row["status"],
                             tuple(json.loads(row["evidence_refs_json"])), tuple(json.loads(row["steps_json"])))

    def list_alerts(self, severity: str | None = None, status: str | None = None,
                    limit: int = 500) -> list[SecurityAlert]:
        clauses, params = [], []
        for column, value in (("severity", severity), ("status", status)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value.upper() if column == "severity" else value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            rows = self.connection.execute(f"SELECT * FROM alerts{where} ORDER BY created_at DESC LIMIT ?",
                                           (*params, max(0, limit))).fetchall()
        return [self._alert(row) for row in rows]

    def count_alerts(self, severity: str | None = None, status: str | None = None) -> int:
        """Count all stored alerts, optionally filtered by severity and status."""
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            row = self.connection.execute(f"SELECT COUNT(*) FROM alerts{where}", params).fetchone()
        return int(row[0])

    def get_alert(self, alert_id: str) -> SecurityAlert | None:
        with self._lock:
            row = self.connection.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return self._alert(row) if row else None

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        if status not in ALERT_STATUSES:
            raise ValueError(f"Unsupported alert status: {status}")
        with self.transaction() as db:
            row = db.execute("SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row is None:
                return False
            db.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
            db.execute("INSERT INTO status_changes VALUES (?, ?, ?, ?, ?, ?)",
                       (str(uuid.uuid4()), "alert", alert_id, row["status"], status,
                        datetime.now(timezone.utc).isoformat(timespec="seconds")))
            return True

    def save_incident(self, incident: Incident) -> None:
        with self.transaction() as db:
            db.execute("""INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET title=excluded.title, created_at=excluded.created_at,
                status=excluded.status, alert_ids_json=excluded.alert_ids_json,
                event_refs_json=excluded.event_refs_json, findings=excluded.findings,
                recommendations=excluded.recommendations""",
                (incident.incident_id, self._safe_text(incident.title), incident.created_at, incident.status,
                 json.dumps(incident.alert_ids), json.dumps(incident.event_refs), self._safe_text(incident.findings),
                 self._safe_text(incident.recommendations)))

    def list_incidents(self) -> list[Incident]:
        with self._lock:
            rows = self.connection.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        return [Incident(row["incident_id"], row["title"], row["created_at"], row["status"],
                         tuple(json.loads(row["alert_ids_json"])), tuple(json.loads(row["event_refs_json"])),
                         row["findings"], row["recommendations"]) for row in rows]

    def update_incident_status(self, incident_id: str, status: str) -> bool:
        if status not in {"open", "investigating", "resolved", "false_positive"}:
            raise ValueError(f"Unsupported incident status: {status}")
        with self.transaction() as db:
            row = db.execute("SELECT status FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if row is None:
                return False
            db.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (status, incident_id))
            db.execute("INSERT INTO status_changes VALUES (?, ?, ?, ?, ?, ?)",
                       (str(uuid.uuid4()), "incident", incident_id, row["status"], status,
                        datetime.now(timezone.utc).isoformat(timespec="seconds")))
            return True

    def add_note(self, note: InvestigationNote) -> None:
        with self.transaction() as db:
            db.execute("INSERT INTO investigation_notes VALUES (?, ?, ?, ?, ?, ?)",
                       (note.note_id, note.incident_id, note.created_at, self._safe_text(note.author), note.category,
                        self._safe_text(note.content)))

    def list_notes(self, incident_id: str) -> list[InvestigationNote]:
        with self._lock:
            rows = self.connection.execute("SELECT * FROM investigation_notes WHERE incident_id = ? ORDER BY created_at",
                                           (incident_id,)).fetchall()
        return [InvestigationNote(row["note_id"], row["incident_id"], row["created_at"], row["author"],
                                  row["category"], row["content"]) for row in rows]

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
