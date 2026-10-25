"""Incident and investigation workflows backed by the storage service."""

from datetime import datetime, timezone
import uuid

from .models import Incident, InvestigationNote, NormalizedEvent, SecurityAlert
from .storage import Storage


def create_incident(title: str, alerts: list[SecurityAlert], events: list[NormalizedEvent] = (),
                    findings: str = "", recommendations: str = "") -> Incident:
    if not title.strip():
        raise ValueError("Incident title is required")
    return Incident(str(uuid.uuid4()), title.strip(), datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    alert_ids=tuple(alert.alert_id for alert in alerts),
                    event_refs=tuple(event.event_id for event in events), findings=findings,
                    recommendations=recommendations)


def add_investigation_note(storage: Storage, incident_id: str, author: str,
                           category: str, content: str) -> InvestigationNote:
    if not content.strip():
        raise ValueError("Investigation note content is required")
    if category not in {"observed_fact", "detection_conclusion", "analyst_hypothesis", "recommended_action"}:
        raise ValueError("Unsupported note category")
    note = InvestigationNote(str(uuid.uuid4()), incident_id,
        datetime.now(timezone.utc).isoformat(timespec="seconds"), author.strip() or "Analyst", category, content.strip())
    storage.add_note(note)
    return note


def incident_timeline(storage: Storage, incident: Incident) -> list[dict[str, str]]:
    timeline = [{"timestamp": incident.created_at, "kind": "incident", "detail": incident.title}]
    timeline.extend({"timestamp": alert.created_at, "kind": "alert", "detail": f"{alert.severity} {alert.rule_id or ''}: {alert.message}"}
                    for alert in storage.list_alerts(limit=5000) if alert.alert_id in incident.alert_ids)
    timeline.extend({"timestamp": event.timestamp, "kind": "event", "detail": f"{event.event_type}: {event.message}"}
                    for event in storage.list_events(limit=5000) if event.event_id in incident.event_refs)
    timeline.extend({"timestamp": note.created_at, "kind": note.category, "detail": note.content}
                    for note in storage.list_notes(incident.incident_id))
    return sorted(timeline, key=lambda item: item["timestamp"])
