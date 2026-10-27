"""Incident and investigation workflows backed by the storage service."""

from datetime import datetime, timezone
import uuid

from .models import (AIActivityRecord, AnalystReview, Incident, InvestigationNote, NormalizedEvent,
                     SecurityAlert, _normalize_iso_timestamp)
from .storage import REVIEW_TRANSITIONS, Storage


REVIEW_DECISION_ORDER = ("needs_review", "confirmed", "false_positive", "dismissed")


def allowed_review_decisions(current: str | None = None) -> tuple[str, ...]:
    allowed = REVIEW_TRANSITIONS.get(current, set())
    return tuple(decision for decision in REVIEW_DECISION_ORDER if decision in allowed)


def record_analyst_review(storage: Storage, subject_type: str, subject_id: str, decision: str,
                          *, analyst: str | None = None, notes: str = "",
                          case_refs: tuple[str, ...] = (), evidence_refs: tuple[str, ...] = ()) -> AnalystReview:
    review = AnalystReview(str(uuid.uuid4()), subject_type, subject_id, decision,
        datetime.now(timezone.utc).isoformat(timespec="seconds"), analyst.strip() or None if analyst is not None else None,
        notes.strip(), case_refs, evidence_refs)
    storage.add_analyst_review(review)
    return storage.latest_analyst_review(subject_type, subject_id)


def record_ai_activity(storage: Storage, provider: str, model: str, status: str, safe_summary: str,
                       *, case_refs: tuple[str, ...] = (), evidence_refs: tuple[str, ...] = (),
                       transmitted_fields: tuple[str, ...] = (), request_time: str | None = None) -> AIActivityRecord:
    activity = AIActivityRecord(str(uuid.uuid4()), provider, model,
        request_time or datetime.now(timezone.utc).isoformat(timespec="seconds"), status, safe_summary,
        case_refs, evidence_refs, transmitted_fields)
    storage.add_ai_activity(activity)
    return storage.list_ai_activity()[-1]


def create_incident(title: str, alerts: list[SecurityAlert], events: list[NormalizedEvent] = (),
                    findings: str = "", recommendations: str = "") -> Incident:
    if not title.strip():
        raise ValueError("Incident title is required")
    return Incident(str(uuid.uuid4()), title.strip(), datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    alert_ids=tuple(dict.fromkeys(alert.alert_id for alert in alerts)),
                    event_refs=tuple(dict.fromkeys(event.event_id for event in events)), findings=findings,
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
    def entry(timestamp: str, kind: str, detail: str, source: str = "",
              evidence_refs: tuple[str, ...] = ()) -> dict[str, str]:
        return {"timestamp": _normalize_iso_timestamp(timestamp, f"{kind} timeline timestamp"),
                "kind": kind, "detail": detail, "source": source,
                "evidence_refs": ", ".join(dict.fromkeys(ref for ref in evidence_refs if ref))}

    timeline = [entry(incident.created_at, "incident", incident.title)]
    timeline.extend(entry(alert.created_at, "alert", f"{alert.severity} {alert.rule_id or ''}: {alert.message}",
                          alert.source, alert.evidence_refs)
                    for alert in storage.list_alerts(limit=5000) if alert.alert_id in incident.alert_ids)
    timeline.extend(entry(event.timestamp, "event", f"{event.event_type}: {event.message}", event.source,
                          (event.evidence_ref,) if event.evidence_ref else ())
                    for event in storage.list_events(limit=5000) if event.event_id in incident.event_refs)
    timeline.extend(entry(note.created_at, note.category, note.content)
                    for note in storage.list_notes(incident.incident_id))
    timeline.extend(entry(review.reviewed_at, "analyst_review",
                          f"{review.subject_type} {review.subject_id}: {review.decision}",
                          evidence_refs=review.evidence_refs)
                    for review in storage.list_case_analyst_reviews(incident.incident_id))
    timeline.extend(entry(item.request_time, "ai_activity", f"{item.status}: {item.provider}/{item.model}",
                          evidence_refs=item.evidence_refs)
                    for item in storage.list_ai_activity(incident.incident_id))
    timeline.extend(entry(change["changed_at"], "case_status",
                          f"{change['old_status'] or 'untracked'} -> {change['new_status']}")
                    for change in storage.list_status_history("incident", incident.incident_id))
    return sorted(timeline, key=lambda item: item["timestamp"])
