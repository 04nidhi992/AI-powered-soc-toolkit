"""Generate portable Markdown incident reports from findings and alerts."""

from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
from typing import Iterable

from .alerts import read_recent_alerts
from .log_analysis import LogFinding
from .models import SecurityAlert
from .models import Incident, InvestigationNote, NormalizedEvent


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b[\w-]*(?:password|token|secret|credential|api[_-]?key)\b\s*[:=]\s*[^\s,;]+"
)
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+\S+")
_USERNAME_ASSIGNMENT = re.compile(r"(?i)\b(user|username|account)\s*[:=]\s*[^\s,;]+")
_LOGIN_USERNAME = re.compile(
    r"(?i)\b(failed password|accepted password)\s+for\s+(?:invalid user\s+)?[^\s,;]+"
)
_WINDOWS_USER_PATH = re.compile(r"(?i)(\\users\\)[^\\\s]+")
_LINUX_USER_PATH = re.compile(r"(?i)(/home/)[^/\s]+")
_IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _report_text(value: str | None, redact_usernames: bool = True,
                 redact_ips: bool = False) -> str:
    """Sanitize untrusted report content before it reaches Markdown or JSON."""
    if not value:
        return ""
    safe = _SECRET_ASSIGNMENT.sub(
        lambda match: re.split(r"[:=]", match.group(0), maxsplit=1)[0] + "=[REDACTED]", value
    )
    safe = _BEARER_VALUE.sub("Bearer [REDACTED]", safe)
    if redact_usernames:
        safe = _USERNAME_ASSIGNMENT.sub(lambda match: match.group(1) + "=[REDACTED]", safe)
        safe = _LOGIN_USERNAME.sub(lambda match: match.group(1) + " for [REDACTED]", safe)
        safe = _WINDOWS_USER_PATH.sub(r"\1[REDACTED]", safe)
        safe = _LINUX_USER_PATH.sub(r"\1[REDACTED]", safe)
    if redact_ips:
        safe = _IP_ADDRESS.sub("[REDACTED_IP]", safe)
    return safe


def _markdown_text(value: str) -> str:
    safe = html.escape(value, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", safe)


def generate_incident_report(findings: Iterable[LogFinding], alerts: Iterable[SecurityAlert],
                             output_path: str | Path, title: str = "SOC Incident Report",
                             redact_usernames: bool = True, redact_ips: bool = False) -> Path:
    finding_list, alert_list = list(findings), list(alerts)
    lines = [f"# {_markdown_text(_report_text(title, redact_usernames, redact_ips))}", "",
             f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "",
             "## Summary", "", f"- Log findings: {len(finding_list)}", f"- System alerts: {len(alert_list)}", "",
             "## Security alerts", ""]
    if alert_list:
        lines.extend(f"- **{_markdown_text(a.severity)}** `{_markdown_text(a.created_at)}` "
                     f"({_markdown_text(_report_text(a.source, redact_usernames, redact_ips))}): "
                     f"{_markdown_text(_report_text(a.message, redact_usernames, redact_ips))} "
                     f"— {_markdown_text(_report_text(a.reason, redact_usernames, redact_ips))} "
                     f"(rule `{_markdown_text(a.rule_id or '')}`)" for a in alert_list)
    else:
        lines.append("No system alerts were recorded.")
    lines.extend(["", "## Log findings", ""])
    if finding_list:
        lines.extend(f"- **{_markdown_text(f.severity)}** "
                     f"`{_markdown_text(_report_text(f.path, redact_usernames, redact_ips))}:{f.line_number}` "
                     f" | {_markdown_text(_report_text(f.text, redact_usernames, redact_ips))} "
                     f"(rule `{_markdown_text(f.rule_id or '')}`; "
                     f"{_markdown_text(_report_text(f.reason, redact_usernames, redact_ips))})"
                     for f in finding_list)
    else:
        lines.append("No matching log events were found.")
    lines.extend(["", "## Analyst notes", "", "Add triage, scope, actions taken, and follow-up items here.", ""])
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8")
    return destination


def report_from_alert_log(output_path: str | Path, alert_log: str | Path,
                          findings: Iterable[LogFinding] = (), redact_usernames: bool = True,
                          redact_ips: bool = False) -> Path:
    return generate_incident_report(findings, read_recent_alerts(alert_log), output_path,
                                    redact_usernames=redact_usernames, redact_ips=redact_ips)


def generate_json_incident_report(findings: Iterable[LogFinding], alerts: Iterable[SecurityAlert],
                                  output_path: str | Path, title: str = "SOC Incident Report",
                                  redact_usernames: bool = True, redact_ips: bool = False) -> Path:
    finding_list, alert_list = list(findings), list(alerts)
    payload = {
        "title": _report_text(title, redact_usernames, redact_ips),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {"log_findings": len(finding_list), "system_alerts": len(alert_list)},
        "alerts": [
            {**alert.to_dict(),
             "source": _report_text(alert.source, redact_usernames, redact_ips),
             "message": _report_text(alert.message, redact_usernames, redact_ips),
             "reason": _report_text(alert.reason, redact_usernames, redact_ips),
             "evidence_refs": [_report_text(value, redact_usernames, redact_ips) for value in alert.evidence_refs],
             "recommended_steps": [_report_text(value, redact_usernames, redact_ips) for value in alert.recommended_steps]}
            for alert in alert_list
        ],
        "findings": [
            {"path": _report_text(finding.path, redact_usernames, redact_ips),
             "line_number": finding.line_number, "severity": finding.severity,
             "rule_id": finding.rule_id, "reason": _report_text(finding.reason, redact_usernames, redact_ips),
             "timestamp": finding.timestamp, "text": _report_text(finding.text, redact_usernames, redact_ips)}
            for finding in finding_list
        ],
        "analyst_notes": "Add triage, scope, actions taken, and follow-up items here.",
    }
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return destination


def build_case_report(incident: Incident, alerts: Iterable[SecurityAlert], events: Iterable[NormalizedEvent],
                      notes: Iterable[InvestigationNote] = (), redact_usernames: bool = True,
                      redact_ips: bool = False) -> tuple[str, dict]:
    """Build report content with explicit redaction and uncertainty sections."""
    alert_list, event_list, note_list = list(alerts), list(events), list(notes)
    alert_list = [item for item in alert_list if item.alert_id in incident.alert_ids]
    event_list = [item for item in event_list if item.event_id in incident.event_refs]
    known_usernames = {event.username for event in event_list if event.username}
    def redact(value: str | None) -> str:
        if not value:
            return ""
        safe = _report_text(value, redact_usernames, redact_ips)
        if redact_usernames:
            for username in sorted(known_usernames, key=len, reverse=True):
                safe = re.sub(rf"(?<!\w){re.escape(username)}(?!\w)", "[REDACTED]", safe, flags=re.I)
        return safe
    def clean_alert(alert: SecurityAlert) -> dict:
        data = alert.to_dict()
        data["source"] = redact(alert.source)
        data["message"] = redact(alert.message)
        data["reason"] = redact(alert.reason)
        data["evidence_refs"] = [redact(ref) for ref in alert.evidence_refs]
        data["recommended_steps"] = [redact(step) for step in alert.recommended_steps]
        return data
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload = {
        "metadata": {"title": redact(incident.title), "generated_at": created, "incident_id": incident.incident_id,
                     "redaction": {"usernames": redact_usernames, "ips": redact_ips}},
        "executive_summary": redact(incident.findings) or f"Incident {redact(incident.title)} is {incident.status}.",
        "scope": {"status": incident.status, "linked_alerts": len(alert_list), "linked_events": len(event_list)},
        "timeline": sorted(
            ([{"timestamp": event.timestamp, "kind": event.event_type, "evidence_ref": redact(event.evidence_ref),
               "message": redact(event.message)} for event in event_list] +
             [{"timestamp": alert.created_at, "kind": "alert",
               "evidence_ref": ", ".join(redact(ref) for ref in alert.evidence_refs),
               "message": redact(alert.message)} for alert in alert_list]),
            key=lambda item: item["timestamp"]),
        "alerts": [clean_alert(alert) for alert in alert_list],
        "findings": redact(incident.findings),
        "investigation_notes": [{"timestamp": note.created_at, "category": note.category,
                                 "author": "[REDACTED]" if redact_usernames else note.author,
                                 "content": redact(note.content)} for note in note_list],
        "recommendations": redact(incident.recommendations),
        "limitations": ["Rule matches and process indicators are leads for review, not proof of compromise.",
                        "Imported event data may be incomplete or malformed."],
        "uncertainty": "Conclusions depend on the selected events and available fields; validate against authoritative sources.",
        "recommended_next_steps": ["Validate evidence with the source system.", "Document analyst decisions and follow-up."],
    }
    markdown = [f"# {_markdown_text(redact(incident.title))}", "", f"Generated: {created}", "",
        "## Executive summary", "", _markdown_text(payload["executive_summary"]), "",
        "## Scope", "", f"- Linked alerts: {len(alert_list)}", f"- Linked events: {len(event_list)}", "",
        "## Timeline", ""]
    if event_list or alert_list:
        markdown.extend(f"- `{_markdown_text(event.timestamp)}` **{_markdown_text(event.event_type)}** `{_markdown_text(redact(event.evidence_ref))}`: {_markdown_text(redact(event.message))}"
                        for event in sorted(event_list, key=lambda x: x.timestamp))
        markdown.extend(f"- `{_markdown_text(alert.created_at)}` **Alert {html.escape(alert.severity)} "
                        f"({_markdown_text(alert.rule_id or alert.source)})**: "
                        f"{_markdown_text(redact(alert.message))} — {_markdown_text(redact(alert.reason))}"
                        for alert in sorted(alert_list, key=lambda x: x.created_at))
    else:
        markdown.append("No events linked.")
    markdown.extend(["", "## Alerts", ""])
    if alert_list:
        markdown.extend(f"- **{html.escape(alert.severity)}** {_markdown_text(redact(alert.message))} - {_markdown_text(redact(alert.reason))}"
                        for alert in alert_list)
    else:
        markdown.append("No alerts linked.")
    markdown.extend(["", "## Investigation findings", "", _markdown_text(redact(incident.findings) or "Not yet documented."), "",
                     "## Analyst notes", ""])
    if note_list:
        markdown.extend(f"- `{html.escape(note.category)}` {_markdown_text(redact(note.content))}" for note in note_list)
    else:
        markdown.append("No notes recorded.")
    markdown.extend(["", "## Recommendations", "", _markdown_text(redact(incident.recommendations) or "Validate the evidence and document next actions."),
                     "", "## Limitations and uncertainty", "", payload["uncertainty"], "",
                     "Rule matches and indicators are not proof of malicious activity. This report does not establish forensic integrity or legal admissibility.", ""])
    return "\n".join(markdown), payload


def write_case_report(incident: Incident, alerts: Iterable[SecurityAlert], events: Iterable[NormalizedEvent],
                      markdown_path: str | Path, json_path: str | Path,
                      notes: Iterable[InvestigationNote] = (), redact_usernames: bool = True,
                      redact_ips: bool = False) -> tuple[Path, Path]:
    markdown, payload = build_case_report(incident, alerts, events, notes, redact_usernames, redact_ips)
    md_path, js_path = Path(markdown_path), Path(json_path)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    js_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown, encoding="utf-8")
    js_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return md_path, js_path
