"""Generate portable Markdown incident reports from findings and alerts."""

from datetime import datetime, timezone
import html
from io import BytesIO
import json
from pathlib import Path
import re
from typing import Iterable

from .alerts import read_recent_alerts
from .log_analysis import LogFinding
from .models import SecurityAlert
from .models import Incident, InvestigationNote, NormalizedEvent
from .attack_mapping import assess_detection_mapping
from .correlation import correlate_events
from .detection import detect_events
from .ioc_extraction import extract_iocs_from_events


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
                      redact_ips: bool = False, *, analyst_reviews: Iterable[object] = (),
                      ai_activity: Iterable[object] = ()) -> tuple[str, dict]:
    """Build report content with explicit redaction and uncertainty sections."""
    alert_list, event_list, note_list = list(alerts), list(events), list(notes)
    alert_list = [item for item in alert_list if item.alert_id in incident.alert_ids]
    event_list = [item for item in event_list if item.event_id in incident.event_refs]
    note_list = [item for item in note_list if item.incident_id == incident.incident_id]
    review_list = list(analyst_reviews)
    ai_list = list(ai_activity)
    detections = detect_events(event_list)
    correlations = correlate_events(event_list)
    indicators = extract_iocs_from_events(event_list)
    technique_matches = [mapping for detection in detections
                         for mapping in assess_detection_mapping(detection, available_events=event_list).matches]
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
        "scope": {"status": incident.status, "linked_alerts": len(alert_list), "linked_events": len(event_list),
                  "analyst_reviews": len(review_list)},
        "timeline": sorted(
            ([{"timestamp": event.timestamp, "kind": event.event_type, "evidence_ref": redact(event.evidence_ref),
               "message": redact(event.message)} for event in event_list] +
             [{"timestamp": alert.created_at, "kind": "alert",
               "evidence_ref": ", ".join(redact(ref) for ref in alert.evidence_refs),
               "message": redact(alert.message)} for alert in alert_list]),
            key=lambda item: item["timestamp"]),
        "alerts": [clean_alert(alert) for alert in alert_list],
        "observed_events": [{"timestamp": event.timestamp, "event_type": event.event_type,
            "evidence_ref": redact(event.evidence_ref), "message": redact(event.message)}
            for event in sorted(event_list, key=lambda item: item.timestamp)],
        "indicators": [{"type": indicator.indicator_type, "value": redact(indicator.value),
            "classification": "extracted", "evidence_refs": [redact(ref) for ref in indicator.evidence_refs]}
            for indicator in indicators],
        "automated_assessments": {
            "detections": [{"rule_id": item.rule_id, "rule_name": item.rule_name,
                "severity": item.severity, "reason": redact(item.reason),
                "evidence_refs": [redact(ref) for ref in item.event_refs]}
                for item in detections],
            "correlations": [{"start_time": item.start_time, "end_time": item.end_time,
                "event_count": item.event_count, "shared_fields": item.shared_fields,
                "explanation": redact(item.explanation), "evidence_refs": [redact(ref) for ref in item.event_refs]}
                for item in correlations],
        },
        "attack_mappings": [{"status": item.mapping_status, "technique_id": item.technique_id,
            "technique_name": item.technique_name, "tactic": item.tactic,
            "rule_id": item.rule_id, "explanation": redact(item.explanation),
            "qualification": redact(item.qualification),
            "evidence_refs": [redact(ref) for ref in item.evidence_refs], "source_url": item.source_url}
            for item in technique_matches],
        "analyst_reviews": [{"reviewed_at": item.reviewed_at, "subject_type": item.subject_type,
            "subject_id": item.subject_id, "decision": item.decision,
            "analyst": "[REDACTED]" if redact_usernames and item.analyst else redact(item.analyst or "Not provided"),
            "notes": redact(item.notes), "case_refs": [redact(ref) for ref in item.case_refs],
            "evidence_refs": [redact(ref) for ref in item.evidence_refs]}
            for item in review_list],
        "ai_activity": [{"provider": redact(item.provider), "model": redact(item.model),
            "request_time": item.request_time, "status": item.status,
            "safe_summary": redact(item.safe_summary), "case_refs": [redact(ref) for ref in item.case_refs],
            "evidence_refs": [redact(ref) for ref in item.evidence_refs],
            "transmitted_fields": item.transmitted_fields}
            for item in ai_list],
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
                     "", "## Automated assessments", ""])
    if detections:
        markdown.extend(f"- `{item.rule_id}` ({item.severity}): {_markdown_text(redact(item.reason))}; evidence: "
                        f"{_markdown_text(', '.join(redact(ref) for ref in item.event_refs))}" for item in detections)
    else:
        markdown.append("No automated detection matched the linked events.")
    markdown.extend(["", "## Extracted indicators", ""])
    if indicators:
        markdown.extend(f"- {indicator.indicator_type}: `{_markdown_text(redact(indicator.value))}` (extracted, not a verdict); evidence: "
                        f"{_markdown_text(', '.join(redact(ref) for ref in indicator.evidence_refs))}" for indicator in indicators)
    else:
        markdown.append("No supported indicators were extracted from linked events.")
    markdown.extend(["", "## Potential ATT&CK matches", ""])
    if technique_matches:
        markdown.extend(f"- Potential `{item.technique_id}` {item.technique_name} ({item.tactic}), rule `{item.rule_id}`: "
                        f"{_markdown_text(redact(item.explanation))} Qualification: {_markdown_text(redact(item.qualification))}; evidence: "
                        f"{_markdown_text(', '.join(redact(ref) for ref in item.evidence_refs))}" for item in technique_matches)
    else:
        markdown.append("No supported ATT&CK technique mapping is available.")
    markdown.extend(["", "## Analyst review decisions", ""])
    if review_list:
        markdown.extend(f"- `{item.reviewed_at}` {item.decision} by "
                        f"{('[REDACTED]' if redact_usernames and item.analyst else redact(item.analyst or 'Not provided'))}: "
                        f"{_markdown_text(redact(item.notes))}; evidence: "
                        f"{_markdown_text(', '.join(redact(ref) for ref in item.evidence_refs))}" for item in review_list)
    else:
        markdown.append("No analyst review decisions recorded.")
    markdown.extend(["", "## AI activity (separate from analyst decisions)", ""])
    if ai_list:
        markdown.extend(f"- `{item.request_time}` {redact(item.provider)} / {redact(item.model)} ({item.status}): "
                        f"{_markdown_text(redact(item.safe_summary))}; evidence: "
                        f"{_markdown_text(', '.join(redact(ref) for ref in item.evidence_refs))}" for item in ai_list)
    else:
        markdown.append("No AI activity was recorded.")
    markdown.extend(["", "## Limitations and uncertainty", "", payload["uncertainty"],
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


def generate_pdf_case_report(incident: Incident, alerts: Iterable[SecurityAlert], events: Iterable[NormalizedEvent],
                             output_path: str | Path, notes: Iterable[InvestigationNote] = (),
                             redact_usernames: bool = True, redact_ips: bool = False, *,
                             analyst_reviews: Iterable[object] = (),
                             ai_activity: Iterable[object] = ()) -> Path:
    """Generate a paginated PDF report from the same sanitized case payload as Markdown/JSON."""
    markdown, payload = build_case_report(incident, alerts, events, notes,
        redact_usernames, redact_ips, analyst_reviews=analyst_reviews, ai_activity=ai_activity)
    del markdown
    try:
        from reportlab import __file__ as reportlab_file
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate,
            Spacer, Table, TableStyle)

        font_dir = Path(reportlab_file).parent / "fonts"
        if "SOCToolkitVera" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("SOCToolkitVera", str(font_dir / "Vera.ttf")))
            pdfmetrics.registerFont(TTFont("SOCToolkitVera-Bold", str(font_dir / "VeraBd.ttf")))
        fallback_fonts = []
        for candidate in (Path("C:/Windows/Fonts/arial.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
                          Path("/System/Library/Fonts/Supplemental/Arial Unicode.ttf")):
            if candidate.is_file():
                fallback_name = "SOCToolkitUnicodeFallback"
                if fallback_name not in pdfmetrics.getRegisteredFontNames():
                    pdfmetrics.registerFont(TTFont(fallback_name, str(candidate)))
                fallback_fonts.append(fallback_name)
                break
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("SOC_Title", parent=styles["Title"], fontName="SOCToolkitVera-Bold",
            fontSize=20, leading=25, textColor=colors.HexColor("#10243A"), alignment=TA_CENTER, spaceAfter=8)
        heading_style = ParagraphStyle("SOC_Heading", parent=styles["Heading2"], fontName="SOCToolkitVera-Bold",
            fontSize=12, leading=16, textColor=colors.HexColor("#14547A"), spaceBefore=12, spaceAfter=5, keepWithNext=True)
        body_style = ParagraphStyle("SOC_Body", parent=styles["BodyText"], fontName="SOCToolkitVera",
            fontSize=8.5, leading=12, wordWrap="CJK", spaceAfter=4)
        small_style = ParagraphStyle("SOC_Small", parent=body_style, fontSize=7, leading=9,
            textColor=colors.HexColor("#566575"))
        empty_style = ParagraphStyle("SOC_Empty", parent=body_style, textColor=colors.HexColor("#566575"), italic=True)

        def paragraph(value: object, style=body_style) -> Paragraph:
            raw = str(value if value is not None else "")
            primary = style.fontName
            font_options = [primary, *fallback_fonts]
            runs: list[tuple[str, str]] = []
            for character in raw:
                font_name = next((name for name in font_options
                    if ord(character) in getattr(pdfmetrics.getFont(name).face, "charToGlyph", {})), primary)
                if runs and runs[-1][0] == font_name:
                    runs[-1] = (font_name, runs[-1][1] + character)
                else:
                    runs.append((font_name, character))
            safe = "".join(f'<font name="{font_name}">{html.escape(text, quote=True)}</font>'
                           for font_name, text in runs).replace("\n", "<br/>")
            return Paragraph(safe or "&#160;", style)

        story = [paragraph(payload["metadata"]["title"] or "Investigation Report", title_style),
                 paragraph(f"Generated {payload['metadata']['generated_at']} · Case {payload['metadata']['incident_id']}", small_style),
                 HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#1B6A8F")), Spacer(1, 10)]

        def section(title: str, entries: Iterable[object], empty: str = "No records available.") -> None:
            story.append(paragraph(title, heading_style))
            rows = list(entries)
            if not rows:
                story.append(paragraph(empty, empty_style))
            else:
                story.extend(paragraph(row) for row in rows)

        section("Case summary", [payload["executive_summary"] or "No summary documented."])
        scope = payload["scope"]
        story.append(paragraph("Scope", heading_style))
        scope_table = Table([
            [paragraph("Case status", small_style), paragraph(scope["status"])],
            [paragraph("Linked alerts", small_style), paragraph(scope["linked_alerts"])],
            [paragraph("Linked events", small_style), paragraph(scope["linked_events"])],
            [paragraph("Analyst reviews", small_style), paragraph(scope["analyst_reviews"])],
        ], colWidths=[1.6 * inch, 4.8 * inch], hAlign="LEFT")
        scope_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF1F7")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CAD5DF")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.extend([scope_table, Spacer(1, 6)])

        section("Observed event timeline", [
            f"{item['timestamp']} · {item['event_type']} · Evidence {item['evidence_ref']} · {item['message']}"
            for item in payload["observed_events"]], "No events are linked to this case.")
        section("Linked alerts", [
            f"{item['severity']} · {item['rule_id'] or item['source']} · {item['message']} · {item['reason']} · Evidence {', '.join(item['evidence_refs'])}"
            for item in payload["alerts"]], "No alerts are linked to this case.")
        section("Observed facts / case findings (analyst-documented)",
            [payload["findings"] or "No findings documented."])
        section("Extracted IOCs (not threat verdicts)", [
            f"{item['type']} · {item['value']} · {item['classification']} · Evidence {', '.join(item['evidence_refs'])}"
            for item in payload["indicators"]], "No supported indicators extracted.")
        automated = payload["automated_assessments"]
        section("Automated detections", [
            f"{item['rule_id']} ({item['severity']}) · {item['reason']} · Evidence {', '.join(item['evidence_refs'])}"
            for item in automated["detections"]], "No detection matched linked events.")
        section("Event correlation evidence", [
            f"{item['start_time']}–{item['end_time']} · {item['event_count']} events · Shared fields {', '.join(item['shared_fields'])} · {item['explanation']} · Evidence {', '.join(item['evidence_refs'])}"
            for item in automated["correlations"]], "No identity-linked correlation group found.")
        section("Potential MITRE ATT&CK matches", [
            f"Potential {item['technique_id']} {item['technique_name']} ({item['tactic']}) · Rule {item['rule_id']} · {item['explanation']} · Qualification: {item['qualification']} · Evidence {', '.join(item['evidence_refs'])} · {item['source_url']}"
            for item in payload["attack_mappings"]], "No supported ATT&CK mapping available.")
        section("Analyst review decisions", [
            f"{item['reviewed_at']} · {item['decision']} · Analyst {item['analyst']} · {item['notes']} · Evidence {', '.join(item['evidence_refs'])}"
            for item in payload["analyst_reviews"]], "No analyst review decisions recorded.")
        section("AI activity and suggestions (separate from analyst decisions)", [
            f"{item['request_time']} · {item['provider']} / {item['model']} · {item['status']} · {item['safe_summary']} · Evidence {', '.join(item['evidence_refs'])}"
            for item in payload["ai_activity"]], "No AI activity recorded.")
        section("Investigation notes", [
            f"{item['timestamp']} · {item['category']} · {item['author']} · {item['content']}"
            for item in payload["investigation_notes"]], "No investigation notes recorded.")
        section("Recommendations", [payload["recommendations"] or "Validate evidence and document next actions."])
        section("Limitations and uncertainty", [*payload["limitations"], payload["uncertainty"],
            "Automated detections, IOCs, correlations, and technique matches support review; they do not establish malicious activity, attribution, forensic integrity, or legal admissibility."])

        buffer = BytesIO()
        generated = payload["metadata"]["generated_at"]
        def page_footer(canvas, document):
            canvas.saveState()
            canvas.setFont("SOCToolkitVera", 7)
            canvas.setFillColor(colors.HexColor("#566575"))
            canvas.drawString(document.leftMargin, 0.45 * inch, f"Generated {generated} · {payload['metadata']['incident_id']}")
            canvas.drawRightString(letter[0] - document.rightMargin, 0.45 * inch, f"Page {document.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.65 * inch, leftMargin=0.65 * inch,
            topMargin=0.7 * inch, bottomMargin=0.7 * inch, title=payload["metadata"]["title"],
            author="AI-Powered SOC & DFIR Investigation Copilot",
            subject=f"Investigation case report · {payload['metadata']['title']}")
        doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(buffer.getvalue())
        return destination
    except Exception as exc:
        raise RuntimeError("PDF report generation failed") from exc
