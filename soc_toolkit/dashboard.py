"""Streamlit dashboard. Streamlit/Plotly are imported only when the app is launched."""

from datetime import datetime, timezone
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile

from soc_toolkit.ai_analysis import OpenAICompatibleProvider, explain_alert, sanitize_ai_payload
from soc_toolkit.config import DEFAULT_CONFIG
from soc_toolkit.correlation import correlate_events
from soc_toolkit.detection import detect_events, detect_process_reviews, detect_system_metrics
from soc_toolkit.investigation import add_investigation_note, create_incident, incident_timeline
from soc_toolkit.log_analysis import ingest_log_file
from soc_toolkit.logging_config import configure_app_logging
from soc_toolkit.models import SecurityAlert, stable_event_id
from soc_toolkit.monitoring import collect_processes, collect_system_snapshot
from soc_toolkit.process_analysis import analyze_processes
from soc_toolkit.reports import build_case_report
from soc_toolkit.settings import Thresholds
from soc_toolkit.storage import Storage


SECTIONS = ("Overview", "System Monitoring", "Process Analysis", "Log Analysis", "Alerts",
            "Correlation", "Incidents", "Reports", "Settings")


def _persist_detections(storage: Storage, detections) -> int:
    count = 0
    for result in detections:
        storage.save_detection(result)
        alert = SecurityAlert(result.timestamp, result.severity, "detection", result.evidence_summary,
                              result.reason, result.rule_id, evidence_refs=result.event_refs,
                              recommended_steps=result.recommended_steps)
        count += int(storage.save_alert(alert))
    return count


def _render_metrics(st, px, alerts):
    snapshot = collect_system_snapshot()
    show_percent = lambda value: f"{value:.1f}%" if value is not None else "Unavailable"
    columns = st.columns(4)
    columns[0].metric("CPU", show_percent(snapshot.cpu_percent))
    columns[1].metric("Memory", show_percent(snapshot.memory_percent))
    columns[2].metric("Disk", show_percent(snapshot.disk_percent))
    uptime = f"{snapshot.uptime_seconds / 3600:.1f} h" if snapshot.uptime_seconds is not None else "Unavailable"
    columns[3].metric("Uptime", uptime)
    columns = st.columns(3)
    for col, status in zip(columns, ("open", "investigating", "resolved")):
        col.metric(status.replace("_", " ").title(), sum(a.status == status for a in alerts))
    if alerts:
        counts = {}
        for alert in alerts:
            counts[alert.severity] = counts.get(alert.severity, 0) + 1
        st.plotly_chart(px.bar(x=list(counts), y=list(counts.values()), labels={"x": "Severity", "y": "Alerts"},
                               title="Alert severity distribution"), use_container_width=True)
        st.subheader("Recent detections")
        st.dataframe([{"Time": a.created_at, "Severity": a.severity, "Rule": a.rule_id,
                       "Reason": a.reason} for a in alerts[:10]], use_container_width=True)
    else:
        st.info("No alerts are stored yet. Refresh system monitoring or import a sample log to begin.")
    return snapshot


def _render_monitoring(st, storage: Storage):
    st.subheader("Local system metrics")
    cpu = st.number_input("CPU warning threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.cpu_percent, key="cpu_warning")
    memory = st.number_input("Memory warning threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.memory_percent, key="memory_warning")
    disk = st.number_input("Disk warning threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.disk_percent, key="disk_warning")
    cpu_critical = st.number_input("CPU critical threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.cpu_critical_percent, key="cpu_critical")
    memory_critical = st.number_input("Memory critical threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.memory_critical_percent, key="memory_critical")
    disk_critical = st.number_input("Disk critical threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.disk_critical_percent, key="disk_critical")
    if st.button("Collect snapshot", type="primary"):
        try:
            thresholds = Thresholds(cpu, memory, disk, cpu_critical, memory_critical, disk_critical)
            snapshot = collect_system_snapshot()
            findings = detect_system_metrics(snapshot, thresholds)
            count = _persist_detections(storage, findings)
            st.success(f"Snapshot collected. {count} new alert(s) persisted.")
            st.json(snapshot.to_dict())
        except ValueError as exc:
            st.error(str(exc))
    try:
        st.dataframe([review.process.__dict__ | {"review_reasons": review.review_reasons}
                      for review in analyze_processes(collect_processes(30))], use_container_width=True)
    except Exception as exc:
        st.warning(f"Process metrics unavailable: {exc}")


def _render_processes(st, storage: Storage):
    st.caption("Path indicators request analyst review; names and locations do not prove malicious activity.")
    try:
        paths = tuple(value.strip() for value in st.session_state.get("process_review_paths", ",".join(DEFAULT_CONFIG.process_indicators.review_paths)).split(",") if value.strip())
        from soc_toolkit.settings import ProcessIndicators
        reviews = analyze_processes(collect_processes(100), ProcessIndicators(paths))
        detections = detect_process_reviews(reviews)
        new_alerts = _persist_detections(storage, detections)
        if new_alerts:
            st.info(f"Created {new_alerts} process review alert(s).")
        query = st.text_input("Filter process name or review reason")
        rows = [{"PID": item.process.pid, "Name": item.process.name, "Executable": item.process.executable or "Unavailable",
                 "CPU %": item.process.cpu_percent, "Memory %": item.process.memory_percent,
                 "Review": "; ".join(item.review_reasons) or "No configured path indicator"}
                for item in reviews]
        if query:
            rows = [row for row in rows if query.casefold() in json.dumps(row).casefold()]
        st.dataframe(rows, use_container_width=True)
        st.write(f"{sum(review.requires_review for review in reviews)} process(es) have a configured path indicator.")
    except Exception as exc:
        st.error(f"Could not collect process details: {exc}")


def _render_log_ingest(st, storage: Storage):
    st.warning("Imported events are stored locally in the project's SQLite database for correlation and investigation.")
    uploaded = st.file_uploader("Choose a supported log", type=["log", "txt", "csv", "json", "jsonl", "ndjson", "xml"],
                               max_upload_size=10)
    selected_format = st.selectbox("Format", ["auto", "syslog", "json", "jsonl", "csv", "xml"])
    if uploaded and st.button("Parse and analyze"):
        if uploaded.size > DEFAULT_CONFIG.max_log_bytes:
            st.error(f"The file exceeds {DEFAULT_CONFIG.max_log_bytes:,} bytes.")
            return
        suffix = Path(uploaded.name).suffix or ".log"
        try:
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp:
                    temp_path = Path(temp.name)
                    temp.write(uploaded.getbuffer())
                result = ingest_log_file(temp_path, selected_format, DEFAULT_CONFIG.max_log_bytes)
            finally:
                if temp_path:
                    temp_path.unlink(missing_ok=True)
            events = tuple(replace(event, source=uploaded.name,
                event_id=stable_event_id(event.timestamp, uploaded.name, event.event_type, event.host,
                                         event.username, event.source_ip, event.message),
                evidence_ref=f"{uploaded.name}:{event.evidence_ref.rsplit(':', 1)[-1]}") for event in result.events)
            inserted = storage.save_events(list(events))
            detections = detect_events(list(events),
                repeated_threshold=int(st.session_state.get("repeated_login_threshold", DEFAULT_CONFIG.repeated_failed_login_threshold)),
                correlation_window_seconds=int(st.session_state.get("configured_correlation_window", DEFAULT_CONFIG.correlation_window_seconds)))
            new_alerts = _persist_detections(storage, detections)
            st.success(f"Parsed {len(result.events)} event(s); stored {inserted} new event(s); created {new_alerts} new alert(s).")
            if result.errors:
                st.warning(f"{len(result.errors)} record(s) could not be parsed.")
                st.dataframe([issue.__dict__ for issue in result.errors], use_container_width=True)
            if result.events:
                st.dataframe([{"timestamp": event.timestamp, "source": event.source,
                    "event_type": event.event_type, "severity": event.severity, "host": event.host,
                    "username": event.username, "source_ip": event.source_ip,
                    "message": Storage._safe_text(event.message), "evidence_ref": event.evidence_ref}
                    for event in events[:200]], use_container_width=True)
            if detections:
                st.dataframe([{"rule_id": d.rule_id, "rule_name": d.rule_name, "severity": d.severity,
                    "reason": Storage._safe_text(d.reason), "evidence_summary": Storage._safe_text(d.evidence_summary),
                    "event_refs": d.event_refs} for d in detections], use_container_width=True)
        except (OSError, ValueError) as exc:
            st.error(f"Log ingestion failed: {exc}")


def _render_alerts(st, storage: Storage):
    left, right = st.columns(2)
    severity = left.selectbox("Severity", ["All", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    status = right.selectbox("Status", ["All", "open", "investigating", "resolved", "false_positive"])
    alerts = storage.list_alerts(None if severity == "All" else severity,
                                 None if status == "All" else status)
    if not alerts:
        st.info("No alerts match these filters.")
        return
    for alert in alerts:
        with st.expander(f"{alert.severity} | {alert.rule_id or alert.source} | {alert.created_at}"):
            st.text(alert.message)
            st.text(f"Reason: {alert.reason}")
            st.write(f"**Status:** {alert.status}")
            st.write(f"**Evidence references:** {', '.join(alert.evidence_refs) or 'None'}")
            if alert.recommended_steps:
                st.write("**Investigation steps**")
                for step in alert.recommended_steps:
                    st.write(f"- {step}")
            choice = st.selectbox("Update status", ["open", "investigating", "resolved", "false_positive"],
                                  index=["open", "investigating", "resolved", "false_positive"].index(alert.status),
                                  key=f"status-{alert.alert_id}")
            if choice != alert.status and st.button("Save status", key=f"save-{alert.alert_id}"):
                storage.update_alert_status(alert.alert_id, choice)
                st.rerun()


def _render_correlation(st, storage: Storage):
    default_window = int(st.session_state.get("configured_correlation_window", DEFAULT_CONFIG.correlation_window_seconds))
    seconds = st.number_input("Correlation window (seconds)", 60, 86400,
                              default_window, step=60, key="correlation_window_active")
    events = storage.list_events(2000)
    groups = correlate_events(events, int(seconds))
    if groups:
        st.dataframe([group.__dict__ for group in groups], use_container_width=True)
    else:
        st.info("No groups found. Events must share host, username, or source IP; time proximity alone is not enough.")


def _render_incidents(st, storage: Storage):
    alerts = storage.list_alerts(limit=1000)
    events = storage.list_events(2000)
    alert_map = {item.alert_id: item for item in alerts}
    event_map = {item.event_id: item for item in events}
    with st.form("create-incident"):
        title = st.text_input("Incident title")
        selected_alert_ids = st.multiselect("Link alerts", list(alert_map), format_func=lambda key: f"{alert_map[key].severity} {alert_map[key].rule_id}: {alert_map[key].message[:80]}")
        selected_event_ids = st.multiselect("Link events", list(event_map), format_func=lambda key: f"{event_map[key].timestamp} {event_map[key].event_type}: {event_map[key].message[:80]}")
        facts = st.text_area("Observed facts / findings")
        recommendations = st.text_area("Recommended actions")
        create = st.form_submit_button("Create incident")
    if create:
        try:
            incident = create_incident(title, [alert_map[key] for key in selected_alert_ids],
                                       [event_map[key] for key in selected_event_ids], facts, recommendations)
            storage.save_incident(incident)
            st.success(f"Created incident {incident.incident_id}")
        except ValueError as exc:
            st.error(str(exc))
    incidents = storage.list_incidents()
    for incident in incidents:
        with st.expander(f"{incident.status.upper()} | {incident.title} | {incident.incident_id[:8]}"):
            status = st.selectbox("Incident status", ["open", "investigating", "resolved", "false_positive"],
                                  index=["open", "investigating", "resolved", "false_positive"].index(incident.status),
                                  key=f"incident-status-{incident.incident_id}")
            if status != incident.status and st.button("Update incident", key=f"incident-update-{incident.incident_id}"):
                storage.update_incident_status(incident.incident_id, status)
                st.rerun()
            st.write(f"Linked alerts: {len(incident.alert_ids)}; linked events: {len(incident.event_refs)}")
            with st.form(f"note-{incident.incident_id}"):
                category = st.selectbox("Note type", ["observed_fact", "detection_conclusion", "analyst_hypothesis", "recommended_action"], key=f"note-kind-{incident.incident_id}")
                author = st.text_input("Analyst", key=f"note-author-{incident.incident_id}")
                content = st.text_area("Investigation note", key=f"note-content-{incident.incident_id}")
                submit_note = st.form_submit_button("Add note")
            if submit_note:
                try:
                    add_investigation_note(storage, incident.incident_id, author, category, content)
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
            st.dataframe(incident_timeline(storage, incident), use_container_width=True)


def _render_reports(st, storage: Storage):
    incidents = storage.list_incidents()
    if not incidents:
        st.info("Create an incident before generating a case report.")
        return
    incident = st.selectbox("Incident", incidents, format_func=lambda item: f"{item.title} ({item.incident_id[:8]})")
    redact_users = st.checkbox("Redact usernames", value=DEFAULT_CONFIG.report_redact_usernames)
    redact_ips = st.checkbox("Redact IP addresses", value=DEFAULT_CONFIG.report_redact_ips)
    if st.button("Build report"):
        alert_list = [alert for alert in storage.list_alerts(limit=1000) if alert.alert_id in incident.alert_ids]
        event_list = [event for event in storage.list_events(5000) if event.event_id in incident.event_refs]
        notes = storage.list_notes(incident.incident_id)
        markdown, payload = build_case_report(incident, alert_list, event_list, notes, redact_users, redact_ips)
        st.code(markdown, language="markdown")
        st.download_button("Download Markdown", markdown, file_name=f"incident-{incident.incident_id[:8]}.md")
        st.download_button("Download JSON", json.dumps(payload, indent=2, ensure_ascii=False),
                           file_name=f"incident-{incident.incident_id[:8]}.json", mime="application/json")


def main() -> None:
    try:
        import streamlit as st
        import plotly.express as px
    except ImportError as exc:
        raise RuntimeError("Install dashboard dependencies with: python -m pip install -r requirements.txt") from exc
    st.set_page_config(page_title="AI-Powered SOC Toolkit", layout="wide")
    logger = configure_app_logging()
    st.title("AI-Powered SOC Toolkit")
    st.caption("Defensive local monitoring and triage. Detections are review leads, not proof of compromise.")
    @st.cache_resource
    def get_storage(path: str) -> Storage:
        return Storage(path)
    storage = get_storage(str(DEFAULT_CONFIG.database_path))
    section = st.sidebar.radio("Workspace", SECTIONS)
    try:
        if section == "Overview":
            _render_metrics(st, px, storage.list_alerts(limit=500))
        elif section == "System Monitoring":
            _render_monitoring(st, storage)
        elif section == "Process Analysis":
            _render_processes(st, storage)
        elif section == "Log Analysis":
            _render_log_ingest(st, storage)
        elif section == "Alerts":
            _render_alerts(st, storage)
        elif section == "Correlation":
            _render_correlation(st, storage)
        elif section == "Incidents":
            _render_incidents(st, storage)
        elif section == "Reports":
            _render_reports(st, storage)
        elif section == "Settings":
            st.subheader("Application settings")
            st.number_input("CPU warning threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.cpu_percent, key="cpu_warning")
            st.number_input("Memory warning threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.memory_percent, key="memory_warning")
            st.number_input("Disk warning threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.disk_percent, key="disk_warning")
            st.number_input("CPU critical threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.cpu_critical_percent, key="cpu_critical")
            st.number_input("Memory critical threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.memory_critical_percent, key="memory_critical")
            st.number_input("Disk critical threshold (%)", 1.0, 100.0, DEFAULT_CONFIG.thresholds.disk_critical_percent, key="disk_critical")
            st.text_input("Process path indicators (comma-separated)",
                          value=",".join(DEFAULT_CONFIG.process_indicators.review_paths), key="process_review_paths")
            st.number_input("Correlation window (seconds)", 60, 86400,
                             DEFAULT_CONFIG.correlation_window_seconds, step=60, key="configured_correlation_window")
            st.number_input("Repeated failed login threshold", 2, 100,
                             DEFAULT_CONFIG.repeated_failed_login_threshold, key="repeated_login_threshold")
            st.json({"database": str(DEFAULT_CONFIG.database_path),
                     "maximum_log_bytes": DEFAULT_CONFIG.max_log_bytes,
                     "alert_deduplication_seconds": DEFAULT_CONFIG.alert_deduplication_seconds,
                     "correlation_window_seconds": DEFAULT_CONFIG.correlation_window_seconds,
                     "optional_ai": "Disabled by default; local explanations remain available."})
            st.info("These dashboard values apply for this session. Edit soc_toolkit/config.py and soc_toolkit/settings.py to change defaults.")
            st.subheader("Optional AI explanation")
            st.caption("Offline explanations are the default. External requests require both switches below, an HTTPS endpoint, and an API key in an environment variable.")
            enabled = st.checkbox("Enable optional external AI analysis", value=os.getenv("SOC_AI_ENABLED", "false").casefold() == "true")
            consent = st.checkbox("I consent to send the previewed sanitized alert summary", value=False)
            endpoint = st.text_input("OpenAI-compatible HTTPS endpoint", value=os.getenv("SOC_AI_ENDPOINT", ""))
            model = st.text_input("Model", value=os.getenv("SOC_AI_MODEL", ""))
            key_env = st.text_input("API key environment variable name", value="SOC_AI_API_KEY")
            ai_alerts = storage.list_alerts(limit=200)
            if ai_alerts:
                selected = st.selectbox("Alert to explain", ai_alerts,
                    format_func=lambda item: f"{item.severity} {item.rule_id}: {item.message[:80]}")
                evidence_text = st.text_area("Optional selected evidence snippets (one per line)")
                snippets = tuple(line for line in evidence_text.splitlines() if line.strip())[:5]
                safe_alert, safe_evidence = sanitize_ai_payload(selected, snippets)
                st.json({"alert_summary": safe_alert, "selected_evidence": list(safe_evidence)})
                if st.button("Explain selected alert"):
                    provider = None
                    if enabled and endpoint.strip() and model.strip():
                        provider = OpenAICompatibleProvider(endpoint.strip(), key_env.strip(), model.strip(), consent)
                    result = explain_alert(selected, provider, enabled=enabled,
                                           explicit_consent=consent, selected_evidence=snippets)
                    st.code(result.text)
                    if result.is_hypothesis:
                        st.caption("AI commentary is an unverified hypothesis, separate from observed evidence.")
    except Exception as exc:
        logger.exception("Dashboard section failed")
        st.error(f"This section could not complete: {exc}")


if __name__ == "__main__":
    main()
