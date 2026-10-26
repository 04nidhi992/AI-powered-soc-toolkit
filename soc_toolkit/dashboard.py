"""Streamlit dashboard. Streamlit/Plotly are imported only when the app is launched."""

from dataclasses import replace
import html
import json
import os
from pathlib import Path
import tempfile

from soc_toolkit.ai_analysis import OpenAICompatibleProvider, explain_alert, sanitize_ai_payload
from soc_toolkit.config import DEFAULT_CONFIG
from soc_toolkit.correlation import correlate_events
from soc_toolkit.detection import detect_events, detect_process_reviews, detect_system_metrics
from soc_toolkit.investigation import add_investigation_note, create_incident, incident_timeline
from soc_toolkit.ioc_extraction import extract_iocs_from_events
from soc_toolkit.log_analysis import ingest_log_file
from soc_toolkit.logging_config import configure_app_logging
from soc_toolkit.models import SecurityAlert, stable_event_id
from soc_toolkit.monitoring import collect_processes, collect_system_snapshot
from soc_toolkit.process_analysis import analyze_processes
from soc_toolkit.reports import build_case_report
from soc_toolkit.settings import DEFAULT_RULES, Thresholds
from soc_toolkit.storage import Storage
from soc_toolkit.threat_intel import VirusTotalProvider, enrich_indicators


SECTIONS = ("Overview", "System Monitoring", "Process Analysis", "Log Analysis", "Threat Intelligence", "Alerts",
            "Correlation", "Incidents", "Reports", "Settings")

SEVERITY_COLORS = {
    "INFO": "#60A5FA", "LOW": "#34D399", "MEDIUM": "#FBBF24",
    "HIGH": "#FB923C", "CRITICAL": "#F87171",
}


def _apply_dashboard_style(st) -> None:
    st.markdown("""
    <style>
      :root { color-scheme: dark; }
      [data-testid="stAppViewContainer"] { background: #07111F; }
      [data-testid="stHeader"] { background: rgba(7, 17, 31, .94); }
      [data-testid="stSidebar"] { background: #0A1728; border-right: 1px solid #20324A; }
      [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: #A9B9CC; }
      .block-container { max-width: 1560px; padding-top: 1.5rem; padding-bottom: 3rem; }
      h1, h2, h3 { color: #F3F7FC; letter-spacing: -0.025em; }
      p, label, [data-testid="stCaptionContainer"] { color: #A9B9CC; }
      .soc-kicker { color: #60A5FA; font-size: .72rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; margin-bottom: -.45rem; }
      .soc-status { background: #101F33; border: 1px solid #263B56; border-radius: 12px; padding: .9rem 1rem; margin-top: 1rem; color: #DCE7F4; font-size: .82rem; }
      .soc-status small { color: #8FA3BA; display: block; margin-top: .25rem; }
      .soc-status-dot { color: #34D399; padding-right: .4rem; }
      .soc-section { border-bottom: 1px solid #20324A; padding: .2rem 0 .85rem; margin: .2rem 0 1.2rem; }
      .soc-section-label { color: #60A5FA; font-size: .68rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
      .soc-section p { margin: .25rem 0 0; color: #9EB0C5; }
      [data-testid="stMetric"] { background: #101F33; border: 1px solid #203650; border-radius: 12px; padding: 1rem 1.1rem; min-height: 112px; }
      [data-testid="stMetricLabel"] { color: #9EB0C5; }
      [data-testid="stMetricValue"] { color: #F3F7FC; font-weight: 700; }
      [data-testid="stMetricDelta"] { color: #9EB0C5; }
      [data-testid="stDataFrame"] { border: 1px solid #203650; border-radius: 10px; overflow: hidden; }
      [data-testid="stExpander"] { background: #0D1A2B; border: 1px solid #203650; border-radius: 10px; }
      [data-testid="stAlert"] { border-radius: 10px; }
      div.stButton > button, [data-testid="stDownloadButton"] button { border-radius: 8px; font-weight: 600; }
      div.stButton > button[kind="primary"] { background: #2563EB; border-color: #3B82F6; }
      .severity-badge { display: inline-block; border-radius: 999px; padding: .18rem .58rem; font-size: .72rem; font-weight: 750; letter-spacing: .04em; border: 1px solid currentColor; }
      .severity-info { color: #60A5FA; background: #102A43; }
      .severity-low { color: #34D399; background: #123126; }
      .severity-medium { color: #FBBF24; background: #332713; }
      .severity-high { color: #FB923C; background: #351E17; }
      .severity-critical { color: #F87171; background: #35191F; }
      @media (max-width: 720px) {
        .block-container { padding-left: 1rem; padding-right: 1rem; }
        .soc-status { margin-top: .35rem; }
      }
    </style>
    """, unsafe_allow_html=True)


def _section_header(st, title: str, description: str, label: str = "SOC WORKSPACE") -> None:
    st.markdown(
        f'<div class="soc-section"><div class="soc-section-label">{html.escape(label)}</div>'
        f'<h2>{html.escape(title)}</h2><p>{html.escape(description)}</p></div>',
        unsafe_allow_html=True,
    )


def _severity_badge(severity: str) -> str:
    normalized = severity.upper()
    css_class = normalized.casefold() if normalized in SEVERITY_COLORS else "info"
    return (f'<span class="severity-badge severity-{css_class}">'
            f'{html.escape(normalized)}</span>')


def _persist_detections(storage: Storage, detections) -> int:
    count = 0
    for result in detections:
        storage.save_detection(result)
        alert = SecurityAlert(result.timestamp, result.severity, "detection", result.evidence_summary,
                              result.reason, result.rule_id, evidence_refs=result.event_refs,
                              recommended_steps=result.recommended_steps)
        count += int(storage.save_alert(alert))
    return count


def _render_metrics(st, px, storage: Storage):
    snapshot = collect_system_snapshot()
    try:
        process_count = len(collect_processes(100))
    except Exception:
        process_count = None
    show_percent = lambda value: f"{value:.1f}%" if value is not None else "Unavailable"
    active_alerts = storage.count_alerts(status="open") + storage.count_alerts(status="investigating")
    critical_alerts = storage.count_alerts(severity="CRITICAL", status="open") + storage.count_alerts(
        severity="CRITICAL", status="investigating")
    columns = st.columns(3)
    columns[0].metric("Events stored", f"{storage.count_events():,}")
    columns[1].metric("Active alerts", f"{active_alerts:,}")
    columns[2].metric("Active critical alerts", f"{critical_alerts:,}")
    columns = st.columns(2)
    columns[0].metric("Processes inspected", f"{process_count:,}" if process_count is not None else "Unavailable",
                      help="Current local process sample, capped at 100 entries.")
    columns[1].metric("Detection status", "READY" if DEFAULT_RULES else "UNAVAILABLE",
                      delta=f"{len(DEFAULT_RULES)} configured text rules" if DEFAULT_RULES else None)

    columns = st.columns(4)
    columns[0].metric("CPU", show_percent(snapshot.cpu_percent))
    columns[1].metric("Memory", show_percent(snapshot.memory_percent))
    columns[2].metric("Disk", show_percent(snapshot.disk_percent))
    uptime = f"{snapshot.uptime_seconds / 3600:.1f} h" if snapshot.uptime_seconds is not None else "Unavailable"
    columns[3].metric("Uptime", uptime)

    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    counts = {severity: storage.count_alerts(severity=severity) for severity in severity_order}
    chart_counts = {severity: count for severity, count in counts.items() if count}
    if chart_counts:
        figure = px.bar(x=list(chart_counts), y=list(chart_counts.values()), color=list(chart_counts),
                        color_discrete_map=SEVERITY_COLORS,
                        category_orders={"x": severity_order}, labels={"x": "Severity", "y": "Alerts"},
                        title="Stored alerts by severity")
        figure.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                             plot_bgcolor="rgba(0,0,0,0)", font_color="#DCE7F4",
                             margin=dict(l=12, r=12, t=50, b=12), showlegend=False)
        st.plotly_chart(figure, use_container_width=True)
        st.subheader("Recent alerts")
        alerts = storage.list_alerts(limit=10)
        st.dataframe([{"Time": a.created_at, "Severity": a.severity, "Rule": a.rule_id or a.source,
                       "Status": a.status, "Reason": Storage._safe_text(a.reason)} for a in alerts],
                     use_container_width=True, hide_index=True)
    else:
        st.info("No alerts are stored yet. Collect a system snapshot or import a synthetic log to begin.")
    recent_events = storage.list_events(limit=10)
    st.subheader("Recent security events")
    if recent_events:
        st.dataframe([{"Time": item.timestamp, "Source": item.source, "Type": item.event_type,
                       "Severity": item.severity, "Host": item.host or "Unavailable",
                       "Message": Storage._safe_text(item.message)} for item in recent_events],
                     use_container_width=True, hide_index=True)
    else:
        st.caption("No events have been imported yet.")
    return snapshot


def _render_monitoring(st, storage: Storage):
    _section_header(st, "System monitoring", "Live host telemetry and configurable resource thresholds.", "TELEMETRY")
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
        process_reviews = analyze_processes(collect_processes(30))
        if process_reviews:
            st.subheader("Process sample")
            st.dataframe([review.process.__dict__ | {"review_reasons": review.review_reasons}
                          for review in process_reviews], use_container_width=True, hide_index=True)
        else:
            st.info("No process records were available for this sample.")
    except Exception as exc:
        st.warning(f"Process metrics unavailable: {exc}")


def _render_processes(st, storage: Storage):
    _section_header(st, "Process analysis", "Review the local process sample using configured path indicators.", "HOST REVIEW")
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
        if rows:
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.info("No processes match this filter.")
        st.write(f"{sum(review.requires_review for review in reviews)} process(es) have a configured path indicator.")
    except Exception as exc:
        st.error(f"Could not collect process details: {exc}")


def _render_log_ingest(st, storage: Storage):
    _section_header(st, "Log analysis", "Import supported exported logs and review normalized security events.", "INGESTION")
    st.warning("Imported events are stored locally in the project's SQLite database for correlation and investigation.")
    uploaded = st.file_uploader("Choose a supported log", type=["log", "txt", "csv", "json", "jsonl", "ndjson", "xml", "evtx"],
                               max_upload_size=10)
    selected_format = st.selectbox("Format", ["auto", "syslog", "json", "jsonl", "csv", "xml", "evtx"])
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
                indicators = extract_iocs_from_events(list(events))
                st.subheader("Extracted indicators")
                st.caption("Indicators are extracted values for analyst review. They are not threat verdicts.")
                if indicators:
                    st.dataframe([{"type": item.indicator_type, "value": item.value,
                        "classification": item.classification, "scope": item.scope,
                        "evidence_refs": item.evidence_refs} for item in indicators], use_container_width=True)
                else:
                    st.info("No supported indicators were extracted from these events.")
            if detections:
                st.dataframe([{"rule_id": d.rule_id, "rule_name": d.rule_name, "severity": d.severity,
                    "reason": Storage._safe_text(d.reason), "evidence_summary": Storage._safe_text(d.evidence_summary),
                    "event_refs": d.event_refs} for d in detections], use_container_width=True)
        except (OSError, ValueError) as exc:
            st.error(f"Log ingestion failed: {exc}")


def _render_threat_intel(st, storage: Storage):
    _section_header(st, "Threat intelligence", "Review local indicators and optionally query an external provider.", "ENRICHMENT")
    st.caption("Offline results only describe locally extracted values. No match or missing intelligence is not evidence that an indicator is benign.")
    indicators = extract_iocs_from_events(storage.list_events(5000))
    if not indicators:
        st.info("Import logs with supported indicators before enrichment.")
        return
    st.subheader("Local extraction")
    st.dataframe([{"type": item.indicator_type, "value": item.value,
        "classification": item.classification, "scope": item.scope,
        "evidence_refs": item.evidence_refs} for item in indicators], use_container_width=True)
    offline = enrich_indicators(indicators)
    st.dataframe([{"indicator": item.indicator_value, "source": item.source,
        "lookup_time": item.lookup_time, "status": item.status, "confidence": "Not provided",
        "summary": item.summary} for item in offline], use_container_width=True)

    mode = st.radio("Enrichment mode", ["Offline (local only)", "VirusTotal (external lookup)"], horizontal=True)
    if mode == "Offline (local only)":
        return
    st.warning("A lookup discloses the selected indicator to VirusTotal, which may add queried IOCs to its shared dataset. No files or event text are sent. URLs with paths, credentials, queries, or fragments, plus private/internal indicators, are skipped.")
    selected = st.selectbox("Indicator to look up", indicators,
        format_func=lambda item: f"{item.indicator_type}: {item.value}")
    consent = st.checkbox("I confirm this indicator is not sensitive, confidential, or personally identifying, and consent to its disclosure to VirusTotal")
    if st.button("Look up selected indicator", disabled=not consent):
        provider = st.session_state.get("_soc_virustotal_provider")
        if provider is None:
            provider = VirusTotalProvider(timeout_seconds=DEFAULT_CONFIG.threat_intel_timeout_seconds,
                minimum_interval_seconds=DEFAULT_CONFIG.threat_intel_min_interval_seconds)
            st.session_state["_soc_virustotal_provider"] = provider
        st.session_state["_soc_threat_intel_result"] = enrich_indicators(
            (selected,), provider, external_enabled=True, explicit_consent=consent)[0]
    result = st.session_state.get("_soc_threat_intel_result")
    if result:
        st.subheader("Latest lookup")
        st.write(f"**Source:** {result.source}  ·  **Lookup time:** {result.lookup_time}  ·  **Status:** {result.status}")
        st.write(f"**Confidence:** {result.confidence if result.confidence is not None else 'Not provided'}")
        st.write(result.summary)
        if result.details:
            st.json(result.details)
        st.caption(f"Evidence references: {', '.join(result.evidence_refs) or 'None'}")


def _render_alerts(st, storage: Storage):
    _section_header(st, "Security alerts", "Triage explainable detections and record alert status changes.", "TRIAGE")
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
            st.markdown(_severity_badge(alert.severity), unsafe_allow_html=True)
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
    _section_header(st, "Event correlation", "Groups require shared identity or network evidence inside the selected window.", "INVESTIGATION")
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
    _section_header(st, "Incident investigations", "Link evidence, document observations, and track case status.", "CASE MANAGEMENT")
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
    _section_header(st, "Incident reports", "Build portable case reports with configurable username and IP redaction.", "REPORTING")
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
    _apply_dashboard_style(st)
    logger = configure_app_logging()
    @st.cache_resource
    def get_storage(path: str) -> Storage:
        return Storage(path)
    storage = get_storage(str(DEFAULT_CONFIG.database_path))
    st.sidebar.markdown(
        '<div class="soc-kicker">🛡 SOC TOOLKIT</div>'
        '<p style="margin-top:.65rem;font-weight:700;color:#EAF2FC">ANALYST WORKSPACE</p>',
        unsafe_allow_html=True,
    )
    header, status = st.columns([4, 1])
    with header:
        st.markdown('<div class="soc-kicker">SECURITY OPERATIONS CENTER</div>', unsafe_allow_html=True)
        st.title("AI-Powered SOC Toolkit")
        st.caption("Local defensive monitoring and triage · Detection matches are review leads, not proof of compromise.")
    with status:
        st.markdown(
            '<div class="soc-status"><span class="soc-status-dot">●</span>LOCAL WORKSPACE'
            '<small>Application storage ready</small></div>',
            unsafe_allow_html=True,
        )
    icons = {"Overview": "▦", "System Monitoring": "◉", "Process Analysis": "⌘",
             "Log Analysis": "≋", "Threat Intelligence": "◎", "Alerts": "⚑", "Correlation": "⌁",
             "Incidents": "▣", "Reports": "▤", "Settings": "⚙"}
    section = st.sidebar.radio("Workspace", SECTIONS,
                               format_func=lambda value: f"{icons.get(value, '•')}  {value}")
    try:
        if section == "Overview":
            _section_header(st, "Security overview", "Current local telemetry, stored events, and alert posture.", "SOC OVERVIEW")
            _render_metrics(st, px, storage)
        elif section == "System Monitoring":
            _render_monitoring(st, storage)
        elif section == "Process Analysis":
            _render_processes(st, storage)
        elif section == "Log Analysis":
            _render_log_ingest(st, storage)
        elif section == "Threat Intelligence":
            _render_threat_intel(st, storage)
        elif section == "Alerts":
            _render_alerts(st, storage)
        elif section == "Correlation":
            _render_correlation(st, storage)
        elif section == "Incidents":
            _render_incidents(st, storage)
        elif section == "Reports":
            _render_reports(st, storage)
        elif section == "Settings":
            _section_header(st, "Application settings", "Session thresholds, detection behavior, and optional integrations.", "CONFIGURATION")
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
