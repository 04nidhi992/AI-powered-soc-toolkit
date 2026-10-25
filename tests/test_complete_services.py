import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from soc_toolkit.ai_analysis import explain_alert
from soc_toolkit import dashboard
from soc_toolkit.config import AppConfig
from soc_toolkit.correlation import correlate_events
from soc_toolkit.detection import detect_events
from soc_toolkit.investigation import add_investigation_note, create_incident, incident_timeline
from soc_toolkit.log_analysis import ingest_log_file
from soc_toolkit.models import NormalizedEvent, SecurityAlert
from soc_toolkit.reports import build_case_report
from soc_toolkit.settings import Thresholds
from soc_toolkit.storage import Storage


PROJECT = Path(__file__).resolve().parents[1]


class CompleteServiceTests(unittest.TestCase):
    def test_dashboard_module_import_is_safe_without_streamlit_runtime(self):
        self.assertTrue(callable(dashboard.main))

    def test_sample_windows_and_linux_logs_trigger_expected_detections(self):
        windows = ingest_log_file(PROJECT / "sample_data" / "windows_security_events.xml")
        linux = ingest_log_file(PROJECT / "sample_data" / "linux_auth.log")
        self.assertEqual(3, len(windows.events))
        self.assertEqual(6, len(linux.events))
        all_events = list(windows.events + linux.events)
        rule_ids = {result.rule_id for result in detect_events(all_events, repeated_threshold=5)}
        self.assertIn("FAILED_THEN_SUCCESS", rule_ids)
        self.assertIn("REPEATED_FAILED_LOGINS", rule_ids)

    def test_synthetic_log_to_incident_report_end_to_end(self):
        parsed = ingest_log_file(PROJECT / "sample_data" / "linux_auth.log")
        self.assertEqual(6, len(parsed.events))
        self.assertEqual((), parsed.errors)
        detections = detect_events(list(parsed.events))
        rule_ids = {item.rule_id for item in detections}
        self.assertEqual({"REPEATED_FAILED_LOGINS", "FAILED_THEN_SUCCESS"}, rule_ids)

        with Storage(":memory:") as store:
            self.assertEqual(6, store.save_events(list(parsed.events)))
            self.assertEqual(0, store.save_events(list(parsed.events)))
            alert_count = dashboard._persist_detections(store, detections)
            self.assertEqual(6, alert_count)
            alerts = store.list_alerts(limit=100)
            self.assertEqual(6, len(alerts))
            groups = correlate_events(store.list_events(), 900)
            self.assertEqual(1, len(groups))
            self.assertTrue({"host", "source_ip", "username"}.issubset(groups[0].shared_fields))

            incident = create_incident(
                "Synthetic authentication investigation", alerts, store.list_events(),
                "Six synthetic authentication events were imported.",
                "Validate the source and surrounding activity.",
            )
            store.save_incident(incident)
            note = add_investigation_note(
                store, incident.incident_id, "Demo analyst", "observed_fact",
                "The fixture shows repeated failures followed by a success.",
            )
            markdown, payload = build_case_report(
                incident, alerts, store.list_events(), [note], redact_usernames=True, redact_ips=True
            )
            self.assertEqual(6, payload["scope"]["linked_events"])
            self.assertEqual(6, payload["scope"]["linked_alerts"])
            self.assertEqual(1, len(payload["investigation_notes"]))
            self.assertIn("FAILED_THEN_SUCCESS", json.dumps(payload["alerts"]))
            self.assertIn("Limitations and uncertainty", markdown)

    def test_json_jsonl_csv_and_xml_ingestion_and_bad_records(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            json_path = root / "events.json"
            json_path.write_text(json.dumps([{"timestamp": "2026-05-01T00:00:00Z", "event_type": "auth",
                                              "severity": "warning", "message": "blocked", "host": "h"}]), encoding="utf-8")
            parsed = ingest_log_file(json_path)
            self.assertEqual("MEDIUM", parsed.events[0].severity)
            self.assertEqual("h", parsed.events[0].host)
            jsonl_path = root / "events.jsonl"
            jsonl_path.write_text('{"timestamp":"bad","message":"invalid"}\nnot json\n', encoding="utf-8")
            invalid = ingest_log_file(jsonl_path)
            self.assertEqual(0, len(invalid.events))
            self.assertEqual(2, len(invalid.errors))
            csv_path = root / "events.csv"
            csv_path.write_text('Date and Time,Level,Source,Event ID,Message\n2026-05-01T00:00:00Z,Warning,Auth,4625,Failed login\n', encoding="utf-8")
            self.assertEqual("4625", ingest_log_file(csv_path).events[0].event_type)

    def test_windows_event_json_and_iso_syslog_normalize_network_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            windows = root / "export.json"
            windows.write_text(json.dumps({"Event": {"System": {"EventID": {"#text": "4625"},
                "Level": {"#text": "3"}, "Computer": "HOST", "TimeCreated": {"@SystemTime": "2026-05-01T00:00:00Z"}},
                "EventData": {"Data": [{"@Name": "TargetUserName", "#text": "alice"},
                                         {"@Name": "IpAddress", "#text": "192.0.2.3"}]}}}), encoding="utf-8")
            event = ingest_log_file(windows).events[0]
            self.assertEqual(("4625", "HOST", "alice", "192.0.2.3"),
                             (event.event_type, event.host, event.username, event.source_ip))
            linux = root / "iso.log"
            linux.write_text("2026-05-01T00:00:00Z host sshd[1]: Failed password for alice from 192.0.2.4", encoding="utf-8")
            event = ingest_log_file(linux).events[0]
            self.assertEqual("failed_login", event.event_type)
            self.assertEqual("alice", event.username)
            self.assertEqual("192.0.2.4", event.source_ip)

    def test_imported_event_ids_are_stable_and_xml_errors_reported(self):
        fixture = PROJECT / "sample_data" / "windows_security_events.xml"
        first = ingest_log_file(fixture)
        second = ingest_log_file(fixture)
        self.assertEqual([event.event_id for event in first.events], [event.event_id for event in second.events])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "broken.xml"
            path.write_text("<Events><Event>", encoding="utf-8")
            result = ingest_log_file(path)
        self.assertTrue(result.errors)

    def test_empty_and_oversized_imports_are_handled_without_crashing(self):
        with tempfile.TemporaryDirectory() as folder:
            empty = Path(folder) / "empty.log"
            empty.write_text("", encoding="utf-8")
            empty_result = ingest_log_file(empty)
            self.assertEqual((), empty_result.events)
            self.assertEqual((), empty_result.errors)

            oversized = Path(folder) / "large.log"
            oversized.write_text("x" * 20, encoding="utf-8")
            oversized_result = ingest_log_file(oversized, max_bytes=10)
            self.assertEqual((), oversized_result.events)
            self.assertIn("limit", oversized_result.errors[0].message)

    def test_correlation_requires_shared_identity_not_time_only(self):
        at = "2026-05-01T00:00:00+00:00"
        first = NormalizedEvent(at, "a", "auth", "INFO", "one", host="host-a")
        second = NormalizedEvent("2026-05-01T00:01:00+00:00", "b", "process", "INFO", "two", host="host-a")
        unrelated = NormalizedEvent("2026-05-01T00:01:00+00:00", "c", "auth", "INFO", "nearby")
        groups = correlate_events([first, second, unrelated], 600)
        self.assertEqual(1, len(groups))
        self.assertIn("host", groups[0].shared_fields)
        self.assertEqual([], correlate_events([first, unrelated], 600))

    def test_correlation_includes_exact_time_boundary_and_excludes_outside(self):
        first = NormalizedEvent("2026-05-01T00:00:00+00:00", "sample", "auth", "INFO", "one", host="host")
        boundary = NormalizedEvent("2026-05-01T00:01:00+00:00", "sample", "auth", "INFO", "two", host="host")
        outside = NormalizedEvent("2026-05-01T00:01:01+00:00", "sample", "auth", "INFO", "three", host="host")
        self.assertEqual(1, len(correlate_events([first, boundary], 60)))
        self.assertEqual([], correlate_events([first, outside], 60))

    def test_sqlite_persists_and_filters_events_alerts_incidents_and_notes(self):
        with Storage(":memory:") as store:
            event = NormalizedEvent("2026-05-01T00:00:00+00:00", "sample", "auth", "HIGH",
                                    "Failed password for alice from 192.0.2.2 password=hunter2",
                                    host="host", username="alice", source_ip="192.0.2.2", evidence_ref="sample:1")
            self.assertTrue(store.save_event(event))
            self.assertFalse(store.save_event(event))
            stored_event = store.list_events()[0]
            self.assertNotIn("alice", stored_event.message)
            self.assertNotIn("192.0.2.2", stored_event.message)
            self.assertNotIn("hunter2", stored_event.message)
            self.assertEqual("alice", stored_event.username)
            self.assertEqual({}, stored_event.raw_fields)
            alert = SecurityAlert.create("HIGH", "detection", "Review event", "rule match", "AUTH",
                                         (event.evidence_ref,), ("Validate source",))
            self.assertTrue(store.save_alert(alert))
            self.assertFalse(store.save_alert(alert))
            self.assertTrue(store.update_alert_status(alert.alert_id, "investigating"))
            stored = store.list_alerts(status="investigating")[0]
            self.assertEqual(alert.alert_id, stored.alert_id)
            incident = create_incident("Test incident", [stored], [event], "Observed event", "Review account")
            store.save_incident(incident)
            note = add_investigation_note(store, incident.incident_id, "analyst", "observed_fact", "Synthetic evidence")
            self.assertEqual(note.note_id, store.list_notes(incident.incident_id)[0].note_id)
            self.assertEqual(4, len(incident_timeline(store, incident)))
            self.assertTrue(store.update_incident_status(incident.incident_id, "resolved"))
            self.assertEqual("resolved", store.list_incidents()[0].status)

    def test_report_redaction_and_uncertainty_sections(self):
        event = NormalizedEvent("2026-05-01T00:00:00+00:00", "sample", "auth", "HIGH",
                                "username=alice from 192.0.2.44", username="alice", source_ip="192.0.2.44")
        alert = SecurityAlert.create("HIGH", "detection", "username=alice from 192.0.2.44",
                                     "Review account", "AUTH", ("user=alice",))
        incident = create_incident("Test", [alert], [event], "Investigate username=alice", "Validate evidence")
        markdown, payload = build_case_report(incident, [alert], [event], redact_usernames=True, redact_ips=True)
        combined = markdown + json.dumps(payload)
        self.assertNotIn("192.0.2.44", combined)
        self.assertNotIn("alice", combined)
        self.assertIn("uncertainty", markdown.lower())
        self.assertIn("limitations", payload)

    def test_ai_is_offline_without_both_flags_and_sanitizes_consented_payload(self):
        alert = SecurityAlert.create("HIGH", "detection", "username=alice email a@example.test 192.0.2.4",
                                     "token=secret", "AUTH")
        provider = Mock()
        provider.explain.return_value = "Review hypothesis"
        explain_alert(alert, provider, enabled=True, explicit_consent=False)
        provider.explain.assert_not_called()
        result = explain_alert(alert, provider, enabled=True, explicit_consent=True,
                               selected_evidence=("password=hunter2 user=bob 198.51.100.1",))
        sent, evidence = provider.explain.call_args.args
        self.assertIn("[REDACTED]", sent["message"])
        self.assertIn("[EMAIL]", sent["message"])
        self.assertIn("[IP]", sent["message"])
        self.assertNotIn("hunter2", evidence[0])
        self.assertTrue(result.is_hypothesis)

    def test_model_and_configuration_validation(self):
        with self.assertRaises(ValueError):
            Thresholds(90, 80, 90, 85, 95, 98)
        with self.assertRaises(ValueError):
            NormalizedEvent("not-a-timestamp", "x", "x", "INFO", "x")
        self.assertEqual(10_000_000, AppConfig().max_log_bytes)

    def test_critical_system_thresholds_generate_critical_detection(self):
        from soc_toolkit.detection import detect_system_metrics
        from soc_toolkit.models import SystemSnapshot
        snapshot = SystemSnapshot("2026-05-01T00:00:00+00:00", "host", "Windows", 99, 40, 40)
        finding = detect_system_metrics(snapshot)[0]
        self.assertEqual("CRITICAL", finding.severity)
        self.assertTrue(finding.event_refs[0].startswith("snapshot:"))


if __name__ == "__main__":
    unittest.main()
