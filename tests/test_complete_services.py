import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from soc_toolkit.ai_analysis import explain_alert
from soc_toolkit import dashboard
from soc_toolkit.config import AppConfig, DEFAULT_CONFIG
from soc_toolkit.correlation import correlate_events
from soc_toolkit.detection import detect_events
from soc_toolkit.investigation import add_investigation_note, create_incident, incident_timeline
from soc_toolkit.log_analysis import ingest_log_file
from soc_toolkit.models import DetectionResult, NormalizedEvent, ProcessRecord, ReportMetadata, SecurityAlert
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

    def test_synthetic_auth_demo_triggers_expected_persisted_alerts_only_for_auth_events(self):
        parsed = ingest_log_file(PROJECT / "sample_data" / "synthetic_auth_demo.log")
        self.assertEqual(8, len(parsed.events))
        self.assertEqual((), parsed.errors)
        normal_events = [event for event in parsed.events if event.event_type == "syslog"]
        failed_events = [event for event in parsed.events if event.event_type == "failed_login"]
        successful_events = [event for event in parsed.events if event.event_type == "successful_login"]
        self.assertEqual(2, len(normal_events))
        self.assertEqual(5, len(failed_events))
        self.assertEqual(1, len(successful_events))
        self.assertEqual({"198.51.100.44"}, {event.source_ip for event in failed_events + successful_events})
        self.assertEqual({"synth-soc-lab"}, {event.host for event in parsed.events})
        self.assertEqual({"demo_alice", "demo_bob", "demo_carol", "demo_dave", "demo_eve"},
                         {event.username for event in failed_events})
        self.assertEqual({"demo_alice"}, {event.username for event in successful_events})

        detections = detect_events(
            list(parsed.events),
            repeated_threshold=DEFAULT_CONFIG.repeated_failed_login_threshold,
            correlation_window_seconds=DEFAULT_CONFIG.correlation_window_seconds,
        )
        repeated = [item for item in detections if item.rule_id == "REPEATED_FAILED_LOGINS"]
        self.assertEqual(1, len(repeated))
        self.assertEqual("HIGH", repeated[0].severity)
        self.assertIn("5 failed-login events shared validated source IP 198.51.100.44", repeated[0].reason)
        self.assertEqual(5, len(repeated[0].event_refs))
        self.assertTrue({event.event_id for event in normal_events}.isdisjoint(repeated[0].event_refs))
        self.assertNotIn("REPEATED_FAILED_LOGINS", {
            item.rule_id for item in detect_events(normal_events, repeated_threshold=5)
        })
        self.assertEqual(5, sum(item.rule_id == "FAILED_THEN_SUCCESS" for item in detections))

        with Storage(":memory:") as store:
            self.assertEqual(8, store.save_events(list(parsed.events)))
            self.assertEqual(6, dashboard._persist_detections(store, detections))
            alerts = store.list_alerts(limit=20)
            repeated_alerts = [item for item in alerts if item.rule_id == "REPEATED_FAILED_LOGINS"]
            sequence_alerts = [item for item in alerts if item.rule_id == "FAILED_THEN_SUCCESS"]
            self.assertEqual(1, len(repeated_alerts))
            self.assertEqual(5, len(sequence_alerts))
            self.assertEqual("HIGH", repeated_alerts[0].severity)
            self.assertEqual({event.event_id for event in failed_events}, set(repeated_alerts[0].evidence_refs))
            success_id = successful_events[0].event_id
            self.assertTrue(all(success_id in alert.evidence_refs for alert in sequence_alerts))
            self.assertTrue(all(len(alert.evidence_refs) == 2 for alert in sequence_alerts))

    def test_repeated_failures_group_valid_shared_ip_across_accounts_and_hosts(self):
        events = [
            NormalizedEvent("2026-05-01T00:00:00+00:00", "synthetic", "failed_login", "HIGH", "failed",
                            host="host-a", username="alice", source_ip="192.0.2.10"),
            NormalizedEvent("2026-05-01T00:00:10+00:00", "synthetic", "failed_login", "HIGH", "failed",
                            host="host-b", username="bob", source_ip="192.0.2.10"),
            NormalizedEvent("2026-05-01T00:00:20+00:00", "synthetic", "failed_login", "HIGH", "failed",
                            host="host-c", username="carol", source_ip="192.0.2.10"),
        ]
        detections = detect_events(events, repeated_threshold=3)
        repeated = [item for item in detections if item.rule_id == "REPEATED_FAILED_LOGINS"]
        self.assertEqual(1, len(repeated))
        self.assertIn("validated source IP 192.0.2.10", repeated[0].reason)
        self.assertEqual(3, len(repeated[0].event_refs))

    def test_repeated_failures_without_ip_require_matching_host_and_username(self):
        same_identity = [
            NormalizedEvent("2026-05-01T00:00:00+00:00", "synthetic", "failed_login", "HIGH", "failed",
                            host="host-a", username="alice"),
            NormalizedEvent("2026-05-01T00:00:10+00:00", "synthetic", "failed_login", "HIGH", "failed",
                            host="host-a", username="alice"),
        ]
        different_users = [
            same_identity[0],
            NormalizedEvent("2026-05-01T00:00:10+00:00", "synthetic", "failed_login", "HIGH", "failed",
                            host="host-a", username="bob"),
        ]
        self.assertIn("REPEATED_FAILED_LOGINS", {item.rule_id for item in detect_events(same_identity, repeated_threshold=2)})
        self.assertNotIn("REPEATED_FAILED_LOGINS", {item.rule_id for item in detect_events(different_users, repeated_threshold=2)})

    def test_repeated_failures_reject_unrelated_ips_and_below_threshold(self):
        events = [
            NormalizedEvent("2026-05-01T00:00:00+00:00", "synthetic", "failed_login", "HIGH", "failed",
                            host="host-a", username="alice", source_ip="192.0.2.10"),
            NormalizedEvent("2026-05-01T00:00:10+00:00", "synthetic", "failed_login", "HIGH", "failed",
                            host="host-b", username="alice", source_ip="192.0.2.11"),
        ]
        self.assertNotIn("REPEATED_FAILED_LOGINS", {item.rule_id for item in detect_events(events, repeated_threshold=2)})
        self.assertNotIn("REPEATED_FAILED_LOGINS", {item.rule_id for item in detect_events(events[:1], repeated_threshold=2)})
        with self.assertRaises(ValueError):
            detect_events(events, repeated_threshold=1)

    def test_invalid_imported_ip_is_discarded_and_not_used_as_shared_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "invalid-ip.json"
            path.write_text(json.dumps([
                {"timestamp": "2026-05-01T00:00:00Z", "event_type": "failed_login",
                 "message": "failed", "host": "host-a", "username": "alice", "source_ip": "not-an-ip"},
                {"timestamp": "2026-05-01T00:00:10Z", "event_type": "failed_login",
                 "message": "failed", "host": "host-a", "username": "bob", "source_ip": "not-an-ip"},
            ]), encoding="utf-8")
            imported = ingest_log_file(path)
        self.assertTrue(all(event.source_ip is None for event in imported.events))
        self.assertNotIn("REPEATED_FAILED_LOGINS", {
            item.rule_id for item in detect_events(list(imported.events), repeated_threshold=2)
        })

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

    def test_correlation_reports_matching_event_types_as_supporting_evidence(self):
        first = NormalizedEvent("2026-05-01T00:00:00+00:00", "a", "auth_failure", "HIGH", "one",
                                host="host-a")
        second = NormalizedEvent("2026-05-01T00:00:10+00:00", "b", "AUTH_FAILURE", "HIGH", "two",
                                 host="host-a")
        group = correlate_events([first, second], 60)[0]
        self.assertEqual(2, group.event_count)
        self.assertIn("event_type", group.shared_fields)
        self.assertEqual(("AUTH_FAILURE", "auth_failure"), group.event_types)
        self.assertIn("required identity evidence", group.explanation)

    def test_correlation_count_threshold_and_unrelated_same_type_events(self):
        at = "2026-05-01T00:00:00+00:00"
        same_host = [
            NormalizedEvent(at, "a", "auth", "INFO", "one", host="host-a"),
            NormalizedEvent("2026-05-01T00:00:10+00:00", "b", "auth", "INFO", "two", host="host-a"),
            NormalizedEvent("2026-05-01T00:00:20+00:00", "c", "process", "INFO", "three", host="host-a"),
        ]
        self.assertEqual([], correlate_events(same_host[:2], 60, minimum_event_count=3))
        group = correlate_events(same_host, 60, minimum_event_count=3)[0]
        self.assertEqual(3, group.event_count)
        self.assertIn("auth", group.event_types)
        unrelated = [
            NormalizedEvent(at, "a", "auth", "INFO", "one"),
            NormalizedEvent("2026-05-01T00:00:01+00:00", "b", "auth", "INFO", "two"),
        ]
        self.assertEqual([], correlate_events(unrelated, 60))
        with self.assertRaises(ValueError):
            correlate_events(same_host, 60, minimum_event_count=1)

    def test_sqlite_persists_and_filters_events_alerts_incidents_and_notes(self):
        with Storage(":memory:") as store:
            event = NormalizedEvent("2026-05-01T00:00:00+00:00", "sample", "auth", "HIGH",
                                    "Failed password for alice from 192.0.2.2 password=hunter2",
                                    host="host", username="alice", source_ip="192.0.2.2", evidence_ref="sample:1")
            self.assertTrue(store.save_event(event))
            self.assertFalse(store.save_event(event))
            self.assertEqual(1, store.count_events())
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
            self.assertEqual(1, store.count_alerts())
            self.assertEqual(1, store.count_alerts(severity="HIGH", status="open"))
            self.assertTrue(store.update_alert_status(alert.alert_id, "investigating"))
            self.assertEqual(1, store.count_alerts(status="investigating"))
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

    def test_detection_result_validation_accepts_valid_records_and_rejects_bad_fields(self):
        valid = DetectionResult("d-1", "RULE", "Rule name", "2026-05-01T00:00:00Z", "HIGH",
                                "Reason", ["sample:1"], "Evidence summary", ["Review evidence"])
        self.assertEqual("2026-05-01T00:00:00+00:00", valid.timestamp)
        self.assertEqual(("sample:1",), valid.event_refs)
        invalid_records = (
            {"detection_id": ""},
            {"timestamp": "not-a-time"},
            {"severity": "UNKNOWN"},
            {"event_refs": [""]},
            {"recommended_steps": [None]},
        )
        values = {"detection_id": "d-1", "rule_id": "RULE", "rule_name": "Rule name",
                  "timestamp": "2026-05-01T00:00:00Z", "severity": "HIGH", "reason": "Reason",
                  "event_refs": ("sample:1",), "evidence_summary": "Evidence summary",
                  "recommended_steps": ("Review evidence",)}
        for updates in invalid_records:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                DetectionResult(**(values | updates))

    def test_process_record_and_report_metadata_validation(self):
        process = ProcessRecord(0, "system", None, 125.0, 50.0, "running")
        self.assertEqual(125.0, process.cpu_percent)
        with self.assertRaises(ValueError):
            ProcessRecord(-1, "bad", None, 0, 0, "running")
        with self.assertRaises(ValueError):
            ProcessRecord(1, "bad", None, float("nan"), 0, "running")
        with self.assertRaises(ValueError):
            ProcessRecord(1, "bad", None, 10 ** 1000, 0, "running")
        with self.assertRaises(ValueError):
            ProcessRecord(1, "bad", None, 0, 101, "running")
        with self.assertRaises(ValueError):
            ProcessRecord(1, "bad", None, 0, 0, "")

        metadata = ReportMetadata("r-1", "Synthetic report", "2026-05-01T00:00:00Z")
        self.assertEqual("2026-05-01T00:00:00+00:00", metadata.generated_at)
        with self.assertRaises(ValueError):
            ReportMetadata("r-2", "Synthetic report", "invalid timestamp")
        with self.assertRaises(ValueError):
            ReportMetadata("r-3", "Synthetic report", "2026-05-01T00:00:00Z", redacted=1)

    def test_critical_system_thresholds_generate_critical_detection(self):
        from soc_toolkit.detection import detect_system_metrics
        from soc_toolkit.models import SystemSnapshot
        snapshot = SystemSnapshot("2026-05-01T00:00:00+00:00", "host", "Windows", 99, 40, 40)
        finding = detect_system_metrics(snapshot)[0]
        self.assertEqual("CRITICAL", finding.severity)
        self.assertTrue(finding.event_refs[0].startswith("snapshot:"))


if __name__ == "__main__":
    unittest.main()
