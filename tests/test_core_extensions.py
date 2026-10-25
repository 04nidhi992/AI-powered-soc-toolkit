import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import psutil

from soc_toolkit.alerts import append_alerts, deduplicate_alerts, evaluate_snapshot, read_recent_alerts
from soc_toolkit.log_analysis import analyze_log, parse_log_lines
from soc_toolkit.models import ProcessRecord, SecurityAlert, SystemSnapshot
from soc_toolkit.monitoring import collect_processes, collect_system_snapshot
from soc_toolkit.process_analysis import analyze_process
from soc_toolkit.reports import generate_json_incident_report
from soc_toolkit.settings import DetectionRule, Thresholds
import re


class CoreExtensionTests(unittest.TestCase):
    def test_thresholds_are_configurable_and_explainable(self):
        snapshot = SystemSnapshot("2026-01-01T00:00:00+00:00", "host", "Windows", 70, 80, 91)
        alerts = evaluate_snapshot(snapshot, Thresholds(65, 75, 95))
        self.assertEqual(["SYSTEM_CPU_THRESHOLD", "SYSTEM_MEMORY_THRESHOLD"], [a.rule_id for a in alerts])
        self.assertTrue(all(a.created_at and a.reason and a.severity == "HIGH" for a in alerts))

    def test_alert_deduplication_uses_rule_and_window(self):
        old = SecurityAlert("2026-01-01T00:00:00+00:00", "HIGH", "system", "high cpu", "reason", "CPU")
        recent = SecurityAlert("2026-01-01T00:02:00+00:00", "HIGH", "system", "high cpu", "reason", "CPU")
        later = SecurityAlert("2026-01-01T00:10:00+00:00", "HIGH", "system", "high cpu", "reason", "CPU")
        self.assertEqual([later], deduplicate_alerts([recent, later], [old], window_seconds=300))

    def test_append_alerts_suppresses_duplicate_in_recent_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.jsonl"
            first = SecurityAlert.create("HIGH", "system", "high CPU", "threshold exceeded", "CPU")
            second = SecurityAlert.create("HIGH", "system", "high CPU", "threshold exceeded", "CPU")
            append_alerts([first], path)
            append_alerts([second], path)
            self.assertEqual(1, len(read_recent_alerts(path)))

    def test_windows_event_viewer_csv_and_malformed_rows(self):
        lines = [
            '"Level","Date and Time","Source","Event ID","Task Category","Message"',
            '"Information","2026-03-01 10:00:00","Microsoft Windows security","4625","Logon","An account failed to log on"',
            '"Warning","bad row',
        ]
        findings = parse_log_lines(lines, log_format="auto")
        self.assertEqual(1, len(findings))
        self.assertEqual("AUTH_FAILURE", findings[0].rule_id)
        self.assertEqual("2026-03-01 10:00:00", findings[0].timestamp)
        self.assertIn("authentication", findings[0].reason)

    def test_linux_syslog_auto_detection_and_malformed_line(self):
        lines = ["Mar  1 10:00:00 workstation sshd[123]: Failed login for invalid user", "not a syslog record"]
        findings = parse_log_lines(lines)
        self.assertEqual(1, len(findings))
        self.assertEqual("HIGH", findings[0].severity)
        self.assertEqual(1, findings[0].line_number)

    def test_custom_detection_rule(self):
        custom = DetectionRule("CUSTOM_TEST", "Test rule", re.compile("needle", re.I), "LOW", "Configured reason")
        findings = parse_log_lines(["plain text needle"], log_format="text", rules=[custom])
        self.assertEqual("CUSTOM_TEST", findings[0].rule_id)
        self.assertEqual("Configured reason", findings[0].reason)

    def test_oversized_logs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.log"
            path.write_text("warning", encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_log(path, max_bytes=2)

    def test_process_path_only_creates_review_indicator(self):
        process = ProcessRecord(1, "normal.exe", "user", 0, 0, "running", r"C:\Users\user\AppData\Local\Temp\normal.exe")
        review = analyze_process(process)
        self.assertTrue(review.requires_review)
        self.assertIn("review", review.review_reasons[0].lower())
        benign = analyze_process(ProcessRecord(2, "known.exe", None, 0, 0, "running", r"C:\Program Files\App\known.exe"))
        self.assertFalse(benign.requires_review)

    @patch("soc_toolkit.monitoring.psutil.disk_usage")
    @patch("soc_toolkit.monitoring.psutil.virtual_memory")
    @patch("soc_toolkit.monitoring.psutil.cpu_percent")
    def test_system_snapshot_uses_mocked_metrics(self, cpu, memory, disk):
        cpu.return_value = 12.5
        memory.return_value = Mock(percent=50.0)
        disk.return_value = Mock(percent=70.0)
        with patch("soc_toolkit.monitoring._disk_path", return_value="C:\\"):
            snapshot = collect_system_snapshot()
        self.assertEqual((12.5, 50.0, 70.0), (snapshot.cpu_percent, snapshot.memory_percent, snapshot.disk_percent))
        disk.assert_called_once_with("C:\\")

    @patch("soc_toolkit.monitoring.psutil.disk_usage", side_effect=psutil.AccessDenied)
    @patch("soc_toolkit.monitoring.psutil.virtual_memory", side_effect=psutil.AccessDenied)
    @patch("soc_toolkit.monitoring.psutil.cpu_percent", side_effect=psutil.AccessDenied)
    def test_unavailable_metrics_are_reported_as_none(self, cpu, memory, disk):
        with patch("soc_toolkit.monitoring.psutil.boot_time", side_effect=psutil.AccessDenied):
            snapshot = collect_system_snapshot()
        self.assertIsNone(snapshot.cpu_percent)
        self.assertIsNone(snapshot.memory_percent)
        self.assertIsNone(snapshot.disk_percent)
        self.assertEqual([], evaluate_snapshot(snapshot))

    @patch("soc_toolkit.monitoring.psutil.process_iter")
    def test_process_collection_handles_access_denied_and_sorts(self, process_iter):
        allowed = Mock()
        allowed.info = {"pid": 1, "name": "a.exe", "username": "u", "cpu_percent": 1,
                        "memory_percent": 2, "status": "running"}
        allowed.exe.return_value = r"C:\Apps\a.exe"
        denied = Mock()
        denied.info = {"pid": 2, "name": "b.exe", "username": None, "cpu_percent": 0,
                       "memory_percent": 90, "status": "running"}
        denied.exe.side_effect = psutil.AccessDenied
        process_iter.return_value = [allowed, denied]
        result = collect_processes(2)
        self.assertEqual([2, 1], [item.pid for item in result])
        self.assertIsNone(result[0].executable)

    def test_json_report_contains_structured_reason_and_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            finding = parse_log_lines(["Failed login"], log_format="text")[0]
            alert = SecurityAlert.create("HIGH", "system", "high CPU", "over configured threshold", "CPU")
            path = generate_json_incident_report([finding], [alert], Path(directory) / "incident.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(1, payload["summary"]["log_findings"])
        self.assertEqual("AUTH_FAILURE", payload["findings"][0]["rule_id"])
        self.assertEqual("over configured threshold", payload["alerts"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
