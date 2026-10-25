import json
import tempfile
import unittest
from pathlib import Path

from soc_toolkit.alerts import append_alerts, evaluate_snapshot, read_recent_alerts
from soc_toolkit.log_analysis import analyze_log
from soc_toolkit.models import SecurityAlert, SystemSnapshot
from soc_toolkit.reports import generate_incident_report


class ToolkitTests(unittest.TestCase):
    def test_threshold_alerts_include_cpu_memory_and_disk(self):
        snapshot = SystemSnapshot("now", "host", "Windows", 95, 90, 91)
        self.assertEqual({"CPU", "Memory", "Disk"}, {
            alert.message.split(" usage")[0] for alert in evaluate_snapshot(snapshot)
        })

    def test_alerts_round_trip_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.jsonl"
            expected = SecurityAlert.create("HIGH", "test", "authentication failure")
            append_alerts([expected], path)
            self.assertEqual([expected], read_recent_alerts(path))
            self.assertEqual("HIGH", json.loads(path.read_text(encoding="utf-8"))['severity'])

    def test_log_analysis_flags_security_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.log"
            path.write_text("normal event\nFailed login for user\nwarning: disk space\n", encoding="utf-8")
            findings = analyze_log(path)
            self.assertEqual([2, 3], [finding.line_number for finding in findings])
            self.assertEqual("HIGH", findings[0].severity)

    def test_report_contains_counts_and_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            finding = analyze_log(self._write_sample(Path(directory) / "event.log"))[0]
            generate_incident_report([finding], [], path)
            report = path.read_text(encoding="utf-8")
            self.assertIn("Log findings: 1", report)
            self.assertIn("failed login", report.lower())

    @staticmethod
    def _write_sample(path):
        path.write_text("failed login", encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
