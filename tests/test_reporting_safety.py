import json
import tempfile
import unittest
from pathlib import Path

from soc_toolkit.investigation import create_incident
from soc_toolkit.log_analysis import LogFinding
from soc_toolkit.models import InvestigationNote, NormalizedEvent, SecurityAlert
from soc_toolkit.reports import (
    build_case_report,
    generate_incident_report,
    generate_json_incident_report,
)


class ReportingSafetyTests(unittest.TestCase):
    def setUp(self):
        self.timestamp = "2026-05-01T00:00:00+00:00"
        self.sensitive = (
            "Failed password for demo_user from 198.51.100.8 "
            "SOC_AI_API_KEY=DEMO_SECRET bearer DEMO_BEARER"
        )
        self.finding = LogFinding(
            r"C:\Users\demo_user\auth.log", 7, "HIGH", self.sensitive,
            "AUTH_FAILURE", "Validate the synthetic event.", self.timestamp,
        )
        self.alert = SecurityAlert.create(
            "HIGH", "synthetic", self.sensitive, self.sensitive, "AUTH_FAILURE",
            (self.sensitive,), (self.sensitive,),
        )
        self.event = NormalizedEvent(
            self.timestamp, "synthetic", "auth", "HIGH", self.sensitive,
            username="demo_user", source_ip="198.51.100.8", evidence_ref=self.sensitive,
        )
        self.incident = create_incident(
            "Synthetic demo_user incident", [self.alert], [self.event],
            self.sensitive, self.sensitive,
        )
        self.note = InvestigationNote(
            "note-1", self.incident.incident_id, self.timestamp, "demo_user",
            "observed_fact", self.sensitive,
        )

    def assert_sensitive_values_redacted(self, content):
        for value in ("DEMO_SECRET", "DEMO_BEARER", "demo_user", "198.51.100.8"):
            self.assertNotIn(value, content)

    def test_legacy_markdown_and_json_writers_redact_sensitive_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            markdown_path = generate_incident_report(
                [self.finding], [self.alert], root / "legacy.md", redact_ips=True
            )
            json_path = generate_json_incident_report(
                [self.finding], [self.alert], root / "legacy.json", redact_ips=True
            )
            markdown = markdown_path.read_text(encoding="utf-8")
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assert_sensitive_values_redacted(markdown)
        self.assert_sensitive_values_redacted(json.dumps(payload))
        self.assertIn("AUTH", markdown)
        finding_lines = [line for line in markdown.splitlines() if r"auth\.log" in line and "rule" in line]
        self.assertEqual(1, len(finding_lines))
        self.assertTrue(finding_lines[0].startswith("- **HIGH** `"))
        self.assertIn(" | Failed password for", finding_lines[0])

    def test_case_report_redacts_raw_objects_and_escapes_untrusted_markdown(self):
        note = InvestigationNote(
            self.note.note_id, self.note.incident_id, self.note.created_at,
            self.note.author, self.note.category, self.sensitive + " [click](https://example.test)",
        )
        markdown, payload = build_case_report(
            self.incident, [self.alert], [self.event], [note],
            redact_usernames=True, redact_ips=True,
        )
        self.assert_sensitive_values_redacted(markdown)
        self.assert_sensitive_values_redacted(json.dumps(payload))
        self.assertIn("AUTH", markdown)
        self.assertNotIn("[click](https://example.test)", markdown)
        self.assertIn(r"\[click\]", markdown)
        self.assertIn("rule", json.dumps(payload["alerts"][0]))


if __name__ == "__main__":
    unittest.main()
