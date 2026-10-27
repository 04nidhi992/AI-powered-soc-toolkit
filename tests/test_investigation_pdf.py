import tempfile
import unittest
from pathlib import Path

from pypdf import PdfReader

from soc_toolkit.ai_analysis import offline_explanation
from soc_toolkit.detection import detect_events
from soc_toolkit.investigation import (create_incident, record_ai_activity,
    record_analyst_review)
from soc_toolkit.log_analysis import ingest_log_file
from soc_toolkit.models import AIActivityRecord, AnalystReview, NormalizedEvent, SecurityAlert
from soc_toolkit.reports import generate_pdf_case_report
from soc_toolkit.storage import Storage


PROJECT = Path(__file__).resolve().parents[1]


class AnalystAuditTests(unittest.TestCase):
    def test_reviews_are_persisted_append_only_with_identity_only_when_provided(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "audit.sqlite3"
            with Storage(database) as store:
                alert = SecurityAlert.create("HIGH", "detection", "Review event", rule_id="AUTH_FAILURE",
                                             evidence_refs=("event-1",))
                store.save_alert(alert)
                incident = create_incident("Audit case", [alert])
                store.save_incident(incident)
                first = record_analyst_review(store, "alert", alert.alert_id, "needs_review",
                    case_refs=(incident.incident_id,), evidence_refs=alert.evidence_refs)
                self.assertIsNone(first.analyst)
                record_analyst_review(store, "alert", alert.alert_id, "confirmed",
                    analyst="Case Analyst", notes="Validated evidence.", case_refs=(incident.incident_id,),
                    evidence_refs=alert.evidence_refs)
                record_analyst_review(store, "alert", alert.alert_id, "false_positive",
                    analyst="Case Analyst", notes="Benign scheduled test.", case_refs=(incident.incident_id,),
                    evidence_refs=alert.evidence_refs)
                history = store.list_analyst_reviews("alert", alert.alert_id)
                self.assertEqual(["needs_review", "confirmed", "false_positive"], [item.decision for item in history])
                self.assertEqual(3, len(store.list_case_analyst_reviews(incident.incident_id)))
                status_history = store.list_status_history("analyst_review", f"alert:{alert.alert_id}")
                self.assertEqual([None, "needs_review", "confirmed"], [item["old_status"] for item in status_history])
            with Storage(database) as reopened:
                self.assertEqual(3, len(reopened.list_analyst_reviews("alert", alert.alert_id)))

    def test_invalid_review_transitions_are_rejected_without_overwriting_history(self):
        with Storage(":memory:") as store:
            record_analyst_review(store, "finding", "finding-1", "dismissed")
            with self.assertRaises(ValueError):
                record_analyst_review(store, "finding", "finding-1", "confirmed")
            record_analyst_review(store, "finding", "finding-1", "needs_review")
            with self.assertRaises(ValueError):
                record_analyst_review(store, "finding", "finding-1", "needs_review")
            self.assertEqual(["dismissed", "needs_review"],
                             [item.decision for item in store.list_analyst_reviews("finding", "finding-1")])

    def test_ai_activity_is_separate_and_secrets_are_redacted(self):
        raw = "Suggestion: password=hunter2 SOC_AI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz Bearer xoxb-abcdefghijklmnopqrstuvwxyz"
        with Storage(":memory:") as store:
            record_ai_activity(store, "OpenAI-compatible", "mock-model", "suggestion", raw,
                case_refs=("case-1",), evidence_refs=("event-1",), transmitted_fields=("message",))
            persisted = store.list_ai_activity("case-1")[0]
            self.assertEqual("suggestion", persisted.status)
            self.assertEqual(("case-1",), persisted.case_refs)
            self.assertEqual(("event-1",), persisted.evidence_refs)
            self.assertEqual(("message",), persisted.transmitted_fields)
            serialized = repr(persisted)
            for secret in ("hunter2", "sk-proj-abcdefghijklmnopqrstuvwxyz", "xoxb-abcdefghijklmnopqrstuvwxyz"):
                self.assertNotIn(secret, serialized)
            self.assertEqual([], store.list_analyst_reviews("alert", "alert-1"))

    def test_models_reject_invalid_review_and_ai_audit_fields(self):
        with self.assertRaises(ValueError):
            AnalystReview("r", "alert", "a", "unknown", "2026-05-01T00:00:00Z")
        with self.assertRaises(ValueError):
            AIActivityRecord("a", "provider", "model", "2026-05-01T00:00:00Z", "suggestion", " ")


class PDFReportTests(unittest.TestCase):
    def test_pdf_contains_sections_unicode_and_applies_redaction(self):
        events = [NormalizedEvent(f"2026-05-01T00:00:0{index}Z", "fixture.log", "failed_login", "HIGH",
            f"Failed password for demo_alice from 198.51.100.44; marker Résumé — análisis λ {index}",
            host="workstation", username="demo_alice", source_ip="198.51.100.44",
            evidence_ref=f"fixture.log:{index}", event_id=f"event-{index}") for index in range(1, 6)]
        alert = SecurityAlert.create("HIGH", "detection", "Failed login for demo_alice from 198.51.100.44",
            "Repeated failed logins", "REPEATED_FAILED_LOGINS", tuple(item.event_id for item in events))
        incident = create_incident("Résumé — análisis λ", [alert], events,
            "Résumé — análisis λ: five synthetic failed logins.", "Review account and validate source.")
        with Storage(":memory:") as store:
            store.save_incident(incident)
            review = record_analyst_review(store, "alert", alert.alert_id, "confirmed", analyst="demo_alice",
                notes="Confirmed from source evidence.", case_refs=(incident.incident_id,),
                evidence_refs=alert.evidence_refs)
            ai = record_ai_activity(store, "local/rule-explanation", "offline-rule-explanation", "offline",
                "Offline suggestion shown; no provider request was made.", case_refs=(incident.incident_id,),
                evidence_refs=alert.evidence_refs)
        with tempfile.TemporaryDirectory() as folder:
            path = generate_pdf_case_report(incident, [alert], events, Path(folder) / "case.pdf",
                redact_usernames=True, redact_ips=True, analyst_reviews=(review,), ai_activity=(ai,))
            self.assertTrue(path.read_bytes().startswith(b"%PDF-"))
            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
        self.assertEqual("Résumé — análisis λ", reader.metadata.title)
        self.assertIn("Résumé — análisis λ", reader.metadata.subject)
        self.assertTrue(reader.metadata.creation_date)
        for expected in ("Case summary", "Scope", "Observed event timeline", "Extracted IOCs",
                         "Automated detections", "Event correlation evidence", "Potential MITRE ATT&CK",
                         "Analyst review decisions", "AI activity", "Limitations and uncertainty", "T1110", "confirmed"):
            self.assertIn(expected, text)
        self.assertIn("Résumé — análisis λ", text)
        self.assertNotIn("demo_alice", text)
        self.assertNotIn("198.51.100.44", text)

    def test_empty_case_and_long_unicode_report_generate_valid_multipage_pdfs(self):
        empty = create_incident("Empty case", [], [], "", "")
        long_case = create_incident("Long case", [], [], "Résumé — " + ("évidence λ " * 1800), "No action.")
        with tempfile.TemporaryDirectory() as folder:
            empty_path = generate_pdf_case_report(empty, [], [], Path(folder) / "empty.pdf")
            long_path = generate_pdf_case_report(long_case, [], [], Path(folder) / "long.pdf")
            empty_reader, long_reader = PdfReader(str(empty_path)), PdfReader(str(long_path))
            empty_text = "\n".join(page.extract_text() or "" for page in empty_reader.pages)
            long_text = "\n".join(page.extract_text() or "" for page in long_reader.pages)
        self.assertIn("Empty case", empty_text)
        self.assertIn("No events are linked", empty_text)
        self.assertGreater(len(long_reader.pages), 1)
        self.assertIn("Résumé", long_text)

    def test_pdf_generation_errors_are_reported_safely(self):
        case = create_incident("Error case", [], [])
        with tempfile.TemporaryDirectory() as folder:
            not_a_directory = Path(folder) / "file"
            not_a_directory.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "PDF report generation failed"):
                generate_pdf_case_report(case, [], [], not_a_directory / "report.pdf")

    def test_end_to_end_import_review_and_pdf_report_without_external_ai(self):
        parsed = ingest_log_file(PROJECT / "sample_data" / "linux_auth.log")
        detections = detect_events(list(parsed.events))
        with tempfile.TemporaryDirectory() as folder, Storage(Path(folder) / "case.sqlite3") as store:
            store.save_events(list(parsed.events))
            for result in detections:
                store.save_alert(SecurityAlert(result.timestamp, result.severity, "detection",
                    result.evidence_summary, result.reason, result.rule_id,
                    evidence_refs=result.event_refs, recommended_steps=result.recommended_steps))
            alerts = store.list_alerts()
            incident = create_incident("Synthetic auth case", alerts, store.list_events(100),
                "Imported synthetic auth evidence.", "Validate surrounding activity.")
            store.save_incident(incident)
            record_analyst_review(store, "alert", alerts[0].alert_id, "needs_review",
                case_refs=(incident.incident_id,), evidence_refs=alerts[0].evidence_refs)
            record_analyst_review(store, "alert", alerts[0].alert_id, "confirmed", analyst="Demo analyst",
                notes="Reviewed synthetic evidence.", case_refs=(incident.incident_id,),
                evidence_refs=alerts[0].evidence_refs)
            offline = offline_explanation(alerts[0])
            record_ai_activity(store, "local/rule-explanation", "offline-rule-explanation", "offline",
                offline.text, case_refs=(incident.incident_id,), evidence_refs=alerts[0].evidence_refs)
            pdf_path = generate_pdf_case_report(incident, alerts, store.list_events(100),
                Path(folder) / "end-to-end.pdf", store.list_notes(incident.incident_id),
                analyst_reviews=store.list_case_analyst_reviews(incident.incident_id),
                ai_activity=store.list_ai_activity(incident.incident_id))
            reader = PdfReader(str(pdf_path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            self.assertTrue(pdf_path.exists())
        self.assertIn("Synthetic auth case", text)
        self.assertIn("REPEATED_FAILED_LOGINS", text)
        self.assertIn("confirmed", text)
        self.assertIn("offline-rule-explanation", text)
        self.assertIn("evidence", text.casefold())


if __name__ == "__main__":
    unittest.main()
