import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from soc_toolkit.ai_analysis import build_investigation_summary, sanitize_ai_payload, sanitize_ai_text
from soc_toolkit.investigation import record_ai_activity
from soc_toolkit.models import Incident, NormalizedEvent, SecurityAlert
from soc_toolkit.storage import Storage


def _event(event_id, evidence_ref, second, *, source="auth.log", message=None):
    return NormalizedEvent(f"2026-07-01T12:00:{second:02d}Z", source, "failed_login", "HIGH",
        message or f"Failed login record {event_id}", host="host-a", username="test-user",
        evidence_ref=evidence_ref, event_id=event_id)


def _alert(refs=("event-1", "event-2"), rule="REPEATED_FAILED_LOGINS"):
    return SecurityAlert("2026-07-01T12:01:00Z", "HIGH", "detection", "Repeated failed login events",
        "Rule threshold met", rule, alert_id="alert-1", evidence_refs=refs,
        recommended_steps=("Review the linked event records.",))


class StructuredInvestigationTests(unittest.TestCase):
    def test_summary_uses_only_case_linked_alert_evidence_and_supported_mapping(self):
        first = _event("event-1", "auth.log:1", 1)
        second = _event("event-2", "auth.log:2", 2)
        unrelated = _event("event-3", "unrelated.log:8", 3, source="unrelated.log")
        alert = _alert()
        incident = Incident("case-1", "Authentication review", "2026-07-01T12:00:00Z",
            alert_ids=(alert.alert_id,), event_refs=(first.event_id, second.event_id),
            recommendations="Compare against the documented change window.")
        group = Mock(event_refs=(first.event_id, second.event_id),
                     explanation="The events share the same host and account.")

        summary = build_investigation_summary(alert, events=(first, second, unrelated), incident=incident,
                                              correlation_groups=(group,))

        self.assertEqual((first.event_id, second.event_id),
                         tuple(item.event_id for item in summary.supporting_evidence))
        self.assertTrue(all("unrelated" not in fact for fact in summary.observed_facts))
        self.assertTrue(any("correlation group" in fact for fact in summary.automated_assessments))
        self.assertEqual(("T1110",), tuple(item.technique_id for item in summary.potential_technique_matches))
        self.assertEqual(("event-1", "event-2"), summary.potential_technique_matches[0].evidence_refs)
        self.assertEqual("potential", summary.technique_assessment.mapping_status)
        self.assertIn("Review the linked event records.", summary.recommended_next_steps)
        self.assertTrue(any("not proof" in item for item in summary.uncertainties))

    def test_unrelated_case_and_unknown_rule_are_explicitly_unmapped(self):
        linked = _event("event-1", "auth.log:1", 1)
        alert = _alert((linked.event_id,), "FAILED_THEN_SUCCESS")
        unrelated_case = Incident("case-other", "Other case", "2026-07-01T12:00:00Z",
            alert_ids=("different-alert",), event_refs=(linked.event_id,))
        result = build_investigation_summary(alert, events=(linked,), incident=unrelated_case)
        self.assertFalse(result.supporting_evidence)
        self.assertFalse(result.potential_technique_matches)
        self.assertEqual("unmapped", result.technique_assessment.mapping_status)
        self.assertTrue(any("not linked" in item for item in result.uncertainties))

    def test_empty_input_has_no_fabricated_facts_or_techniques(self):
        summary = build_investigation_summary()
        self.assertEqual((), summary.observed_facts)
        self.assertEqual((), summary.supporting_evidence)
        self.assertEqual((), summary.recommended_next_steps)
        self.assertEqual((), summary.potential_technique_matches)
        self.assertEqual("unmapped", summary.technique_assessment.mapping_status)
        self.assertTrue(summary.uncertainties)

    def test_provider_is_opt_in_and_hypothesis_is_separate_from_deterministic_sections(self):
        alert = _alert(("event-1",))
        event = _event("event-1", "auth.log:1", 1)
        provider = Mock()
        provider.explain.return_value = "Maybe review adjacent authentication events."
        offline = build_investigation_summary(alert, events=(event,), provider=provider,
                                               enabled=True, explicit_consent=False)
        provider.explain.assert_not_called()
        self.assertEqual("offline", offline.ai_status)
        self.assertIsNone(offline.ai_suggestion)

        with patch.dict(os.environ, {"SOC_TEST_API_KEY": "test-only"}):
            assisted = build_investigation_summary(alert, events=(event,), provider=provider,
                enabled=True, explicit_consent=True, selected_evidence=("auth.log:1",))
        self.assertEqual("suggestion", assisted.ai_status)
        self.assertTrue(assisted.ai_suggestion.startswith("Unverified AI hypothesis:"))
        self.assertEqual(("event-1",), assisted.technique_assessment.evidence_refs)
        self.assertNotIn("ai_suggestion", assisted.observed_facts)
        self.assertIn("selected_evidence", assisted.transmitted_fields)

    def test_provider_timeout_and_invalid_credentials_return_safe_fallback(self):
        for failure in (TimeoutError("sensitive-api-key-value"),
                        HTTPError("https://provider.example", 401, "invalid secret", {}, None)):
            provider = Mock()
            provider.explain.side_effect = failure
            result = build_investigation_summary(_alert(("event-1",)), events=(_event("event-1", "auth.log:1", 1),),
                provider=provider, enabled=True, explicit_consent=True)
            self.assertEqual("failed", result.ai_status)
            self.assertIn("offline explanation is shown", result.ai_suggestion)
            self.assertNotIn("sensitive-api-key-value", result.ai_suggestion)
            self.assertNotIn("invalid secret", result.ai_suggestion)

    def test_ai_payload_and_audit_text_redact_credentials_urls_and_sensitive_values(self):
        secret_text = ("username=alice password=hunter2 token=xyz api_key=secret-value "
                       "Bearer xoxb-abcdefghijklmnopqrstuvwxyz https://internal.example/path?token=abc "
                       "192.0.2.44 alice@example.test")
        alert = _alert(("event-1",))
        alert = SecurityAlert(alert.created_at, alert.severity, alert.source, secret_text, secret_text,
                              alert.rule_id, alert.alert_id, evidence_refs=alert.evidence_refs)
        safe, selected = sanitize_ai_payload(alert, (secret_text,))
        serialized = json.dumps((safe, selected))
        for secret in ("alice", "hunter2", "xyz", "secret-value", "xoxb-abcdefghijklmnopqrstuvwxyz",
                       "internal.example", "192.0.2.44", "alice@example.test"):
            self.assertNotIn(secret, serialized)
        audit_safe = sanitize_ai_text(secret_text)
        self.assertNotIn("hunter2", audit_safe)
        self.assertNotIn("internal.example", audit_safe)

    def test_structured_summary_audit_persists_without_raw_prompt_or_credentials(self):
        event = _event("event-1", "auth.log:1", 1)
        alert = _alert((event.event_id,))
        summary = build_investigation_summary(alert, events=(event,))
        dangerous_suggestion = "Review this hypothesis; password=hunter2 token=secret https://private.test/?x=1"
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "ai-audit.sqlite3"
            with Storage(database) as store:
                record_ai_activity(store, "local/rule-investigation-summary", "offline-structured-summary",
                    "offline", sanitize_ai_text(dangerous_suggestion), evidence_refs=(event.evidence_ref,),
                    transmitted_fields=summary.transmitted_fields)
            with Storage(database) as reopened:
                audit = reopened.list_ai_activity()[0]
                self.assertEqual("offline", audit.status)
                self.assertEqual((event.evidence_ref,), audit.evidence_refs)
                self.assertNotIn("hunter2", repr(audit))
                self.assertNotIn("secret", repr(audit))
                self.assertNotIn("private.test", repr(audit))


if __name__ == "__main__":
    unittest.main()
