from dataclasses import replace
from types import SimpleNamespace
import unittest

from soc_toolkit.attack_mapping import assess_detection_mapping, potential_technique_matches
from soc_toolkit.models import DetectionResult, NormalizedEvent
from soc_toolkit.settings import ThreatScoringConfig
from soc_toolkit.threat_intel import EnrichmentResult
from soc_toolkit.threat_scoring import score_threat


def event(index, *, source="auth.log", host="workstation"):
    return NormalizedEvent(f"2026-05-01T00:00:{index:02d}Z", source, "failed_login", "HIGH",
        "synthetic failed login", host=host, username="demo", evidence_ref=f"{source}:{index}",
        event_id=f"event-{index}")


def detection(rule="REPEATED_FAILED_LOGINS", refs=("event-1",), severity="HIGH"):
    return DetectionResult(f"det-{rule}", rule, rule, "2026-05-01T00:00:10Z", severity,
        "Synthetic test evidence", refs, "Synthetic summary", ("Review evidence",))


class AttackMappingTests(unittest.TestCase):
    def test_repeated_failed_login_maps_to_potential_generic_brute_force(self):
        result = potential_technique_matches(detection(refs=("event-1", "event-2")))
        self.assertEqual(1, len(result))
        mapping = result[0]
        self.assertEqual(("T1110", "Brute Force", "Credential Access", "potential"),
                         (mapping.technique_id, mapping.technique_name, mapping.tactic, mapping.mapping_status))
        self.assertEqual(("event-1", "event-2"), mapping.evidence_refs)
        self.assertIn("does not establish adversary intent", mapping.explanation)
        self.assertIn("Behavioral alignment only", mapping.qualification)
        self.assertTrue(mapping.source_url.startswith("https://attack.mitre.org/"))

    def test_unknown_rule_and_missing_evidence_are_not_mapped(self):
        self.assertEqual((), potential_technique_matches(detection("UNKNOWN_RULE")))
        unknown = assess_detection_mapping(detection("UNKNOWN_RULE"))
        self.assertEqual("unmapped", unknown.mapping_status)
        self.assertIn("No documented", unknown.explanation)
        no_evidence = SimpleNamespace(rule_id="REPEATED_FAILED_LOGINS", event_refs=())
        self.assertEqual((), potential_technique_matches(no_evidence))
        self.assertEqual("unmapped", assess_detection_mapping(no_evidence).mapping_status)

    def test_insufficient_or_unresolved_evidence_is_explicitly_unmapped(self):
        one_ref = assess_detection_mapping(detection(refs=("event-1",)))
        self.assertEqual("unmapped", one_ref.mapping_status)
        self.assertEqual((), one_ref.matches)
        unresolved = assess_detection_mapping(detection(refs=("event-1", "event-2")),
                                             available_event_refs={"event-1"})
        self.assertEqual(("event-1",), unresolved.evidence_refs)
        self.assertEqual("unmapped", unresolved.mapping_status)
        self.assertEqual((), unresolved.matches)

    def test_linked_but_unrelated_event_content_does_not_support_a_technique(self):
        benign_events = [NormalizedEvent(f"2026-05-01T00:00:0{index}Z", "auth.log", "login_success", "INFO",
            "Successful login after user correction", event_id=f"event-{index}") for index in (1, 2)]
        assessment = assess_detection_mapping(detection(refs=("event-1", "event-2")),
                                              available_events=benign_events)
        self.assertEqual("unmapped", assessment.mapping_status)
        self.assertEqual((), assessment.matches)
        self.assertIn("show failed authentication", assessment.explanation)
        single_event = event(1)
        aliases = assess_detection_mapping(detection(refs=(single_event.event_id, single_event.evidence_ref)),
                                           available_events=(single_event,))
        self.assertEqual("unmapped", aliases.mapping_status)
        self.assertEqual((single_event.event_id,), aliases.evidence_refs)

    def test_other_current_detection_rules_remain_unmapped_without_rule_support(self):
        for rule_id in ("FAILED_THEN_SUCCESS", "REPEATED_SECURITY_EVENT", "AUTH_FAILURE",
                        "ACCESS_DENIED", "MALWARE_INDICATOR", "SECURITY_WARNING"):
            with self.subTest(rule_id=rule_id):
                assessment = assess_detection_mapping(detection(rule_id, ("event-1", "event-2")))
                self.assertEqual("unmapped", assessment.mapping_status)
                self.assertFalse(assessment.matches)


class ThreatScoringTests(unittest.TestCase):
    def test_score_zero_boundaries_and_unrelated_events(self):
        unrelated = [event(1), event(2, source="other.log", host="elsewhere")]
        score = score_threat(unrelated, (), (), ())
        self.assertEqual((0, "LOW", 0, ()), (score.score, score.level, score.unique_event_count, score.matched_rules))
        self.assertTrue(any("does not indicate benign" in item for item in score.uncertainty))

    def test_unresolved_detection_evidence_is_excluded(self):
        score = score_threat([event(1)], [detection(refs=("missing-event",))])
        self.assertEqual(0, score.score)
        self.assertEqual((), score.matched_rules)
        self.assertTrue(any("could not be matched" in item for item in score.uncertainty))

    def test_duplicate_event_rule_and_enrichment_representations_are_counted_once(self):
        first = event(1)
        duplicate_object = replace(first, message="different representation")
        intelligence = EnrichmentResult("IPv4", "8.8.8.8", "VirusTotal", "2026-05-01T00:00:10Z",
            "found", details={"last_analysis_stats": {"malicious": 1, "suspicious": 0}},
            evidence_refs=(first.evidence_ref,))
        score = score_threat([first, duplicate_object],
            [detection(refs=("event-1",)), detection(refs=("event-1",))],
            enrichment_results=[intelligence, intelligence])
        self.assertEqual(35, score.score)  # one HIGH rule (20) plus one malicious IOC (15)
        self.assertEqual(1, score.unique_event_count)
        self.assertEqual(("REPEATED_FAILED_LOGINS",), score.matched_rules)

    def test_event_corroboration_and_enrichment_points_are_evidence_linked(self):
        events = [event(1), event(2, source="windows.xml"), event(3, source="unrelated.log", host="other")]
        group = SimpleNamespace(event_refs=("event-1", "event-2"))
        malicious = EnrichmentResult("DOMAIN", "bad.example.net", "VirusTotal", "2026-05-01T00:00:10Z",
            "found", details={"last_analysis_stats": {"malicious": 1}}, evidence_refs=(events[0].evidence_ref,))
        offline = EnrichmentResult("DOMAIN", "offline.example.net", "local/offline", "2026-05-01T00:00:10Z",
            "offline", evidence_refs=(events[1].evidence_ref,))
        result = score_threat(events, [detection(refs=("event-1", "event-2"))], [group], [malicious, offline])
        self.assertEqual(2, result.unique_event_count)
        self.assertEqual(2, next(component.points for component in result.components
                                 if component.name == "Unique supporting events"))
        self.assertEqual(5, next(component.points for component in result.components if component.name == "Independent sources"))
        self.assertEqual(5, next(component.points for component in result.components if component.name == "Correlated evidence"))
        self.assertEqual(15, next(component.points for component in result.components if component.name == "External indicator enrichment"))
        self.assertNotIn("event-3", result.evidence_refs)

    def test_score_caps_at_100_and_thresholds_are_configurable(self):
        events = [event(i, source=f"source-{i}") for i in range(1, 21)]
        rules = [detection(f"RULE_{i}", tuple(item.event_id for item in events), "CRITICAL") for i in range(1, 5)]
        intel = [EnrichmentResult("SHA-256", f"{i:064x}", "VirusTotal", "2026-05-01T00:00:10Z",
            "found", details={"last_analysis_stats": {"malicious": 1}}, evidence_refs=(events[i].evidence_ref,))
            for i in range(10)]
        config = ThreatScoringConfig(medium_threshold=10, high_threshold=20, critical_threshold=30)
        result = score_threat(events, rules, enrichment_results=intel, config=config)
        self.assertEqual(100, result.score)
        self.assertEqual("CRITICAL", result.level)
        with self.assertRaises(ValueError):
            ThreatScoringConfig(medium_threshold=50, high_threshold=40, critical_threshold=75)


if __name__ == "__main__":
    unittest.main()
