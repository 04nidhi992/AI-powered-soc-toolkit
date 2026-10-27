"""Evidence-linked, conservative potential mappings to MITRE ATT&CK Enterprise."""

from dataclasses import dataclass
from collections.abc import Iterable

from .models import DetectionResult


@dataclass(frozen=True)
class TechniqueMapping:
    technique_id: str
    technique_name: str
    tactic: str
    explanation: str
    qualification: str
    source_url: str


@dataclass(frozen=True)
class PotentialTechniqueMatch:
    technique_id: str
    technique_name: str
    tactic: str
    mapping_status: str
    rule_id: str
    explanation: str
    qualification: str
    evidence_refs: tuple[str, ...]
    source_url: str


@dataclass(frozen=True)
class TechniqueAssessment:
    mapping_status: str
    rule_id: str
    evidence_refs: tuple[str, ...]
    explanation: str
    matches: tuple[PotentialTechniqueMatch, ...] = ()


# Generic T1110 is used because the rule detects repeated failed authentication
# attempts but does not establish password guessing, spraying, or stuffing.
RULE_TECHNIQUES: dict[str, tuple[TechniqueMapping, ...]] = {
    "REPEATED_FAILED_LOGINS": (TechniqueMapping(
        "T1110", "Brute Force", "Credential Access",
        "The rule observed thresholded repeated failed authentication attempts. This behavior is consistent with brute-force credential access, but does not establish adversary intent or distinguish a sub-technique.",
        "Behavioral alignment only; repeated failures can result from user error or benign automation. Adversary intent and sub-technique are unconfirmed.",
        "https://attack.mitre.org/techniques/T1110/",
    ),),
}


def _supports_rule_behavior(rule_id: str, event: object) -> bool:
    if rule_id == "REPEATED_FAILED_LOGINS":
        event_type = str(getattr(event, "event_type", "")).casefold()
        message = str(getattr(event, "message", "")).casefold()
        return "fail" in event_type or "4625" in event_type or "failed" in message
    return False


def assess_rule_mapping(rule_id: str, event_refs: Iterable[str], *,
                        available_event_refs: set[str] | None = None,
                        available_events: Iterable[object] | None = None) -> TechniqueAssessment:
    """Return a mapped or explicit unmapped assessment for a rule and its evidence.

    When ``available_event_refs`` is supplied, only references that resolve to
    the caller's actual event set can support a potential technique match.
    """
    references = tuple(dict.fromkeys(reference for reference in event_refs if reference))
    events_by_reference: dict[str, object] = {}
    if available_events is not None:
        for event in available_events:
            event_id = getattr(event, "event_id", "")
            evidence_ref = getattr(event, "evidence_ref", "")
            if event_id:
                events_by_reference[event_id] = event
            if evidence_ref:
                events_by_reference[evidence_ref] = event
        resolved: list[str] = []
        seen_event_ids: set[str] = set()
        for reference in references:
            event = events_by_reference.get(reference)
            identity = str(getattr(event, "event_id", "")) if event is not None else ""
            identity = identity or reference
            if event is not None and identity not in seen_event_ids:
                resolved.append(reference)
                seen_event_ids.add(identity)
        references = tuple(resolved)
    elif available_event_refs is not None:
        references = tuple(reference for reference in references if reference in available_event_refs)
    if not references:
        return TechniqueAssessment("unmapped", rule_id, (),
                                   "No detection evidence references resolved to supplied events with the required observed behavior.")
    if rule_id not in RULE_TECHNIQUES:
        return TechniqueAssessment("unmapped", rule_id, references,
                                   "No documented ATT&CK mapping is supported for this detection rule.")
    behavior_refs = (tuple(reference for reference in references
                           if _supports_rule_behavior(rule_id, events_by_reference[reference]))
                     if available_events is not None else references)
    if len(behavior_refs) < 2:
        return TechniqueAssessment("unmapped", rule_id, references,
                                   "This rule requires at least two distinct resolved event records that show failed authentication to support its potential technique match.")
    references = behavior_refs
    matches = tuple(PotentialTechniqueMatch(mapping.technique_id, mapping.technique_name,
        mapping.tactic, "potential", rule_id, mapping.explanation, mapping.qualification,
        references, mapping.source_url) for mapping in RULE_TECHNIQUES[rule_id])
    return TechniqueAssessment("potential", rule_id, references,
                               "Potential mapping supported by the rule and resolved evidence.", matches)


def assess_detection_mapping(detection: DetectionResult, *,
                             available_event_refs: set[str] | None = None,
                             available_events: Iterable[object] | None = None) -> TechniqueAssessment:
    """Assess a detection and return explicit unmapped results when unsupported."""
    return assess_rule_mapping(detection.rule_id, detection.event_refs,
                               available_event_refs=available_event_refs,
                               available_events=available_events)


def potential_technique_matches(detection: DetectionResult) -> tuple[PotentialTechniqueMatch, ...]:
    """Compatibility helper returning only evidence-backed potential matches."""
    return assess_detection_mapping(detection).matches
