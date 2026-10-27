"""Explainable triage scoring over unique, corroborated evidence."""

from dataclasses import dataclass
from typing import Iterable

from .models import DetectionResult, NormalizedEvent
from .settings import ThreatScoringConfig


@dataclass(frozen=True)
class ScoreComponent:
    name: str
    points: int
    explanation: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class ThreatScore:
    score: int
    level: str
    components: tuple[ScoreComponent, ...]
    matched_rules: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    unique_event_count: int
    uncertainty: tuple[str, ...]


def score_threat(events: Iterable[NormalizedEvent], detections: Iterable[DetectionResult],
                 correlation_groups: Iterable[object] = (), enrichment_results: Iterable[object] = (),
                 config: ThreatScoringConfig | None = None) -> ThreatScore:
    """Return a bounded 0–100 triage score, deduplicated by event and indicator identity.

    Only detections whose references resolve to supplied events contribute. Rule
    severity is counted once per distinct rule; repeated references to one event
    or one enriched indicator do not increase the score.
    """
    settings = config or ThreatScoringConfig()
    enrichment_results = tuple(enrichment_results)
    unique_events = {event.event_id: event for event in events}
    evidence_lookup: dict[str, NormalizedEvent] = {}
    for event in unique_events.values():
        evidence_lookup[event.event_id] = event
        if event.evidence_ref:
            evidence_lookup[event.evidence_ref] = event

    supported: list[tuple[DetectionResult, tuple[str, ...], tuple[NormalizedEvent, ...]]] = []
    unresolved = False
    for detection in detections:
        refs = tuple(dict.fromkeys(ref for ref in detection.event_refs if ref))
        matched_refs = tuple(ref for ref in refs if ref in evidence_lookup)
        matched_events = tuple({evidence_lookup[ref].event_id: evidence_lookup[ref] for ref in matched_refs}.values())
        if matched_events:
            supported.append((detection, matched_refs, matched_events))
        elif refs:
            unresolved = True

    rule_severity: dict[str, str] = {}
    rule_refs: dict[str, set[str]] = {}
    evidence_events: dict[str, NormalizedEvent] = {}
    all_refs: set[str] = set()
    rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    points_by_severity = {"INFO": settings.info_rule_points, "LOW": settings.low_rule_points,
        "MEDIUM": settings.medium_rule_points, "HIGH": settings.high_rule_points,
        "CRITICAL": settings.critical_rule_points}
    for detection, refs, linked_events in supported:
        severity = detection.severity.upper()
        prior = rule_severity.get(detection.rule_id)
        if prior is None or rank.get(severity, 0) > rank.get(prior, 0):
            rule_severity[detection.rule_id] = severity
        rule_refs.setdefault(detection.rule_id, set()).update(refs)
        all_refs.update(refs)
        evidence_events.update((event.event_id, event) for event in linked_events)
    rule_points_unclipped = sum(points_by_severity.get(severity, 0) for severity in rule_severity.values())
    rule_points = min(rule_points_unclipped, settings.max_rule_points)
    components = [ScoreComponent("Distinct rule severity", rule_points,
        ("No evidence-backed rule matches." if not rule_severity else
         "; ".join(f"{rule}={severity} ({points_by_severity.get(severity, 0)} points)"
                    for rule, severity in sorted(rule_severity.items())) +
         f"; capped at {settings.max_rule_points}."),
        tuple(sorted({ref for refs in rule_refs.values() for ref in refs})))]

    event_ids = set(evidence_events)
    event_count_points = min(max(0, len(event_ids) - 1) * settings.points_per_additional_event,
                             settings.max_event_points) if rule_severity else 0
    components.append(ScoreComponent("Unique supporting events", event_count_points,
        f"{len(event_ids)} unique event(s); first event adds 0 and each additional event adds {settings.points_per_additional_event}, capped at {settings.max_event_points}.",
        tuple(sorted(event_ids))))

    sources = {event.source for event in evidence_events.values() if event.source}
    source_points = settings.independent_source_points if len(sources) >= 2 else 0
    components.append(ScoreComponent("Independent sources", source_points,
        f"{len(sources)} distinct source(s); {settings.independent_source_points} points require at least two.",
        tuple(sorted(event.event_id for event in evidence_events.values() if event.source))))

    corroborating_refs: set[str] = set()
    for group in correlation_groups:
        group_refs = set(getattr(group, "event_refs", ()))
        overlap = group_refs & event_ids
        if len(overlap) >= 2:
            corroborating_refs.update(overlap)
    corroboration_points = settings.correlation_group_points if corroborating_refs else 0
    components.append(ScoreComponent("Correlated evidence", corroboration_points,
        f"{'At least one identity-linked group overlaps two or more supporting events.' if corroborating_refs else 'No correlation group overlaps two or more supporting events.'} Adds {settings.correlation_group_points} points at most.",
        tuple(sorted(corroborating_refs))))

    intel_by_indicator: dict[tuple[str, str], tuple[int, set[str]]] = {}
    for result in enrichment_results:
        if getattr(result, "status", None) != "found" or getattr(result, "source", "").startswith("local/"):
            continue
        refs = set(getattr(result, "evidence_refs", ()))
        if refs and not (refs & (all_refs | {event.evidence_ref for event in evidence_events.values()})):
            continue
        stats = getattr(result, "details", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        key = (getattr(result, "indicator_type", ""), getattr(result, "indicator_value", ""))
        level = 2 if malicious > 0 else 1 if suspicious > 0 else 0
        previous, seen_refs = intel_by_indicator.get(key, (0, set()))
        intel_by_indicator[key] = (max(previous, level), seen_refs | refs)
    intel_points_unclipped = sum(settings.malicious_intel_points if level == 2 else
        settings.suspicious_intel_points if level == 1 else 0 for level, _ in intel_by_indicator.values())
    intel_points = min(intel_points_unclipped, settings.max_intel_points)
    components.append(ScoreComponent("External indicator enrichment", intel_points,
        f"{sum(level == 2 for level, _ in intel_by_indicator.values())} unique malicious and {sum(level == 1 for level, _ in intel_by_indicator.values())} unique suspicious provider result(s); capped at {settings.max_intel_points}. Missing/offline/no-match results add zero and are not benign findings.",
        tuple(sorted({ref for _, refs in intel_by_indicator.values() for ref in refs}))))

    score = min(100, sum(component.points for component in components))
    level = ("CRITICAL" if score >= settings.critical_threshold else
             "HIGH" if score >= settings.high_threshold else
             "MEDIUM" if score >= settings.medium_threshold else "LOW")
    uncertainty = ["This score prioritizes analyst review; it is not a probability, attribution, or verdict."]
    if not supported:
        uncertainty.append("No detection references resolved to supplied events; score is zero and does not indicate benign activity.")
    if unresolved:
        uncertainty.append("Some detection references could not be matched to supplied events and were excluded from scoring.")
    if not enrichment_results:
        uncertainty.append("No enrichment results were supplied; indicator intelligence contributed no points.")
    return ThreatScore(score, level, tuple(components), tuple(sorted(rule_severity)),
                       tuple(sorted(all_refs)), len(event_ids), tuple(uncertainty))
