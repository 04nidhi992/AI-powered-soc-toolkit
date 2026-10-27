"""Offline-first, evidence-linked investigation summaries and optional AI hypotheses."""

from dataclasses import asdict, dataclass
import json
import os
import re
from collections.abc import Iterable
from typing import Protocol
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .attack_mapping import PotentialTechniqueMatch, TechniqueAssessment, assess_rule_mapping
from .correlation import CorrelationGroup
from .models import Incident, NormalizedEvent, SecurityAlert


@dataclass(frozen=True)
class AICommentary:
    text: str
    is_hypothesis: bool = True
    transmitted_fields: tuple[str, ...] = ()
    provider_status: str = "offline"


class AIProvider(Protocol):
    def explain(self, sanitized_alert: dict[str, str], selected_evidence: tuple[str, ...]) -> str: ...


@dataclass(frozen=True)
class OpenAICompatibleProvider:
    endpoint: str
    api_key_env_var: str
    model: str
    explicit_consent: bool = False
    timeout_seconds: int = 15

    def explain(self, sanitized_alert: dict[str, str], selected_evidence: tuple[str, ...]) -> str:
        if not self.explicit_consent:
            raise PermissionError("Explicit user consent is required before sending alert data externally")
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
            raise ValueError("External AI endpoints must use HTTPS")
        api_key = os.environ.get(self.api_key_env_var)
        if not api_key:
            raise ValueError(f"Configure the API key in environment variable {self.api_key_env_var}")
        prompt = {"alert": sanitized_alert, "selected_evidence": list(selected_evidence),
                  "instruction": ("Provide a concise suggestion only from the supplied alert and selected snippets. "
                    "Separate hypotheses from observations, state uncertainty, and recommend validation steps. "
                    "Do not assert compromise or invent event details, IOCs, or ATT&CK techniques.")}
        body = json.dumps({"model": self.model, "messages": [{"role": "user", "content": json.dumps(prompt)}]},
                          ensure_ascii=False).encode("utf-8")
        request = Request(self.endpoint, data=body, headers={"Authorization": f"Bearer {api_key}",
                          "Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read(1_000_000))
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Optional AI provider request failed: {exc}") from exc
        try:
            return str(payload["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("AI provider returned an unsupported response format") from exc


def sanitize_ai_payload(alert: SecurityAlert, selected_evidence: tuple[str, ...] = ()) -> tuple[dict[str, str], tuple[str, ...]]:
    def sanitize(value: str) -> str:
        return sanitize_ai_text(value)[:500]
    sanitized = {"severity": alert.severity, "rule_id": alert.rule_id or "",
                 "reason": sanitize(alert.reason), "message": sanitize(alert.message)}
    snippets = tuple(sanitize(item) for item in selected_evidence[:5])
    return sanitized, snippets


def sanitize_ai_text(value: str) -> str:
    """Remove common credentials, personal identifiers, and full URLs from AI text."""
    value = re.sub(r"(?i)\b(user|username|account|password|passphrase|token|secret|credential|api[_-]?key|access[_-]?key|client[_-]?secret|authorization)\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
                   r"\1=[REDACTED]", value)
    value = re.sub(r"(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[A-Z0-9]{16})\b",
                   "[REDACTED_SECRET]", value)
    value = re.sub(r"(?i)\bbearer\s+\S+", "Bearer [REDACTED]", value)
    value = re.sub(r"https?://[^\s<>\"']+", "[URL]", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", value)
    value = re.sub(r"(?i)(failed password|accepted password) for (?:invalid user )?\S+", r"\1 for [REDACTED]", value)
    value = re.sub(r"(?i)(\\users\\)[^\\\s]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(/home/)[^/\s]+", r"\1[REDACTED]", value)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", value)
    return value[:2000]


def offline_explanation(alert: SecurityAlert) -> AICommentary:
    return AICommentary(f"Rule {alert.rule_id or 'unspecified'} matched: {alert.reason or alert.message} "
                        "Review the linked evidence and nearby activity before drawing conclusions.",
                        provider_status="offline")


def explain_alert(alert: SecurityAlert, provider: AIProvider | None = None, *, enabled: bool = False,
                  explicit_consent: bool = False, selected_evidence: tuple[str, ...] = ()) -> AICommentary:
    """Use local explanation by default; external providers require both switches.

    Only a sanitized summary and explicitly selected evidence snippets are sent.
    """
    if not enabled or not explicit_consent or provider is None:
        return offline_explanation(alert)
    sanitized, snippets = sanitize_ai_payload(alert, selected_evidence)
    try:
        text = provider.explain(sanitized, snippets)
    except Exception:
        fallback = offline_explanation(alert)
        return AICommentary(fallback.text + " Optional AI analysis failed; the offline explanation is shown.",
                            True, provider_status="failed")
    return AICommentary("Unverified AI hypothesis: " + text, True,
                        tuple(sanitized) + (("selected_evidence",) if snippets else ()), "suggestion")


@dataclass(frozen=True)
class SupportingEvidence:
    event_id: str
    source: str
    timestamp: str
    event_type: str
    message: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class InvestigationSummary:
    alert_summary: str
    case_summary: str
    observed_facts: tuple[str, ...]
    supporting_evidence: tuple[SupportingEvidence, ...]
    automated_assessments: tuple[str, ...]
    uncertainties: tuple[str, ...]
    recommended_next_steps: tuple[str, ...]
    technique_assessment: TechniqueAssessment
    potential_technique_matches: tuple[PotentialTechniqueMatch, ...]
    ai_suggestion: str | None = None
    ai_status: str = "offline"
    transmitted_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_investigation_summary(alert: SecurityAlert | None = None, *,
        events: Iterable[NormalizedEvent] = (), incident: Incident | None = None,
        correlation_groups: Iterable[CorrelationGroup] = (), provider: AIProvider | None = None,
        enabled: bool = False, explicit_consent: bool = False,
        selected_evidence: tuple[str, ...] = ()) -> InvestigationSummary:
    """Build a deterministic case/alert summary from exactly linked supplied records.

    Case events are limited to the incident's explicit event references. Alert
    evidence must resolve to an event ID or evidence reference. Provider output
    remains a separate, unverified suggestion and receives only the sanitized
    alert plus snippets the analyst explicitly selected.
    """
    supplied_events = tuple(events)
    case_linked = incident is not None and (alert is None or alert.alert_id in incident.alert_ids)
    if incident is not None and not case_linked:
        supplied_events = ()
    elif case_linked:
        allowed_ids = set(incident.event_refs)
        supplied_events = tuple(event for event in supplied_events if event.event_id in allowed_ids)

    requested_refs = set(alert.evidence_refs) if alert else set()
    linked: dict[str, tuple[NormalizedEvent, set[str]]] = {}
    if alert:
        for event in supplied_events:
            matched = requested_refs & {event.event_id, event.evidence_ref}
            if matched:
                existing = linked.get(event.event_id)
                if existing:
                    existing[1].update(matched)
                else:
                    linked[event.event_id] = (event, set(matched))
    elif incident:
        linked = {event.event_id: (event, {event.evidence_ref or event.event_id})
                  for event in supplied_events if event.event_id in incident.event_refs}

    evidence = tuple(SupportingEvidence(event.event_id, event.source, event.timestamp, event.event_type,
                    event.message, tuple(sorted(refs | ({event.evidence_ref} if event.evidence_ref else set()))))
                    for event, refs in sorted(linked.values(), key=lambda item: item[0].timestamp))
    observed = tuple(f"Event {item.event_id} at {item.timestamp} from {item.source} has type {item.event_type}; recorded message: {item.message}"
                     for item in evidence)
    if alert:
        alert_summary = f"Automated alert {alert.alert_id}: {alert.severity} {alert.rule_id or 'unspecified rule'}; {alert.message}"
    else:
        alert_summary = "No alert selected."
    if case_linked:
        case_summary = f"{incident.title} (status: {incident.status})"
    elif incident:
        case_summary = "No related case selected; the supplied case did not link to this alert."
    else:
        case_summary = "No case selected."

    uncertainties = ["An automated alert or event pattern is a triage lead, not proof of malicious activity or attribution."]
    if alert and not evidence:
        uncertainties.append("No alert evidence references resolved to supplied, case-linked events; event facts and technique mappings are unavailable.")
    elif alert:
        resolved = {ref for item in evidence for ref in item.evidence_refs} | {item.event_id for item in evidence}
        unresolved = tuple(sorted(requested_refs - resolved))
        if unresolved:
            uncertainties.append("Some alert evidence references were not resolved: " + ", ".join(unresolved))
    if incident and not case_linked:
        uncertainties.append("The supplied case is not linked to the selected alert and was excluded from this summary.")

    event_ids = set(linked)
    automated_assessments = [alert_summary] if alert else []
    for group in correlation_groups:
        refs = tuple(dict.fromkeys(ref for ref in group.event_refs if ref))
        if len(refs) >= 2 and set(refs).issubset(event_ids):
            automated_assessments.append(
                f"A supplied correlation group links events {', '.join(refs)}: {group.explanation}")

    map_refs = tuple(item.event_id for item in evidence)
    if alert:
        assessment = assess_rule_mapping(alert.rule_id or "", map_refs,
            available_events=(event for event, _ in linked.values()))
    else:
        assessment = assess_rule_mapping("", (), available_events=(event for event, _ in linked.values()))
    recommendations = tuple(alert.recommended_steps) if alert else ()
    if incident and case_linked and incident.recommendations.strip():
        recommendations += ("Existing case recommendation: " + incident.recommendations.strip(),)
    if not supplied_events and not incident:
        uncertainties.append("No evidence records or case context were supplied.")

    suggestion: str | None = None
    ai_status = "offline"
    transmitted: tuple[str, ...] = ()
    if alert and provider and enabled and explicit_consent:
        commentary = explain_alert(alert, provider, enabled=True, explicit_consent=True,
                                   selected_evidence=selected_evidence)
        suggestion = commentary.text
        ai_status = commentary.provider_status
        transmitted = commentary.transmitted_fields
    techniques = assessment.matches
    return InvestigationSummary(alert_summary, case_summary, observed, evidence, tuple(automated_assessments),
        tuple(dict.fromkeys(uncertainties)),
        recommendations, assessment, techniques, suggestion, ai_status, transmitted)
