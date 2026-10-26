"""Explainable defensive detections over normalized logs, metrics, and process reviews."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import uuid

from .alerts import evaluate_snapshot
from .log_analysis import LogFinding
from .models import DetectionResult, NormalizedEvent, SystemSnapshot
from .process_analysis import ProcessReview
from .settings import DEFAULT_RULES, DetectionRule, Thresholds


DEFAULT_INVESTIGATION_STEPS = (
    "Validate the source event and confirm the affected account or host.",
    "Review adjacent events and known maintenance or user activity before escalation.",
)


def _detection(rule_id: str, name: str, severity: str, reason: str,
               events: list[NormalizedEvent], summary: str,
               steps: tuple[str, ...] = DEFAULT_INVESTIGATION_STEPS) -> DetectionResult:
    return DetectionResult(str(uuid.uuid4()), rule_id, name, datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           severity, reason, tuple(event.event_id for event in events), summary, steps)


def detect_events(events: list[NormalizedEvent], rules: tuple[DetectionRule, ...] = DEFAULT_RULES,
                  repeated_threshold: int = 5, correlation_window_seconds: int = 900) -> list[DetectionResult]:
    if (isinstance(repeated_threshold, bool) or not isinstance(repeated_threshold, int)
            or repeated_threshold < 2):
        raise ValueError("repeated_threshold must be at least 2")
    results: list[DetectionResult] = []
    ordered = sorted(events, key=lambda event: event.timestamp)
    window = timedelta(seconds=max(0, correlation_window_seconds))
    for event in ordered:
        for rule in rules:
            if rule.pattern.search(event.message):
                results.append(_detection(rule.rule_id, rule.name, rule.severity, rule.reason,
                                          [event], f"Matched event {event.event_id}: {event.message[:400]}"))
    failed = [event for event in ordered if "fail" in event.event_type.casefold() or
              "4625" in event.event_type or "failed" in event.message.casefold()]
    successful = [event for event in ordered if "success" in event.event_type.casefold() or
                  "4624" in event.event_type or "successful" in event.message.casefold()]
    failure_groups: dict[tuple[str, ...], list[NormalizedEvent]] = defaultdict(list)
    for event in failed:
        source_ip = None
        if event.source_ip:
            try:
                source_ip = str(ipaddress.ip_address(event.source_ip))
            except ValueError:
                source_ip = None
        if source_ip:
            # A shared, validated source IP can reveal spraying across accounts or hosts.
            identity = ("source_ip", source_ip)
        elif event.host and event.username:
            # Without a usable IP, require the more specific host+account pair.
            identity = ("host_user", event.host.casefold(), event.username.casefold())
        else:
            continue
        failure_groups[identity].append(event)

    for identity, grouped_failures in failure_groups.items():
        group = sorted(grouped_failures, key=lambda event: event.timestamp)
        qualifying: list[NormalizedEvent] = []
        for start in range(len(group)):
            end = start
            while (end < len(group) and
                   datetime.fromisoformat(group[end].timestamp) - datetime.fromisoformat(group[start].timestamp) <= window):
                end += 1
            if end - start >= repeated_threshold:
                qualifying = group[start:end]
                break
        if not qualifying:
            continue
        if identity[0] == "source_ip":
            reason = (f"{len(qualifying)} failed-login events shared validated source IP {identity[1]} "
                      "within the configured time window, across the observed account/host values.")
            summary = identity[1]
        else:
            reason = (f"{len(qualifying)} failed-login events shared host and username identity "
                      "within the configured time window; no valid source IP was available.")
            summary = f"host={identity[1]}; username={identity[2]}"
        results.append(_detection("REPEATED_FAILED_LOGINS", "Repeated failed logins", "HIGH",
                                   reason, qualifying, summary))
    for failure in failed:
        for success in successful:
            if not (failure.source_ip or failure.username or failure.host):
                continue
            shared = [field for field in ("source_ip", "username", "host")
                      if getattr(failure, field) and getattr(failure, field) == getattr(success, field)]
            if not shared:
                continue
            before = datetime.fromisoformat(failure.timestamp) <= datetime.fromisoformat(success.timestamp)
            delta = datetime.fromisoformat(success.timestamp) - datetime.fromisoformat(failure.timestamp)
            if before and timedelta(0) <= delta <= window:
                results.append(_detection("FAILED_THEN_SUCCESS", "Failed login followed by success", "HIGH",
                    f"A success followed a failed login within {int(window.total_seconds())} seconds; shared fields: {', '.join(shared)}.",
                    [failure, success], f"Failed event {failure.event_id}; success event {success.event_id}."))
    buckets: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in ordered:
        if event.event_type and event.event_type.casefold() not in {"unknown", "log", "syslog"}:
            buckets[(event.host or "", event.event_type)].append(event)
    for (host, event_type), group in buckets.items():
        if event_type.casefold() in {"failed_login", "login_failure", "authentication failure", "4625", "4624"}:
            continue
        group.sort(key=lambda event: event.timestamp)
        for start in range(len(group)):
            end = start
            while end < len(group) and datetime.fromisoformat(group[end].timestamp) - datetime.fromisoformat(group[start].timestamp) <= window:
                end += 1
            if end - start >= repeated_threshold:
                selected = group[start:end]
                results.append(_detection("REPEATED_SECURITY_EVENT", "Repeated event type", "MEDIUM",
                    f"The same event type occurred {len(selected)} times for host {host or 'unknown'} in the configured time window.",
                    selected, event_type))
                break
    return _dedupe_results(results)


def detect_findings(findings: list[LogFinding]) -> list[DetectionResult]:
    return [DetectionResult(str(uuid.uuid4()), finding.rule_id or "LOG_RULE", finding.rule_id or "Log rule",
            finding.timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"), finding.severity,
            finding.reason, (finding.path + ":" + str(finding.line_number),), finding.text,
            DEFAULT_INVESTIGATION_STEPS) for finding in findings]


def detect_process_reviews(reviews: list[ProcessReview]) -> list[DetectionResult]:
    bucket = int(datetime.now(timezone.utc).timestamp()) // 300
    return [DetectionResult(str(uuid.uuid4()), "PROCESS_PATH_REVIEW", "Process path review",
                       datetime.now(timezone.utc).isoformat(timespec="seconds"), "MEDIUM", reason,
                       (f"process:{review.process.pid}:{bucket}",), f"PID {review.process.pid} {review.process.name}: {reason}",
                       DEFAULT_INVESTIGATION_STEPS)
            for review in reviews for reason in review.review_reasons]


def detect_system_metrics(snapshot: SystemSnapshot, thresholds: Thresholds | None = None) -> list[DetectionResult]:
    results = []
    bucket = int(datetime.fromisoformat(snapshot.captured_at).timestamp()) // 300
    for alert in evaluate_snapshot(snapshot, thresholds):
        results.append(DetectionResult(str(uuid.uuid4()), alert.rule_id or "SYSTEM_THRESHOLD",
            "System metric threshold", snapshot.captured_at, alert.severity, alert.reason,
            (f"snapshot:{bucket}:{alert.rule_id}",), alert.message, DEFAULT_INVESTIGATION_STEPS))
    return results


def _dedupe_results(results: list[DetectionResult]) -> list[DetectionResult]:
    seen: set[tuple[str, tuple[str, ...]]] = set()
    unique = []
    for result in results:
        key = (result.rule_id, result.event_refs)
        if key not in seen:
            unique.append(result)
            seen.add(key)
    return unique
