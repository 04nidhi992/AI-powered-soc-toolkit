"""Typed, editable defaults for monitoring thresholds and detection rules."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Thresholds:
    cpu_percent: float = 90.0
    memory_percent: float = 85.0
    disk_percent: float = 90.0
    cpu_critical_percent: float = 98.0
    memory_critical_percent: float = 95.0
    disk_critical_percent: float = 98.0

    def __post_init__(self) -> None:
        for name, warning, critical in (
            ("CPU", self.cpu_percent, self.cpu_critical_percent),
            ("memory", self.memory_percent, self.memory_critical_percent),
            ("disk", self.disk_percent, self.disk_critical_percent),
        ):
            if not 0 <= warning <= 100 or not 0 <= critical <= 100 or critical < warning:
                raise ValueError(f"{name} thresholds must be 0..100 with critical >= warning")


@dataclass(frozen=True)
class ProcessIndicators:
    review_paths: tuple[str, ...] = (
        "\\users\\public\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\",
    )

    def __post_init__(self) -> None:
        if any(not path.strip() for path in self.review_paths):
            raise ValueError("Process indicator paths cannot be blank")


@dataclass(frozen=True)
class ThreatScoringConfig:
    """Configurable triage score weights; points are not probabilities."""

    info_rule_points: int = 0
    low_rule_points: int = 5
    medium_rule_points: int = 10
    high_rule_points: int = 20
    critical_rule_points: int = 25
    max_rule_points: int = 60
    points_per_additional_event: int = 2
    max_event_points: int = 20
    independent_source_points: int = 5
    correlation_group_points: int = 5
    malicious_intel_points: int = 15
    suspicious_intel_points: int = 5
    max_intel_points: int = 15
    medium_threshold: int = 25
    high_threshold: int = 50
    critical_threshold: int = 75

    def __post_init__(self) -> None:
        values = (self.info_rule_points, self.low_rule_points, self.medium_rule_points,
                  self.high_rule_points, self.critical_rule_points, self.max_rule_points,
                  self.points_per_additional_event, self.max_event_points,
                  self.independent_source_points, self.correlation_group_points,
                  self.malicious_intel_points, self.suspicious_intel_points, self.max_intel_points)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
            raise ValueError("Threat scoring weights must be non-negative integers")
        if not 1 <= self.medium_threshold <= 100 or not self.medium_threshold < self.high_threshold <= 100 or not self.high_threshold < self.critical_threshold <= 100:
            raise ValueError("Threat score thresholds must be increasing values from 1 to 100")


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: str
    reason: str

    def __post_init__(self) -> None:
        if not self.rule_id.strip() or not self.name.strip() or not self.reason.strip():
            raise ValueError("Detection rules require an ID, name, and reason")
        if self.severity.upper() not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(f"Unsupported rule severity: {self.severity}")


DEFAULT_RULES = (
    DetectionRule("AUTH_FAILURE", "Authentication failure", re.compile(r"\b(failed login|authentication failure|login failure|invalid user|event id\s*4625)\b", re.I), "HIGH", "The log entry indicates a failed or invalid authentication attempt."),
    DetectionRule("ACCESS_DENIED", "Denied or unauthorized access", re.compile(r"\b(access denied|unauthorized|permission denied|event id\s*4663)\b", re.I), "HIGH", "The log entry indicates an access denial or an access-related Windows event requiring review."),
    DetectionRule("MALWARE_INDICATOR", "Malware-related keyword", re.compile(r"\b(malware|virus detected|quarantined threat)\b", re.I), "HIGH", "A malware-related term appears in the source log; validate the originating product and event."),
    DetectionRule("SECURITY_WARNING", "Security warning", re.compile(r"\b(error|warning|blocked|firewall)\b", re.I), "MEDIUM", "A warning, error, or blocking event was recorded and may need triage."),
)
