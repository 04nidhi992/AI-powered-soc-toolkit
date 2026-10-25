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
