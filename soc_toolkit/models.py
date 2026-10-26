"""Shared data models used by the collectors and dashboard."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import ipaddress
import math
import uuid
from typing import Any


def _normalize_iso_timestamp(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def stable_event_id(timestamp: str, source: str, event_type: str, host: str | None,
                    username: str | None, source_ip: str | None, message: str) -> str:
    identity = "\0".join((timestamp, source, event_type, host or "", username or "", source_ip or "", message))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, identity))


@dataclass(frozen=True)
class SystemSnapshot:
    captured_at: str
    hostname: str
    operating_system: str
    cpu_percent: float | None
    memory_percent: float | None
    disk_percent: float | None
    uptime_seconds: float | None = None

    def __post_init__(self) -> None:
        for name in ("cpu_percent", "memory_percent", "disk_percent"):
            value = getattr(self, name)
            if value is not None and not 0 <= value <= 100:
                raise ValueError(f"{name} must be between 0 and 100")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    name: str
    username: str | None
    cpu_percent: float
    memory_percent: float
    status: str
    executable: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid < 0:
            raise ValueError("pid must be a non-negative integer")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Process name is required")
        if self.username is not None and not isinstance(self.username, str):
            raise ValueError("username must be text or None")
        if not isinstance(self.status, str) or not self.status.strip():
            raise ValueError("Process status is required")
        if self.executable is not None and not isinstance(self.executable, str):
            raise ValueError("executable must be text or None")
        if not _is_finite_number(self.cpu_percent) or self.cpu_percent < 0:
            raise ValueError("cpu_percent must be a finite non-negative number")
        if not _is_finite_number(self.memory_percent) or not 0 <= self.memory_percent <= 100:
            raise ValueError("memory_percent must be a finite number between 0 and 100")


@dataclass(frozen=True)
class SecurityAlert:
    created_at: str
    severity: str
    source: str
    message: str
    reason: str = ""
    rule_id: str | None = None
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "open"
    evidence_refs: tuple[str, ...] = ()
    recommended_steps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity.upper() not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(f"Unsupported alert severity: {self.severity}")
        if self.status not in {"open", "investigating", "resolved", "false_positive"}:
            raise ValueError(f"Unsupported alert status: {self.status}")
        try:
            stamp = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValueError("Alert timestamp must be ISO 8601") from exc
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        object.__setattr__(self, "created_at", stamp.astimezone(timezone.utc).isoformat(timespec="seconds"))

    @classmethod
    def create(cls, severity: str, source: str, message: str, reason: str = "",
               rule_id: str | None = None, evidence_refs: tuple[str, ...] = (),
               recommended_steps: tuple[str, ...] = ()) -> "SecurityAlert":
        return cls(datetime.now(timezone.utc).isoformat(timespec="seconds"), severity, source,
                   message, reason, rule_id, evidence_refs=evidence_refs,
                   recommended_steps=recommended_steps)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence_refs"] = list(self.evidence_refs)
        result["recommended_steps"] = list(self.recommended_steps)
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass(frozen=True)
class NormalizedEvent:
    timestamp: str
    source: str
    event_type: str
    severity: str
    message: str
    host: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    evidence_ref: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    raw_fields: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        try:
            parsed = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Event timestamp must be ISO 8601") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        object.__setattr__(self, "timestamp", parsed.astimezone(timezone.utc).isoformat(timespec="seconds"))
        if self.severity.upper() not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(f"Unsupported event severity: {self.severity}")
        for name in ("source_ip", "destination_ip"):
            value = getattr(self, name)
            if value:
                try:
                    canonical = str(ipaddress.ip_address(value))
                except ValueError as exc:
                    raise ValueError(f"{name} is not a valid IP address") from exc
                object.__setattr__(self, name, canonical)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass(frozen=True)
class DetectionResult:
    detection_id: str
    rule_id: str
    rule_name: str
    timestamp: str
    severity: str
    reason: str
    event_refs: tuple[str, ...]
    evidence_summary: str
    recommended_steps: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("detection_id", "rule_id", "rule_name", "reason", "evidence_summary"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
        if not isinstance(self.severity, str) or self.severity.upper() not in {
                "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(f"Unsupported detection severity: {self.severity}")
        object.__setattr__(self, "timestamp", _normalize_iso_timestamp(self.timestamp, "Detection timestamp"))
        if not isinstance(self.event_refs, (tuple, list)) or any(
                not isinstance(reference, str) or not reference.strip() for reference in self.event_refs):
            raise ValueError("event_refs must contain non-empty text references")
        if not isinstance(self.recommended_steps, (tuple, list)) or any(
                not isinstance(step, str) or not step.strip() for step in self.recommended_steps):
            raise ValueError("recommended_steps must contain non-empty text")
        object.__setattr__(self, "event_refs", tuple(self.event_refs))
        object.__setattr__(self, "recommended_steps", tuple(self.recommended_steps))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Incident:
    incident_id: str
    title: str
    created_at: str
    status: str = "open"
    alert_ids: tuple[str, ...] = ()
    event_refs: tuple[str, ...] = ()
    findings: str = ""
    recommendations: str = ""

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise ValueError("Incident title is required")
        if self.status not in {"open", "investigating", "resolved", "false_positive"}:
            raise ValueError(f"Unsupported incident status: {self.status}")


@dataclass(frozen=True)
class InvestigationNote:
    note_id: str
    incident_id: str
    created_at: str
    author: str
    category: str
    content: str

    def __post_init__(self) -> None:
        if self.category not in {"observed_fact", "detection_conclusion", "analyst_hypothesis", "recommended_action"}:
            raise ValueError(f"Unsupported investigation note category: {self.category}")
        if not self.content.strip():
            raise ValueError("Investigation note content is required")


@dataclass(frozen=True)
class ReportMetadata:
    report_id: str
    title: str
    generated_at: str
    redacted: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.report_id, str) or not self.report_id.strip():
            raise ValueError("report_id is required")
        if not isinstance(self.title, str) or not self.title.strip():
            raise ValueError("Report title is required")
        object.__setattr__(self, "generated_at", _normalize_iso_timestamp(self.generated_at, "Report timestamp"))
        if not isinstance(self.redacted, bool):
            raise ValueError("redacted must be a boolean")
