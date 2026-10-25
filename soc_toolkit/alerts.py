"""Rule-based alert creation and persistent JSON Lines alert history."""

import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Iterable
import uuid

from .models import SecurityAlert, SystemSnapshot
from .logging_config import configure_app_logging
from .settings import Thresholds


def configure_logging(path: str | Path):
    """Backward-compatible name for the shared logging configuration."""
    return configure_app_logging(path)


def evaluate_snapshot(snapshot: SystemSnapshot, thresholds: Thresholds | None = None,
                      cpu_threshold: float | None = None, memory_threshold: float | None = None,
                      disk_threshold: float | None = None) -> list[SecurityAlert]:
    configured = thresholds or Thresholds()
    limits = (
        cpu_threshold if cpu_threshold is not None else configured.cpu_percent,
        memory_threshold if memory_threshold is not None else configured.memory_percent,
        disk_threshold if disk_threshold is not None else configured.disk_percent,
    )
    alerts: list[SecurityAlert] = []
    critical_limits = (configured.cpu_critical_percent, configured.memory_critical_percent,
                       configured.disk_critical_percent)
    for metric, value, threshold, critical in zip(("CPU", "Memory", "Disk"),
            (snapshot.cpu_percent, snapshot.memory_percent, snapshot.disk_percent), limits, critical_limits):
        if value is not None and value >= threshold:
            message = f"{metric} usage is {value:.1f}% (threshold {threshold:.1f}%)."
            severity = "CRITICAL" if value >= critical else "HIGH"
            alerts.append(SecurityAlert.create(severity, "system", message, reason=message,
                                               rule_id=f"SYSTEM_{metric.upper()}_THRESHOLD"))
    return alerts


def deduplicate_alerts(alerts: Iterable[SecurityAlert], existing: Iterable[SecurityAlert] = (),
                       window_seconds: int = 300) -> list[SecurityAlert]:
    """Drop same-rule/source/message alerts observed within the configured window."""
    candidates = list(existing)
    result: list[SecurityAlert] = []
    window = timedelta(seconds=max(0, window_seconds))
    for alert in alerts:
        try:
            timestamp = datetime.fromisoformat(alert.created_at)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        except ValueError:
            result.append(alert)
            continue
        duplicate = False
        for previous in reversed(candidates):
            if (alert.source, alert.rule_id, alert.message) != (previous.source, previous.rule_id, previous.message):
                continue
            try:
                previous_time = datetime.fromisoformat(previous.created_at)
                if previous_time.tzinfo is None:
                    previous_time = previous_time.replace(tzinfo=timezone.utc)
                age = timestamp - previous_time
                if timedelta(0) <= age <= window:
                    duplicate = True
                    break
            except ValueError:
                continue
        if not duplicate:
            result.append(alert)
            candidates.append(alert)
    return result


def append_alerts(alerts: Iterable[SecurityAlert], path: str | Path, deduplicate: bool = True,
                  window_seconds: int = 300) -> None:
    target = Path(path)
    new_alerts = list(alerts)
    if deduplicate:
        new_alerts = deduplicate_alerts(new_alerts, read_recent_alerts(target), window_seconds)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as stream:
        for alert in new_alerts:
            stream.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")


def read_recent_alerts(path: str | Path, limit: int = 100) -> list[SecurityAlert]:
    target = Path(path)
    if not target.exists():
        return []
    alerts: list[SecurityAlert] = []
    with target.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                item = json.loads(line)
                alerts.append(SecurityAlert(item["created_at"], item["severity"], item["source"], item["message"],
                    item.get("reason", ""), item.get("rule_id"), item.get("alert_id") or str(uuid.uuid4()),
                    item.get("status", "open"), tuple(item.get("evidence_refs", ())),
                    tuple(item.get("recommended_steps", ()))))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
    return alerts[-limit:] if limit > 0 else []
