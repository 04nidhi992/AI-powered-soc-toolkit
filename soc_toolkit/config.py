"""Central application configuration with safe local defaults."""

from dataclasses import dataclass
from pathlib import Path

from .settings import ProcessIndicators, ThreatScoringConfig, Thresholds


@dataclass(frozen=True)
class AppConfig:
    data_dir: Path = Path("soc_data")
    database_path: Path = Path("soc_data/soc_toolkit.sqlite3")
    max_log_bytes: int = 10_000_000
    sampling_interval_seconds: int = 5
    alert_deduplication_seconds: int = 300
    correlation_window_seconds: int = 900
    repeated_failed_login_threshold: int = 5
    repeated_event_threshold: int = 5
    threat_intel_timeout_seconds: float = 5.0
    threat_intel_min_interval_seconds: float = 15.0
    thresholds: Thresholds = Thresholds()
    process_indicators: ProcessIndicators = ProcessIndicators()
    threat_scoring: ThreatScoringConfig = ThreatScoringConfig()
    report_redact_ips: bool = False
    report_redact_usernames: bool = True

    def __post_init__(self) -> None:
        if self.max_log_bytes <= 0:
            raise ValueError("max_log_bytes must be positive")
        if self.sampling_interval_seconds <= 0:
            raise ValueError("sampling_interval_seconds must be positive")
        if self.alert_deduplication_seconds < 0 or self.correlation_window_seconds < 0:
            raise ValueError("time windows cannot be negative")
        if self.threat_intel_timeout_seconds <= 0 or self.threat_intel_min_interval_seconds < 0:
            raise ValueError("threat intelligence timeout must be positive and rate interval non-negative")
        if self.repeated_failed_login_threshold < 2 or self.repeated_event_threshold < 2:
            raise ValueError("repeated-event thresholds must be at least 2")


DEFAULT_CONFIG = AppConfig()
