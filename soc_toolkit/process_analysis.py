"""Conservative process indicators for analyst review; never classify malware."""

from dataclasses import dataclass

from .models import ProcessRecord
from .settings import ProcessIndicators


@dataclass(frozen=True)
class ProcessReview:
    process: ProcessRecord
    review_reasons: tuple[str, ...]

    @property
    def requires_review(self) -> bool:
        return bool(self.review_reasons)


def analyze_process(process: ProcessRecord, indicators: ProcessIndicators | None = None) -> ProcessReview:
    """Flag location indicators that merit review, not proof of maliciousness."""
    executable = process.executable
    configured = indicators or ProcessIndicators()
    reasons: list[str] = []
    if executable:
        normalized = executable.replace("/", "\\").casefold()
        matched = next((marker for marker in configured.review_paths if marker.casefold() in normalized), None)
        if matched:
            reasons.append(f"Review executable path matching configured indicator '{matched}'; confirm origin and context.")
    return ProcessReview(process, tuple(reasons))


def analyze_processes(processes: list[ProcessRecord], indicators: ProcessIndicators | None = None) -> list[ProcessReview]:
    return [analyze_process(process, indicators) for process in processes]
