"""Evidence-led event grouping; time proximity alone never creates a group."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from .models import NormalizedEvent


@dataclass(frozen=True)
class CorrelationGroup:
    event_refs: tuple[str, ...]
    explanation: str
    shared_fields: tuple[str, ...]
    start_time: str
    end_time: str


def correlate_events(events: list[NormalizedEvent], window_seconds: int = 900,
                     minimum_shared_fields: int = 1) -> list[CorrelationGroup]:
    """Group events that share identity/network evidence and fit a time window."""
    window = timedelta(seconds=max(0, window_seconds))
    ordered = sorted(events, key=lambda item: item.timestamp)
    parent = list(range(len(ordered)))
    pair_evidence: dict[tuple[int, int], set[str]] = {}

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for left in range(len(ordered)):
        left_time = datetime.fromisoformat(ordered[left].timestamp)
        left_fields = {name: getattr(ordered[left], name) for name in ("source_ip", "username", "host")}
        for right in range(left + 1, len(ordered)):
            right_time = datetime.fromisoformat(ordered[right].timestamp)
            if right_time - left_time > window:
                break
            shared = {name for name, value in left_fields.items()
                      if value and value == getattr(ordered[right], name)}
            if len(shared) >= max(1, minimum_shared_fields):
                parent[root(right)] = root(left)
                pair_evidence[(left, right)] = shared

    components: dict[int, list[int]] = {}
    for index in range(len(ordered)):
        components.setdefault(root(index), []).append(index)
    groups: list[CorrelationGroup] = []
    for indexes in components.values():
        if len(indexes) < 2:
            continue
        refs = tuple(sorted(ordered[index].event_id for index in indexes))
        shared = set().union(*(fields for (left, right), fields in pair_evidence.items()
                               if left in indexes and right in indexes))
        if not shared:
            continue
        explanation_fields = tuple(sorted(shared))
        groups.append(CorrelationGroup(refs,
            f"Grouped because at least one pair shared {', '.join(explanation_fields)} within the configured window; time proximity alone was insufficient.",
            explanation_fields, ordered[indexes[0]].timestamp, ordered[indexes[-1]].timestamp))
    return groups
