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
    event_count: int = 0
    event_types: tuple[str, ...] = ()


def correlate_events(events: list[NormalizedEvent], window_seconds: int = 900,
                     minimum_shared_fields: int = 1,
                     minimum_event_count: int = 2) -> list[CorrelationGroup]:
    """Group events with shared identity evidence inside a time/count boundary.

    Matching event types are retained as supporting evidence, but event type and
    time proximity alone never create a group.
    """
    if isinstance(minimum_event_count, bool) or not isinstance(minimum_event_count, int) or minimum_event_count < 2:
        raise ValueError("minimum_event_count must be an integer of at least 2")
    if isinstance(minimum_shared_fields, bool) or not isinstance(minimum_shared_fields, int) or minimum_shared_fields < 1:
        raise ValueError("minimum_shared_fields must be a positive integer")
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
                if (ordered[left].event_type and ordered[right].event_type and
                        ordered[left].event_type.casefold() == ordered[right].event_type.casefold()):
                    shared.add("event_type")
                pair_evidence[(left, right)] = shared

    components: dict[int, list[int]] = {}
    for index in range(len(ordered)):
        components.setdefault(root(index), []).append(index)
    groups: list[CorrelationGroup] = []
    for indexes in components.values():
        if len(indexes) < minimum_event_count:
            continue
        refs = tuple(sorted(ordered[index].event_id for index in indexes))
        shared = set().union(*(fields for (left, right), fields in pair_evidence.items()
                               if left in indexes and right in indexes))
        if not shared:
            continue
        explanation_fields = tuple(sorted(shared))
        event_types = tuple(sorted({ordered[index].event_type for index in indexes if ordered[index].event_type}))
        explanation = (
            f"Grouped {len(indexes)} events within the configured {int(window.total_seconds())}-second window "
            f"because linked pairs shared fields ({', '.join(explanation_fields)}), including required identity evidence; "
            f"observed event types: {', '.join(event_types) or 'unspecified'}. "
            "Time proximity alone was insufficient."
        )
        groups.append(CorrelationGroup(refs,
            explanation, explanation_fields, ordered[indexes[0]].timestamp,
            ordered[indexes[-1]].timestamp, len(indexes), event_types))
    return groups
