"""Extract and validate IOC-shaped values without making threat judgments."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

from .models import NormalizedEvent


@dataclass(frozen=True)
class ExtractedIndicator:
    indicator_type: str
    value: str
    evidence_refs: tuple[str, ...]
    classification: str = "extracted"
    scope: str = "unknown"


_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_DOMAIN = re.compile(r"(?i)(?<![\w@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])")
_HASHES = (
    ("MD5", re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")),
    ("SHA-1", re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")),
    ("SHA-256", re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")),
)
_EXAMPLE_DOMAINS = {"example.com", "example.net", "example.org", "example.test", "example.invalid"}


def _scope(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    documentation = ((ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"),
                      ipaddress.ip_network("203.0.113.0/24")) if address.version == 4 else
                     (ipaddress.ip_network("2001:db8::/32"),))
    if any(address in network for network in documentation) or address.is_reserved:
        return "reserved_or_documentation"
    private = ((ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16")) if address.version == 4 else
               (ipaddress.ip_network("fc00::/7"),))
    if any(address in network for network in private):
        return "private"
    if not address.is_global:
        return "reserved_or_documentation"
    return "global"


def _domain(value: str) -> str | None:
    candidate = value.rstrip('.,;:!?)"').casefold()
    if candidate in _EXAMPLE_DOMAINS or candidate.endswith((".example", ".test", ".invalid", ".localhost", ".local")):
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = candidate.split(".")
    if len(candidate) > 253 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        return None
    return candidate


def extract_iocs_from_text(text: str, evidence_ref: str = "") -> tuple[ExtractedIndicator, ...]:
    """Extract URLs, domains, IPs, and common hashes from text as unverified indicators."""
    if not isinstance(text, str) or not text:
        return ()
    found: dict[tuple[str, str], set[str]] = {}

    def add(kind: str, value: str, ref: str = evidence_ref) -> None:
        key = (kind, value)
        found.setdefault(key, set())
        if ref:
            found[key].add(ref)

    for match in _URL.finditer(text):
        raw = match.group(0).rstrip('.,;:!?)"')
        try:
            parsed = urlsplit(raw)
            host = parsed.hostname
            if parsed.scheme.casefold() not in {"http", "https"} or not host:
                continue
            normalized_host = str(ipaddress.ip_address(host)) if ":" in host or re.fullmatch(r"[\d.]+", host) else _domain(host)
            if not normalized_host:
                continue
            normalized = urlunsplit((parsed.scheme.casefold(), parsed.netloc.casefold(), parsed.path or "/", parsed.query, ""))
        except (ValueError, UnicodeError):
            continue
        add("URL", normalized)

    for candidate in _IPV4.findall(text):
        _add_ip(candidate, add)
    for candidate in _IPV6.findall(text):
        _add_ip(candidate.strip("[](),.;"), add)
    for candidate in _DOMAIN.findall(text):
        domain = _domain(candidate)
        if domain:
            add("DOMAIN", domain)
    for kind, pattern in _HASHES:
        for value in pattern.findall(text):
            add(kind, value.casefold())
    return tuple(ExtractedIndicator(kind, value, tuple(sorted(refs)), "extracted", _indicator_scope(kind, value))
                 for (kind, value), refs in sorted(found.items()))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _add_ip(candidate: str, add) -> None:
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return
    add("IPv4" if address.version == 4 else "IPv6", str(address))


def _indicator_scope(kind: str, value: str) -> str:
    if kind in {"IPv4", "IPv6"}:
        return _scope(ipaddress.ip_address(value))
    if kind in {"DOMAIN", "URL"}:
        return "example" if "example" in value or value.endswith((".test", ".invalid")) else "unknown"
    return "unknown"


def extract_iocs_from_event(event: NormalizedEvent) -> tuple[ExtractedIndicator, ...]:
    """Extract indicators from an event's message and normalized/raw fields."""
    fragments = [event.message]
    if event.raw_fields:
        fragments.append(json.dumps(event.raw_fields, ensure_ascii=False, default=str))
    # Dedicated normalized fields can otherwise be absent from message/raw_fields.
    fragments.extend(value for value in (event.source_ip, event.destination_ip) if value)
    text = "\n".join(fragments)
    return extract_iocs_from_text(text, event.evidence_ref or event.event_id)


def extract_iocs_from_events(events: list[NormalizedEvent]) -> tuple[ExtractedIndicator, ...]:
    """Aggregate indicators across events, retaining every distinct evidence reference."""
    refs: dict[tuple[str, str], set[str]] = {}
    for event in events:
        for indicator in extract_iocs_from_event(event):
            refs.setdefault((indicator.indicator_type, indicator.value), set()).update(indicator.evidence_refs)
    return tuple(ExtractedIndicator(kind, value, tuple(sorted(evidence)), "extracted", _indicator_scope(kind, value))
                 for (kind, value), evidence in sorted(refs.items()))
