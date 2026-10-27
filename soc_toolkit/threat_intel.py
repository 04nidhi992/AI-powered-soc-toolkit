"""Offline-first threat intelligence lookup with explicit external disclosure controls."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import base64
import ipaddress
import json
import os
import re
import threading
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .ioc_extraction import ExtractedIndicator


@dataclass(frozen=True)
class EnrichmentResult:
    indicator_type: str
    indicator_value: str
    source: str
    lookup_time: str
    status: str
    confidence: float | None = None
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ThreatIntelProvider(Protocol):
    source: str

    def lookup(self, indicator: ExtractedIndicator) -> EnrichmentResult:
        """Look up one indicator without uploading any associated file or evidence."""


def _result(indicator: ExtractedIndicator, source: str, status: str, summary: str = "",
            confidence: float | None = None, details: dict[str, Any] | None = None) -> EnrichmentResult:
    return EnrichmentResult(indicator.indicator_type, indicator.value, source,
        datetime.now(timezone.utc).isoformat(timespec="seconds"), status, confidence,
        summary, details or {}, indicator.evidence_refs)


def offline_result(indicator: ExtractedIndicator) -> EnrichmentResult:
    """Return local extraction context only; offline absence is not a benign verdict."""
    return _result(indicator, "local/offline", "offline",
        f"Extracted indicator; local scope is {indicator.scope}. No reputation lookup was performed.")


def _is_internal_or_example_domain(value: str) -> bool:
    domain = value.casefold().rstrip(".")
    reserved_suffixes = (".local", ".internal", ".lan", ".corp", ".home", ".localhost",
                         ".test", ".invalid", ".example", ".example.com", ".example.net",
                         ".example.org")
    return ("." not in domain or domain.endswith(reserved_suffixes)
            or domain in {"example.com", "example.net", "example.org"})


def _external_lookup_allowed(indicator: ExtractedIndicator) -> tuple[bool, str]:
    kind, value = indicator.indicator_type, indicator.value
    if kind in {"IPv4", "IPv6"}:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False, "Invalid IP address; lookup skipped."
        if not address.is_global:
            return False, "Private, reserved, or non-global IP; external lookup skipped."
        return True, ""
    if kind == "DOMAIN":
        domain = value.casefold().rstrip(".")
        if _is_internal_or_example_domain(domain):
            return False, "Internal or example domain; external lookup skipped."
        return True, ""
    if kind == "URL":
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            if parsed.scheme not in {"http", "https"} or not host:
                raise ValueError
            if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
                return False, "URL contains path, credentials, query, or fragment data; external lookup skipped as a privacy precaution."
            try:
                address = ipaddress.ip_address(host)
                if not address.is_global:
                    return False, "URL host is a private, reserved, or non-global IP; external lookup skipped."
            except ValueError:
                if _is_internal_or_example_domain(host):
                    return False, "URL host appears internal or reserved; external lookup skipped."
        except ValueError:
            return False, "Invalid URL; external lookup skipped."
        return True, ""
    if kind in {"MD5", "SHA-1", "SHA-256"}:
        expected = {"MD5": 32, "SHA-1": 40, "SHA-256": 64}[kind]
        if len(value) != expected or not re.fullmatch(r"[0-9a-fA-F]+", value):
            return False, "Invalid file hash; lookup skipped."
        return True, ""
    return False, "Unsupported indicator type; lookup skipped."


class VirusTotalProvider:
    """VirusTotal v3 lookup client; sends indicator identifiers only, never files."""

    source = "VirusTotal"
    endpoint = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key_env: str = "SOC_VIRUSTOTAL_API_KEY", timeout_seconds: float = 5.0,
                 minimum_interval_seconds: float = 15.0) -> None:
        if not api_key_env or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", api_key_env):
            raise ValueError("API key environment variable name is invalid")
        if timeout_seconds <= 0 or minimum_interval_seconds < 0:
            raise ValueError("timeout must be positive and rate interval non-negative")
        self.api_key_env = api_key_env
        self.timeout_seconds = timeout_seconds
        self.minimum_interval_seconds = minimum_interval_seconds
        self._last_request_at: float | None = None
        self._lock = threading.Lock()

    def _object_path(self, indicator: ExtractedIndicator) -> str:
        value = indicator.value
        if indicator.indicator_type in {"IPv4", "IPv6"}:
            return f"ip_addresses/{quote(value, safe=':.')}"
        if indicator.indicator_type == "DOMAIN":
            return f"domains/{quote(value.casefold(), safe='.-')}"
        if indicator.indicator_type == "URL":
            object_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
            return f"urls/{object_id}"
        return f"files/{quote(value.casefold(), safe='')}"

    def lookup(self, indicator: ExtractedIndicator) -> EnrichmentResult:
        allowed, reason = _external_lookup_allowed(indicator)
        if not allowed:
            return _result(indicator, "local/safety-filter", "skipped_sensitive", reason)
        api_key = os.getenv(self.api_key_env)
        if not api_key:
            return _result(indicator, self.source, "invalid_credentials", "API key is missing from the configured environment variable.")
        now = time.monotonic()
        with self._lock:
            if self._last_request_at is not None:
                remaining = self.minimum_interval_seconds - (now - self._last_request_at)
                if remaining > 0:
                    return _result(indicator, self.source, "rate_limited", "Local provider request interval has not elapsed.",
                                   details={"retry_after_seconds": round(remaining, 2)})
            self._last_request_at = now
        request = Request(f"{self.endpoint}/{self._object_path(indicator)}",
                          headers={"x-apikey": api_key, "accept": "application/json"}, method="GET")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = response.read(1_000_001)
            if len(payload) > 1_000_000:
                return _result(indicator, self.source, "error", "Provider response exceeded the size limit.")
            decoded = json.loads(payload.decode("utf-8"))
        except HTTPError as exc:
            if exc.code == 404:
                return _result(indicator, self.source, "no_match", "Provider has no record for this indicator.")
            if exc.code in {401, 403}:
                return _result(indicator, self.source, "invalid_credentials", "Provider rejected the API credentials or account permissions.")
            if exc.code == 429:
                return _result(indicator, self.source, "rate_limited", "Provider rate limit reached.")
            return _result(indicator, self.source, "error", f"Provider returned HTTP {exc.code}.")
        except TimeoutError:
            return _result(indicator, self.source, "timeout", "Provider lookup timed out.")
        except (URLError, OSError):
            return _result(indicator, self.source, "unavailable", "Provider is unavailable or the network request failed.")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return _result(indicator, self.source, "error", "Provider returned an invalid response.")
        data = decoded.get("data") if isinstance(decoded, dict) else None
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if not isinstance(attributes, dict):
            return _result(indicator, self.source, "error", "Provider returned an invalid response.")
        raw_stats = attributes.get("last_analysis_stats", {})
        if not isinstance(raw_stats, dict):
            return _result(indicator, self.source, "error", "Provider returned an invalid response.")
        try:
            stats = {key: int(raw_stats.get(key, 0))
                     for key in ("malicious", "suspicious", "harmless", "undetected")}
        except (TypeError, ValueError, OverflowError):
            return _result(indicator, self.source, "error", "Provider returned an invalid response.")
        return _result(indicator, self.source, "found",
            f"Provider reports {stats['malicious']} malicious and {stats['suspicious']} suspicious detections.",
            details={"last_analysis_stats": stats, "reputation": attributes.get("reputation")})


def enrich_indicators(indicators: tuple[ExtractedIndicator, ...] | list[ExtractedIndicator],
                      provider: ThreatIntelProvider | None = None, *, external_enabled: bool = False,
                      explicit_consent: bool = False) -> tuple[EnrichmentResult, ...]:
    """Use local-only results by default; external disclosure requires two explicit controls."""
    if not external_enabled or not explicit_consent or provider is None:
        return tuple(offline_result(item) for item in indicators)
    return tuple(provider.lookup(item) for item in indicators)
