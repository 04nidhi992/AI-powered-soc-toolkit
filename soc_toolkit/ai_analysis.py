"""Optional AI explanation interface. Offline explanations are always available."""

from dataclasses import dataclass
import json
import os
import re
from typing import Protocol
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .models import SecurityAlert


@dataclass(frozen=True)
class AICommentary:
    text: str
    is_hypothesis: bool = True
    transmitted_fields: tuple[str, ...] = ()


class AIProvider(Protocol):
    def explain(self, sanitized_alert: dict[str, str], selected_evidence: tuple[str, ...]) -> str: ...


@dataclass(frozen=True)
class OpenAICompatibleProvider:
    endpoint: str
    api_key_env_var: str
    model: str
    explicit_consent: bool = False
    timeout_seconds: int = 15

    def explain(self, sanitized_alert: dict[str, str], selected_evidence: tuple[str, ...]) -> str:
        if not self.explicit_consent:
            raise PermissionError("Explicit user consent is required before sending alert data externally")
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
            raise ValueError("External AI endpoints must use HTTPS")
        api_key = os.environ.get(self.api_key_env_var)
        if not api_key:
            raise ValueError(f"Configure the API key in environment variable {self.api_key_env_var}")
        prompt = {"alert": sanitized_alert, "selected_evidence": list(selected_evidence),
                  "instruction": "Explain as an unverified hypothesis. Do not assert compromise."}
        body = json.dumps({"model": self.model, "messages": [{"role": "user", "content": json.dumps(prompt)}]},
                          ensure_ascii=False).encode("utf-8")
        request = Request(self.endpoint, data=body, headers={"Authorization": f"Bearer {api_key}",
                          "Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read(1_000_000))
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Optional AI provider request failed: {exc}") from exc
        try:
            return str(payload["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("AI provider returned an unsupported response format") from exc


def sanitize_ai_payload(alert: SecurityAlert, selected_evidence: tuple[str, ...] = ()) -> tuple[dict[str, str], tuple[str, ...]]:
    def sanitize(value: str) -> str:
        value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", value)
        value = re.sub(r"(?i)\b(user|username|account|password|token|secret|credential|api[_-]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", value)
        value = re.sub(r"(?i)(failed password|accepted password) for (?:invalid user )?\S+", r"\1 for [REDACTED]", value)
        value = re.sub(r"(?i)(\\users\\)[^\\\s]+", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)(/home/)[^/\s]+", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)\bbearer\s+\S+", "Bearer [REDACTED]", value)
        value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", value)
        return value[:500]
    sanitized = {"severity": alert.severity, "rule_id": alert.rule_id or "",
                 "reason": sanitize(alert.reason), "message": sanitize(alert.message)}
    snippets = tuple(sanitize(item) for item in selected_evidence[:5])
    return sanitized, snippets


def offline_explanation(alert: SecurityAlert) -> AICommentary:
    return AICommentary(f"Rule {alert.rule_id or 'unspecified'} matched: {alert.reason or alert.message} "
                        "Review the linked evidence and nearby activity before drawing conclusions.")


def explain_alert(alert: SecurityAlert, provider: AIProvider | None = None, *, enabled: bool = False,
                  explicit_consent: bool = False, selected_evidence: tuple[str, ...] = ()) -> AICommentary:
    """Use local explanation by default; external providers require both switches.

    Only a sanitized summary and explicitly selected evidence snippets are sent.
    """
    if not enabled or not explicit_consent or provider is None:
        return offline_explanation(alert)
    sanitized, snippets = sanitize_ai_payload(alert, selected_evidence)
    try:
        text = provider.explain(sanitized, snippets)
    except Exception as exc:
        fallback = offline_explanation(alert)
        return AICommentary(fallback.text + f" Optional AI analysis failed: {exc}", True)
    return AICommentary("Unverified AI hypothesis: " + text, True,
                        tuple(sanitized) + (("selected_evidence",) if snippets else ()))
