"""Parse Windows Event Viewer CSV and Linux syslog text; apply explainable rules."""

import csv
from datetime import datetime, timezone
import ipaddress
import json
import re
from dataclasses import dataclass
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from .models import NormalizedEvent, stable_event_id
from .settings import DEFAULT_RULES, DetectionRule


LINUX_SYSLOG = re.compile(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\S+)")
WINDOWS_HEADER_FIELDS = {"date and time", "event id", "level", "source"}
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RFC3164 = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<message>.*)$")
ISO_SYSLOG = re.compile(r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\S+)\s+(?P<host>\S+)\s+(?P<message>.*)$")


@dataclass(frozen=True)
class ParseIssue:
    record: str
    message: str


@dataclass(frozen=True)
class IngestionResult:
    events: tuple[NormalizedEvent, ...]
    errors: tuple[ParseIssue, ...]


@dataclass(frozen=True)
class LogFinding:
    path: str
    line_number: int
    severity: str
    text: str
    rule_id: str | None = None
    reason: str = ""
    timestamp: str | None = None


def parse_log_lines(lines: Iterable[str], source: str = "<memory>", log_format: str = "auto",
                    rules: Iterable[DetectionRule] = DEFAULT_RULES) -> list[LogFinding]:
    """Parse Windows Event Viewer CSV or Linux syslog text without executing input."""
    if log_format not in {"auto", "windows_csv", "linux_syslog", "text"}:
        raise ValueError("log_format must be auto, windows_csv, linux_syslog, or text")
    rows = list(lines)
    detected = log_format
    if detected == "auto":
        first = next((line.strip() for line in rows if line.strip()), "")
        try:
            fields = {field.strip().strip('"').casefold() for field in next(csv.reader([first], strict=True))}
        except (csv.Error, StopIteration):
            fields = set()
        detected = ("windows_csv" if WINDOWS_HEADER_FIELDS.issubset(fields) else
                    "linux_syslog" if LINUX_SYSLOG.match(first) else "text")

    active_rules = tuple(rules)
    findings: list[LogFinding] = []
    csv_headers: list[str] | None = None
    for line_number, raw in enumerate(rows, 1):
        line = raw.strip()
        if not line:
            continue
        timestamp = None
        event_id = None
        normalized = line
        if detected == "windows_csv":
            try:
                fields = next(csv.reader([line], strict=True))
            except csv.Error:
                continue
            headers = [field.strip().strip('"').casefold() for field in fields]
            if WINDOWS_HEADER_FIELDS.issubset(set(headers)):
                csv_headers = headers
                continue
            if csv_headers:
                values = {key: value.strip() for key, value in zip(csv_headers, fields)}
                timestamp = values.get("date and time")
                event_id = values.get("event id")
                normalized = " | ".join(f"{key}: {value}" for key, value in values.items())
        elif detected == "linux_syslog":
            if not LINUX_SYSLOG.match(line):
                continue
            timestamp = line[:15] if re.match(r"^[A-Z][a-z]{2}", line) else line.split(maxsplit=1)[0]

        if event_id:
            normalized += f" Event ID {event_id}"
        matched = [rule for rule in active_rules if rule.pattern.search(normalized)]
        if matched:
            rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            rule = max(matched, key=lambda item: rank.get(item.severity.upper(), 0))
            findings.append(LogFinding(source, line_number, rule.severity, normalized[:2000],
                                       rule.rule_id, rule.reason, timestamp))
    return findings


def analyze_log(path: str | Path, max_bytes: int = 10_000_000, log_format: str = "auto",
                rules: Iterable[DetectionRule] = DEFAULT_RULES) -> list[LogFinding]:
    source = Path(path)
    if source.stat().st_size > max_bytes:
        raise ValueError(f"Log exceeds the {max_bytes:,}-byte analysis limit: {source}")
    with source.open("r", encoding="utf-8", errors="replace") as stream:
        return parse_log_lines(stream, str(source), log_format, rules)


def _event_from_mapping(data: dict, source: str, record: str, message: str = "") -> NormalizedEvent:
    data = _flatten_windows_json(data)
    normalized = {str(key).casefold().replace(" ", "_"): value for key, value in data.items()}
    timestamp = normalized.get("timestamp") or normalized.get("timecreated") or normalized.get("date_and_time") or normalized.get("time")
    if isinstance(timestamp, dict):
        timestamp = timestamp.get("systemtime") or timestamp.get("SystemTime")
    if timestamp:
        stamp = str(timestamp).strip()
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            timestamp = parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            raise ValueError(f"Invalid event timestamp: {stamp}")
    else:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    raw_severity = str(normalized.get("severity") or normalized.get("level") or "INFO").casefold()
    severity = {"0": "INFO", "information": "INFO", "info": "INFO", "1": "CRITICAL", "critical": "CRITICAL",
                "2": "HIGH", "error": "HIGH", "3": "MEDIUM", "warning": "MEDIUM", "warn": "MEDIUM",
                "4": "INFO", "5": "INFO", "debug": "INFO"}.get(raw_severity, "INFO")
    event_type = str(normalized.get("event_type") or normalized.get("eventid") or normalized.get("event_id") or
                     normalized.get("provider") or normalized.get("source") or "log")
    text = message or normalized.get("message") or normalized.get("event_data") or normalized.get("details") or ""
    if isinstance(text, (dict, list)):
        text = json.dumps(text, ensure_ascii=False)
    if not text:
        text = " | ".join(f"{key}: {value}" for key, value in normalized.items() if key.startswith("data_"))
    text = str(text)
    ip_values = IP_PATTERN.findall(text)
    host = str(normalized.get("host") or normalized.get("computer") or normalized.get("hostname") or "") or None
    username = str(normalized.get("username") or normalized.get("user") or normalized.get("account_name") or "") or None
    source_value = normalized.get("source_ip") or normalized.get("ip_address") or (ip_values[0] if ip_values else "")
    destination_value = normalized.get("destination_ip") or (ip_values[1] if len(ip_values) > 1 else "")
    try:
        source_ip = str(ipaddress.ip_address(str(source_value))) if source_value else None
    except ValueError:
        source_ip = None
    try:
        destination_ip = str(ipaddress.ip_address(str(destination_value))) if destination_value else None
    except ValueError:
        destination_ip = None
    return NormalizedEvent(str(timestamp), source, event_type, severity, text, host, username,
        source_ip, destination_ip, f"{source}:{record}",
        stable_event_id(str(timestamp), source, event_type, host, username, source_ip, text), normalized)


def _flatten_windows_json(data: dict) -> dict:
    """Flatten common Windows Event Viewer JSON shapes into normalized fields."""
    root = data.get("Event", data)
    if not isinstance(root, dict):
        return data
    system = root.get("System", root.get("system", {}))
    event_data = root.get("EventData", root.get("eventData", {}))
    if not isinstance(system, dict):
        system = {}
    flattened = dict(data)
    provider = system.get("Provider", system.get("provider", {}))
    created = system.get("TimeCreated", system.get("timeCreated", {}))
    if isinstance(provider, dict):
        name = provider.get("@Name", provider.get("Name", provider.get("name")))
        if name:
            flattened["provider"] = name
    if isinstance(created, dict):
        timestamp = created.get("@SystemTime", created.get("SystemTime", created.get("systemTime")))
        if timestamp:
            flattened["timestamp"] = timestamp
    for from_key, to_key in (("EventID", "event_id"), ("Level", "level"), ("Computer", "host")):
        if from_key in system:
            value = system[from_key]
            flattened[to_key] = value.get("#text", value.get("value", value)) if isinstance(value, dict) else value
    values = event_data.get("Data", []) if isinstance(event_data, dict) else []
    if isinstance(values, list):
        for item in values:
            if not isinstance(item, dict):
                continue
            name = str(item.get("@Name") or item.get("Name") or "").casefold()
            value = item.get("#text", item.get("value", item.get("Value")))
            if name in {"targetusername", "username", "user"}:
                flattened["username"] = value
            elif name in {"ipaddress", "sourceip", "sourceaddress"}:
                flattened["source_ip"] = value
            elif name in {"workstationname", "computername"}:
                flattened["host"] = value
            flattened[f"data_{name or len(flattened)}"] = value
    return flattened


def _xml_event(element: ET.Element, source: str, number: int) -> NormalizedEvent:
    local = lambda tag: tag.rsplit("}", 1)[-1]
    fields: dict[str, object] = {}
    for node in element.iter():
        name = local(node.tag)
        if name == "EventID" and node.text:
            fields["event_id"] = node.text
        elif name == "Level" and node.text:
            fields["level"] = node.text
        elif name == "Computer" and node.text:
            fields["computer"] = node.text
        elif name == "Provider" and node.attrib.get("Name"):
            fields["provider"] = node.attrib["Name"]
        elif name == "TimeCreated" and node.attrib.get("SystemTime"):
            fields["timestamp"] = node.attrib["SystemTime"]
        elif name == "Data" and node.text:
            data_name = node.attrib.get("Name", str(len(fields)))
            fields[f"data_{data_name}"] = node.text
            if data_name.casefold() in {"ipaddress", "sourceip", "sourceaddress"}:
                fields["source_ip"] = node.text
            elif data_name.casefold() in {"targetusername", "subjectusername", "username", "user", "accountname"}:
                fields["username"] = node.text
            elif data_name.casefold() in {"workstationname", "computername"}:
                fields["host"] = node.text
    message = " | ".join(f"{key}={value}" for key, value in fields.items())
    return _event_from_mapping(fields, source, f"event-{number}", message)


def _ingest_evtx(source: Path) -> IngestionResult:
    """Parse native EVTX records with python-evtx and normalize each record's XML."""
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        return IngestionResult((), (ParseIssue("dependency", "Native EVTX parsing requires python-evtx; install it with `python -m pip install -r requirements.txt`"),))
    events: list[NormalizedEvent] = []
    issues: list[ParseIssue] = []
    try:
        with Evtx(str(source)) as log:
            for number, record in enumerate(log.records(), 1):
                try:
                    root = ET.fromstring(record.xml())
                    event = next((node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "Event"), root)
                    events.append(_xml_event(event, str(source), number))
                except (ET.ParseError, ValueError, TypeError, AttributeError) as exc:
                    issues.append(ParseIssue(f"record-{number}", f"Malformed EVTX record: {exc}"))
    except (OSError, ValueError, EOFError) as exc:
        issues.append(ParseIssue("evtx", f"Could not parse EVTX file: {exc}"))
    except Exception as exc:
        # Parser-specific structural errors vary by python-evtx release.
        issues.append(ParseIssue("evtx", f"Could not parse EVTX file: {type(exc).__name__}: {exc}"))
    return IngestionResult(tuple(events), tuple(issues))


def ingest_log_file(path: str | Path, log_format: str = "auto", max_bytes: int = 10_000_000) -> IngestionResult:
    """Ingest supported text exports and native Windows EVTX into normalized events."""
    source = Path(path)
    issues: list[ParseIssue] = []
    events: list[NormalizedEvent] = []
    if source.stat().st_size > max_bytes:
        return IngestionResult((), (ParseIssue("file", f"File exceeds {max_bytes:,} byte limit"),))
    kind = log_format.casefold()
    if kind == "auto":
        kind = {".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl", ".xml": "xml", ".evtx": "evtx"}.get(source.suffix.casefold(), "syslog")
    if kind not in {"syslog", "json", "jsonl", "csv", "xml", "evtx"}:
        return IngestionResult((), (ParseIssue("format", f"Unsupported log format: {log_format}"),))
    if kind == "evtx":
        return _ingest_evtx(source)
    if kind == "xml":
        try:
            for number, (_, element) in enumerate(ET.iterparse(source, events=("end",)), 1):
                if element.tag.rsplit("}", 1)[-1] == "Event":
                    try:
                        events.append(_xml_event(element, str(source), number))
                    except (ValueError, TypeError) as exc:
                        issues.append(ParseIssue(f"event-{number}", str(exc)))
                    element.clear()
        except ET.ParseError as exc:
            issues.append(ParseIssue("xml", f"Malformed XML: {exc}"))
        return IngestionResult(tuple(events), tuple(issues))
    if kind == "csv":
        try:
            with source.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
                reader = csv.DictReader(stream)
                for row in reader:
                    number = reader.line_num
                    if not row or None in row:
                        issues.append(ParseIssue(str(number), "Malformed CSV row"))
                        continue
                    if any(value is not None for value in row.values()):
                        try:
                            events.append(_event_from_mapping(row, str(source), str(number)))
                        except ValueError as exc:
                            issues.append(ParseIssue(str(number), str(exc)))
        except (OSError, csv.Error) as exc:
            issues.append(ParseIssue("csv", str(exc)))
        return IngestionResult(tuple(events), tuple(issues))
    if kind == "json":
        try:
            data = json.loads(source.read_text(encoding="utf-8-sig"))
            event_list = next((value for key, value in data.items() if key.casefold() == "events"), None) if isinstance(data, dict) else None
            records = data if isinstance(data, list) else event_list if isinstance(event_list, list) else [data] if isinstance(data, dict) else []
            for number, item in enumerate(records, 1):
                if isinstance(item, dict):
                    try:
                        events.append(_event_from_mapping(item, str(source), str(number)))
                    except ValueError as exc:
                        issues.append(ParseIssue(str(number), str(exc)))
                else:
                    issues.append(ParseIssue(str(number), "JSON event must be an object"))
        except (OSError, json.JSONDecodeError) as exc:
            issues.append(ParseIssue("json", str(exc)))
        return IngestionResult(tuple(events), tuple(issues))
    if kind == "jsonl":
        with source.open("r", encoding="utf-8-sig", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    if not isinstance(item, dict):
                        raise ValueError("JSONL record must be an object")
                    events.append(_event_from_mapping(item, str(source), str(number)))
                except (json.JSONDecodeError, ValueError) as exc:
                    issues.append(ParseIssue(str(number), str(exc)))
        return IngestionResult(tuple(events), tuple(issues))

    with source.open("r", encoding="utf-8-sig", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            match = RFC3164.match(line.strip())
            iso_match = ISO_SYSLOG.match(line.strip())
            if not match and iso_match:
                match = iso_match
                stamp = match.group("stamp")
            elif match:
                try:
                    stamp = datetime.strptime(f"{datetime.now(timezone.utc).year} {match.group('stamp')}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
                except ValueError as exc:
                    issues.append(ParseIssue(str(number), f"Invalid syslog timestamp: {exc}"))
                    continue
            if match:
                message = match.group("message")
                failed = re.search(r"failed (?:password|login)(?: for)? (?:invalid user )?(?P<user>\S+).*?(?:from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?", message, re.I)
                succeeded = re.search(r"(?:accepted password|successful login) for (?P<user>\S+).*?from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})", message, re.I)
                login = failed or succeeded
                events.append(_event_from_mapping({"timestamp": stamp, "host": match.group("host"),
                    "message": message, "event_type": "failed_login" if failed else "successful_login" if succeeded else "syslog",
                    "username": login.group("user") if login else None,
                    "source_ip": login.group("ip") if login else None}, str(source), str(number)))
            else:
                issues.append(ParseIssue(str(number), "Line does not match supported syslog format"))
    return IngestionResult(tuple(events), tuple(issues))
