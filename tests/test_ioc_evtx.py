import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from soc_toolkit.ioc_extraction import extract_iocs_from_event, extract_iocs_from_events, extract_iocs_from_text
from soc_toolkit.log_analysis import ingest_log_file
from soc_toolkit.models import NormalizedEvent
from soc_toolkit.storage import Storage


class IOCExtractionTests(unittest.TestCase):
    def test_extracts_and_normalizes_supported_types_without_false_verdicts(self):
        text = ("connect https://Sub.Example.org/a?q=1, domain EXAMPLE.org "
                "public 8.8.8.8 private 192.168.1.4 v6 2001:4860:4860::8888 "
                "hashes " + "a" * 32 + " " + "b" * 40 + " " + "c" * 64 +
                " example example.com timestamp 2026-05-01T10:20:30Z 999.999.999.999")
        result = extract_iocs_from_text(text, "audit.log:7")
        by_key = {(item.indicator_type, item.value): item for item in result}
        self.assertIn(("URL", "https://sub.example.org/a?q=1"), by_key)
        self.assertIn(("IPv4", "8.8.8.8"), by_key)
        self.assertEqual("private", by_key[("IPv4", "192.168.1.4")].scope)
        self.assertIn(("IPv6", "2001:4860:4860::8888"), by_key)
        self.assertIn(("DOMAIN", "sub.example.org"), by_key)
        self.assertNotIn(("DOMAIN", "example.org"), by_key)
        self.assertNotIn(("DOMAIN", "example.com"), by_key)
        self.assertNotIn(("IPv4", "2026.5.1"), by_key)
        self.assertEqual({"MD5", "SHA-1", "SHA-256"}, {item.indicator_type for item in result if item.indicator_type in {"MD5", "SHA-1", "SHA-256"}})
        self.assertTrue(all(item.classification == "extracted" for item in result))
        self.assertTrue(all("audit.log:7" in item.evidence_refs for item in result))

    def test_event_indicators_deduplicate_across_events_and_retain_evidence(self):
        events = [
            NormalizedEvent("2026-05-01T00:00:00Z", "x", "log", "INFO", "connect 192.0.2.8",
                            source_ip="192.0.2.8", evidence_ref="x:1"),
            NormalizedEvent("2026-05-01T00:00:01Z", "x", "log", "INFO", "connect 192.0.2.8",
                            evidence_ref="x:2"),
        ]
        result = extract_iocs_from_events(events)
        self.assertEqual(1, len(result))
        self.assertEqual(("x:1", "x:2"), result[0].evidence_refs)
        self.assertEqual(("x:1",), extract_iocs_from_event(events[0])[0].evidence_refs)
        self.assertEqual("reserved_or_documentation", result[0].scope)

    def test_log_ingest_to_storage_ioc_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "evidence.jsonl"
            path.write_text('{"timestamp":"2026-05-01T00:00:00Z","message":"download https://bad.example.org/a 8.8.4.4 ' + "d" * 64 + '"}\n', encoding="utf-8")
            parsed = ingest_log_file(path)
            indicators = extract_iocs_from_events(list(parsed.events))
            with Storage(":memory:") as store:
                self.assertEqual(1, store.save_events(list(parsed.events)))
        self.assertEqual({"URL", "DOMAIN", "IPv4", "SHA-256"}, {item.indicator_type for item in indicators})
        self.assertTrue(all(item.evidence_refs == (parsed.events[0].evidence_ref,) for item in indicators))


class EVTXIngestionTests(unittest.TestCase):
    def _mock_evtx_module(self, records=None, failure=None):
        module = types.ModuleType("Evtx.Evtx")

        class Reader:
            def __init__(self, _path):
                if failure:
                    raise failure

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def records(self):
                return iter(records or [])

        module.Evtx = Reader
        package = types.ModuleType("Evtx")
        package.__path__ = []
        return {"Evtx": package, "Evtx.Evtx": module}

    def test_evtx_records_normalize_event_identity_and_data(self):
        xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
               '<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>'
               '<Level>0</Level><TimeCreated SystemTime="2026-05-01T00:00:00.000Z"/>'
               '<Computer>WORKSTATION-1</Computer></System><EventData>'
               '<Data Name="TargetUserName">demo</Data><Data Name="IpAddress">192.0.2.7</Data>'
               '<Data Name="LogonType">3</Data></EventData></Event>')

        class Record:
            def xml(self):
                return xml

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.evtx"
            path.write_bytes(b"synthetic test input")
            with patch.dict(sys.modules, self._mock_evtx_module([Record()])):
                result = ingest_log_file(path)
        self.assertEqual((), result.errors)
        self.assertEqual(1, len(result.events))
        event = result.events[0]
        self.assertEqual(("4625", "Microsoft-Windows-Security-Auditing", "WORKSTATION-1", "demo", "192.0.2.7"),
                         (event.event_type, event.raw_fields["provider"], event.host, event.username, event.source_ip))
        self.assertEqual("3", event.raw_fields["data_logontype"])

    def test_malformed_evtx_is_reported_and_size_limit_applies(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.evtx"
            path.write_bytes(b"bad")
            with patch.dict(sys.modules, self._mock_evtx_module(failure=ValueError("invalid header"))):
                result = ingest_log_file(path)
            self.assertFalse(result.events)
            self.assertIn("EVTX", result.errors[0].message)
            large = ingest_log_file(path, max_bytes=1)
            self.assertIn("limit", large.errors[0].message)

    def test_missing_parser_is_reported_instead_of_treating_evtx_as_text(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "missing.evtx"
            path.write_bytes(b"not text")
            with patch.dict(sys.modules, {"Evtx": None, "Evtx.Evtx": None}):
                result = ingest_log_file(path)
        self.assertFalse(result.events)
        self.assertIn("python-evtx", result.errors[0].message)


if __name__ == "__main__":
    unittest.main()
