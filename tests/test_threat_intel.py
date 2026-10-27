import json
import os
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

from soc_toolkit.ioc_extraction import ExtractedIndicator
from soc_toolkit.threat_intel import VirusTotalProvider, enrich_indicators


class VirusTotalEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.indicator = ExtractedIndicator("IPv4", "8.8.8.8", ("auth.log:4",), scope="global")

    def provider(self):
        return VirusTotalProvider("SOC_TEST_VT_KEY", timeout_seconds=0.25, minimum_interval_seconds=0)

    def response(self, body):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return json.dumps(body).encode("utf-8")

        return Response()

    def http_error(self, code):
        return HTTPError("https://www.virustotal.com/", code, "status", {}, None)

    def test_success_reports_provider_source_stats_and_never_claims_confidence(self):
        body = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 3, "suspicious": 1, "harmless": 4, "undetected": 8}, "reputation": 2}}}
        with patch.dict(os.environ, {"SOC_TEST_VT_KEY": "test-secret"}), \
                patch("soc_toolkit.threat_intel.urlopen", return_value=self.response(body)) as open_url:
            result = self.provider().lookup(self.indicator)
        request = open_url.call_args.args[0]
        self.assertEqual("test-secret", request.get_header("X-apikey"))
        self.assertEqual("VirusTotal", result.source)
        self.assertEqual("found", result.status)
        self.assertIsNone(result.confidence)
        self.assertEqual(3, result.details["last_analysis_stats"]["malicious"])
        self.assertEqual(("auth.log:4",), result.evidence_refs)

    def test_no_match_timeout_rate_limit_invalid_credentials_and_unavailable(self):
        failures = ((404, "no_match"), (429, "rate_limited"), (401, "invalid_credentials"),
                    (403, "invalid_credentials"), (500, "error"))
        for code, expected in failures:
            with self.subTest(code=code), patch.dict(os.environ, {"SOC_TEST_VT_KEY": "test-secret"}), \
                    patch("soc_toolkit.threat_intel.urlopen", side_effect=self.http_error(code)):
                self.assertEqual(expected, self.provider().lookup(self.indicator).status)
        with patch.dict(os.environ, {"SOC_TEST_VT_KEY": "test-secret"}), \
                patch("soc_toolkit.threat_intel.urlopen", side_effect=TimeoutError()):
            self.assertEqual("timeout", self.provider().lookup(self.indicator).status)
        with patch.dict(os.environ, {"SOC_TEST_VT_KEY": "test-secret"}), \
                patch("soc_toolkit.threat_intel.urlopen", side_effect=OSError()):
            self.assertEqual("unavailable", self.provider().lookup(self.indicator).status)

    def test_malformed_provider_json_shapes_return_safe_error(self):
        payloads = (
            {"data": "unexpected"},
            {"data": {"attributes": {"last_analysis_stats": []}}},
            {"data": {"attributes": {"last_analysis_stats": {"malicious": "not-a-count"}}}},
        )
        with patch.dict(os.environ, {"SOC_TEST_VT_KEY": "test-secret"}):
            for payload in payloads:
                with self.subTest(payload=payload), patch(
                        "soc_toolkit.threat_intel.urlopen", return_value=self.response(payload)):
                    result = self.provider().lookup(self.indicator)
                self.assertEqual("error", result.status)
                self.assertEqual("Provider returned an invalid response.", result.summary)

    def test_missing_credentials_and_offline_mode_make_no_request(self):
        with patch.dict(os.environ, {}, clear=True), patch("soc_toolkit.threat_intel.urlopen") as open_url:
            missing = self.provider().lookup(self.indicator)
            offline = enrich_indicators((self.indicator,), self.provider(), external_enabled=False, explicit_consent=True)
            no_consent = enrich_indicators((self.indicator,), self.provider(), external_enabled=True, explicit_consent=False)
        open_url.assert_not_called()
        self.assertEqual("invalid_credentials", missing.status)
        self.assertEqual("offline", offline[0].status)
        self.assertEqual("local/offline", offline[0].source)
        self.assertEqual("offline", no_consent[0].status)
        self.assertIn("No reputation lookup was performed", offline[0].summary)

    def test_private_addresses_and_sensitive_urls_are_never_sent(self):
        indicators = (
            ExtractedIndicator("IPv4", "10.0.0.5", ("internal:1",), scope="private"),
            ExtractedIndicator("URL", "https://public.example/path?token=secret", ("web:2",)),
            ExtractedIndicator("DOMAIN", "host.internal", ("dns:3",)),
        )
        with patch.dict(os.environ, {"SOC_TEST_VT_KEY": "test-secret"}), \
                patch("soc_toolkit.threat_intel.urlopen") as open_url:
            results = tuple(self.provider().lookup(item) for item in indicators)
        open_url.assert_not_called()
        self.assertTrue(all(item.status == "skipped_sensitive" for item in results))

    def test_example_domain_and_url_subdomains_are_never_sent(self):
        indicators = (
            ExtractedIndicator("DOMAIN", "sub.example.org", ("dns:4",)),
            ExtractedIndicator("URL", "https://sub.example.com/", ("web:5",)),
        )
        with patch.dict(os.environ, {"SOC_TEST_VT_KEY": "test-secret"}), \
                patch("soc_toolkit.threat_intel.urlopen") as open_url:
            results = tuple(self.provider().lookup(item) for item in indicators)
        open_url.assert_not_called()
        self.assertTrue(all(item.status == "skipped_sensitive" for item in results))
        self.assertTrue(all("reserved" in item.summary or "example" in item.summary for item in results))

    def test_local_request_interval_prevents_provider_burst(self):
        body = {"data": {"attributes": {"last_analysis_stats": {}}}}
        provider = VirusTotalProvider("SOC_TEST_VT_KEY", minimum_interval_seconds=60)
        with patch.dict(os.environ, {"SOC_TEST_VT_KEY": "test-secret"}), \
                patch("soc_toolkit.threat_intel.time.monotonic", side_effect=[10.0, 11.0]), \
                patch("soc_toolkit.threat_intel.urlopen", return_value=self.response(body)) as open_url:
            first = provider.lookup(self.indicator)
            second = provider.lookup(self.indicator)
        self.assertEqual("found", first.status)
        self.assertEqual("rate_limited", second.status)
        open_url.assert_called_once()


if __name__ == "__main__":
    unittest.main()
