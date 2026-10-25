import json
import os
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

from soc_toolkit.ai_analysis import OpenAICompatibleProvider, explain_alert
from soc_toolkit.models import SecurityAlert


class AIProviderContractTests(unittest.TestCase):
    def setUp(self):
        self.alert = SecurityAlert.create(
            "HIGH", "detection", "username=alice sign-in failed", "Review the account", "AUTH_FAILURE"
        )
        self.provider = OpenAICompatibleProvider(
            "https://provider.example/v1/chat/completions", "SOC_TEST_API_KEY", "mock-model", True
        )

    def test_missing_key_falls_back_without_request(self):
        with patch.dict(os.environ, {}, clear=True), patch("soc_toolkit.ai_analysis.urlopen") as urlopen:
            result = explain_alert(self.alert, self.provider, enabled=True, explicit_consent=True)
        urlopen.assert_not_called()
        self.assertTrue(result.text.startswith("Rule AUTH_FAILURE matched:"))
        self.assertIn("Optional AI analysis failed", result.text)

    def test_insecure_external_endpoint_is_rejected_without_request(self):
        provider = OpenAICompatibleProvider(
            "http://provider.example/v1/chat/completions", "SOC_TEST_API_KEY", "mock-model", True
        )
        with patch.dict(os.environ, {"SOC_TEST_API_KEY": "test-only"}), \
                patch("soc_toolkit.ai_analysis.urlopen") as urlopen:
            result = explain_alert(self.alert, provider, enabled=True, explicit_consent=True)
        urlopen.assert_not_called()
        self.assertIn("External AI endpoints must use HTTPS", result.text)

    def test_timeout_and_rate_limit_use_offline_fallback(self):
        failures = (
            TimeoutError("simulated timeout"),
            HTTPError(self.provider.endpoint, 429, "Too Many Requests", {}, None),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), \
                    patch.dict(os.environ, {"SOC_TEST_API_KEY": "test-only"}), \
                    patch("soc_toolkit.ai_analysis.urlopen", side_effect=failure):
                result = explain_alert(self.alert, self.provider, enabled=True, explicit_consent=True)
            self.assertTrue(result.is_hypothesis)
            self.assertTrue(result.text.startswith("Rule AUTH_FAILURE matched:"))
            self.assertIn("Optional AI analysis failed", result.text)

    def test_success_sends_only_sanitized_selected_summary(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return json.dumps({"choices": [{"message": {"content": "Check related events"}}]}).encode()

        selected = ("password=hunter2 source 192.0.2.7",)
        with patch.dict(os.environ, {"SOC_TEST_API_KEY": "test-only"}), \
                patch("soc_toolkit.ai_analysis.urlopen", return_value=Response()) as urlopen:
            result = explain_alert(self.alert, self.provider, enabled=True, explicit_consent=True,
                                   selected_evidence=selected)
        request = urlopen.call_args.args[0]
        sent = request.data.decode("utf-8")
        self.assertNotIn("alice", sent)
        self.assertNotIn("hunter2", sent)
        self.assertNotIn("192.0.2.7", sent)
        self.assertEqual("test-only", request.get_header("Authorization").removeprefix("Bearer "))
        self.assertIn("Unverified AI hypothesis:", result.text)


if __name__ == "__main__":
    unittest.main()
