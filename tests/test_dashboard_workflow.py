import gc
import json
import logging
import tempfile
import unittest
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader
from streamlit.testing.v1 import AppTest

from soc_toolkit.config import DEFAULT_CONFIG
from soc_toolkit.models import SystemSnapshot
from soc_toolkit.storage import Storage


PROJECT = Path(__file__).resolve().parents[1]
DASHBOARD = PROJECT / "soc_toolkit" / "dashboard.py"
SYNTHETIC_LOG = PROJECT / "sample_data" / "synthetic_auth_demo.log"


class DashboardWorkflowTests(unittest.TestCase):
    def _app(self, database: Path, folder: str) -> AppTest:
        config = replace(DEFAULT_CONFIG, data_dir=Path(folder), database_path=database)
        patchers = [
            patch("soc_toolkit.config.DEFAULT_CONFIG", config),
            patch("soc_toolkit.logging_config.configure_app_logging",
                  return_value=logging.getLogger("dashboard-workflow-test")),
            patch("soc_toolkit.monitoring.collect_system_snapshot", return_value=SystemSnapshot(
                "2026-10-01T00:00:00Z", "test-host", "Windows test", 10, 20, 30, 3600)),
            patch("soc_toolkit.monitoring.collect_processes", return_value=[]),
        ]
        for patcher in patchers:
            patcher.start()
        app = AppTest.from_file(str(DASHBOARD))
        app.run(timeout=20)
        app._workflow_patchers = patchers
        return app

    def test_synthetic_log_to_case_report_download_elements(self):
        import streamlit as st

        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "workflow.sqlite3"
            try:
                app = self._app(database, folder)
                app.sidebar.radio[0].set_value("Log Analysis")
                app.run(timeout=20)
                self.assertFalse(app.exception)

                uploader = app.get("file_uploader")[0]
                uploader.upload(SYNTHETIC_LOG.name, SYNTHETIC_LOG.read_bytes(), "text/plain")
                app.run(timeout=20)
                next(item for item in app.button if item.label == "Parse and analyze").click()
                app.run(timeout=20)
                self.assertFalse(app.exception)
                self.assertTrue(any("Parsed 8 event(s)" in item.value and
                                    "created 6 new alert(s)" in item.value for item in app.success))

                with Storage(database) as store:
                    events = store.list_events(100)
                    alerts = store.list_alerts(limit=100)
                    self.assertEqual(8, len(events))
                    self.assertEqual({"synth-soc-lab"}, {event.host for event in events})
                    self.assertEqual({"syslog", "failed_login", "successful_login"},
                                     {event.event_type for event in events})
                    self.assertEqual({"REPEATED_FAILED_LOGINS", "FAILED_THEN_SUCCESS"},
                                     {alert.rule_id for alert in alerts})
                    self.assertEqual(6, len(alerts))
                    repeated = next(alert for alert in alerts if alert.rule_id == "REPEATED_FAILED_LOGINS")
                    selected_alert_ids = [repeated.alert_id]
                    selected_event_ids = list(repeated.evidence_refs)

                app.sidebar.radio[0].set_value("Incidents")
                app.run(timeout=20)
                next(item for item in app.text_input if item.label == "Incident title").set_value(
                    "Synthetic authentication investigation")
                next(item for item in app.multiselect if item.label == "Link alerts").set_value(
                    selected_alert_ids)
                next(item for item in app.multiselect if item.label == "Link events").set_value(
                    selected_event_ids)
                next(item for item in app.form_submit_button if item.label == "Create incident").click()
                app.run(timeout=20)
                self.assertFalse(app.exception)
                self.assertTrue(any("Created incident" in item.value for item in app.success),
                                f"errors={ [item.value for item in app.error] }; "
                                f"success={ [item.value for item in app.success] }")

                with Storage(database) as store:
                    incident = store.list_incidents()[0]
                    self.assertEqual(tuple(selected_alert_ids), incident.alert_ids)
                    self.assertEqual(set(selected_event_ids), set(incident.event_refs))

                app.sidebar.radio[0].set_value("Reports")
                app.run(timeout=20)
                next(item for item in app.button if item.label == "Build report").click()
                app.run(timeout=20)
                self.assertFalse(app.exception)
                self.assertEqual({"Download Markdown", "Download JSON", "Download PDF"},
                                 {item.label for item in app.get("download_button")})

                state_key = f"_soc_case_report_{incident.incident_id}_1_0"
                markdown, payload, pdf_bytes = app.session_state[state_key]
                self.assertIn("Synthetic authentication investigation", markdown)
                self.assertIn("REPEATED_FAILED_LOGINS", markdown)
                self.assertIn("## timeline", markdown.casefold())
                json_text = json.dumps(payload, ensure_ascii=False)
                self.assertIn("REPEATED_FAILED_LOGINS", json_text)
                self.assertEqual(5, payload["scope"]["linked_events"])
                pdf = PdfReader(BytesIO(pdf_bytes))
                self.assertTrue(pdf.pages)
                pdf_text = "\n".join(page.extract_text() or "" for page in pdf.pages)
                self.assertIn("REPEATED_FAILED_LOGINS", pdf_text)
                self.assertIn("Synthetic authentication investigation", pdf_text)
            finally:
                for patcher in reversed(getattr(locals().get("app"), "_workflow_patchers", [])):
                    patcher.stop()
                st.cache_resource.clear()
                gc.collect()

    def test_invalid_log_and_empty_investigation_have_safe_ui_states(self):
        import streamlit as st

        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "invalid.sqlite3"
            try:
                app = self._app(database, folder)
                app.sidebar.radio[0].set_value("Log Analysis")
                app.run(timeout=20)
                app.get("file_uploader")[0].upload(
                    "malformed.log", b"not a supported syslog record\n", "text/plain")
                app.run(timeout=20)
                next(item for item in app.button if item.label == "Parse and analyze").click()
                app.run(timeout=20)
                self.assertFalse(app.exception)
                self.assertTrue(any("Parsed 0 event(s)" in item.value for item in app.success))
                self.assertTrue(any("could not be parsed" in item.value for item in app.warning))
                with Storage(database) as store:
                    self.assertEqual(0, store.count_events())
                    self.assertEqual(0, store.count_alerts())

                app.sidebar.radio[0].set_value("Reports")
                app.run(timeout=20)
                self.assertTrue(any("Create an incident before generating" in item.value for item in app.info))

                app.sidebar.radio[0].set_value("Incidents")
                app.run(timeout=20)
                next(item for item in app.form_submit_button if item.label == "Create incident").click()
                app.run(timeout=20)
                self.assertFalse(app.exception)
                self.assertTrue(any("Incident title is required" in item.value for item in app.error))
                with Storage(database) as store:
                    self.assertEqual([], store.list_incidents())
            finally:
                for patcher in reversed(getattr(locals().get("app"), "_workflow_patchers", [])):
                    patcher.stop()
                st.cache_resource.clear()
                gc.collect()


if __name__ == "__main__":
    unittest.main()
