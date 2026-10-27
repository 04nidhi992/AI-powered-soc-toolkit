import logging
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from soc_toolkit.config import DEFAULT_CONFIG
from soc_toolkit.investigation import create_incident
from soc_toolkit.models import NormalizedEvent, SecurityAlert, SystemSnapshot
from soc_toolkit.storage import Storage


PROJECT = Path(__file__).resolve().parents[1]


class DashboardAIInvestigationTests(unittest.TestCase):
    def test_settings_assistant_renders_grounded_summary_and_persists_offline_audit(self):
        events = [NormalizedEvent(f"2026-07-01T12:00:0{index}Z", "auth.log", "failed_login", "HIGH",
            f"Synthetic failure {index}", host="host-a", username="demo-user",
            evidence_ref=f"auth.log:{index}", event_id=f"event-{index}") for index in (1, 2)]
        alert = SecurityAlert("2026-07-01T12:01:00Z", "HIGH", "detection", "Repeated failed logins",
            "Repeated threshold met", "REPEATED_FAILED_LOGINS", alert_id="assistant-alert",
            evidence_refs=tuple(event.event_id for event in events),
            recommended_steps=("Review the linked authentication events.",))
        snapshot = SystemSnapshot("2026-07-01T12:00:00Z", "test-host", "Windows test", 10, 20, 30, 3600)

        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "assistant.sqlite3"
            with Storage(database) as seed:
                seed.save_events(events)
                seed.save_alert(alert)
                incident = create_incident("Assistant case", [alert], events,
                    "Synthetic alert-linked case", "Check adjacent events.")
                seed.save_incident(incident)
            config = replace(DEFAULT_CONFIG, data_dir=Path(folder), database_path=database)
            try:
                with patch("soc_toolkit.config.DEFAULT_CONFIG", config), \
                     patch("soc_toolkit.logging_config.configure_app_logging", return_value=logging.getLogger("assistant-app-test")), \
                     patch("soc_toolkit.monitoring.collect_system_snapshot", return_value=snapshot), \
                     patch("soc_toolkit.monitoring.collect_processes", return_value=[]), \
                     patch.dict(os.environ, {"SOC_AI_ENABLED": "false", "SOC_AI_ENDPOINT": ""}):
                    app = AppTest.from_file(str(PROJECT / "soc_toolkit" / "dashboard.py"))
                    app.run(timeout=20)
                    app.sidebar.radio[0].set_value("Settings")
                    app.run(timeout=20)
                    self.assertFalse(app.exception)
                    next(item for item in app.selectbox if item.label == "Related case (optional)").set_value(incident)
                    app.run(timeout=20)
                    next(item for item in app.button if item.label == "Build investigation summary").click()
                    app.run(timeout=20)
                    self.assertFalse(app.exception)
                    markdown = " ".join(item.value for item in app.markdown)
                    self.assertIn("Observed facts", markdown)
                    self.assertIn("Supporting evidence", markdown)
                    self.assertIn("Uncertainties", markdown)
                    self.assertIn("Potential MITRE ATT&CK mapping", markdown)
                    self.assertTrue(any(any(record.get("technique_id") == "T1110"
                        for record in frame.value.to_dict("records"))
                        for frame in app.dataframe if hasattr(frame.value, "to_dict")))
            finally:
                import streamlit as st
                import gc
                st.cache_resource.clear()
                gc.collect()

            with Storage(database) as reopened:
                activity = reopened.list_ai_activity(incident.incident_id)
                self.assertEqual(1, len(activity))
                self.assertEqual("offline", activity[0].status)
                self.assertEqual((), activity[0].transmitted_fields)
                self.assertEqual(tuple(sorted({reference for event in events
                    for reference in (event.event_id, event.evidence_ref)})), activity[0].evidence_refs)


if __name__ == "__main__":
    unittest.main()
