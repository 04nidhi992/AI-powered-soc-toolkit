import logging
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from soc_toolkit.config import DEFAULT_CONFIG
from soc_toolkit.investigation import add_investigation_note, create_incident, incident_timeline
from soc_toolkit.models import Incident, InvestigationNote, NormalizedEvent, SecurityAlert, SystemSnapshot
from soc_toolkit.storage import Storage


PROJECT = Path(__file__).resolve().parents[1]


def _event(event_id: str, timestamp: str, evidence_ref: str, source: str = "auth.evtx") -> NormalizedEvent:
    return NormalizedEvent(timestamp, source, "failed_login", "HIGH", f"Failed login {event_id}",
                           host="workstation", username="demo-user", evidence_ref=evidence_ref,
                           event_id=event_id)


class CaseManagementTests(unittest.TestCase):
    def test_case_lifecycle_notes_links_and_history_survive_storage_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "cases.sqlite3"
            linked_event = _event("linked-event", "2026-06-01T10:00:00-04:00", "auth.evtx:Record 4")
            unrelated_event = _event("other-event", "2026-06-01T10:01:00-04:00", "other.evtx:Record 2", "other.evtx")
            linked_alert = SecurityAlert("2026-06-01T14:02:00Z", "HIGH", "rule-engine",
                "Repeated login failures", "Threshold reached", "REPEATED_FAILED_LOGINS",
                evidence_refs=(linked_event.evidence_ref,))
            unrelated_alert = SecurityAlert("2026-06-01T14:03:00Z", "LOW", "rule-engine",
                "Unrelated finding", "Separate evidence", "OTHER_RULE", evidence_refs=("other.evtx:Record 2",))

            with Storage(database) as store:
                store.save_events([linked_event, unrelated_event])
                store.save_alert(linked_alert)
                store.save_alert(unrelated_alert)
                incident = create_incident("Authentication investigation",
                    [linked_alert, linked_alert], [linked_event, linked_event],
                    "Observed repeated failures", "Review the linked records")
                self.assertEqual((linked_alert.alert_id,), incident.alert_ids)
                self.assertEqual((linked_event.event_id,), incident.event_refs)
                store.save_incident(incident)
                note = add_investigation_note(store, incident.incident_id, "Analyst",
                    "observed_fact", "Reviewed the source event references.")
                self.assertTrue(store.update_incident_status(incident.incident_id, "investigating"))
                self.assertTrue(store.update_incident_status(incident.incident_id, "resolved"))
                self.assertFalse(store.update_incident_status("missing-case", "resolved"))
                with self.assertRaisesRegex(ValueError, "Unsupported incident status"):
                    store.update_incident_status(incident.incident_id, "closed")
                self.assertEqual("resolved", store.list_incidents()[0].status)

            with Storage(database) as reopened:
                stored_case = reopened.list_incidents()[0]
                self.assertEqual(incident.incident_id, stored_case.incident_id)
                self.assertEqual((linked_event.event_id,), stored_case.event_refs)
                self.assertEqual((linked_alert.alert_id,), stored_case.alert_ids)
                self.assertEqual(note.note_id, reopened.list_notes(incident.incident_id)[0].note_id)
                history = reopened.list_status_history("incident", incident.incident_id)
                self.assertEqual([("open", "investigating"), ("investigating", "resolved")],
                    [(item["old_status"], item["new_status"]) for item in history])

    def test_timeline_is_utc_chronological_deduplicated_and_evidence_linked(self):
        with tempfile.TemporaryDirectory() as folder, Storage(Path(folder) / "timeline.sqlite3") as store:
            event = _event("event-1", "2026-06-01T15:00:00-05:00", "auth.evtx:Record 9")
            unrelated = _event("event-other", "2026-06-01T10:00:00Z", "other.evtx:Record 1", "other.evtx")
            alert = SecurityAlert("2026-06-01T21:00:00+01:00", "HIGH", "rule-engine", "Observed finding",
                "Evidence-linked rule", "AUTH_RULE", evidence_refs=("auth.evtx:Record 9",))
            store.save_events([event, event, unrelated])
            store.save_alert(alert)
            store.save_alert(SecurityAlert("2026-06-01T10:05:00Z", "LOW", "other", "Unrelated alert"))
            incident = Incident("case-1", "Timeline case", "2026-06-01T22:00:00+02:00",
                alert_ids=(alert.alert_id, "missing-alert"),
                event_refs=(event.event_id, event.event_id, "missing-event"))
            store.save_incident(incident)
            note = InvestigationNote("note-1", incident.incident_id, "2026-06-01T16:30:00-04:00",
                "Analyst", "observed_fact", "Timestamped review note")
            store.add_note(note)
            store.update_incident_status(incident.incident_id, "investigating")

            timeline = incident_timeline(store, incident)
            parsed_times = [datetime.fromisoformat(item["timestamp"]) for item in timeline]
            self.assertEqual(parsed_times, sorted(parsed_times))
            self.assertEqual(["incident", "alert", "event", "observed_fact"],
                [item["kind"] for item in timeline[:4]])
            self.assertEqual(1, sum(item["kind"] == "event" for item in timeline))
            self.assertEqual(1, sum(item["kind"] == "alert" for item in timeline))
            event_entry = next(item for item in timeline if item["kind"] == "event")
            self.assertEqual("auth.evtx", event_entry["source"])
            self.assertEqual("auth.evtx:Record 9", event_entry["evidence_refs"])
            alert_entry = next(item for item in timeline if item["kind"] == "alert")
            self.assertEqual("rule-engine", alert_entry["source"])
            self.assertEqual("auth.evtx:Record 9", alert_entry["evidence_refs"])
            self.assertIn("case_status", [item["kind"] for item in timeline])
            self.assertNotIn("other.evtx", " ".join(item["source"] for item in timeline))
            self.assertNotIn("missing-event", " ".join(item["detail"] for item in timeline))

    def test_empty_case_history_and_missing_timestamps_are_handled_explicitly(self):
        with tempfile.TemporaryDirectory() as folder, Storage(Path(folder) / "empty.sqlite3") as store:
            incident = Incident("empty", "Empty case", "2026-06-01T12:00:00-04:00")
            self.assertEqual("2026-06-01T16:00:00+00:00", incident.created_at)
            self.assertEqual(["incident"], [item["kind"] for item in incident_timeline(store, incident)])
            with self.assertRaisesRegex(ValueError, "Incident timestamp"):
                Incident("bad", "Missing timestamp", "")
            with self.assertRaisesRegex(ValueError, "Investigation note timestamp"):
                InvestigationNote("note", incident.incident_id, "", "Analyst", "observed_fact", "No time")
            with self.assertRaisesRegex(ValueError, "Event timestamp"):
                NormalizedEvent("", "source", "event", "INFO", "Missing time")

    def test_dashboard_can_create_a_case_link_evidence_and_render_its_timeline(self):
        event = _event("dashboard-event", "2026-06-01T10:00:00Z", "dashboard.log:5")
        alert = SecurityAlert("2026-06-01T10:01:00Z", "HIGH", "rule-engine", "Dashboard finding",
            "Evidence available", "DASHBOARD_RULE", evidence_refs=(event.evidence_ref,))
        snapshot = SystemSnapshot("2026-06-01T10:00:00Z", "test-host", "Windows test", 12, 34, 56, 3600)

        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "dashboard.sqlite3"
            with Storage(database) as seed:
                seed.save_event(event)
                seed.save_alert(alert)
            config = replace(DEFAULT_CONFIG, data_dir=Path(folder), database_path=database)
            try:
                with patch("soc_toolkit.config.DEFAULT_CONFIG", config), \
                     patch("soc_toolkit.logging_config.configure_app_logging", return_value=logging.getLogger("case-app-test")), \
                     patch("soc_toolkit.monitoring.collect_system_snapshot", return_value=snapshot), \
                     patch("soc_toolkit.monitoring.collect_processes", return_value=[]):
                    app = AppTest.from_file(str(PROJECT / "soc_toolkit" / "dashboard.py"))
                    app.run(timeout=20)
                    app.sidebar.radio[0].set_value("Incidents")
                    app.run(timeout=20)
                    self.assertFalse(app.exception)
                    next(item for item in app.text_input if item.label == "Incident title").set_value("AppTest case")
                    next(item for item in app.multiselect if item.label == "Link alerts").set_value([alert.alert_id])
                    next(item for item in app.multiselect if item.label == "Link events").set_value([event.event_id])
                    next(item for item in app.form_submit_button if item.label == "Create incident").click()
                    app.run(timeout=20)
                    self.assertFalse(app.exception)
                    self.assertTrue(any("Created incident" in item.value for item in app.success))
                    timeline_frames = [frame.value for frame in app.dataframe
                                       if hasattr(frame.value, "columns") and "kind" in frame.value.columns]
                    self.assertTrue(any("event" in frame["kind"].tolist() and
                                        "dashboard.log:5" in " ".join(frame["evidence_refs"].astype(str))
                                        for frame in timeline_frames))
                    next(item for item in app.selectbox if item.label == "Incident status").set_value("resolved")
                    app.run(timeout=20)
                    next(item for item in app.button if item.label == "Update incident").click()
                    app.run(timeout=20)
                    self.assertFalse(app.exception)
                    next(item for item in app.text_area if item.label == "Investigation note").set_value(
                        "Reviewed linked dashboard evidence")
                    next(item for item in app.form_submit_button if item.label == "Add note").click()
                    app.run(timeout=20)
                    self.assertFalse(app.exception)
            finally:
                import streamlit as st
                import gc
                st.cache_resource.clear()
                gc.collect()

            with Storage(database) as reopened:
                self.assertEqual(1, len(reopened.list_incidents()))
                case = reopened.list_incidents()[0]
                self.assertEqual((alert.alert_id,), case.alert_ids)
                self.assertEqual((event.event_id,), case.event_refs)
                self.assertEqual("resolved", case.status)
                self.assertEqual("Reviewed linked dashboard evidence",
                                 reopened.list_notes(case.incident_id)[0].content)


if __name__ == "__main__":
    unittest.main()
