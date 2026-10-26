import logging
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from streamlit.testing.v1 import AppTest

from soc_toolkit.config import DEFAULT_CONFIG
from soc_toolkit.models import SystemSnapshot


class DashboardSmokeTests(unittest.TestCase):
    def test_streamlit_dashboard_renders_overview_without_live_state_or_storage(self):
        snapshot = SystemSnapshot("2026-05-01T00:00:00+00:00", "test-host", "Windows test", 12, 34, 56, 3600)
        fake_storage = Mock()
        fake_storage.list_alerts.return_value = []
        fake_storage.list_events.return_value = []
        fake_storage.count_events.return_value = 0
        fake_storage.count_alerts.return_value = 0
        with tempfile.TemporaryDirectory() as directory:
            config = replace(DEFAULT_CONFIG, data_dir=Path(directory),
                             database_path=Path(directory) / "test.sqlite3")
            with patch("soc_toolkit.config.DEFAULT_CONFIG", config), \
                 patch("soc_toolkit.storage.Storage", return_value=fake_storage), \
                 patch("soc_toolkit.logging_config.configure_app_logging", return_value=logging.getLogger("smoke")), \
                 patch("soc_toolkit.monitoring.collect_system_snapshot", return_value=snapshot), \
                 patch("soc_toolkit.monitoring.collect_processes", return_value=[]):
                app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "soc_toolkit" / "dashboard.py"))
                app.run(timeout=20)
        self.assertFalse(app.exception)
        self.assertEqual(["AI-Powered SOC Toolkit"], [item.value for item in app.title])


if __name__ == "__main__":
    unittest.main()
