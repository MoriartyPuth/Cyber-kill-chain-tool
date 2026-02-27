import unittest

from services.analytics_service import AnalyticsService


class AnalyticsServiceTests(unittest.TestCase):
    def setUp(self):
        self.svc = AnalyticsService({"kill_chain_data": [("Reconnaissance", "", "", "")]})

    def test_parse_history_time_iso(self):
        dt = self.svc.parse_history_time("2026-02-01T12:34:56")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)

    def test_case_timeline_exposes_values_for_templates(self):
        history = [{"_ts": "2026-02-20T10:00:00", "score": 50}]
        out = self.svc.case_timeline(history, days=3)
        self.assertIn("labels", out)
        self.assertIn("counts", out)
        self.assertIn("values", out)
        self.assertEqual(out["counts"], out["values"])


if __name__ == "__main__":
    unittest.main()
