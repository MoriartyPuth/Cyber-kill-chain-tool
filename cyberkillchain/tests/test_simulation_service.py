import unittest

from services.simulation_service import SimulationService


class _DummySession(dict):
    modified = False


class SimulationServiceTests(unittest.TestCase):
    def test_calculate_upgrade_roi(self):
        svc = SimulationService(
            {
                "session": _DummySession({"upgrades_purchased": {"SIEM Upgrade": 2}}),
                "UPGRADES": {"SIEM Upgrade": {"cost": 100, "roi": 2.5}},
            }
        )
        roi = svc.calculate_upgrade_roi()
        self.assertIn("SIEM Upgrade", roi)
        self.assertEqual(roi["SIEM Upgrade"]["cost"], 200)
        self.assertEqual(roi["SIEM Upgrade"]["total_roi"], 500.0)

    def test_run_simulation_for_guest_updates_session_history(self):
        session = _DummySession({"history": [], "upgrades": {}})
        recorded = []
        svc = SimulationService(
            {
                "session": session,
                "get_simulation_fn": lambda _attack_type, variant="standard": ([{"stage": "Delivery", "status": "Detected"}], 80, ["Delivery"], []),
                "index_simulation_events_fn": lambda *args, **kwargs: recorded.append(("index", args, kwargs)),
                "record_threat_discovery_fn": lambda *args, **kwargs: recorded.append(("threat", args, kwargs)),
            }
        )
        events, score, weakest, _recs = svc.run_simulation_for_user("Phishing", user_id=None)
        self.assertEqual(score, 80)
        self.assertEqual(len(events), 1)
        self.assertEqual(len(weakest), 1)
        self.assertEqual(len(session["history"]), 1)
        self.assertTrue(session.modified)
        self.assertGreaterEqual(len(recorded), 2)


if __name__ == "__main__":
    unittest.main()
