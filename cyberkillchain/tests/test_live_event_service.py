import unittest

from services.live_event_service import LiveEventService


class LiveEventServiceTests(unittest.TestCase):
    def setUp(self):
        self.svc = LiveEventService(
            {
                "kill_chain_data": [
                    ("Reconnaissance", "Nmap", "", ""),
                    ("Delivery", "Email Gateway", "", ""),
                ],
                "recommendations_map": {
                    "Delivery": {"improve": "Harden mail filtering", "response": "Quarantine suspicious attachments"}
                },
            }
        )

    def test_map_log_to_event_defaults_missed(self):
        out = self.svc.map_log_to_event({"kill_chain_stage": "Delivery", "detected": False, "tool": "Gateway"})
        self.assertEqual(out["status"], "Missed")
        self.assertEqual(out["stage"], "Delivery")

    def test_recommendations_for_missed_stage(self):
        recs = self.svc.recommendations_for_event({"stage": "Delivery", "status": "Missed"})
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["stage"], "Delivery")


if __name__ == "__main__":
    unittest.main()
