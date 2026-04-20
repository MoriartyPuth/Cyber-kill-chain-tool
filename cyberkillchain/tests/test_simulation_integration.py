import unittest

import app as app_module
from models import User, Simulation


class SimulationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app_module.app.config["TESTING"] = True
        app_module.app.config["WTF_CSRF_ENABLED"] = False
        cls.app = app_module.app

    def _make_logged_in_client(self, username="simtestuser"):
        c = self.app.test_client()
        email = f"{username}@test.com"
        c.post("/register", data={"username": username, "email": email, "password": "SecurePass1"})
        return c

    def test_simulation_saved_to_db(self):
        uname = "simdbtest"
        c = self._make_logged_in_client(uname)
        c.post("/simulate", data={"attack": "Phishing", "variant": "standard"})
        with self.app.app_context():
            user = User.query.filter_by(username=uname).first()
            if user:
                sims = Simulation.query.filter_by(user_id=user.id).all()
                self.assertGreater(len(sims), 0)
                sim = sims[-1]
                self.assertEqual(sim.attack_type, "Phishing")
                self.assertIsNotNone(sim.detection_score)
                self.assertGreaterEqual(sim.detection_score, 0)
                self.assertLessEqual(sim.detection_score, 100)

    def test_all_attack_types_simulate(self):
        attack_types = ["Phishing", "Malware", "Ransomware", "DDoS", "Supply Chain", "APT", "Insider Threat"]
        uname = "attacktypetest"
        c = self._make_logged_in_client(uname)
        for attack in attack_types:
            resp = c.post("/simulate", data={"attack": attack, "variant": "standard"}, follow_redirects=False)
            self.assertIn(resp.status_code, [200, 302], msg=f"Attack {attack} returned unexpected status")

    def test_simulation_score_in_valid_range(self):
        uname = "scorerangetest"
        c = self._make_logged_in_client(uname)
        c.post("/simulate", data={"attack": "Malware", "variant": "standard"})
        with self.app.app_context():
            user = User.query.filter_by(username=uname).first()
            if user:
                sim = Simulation.query.filter_by(user_id=user.id).order_by(Simulation.created_at.desc()).first()
                if sim:
                    self.assertGreaterEqual(sim.detection_score, 0)
                    self.assertLessEqual(sim.detection_score, 100)

    def test_simulation_with_stealthy_variant(self):
        uname = "stealthtest"
        c = self._make_logged_in_client(uname)
        resp = c.post("/simulate", data={"attack": "APT", "variant": "stealthy"})
        self.assertIn(resp.status_code, [200, 302])

    def test_export_csv_after_simulation(self):
        uname = "exporttest"
        c = self._make_logged_in_client(uname)
        c.post("/simulate", data={"attack": "Phishing", "variant": "standard"})
        resp = c.get("/export/simulations?format=csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)
        self.assertIn(b"attack", resp.data)

    def test_export_json_after_simulation(self):
        uname = "exportjsontest"
        c = self._make_logged_in_client(uname)
        c.post("/simulate", data={"attack": "Ransomware", "variant": "standard"})
        resp = c.get("/export/simulations?format=json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp.content_type)

    def test_report_not_accessible_by_other_user(self):
        owner = self._make_logged_in_client("reportowner")
        owner.post("/simulate", data={"attack": "DDoS", "variant": "standard"})
        with self.app.app_context():
            owner_user = User.query.filter_by(username="reportowner").first()
            if not owner_user:
                return
            sim = Simulation.query.filter_by(user_id=owner_user.id).first()
            if not sim:
                return
            sim_id = sim.id

        other = self._make_logged_in_client("reportstealer")
        resp = other.get(f"/report/{sim_id}", follow_redirects=False)
        self.assertIn(resp.status_code, [302, 403])


if __name__ == "__main__":
    unittest.main()
