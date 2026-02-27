import unittest

import app as app_module


class RouteSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app_module.app.config["TESTING"] = True
        cls.client = app_module.app.test_client()

    def test_root_redirects_to_login_when_logged_out(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.location)

    def test_analytics_endpoint_returns_json(self):
        resp = self.client.get("/analytics")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertIn("analytics", body)
        self.assertIn("roi", body)

    def test_ai_live_brief_endpoint_available(self):
        resp = self.client.post("/ai/live/brief", json={"events": []})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertIn("summary", body)

    def test_presets_requires_auth(self):
        resp = self.client.get("/presets")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.location)


if __name__ == "__main__":
    unittest.main()
