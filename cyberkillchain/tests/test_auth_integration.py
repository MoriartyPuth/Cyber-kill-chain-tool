import unittest

import app as app_module


class AuthIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app_module.app.config["TESTING"] = True
        app_module.app.config["WTF_CSRF_ENABLED"] = False
        cls.app = app_module.app
        cls.client = app_module.app.test_client()

    def _register(self, username, password="SecurePass1", email=None):
        email = email or f"{username}@test.com"
        return self.client.post(
            "/register",
            data={"username": username, "email": email, "password": password},
            follow_redirects=False,
        )

    def _login(self, username, password="SecurePass1"):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )

    # --- Registration ---

    def test_register_redirects_on_success(self):
        with self.app.test_client() as c:
            resp = self._register_with_client(c, "newuser_reg")
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/", resp.location)

    def test_register_rejects_short_password(self):
        with self.app.test_client() as c:
            resp = self._register_with_client(c, "shortpwuser", password="abc")
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/register", resp.location)

    def test_register_rejects_invalid_username(self):
        with self.app.test_client() as c:
            resp = self._register_with_client(c, "bad user!", password="SecurePass1")
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/register", resp.location)

    def test_register_rejects_invalid_email(self):
        with self.app.test_client() as c:
            resp = c.post(
                "/register",
                data={"username": "emailuser", "email": "notanemail", "password": "SecurePass1"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/register", resp.location)

    def test_register_duplicate_username_rejected(self):
        with self.app.test_client() as c:
            self._register_with_client(c, "dupuser99")
            resp = self._register_with_client(c, "dupuser99")
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/register", resp.location)

    # --- Login ---

    def test_login_with_correct_credentials(self):
        uname = "logintest_ok"
        with self.app.test_client() as c:
            self._register_with_client(c, uname)
            resp = c.post(
                "/login",
                data={"username": uname, "password": "SecurePass1"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/", resp.location)

    def test_login_with_wrong_password_rejected(self):
        uname = "logintest_bad"
        with self.app.test_client() as c:
            self._register_with_client(c, uname)
            resp = c.post(
                "/login",
                data={"username": uname, "password": "WrongPassword"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Invalid", resp.data)

    def test_login_nonexistent_user_rejected(self):
        with self.app.test_client() as c:
            resp = c.post(
                "/login",
                data={"username": "ghostuser_xyz", "password": "anything"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Invalid", resp.data)

    # --- Protected routes ---

    def test_dashboard_requires_auth(self):
        with self.app.test_client() as c:
            resp = c.get("/", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.location)

    def test_simulate_requires_auth(self):
        with self.app.test_client() as c:
            resp = c.post("/simulate", data={"attack": "Phishing"}, follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.location)

    def test_upgrade_requires_auth(self):
        with self.app.test_client() as c:
            resp = c.post("/upgrade", data={"item": "Advanced Firewall"}, follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.location)

    def test_export_requires_auth(self):
        with self.app.test_client() as c:
            resp = c.get("/export/simulations", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.location)

    def test_logout_clears_session(self):
        uname = "logouttest"
        with self.app.test_client() as c:
            self._register_with_client(c, uname)
            c.get("/logout", follow_redirects=False)
            resp = c.get("/", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.location)

    # --- Password hashing verification ---

    def test_password_not_stored_in_plaintext(self):
        uname = "hashcheck"
        with self.app.test_client() as c:
            self._register_with_client(c, uname)
        with self.app.app_context():
            from models import User
            user = User.query.filter_by(username=uname).first()
            if user:
                self.assertNotEqual(user.password_hash, "SecurePass1")
                self.assertTrue(user.password_hash.startswith(("pbkdf2:", "scrypt:", "$2b$")))

    def _register_with_client(self, c, username, password="SecurePass1", email=None):
        email = email or f"{username}@test.com"
        return c.post(
            "/register",
            data={"username": username, "email": email, "password": password},
            follow_redirects=False,
        )


if __name__ == "__main__":
    unittest.main()
