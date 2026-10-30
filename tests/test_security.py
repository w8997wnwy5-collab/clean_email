import os
import ssl
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clean_email import credentials, security
from clean_email.credentials import Credentials


class TlsPolicyTest(unittest.TestCase):
    def test_context_verifies_and_requires_tls12(self):
        ctx = security.tls_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_only_apple_imap(self):
        security.check_server("imap.mail.me.com", 993)
        for host, port in (("imap.mail.me.com", 143), ("imap.evil.example", 993), ("mail.me.com", 993)):
            with self.assertRaises(ValueError):
                security.check_server(host, port)

    def test_safe_text_strips_terminal_tricks(self):
        self.assertEqual(security.safe_text("Ciao\x1b[2J\x1b]0;pwned\x07 mondo"), "Ciao [2J ]0;pwned mondo")
        self.assertEqual(security.safe_text("evil‮txt.exe"), "evil txt.exe")
        self.assertEqual(security.safe_text("a" * 10, limit=5), "aaaa…")


class CredentialsTest(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.home = Path(home.name)
        patcher = mock.patch.dict(os.environ, {"CLEAN_EMAIL_HOME": str(self.home)}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in (credentials.ENV_EMAIL, credentials.ENV_PASSWORD):
            os.environ.pop(name, None)

    def test_login_name(self):
        self.assertEqual(Credentials("mario@icloud.com", "x").login, "mario@icloud.com")
        self.assertEqual(Credentials("mario@icloud.com", "x", username="mario").login, "mario")

    def test_app_password_format(self):
        self.assertTrue(credentials.looks_like_app_password(credentials.normalize_password(" ABCD-efgh-ijkl-mnop ")))
        self.assertFalse(credentials.looks_like_app_password("MiaPassword123!"))

    def test_saved_file_is_private_and_password_never_in_repr(self):
        creds = Credentials("me@icloud.com", "abcd-efgh-ijkl-mnop")
        self.assertNotIn("abcd", repr(creds))
        credentials.save(creds)
        mode = stat.S_IMODE((self.home / "password").stat().st_mode)
        self.assertEqual(mode, 0o600)
        loaded = credentials.load()
        self.assertEqual((loaded.email, loaded.password), (creds.email, creds.password))
        self.assertTrue(credentials.forget())
        self.assertIsNone(credentials.load())

    def test_environment_wins(self):
        credentials.save(Credentials("me@icloud.com", "abcd-efgh-ijkl-mnop"))
        ci = {credentials.ENV_EMAIL: "ci@icloud.com", credentials.ENV_PASSWORD: "wxyz-wxyz-wxyz-wxyz"}
        with mock.patch.dict(os.environ, ci):
            self.assertEqual(credentials.load().email, "ci@icloud.com")


if __name__ == "__main__":
    unittest.main()
