import contextlib
import io
import os
import unittest
from unittest import mock

from clean_email import ui


def environment(**values):
    """The current environment without a-Shell's markers, plus `values`."""
    env = {k: v for k, v in os.environ.items() if k not in ("TERM_PROGRAM", "APPNAME")}
    env.update(values)
    return mock.patch.dict(os.environ, env, clear=True)


class SecretInputTest(unittest.TestCase):
    def test_a_shell_reads_the_password_as_a_plain_line(self):
        # In a-Shell getpass never sees the Enter key: it must not be used.
        with environment(TERM_PROGRAM="a-Shell"), \
                mock.patch("builtins.input", return_value=" abcd-efgh-ijkl-mnop ") as typed, \
                mock.patch("clean_email.ui.getpass.getpass", side_effect=AssertionError("would hang")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(ui.ask_secret("Password: "), "abcd-efgh-ijkl-mnop")
        typed.assert_called_once_with("Password: ")
        self.assertIn("visibile", out.getvalue())

    def test_a_shell_mini(self):
        with environment(APPNAME="a-Shell-mini"):
            self.assertFalse(ui.can_hide_input())

    def test_other_iphone_terminals(self):
        with environment(), mock.patch("platform.machine", return_value="iPhone15,3"):
            self.assertFalse(ui.can_hide_input())

    def test_ordinary_terminals_hide_the_password(self):
        with environment(), mock.patch("platform.machine", return_value="x86_64"), \
                mock.patch("clean_email.ui.getpass.getpass", return_value="segreta") as hidden:
            self.assertTrue(ui.can_hide_input())
            self.assertEqual(ui.ask_secret("Password: "), "segreta")
        hidden.assert_called_once()


if __name__ == "__main__":
    unittest.main()
