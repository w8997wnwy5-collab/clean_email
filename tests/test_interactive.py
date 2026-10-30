"""A whole menu session, as the user would type it on the phone."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
from unittest import mock

from clean_email import cli, credentials, security
from clean_email.imap import MailClient

from .dovecot_server import PASSWORD
from .helpers import DovecotTestCase, days_ago, mail

NEWSLETTER = {"List-Unsubscribe": "<https://example.com/unsubscribe>"}


class MenuTest(DovecotTestCase):
    user = "menu@example.com"

    def setUp(self):
        real = MailClient.connect
        server = self.server

        def connect(creds, **kwargs):
            return real(creds, host=server.host, port=server.port,
                        ssl_context=security.tls_context(cafile=server.cafile), allow_test_server=True)

        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        for patcher in (
            mock.patch.object(MailClient, "connect", staticmethod(connect)),
            mock.patch.dict(os.environ, {"ICLOUD_EMAIL": self.user, "ICLOUD_APP_PASSWORD": PASSWORD,
                                         "CLEAN_EMAIL_HOME": home.name}),
            mock.patch("sys.stdin.isatty", return_value=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def type_answers(self, *answers: str) -> str:
        pending = list(answers)

        def fake_input(prompt: str = "") -> str:
            print(prompt)
            if not pending:
                raise AssertionError(f"Unexpected question: {prompt}")
            return pending.pop(0)

        out = io.StringIO()
        with mock.patch("builtins.input", fake_input), contextlib.redirect_stdout(out):
            code = cli.main([])
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(pending, [], out.getvalue())
        return out.getvalue()

    def test_analyze_approve_and_apply(self):
        client = self.connect_as(self.user)
        for raw in (
            mail("Il Post <newsletter@ilpost.it>", "Prima", to=self.user, headers=NEWSLETTER),
            mail("Il Post <newsletter@ilpost.it>", "Seconda", to=self.user, headers=NEWSLETTER),
            mail("Zalando <news@zalando.ch>", "Saldi -50%", to=self.user, headers=NEWSLETTER),
            mail("PayPal <secure@paypa1-verify.xyz>", "Account sospeso, verifica il tuo account", to=self.user,
                 headers={"Authentication-Results": "mx; dmarc=fail"}),
            mail("Anna <anna@example.ch>", "Ci vediamo?", to=self.user),
        ):
            client.append("INBOX", raw, flags=None, when=days_ago(1))

        out = self.type_answers(
            "1",      # Analizza la posta
            "tutte",  # approve every proposal
            "s",      # always trash some senders?
            "2",      # Zalando (Il Post is first, with 2 mail)
            "",       # save (default yes)
            "",       # apply now (default yes)
            "s",      # go ahead
            "2",      # Le mie regole
            "",       # back
            "0",      # exit
        )
        self.assertIn("Proposte", out)
        self.assertIn("Fatto: 4 mail sistemate", out)
        self.assertEqual(self.messages_in(client, "INBOX"), ["Ci vediamo?"])
        self.assertEqual(self.messages_in(client, "Newsletter"), ["Prima", "Seconda"])
        self.assertEqual(self.messages_in(client, "Junk"), ["Account sospeso, verifica il tuo account"])
        self.assertEqual(self.messages_in(client, "Deleted Messages"), ["Saldi -50%"])
        self.assertIn("Mittenti da buttare", out)

    def test_first_run_asks_for_the_password_and_saves_it(self):
        os.environ.pop("ICLOUD_EMAIL")
        os.environ.pop("ICLOUD_APP_PASSWORD")
        with mock.patch("clean_email.ui.getpass.getpass", return_value=" ABCD-EFGH-IJKL-MNOP "):
            out = self.type_answers(
                "10",                 # Verifica la connessione sicura
                "nuovo@example.com",  # first run: address
                "",                   # save the credentials (default yes)
                "0",
            )
        self.assertIn("Accesso riuscito", out)
        self.assertIn("emesso da: commonName=Clean Email Test CA", out)
        saved = credentials.load()
        self.assertEqual((saved.email, saved.password), ("nuovo@example.com", PASSWORD))

