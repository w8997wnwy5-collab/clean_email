from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime

from clean_email import security
from clean_email.credentials import Credentials
from clean_email.imap import MailClient

from . import dovecot_server


def days_ago(days: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def mail(sender: str, subject: str, *, to: str = "utente@example.com", headers: dict | None = None,
         when: datetime | None = None) -> bytes:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = format_datetime(when or datetime.now(timezone.utc))
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@test.example>"
    for key, value in (headers or {}).items():
        msg[key] = value
    msg.set_content("Testo del messaggio.\n")
    return msg.as_bytes(policy=SMTP)


@unittest.skipUnless(dovecot_server.available(), "serve Dovecot (apt-get install dovecot-imapd) e openssl")
class DovecotTestCase(unittest.TestCase):
    server_options: dict = {}

    @classmethod
    def setUpClass(cls):
        cls.server = dovecot_server.DovecotServer(**cls.server_options).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def connect_as(self, user: str, password: str = dovecot_server.PASSWORD, context=None) -> MailClient:
        client = MailClient.connect(
            Credentials(user, password),
            host=self.server.host,
            port=self.server.port,
            ssl_context=context or security.tls_context(cafile=self.server.cafile),
            allow_test_server=True,
        )
        self.addCleanup(client.logout)
        return client

    @staticmethod
    def messages_in(client: MailClient, folder: str) -> list[str]:
        """Subjects in a folder, sorted."""
        client.folders(refresh=True)
        if client.find_folder(folder) is None:
            return []
        client.select(folder)
        return sorted(m.subject for m in client.fetch_headers(client.search("UNDELETED")))
