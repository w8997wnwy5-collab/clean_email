"""End-to-end tests against a real IMAP server (Dovecot) over TLS."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from unittest import mock

from clean_email import cli, security
from clean_email.analysis import analyze, propose
from clean_email.credentials import Credentials
from clean_email.engine import Classifier, Engine, undo
from clean_email.imap import AuthError, CertificateError, MailClient, MailError
from clean_email.rules import RESERVED_FOLDER, Action, Match, Rule, RuleSet, insert_rule
from clean_email.store import DOC_HEADER, MailboxStore, load_journal, load_rules, save_journal, save_rules

from .dovecot_server import PASSWORD
from .helpers import DovecotTestCase, days_ago, mail

NEWSLETTER = {"List-Unsubscribe": "<https://example.com/unsubscribe>"}


def seed(client: MailClient, user: str) -> None:
    inbox = [
        (mail("Il Post <newsletter@ilpost.it>", "Le notizie di oggi", to=user, headers=NEWSLETTER), days_ago(2)),
        (mail("Il Post <newsletter@ilpost.it>", "Le notizie di due mesi fa", to=user, headers=NEWSLETTER),
         days_ago(60)),
        (mail("Zalando <news@zalando.ch>", "-30% su tutto, solo oggi", to=user, headers=NEWSLETTER), days_ago(1)),
        (mail("PayPal <secure@paypa1-verify.xyz>", "Account sospeso: verifica il tuo account", to=user,
              headers={"Authentication-Results": "mx.example; dmarc=fail header.from=paypa1-verify.xyz"}), days_ago(1)),
        (mail("Mario Rossi <mario.rossi@gmail.com>", "Cena sabato?", to=user), days_ago(1)),
        (mail("Amazon.it <conferma-spedizione@amazon.it>", "Il tuo ordine è stato spedito", to=user), days_ago(3)),
        (mail("LinkedIn <messages-noreply@linkedin.com>", "Hai un nuovo messaggio", to=user, headers=NEWSLETTER),
         days_ago(1)),
        (mail("Swisscom <noreply@swisscom.ch>", "Il tuo codice di accesso", to=user,
              headers={"Auto-Submitted": "auto-generated"}), days_ago(1)),
        (mail("Club <news@protetto.ch>", "Notizie del club", to=user, headers=NEWSLETTER), days_ago(1)),
    ]
    for raw, when in inbox:
        client.append("INBOX", raw, flags=None, when=when)
    client.append("Sent Messages", mail(user, "Ciao Mario", to="mario.rossi@gmail.com"), when=days_ago(10))


class ConnectionSecurityTest(DovecotTestCase):
    def test_refuses_a_certificate_the_system_does_not_trust(self):
        with self.assertRaises(CertificateError):
            self.connect_as("sicurezza@example.com", context=security.tls_context())

    def test_only_apple_server_without_the_test_switch(self):
        with self.assertRaises(ValueError):
            MailClient.connect(Credentials("a@example.com", PASSWORD), host=self.server.host, port=self.server.port)

    def test_refuses_contexts_that_skip_verification(self):
        context = security.tls_context(cafile=self.server.cafile)
        context.check_hostname = False
        with self.assertRaises(MailError):
            self.connect_as("sicurezza@example.com", context=context)

    def test_wrong_password(self):
        with self.assertRaises(AuthError):
            self.connect_as("sicurezza@example.com", password="wrong-pass-word-xxxx")

    def test_tls_details(self):
        info = self.connect_as("sicurezza@example.com").tls_info()
        self.assertIn(info["protocollo"], security.ACCEPTED_TLS_VERSIONS)
        self.assertIn("localhost", info["certificato"])


class EndToEndTest(DovecotTestCase):
    def test_analyze_save_apply_clean_and_undo(self):
        user = "e2e@example.com"
        client = self.connect_as(user)
        seed(client, user)

        analysis = analyze(client, Classifier(client), "INBOX", 1000)
        categories = {m.subject: c.category for m, c in analysis.items}
        self.assertEqual(categories["Le notizie di oggi"], "newsletter")
        self.assertEqual(categories["-30% su tutto, solo oggi"], "promozioni")
        self.assertEqual(categories["Account sospeso: verifica il tuo account"], "spam")
        self.assertEqual(categories["Cena sabato?"], "personale")
        self.assertEqual(categories["Il tuo ordine è stato spedito"], "acquisti")
        self.assertEqual(categories["Hai un nuovo messaggio"], "social")
        self.assertEqual(categories["Il tuo codice di accesso"], "notifiche")

        ruleset = RuleSet(protected=["news@protetto.ch"])
        for proposal in propose(analysis, ruleset):
            ruleset = insert_rule(ruleset, proposal.rule)
        self.assertEqual(ruleset.rules[0].action.kind, "junk")

        store = MailboxStore(lambda: client)
        save_rules(store, ruleset)
        save_rules(store, ruleset)  # replaces, never duplicates
        self.assertEqual(load_rules(store), ruleset)
        client.select(RESERVED_FOLDER)
        self.assertEqual(len(client.search("UNDELETED")), 1)

        engine = Engine(client, ruleset, Classifier(client), run="r1")
        outcome = engine.execute(engine.plan())
        self.assertFalse(outcome.errors)
        save_journal(store, load_journal(store).__class__(entries=outcome.journal))

        self.assertEqual(self.messages_in(client, "INBOX"), ["Cena sabato?", "Notizie del club"])
        self.assertEqual(self.messages_in(client, "Junk"), ["Account sospeso: verifica il tuo account"])
        self.assertEqual(self.messages_in(client, "Newsletter"), ["Le notizie di due mesi fa", "Le notizie di oggi"])
        self.assertEqual(self.messages_in(client, "Promozioni"), ["-30% su tutto, solo oggi"])
        self.assertEqual(self.messages_in(client, "Acquisti"), ["Il tuo ordine è stato spedito"])
        self.assertEqual(self.messages_in(client, "Social"), ["Hai un nuovo messaggio"])
        self.assertEqual(self.messages_in(client, "Notifiche"), ["Il tuo codice di accesso"])

        # A second, unattended run reaches the clean-up rule of «Newsletter».
        later = Engine(client, ruleset, Classifier(client), lookback_days=7, run="r2")
        outcome = later.run_all(limit=300)
        self.assertEqual(outcome.total, 1)
        self.assertEqual(self.messages_in(client, "Deleted Messages"), ["Le notizie di due mesi fa"])

        restored, missing, entries = undo(client, outcome.journal, now=datetime.now(timezone.utc), run="u1")
        self.assertEqual((restored, missing), (1, 0))
        self.assertEqual(entries[0].action, "restore")
        self.assertEqual(self.messages_in(client, "Deleted Messages"), [])
        self.assertIn("Le notizie di due mesi fa", self.messages_in(client, "Newsletter"))

    def test_rules_mailed_by_someone_else_are_ignored(self):
        user = "falso@example.com"
        client = self.connect_as(user)
        store = MailboxStore(lambda: client)
        mine = RuleSet([Rule("Mia", Match(senders=("@zalando.ch",)), Action("move", "Acquisti"))])
        save_rules(store, mine)

        forged = EmailMessage()
        forged["Received"] = "from evil.example by mx.example"
        forged["From"] = user
        forged["Subject"] = "Regole del bot (non cancellare)"
        forged[DOC_HEADER] = "rules"
        forged.set_content("x")
        evil = {"version": 1, "rules": [{"name": "Tutto", "match": {"subjects": ["re:"]}, "action": {"kind": "trash"}}]}
        forged.add_attachment(json.dumps(evil).encode(), maintype="application", subtype="json")
        client.append(RESERVED_FOLDER, forged.as_bytes(policy=SMTP))

        self.assertEqual(load_rules(store), mine)

    def test_rules_never_touch_protected_senders(self):
        user = "protetti@example.com"
        client = self.connect_as(user)
        client.append("INBOX", mail("Capo <capo@lavoro.ch>", "Riunione", to=user), flags=None)
        ruleset = RuleSet([Rule("Lavoro", Match(senders=("@lavoro.ch",)), Action("trash"))],
                          protected=["capo@lavoro.ch"])
        engine = Engine(client, ruleset, Classifier(client))
        plans = engine.plan()
        self.assertEqual(plans[0].protected, 1)
        self.assertEqual(engine.execute(plans).total, 0)
        self.assertEqual(self.messages_in(client, "INBOX"), ["Riunione"])

    def test_first_matching_rule_wins_even_with_nothing_to_do(self):
        user = "ordine@example.com"
        client = self.connect_as(user)
        client.append("INBOX", mail("Club <news@club.ch>", "Letta", to=user, headers=NEWSLETTER), flags=r"(\Seen)")
        client.append("INBOX", mail("Club <news@club.ch>", "Da leggere", to=user, headers=NEWSLETTER), flags=None)
        ruleset = RuleSet([
            Rule("Club letto", Match(senders=("@club.ch",)), Action("mark_read")),
            Rule("Newsletter", Match(categories=("newsletter",)), Action("move", "Newsletter")),
        ])
        for _ in range(2):  # the same result on every run
            outcome = Engine(client, ruleset, Classifier(client)).run_all()
            self.assertEqual(self.messages_in(client, "INBOX"), ["Da leggere", "Letta"])
        self.assertEqual(outcome.total, 0)
        client.select("INBOX")
        self.assertEqual(client.search("UNSEEN"), [])

    def test_over_limit_rules_are_skipped(self):
        user = "limite@example.com"
        client = self.connect_as(user)
        for n in range(3):
            client.append("INBOX", mail("Shop <promo@shop.ch>", f"Offerta {n}", to=user), flags=None)
        ruleset = RuleSet([Rule("Shop", Match(senders=("@shop.ch",)), Action("trash"))])
        outcome = Engine(client, ruleset, Classifier(client)).run_all(limit=2)
        self.assertEqual(outcome.over_limit, {1: 3})
        self.assertEqual(len(self.messages_in(client, "INBOX")), 3)

    def test_folder_names_with_accents_and_ampersand(self):
        client = self.connect_as("cartelle@example.com")
        client.append("INBOX", mail("A <a@b.ch>", "Ciao"), flags=None)
        client.select("INBOX", readonly=False)
        client.move(client.search("ALL"), client.ensure_folder("Società & Co/Ricevute").name)
        self.assertEqual(self.messages_in(client, "Società & Co/Ricevute"), ["Ciao"])


class WithoutMoveOrSpecialUseTest(DovecotTestCase):
    """Servers that do not announce MOVE or special-use folders (iCloud may not)."""

    server_options = {
        "special_use": False,
        "capabilities": "IMAP4rev1 LITERAL+ SASL-IR ID ENABLE IDLE NAMESPACE UNSELECT CHILDREN UIDPLUS ESEARCH",
    }

    def test_moves_with_copy_and_uid_expunge(self):
        user = "vecchio@example.com"
        client = self.connect_as(user)
        self.assertNotIn("MOVE", client.capabilities)
        self.assertEqual(client.special_folder("trash").name, "Deleted Messages")
        self.assertEqual(client.special_folder("junk").name, "Junk")
        client.append("INBOX", mail("Shop <promo@shop.ch>", "Offerta", to=user), flags=None)
        client.append("INBOX", mail("Amica <amica@example.ch>", "Ciao", to=user), flags=None)
        # Another app's message marked as deleted but not yet expunged must survive.
        client.select("INBOX", readonly=False)
        uids = client.search("ALL")
        client.set_flags([uids[1]], r"\Deleted")
        ruleset = RuleSet([Rule("Shop", Match(senders=("@shop.ch",)), Action("trash"))])
        outcome = Engine(client, ruleset, Classifier(client)).run_all()
        self.assertEqual(outcome.total, 1)
        self.assertEqual(self.messages_in(client, "Deleted Messages"), ["Offerta"])
        client.select("INBOX")
        self.assertEqual(client.search("ALL"), [uids[1]])


class CommandLineTest(DovecotTestCase):
    """The command line, connected to the test server instead of iCloud."""

    user = "cli@example.com"

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
            mock.patch("sys.stdin.isatty", return_value=False),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_commands(self):
        client = self.connect_as(self.user)
        client.append("INBOX", mail("Zalando <news@zalando.ch>", "Saldi", to=self.user, headers=NEWSLETTER), flags=None)
        client.append("INBOX", mail("Zalando <news@zalando.ch>", "Novità", to=self.user, headers=NEWSLETTER),
                      flags=None)

        code, out = self.run_cli("aggiungi", "--da", "@zalando.ch", "--sposta", "Shopping", "--si")
        self.assertEqual(code, 0, out)
        code, out = self.run_cli("regole", "--json")
        self.assertEqual(json.loads(out)["rules"][0]["action"], {"kind": "move", "folder": "Shopping"})

        code, out = self.run_cli("applica")
        self.assertIn("solo un'anteprima", out)
        self.assertEqual(len(self.messages_in(client, "INBOX")), 2)

        code, out = self.run_cli("automatico", "--prova")
        self.assertEqual(code, 0, out)
        self.assertIn("Regola 1: 2 mail (prova", out)

        code, out = self.run_cli("automatico")
        self.assertEqual(code, 0, out)
        self.assertNotIn("@", out)  # public log: numbers only
        self.assertNotIn("Shopping", out)
        self.assertEqual(self.messages_in(client, "Shopping"), ["Novità", "Saldi"])

        code, out = self.run_cli("registro")
        self.assertIn("spostata in «Shopping»", out)

        code, out = self.run_cli("cartelle")
        self.assertRegex(out, r"Shopping\s+2")

        code, out = self.run_cli("verifica")
        self.assertEqual(code, 0, out)
        self.assertIn("emesso da: commonName=Clean Email Test CA", out)

        code, out = self.run_cli("esporta-icloud")
        self.assertIn("Proviene da: @zalando.ch", out)

        code, out = self.run_cli("annulla", "--si")
        self.assertIn("Rimesse a posto 2 mail", out)
        self.assertEqual(self.messages_in(client, "INBOX"), ["Novità", "Saldi"])

        code, out = self.run_cli("annulla", "--si")
        self.assertIn("niente da annullare", out)

        # «Saldi» is a promotion, «Novità» a newsletter.
        code, out = self.run_cli("pulisci", "--categoria", "newsletter", "--categoria", "promozioni",
                                 "--cestina", "--esegui")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.messages_in(client, "Deleted Messages"), ["Novità", "Saldi"])

    def test_bad_rule_is_refused(self):
        code, out = self.run_cli("aggiungi", "--da", "ab", "--cestina", "--si")
        self.assertEqual(code, 1)
        self.assertIn("troppo corto", out)


if __name__ == "__main__":
    unittest.main()
