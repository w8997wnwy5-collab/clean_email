import unittest

from clean_email.classifier import NO_CONTEXT, Context, classify
from clean_email.message import parse_header_block, registrable_domain


def headers(text: str, **kw):
    raw = (text.strip().replace("\n", "\r\n") + "\r\n\r\n").encode("utf-8")
    return parse_header_block(raw, uid=1, folder="INBOX", **kw)


BASE = "Message-ID: <x@y>\nDate: Mon, 1 Jan 2024 10:00:00 +0000\n"


class MessageParsingTest(unittest.TestCase):
    def test_encoded_words_folding_and_raw_utf8(self):
        msg = headers(
            "From: =?utf-8?q?Caff=C3=A8_Bar?= <Info@Caffe.CH>\n"
            "Subject: =?utf-8?b?UHJvbW96aW9uZSDwn46J?=\n =?utf-8?q?_finale?=\n"
            "To: a@b.ch, \"Rossi, Mario\" <m@r.it>\n"
        )
        self.assertEqual(msg.from_name, "Caffè Bar")
        self.assertEqual(msg.from_addr, "info@caffe.ch")
        self.assertEqual(msg.subject, "Promozione 🎉 finale")
        self.assertEqual(msg.recipients, ("a@b.ch", "m@r.it"))
        raw = headers("From: Zoë <zoe@example.ch>\nSubject: Ciao già")
        self.assertEqual((raw.from_name, raw.subject), ("Zoë", "Ciao già"))

    def test_addresses_with_control_characters_are_dropped(self):
        msg = headers("From: X <ev\x1b[2Jil@x.com>\nTo: ok@x.ch, bad\u202e@x.ch\nSubject: a")
        self.assertEqual(msg.from_addr, "")
        self.assertEqual(msg.recipients, ("ok@x.ch",))

    def test_malformed_sender(self):
        msg = headers("From: <<<>>>\nSubject: x")
        self.assertEqual(msg.from_addr, "")

    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("mail.shop.co.uk"), "shop.co.uk")
        self.assertEqual(registrable_domain("e.zalando.ch"), "zalando.ch")
        self.assertEqual(registrable_domain("agenziaentrate.gov.it"), "agenziaentrate.gov.it")


class ClassifierTest(unittest.TestCase):
    def check(self, text: str, expected: str, context: Context = NO_CONTEXT):
        verdict = classify(headers(BASE + text), context)
        self.assertEqual(verdict.category, expected, verdict)
        self.assertTrue(verdict.reasons)
        return verdict

    def test_categories(self):
        self.check("From: Il Post <news@ilpost.it>\nSubject: Notizie\nList-Unsubscribe: <https://x>", "newsletter")
        self.check("From: Shop <news@shop.ch>\nSubject: Saldi: -40%\nList-Id: <promo.shop.ch>", "promozioni")
        self.check("From: Galaxus <info@galaxus.ch>\nSubject: Il tuo ordine è stato spedito", "acquisti")
        self.check("From: Shop <news@shop.ch>\nSubject: Spedizione gratuita!\nPrecedence: bulk", "promozioni")
        self.check("From: Instagram <no-reply@mail.instagram.com>\nSubject: Nuovi follower", "social")
        self.check("From: Banca <noreply@banca.ch>\nSubject: Nuovo accesso", "notifiche")
        self.check("From: Anna <anna@gmail.com>\nSubject: Ci vediamo?", "personale")
        self.check("From: Tool <bot@tool.io>\nSubject: Report\nX-Mailer: Mailchimp Mailer", "newsletter")

    def test_phishing_with_a_brand_name(self):
        verdict = self.check(
            "From: Poste Italiane <avviso@poste-it-verifica.top>\nSubject: Pacco in giacenza, ultimo avviso",
            "spam",
        )
        self.assertTrue(any("Poste Italiane" in r for r in verdict.reasons))

    def test_brand_from_its_own_domain_is_fine(self):
        self.check("From: PayPal <service@paypal.ch>\nSubject: Ricevuta del pagamento", "acquisti")
        self.check("From: Apple <no_reply@email.apple.com>\nSubject: La tua ricevuta", "acquisti")

    def test_server_verdicts(self):
        self.check("From: X <x@x.ch>\nSubject: ciao\nX-Spam-Flag: YES", "spam")
        self.check(
            "From: X <x@x.ch>\nSubject: ciao\nX-Proofpoint-Spam-Details: rule=spam policy=default score=90",
            "spam",
        )
        self.check(
            "From: X <x@x.ch>\nSubject: ciao\n"
            "X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0",
            "personale",
        )

    def test_only_the_topmost_authentication_result_counts(self):
        self.check(
            "From: X <x@x.ch>\nSubject: ciao\n"
            "Authentication-Results: mx.icloud.com; dmarc=pass\n"
            "Authentication-Results: fake; dmarc=fail\n",
            "personale",
        )

    def test_known_contacts_are_never_spam(self):
        text = "From: Luca <luca@example.xyz>\nSubject: URGENTE!!! hai vinto\nX-Spam-Flag: YES"
        self.check(text, "spam")
        self.check(text, "personale", Context(known_contacts=frozenset({"luca@example.xyz"})))

    def test_display_name_with_another_address(self):
        verdict = self.check(
            'From: "support@bank.ch" <x@other.example>\nSubject: Verifica il tuo account', "spam",
        )
        self.assertTrue(any("indirizzo diverso" in r for r in verdict.reasons))

    def test_forwarded_mail_failing_spf_alone_is_not_spam(self):
        self.check(
            "From: Amica <amica@gmx.ch>\nSubject: Foto\nAuthentication-Results: mx; spf=fail; dmarc=fail",
            "personale",
        )


if __name__ == "__main__":
    unittest.main()
