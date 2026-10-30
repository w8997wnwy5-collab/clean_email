import unittest
from datetime import datetime, timedelta, timezone

from clean_email.message import MessageInfo
from clean_email.rules import (
    RESERVED_FOLDER, Action, Match, Rule, RuleError, RuleSet, address_matches, describe, insert_rule,
    rule_matches, ruleset_from_dict, ruleset_to_dict, validate,
)

NOW = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)


def message(**kw) -> MessageInfo:
    defaults = dict(uid=1, folder="INBOX", from_addr="news@mail.zalando.ch", from_name="Zalando",
                    subject="Saldi d'autunno", recipients=("me@icloud.com",), date=NOW - timedelta(days=3))
    defaults.update(kw)
    return MessageInfo(**defaults)


def rule(match: Match, action: Action | None = None, **kw) -> Rule:
    return validate(Rule("prova", match, action or Action("trash"), **kw))


class MatchingTest(unittest.TestCase):
    def test_address_patterns(self):
        self.assertTrue(address_matches("@zalando.ch", "news@mail.zalando.ch"))
        self.assertTrue(address_matches("@zalando.ch", "news@zalando.ch"))
        self.assertFalse(address_matches("@zalando.ch", "news@notzalando.ch"))
        self.assertTrue(address_matches("news@zalando.ch", "NEWS@zalando.ch"))
        self.assertFalse(address_matches("news@zalando.ch", "news@mail.zalando.ch"))
        self.assertTrue(address_matches("zalando", "x@y.ch", "Zalando Lounge"))

    def test_conditions_combine(self):
        r = rule(Match(senders=("@zalando.ch", "@galaxus.ch"), subjects=("saldi",)))
        category = lambda m: "promozioni"  # noqa: E731
        self.assertTrue(rule_matches(r, message(), category, NOW))
        self.assertFalse(rule_matches(r, message(subject="Ordine"), category, NOW))
        self.assertFalse(rule_matches(r, message(from_addr="a@b.ch", from_name=""), category, NOW))

    def test_age_unread_and_category(self):
        r = rule(Match(categories=("newsletter",), older_than_days=30, unread_only=True))
        newsletter = lambda m: "newsletter"  # noqa: E731
        old = message(date=NOW - timedelta(days=40))
        self.assertTrue(rule_matches(r, old, newsletter, NOW))
        self.assertFalse(rule_matches(r, message(), newsletter, NOW))
        self.assertFalse(rule_matches(r, message(date=None), newsletter, NOW))
        self.assertFalse(rule_matches(r, message(date=old.date, flags=frozenset({"\\seen"})), newsletter, NOW))
        self.assertFalse(rule_matches(r, old, lambda m: "promozioni", NOW))


class ValidationTest(unittest.TestCase):
    def test_refuses_dangerous_or_empty_rules(self):
        bad = [
            Rule("x", Match(), Action("trash")),
            Rule("x", Match(senders=("ab",)), Action("trash")),
            Rule("x", Match(senders=("x@",)), Action("trash")),
            Rule("x", Match(categories=("boh",)), Action("trash")),
            Rule("x", Match(categories=("personale",)), Action("trash")),
            Rule("x", Match(senders=("@a.ch",)), Action("move")),
            Rule("x", Match(senders=("@a.ch",)), Action("move", RESERVED_FOLDER)),
            Rule("x", Match(senders=("@a.ch",)), Action("move", "INBOX")),
            Rule("x", Match(senders=("@a.ch",)), Action("trash"), source=RESERVED_FOLDER),
            Rule("x", Match(older_than_days=0), Action("trash")),
            Rule("x", Match(older_than_days="tanti"), Action("trash")),
            Rule("x", Match(senders=("@a.ch",)), Action("delete_forever")),
            Rule("", Match(senders=("@a.ch",)), Action("trash")),
        ]
        for r in bad:
            with self.assertRaises(RuleError, msg=r):
                validate(r)

    def test_normalizes(self):
        r = validate(Rule("  Mia   regola ", Match(senders=(" @Zalando.CH ", "@zalando.ch")),
                          Action("move", "Acquisti", True), source="inbox"))
        self.assertEqual(r.name, "Mia regola")
        self.assertEqual(r.match.senders, ("@zalando.ch",))
        self.assertEqual(r.source, "INBOX")
        self.assertTrue(r.action.mark_read)
        flag = validate(Rule("x", Match(senders=("@a.ch",)), Action("flag", mark_read=True)))
        self.assertFalse(flag.action.mark_read)

    def test_json_round_trip(self):
        ruleset = RuleSet(
            [rule(Match(categories=("newsletter",)), Action("move", "Newsletter")),
             rule(Match(older_than_days=30), Action("trash"), source="Newsletter")],
            protected=["capo@lavoro.ch"],
        )
        self.assertEqual(ruleset_from_dict(ruleset_to_dict(ruleset)), ruleset)
        with self.assertRaises(RuleError):
            ruleset_from_dict({"version": 99})

    def test_describe(self):
        text = describe(rule(Match(senders=("@a.ch",), older_than_days=7), Action("move", "Vecchie"),
                             source="Archivio"))
        self.assertEqual(
            text, "in «Archivio»: mittente @a.ch, più vecchie di 7 giorni → sposta nella cartella «Vecchie»",
        )


class OrderTest(unittest.TestCase):
    def test_precise_rules_go_before_categories(self):
        spam = rule(Match(categories=("spam",)), Action("junk"))
        newsletters = rule(Match(categories=("newsletter",)), Action("move", "Newsletter"))
        sender = rule(Match(senders=("@zalando.ch",)), Action("trash"))
        cleanup = rule(Match(older_than_days=30), Action("trash"), source="Newsletter")
        ruleset = RuleSet()
        for r in (newsletters, cleanup, spam, sender):
            ruleset = insert_rule(ruleset, r)
        self.assertEqual(ruleset.rules, [sender, spam, newsletters, cleanup])


if __name__ == "__main__":
    unittest.main()
