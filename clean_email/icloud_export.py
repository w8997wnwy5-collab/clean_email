"""Turn the bot's rules into rules to create by hand on iCloud.com.

iCloud offers no way for programs to create its rules, so the bot cannot write
them itself. Native rules have one advantage: Apple's servers apply them as
soon as mail arrives, even when the bot is not running. They can only look at
the sender, the recipients or the subject, with one condition per rule.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .analysis import Analysis
from .message import registrable_domain
from .rules import Action, RuleSet

# Shared mailbox providers: a rule on the whole domain would catch real people.
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "icloud.com", "me.com", "mac.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "yahoo.com", "yahoo.it", "yahoo.de", "yahoo.fr", "aol.com", "gmx.ch",
    "gmx.net", "gmx.de", "gmx.at", "web.de", "t-online.de", "bluewin.ch", "hispeed.ch", "sunrise.ch",
    "libero.it", "virgilio.it", "alice.it", "tiscali.it", "tim.it", "fastwebnet.it", "email.it",
    "proton.me", "protonmail.com", "pm.me", "yandex.com", "mail.ru", "zoho.com",
})


@dataclass(frozen=True)
class NativeRule:
    number: int  # the bot rule it comes from
    condition: str
    value: str
    action: str


def native_action(action: Action) -> str | None:
    if action.kind == "move":
        return f"Sposta nella cartella «{action.folder}»"
    if action.kind == "trash":
        return "Sposta nel Cestino"
    if action.kind == "junk":
        return "Sposta nella cartella «Junk» (Indesiderata)"
    if action.kind == "archive":
        return "Sposta nella cartella «Archive» (Archivio)"
    if action.kind == "mark_read":
        return "Segna come letto"
    return None


def senders_for(analysis: Analysis, categories: tuple[str, ...], limit: int) -> list[str]:
    """Domains (or single addresses on shared providers) whose mail is all of these categories."""
    by_domain: dict[str, Counter] = defaultdict(Counter)
    by_address: dict[str, Counter] = defaultdict(Counter)
    for msg, verdict in analysis.items:
        if not msg.from_addr:
            continue
        inside = verdict.category in categories
        by_domain[registrable_domain(msg.from_domain)][inside] += 1
        by_address[msg.from_addr][inside] += 1

    picks: Counter = Counter()
    for domain, counts in by_domain.items():
        if counts[True] and not counts[False] and domain not in FREE_MAIL_DOMAINS:
            picks["@" + domain] = counts[True]
    for address, counts in by_address.items():
        domain = registrable_domain(address.rsplit("@", 1)[1])
        if counts[True] and not counts[False] and "@" + domain not in picks:
            picks[address] = counts[True]
    return [value for value, _ in picks.most_common(limit)]


def native_rules(
    ruleset: RuleSet, analysis: Analysis | None, per_category: int = 10,
) -> tuple[list[NativeRule], list[tuple[int, str]]]:
    """Native rules to create, and (rule number, reason) for rules only the bot can apply."""
    natives: list[NativeRule] = []
    bot_only: list[tuple[int, str]] = []
    for number, rule in enumerate(ruleset.rules, 1):
        if not rule.enabled:
            continue
        m = rule.match
        action = native_action(rule.action)
        kinds = [k for k in (m.senders, m.recipients, m.subjects, m.categories) if k]
        if rule.source != "INBOX":
            bot_only.append((number, "iCloud applica le regole solo alla posta in arrivo"))
        elif action is None:
            bot_only.append((number, "iCloud non sa contrassegnare i messaggi con una regola"))
        elif m.older_than_days or m.unread_only:
            bot_only.append((number, "iCloud non guarda l'età dei messaggi né se sono letti"))
        elif len(kinds) > 1:
            bot_only.append((number, "iCloud accetta una sola condizione per regola"))
        elif "spam" in m.categories:
            bot_only.append((number, "lo spam lo riconosce solo il bot"))
        elif m.senders:
            natives += [NativeRule(number, "Proviene da", s, action) for s in m.senders]
        elif m.recipients:
            natives += [NativeRule(number, "È indirizzato a", s, action) for s in m.recipients]
        elif m.subjects:
            natives += [NativeRule(number, "L'oggetto contiene", s, action) for s in m.subjects]
        elif analysis is None:
            bot_only.append((number, "per tradurla serve prima un'analisi della posta"))
        else:
            values = senders_for(analysis, m.categories, per_category)
            if values:
                natives += [NativeRule(number, "Proviene da", v, action) for v in values]
            else:
                bot_only.append((number, "nell'analisi non ci sono mittenti di questa categoria"))
    return natives, bot_only
