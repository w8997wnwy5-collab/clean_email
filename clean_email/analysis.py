"""Look at a folder and suggest rules; the user decides which to keep."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .classifier import CATEGORIES, SUGGESTED_FOLDERS, Classification
from .engine import Classifier
from .imap import MailClient
from .message import MessageInfo
from .rules import Action, Match, Rule, RuleSet
from .security import safe_text

CLEANUP_DAYS = 30
_WHAT = {
    "newsletter": "le newsletter",
    "promozioni": "le promozioni",
    "social": "le mail dei social",
    "notifiche": "le notifiche automatiche",
    "acquisti": "ordini, spedizioni e ricevute",
}


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


@dataclass
class Sender:
    address: str
    name: str = ""
    count: int = 0
    unread: int = 0
    categories: Counter = field(default_factory=Counter)
    subjects: list[str] = field(default_factory=list)
    reasons: Counter = field(default_factory=Counter)

    @property
    def category(self) -> str:
        return self.categories.most_common(1)[0][0] if self.categories else "personale"

    @property
    def label(self) -> str:
        name = safe_text(self.name, 40)
        address = safe_text(self.address, 80)
        return f"{name} <{address}>" if name else address


@dataclass
class Analysis:
    folder: str
    total: int  # messages in the folder
    items: list[tuple[MessageInfo, Classification]]

    @property
    def counts(self) -> Counter:
        return Counter(c.category for _, c in self.items)

    def senders(self, category: str | None = None) -> list[Sender]:
        by_address: dict[str, Sender] = {}
        for msg, verdict in self.items:
            if category and verdict.category != category:
                continue
            key = msg.from_addr or safe_text(msg.from_name, 60) or "(senza mittente)"
            sender = by_address.setdefault(key, Sender(key, msg.from_name))
            sender.count += 1
            sender.unread += 0 if msg.seen else 1
            sender.categories[verdict.category] += 1
            sender.reasons.update(verdict.reasons)
            if len(sender.subjects) < 3:
                sender.subjects.append(safe_text(msg.subject, 70))
        return sorted(by_address.values(), key=lambda s: (-s.count, s.address))

    def older_than(self, category: str, days: int, now: datetime) -> int:
        limit = now - timedelta(days=days)
        return sum(1 for m, c in self.items if c.category == category and m.date and m.date <= limit)


def analyze(client: MailClient, classifier: Classifier, folder: str = "INBOX", limit: int | None = 1000) -> Analysis:
    classifier.prepare()
    total, _ = client.select(folder, readonly=True)
    uids = client.search("UNDELETED")
    if limit:
        uids = uids[-limit:]
    messages = client.fetch_headers(uids)
    return Analysis(folder, total, [(m, classifier(m)) for m in messages])


@dataclass
class Proposal:
    title: str
    examples: list[str]
    rule: Rule


def _covered(ruleset: RuleSet, category: str) -> bool:
    return any(r.source == "INBOX" and category in r.match.categories for r in ruleset.rules)


def propose(analysis: Analysis, ruleset: RuleSet, now: datetime | None = None) -> list[Proposal]:
    now = now or datetime.now(timezone.utc)
    counts = analysis.counts
    proposals: list[Proposal] = []

    if counts["spam"] and not _covered(ruleset, "spam"):
        examples = [
            f"{s.label}: {s.reasons.most_common(1)[0][0]}" for s in analysis.senders("spam")[:3]
        ]
        proposals.append(Proposal(
            f"Metti in Indesiderata lo spam sospetto ({counts['spam']} mail), ora e in futuro",
            examples,
            Rule("Spam sospetto in Indesiderata", Match(categories=("spam",)), Action("junk")),
        ))

    for category in ("newsletter", "promozioni", "social", "notifiche", "acquisti"):
        if not counts[category] or _covered(ruleset, category):
            continue
        folder = SUGGESTED_FOLDERS[category]
        senders = analysis.senders(category)
        examples = [f"{s.label} ({s.count})" for s in senders[:3]]
        proposals.append(Proposal(
            f"Sposta {_WHAT[category]} nella cartella «{folder}» "
            f"({counts[category]} mail da {_plural(len(senders), 'mittente', 'mittenti')})",
            examples,
            Rule(f"{CATEGORIES[category]} in «{folder}»", Match(categories=(category,)), Action("move", folder)),
        ))

    for category in ("newsletter", "promozioni"):
        folder = SUGGESTED_FOLDERS[category]
        already = any(r.source == folder and r.action.kind == "trash" for r in ruleset.rules)
        if not counts[category] or already:
            continue
        old = analysis.older_than(category, CLEANUP_DAYS, now)
        proposals.append(Proposal(
            f"Nella cartella «{folder}», metti nel Cestino le mail più vecchie di {CLEANUP_DAYS} giorni"
            + (f" (ora circa {old})" if old else ""),
            ["Il Cestino di iCloud le tiene ancora 30 giorni: puoi recuperarle."],
            Rule(f"Pulizia «{folder}»", Match(older_than_days=CLEANUP_DAYS), Action("trash"), source=folder),
        ))
    return proposals


def bulk_senders(analysis: Analysis, limit: int = 15) -> list[Sender]:
    """Most frequent newsletter and promotion senders, for "always trash" picks."""
    senders = [s for s in analysis.senders() if s.category in ("newsletter", "promozioni") and "@" in s.address]
    return senders[:limit]
