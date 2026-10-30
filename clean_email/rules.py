"""Rules the user approves: which messages, and what to do with them.

Within a rule, conditions of different kinds must all hold (sender AND
subject...), while the values of one kind are alternatives (this sender OR
that one). Rules run in order and the first one that matches a message wins.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Callable

from .classifier import CATEGORIES
from .imap import MailError, validate_folder_name
from .message import MessageInfo
from .security import has_control_chars

# The bot keeps its rules and journal here; rules can neither read from nor
# move messages into it.
RESERVED_FOLDER = "Bot Email"
FORMAT_VERSION = 1

ACTIONS = {
    "move": "sposta nella cartella",
    "trash": "metti nel Cestino",
    "junk": "metti in Indesiderata",
    "archive": "archivia",
    "mark_read": "segna come letta",
    "flag": "contrassegna",
}
MOVING_ACTIONS = frozenset({"move", "trash", "junk", "archive"})

_DOMAIN = re.compile(r"^@?[^@\s.]+(?:\.[^@\s.]+)+$")
_ADDRESS = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")


class RuleError(ValueError):
    """A rule that cannot be saved; the message is in Italian."""


@dataclass(frozen=True)
class Match:
    senders: tuple[str, ...] = ()
    recipients: tuple[str, ...] = ()
    subjects: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    older_than_days: int | None = None
    unread_only: bool = False

    def is_empty(self) -> bool:
        return not (self.senders or self.recipients or self.subjects or self.categories or self.older_than_days)


@dataclass(frozen=True)
class Action:
    kind: str
    folder: str | None = None
    mark_read: bool = False


@dataclass(frozen=True)
class Rule:
    name: str
    match: Match
    action: Action
    source: str = "INBOX"
    enabled: bool = True


@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)
    # Sender patterns no rule may ever touch.
    protected: list[str] = field(default_factory=list)


def address_matches(pattern: str, address: str, name: str = "") -> bool:
    """`@domain` matches the domain and its subdomains, `a@b.c` the exact
    address, anything else is looked for inside the address and the name."""
    pattern = pattern.strip().lower()
    address = address.lower()
    if pattern.startswith("@"):
        domain = address.rsplit("@", 1)[-1] if "@" in address else ""
        return domain == pattern[1:] or domain.endswith("." + pattern[1:])
    if "@" in pattern:
        return address == pattern
    return pattern in address or pattern in name.lower()


def is_protected(ruleset: RuleSet, msg: MessageInfo) -> bool:
    return any(address_matches(p, msg.from_addr, msg.from_name) for p in ruleset.protected)


def rule_matches(rule: Rule, msg: MessageInfo, category_of: Callable[[MessageInfo], str], now: datetime) -> bool:
    m = rule.match
    if m.senders and not any(address_matches(p, msg.from_addr, msg.from_name) for p in m.senders):
        return False
    if m.recipients and not any(address_matches(p, a) for p in m.recipients for a in msg.recipients):
        return False
    if m.subjects:
        subject = msg.subject.casefold()
        if not any(s.casefold() in subject for s in m.subjects):
            return False
    if m.older_than_days:
        if msg.date is None or msg.date > now - timedelta(days=m.older_than_days):
            return False
    if m.unread_only and msg.seen:
        return False
    if m.categories and category_of(msg) not in m.categories:
        return False
    return True


def _clean_patterns(values, what: str, *, allow_plain: bool = True) -> tuple[str, ...]:
    cleaned = []
    for value in values or ():
        value = str(value).strip().lower()
        if not value:
            continue
        if has_control_chars(value) or len(value) > 254:
            raise RuleError(f"{what}: «{value[:40]}» non è valido")
        if "@" in value:
            if not (_DOMAIN.match(value) if value.startswith("@") else _ADDRESS.match(value)):
                raise RuleError(f"{what}: «{value}» non è un indirizzo o un dominio valido")
        elif not allow_plain:
            raise RuleError(f"{what}: scrivi un indirizzo (nome@dominio) o un dominio (@dominio)")
        elif len(value) < 3:
            raise RuleError(f"{what}: «{value}» è troppo corto, prenderebbe troppe mail")
        cleaned.append(value)
    return tuple(dict.fromkeys(cleaned))


def validate(rule: Rule) -> Rule:
    """Return a normalized copy of `rule`, or raise RuleError."""
    name = " ".join(rule.name.split())
    if not name or len(name) > 80 or has_control_chars(name):
        raise RuleError("Il nome della regola deve avere da 1 a 80 caratteri")
    try:
        source = validate_folder_name(rule.source)
    except MailError as exc:
        raise RuleError(str(exc)) from None
    if source.upper() == "INBOX":
        source = "INBOX"
    if source == RESERVED_FOLDER:
        raise RuleError(f"La cartella «{RESERVED_FOLDER}» è riservata al bot")

    m = rule.match
    subjects = []
    for s in m.subjects:
        s = " ".join(str(s).split())
        if len(s) < 3 or len(s) > 200 or has_control_chars(s):
            raise RuleError(f"Oggetto: «{s[:40]}» deve avere da 3 a 200 caratteri")
        subjects.append(s)
    categories = tuple(dict.fromkeys(c.strip().lower() for c in m.categories))
    unknown = [c for c in categories if c not in CATEGORIES]
    if unknown:
        raise RuleError(f"Categoria sconosciuta: {', '.join(unknown)}. Valide: {', '.join(CATEGORIES)}")
    days = m.older_than_days
    if days in (None, ""):
        days = None
    else:
        try:
            days = int(days)
        except (TypeError, ValueError):
            raise RuleError("I giorni devono essere un numero") from None
        if not 1 <= days <= 3650:
            raise RuleError("I giorni devono essere tra 1 e 3650")
    match = Match(
        senders=_clean_patterns(m.senders, "Mittente"),
        recipients=_clean_patterns(m.recipients, "Destinatario"),
        subjects=tuple(dict.fromkeys(subjects)),
        categories=categories,
        older_than_days=days,
        unread_only=bool(m.unread_only),
    )
    if match.is_empty():
        raise RuleError("La regola non ha condizioni: prenderebbe tutta la posta")

    a = rule.action
    if a.kind not in ACTIONS:
        raise RuleError(f"Azione sconosciuta: {a.kind}")
    folder = None
    if a.kind == "move":
        if not a.folder:
            raise RuleError("Indica la cartella in cui spostare le mail")
        try:
            folder = validate_folder_name(a.folder)
        except MailError as exc:
            raise RuleError(str(exc)) from None
        if folder == RESERVED_FOLDER:
            raise RuleError(f"La cartella «{RESERVED_FOLDER}» è riservata al bot")
        if folder == source:
            raise RuleError("La cartella di destinazione è la stessa di origine")
    if a.kind in ("trash", "junk") and "personale" in categories:
        raise RuleError("Per sicurezza il bot non butta mai la posta personale")
    action = Action(a.kind, folder, bool(a.mark_read) and a.kind in MOVING_ACTIONS)
    return Rule(name=name, match=match, action=action, source=source, enabled=bool(rule.enabled))


def describe(rule: Rule) -> str:
    """One line in Italian, e.g. «Newsletter» da INBOX → sposta nella cartella «Newsletter»."""
    m = rule.match
    parts = []
    if m.senders:
        parts.append("mittente " + " o ".join(m.senders))
    if m.recipients:
        parts.append("destinatario " + " o ".join(m.recipients))
    if m.subjects:
        parts.append("oggetto con " + " o ".join(f"«{s}»" for s in m.subjects))
    if m.categories:
        parts.append("categoria " + " o ".join(CATEGORIES[c] for c in m.categories))
    if m.older_than_days:
        parts.append(f"più vecchie di {m.older_than_days} giorni")
    if m.unread_only:
        parts.append("non lette")
    action = ACTIONS[rule.action.kind]
    if rule.action.kind == "move":
        action += f" «{rule.action.folder}»"
    if rule.action.mark_read:
        action += " e segna come letta"
    where = "" if rule.source == "INBOX" else f"in «{rule.source}»: "
    return f"{where}{', '.join(parts)} → {action}"


def rule_to_dict(rule: Rule) -> dict:
    m, a = rule.match, rule.action
    match = {
        "senders": list(m.senders), "recipients": list(m.recipients), "subjects": list(m.subjects),
        "categories": list(m.categories), "older_than_days": m.older_than_days, "unread_only": m.unread_only,
    }
    return {
        "name": rule.name,
        "enabled": rule.enabled,
        "source": rule.source,
        "match": {k: v for k, v in match.items() if v},
        "action": {k: v for k, v in {"kind": a.kind, "folder": a.folder, "mark_read": a.mark_read}.items() if v},
    }


def rule_from_dict(data: dict) -> Rule:
    if not isinstance(data, dict):
        raise RuleError("Regola non valida")
    m = data.get("match") or {}
    a = data.get("action") or {}

    def strings(key: str) -> tuple[str, ...]:
        values = m.get(key) or []
        if not isinstance(values, list):
            raise RuleError(f"«{key}» deve essere un elenco")
        return tuple(str(v) for v in values)

    rule = Rule(
        name=str(data.get("name", "")),
        enabled=bool(data.get("enabled", True)),
        source=str(data.get("source", "INBOX")),
        match=Match(
            senders=strings("senders"), recipients=strings("recipients"), subjects=strings("subjects"),
            categories=strings("categories"), older_than_days=m.get("older_than_days"),
            unread_only=bool(m.get("unread_only", False)),
        ),
        action=Action(kind=str(a.get("kind", "")), folder=a.get("folder"), mark_read=bool(a.get("mark_read", False))),
    )
    return validate(rule)


def ruleset_to_dict(ruleset: RuleSet) -> dict:
    return {
        "version": FORMAT_VERSION,
        "rules": [rule_to_dict(r) for r in ruleset.rules],
        "protected": list(ruleset.protected),
    }


def ruleset_from_dict(data: dict) -> RuleSet:
    if not isinstance(data, dict) or data.get("version") != FORMAT_VERSION:
        raise RuleError("Il file delle regole ha un formato sconosciuto")
    rules = [rule_from_dict(r) for r in data.get("rules") or []]
    protected = list(_clean_patterns(data.get("protected") or [], "Mittente protetto"))
    return RuleSet(rules=rules, protected=protected)


def ruleset_to_json(ruleset: RuleSet) -> str:
    return json.dumps(ruleset_to_dict(ruleset), ensure_ascii=False, indent=2)


def _priority(rule: Rule) -> int:
    m = rule.match
    if m.senders or m.recipients or m.subjects:
        return 0  # a precise choice of the user beats a category
    if "spam" in m.categories:
        return 1
    return 2 if m.categories else 3


def insert_rule(ruleset: RuleSet, rule: Rule) -> RuleSet:
    """Add a rule before the first, less precise one on the same folder, so
    that «always trash this sender» wins over «move newsletters»."""
    rules = list(ruleset.rules)
    position = next(
        (i for i, r in enumerate(rules) if r.source == rule.source and _priority(r) > _priority(rule)),
        len(rules),
    )
    rules.insert(position, rule)
    return replace(ruleset, rules=rules)


def add_protected(ruleset: RuleSet, pattern: str) -> RuleSet:
    cleaned = _clean_patterns([pattern], "Mittente protetto")
    return replace(ruleset, protected=list(dict.fromkeys([*ruleset.protected, *cleaned])))
