"""Plan what the rules ask, show it, then carry it out folder by folder."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .classifier import Classification, Context, classify
from .imap import MailClient, MailError, imap_date
from .message import MessageInfo
from .rules import MOVING_ACTIONS, Action, Rule, RuleSet, is_protected, rule_matches
from .store import JournalEntry

CONTACTS_SCAN = 500


def known_contacts(client: MailClient) -> frozenset[str]:
    """Addresses the user has written to, from the latest sent messages."""
    sent = client.special_folder("sent")
    if sent is None:
        return frozenset()
    client.select(sent.name, readonly=True)
    own = {client.email.lower()}
    contacts: set[str] = set()
    for msg in client.fetch_headers(client.search("ALL")[-CONTACTS_SCAN:]):
        if msg.from_addr:
            own.add(msg.from_addr)
        contacts.update(msg.recipients)
    return frozenset(contacts - own)


class Classifier:
    """Classifies the messages of one mailbox, reading the user's contacts once."""

    def __init__(self, client: MailClient, context: Context | None = None):
        self._client = client
        self._context = context
        self._cache: dict[tuple[str, int], Classification] = {}

    def prepare(self) -> None:
        # Reading contacts selects Sent Messages: do it before opening a folder.
        if self._context is None:
            self._context = Context(known_contacts=known_contacts(self._client))

    def __call__(self, msg: MessageInfo) -> Classification:
        if self._context is None:
            raise RuntimeError("Classifier.prepare() must run before classifying")
        key = (msg.folder, msg.uid)
        if key not in self._cache:
            self._cache[key] = classify(msg, self._context)
        return self._cache[key]

    def category(self, msg: MessageInfo) -> str:
        return self(msg).category


def _already_done(action: Action, msg: MessageInfo) -> bool:
    if action.kind == "mark_read":
        return msg.seen
    if action.kind == "flag":
        return "\\flagged" in msg.flags
    return False


@dataclass
class Change:
    number: int  # position of the rule, from 1
    rule: Rule
    messages: list[MessageInfo]


@dataclass
class FolderPlan:
    folder: str
    uidvalidity: int | None
    changes: list[Change] = field(default_factory=list)
    protected: int = 0

    @property
    def total(self) -> int:
        return sum(len(c.messages) for c in self.changes)


@dataclass
class Outcome:
    done: dict[int, int] = field(default_factory=dict)  # rule number -> messages changed
    over_limit: dict[int, int] = field(default_factory=dict)  # rule number -> messages it wanted
    errors: list[str] = field(default_factory=list)
    journal: list[JournalEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.done.values())


class Engine:
    def __init__(
        self,
        client: MailClient,
        ruleset: RuleSet,
        classifier: Classifier | None = None,
        *,
        now: datetime | None = None,
        lookback_days: int | None = None,
        run: str = "",
    ):
        self.client = client
        self.ruleset = ruleset
        self.classifier = classifier or Classifier(client)
        self.now = now or datetime.now(timezone.utc)
        self.lookback_days = lookback_days
        self.run = run

    def groups(self) -> list[tuple[str, list[tuple[int, Rule]]]]:
        """Enabled rules by source folder, in the order the folders first appear."""
        groups: dict[str, list[tuple[int, Rule]]] = {}
        for number, rule in enumerate(self.ruleset.rules, 1):
            if rule.enabled:
                groups.setdefault(rule.source, []).append((number, rule))
        return list(groups.items())

    def _criteria(self, rule: Rule) -> list[str]:
        criteria = ["UNDELETED"]
        m = rule.match
        if m.older_than_days:
            criteria += ["BEFORE", imap_date((self.now - timedelta(days=m.older_than_days)).date())]
        elif self.lookback_days:
            criteria += ["SINCE", imap_date((self.now - timedelta(days=self.lookback_days)).date())]
        if m.unread_only:
            criteria.append("UNSEEN")
        return criteria

    def plan_folder(self, folder: str, rules: list[tuple[int, Rule]]) -> FolderPlan | None:
        if self.client.find_folder(folder) is None:
            return None  # e.g. a clean-up rule for a folder no rule has filled yet
        if any(rule.match.categories for _, rule in rules):
            self.classifier.prepare()
        exists, uidvalidity = self.client.select(folder, readonly=True)
        plan = FolderPlan(folder, uidvalidity)
        if not exists:
            return plan
        candidates = {number: set(self.client.search(*self._criteria(rule))) for number, rule in rules}
        assigned: dict[int, list[MessageInfo]] = defaultdict(list)
        for msg in sorted(self.client.fetch_headers(set().union(*candidates.values())), key=lambda m: m.uid):
            for number, rule in rules:
                if msg.uid in candidates[number] and rule_matches(rule, msg, self.classifier.category, self.now):
                    # The first matching rule claims the message, even when
                    # there is nothing left to do (already read or flagged).
                    if is_protected(self.ruleset, msg):
                        plan.protected += 1
                    elif not _already_done(rule.action, msg):
                        assigned[number].append(msg)
                    break
        plan.changes = [Change(number, rule, assigned[number]) for number, rule in rules if assigned.get(number)]
        return plan

    def plan(self) -> list[FolderPlan]:
        self.client.folders(refresh=True)
        plans = []
        for folder, rules in self.groups():
            plan = self.plan_folder(folder, rules)
            if plan is not None:
                plans.append(plan)
        return plans

    def destination(self, action: Action) -> str | None:
        if action.kind == "move":
            return self.client.ensure_folder(action.folder).name
        if action.kind in ("trash", "junk"):
            folder = self.client.special_folder(action.kind)
            if folder is None:
                raise MailError("Non trovo la cartella " + ("Cestino" if action.kind == "trash" else "Indesiderata"))
            return folder.name
        if action.kind == "archive":
            folder = self.client.special_folder("archive")
            return folder.name if folder else self.client.ensure_folder("Archive").name
        return None

    def _apply(self, folder: str, change: Change) -> str | None:
        action = change.rule.action
        uids = [m.uid for m in change.messages]
        if action.kind == "mark_read":
            self.client.set_flags(uids, r"\Seen")
            return None
        if action.kind == "flag":
            self.client.set_flags(uids, r"\Flagged")
            return None
        dest = self.destination(action)
        if dest == folder:
            raise MailError("la destinazione coincide con la cartella di origine")
        if action.mark_read:
            self.client.set_flags(uids, r"\Seen")
        self.client.move(uids, dest)
        return dest

    def execute_folder(self, plan: FolderPlan, outcome: Outcome, *, limit: int | None = None) -> None:
        if not plan.changes:
            return
        _, uidvalidity = self.client.select(plan.folder, readonly=False)
        if plan.uidvalidity is not None and uidvalidity != plan.uidvalidity:
            outcome.errors.append(f"La cartella «{plan.folder}» è cambiata nel frattempo: riprova")
            return
        stamp = self.now.isoformat(timespec="seconds")
        for change in plan.changes:
            count = len(change.messages)
            if limit is not None and count > limit:
                outcome.over_limit[change.number] = count
                continue
            try:
                dest = self._apply(plan.folder, change)
            except MailError as exc:
                outcome.errors.append(f"Regola {change.number}: {exc}")
                continue
            outcome.done[change.number] = count
            outcome.journal.extend(
                JournalEntry(
                    time=stamp, run=self.run, rule=change.rule.name, action=change.rule.action.kind,
                    source=plan.folder, dest=dest, message_id=m.message_id,
                    sender=f"{m.from_name} <{m.from_addr}>" if m.from_name else m.from_addr,
                    subject=m.subject[:150],
                )
                for m in change.messages
            )

    def execute(self, plans: list[FolderPlan], *, limit: int | None = None) -> Outcome:
        """Carry out exactly the plans the user has seen."""
        outcome = Outcome()
        for plan in plans:
            try:
                self.execute_folder(plan, outcome, limit=limit)
            except MailError as exc:
                outcome.errors.append(f"«{plan.folder}»: {exc}")
        return outcome

    def run_all(self, *, limit: int | None = None) -> Outcome:
        """Plan and execute folder by folder, so a message moved into a folder
        by one rule meets that folder's rules in the same run."""
        outcome = Outcome()
        self.client.folders(refresh=True)
        for folder, rules in self.groups():
            try:
                plan = self.plan_folder(folder, rules)
                if plan is not None:
                    self.execute_folder(plan, outcome, limit=limit)
            except MailError as exc:
                outcome.errors.append(f"«{folder}»: {exc}")
        return outcome


def undo(
    client: MailClient, entries: list[JournalEntry], *, now: datetime, run: str,
) -> tuple[int, int, list[JournalEntry]]:
    """Put back what one run did. Returns (restored, not found, journal entries)."""
    restored = missing = 0
    journal: list[JournalEntry] = []
    stamp = now.isoformat(timespec="seconds")
    moved: dict[str, list[JournalEntry]] = defaultdict(list)
    flagged: dict[str, list[JournalEntry]] = defaultdict(list)
    for entry in entries:
        if entry.action in MOVING_ACTIONS and entry.dest:
            moved[entry.dest].append(entry)
        elif entry.action in ("mark_read", "flag"):
            flagged[entry.source].append(entry)

    for dest, items in moved.items():
        if client.find_folder(dest) is None:
            missing += len(items)
            continue
        client.select(dest, readonly=False)
        back: dict[str, list[int]] = defaultdict(list)
        for entry in items:
            uids = client.find_by_message_id(entry.message_id) if entry.message_id else []
            if not uids:
                missing += 1
                continue
            back[entry.source].extend(uids)
            restored += 1
            journal.append(JournalEntry(stamp, run, entry.rule, "restore", dest, entry.source,
                                        entry.message_id, entry.sender, entry.subject))
        for source, uids in back.items():
            client.ensure_folder(source)
            client.move(uids, source)

    for source, items in flagged.items():
        if client.find_folder(source) is None:
            missing += len(items)
            continue
        client.select(source, readonly=False)
        for entry in items:
            uids = client.find_by_message_id(entry.message_id) if entry.message_id else []
            if not uids:
                missing += 1
                continue
            client.set_flags(uids, r"\Seen" if entry.action == "mark_read" else r"\Flagged", add=False)
            restored += 1
            journal.append(JournalEntry(stamp, run, entry.rule, "restore", source, source,
                                        entry.message_id, entry.sender, entry.subject))
    return restored, missing, journal
