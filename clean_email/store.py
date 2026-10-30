"""Where the rules and the journal live: in the mailbox, in the bot's folder.

Keeping them in iCloud means the public repository never holds personal data,
and every place the bot runs (the iPhone, GitHub Actions) reads the same rules.
A stored document is a message the bot appended itself. Mail delivered from
outside always carries Received headers, so a forged copy that someone mails
to the user is ignored.
"""

from __future__ import annotations

import email
import email.policy
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Callable

from .imap import MailClient
from .rules import RESERVED_FOLDER, RuleError, RuleSet, describe, ruleset_from_dict, ruleset_to_dict
from .security import safe_text

DOC_HEADER = "X-Clean-Email-Document"
SUBJECTS = {"rules": "Regole del bot (non cancellare)", "journal": "Registro del bot"}
JOURNAL_LIMIT = 1000
_KINDS = frozenset(SUBJECTS)


def _parse(text: str, kind: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        what = "Le regole salvate" if kind == "rules" else "Il registro salvato"
        raise RuleError(f"{what} non si possono leggere: il file è rovinato")
    return data


class MailboxStore:
    def __init__(self, client: Callable[[], MailClient]):
        self._client = client

    def _documents(self, kind: str) -> list[int]:
        """UIDs of the bot's own copies of a document, oldest first."""
        client = self._client()
        if client.find_folder(RESERVED_FOLDER) is None:
            return []
        client.select(RESERVED_FOLDER, readonly=True)
        headers = client.fetch_fields(client.search("UNDELETED"), (DOC_HEADER, "Received"))
        found = []
        for uid, raw in headers.items():
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            if str(msg.get(DOC_HEADER, "")).strip() == kind and not msg.get_all("Received"):
                found.append(uid)
        return sorted(found)

    def load(self, kind: str) -> dict | None:
        docs = self._documents(kind)
        raw = self._client().fetch_raw(docs[-1]) if docs else None
        if not raw:
            return None
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        if msg.get_all("Received"):
            return None
        for part in msg.walk():
            if part.get_content_type() == "application/json":
                payload = part.get_payload(decode=True) or b""
                return _parse(payload.decode("utf-8", "replace"), kind)
        return None

    def save(self, kind: str, data: dict, summary: str) -> None:
        if kind not in _KINDS:
            raise ValueError(kind)
        client = self._client()
        old = self._documents(kind)
        msg = EmailMessage()
        msg["From"] = f"Bot email <{client.email}>"
        msg["To"] = client.email
        msg["Subject"] = SUBJECTS[kind]
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="clean-email.local")
        msg[DOC_HEADER] = kind
        msg.set_content(summary)
        msg.add_attachment(
            json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"),
            maintype="application", subtype="json", filename=f"{kind}.json",
        )
        client.ensure_folder(RESERVED_FOLDER)
        # Write the new copy before removing the old ones: a failure in between
        # leaves two copies, and the newest (highest UID) wins.
        client.append(RESERVED_FOLDER, msg.as_bytes(policy=email.policy.SMTP))
        if old:
            client.select(RESERVED_FOLDER, readonly=False)
            client.remove_own_messages(old)


class FileStore:
    """Rules in a local JSON file, the journal next to it."""

    def __init__(self, rules_path: Path):
        self._paths = {"rules": rules_path, "journal": rules_path.with_name(rules_path.stem + ".registro.json")}

    def load(self, kind: str) -> dict | None:
        try:
            return _parse(self._paths[kind].read_text(encoding="utf-8"), kind)
        except FileNotFoundError:
            return None

    def save(self, kind: str, data: dict, summary: str) -> None:
        path = self._paths[kind]
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)


def load_rules(store) -> RuleSet:
    data = store.load("rules")
    return ruleset_from_dict(data) if data else RuleSet()


def save_rules(store, ruleset: RuleSet) -> None:
    lines = [
        "Queste sono le regole del bot di pulizia della posta.",
        "Non cancellare questo messaggio: il bot le legge da qui.",
        "Per cambiarle usa il bot (python3 bot.py, voce «Le mie regole»).",
        "",
    ]
    for n, rule in enumerate(ruleset.rules, 1):
        state = "attiva" if rule.enabled else "spenta"
        lines.append(f"{n}. [{state}] {rule.name}: {describe(rule)}")
    if not ruleset.rules:
        lines.append("Nessuna regola.")
    if ruleset.protected:
        lines += ["", "Mittenti protetti (il bot non li tocca mai): " + ", ".join(ruleset.protected)]
    store.save("rules", ruleset_to_dict(ruleset), "\n".join(lines) + "\n")


@dataclass(frozen=True)
class JournalEntry:
    time: str
    run: str
    rule: str
    action: str
    source: str
    dest: str | None
    message_id: str
    sender: str
    subject: str


@dataclass
class Journal:
    entries: list[JournalEntry] = field(default_factory=list)  # oldest first
    undone: list[str] = field(default_factory=list)  # runs already undone
    errors: list[str] = field(default_factory=list)  # latest problems, newest last


def load_journal(store) -> Journal:
    data = store.load("journal") or {}
    entries = []
    for item in data.get("entries") or []:
        if isinstance(item, dict):
            entries.append(JournalEntry(**{k: item.get(k) for k in JournalEntry.__dataclass_fields__}))
    return Journal(
        entries,
        [str(r) for r in data.get("undone") or []],
        [str(e) for e in data.get("errors") or []],
    )


def save_journal(store, journal: Journal) -> None:
    entries = journal.entries[-JOURNAL_LIMIT:]
    kept_runs = {e.run for e in entries}
    errors = journal.errors[-20:]
    lines = []
    if errors:
        lines += ["Ultimi problemi:", *(f"  {e}" for e in reversed(errors[-5:])), ""]
    lines += ["Le ultime azioni del bot, le più recenti in alto.", ""]
    lines += [entry_line(e) for e in reversed(entries[-60:])] or ["Nessuna azione."]
    data = {
        "version": 1,
        "entries": [asdict(e) for e in entries],
        "undone": [r for r in journal.undone if r in kept_runs],
        "errors": errors,
    }
    store.save("journal", data, "\n".join(lines) + "\n")


ACTION_WORDS = {
    "move": "spostata in",
    "trash": "nel Cestino",
    "junk": "in Indesiderata",
    "archive": "archiviata in",
    "mark_read": "segnata come letta",
    "flag": "contrassegnata",
    "restore": "rimessa a posto in",
}


def entry_line(entry: JournalEntry) -> str:
    try:
        when = datetime.fromisoformat(entry.time).astimezone().strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError):
        when = str(entry.time)[:16]
    what = ACTION_WORDS.get(entry.action, entry.action)
    if entry.action in ("move", "archive", "restore") and entry.dest:
        what += f" «{safe_text(entry.dest, 40)}»"
    return f"{when} · {what} · {safe_text(entry.sender, 50)} · {safe_text(entry.subject, 60)}"


def run_id(kind: str, now: datetime) -> str:
    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{kind}"
