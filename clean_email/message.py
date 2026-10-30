"""A message as the bot sees it: header fields only, never the body."""

from __future__ import annotations

import email
import email.errors
import email.header
import email.utils
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.policy import compat32

# The only header fields the bot downloads. Bodies and attachments stay on the
# server: classification works on these alone.
HEADER_FIELDS = (
    "From", "Sender", "Reply-To", "To", "Cc", "Subject", "Date", "Message-ID",
    "List-Id", "List-Unsubscribe", "List-Unsubscribe-Post", "List-Post", "Precedence",
    "Auto-Submitted", "X-Auto-Response-Suppress", "Feedback-ID", "X-Mailer",
    "X-CSA-Complaints", "X-Campaign", "X-MC-User", "X-SG-EID", "X-SES-Outgoing",
    "X-Mailgun-Sid", "X-SFMC-Stack", "X-MJ-Mid",
    "Authentication-Results", "X-Spam-Flag", "X-Spam-Status", "X-Proofpoint-Spam-Details",
)

_FOLDED = re.compile(r"\r?\n[ \t]+")
_UNSAFE_IN_ADDRESS = re.compile(r"[\s\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")

# Common two-level public suffixes, enough to tell "evil.co.uk" from "co.uk".
_MULTI_LEVEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "ne.jp", "co.za", "com.br", "com.mx", "com.ar", "com.tr",
    "co.in", "com.cn", "com.hk", "com.sg", "co.il", "co.kr", "com.tw", "gov.it",
    "edu.it", "admin.ch",
})


def _decode_bytes(data: bytes, charset: str | None = None) -> str:
    if charset:
        try:
            return data.decode(charset, "replace")
        except LookupError:
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _as_text(value: object) -> str:
    """A raw header value as text. Unencoded 8-bit bytes, which compat32 wraps
    in an "unknown-8bit" Header, are read as UTF-8 (or Latin-1)."""
    if isinstance(value, email.header.Header):
        pieces = []
        for chunk, charset in email.header.decode_header(value):
            if isinstance(chunk, bytes):
                chunk = _decode_bytes(chunk, None if charset in (None, "unknown-8bit") else charset)
            pieces.append(chunk)
        value = "".join(pieces)
    text = str(value)
    try:
        text = text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeError:
        pass
    return _FOLDED.sub(" ", text)


def decode_header_value(value: object) -> str:
    if value is None:
        return ""
    text = _as_text(value)
    try:
        return str(email.header.make_header(email.header.decode_header(text)))
    except (LookupError, UnicodeError, ValueError, email.errors.HeaderParseError):
        pieces = []
        for chunk, charset in email.header.decode_header(text):
            if isinstance(chunk, bytes):
                chunk = _decode_bytes(chunk, charset)
            pieces.append(chunk)
        return "".join(pieces)


def parse_addresses(values: list[str]) -> list[tuple[str, str]]:
    """(display name, lowercase address) pairs; malformed entries are dropped."""
    raw = [_as_text(v) for v in values]
    result = []
    for name, addr in email.utils.getaddresses(raw):
        addr = addr.strip().lower()
        if "@" not in addr or _UNSAFE_IN_ADDRESS.search(addr):
            continue
        result.append((decode_header_value(name).strip(), addr))
    return result


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[1].lower().rstrip(".") if "@" in address else ""


def registrable_domain(domain: str) -> str:
    labels = [p for p in domain.lower().strip(".").split(".") if p]
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass
class MessageInfo:
    uid: int
    folder: str
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    recipients: tuple[str, ...] = ()
    subject: str = ""
    message_id: str = ""
    date: datetime | None = None
    size: int = 0
    flags: frozenset[str] = frozenset()
    # Lowercase field name -> decoded values in message order (topmost first).
    headers: dict[str, list[str]] = field(default_factory=dict)

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)

    @property
    def seen(self) -> bool:
        return "\\seen" in self.flags

    def header(self, name: str) -> str:
        values = self.headers.get(name.lower())
        return values[0] if values else ""

    def has_header(self, name: str) -> bool:
        return name.lower() in self.headers


def parse_header_block(
    raw: bytes,
    *,
    uid: int,
    folder: str,
    flags: frozenset[str] = frozenset(),
    internal_date: datetime | None = None,
    size: int = 0,
) -> MessageInfo:
    msg = email.message_from_bytes(raw, policy=compat32)
    raw_values: dict[str, list[str]] = {}
    for key, value in msg.items():
        raw_values.setdefault(key.lower(), []).append(value)

    headers = {k: [decode_header_value(v) for v in vs] for k, vs in raw_values.items()}
    senders = parse_addresses(raw_values.get("from", [])[:1])
    from_name, from_addr = senders[0] if senders else ("", "")
    if not from_addr:
        from_name = headers.get("from", [""])[0]
    reply = parse_addresses(raw_values.get("reply-to", [])[:1])
    recipients = tuple(a for _, a in parse_addresses(raw_values.get("to", []) + raw_values.get("cc", [])))

    date = internal_date
    if date is None and headers.get("date"):
        try:
            date = email.utils.parsedate_to_datetime(headers["date"][0])
        except (TypeError, ValueError, IndexError):
            date = None
    if date is not None and date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)

    return MessageInfo(
        uid=uid,
        folder=folder,
        from_name=from_name,
        from_addr=from_addr,
        reply_to=reply[0][1] if reply else "",
        recipients=recipients,
        subject=headers.get("subject", [""])[0],
        message_id=headers.get("message-id", [""])[0].strip(),
        date=date,
        size=size,
        flags=flags,
        headers=headers,
    )
