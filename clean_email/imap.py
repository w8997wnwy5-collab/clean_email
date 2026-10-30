"""IMAP access to iCloud Mail over verified TLS.

Messages are never deleted for good: the bot moves them (to a folder, to Junk
or to Deleted Messages, which iCloud keeps for 30 days) or changes their
flags. The one exception is the bot's own folder, where it replaces its rules
and journal messages.
"""

from __future__ import annotations

import imaplib
import re
import ssl
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Iterable, Iterator

from . import imap_utf7, security
from .credentials import Credentials
from .message import HEADER_FIELDS, MessageInfo, parse_header_block

FETCH_BATCH = 100
CHANGE_BATCH = 200
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# Special-use attribute, then the names iCloud (and other servers) use.
SPECIAL_FOLDERS = {
    "trash": ("\\trash", ("Deleted Messages", "Trash")),
    "junk": ("\\junk", ("Junk", "Spam")),
    "archive": ("\\archive", ("Archive",)),
    "sent": ("\\sent", ("Sent Messages", "Sent")),
    "drafts": ("\\drafts", ("Drafts",)),
}

_LIST_LINE = re.compile(rb'^\((?P<flags>[^)]*)\)\s+(?P<delim>NIL|"(?:\\.|[^"\\])*")\s+(?P<name>.*)$', re.I | re.S)
_FETCH_START = re.compile(rb"^\d+ \(")
_UID = re.compile(rb"\bUID (\d+)")
_FLAGS = re.compile(rb"\bFLAGS \(([^)]*)\)")
_INTERNALDATE = re.compile(rb'\bINTERNALDATE "([^"]+)"')
_SIZE = re.compile(rb"\bRFC822\.SIZE (\d+)")
_STATUS = re.compile(rb"\b(MESSAGES|UNSEEN) (\d+)", re.I)
_INTERNALDATE_TEXT = re.compile(
    r"\s*(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})"
)
_MESSAGE_ID = re.compile(r"^<[^<>\"\\\s]{3,400}>$")


class MailError(Exception):
    """A failure explained in Italian, safe to show to the user."""


class AuthError(MailError):
    pass


class CertificateError(MailError):
    pass


@dataclass(frozen=True)
class Folder:
    name: str
    flags: frozenset = frozenset()
    delimiter: str | None = "/"

    @property
    def selectable(self) -> bool:
        return not ({"\\noselect", "\\nonexistent"} & self.flags)


def validate_folder_name(name: str) -> str:
    name = name.strip()
    if not name or len(name) > 200:
        raise MailError("Il nome della cartella è vuoto o troppo lungo")
    if security.has_control_chars(name) or any(c in name for c in '*%"\\'):
        raise MailError(f"Il nome «{security.safe_text(name)}» contiene caratteri non ammessi")
    if name.startswith("/") or name.endswith("/") or "//" in name:
        raise MailError(f"Il nome «{security.safe_text(name)}» non è valido")
    return name


def quote(value: str) -> str:
    if security.has_control_chars(value):
        raise MailError("Il testo contiene caratteri non ammessi")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def quote_mailbox(name: str) -> str:
    return quote(imap_utf7.encode(name))


def imap_date(day: date) -> str:
    """IMAP search date; month names are English whatever the locale."""
    return f"{day.day}-{_MONTHS[day.month - 1]}-{day.year}"


def uid_set(uids: Iterable[int]) -> str:
    """Compact UIDs into IMAP ranges, e.g. 1:3,7,9:10."""
    parts: list[str] = []
    start = prev = None
    for uid in sorted(set(uids)):
        if start is None:
            start = prev = uid
        elif uid == prev + 1:
            prev = uid
        else:
            parts.append(str(start) if start == prev else f"{start}:{prev}")
            start = prev = uid
    if start is not None:
        parts.append(str(start) if start == prev else f"{start}:{prev}")
    return ",".join(parts)


def _chunks(items: list[int], size: int) -> Iterator[list[int]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def parse_internaldate(text: str) -> datetime | None:
    m = _INTERNALDATE_TEXT.match(text)
    if not m:
        return None
    day, mon, year, hh, mm, ss, sign, tzh, tzm = m.groups()
    try:
        month = [x.lower() for x in _MONTHS].index(mon.lower()) + 1
        offset = timedelta(hours=int(tzh), minutes=int(tzm))
        tz = timezone(offset if sign == "+" else -offset)
        return datetime(int(year), month, int(day), int(hh), int(mm), int(ss), tzinfo=tz)
    except ValueError:
        return None


def _unquote(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace").strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return re.sub(r"\\(.)", r"\1", text[1:-1])
    return text


def parse_list_response(data: list) -> list[Folder]:
    folders = []
    for item in data or []:
        literal = None
        if isinstance(item, tuple):
            line, literal = item[0], item[1]
        else:
            line = item
        if not line:
            continue
        m = _LIST_LINE.match(bytes(line).strip())
        if not m:
            continue
        flags = frozenset(f.lower() for f in m.group("flags").decode("ascii", "replace").split())
        delim_raw = m.group("delim")
        delimiter = None if delim_raw.upper() == b"NIL" else _unquote(delim_raw)
        raw_name = literal.decode("utf-8", "replace") if literal is not None else _unquote(m.group("name"))
        folders.append(Folder(imap_utf7.decode(raw_name), flags, delimiter))
    return folders


def fetch_records(data: list) -> Iterator[tuple[bytes, bytes]]:
    """(metadata, literal) for each FETCH response, whatever order its items come in.

    imaplib returns a literal as (prefix, literal) followed by the rest of the
    line; some servers (iCloud among them) put UID or FLAGS after the literal.
    """
    current: list | None = None
    for item in data or []:
        if isinstance(item, tuple):
            if current is not None:
                yield current[0], current[1]
            current = [bytes(item[0]), bytes(item[1])]
        elif isinstance(item, (bytes, bytearray)) and item:
            if current is not None and not _FETCH_START.match(item):
                current[0] += b" " + bytes(item)
                continue
            if current is not None:
                yield current[0], current[1]
                current = None
            yield bytes(item), b""
    if current is not None:
        yield current[0], current[1]


def message_from_fetch(meta: bytes, literal: bytes, folder: str) -> MessageInfo | None:
    uid = _UID.search(meta)
    if not uid:
        return None
    flags_m = _FLAGS.search(meta)
    flags: frozenset = frozenset()
    if flags_m:
        flags = frozenset(f.lower() for f in flags_m.group(1).decode("ascii", "replace").split())
    date_m = _INTERNALDATE.search(meta)
    size_m = _SIZE.search(meta)
    return parse_header_block(
        literal,
        uid=int(uid.group(1)),
        folder=folder,
        flags=flags,
        internal_date=parse_internaldate(date_m.group(1).decode("ascii", "replace")) if date_m else None,
        size=int(size_m.group(1)) if size_m else 0,
    )


def _error_text(exc: Exception) -> str:
    # Python 3.10's imaplib puts the server reply in the error as a bytes repr.
    text = str(exc)
    if text[:2] in ("b'", 'b"') and text[-1:] in ("'", '"'):
        text = text[2:-1]
    return security.safe_text(text, 160)


def _server_text(data: list) -> str:
    for item in data or []:
        if isinstance(item, (bytes, bytearray)):
            return security.safe_text(item.decode("utf-8", "replace"), 160)
    return ""


class MailClient:
    def __init__(self, conn: imaplib.IMAP4, address: str):
        self._conn = conn
        self.email = address
        self.capabilities = self._read_capabilities()
        self._folders: list[Folder] | None = None
        self.selected: str | None = None

    @classmethod
    def connect(
        cls,
        creds: Credentials,
        *,
        host: str = security.ICLOUD_IMAP_HOST,
        port: int = security.ICLOUD_IMAP_PORT,
        ssl_context: ssl.SSLContext | None = None,
        timeout: float = 30.0,
        allow_test_server: bool = False,
    ) -> "MailClient":
        """Open a verified TLS connection and log in.

        `allow_test_server` exists for the test suite only; the command line
        cannot reach it, so the password only ever goes to Apple's server.
        """
        if not allow_test_server:
            security.check_server(host, port)
        context = ssl_context or security.tls_context()
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise MailError("Connessione rifiutata: la verifica del certificato deve restare attiva")
        if context.minimum_version < ssl.TLSVersion.TLSv1_2:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            conn = imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=timeout)
        except ssl.SSLCertVerificationError as exc:
            raise CertificateError(
                "Il certificato del server non è valido: connessione interrotta prima di "
                f"inviare la password ({exc.verify_message})."
            ) from None
        except ssl.SSLError as exc:
            raise MailError(f"La connessione cifrata non è riuscita ({exc.reason or exc}).") from None
        except (OSError, imaplib.IMAP4.error) as exc:
            raise MailError(f"Non riesco a raggiungere {host}: {exc}") from None

        conn.debug = 0  # imaplib debug output would include the LOGIN command
        if conn.sock.version() not in security.ACCEPTED_TLS_VERSIONS:
            conn.shutdown()
            raise MailError("Il server propone una versione di TLS troppo vecchia: connessione interrotta.")
        try:
            conn.login(creds.login, creds.password)
        except imaplib.IMAP4.error as exc:
            try:
                conn.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
            raise AuthError(
                "iCloud ha rifiutato l'accesso. Controlla di usare una password specifica per "
                f"le app (non quella dell'Apple ID) e l'indirizzo iCloud giusto. Risposta: {_error_text(exc)}"
            ) from None
        return cls(conn, creds.email)

    def __enter__(self) -> "MailClient":
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    def logout(self) -> None:
        # LOGOUT, never CLOSE: CLOSE would also expunge messages that another
        # app has only marked as deleted.
        try:
            self._conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass

    def noop(self) -> bool:
        try:
            return self._conn.noop()[0] == "OK"
        except (imaplib.IMAP4.error, OSError):
            return False

    def tls_info(self) -> dict[str, str]:
        sock = self._conn.sock
        cert = sock.getpeercert() or {}

        def dn(parts) -> str:
            return ", ".join(f"{k}={v}" for rdn in parts for (k, v) in rdn)

        cipher = sock.cipher()
        return {
            "protocollo": sock.version() or "?",
            "cifratura": cipher[0] if cipher else "?",
            "certificato": dn(cert.get("subject", ())),
            "emesso da": dn(cert.get("issuer", ())),
            "valido fino al": str(cert.get("notAfter", "?")),
        }

    def _read_capabilities(self) -> frozenset[str]:
        try:
            typ, data = self._conn.capability()
        except imaplib.IMAP4.error:
            return frozenset(getattr(self._conn, "capabilities", ()))
        words: set[str] = set()
        for chunk in data or []:
            if chunk:
                words.update(chunk.decode("ascii", "replace").upper().split())
        return frozenset(words)

    @staticmethod
    def _ok(result: tuple, message: str) -> list:
        typ, data = result
        if typ != "OK":
            detail = _server_text(data)
            raise MailError(f"{message}{': ' + detail if detail else ''}")
        return data

    # Folders

    def folders(self, refresh: bool = False) -> list[Folder]:
        if self._folders is None or refresh:
            data = self._ok(self._conn.list(), "Non riesco a leggere l'elenco delle cartelle")
            self._folders = parse_list_response(data)
        return self._folders

    def find_folder(self, name: str) -> Folder | None:
        for folder in self.folders():
            if folder.name == name or (name.upper() == "INBOX" and folder.name.upper() == "INBOX"):
                return folder
        return None

    def special_folder(self, kind: str) -> Folder | None:
        flag, names = SPECIAL_FOLDERS[kind]
        for folder in self.folders():
            if flag in folder.flags:
                return folder
        for name in names:
            folder = self.find_folder(name)
            if folder:
                return folder
        return None

    def ensure_folder(self, name: str) -> Folder:
        name = validate_folder_name(name)
        found = self.find_folder(name)
        if found:
            return found
        typ, data = self._conn.create(quote_mailbox(name))
        self._folders = None
        if typ == "OK":
            try:
                self._conn.subscribe(quote_mailbox(name))
            except imaplib.IMAP4.error:
                pass
        found = self.find_folder(name)
        if found is None:
            detail = _server_text(data)
            detail = f": {detail}" if detail else ""
            raise MailError(f"Non riesco a creare la cartella «{security.safe_text(name)}»{detail}")
        return found

    def select(self, name: str, *, readonly: bool = True) -> tuple[int, int | None]:
        """Open a folder; return (message count, UIDVALIDITY)."""
        typ, data = self._conn.select(quote_mailbox(name), readonly=readonly)
        if typ != "OK":
            self.selected = None
            raise MailError(f"Non riesco ad aprire la cartella «{security.safe_text(name)}»")
        self.selected = name
        exists = int(data[0]) if data and data[0] and bytes(data[0]).isdigit() else 0
        _, values = self._conn.response("UIDVALIDITY")
        uidvalidity = int(values[0]) if values and values[0] and bytes(values[0]).isdigit() else None
        return exists, uidvalidity

    def status(self, name: str) -> tuple[int, int]:
        """(messages, unread) of a folder, without opening it."""
        data = self._ok(self._conn.status(quote_mailbox(name), "(MESSAGES UNSEEN)"), "Stato non disponibile")
        text = b" ".join(b" ".join(i) if isinstance(i, tuple) else bytes(i or b"") for i in data)
        values = {k.upper(): int(v) for k, v in _STATUS.findall(text.rsplit(b"(", 1)[-1])}
        return values.get(b"MESSAGES", 0), values.get(b"UNSEEN", 0)

    # Reading

    def search(self, *criteria: str) -> list[int]:
        data = self._ok(self._conn.uid("SEARCH", *(criteria or ("ALL",))), "Ricerca non riuscita")
        uids: set[int] = set()
        for chunk in data or []:
            if chunk:
                uids.update(int(x) for x in bytes(chunk).split() if x.isdigit())
        return sorted(uids)

    def fetch_headers(self, uids: Iterable[int]) -> list[MessageInfo]:
        fields = " ".join(f.upper() for f in HEADER_FIELDS)
        items = f"(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS ({fields})])"
        folder = self.selected or ""
        result: list[MessageInfo] = []
        for batch in _chunks(sorted(set(uids)), FETCH_BATCH):
            wanted = set(batch)
            data = self._ok(self._conn.uid("FETCH", uid_set(batch), items), "Lettura dei messaggi non riuscita")
            for meta, literal in fetch_records(data):
                info = message_from_fetch(meta, literal, folder)
                if info is not None and info.uid in wanted:
                    wanted.discard(info.uid)
                    result.append(info)
        return result

    def fetch_fields(self, uids: Iterable[int], fields: tuple[str, ...]) -> dict[int, bytes]:
        """The given header fields of each message, as a raw header block."""
        items = f"(UID BODY.PEEK[HEADER.FIELDS ({' '.join(f.upper() for f in fields)})])"
        result: dict[int, bytes] = {}
        for batch in _chunks(sorted(set(uids)), FETCH_BATCH):
            data = self._ok(self._conn.uid("FETCH", uid_set(batch), items), "Lettura non riuscita")
            for meta, literal in fetch_records(data):
                m = _UID.search(meta)
                if m and int(m.group(1)) in batch:
                    result[int(m.group(1))] = literal
        return result

    def fetch_raw(self, uid: int) -> bytes | None:
        """Whole message, used only for the bot's own messages."""
        data = self._ok(self._conn.uid("FETCH", str(uid), "(BODY.PEEK[])"), "Lettura non riuscita")
        for meta, literal in fetch_records(data):
            m = _UID.search(meta)
            if m and int(m.group(1)) == uid and literal:
                return literal
        return None

    def find_by_message_id(self, message_id: str) -> list[int]:
        if not _MESSAGE_ID.match(message_id):
            return []
        return self.search("HEADER", "Message-ID", quote(message_id))

    # Changing

    def move(self, uids: Iterable[int], dest: str) -> int:
        """Move messages of the selected folder; returns how many were asked to move."""
        ordered = sorted(set(uids))
        target = quote_mailbox(dest)
        for batch in _chunks(ordered, CHANGE_BATCH):
            ids = uid_set(batch)
            failure = f"Spostamento in «{security.safe_text(dest)}» non riuscito"
            if "MOVE" in self.capabilities:
                self._ok(self._conn.uid("MOVE", ids, target), failure)
            elif "UIDPLUS" in self.capabilities:
                self._ok(self._conn.uid("COPY", ids, target), failure)
                self._ok(self._conn.uid("STORE", ids, "+FLAGS.SILENT", r"(\Deleted)"), failure)
                self._ok(self._conn.uid("EXPUNGE", ids), failure)
            else:
                # Plain EXPUNGE would also purge messages other apps marked as deleted.
                raise MailError("Il server non permette di spostare i messaggi in modo sicuro")
        return len(ordered)

    def set_flags(self, uids: Iterable[int], flags: str, *, add: bool = True) -> int:
        ordered = sorted(set(uids))
        op = "+FLAGS.SILENT" if add else "-FLAGS.SILENT"
        for batch in _chunks(ordered, CHANGE_BATCH):
            self._ok(self._conn.uid("STORE", uid_set(batch), op, f"({flags})"), "Modifica non riuscita")
        return len(ordered)

    def append(self, folder: str, raw: bytes, flags: str | None = r"(\Seen)", when: datetime | None = None) -> None:
        self._ok(self._conn.append(quote_mailbox(folder), flags, when, raw), "Salvataggio non riuscito")

    def remove_own_messages(self, uids: Iterable[int]) -> None:
        """Delete messages for good. Only for the bot's own folder and messages."""
        ordered = sorted(set(uids))
        if not ordered:
            return
        ids = uid_set(ordered)
        self._ok(self._conn.uid("STORE", ids, "+FLAGS.SILENT", r"(\Deleted)"), "Pulizia non riuscita")
        if "UIDPLUS" in self.capabilities:
            self._ok(self._conn.uid("EXPUNGE", ids), "Pulizia non riuscita")
        else:
            self._ok(self._conn.expunge(), "Pulizia non riuscita")
