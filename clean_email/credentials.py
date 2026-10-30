"""Where the iCloud address and its app-specific password are kept.

Order of lookup:
1. the ICLOUD_EMAIL and ICLOUD_APP_PASSWORD environment variables (GitHub
   Actions secrets end up here);
2. what `configura` saved on this device: the address in account.json, the
   password in the iOS Keychain when running in Pythonista, otherwise in a
   file readable only by the owner (mode 0600).

The password is an app-specific password: it only opens Mail, Contacts and
Calendars, and it can be revoked at account.apple.com without touching the
Apple ID password, which the bot never needs.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

ENV_EMAIL = "ICLOUD_EMAIL"
ENV_PASSWORD = "ICLOUD_APP_PASSWORD"
ENV_USERNAME = "ICLOUD_USERNAME"  # only if iCloud wants the name before the @ to log in
ENV_HOME = "CLEAN_EMAIL_HOME"
KEYCHAIN_SERVICE = "clean_email.icloud"

_APP_PASSWORD = re.compile(r"^[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True)
class Credentials:
    email: str
    password: str = field(repr=False)
    source: str = ""
    # Apple's settings say the login name is "usually" the part before the @;
    # most accounts accept the whole address, some only the short name.
    username: str = ""

    @property
    def login(self) -> str:
        return self.username or self.email


def normalize_password(raw: str) -> str:
    return "".join(raw.split()).lower()


def looks_like_app_password(password: str) -> bool:
    return bool(_APP_PASSWORD.match(password))


def valid_email(address: str) -> bool:
    return bool(_EMAIL.match(address))


def config_dir() -> Path:
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    home = Path.home()
    if (home / "Library").is_dir():
        # macOS, and iPhone apps such as a-Shell or Pythonista, whose home
        # folder itself is not writable.
        return home / "Library" / "Application Support" / "clean_email"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg).expanduser() if xdg else home / ".config") / "clean_email"


def _account_file() -> Path:
    return config_dir() / "account.json"


def _password_file() -> Path:
    return config_dir() / "password"


def _pythonista_keychain():
    try:
        import keychain  # type: ignore[import-not-found]  # Pythonista on iOS
    except ImportError:
        return None
    if all(hasattr(keychain, n) for n in ("get_password", "set_password", "delete_password")):
        return keychain
    return None


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_private(path: Path) -> str | None:
    try:
        if path.stat().st_mode & 0o077:
            os.chmod(path, 0o600)
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def load() -> Credentials | None:
    email = os.environ.get(ENV_EMAIL, "").strip()
    password = os.environ.get(ENV_PASSWORD, "")
    if email and password:
        username = os.environ.get(ENV_USERNAME, "").strip()
        return Credentials(email, normalize_password(password), "variabili d'ambiente", username)

    raw = _read_private(_account_file())
    if not raw:
        return None
    try:
        account = json.loads(raw)
        email = str(account["email"])
        store = str(account.get("store", "file"))
        username = str(account.get("username", ""))
    except (ValueError, KeyError, TypeError):
        return None

    if store == "keychain":
        keychain = _pythonista_keychain()
        password = keychain.get_password(KEYCHAIN_SERVICE, email) if keychain else None
        source = "portachiavi di iOS"
    else:
        password = _read_private(_password_file())
        source = f"file protetto in {config_dir()}"
    if not password:
        return None
    return Credentials(email, password.strip(), source, username)


def save(creds: Credentials) -> str:
    """Store credentials on this device; return a description of where."""
    keychain = _pythonista_keychain()
    if keychain:
        keychain.set_password(KEYCHAIN_SERVICE, creds.email, creds.password)
        store, where = "keychain", "nel portachiavi di iOS"
    else:
        _write_private(_password_file(), creds.password)
        store, where = "file", f"in un file leggibile solo da te ({_password_file()})"
    account = {"email": creds.email, "store": store}
    if creds.username:
        account["username"] = creds.username
    _write_private(_account_file(), json.dumps(account))
    return where


def forget() -> bool:
    removed = False
    raw = _read_private(_account_file())
    if raw:
        try:
            email = json.loads(raw).get("email")
        except ValueError:
            email = None
        keychain = _pythonista_keychain()
        if keychain and email:
            try:
                keychain.delete_password(KEYCHAIN_SERVICE, email)
            except Exception:  # Pythonista raises if the item is missing
                pass
    for path in (_password_file(), _account_file()):
        try:
            path.unlink()
            removed = True
        except FileNotFoundError:
            pass
    return removed
