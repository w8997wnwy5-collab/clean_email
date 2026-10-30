"""Connection policy and handling of untrusted text.

The bot only ever talks to Apple's IMAP server over implicit TLS on port 993,
with certificate and host name verification and TLS 1.2 as the floor. There is
no switch to turn verification off or to point the bot at another server:
a tampered configuration cannot send the password elsewhere.
"""

from __future__ import annotations

import re
import ssl

ICLOUD_IMAP_HOST = "imap.mail.me.com"
ICLOUD_IMAP_PORT = 993
ALLOWED_HOSTS = frozenset({ICLOUD_IMAP_HOST})
ACCEPTED_TLS_VERSIONS = frozenset({"TLSv1.2", "TLSv1.3"})

# C0/C1 control characters, including ESC: a subject line must not be able to
# drive the terminal it is printed on.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_WHITESPACE = re.compile(r"\s+")


def tls_context(cafile: str | None = None) -> ssl.SSLContext:
    """Build the client TLS context: verified certificates, TLS 1.2 or newer."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if cafile is None and ctx.cert_store_stats().get("x509_ca", 0) == 0:
        # Some Python builds (python.org on macOS, some iPhone apps) ship without
        # system CA certificates. certifi fills the gap when it is installed;
        # verification is never switched off.
        try:
            import certifi  # type: ignore[import-not-found]
        except ImportError:
            pass
        else:
            ctx.load_verify_locations(certifi.where())
    return ctx


def check_server(host: str, port: int) -> None:
    if host not in ALLOWED_HOSTS or port != ICLOUD_IMAP_PORT:
        raise ValueError(
            f"Per sicurezza il bot si collega solo a {ICLOUD_IMAP_HOST}:{ICLOUD_IMAP_PORT}"
        )


def safe_text(value: object, limit: int = 120) -> str:
    """Make untrusted text (subjects, names) safe to print on one terminal line."""
    text = _CONTROL_CHARS.sub(" ", str(value))
    text = _WHITESPACE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def has_control_chars(value: str) -> bool:
    return bool(re.search(r"[\x00-\x1f\x7f]", value))
