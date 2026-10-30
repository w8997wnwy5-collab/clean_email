"""A throwaway Dovecot IMAP server over TLS, for the integration tests.

It runs without root (as the current user, or as `nobody` when the tests run
as root), listens on 127.0.0.1 with a certificate from a private test CA, and
mimics iCloud's folder names. Tests skip when Dovecot or openssl is missing.
On Debian or Ubuntu: sudo apt-get install dovecot-imapd
"""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

DOVECOT = shutil.which("dovecot") or ("/usr/sbin/dovecot" if os.path.exists("/usr/sbin/dovecot") else None)
OPENSSL = shutil.which("openssl")
PASSWORD = "abcd-efgh-ijkl-mnop"  # any user name logs in with it, each with its own mailbox


def available() -> bool:
    return bool(DOVECOT and OPENSSL)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(*args: str, cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


class DovecotServer:
    def __init__(self, *, special_use: bool = True, capabilities: str | None = None):
        self.special_use = special_use
        self.capabilities = capabilities
        self.dir = Path(tempfile.mkdtemp(prefix="clean-email-dovecot-"))
        self.port = _free_port()
        self.host = "localhost"
        self.cafile = str(self.dir / "ca.crt")
        self.process: subprocess.Popen | None = None

    def _certificates(self) -> None:
        d = self.dir
        # Python 3.13 verifies strictly (VERIFY_X509_STRICT): both certificates
        # need the usual X.509 v3 extensions.
        _run(OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/CN=Clean Email Test CA", "-keyout", "ca.key", "-out", "ca.crt",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-addext", "subjectKeyIdentifier=hash", cwd=d)
        _run(OPENSSL, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", "server.key", "-out", "server.csr", cwd=d)
        (d / "san.ext").write_text(
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
        )
        _run(OPENSSL, "x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
             "-CAcreateserial", "-days", "2", "-extfile", "san.ext", "-out", "server.crt", cwd=d)

    def _config(self, user: str, uid: int, gid: int) -> Path:
        d = self.dir
        special = {
            "Deleted Messages": "\\Trash", "Junk": "\\Junk", "Archive": "\\Archive",
            "Sent Messages": "\\Sent", "Drafts": "\\Drafts",
        }
        mailboxes = "\n".join(
            f'  mailbox "{name}" {{\n    auto = subscribe\n'
            + (f"    special_use = {flag}\n" if self.special_use else "")
            + "  }"
            for name, flag in special.items()
        )
        capability = f"imap_capability = {self.capabilities}\n" if self.capabilities else ""
        conf = f"""
base_dir = {d}/run
state_dir = {d}/state
log_path = {d}/dovecot.log
protocols = imap
listen = 127.0.0.1
ssl = required
ssl_cert = <{d}/server.crt
ssl_key = <{d}/server.key
ssl_min_protocol = TLSv1.2
default_internal_user = {user}
default_internal_group = {grp.getgrgid(gid).gr_name}
default_login_user = {user}
first_valid_uid = 1
auth_mechanisms = plain login
mail_location = maildir:{d}/mail/%u:LAYOUT=fs
{capability}
passdb {{
  driver = static
  args = password={PASSWORD}
}}
userdb {{
  driver = static
  args = uid={uid} gid={gid} home={d}/mail/%u
}}
namespace inbox {{
  inbox = yes
  separator = /
{mailboxes}
}}
service imap-login {{
  chroot =
  inet_listener imap {{
    port = 0
  }}
  inet_listener imaps {{
    address = 127.0.0.1
    port = {self.port}
    ssl = yes
  }}
}}
service anvil {{
  chroot =
}}
service imap {{
  process_limit = 10
}}
service stats {{
  unix_listener stats-reader {{
    user = {user}
  }}
  unix_listener stats-writer {{
    user = {user}
  }}
}}
"""
        path = d / "dovecot.conf"
        path.write_text(conf)
        return path

    def start(self) -> "DovecotServer":
        self._certificates()
        if os.geteuid() == 0:
            entry = pwd.getpwnam("nobody")
            user, uid, gid = "nobody", entry.pw_uid, entry.pw_gid
        else:
            entry = pwd.getpwuid(os.geteuid())
            user, uid, gid = entry.pw_name, entry.pw_uid, entry.pw_gid
        conf = self._config(user, uid, gid)
        for sub in ("run", "state", "mail"):
            (self.dir / sub).mkdir()
        kwargs = {}
        if os.geteuid() == 0:
            os.chmod(self.dir, 0o755)
            for path in [self.dir, *self.dir.rglob("*")]:
                os.chown(path, uid, gid)
            kwargs = {"user": uid, "group": gid, "extra_groups": []}
        self.process = subprocess.Popen(
            [DOVECOT, "-F", "-c", str(conf)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                out = self.process.stdout.read().decode(errors="replace") if self.process.stdout else ""
                raise RuntimeError(f"Dovecot did not start:\n{out}\n{self.log()}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return self
            except OSError:
                time.sleep(0.1)
        self.stop()
        raise RuntimeError(f"Dovecot did not open its port:\n{self.log()}")

    def log(self) -> str:
        try:
            return (self.dir / "dovecot.log").read_text(errors="replace")
        except OSError:
            return ""

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self.process and self.process.stdout:
            self.process.stdout.close()
        shutil.rmtree(self.dir, ignore_errors=True)
