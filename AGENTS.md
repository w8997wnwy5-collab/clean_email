# Bot pulizia email (iCloud)

A command-line bot that classifies the owner's iCloud Mail from header fields, proposes rules, and applies only the rules the owner approves. The owner uses it from an iPhone (a-Shell) and, optionally, hourly from GitHub Actions (`.github/workflows/regole.yml`). The owner's guide is the Italian `README.md`; keep it in step with anything the owner sees or does. Everything the user sees is Italian; code, comments and commit messages are English.

Layout (`clean_email/`): `security.py` (connection policy, terminal-safe text), `credentials.py`, `imap.py` (the only IMAP code), `message.py` (header parsing), `classifier.py`, `rules.py`, `engine.py` (plan, execute, undo), `store.py` (rules and journal kept as messages in the mailbox), `analysis.py` (statistics and proposals), `icloud_export.py`, `cli.py` and `ui.py` (Italian menu and commands). `bot.py` is the launcher.

Hard constraints:

- Standard library only, Python 3.10+ (Pythonista runs 3.10; a-Shell 3.13). Keep every module importable on both; the test matrix covers both, including the newer imaplib that quotes arguments itself.
- Connect only to `imap.mail.me.com:993` over verified TLS 1.2+. Never add a setting, flag or environment variable that disables certificate checks or changes the host; `allow_test_server` exists for the tests and must stay out of the CLI.
- Download header fields only (`BODY.PEEK[HEADER.FIELDS ...]`), never bodies, except the bot's own messages in `Bot Email`.
- Never delete mail for good, never send `CLOSE` or a bare `EXPUNGE` on user folders. Moves use `MOVE`, or `COPY` + `UID EXPUNGE` when the server has UIDPLUS. Only the bot's own folder may lose messages.
- Nothing personal in the repository or in unattended output: the repository and its Actions logs are public. `automatico` prints counts and rule numbers only; details go to the mailbox journal.
- Untrusted text (subjects, names, folder names) goes through `security.safe_text` before printing; values sent to the server go through `imap.quote`/`quote_mailbox`.
- Signals a sender can forge may only make a message look worse, never better (see `classifier.py`).
- Changes the user did not approve must not happen: interactive commands preview and ask; unattended runs only apply saved rules and skip a rule above the `--limite` cap.

Run `python3 -m unittest discover -s . -p 'test_*.py'` for every change. The integration tests start a throwaway Dovecot over TLS (`sudo apt-get install dovecot-imapd`) and are skipped without it; run them before claiming IMAP behaviour works. They imitate iCloud's folder names and a server without MOVE or special-use flags, but they are not iCloud: say so when reporting.

Repository tasks do not authorise access to the owner's mailbox. Never ask for, print or commit the app-specific password; it belongs in the owner's device or in GitHub Actions secrets.
