"""The bot's command line and interactive menu, in Italian."""

from __future__ import annotations

import argparse
import imaplib
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, credentials
from .analysis import Analysis, analyze, bulk_senders, propose
from .classifier import CATEGORIES
from .credentials import Credentials
from .engine import Classifier, Engine, FolderPlan, Outcome, undo
from .icloud_export import native_rules
from .imap import AuthError, CertificateError, MailClient, MailError
from .rules import (
    ACTIONS, RESERVED_FOLDER, Action, Match, Rule, RuleError, RuleSet, add_protected, describe,
    insert_rule, ruleset_to_json, validate,
)
from .security import ICLOUD_IMAP_HOST, ICLOUD_IMAP_PORT, safe_text
from .store import (
    FileStore, Journal, MailboxStore, entry_line, load_journal, load_rules, run_id, save_journal, save_rules,
)
from .ui import Abort, ask, ask_int, ask_secret, confirm, pick_numbers, pick_one, progress, say

APP_PASSWORD_HELP = """\
Serve una «password specifica per le app», non la password dell'Apple ID:
  1. apri account.apple.com e accedi
  2. «Accesso e sicurezza» → «Password specifiche per le app»
  3. tocca +, chiamala «Bot email» e copia la password
     (quattro gruppi di lettere: xxxx-xxxx-xxxx-xxxx)
Puoi revocarla quando vuoi, senza toccare il tuo Apple ID."""

PREVIEW_EXAMPLES = 3


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Session:
    """One connection to iCloud, opened when first needed and reopened if it drops."""

    def __init__(self, args: argparse.Namespace, interactive: bool):
        self.args = args
        self.interactive = interactive
        self.creds: Credentials | None = None
        self._client: MailClient | None = None
        self._classifier: Classifier | None = None
        self._classifier_client: MailClient | None = None

    def adopt(self, client: MailClient, creds: Credentials) -> None:
        self.close()
        self._client, self.creds = client, creds

    def client(self) -> MailClient:
        if self._client is not None and self._client.noop():
            return self._client
        self.close()
        creds = credentials.load()
        if creds is None:
            if not self.interactive:
                raise MailError(
                    "Mancano le credenziali: imposta ICLOUD_EMAIL e ICLOUD_APP_PASSWORD "
                    "oppure esegui «python3 bot.py configura»."
                )
            say("Non hai ancora configurato il bot.")
            configure(self)
            if self._client is None:
                raise Abort()
            return self._client
        progress("🔒 Connessione cifrata a iCloud…")
        self._client, self.creds = MailClient.connect(creds), creds
        return self._client

    def classifier(self) -> Classifier:
        client = self.client()
        if self._classifier is None or self._classifier_client is not client:
            self._classifier, self._classifier_client = Classifier(client), client
        return self._classifier

    def store(self):
        if self.args.regole_file:
            return FileStore(Path(self.args.regole_file).expanduser())
        return MailboxStore(self.client)

    def rules(self) -> RuleSet:
        return load_rules(self.store())

    def save_rules(self, ruleset: RuleSet) -> None:
        save_rules(self.store(), ruleset)

    def close(self) -> None:
        if self._client is not None:
            self._client.logout()
        self._client = None
        self._classifier = None


# Printing


def print_rules(ruleset: RuleSet) -> None:
    if not ruleset.rules:
        say("Non hai ancora regole. Usa «Analizza la posta» per farti proporre le prime.")
    else:
        say("Le tue regole (vale la prima che corrisponde):")
        for n, rule in enumerate(ruleset.rules, 1):
            state = "✅" if rule.enabled else "⏸️ "
            say(f" {n:>2}. {state} {safe_text(rule.name)}")
            say(f"       {safe_text(describe(rule), 300)}")
    if ruleset.protected:
        say("🛡️  Mittenti protetti (mai toccati): " + ", ".join(ruleset.protected))


def print_analysis(analysis: Analysis, details: bool) -> None:
    counts = analysis.counts
    scanned = len(analysis.items)
    say(f"Su {scanned} mail esaminate (in «{safe_text(analysis.folder, 40)}» ce ne sono {analysis.total}):")
    for category, label in CATEGORIES.items():
        if counts[category]:
            say(f"  {label:<14} {counts[category]:>5}")
    senders = analysis.senders()[:10 if not details else 25]
    if senders:
        say("Mittenti più frequenti:")
    for sender in senders:
        say(f"  {sender.count:>4}  {sender.label} · {CATEGORIES[sender.category]}")
        if details:
            for reason, _ in sender.reasons.most_common(2):
                say(f"        perché {safe_text(reason, 200)}")
            for subject in sender.subjects[:2]:
                say(f"        «{subject}»")


def short_sender(msg) -> str:
    """Name and real domain, so that a fake «PayPal» shows where it comes from."""
    if msg.from_name and msg.from_domain:
        return f"{safe_text(msg.from_name, 24)} ({safe_text(msg.from_domain, 40)})"
    return safe_text(msg.from_addr or msg.from_name, 40)


def print_plans(plans: list[FolderPlan]) -> int:
    total = 0
    for plan in plans:
        for change in plan.changes:
            count = len(change.messages)
            total += count
            target = ACTIONS[change.rule.action.kind]
            if change.rule.action.kind == "move":
                target += f" «{safe_text(change.rule.action.folder, 40)}»"
            where = "" if plan.folder == "INBOX" else f" (da «{safe_text(plan.folder, 30)}»)"
            say(f" • {safe_text(change.rule.name)}{where}: {count} mail → {target}")
            for msg in change.messages[:PREVIEW_EXAMPLES]:
                say(f"     {short_sender(msg)} · {safe_text(msg.subject, 45)}")
            if count > PREVIEW_EXAMPLES:
                say(f"     … e altre {count - PREVIEW_EXAMPLES}")
    protected = sum(p.protected for p in plans)
    if protected:
        say(f"🛡️  {protected} mail di mittenti protetti restano dove sono.")
    return total


def record(session: Session, outcome: Outcome, notes: list[str] = (), *, quiet: bool = False) -> None:
    """Add what happened to the journal in the mailbox (never to the console log)."""
    stamp = now_utc().astimezone().strftime("%d.%m.%Y %H:%M")
    problems = [f"{stamp} {p}" for p in [*outcome.errors, *notes]]
    if not outcome.journal and not problems:
        return
    try:
        store = session.store()
        try:
            journal = load_journal(store)
        except RuleError:
            journal = Journal()  # a damaged journal is replaced: today's actions matter more
        journal.entries.extend(outcome.journal)
        journal.errors.extend(problems)
        save_journal(store, journal)
    except (MailError, OSError) as exc:
        say("⚠️  Non sono riuscito ad aggiornare il registro." + ("" if quiet else f" ({exc})"))


# Applying rules


def preview_and_apply(
    session: Session, ruleset: RuleSet, *, run_kind: str, assume_yes: bool, lookback: int | None = None,
) -> int:
    engine = Engine(session.client(), ruleset, session.classifier(), lookback_days=lookback,
                    run=run_id(run_kind, now_utc()))
    progress("🔎 Preparo l'anteprima…")
    plans = engine.plan()
    if not any(p.changes for p in plans):
        say("Niente da fare: nessuna mail corrisponde.")
        return 0
    say("Ecco cosa farei:")
    total = print_plans(plans)
    if not assume_yes:
        if not session.interactive:
            say("Questa è solo un'anteprima: aggiungi --esegui per farlo davvero.")
            return 0
        if not confirm(f"Procedo con {total} mail?"):
            say("Va bene, non tocco niente.")
            return 0
    outcome = engine.execute(plans)
    record(session, outcome)
    say(f"✅ Fatto: {outcome.total} mail sistemate.")
    if outcome.journal:
        say("Se qualcosa non va, «annulla» rimette tutto com'era.")
    for error in outcome.errors:
        say(f"⚠️  {error}")
    return 1 if outcome.errors else 0


# Building rules


def rule_from_args(args: argparse.Namespace) -> Rule | None:
    conditions = any([args.da, args.a, args.oggetto, args.categoria, args.piu_vecchie_di])
    action = None
    if args.sposta:
        action = Action("move", args.sposta, args.e_segna_letta)
    elif args.cestina:
        action = Action("trash")
    elif args.spam:
        action = Action("junk")
    elif args.archivia:
        action = Action("archive", mark_read=args.e_segna_letta)
    elif args.segna_lette:
        action = Action("mark_read")
    elif args.contrassegna:
        action = Action("flag")
    if not conditions and action is None:
        return None
    if not conditions or action is None:
        raise RuleError(
            "Servono almeno una condizione (--da, --oggetto, --categoria…) e un'azione (--sposta, --cestina…)"
        )
    rule = Rule(
        name=args.nome or "regola",
        source=args.in_cartella,
        match=Match(
            senders=tuple(args.da or ()), recipients=tuple(args.a or ()), subjects=tuple(args.oggetto or ()),
            categories=tuple(args.categoria or ()), older_than_days=args.piu_vecchie_di, unread_only=args.non_lette,
        ),
        action=action,
    )
    rule = validate(rule)
    return rule if args.nome else replace(rule, name=default_name(rule))


def default_name(rule: Rule) -> str:
    m = rule.match
    if m.senders:
        what = ", ".join(m.senders[:2])
    elif m.categories:
        what = ", ".join(CATEGORIES[c] for c in m.categories)
    elif m.subjects:
        what = f"oggetto «{m.subjects[0]}»"
    elif m.recipients:
        what = f"per {m.recipients[0]}"
    else:
        what = f"«{rule.source}» oltre {m.older_than_days} giorni"
    action = rule.action.folder if rule.action.kind == "move" else ACTIONS[rule.action.kind]
    return f"{what} → {action}"[:80]


def rule_wizard() -> Rule:
    say("Quali mail?")
    kind = pick_one("Scelta: ", [
        "di un mittente o di un dominio (es. @zalando.ch)",
        "con una parola nell'oggetto",
        "di una categoria (newsletter, promozioni…)",
        "tutte quelle di una cartella, più vecchie di N giorni",
    ])
    senders: tuple[str, ...] = ()
    subjects: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    days: int | None = None
    source = "INBOX"
    if kind == 0:
        senders = tuple(ask("Mittenti o domini, separati da spazi: ").split())
    elif kind == 1:
        subjects = (ask("Parola o frase nell'oggetto: "),)
    elif kind == 2:
        keys = list(CATEGORIES)
        for n, key in enumerate(keys, 1):
            say(f"  {n}) {CATEGORIES[key]}")
        categories = tuple(keys[i - 1] for i in pick_numbers("Numeri delle categorie: ", len(keys)))
    else:
        source = ask("Cartella [INBOX]: ", "INBOX")
        days = ask_int("Più vecchie di quanti giorni?", 30, 1, 3650)
    if kind != 3 and confirm("Solo quelle più vecchie di qualche giorno?"):
        days = ask_int("Quanti giorni?", 30, 1, 3650)

    say("Cosa ne faccio?")
    kinds = ["move", "trash", "junk", "archive", "mark_read", "flag"]
    action_kind = kinds[pick_one("Scelta: ", [ACTIONS[k] for k in kinds])]
    folder = ask("Nome della cartella (la creo io se non c'è): ") if action_kind == "move" else None
    mark_read = action_kind in ("move", "archive") and confirm("Le segno anche come lette?")
    rule = validate(Rule(
        "regola",
        Match(senders=senders, subjects=subjects, categories=categories, older_than_days=days),
        Action(action_kind, folder, mark_read),
        source=source,
    ))
    proposed = default_name(rule)
    return validate(replace(rule, name=ask(f"Nome della regola [{proposed}]: ", proposed)))


# Commands


def configure(session: Session) -> int:
    say(APP_PASSWORD_HELP)
    say()
    email = ask("Indirizzo iCloud (es. nome@icloud.com): ").lower()
    while not credentials.valid_email(email):
        email = ask("Indirizzo non valido, riprova: ").lower()
    password = credentials.normalize_password(ask_secret("Password per le app (incollala e premi invio): "))
    if not credentials.looks_like_app_password(password):
        say("⚠️  Non sembra una password per le app (xxxx-xxxx-xxxx-xxxx).")
        say("   Non usare mai la password del tuo Apple ID.")
        if not confirm("Vuoi provarla lo stesso?"):
            return 1
    creds = Credentials(email, password, "inserita ora")
    progress("🔒 Provo la connessione cifrata…")
    try:
        client = MailClient.connect(creds)
    except AuthError:
        short = email.split("@")[0]
        say("iCloud ha rifiutato l'indirizzo completo come nome utente.")
        if not confirm(f"Riprovo con «{short}» (a volte Apple vuole solo la parte prima della @)?", default=True):
            raise
        creds = replace(creds, username=short)
        client = MailClient.connect(creds)
    info = client.tls_info()
    say(f"✅ Accesso riuscito ({info['protocollo']}, certificato di {ICLOUD_IMAP_HOST} verificato).")
    session.adopt(client, creds)
    if confirm("Salvo le credenziali su questo dispositivo, così non devi reinserirle?", default=True):
        where = credentials.save(creds)
        session.creds = replace(creds, source="salvate su questo dispositivo")
        say(f"Salvate {where}.")
    return 0


def cmd_configura(session: Session, args) -> int:
    return configure(session)


def cmd_verifica(session: Session, args) -> int:
    client = session.client()
    info = client.tls_info()
    caps = client.capabilities
    say("🔒 Connessione verificata")
    say(f"  server: {ICLOUD_IMAP_HOST}:{ICLOUD_IMAP_PORT}, cifrata dall'inizio (mai in chiaro)")
    for key, value in info.items():
        say(f"  {key}: {value}")
    moving = "sì (MOVE)" if "MOVE" in caps else "sì (UIDPLUS)" if "UIDPLUS" in caps else "no"
    say(f"  spostamento sicuro dei messaggi: {moving}")
    if session.creds:
        say(f"  credenziali: {session.creds.source}")
    say(f"  cartelle: {len(client.folders())}")
    say("Il bot legge solo le intestazioni (mittente, oggetto, data…), mai il testo delle mail.")
    return 0


def cmd_analizza(session: Session, args) -> int:
    client = session.client()
    progress(f"📊 Analizzo «{args.cartella}» (al massimo le ultime {args.quante} mail)…")
    analysis = analyze(client, session.classifier(), args.cartella, args.quante)
    print_analysis(analysis, args.dettagli)
    ruleset = session.rules()
    proposals = propose(analysis, ruleset)
    say()
    if not proposals:
        say("Nessuna nuova proposta: le tue regole coprono già quello che ho trovato.")
    else:
        say("💡 Proposte (decidi tu):")
        for n, proposal in enumerate(proposals, 1):
            say(f" {n}. {safe_text(proposal.title, 200)}")
            for example in proposal.examples:
                say(f"      {safe_text(example, 200)}")
    if not session.interactive:
        if proposals:
            say("Per approvarle avvia il bot senza argomenti: python3 bot.py")
        return 0

    chosen = [proposals[i - 1].rule for i in pick_numbers(
        "Quali approvi? Numeri (es. 1 3), «tutte», o invio per nessuna: ", len(proposals))] if proposals else []
    senders = bulk_senders(analysis)
    if senders and confirm("Vuoi buttare sempre nel Cestino le mail di qualche mittente?"):
        for n, sender in enumerate(senders, 1):
            say(f" {n:>2}. {sender.label} · {sender.count} mail")
        picks = pick_numbers("Numeri dei mittenti (invio per nessuno): ", len(senders))
        if picks:
            chosen.append(validate(Rule(
                "Mittenti da buttare",
                Match(senders=tuple(senders[i - 1].address for i in picks)),
                Action("trash"),
            )))
    if not chosen:
        say("Nessuna nuova regola.")
        return 0
    say("Nuove regole:")
    for rule in chosen:
        say(f" • {safe_text(rule.name)}: {safe_text(describe(rule), 300)}")
    if not confirm("Le salvo?", default=True):
        return 0
    for rule in chosen:
        ruleset = insert_rule(ruleset, rule)
    session.save_rules(ruleset)
    say(f"✅ Regole salvate nella tua posta, cartella «{RESERVED_FOLDER}».")
    if confirm("Le applico subito anche alla posta che c'è già?", default=True):
        return preview_and_apply(session, ruleset, run_kind="manuale", assume_yes=False)
    return 0


def cmd_regole(session: Session, args) -> int:
    ruleset = session.rules()
    if args.json:
        print(ruleset_to_json(ruleset))
        return 0
    print_rules(ruleset)
    return 0


def manage_rules(session: Session, args) -> int:
    while True:
        ruleset = session.rules()
        print_rules(ruleset)
        if not ruleset.rules:
            return 0
        answer = ask("Numero di una regola da cambiare (invio per tornare): ")
        if not answer:
            return 0
        if not answer.isdigit() or not 1 <= int(answer) <= len(ruleset.rules):
            say("Numero non valido.")
            continue
        index = int(answer) - 1
        rule = ruleset.rules[index]
        choice = pick_one("Cosa faccio? ", [
            "spegni" if rule.enabled else "accendi", "elimina", "lasciala com'è",
        ])
        rules = list(ruleset.rules)
        if choice == 0:
            rules[index] = replace(rule, enabled=not rule.enabled)
        elif choice == 1 and confirm(f"Elimino «{rule.name}»?"):
            del rules[index]
        else:
            continue
        session.save_rules(replace(ruleset, rules=rules))
        say("✅ Fatto.")


def _change_rule(session: Session, number: int, change) -> int:
    ruleset = session.rules()
    if not 1 <= number <= len(ruleset.rules):
        raise RuleError(f"Non c'è una regola numero {number}")
    rules = list(ruleset.rules)
    message = change(rules, number - 1)
    session.save_rules(replace(ruleset, rules=rules))
    say(f"✅ {message}")
    return 0


def cmd_rimuovi(session: Session, args) -> int:
    def remove(rules, i):
        return f"Regola «{rules.pop(i).name}» eliminata."
    return _change_rule(session, args.numero, remove)


def cmd_attiva(session: Session, args) -> int:
    def enable(rules, i):
        rules[i] = replace(rules[i], enabled=True)
        return f"Regola «{rules[i].name}» accesa."
    return _change_rule(session, args.numero, enable)


def cmd_disattiva(session: Session, args) -> int:
    def disable(rules, i):
        rules[i] = replace(rules[i], enabled=False)
        return f"Regola «{rules[i].name}» spenta."
    return _change_rule(session, args.numero, disable)


def cmd_aggiungi(session: Session, args) -> int:
    rule = rule_from_args(args)
    if rule is None:
        if not session.interactive:
            raise RuleError("Indica condizioni e azione, per esempio: aggiungi --da @zalando.ch --sposta Acquisti")
        rule = rule_wizard()
    say(f"Nuova regola: {safe_text(rule.name)}")
    say(f"  {safe_text(describe(rule), 300)}")
    if session.interactive and not args.si and not confirm("La salvo?", default=True):
        return 0
    ruleset = insert_rule(session.rules(), rule)
    session.save_rules(ruleset)
    say("✅ Regola salvata.")
    if session.interactive and confirm("La applico subito anche alla posta che c'è già?", default=True):
        return preview_and_apply(session, ruleset, run_kind="manuale", assume_yes=False)
    return 0


def cmd_pulisci(session: Session, args) -> int:
    rule = rule_from_args(args)
    if rule is None:
        if not session.interactive:
            raise RuleError(
                "Indica cosa pulire, per esempio: pulisci --categoria newsletter --piu-vecchie-di 30 --cestina"
            )
        say("Pulizia una tantum: la regola non viene salvata.")
        rule = rule_wizard()
    protected = session.rules().protected
    return preview_and_apply(session, RuleSet([rule], protected), run_kind="pulizia",
                             assume_yes=args.si or args.esegui)


def cmd_applica(session: Session, args) -> int:
    ruleset = session.rules()
    if not any(r.enabled for r in ruleset.rules):
        say("Non ci sono regole attive.")
        return 0
    return preview_and_apply(session, ruleset, run_kind="manuale", assume_yes=args.si or args.esegui,
                             lookback=args.giorni)


def cmd_proteggi(session: Session, args) -> int:
    ruleset = add_protected(session.rules(), args.mittente)
    session.save_rules(ruleset)
    say(f"🛡️  Da ora il bot non tocca più le mail di {args.mittente.strip().lower()}.")
    return 0


def cmd_sproteggi(session: Session, args) -> int:
    ruleset = session.rules()
    pattern = args.mittente.strip().lower()
    if pattern not in ruleset.protected:
        raise RuleError(f"{pattern} non è tra i mittenti protetti")
    session.save_rules(replace(ruleset, protected=[p for p in ruleset.protected if p != pattern]))
    say(f"Tolto {pattern} dai mittenti protetti.")
    return 0


def cmd_cartelle(session: Session, args) -> int:
    client = session.client()
    say("Cartelle:")
    for folder in sorted(client.folders(refresh=True), key=lambda f: (f.name.upper() != "INBOX", f.name.lower())):
        if not folder.selectable:
            continue
        total, unread = client.status(folder.name)
        extra = f" ({unread} non lette)" if unread else ""
        say(f"  {safe_text(folder.name, 32):<32} {total:>6}{extra}")
    return 0


def cmd_esporta(session: Session, args) -> int:
    ruleset = session.rules()
    analysis = None
    if any(r.enabled and r.source == "INBOX" and r.match.categories for r in ruleset.rules):
        progress("📊 Guardo la posta per trovare i mittenti di ogni categoria…")
        analysis = analyze(session.client(), session.classifier(), "INBOX", args.quante)
    natives, bot_only = native_rules(ruleset, analysis)
    if natives:
        say("Regole da creare su iCloud.com: le applicano i server Apple appena")
        say("arriva la posta, anche quando il bot è spento.")
        say("  1. Apri icloud.com/mail (su iPhone: Safari → «aA» → «Richiedi sito desktop»)")
        say("  2. ⚙︎ Impostazioni → Regole → Aggiungi una regola")
        say("  3. Per ogni riga: condizione, valore, azione")
        say()
        for n, native in enumerate(natives, 1):
            say(f" {n:>2}. {native.condition}: {safe_text(native.value)}")
            say(f"     → {safe_text(native.action)}")
        say("Nel valore puoi scrivere un indirizzo completo o solo il dominio (@esempio.ch).")
    else:
        say("Nessuna regola si può copiare su iCloud.com.")
    if bot_only:
        say()
        say("Queste le applica solo il bot:")
        for number, reason in bot_only:
            say(f"  regola {number} «{safe_text(ruleset.rules[number - 1].name)}»: {reason}")
    return 0


def cmd_registro(session: Session, args) -> int:
    journal = load_journal(session.store())
    if journal.errors:
        say("Ultimi problemi:")
        for error in reversed(journal.errors[-5:]):
            say(f"  {safe_text(error, 150)}")
        say()
    if not journal.entries:
        say("Il bot non ha ancora fatto niente.")
        return 0
    say(f"Ultime {min(args.ultime, len(journal.entries))} azioni, le più recenti in alto:")
    for entry in reversed(journal.entries[-args.ultime:]):
        say(f"  {entry_line(entry)}")
    return 0


def cmd_annulla(session: Session, args) -> int:
    store = session.store()
    journal = load_journal(store)
    runs = [e.run for e in journal.entries if e.action != "restore" and e.run not in journal.undone]
    if not runs:
        say("Non c'è niente da annullare.")
        return 0
    last = runs[-1]
    entries = [e for e in journal.entries if e.run == last and e.action != "restore"]
    say(f"L'ultima operazione ({entry_line(entries[0]).split(' · ')[0]}) ha toccato {len(entries)} mail, ad esempio:")
    for entry in entries[:PREVIEW_EXAMPLES]:
        say(f"  {entry_line(entry)}")
    if not args.si and not (session.interactive and confirm("Le rimetto dov'erano?")):
        if not session.interactive:
            say("Aggiungi --si per confermare.")
        return 0
    stamp = now_utc()
    restored, missing, new_entries = undo(session.client(), entries, now=stamp, run=run_id("annulla", stamp))
    journal.entries.extend(new_entries)
    journal.undone.append(last)
    save_journal(store, journal)
    say(f"✅ Rimesse a posto {restored} mail.")
    if missing:
        say(f"{missing} non le ho trovate: forse le hai già spostate o eliminate.")
    return 0


def cmd_automatico(session: Session, args) -> int:
    """Unattended run (GitHub Actions, Shortcuts). Prints numbers only: on a
    public repository the log is public, details go to the mailbox journal."""
    if credentials.load() is None:
        say(f"❌ Mancano i segreti {credentials.ENV_EMAIL} e {credentials.ENV_PASSWORD} "
            "(su GitHub: Settings → Secrets and variables → Actions).")
        return 2
    ruleset = session.rules()
    active = [r for r in ruleset.rules if r.enabled]
    say(f"Regole attive: {len(active)}")
    if not active:
        return 0
    client = session.client()
    engine = Engine(client, ruleset, Classifier(client), lookback_days=args.giorni,
                    run=run_id("automatico", now_utc()))
    if args.prova:
        for plan in engine.plan():
            for change in plan.changes:
                say(f"Regola {change.number}: {len(change.messages)} mail (prova, nessuna modifica)")
        return 0
    outcome = engine.run_all(limit=args.limite)
    for number, count in sorted(outcome.done.items()):
        say(f"Regola {number}: {count} mail")
    notes = []
    for number, count in sorted(outcome.over_limit.items()):
        say(f"Regola {number}: saltata, toccherebbe {count} mail (limite {args.limite})")
        notes.append(f"Regola {number} «{ruleset.rules[number - 1].name}» saltata: toccherebbe {count} mail, "
                     f"oltre il limite di {args.limite}. Applicala dal telefono se è giusto così.")
    if outcome.errors:
        say(f"Problemi: {len(outcome.errors)} (dettagli nel «Registro del bot», cartella «{RESERVED_FOLDER}»)")
    record(session, outcome, notes, quiet=True)
    say(f"Totale: {outcome.total} mail sistemate")
    return 1 if outcome.errors else 0


def cmd_dimentica(session: Session, args) -> int:
    if credentials.forget():
        say("Credenziali cancellate da questo dispositivo.")
        say("Per sicurezza puoi anche revocare la password su account.apple.com.")
    else:
        say("Su questo dispositivo non c'erano credenziali salvate.")
    return 0


# Menu


MENU = (
    ("Analizza la posta e proponi regole", "analizza"),
    ("Le mie regole", None),
    ("Aggiungi una regola", "aggiungi"),
    ("Applica le regole adesso", "applica"),
    ("Pulizia una tantum", "pulisci"),
    ("Cartelle", "cartelle"),
    ("Regole da copiare su iCloud.com", "esporta-icloud"),
    ("Cosa ha fatto il bot", "registro"),
    ("Annulla l'ultima operazione", "annulla"),
    ("Verifica la connessione sicura", "verifica"),
)


def menu(session: Session, parser: argparse.ArgumentParser) -> int:
    say(f"🤖 Bot pulizia email per iCloud · versione {__version__}")
    while True:
        say()
        for n, (label, _) in enumerate(MENU, 1):
            say(f" {n:>2}) {label}")
        say("  0) Esci")
        choice = ask("Scelta: ").lower()
        if choice in ("0", "esci", "q"):
            return 0
        if not choice:
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(MENU):
            say("Scelta non valida.")
            continue
        _, command = MENU[int(choice) - 1]
        say()
        if command is None:
            run_safely(session, manage_rules, parser.parse_args(["regole"]))
        else:
            args = parser.parse_args([command])
            run_safely(session, args.func, args)


def run_safely(session: Session, func, args) -> int:
    automatic = getattr(args, "command", "") == "automatico"
    try:
        return func(session, args)
    except AuthError as exc:
        say(f"❌ {exc}")
        if not automatic:
            say(APP_PASSWORD_HELP)
        return 3
    except CertificateError as exc:
        say(f"❌ {exc}")
        return 4
    except (MailError, RuleError) as exc:
        say("❌ Errore durante l'esecuzione." if automatic else f"❌ {exc}")
        return 1
    except (imaplib.IMAP4.error, OSError) as exc:
        session.close()
        say("❌ La connessione con iCloud si è interrotta." + ("" if automatic else f" ({exc})"))
        return 1
    except Exception as exc:
        if not automatic:
            raise
        # The log of an unattended run may be public: no traceback, no data.
        say(f"❌ Errore imprevisto ({type(exc).__name__}).")
        return 1


def _count(text: str) -> int:
    if not text.isdigit():
        raise argparse.ArgumentTypeError(f"serve un numero intero non negativo, non «{text}»")
    return int(text)


def _italian(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser._optionals.title = "opzioni"
    parser._positionals.title = "argomenti"
    parser.add_argument("-h", "--help", action="help", help="mostra questo aiuto")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = _italian(argparse.ArgumentParser(
        prog="bot.py",
        description="Bot di pulizia per la posta iCloud. Senza comandi apre il menu.",
        add_help=False,
    ))
    parser.add_argument("--version", action="version", version=__version__, help="mostra la versione")
    parser.add_argument("--regole-file", metavar="FILE",
                        help="tieni le regole in un file locale invece che nella posta")
    sub = parser.add_subparsers(dest="command", metavar="comando", title="comandi")

    def command(name: str, func, text: str) -> argparse.ArgumentParser:
        p = _italian(sub.add_parser(name, help=text, description=text, add_help=False))
        p.set_defaults(func=func)
        return p

    command("configura", cmd_configura, "inserisci indirizzo e password per le app e prova la connessione")
    command("verifica", cmd_verifica, "mostra come è protetta la connessione")
    p = command("analizza", cmd_analizza, "classifica la posta e proponi regole")
    p.add_argument("--cartella", default="INBOX")
    p.add_argument("--quante", type=_count, default=1000, help="quante mail recenti esaminare (0 = tutte)")
    p.add_argument("--dettagli", action="store_true", help="mostra perché ogni mittente è in una categoria")
    p = command("regole", cmd_regole, "elenca le regole")
    p.add_argument("--json", action="store_true", help="stampa le regole in JSON (per un backup)")
    for name, func, text in (
        ("rimuovi", cmd_rimuovi, "elimina una regola"),
        ("attiva", cmd_attiva, "accendi una regola"),
        ("disattiva", cmd_disattiva, "spegni una regola"),
    ):
        command(name, func, text).add_argument("numero", type=int)
    for name, func, text in (
        ("proteggi", cmd_proteggi, "il bot non toccherà mai questo mittente (indirizzo, @dominio o parola)"),
        ("sproteggi", cmd_sproteggi, "togli un mittente dai protetti"),
    ):
        command(name, func, text).add_argument("mittente")

    def rule_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--da", action="append", metavar="MITTENTE", help="indirizzo, @dominio o parola (ripetibile)")
        p.add_argument("--a", action="append", metavar="DESTINATARIO")
        p.add_argument("--oggetto", action="append", metavar="TESTO")
        p.add_argument("--categoria", action="append", choices=list(CATEGORIES))
        p.add_argument("--piu-vecchie-di", type=_count, metavar="GIORNI")
        p.add_argument("--non-lette", action="store_true")
        p.add_argument("--in", dest="in_cartella", default="INBOX", metavar="CARTELLA", help="cartella da controllare")
        group = p.add_mutually_exclusive_group()
        group.add_argument("--sposta", metavar="CARTELLA")
        group.add_argument("--cestina", action="store_true")
        group.add_argument("--spam", action="store_true", help="metti in Indesiderata")
        group.add_argument("--archivia", action="store_true")
        group.add_argument("--segna-lette", action="store_true")
        group.add_argument("--contrassegna", action="store_true")
        p.add_argument("--e-segna-letta", action="store_true", help="con --sposta o --archivia, segna anche come letta")
        p.add_argument("--nome")
        p.add_argument("--si", action="store_true", help="non chiedere conferma")

    rule_options(command("aggiungi", cmd_aggiungi, "aggiungi una regola"))
    p = command("pulisci", cmd_pulisci, "pulizia una tantum, senza salvare la regola")
    rule_options(p)
    p.add_argument("--esegui", action="store_true", help="esegui senza chiedere (anche fuori dal terminale)")
    p = command("applica", cmd_applica, "applica le regole salvate (prima mostra l'anteprima)")
    p.add_argument("--giorni", type=_count, help="solo la posta degli ultimi N giorni")
    p.add_argument("--esegui", action="store_true", help="esegui senza chiedere")
    p.add_argument("--si", action="store_true", help="non chiedere conferma")
    command("cartelle", cmd_cartelle, "elenca le cartelle")
    p = command("esporta-icloud", cmd_esporta, "regole da creare a mano su iCloud.com")
    p.add_argument("--quante", type=_count, default=1000)
    p = command("registro", cmd_registro, "cosa ha fatto il bot")
    p.add_argument("--ultime", type=_count, default=20)
    p = command("annulla", cmd_annulla, "rimetti a posto le mail dell'ultima operazione")
    p.add_argument("--si", action="store_true")
    p = command("automatico", cmd_automatico, "applica le regole senza domande (GitHub Actions, Comandi rapidi)")
    p.add_argument("--giorni", type=_count, default=7, help="controlla la posta degli ultimi N giorni (default 7)")
    p.add_argument("--limite", type=_count, default=300, help="salta una regola che toccherebbe più mail di così")
    p.add_argument("--prova", action="store_true", help="conta soltanto, senza modificare niente")
    command("dimentica", cmd_dimentica, "cancella le credenziali salvate su questo dispositivo")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    interactive = sys.stdin.isatty() and args.command != "automatico"
    session = Session(args, interactive)
    try:
        if args.command is None:
            if not interactive:
                parser.print_help()
                return 2
            return menu(session, parser)
        return run_safely(session, args.func, args)
    except (KeyboardInterrupt, Abort):
        say("\nInterrotto.")
        return 130
    finally:
        session.close()
