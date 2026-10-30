"""Classify a message from its header fields alone.

Every verdict carries its reasons, in Italian, so the user sees why the bot
suggests what it suggests. Senders can forge headers, so the bot only trusts
signals that make a message look *worse* (a failed authentication check, a spam
verdict), read from the topmost header, the one iCloud's servers add last.
Nothing a sender writes can lower a spam score; only the user's own history
(people they have written to) does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .message import MessageInfo, registrable_domain

CATEGORIES = {
    "spam": "Spam sospetto",
    "newsletter": "Newsletter",
    "promozioni": "Promozioni",
    "social": "Social",
    "notifiche": "Notifiche",
    "acquisti": "Acquisti",
    "personale": "Personali",
}
SUGGESTED_FOLDERS = {
    "newsletter": "Newsletter",
    "promozioni": "Promozioni",
    "social": "Social",
    "notifiche": "Notifiche",
    "acquisti": "Acquisti",
}
SPAM_THRESHOLD = 5

SOCIAL_DOMAINS = frozenset({
    "facebookmail.com", "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "tiktok.com", "pinterest.com", "reddit.com", "redditmail.com", "quora.com", "tumblr.com",
    "snapchat.com", "discord.com", "twitch.tv", "youtube.com", "meetup.com", "nextdoor.com",
    "strava.com", "threads.net", "bsky.app", "telegram.org", "whatsapp.com", "xing.com",
})

# Header -> platform. Marketing platforms point to newsletters; the others also
# send receipts and alerts, so they only say "sent by a machine".
_MARKETING_HEADERS = {"x-mc-user": "Mailchimp", "x-sfmc-stack": "Salesforce Marketing Cloud"}
_SENDING_SERVICE_HEADERS = {
    "x-sg-eid": "SendGrid", "x-ses-outgoing": "Amazon SES", "x-mailgun-sid": "Mailgun", "x-mj-mid": "Mailjet",
}
_MARKETING_MAILERS = {
    "mailchimp": "Mailchimp", "sendinblue": "Brevo", "brevo": "Brevo", "klaviyo": "Klaviyo",
    "hubspot": "HubSpot", "mailerlite": "MailerLite", "substack": "Substack",
    "createsend": "Campaign Monitor", "campaign monitor": "Campaign Monitor",
    "activecampaign": "ActiveCampaign", "constant contact": "Constant Contact", "beehiiv": "beehiiv",
    "newsletter2go": "Newsletter2Go", "cleverreach": "CleverReach", "rapidmail": "rapidmail",
    "emarsys": "Emarsys", "marketo": "Marketo", "mailpoet": "MailPoet", "acymailing": "AcyMailing",
}

_NOREPLY = re.compile(
    r"^(?:no[-_.]?reply|do[-_.]?not[-_.]?reply|notifications?|notify|alerts?|automated|"
    r"mailer-daemon|postmaster|bounces?)\b",
    re.I,
)

_PROMO = re.compile("|".join((
    r"\d+\s?%", r"\bscont[oi]\b", r"\bscontat", r"\boffert[ae]\b", r"\bsaldi\b", r"\bpromo",
    r"\bcoupon\b", r"black friday", r"cyber monday", r"\bgratis\b", r"spedizione gratuita",
    r"\bsolo (?:per )?oggi\b", r"\bultim[ei] (?:ore|giorni|pezzi)\b", r"\brisparmi", r"\bimperdibil",
    r"nuova collezione", r"\boutlet\b", r"\bsale\b", r"\bdeals?\b", r"\bdiscount", r"free shipping",
    r"limited time", r"last chance", r"\brabatt", r"\bangebot", r"\baktion\b", r"\bgutschein",
    r"\br[ée]duction", r"\boffres?\b", r"\bsoldes\b",
)), re.I)

_PURCHASE = re.compile("|".join((
    r"\bordine\b", r"\bspedit[oaie]\b", r"\bspedizione\b(?! gratuita)", r"\bin consegna\b",
    r"\bconsegnat[oaie]\b", r"\bfattura\b", r"\bricevuta\b", r"\bpagamento (?:ricevuto|confermato|effettuato)\b",
    r"\brimborso\b", r"\border\b", r"\bshipped\b", r"\bout for delivery\b", r"\bdelivered\b",
    r"\binvoice\b", r"\breceipt\b", r"\bpayment (?:received|confirmation)\b", r"\bbestellung",
    r"\brechnung\b", r"\bversand", r"\blieferung\b", r"\bquittung\b", r"\bcommande\b",
    r"\bfacture\b", r"\blivraison\b", r"\bexp[ée]di",
)), re.I)

_SPAM_PHRASES = re.compile("|".join((
    # Italiano
    r"hai vinto", r"\bvincit(?:ore|rice)\b", r"\blotteria\b", r"\beredit[àa]\b",
    r"\bcongratulazioni\b", r"\bbitcoin\b", r"\bcriptovalut", r"investiment[oi] garantit",
    r"\bguadagn(?:a|are|i) (?:subito|facile|da casa)", r"soldi facili", r"prestito (?:immediato|garantito)",
    r"verifica (?:subito )?(?:il tuo |l')?account", r"account (?:sospeso|bloccato|limitato|disattivato)",
    r"conferma i tuoi dati", r"aggiorna i (?:tuoi )?dati", r"pacco in giacenza",
    r"spedizione (?:in sospeso|bloccata)", r"ultimo avviso", r"azione richiesta", r"\burgente\b",
    r"carta (?:bloccata|sospesa)", r"pagamento (?:non riuscito|rifiutato|sospeso)",
    r"ho accesso al tuo", r"\bwebcam\b", r"\bhacker", r"\bviagra\b", r"\bcasin[oò]\b", r"\bdimagr",
    # English
    r"you(?:'ve| have) won", r"\bwinner\b", r"\blottery\b", r"\binheritance\b", r"verify your account",
    r"account (?:suspended|locked|limited)", r"unusual (?:sign-in )?activity", r"payment (?:failed|declined)",
    r"final notice", r"action required", r"\burgent\b", r"\bcrypto\b", r"weight loss",
    # Deutsch, français
    r"\bgewonnen\b", r"\bgewinner\b", r"konto (?:gesperrt|eingeschränkt)", r"\bdringend\b",
    r"\bf[ée]licitations\b", r"vous avez gagn[ée]", r"compte (?:suspendu|bloqu[ée])", r"\bcolis\b",
)), re.I)

# Display-name brand -> domains the brand really sends from.
_BRANDS = (
    (r"paypal", "PayPal",
     {"paypal.com", "paypal.it", "paypal.ch", "paypal.de", "paypal.fr", "paypal.co.uk", "paypal.at"}),
    (r"\bapple\b|\bicloud\b|\bitunes\b", "Apple", {"apple.com", "icloud.com", "me.com", "mac.com", "itunes.com"}),
    (r"amazon", "Amazon",
     {"amazon.com", "amazon.it", "amazon.de", "amazon.fr", "amazon.co.uk", "amazon.es", "amazon.nl", "primevideo.com"}),
    (r"netflix", "Netflix", {"netflix.com"}),
    (r"poste ?italiane|bancoposta|postepay", "Poste Italiane", {"poste.it", "posteitaliane.it", "postepay.it"}),
    (r"postfinance", "PostFinance", {"postfinance.ch"}),
    (r"posta svizzera|swiss ?post|die post\b|la poste suisse", "La Posta", {"post.ch", "swisspost.ch"}),
    (r"\bubs\b|credit suisse", "UBS", {"ubs.com", "ubs.ch", "credit-suisse.com"}),
    (r"raiffeisen", "Raiffeisen", {"raiffeisen.ch", "raiffeisen.it", "raiffeisen.at", "raiffeisen.de"}),
    (r"swisscom", "Swisscom", {"swisscom.ch", "swisscom.com"}),
    (r"\btwint\b", "TWINT", {"twint.ch"}),
    (r"\bsbb\b", "FFS", {"sbb.ch"}),
    (r"\bdhl\b", "DHL", {"dhl.com", "dhl.de", "dhl.ch", "dhl.it", "dhl.fr", "dhl.co.uk"}),
    (r"\bups\b", "UPS", {"ups.com"}),
    (r"fedex", "FedEx", {"fedex.com"}),
    (r"intesa ?sanpaolo", "Intesa Sanpaolo", {"intesasanpaolo.com", "intesasanpaolo.it"}),
    (r"unicredit", "UniCredit", {"unicredit.it", "unicredit.eu", "unicreditgroup.eu"}),
    (r"agenzia (?:delle )?entrate", "Agenzia delle Entrate", {"agenziaentrate.it", "agenziaentrate.gov.it"}),
    (r"\binps\b", "INPS", {"inps.it"}),
    (r"microsoft|office ?365", "Microsoft", {"microsoft.com", "office.com", "office365.com", "microsoftonline.com"}),
    (r"\bgoogle\b", "Google", {"google.com", "youtube.com"}),
    (r"revolut", "Revolut", {"revolut.com"}),
    (r"\bn26\b", "N26", {"n26.com"}),
    (r"\bnexi\b", "Nexi", {"nexi.it", "nexigroup.com"}),
    (r"booking\.com", "Booking.com", {"booking.com"}),
    (r"spotify", "Spotify", {"spotify.com"}),
    (r"\bebay\b", "eBay", {"ebay.com", "ebay.it", "ebay.de", "ebay.ch", "ebay.fr", "ebay.co.uk"}),
)
_BRAND_PATTERNS = tuple((re.compile(p, re.I), label, domains) for p, label, domains in _BRANDS)

_SUSPICIOUS_TLDS = frozenset({
    "top", "xyz", "click", "buzz", "rest", "monster", "cyou", "icu", "cfd", "sbs", "bond", "quest",
    "loan", "work", "gq", "tk", "ml", "cf", "ga", "zip", "mov", "country", "kim", "men", "date",
    "faith", "review", "win", "bid", "stream", "download", "racing", "science", "party", "cricket",
    "accountant", "trade", "webcam",
})
_ADDRESS_IN_NAME = re.compile(r"[\w.+-]+@(?:[\w-]+\.)+[\w-]+")


@dataclass(frozen=True)
class Classification:
    category: str
    spam_score: int
    reasons: tuple[str, ...]

    @property
    def label(self) -> str:
        return CATEGORIES[self.category]


@dataclass(frozen=True)
class Context:
    # Addresses the user has written to (taken from Sent Messages).
    known_contacts: frozenset[str] = frozenset()


NO_CONTEXT = Context()
_PURCHASE_REASON = "l'oggetto parla di un ordine, una spedizione o un pagamento"


def _score(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _proofpoint(msg: MessageInfo) -> dict[str, str]:
    # iCloud filters mail with Proofpoint; when its verdict is present, use it.
    return dict(re.findall(r"(\w+)=([\w.-]+)", msg.header("x-proofpoint-spam-details").lower()))


def spam_signals(msg: MessageInfo) -> list[tuple[int, str]]:
    signals: list[tuple[int, str]] = []
    add = signals.append

    if msg.header("x-spam-flag").strip().lower().startswith("yes") or \
            msg.header("x-spam-status").strip().lower().startswith("yes"):
        add((5, "un filtro antispam l'ha già segnata come spam"))

    verdict = _proofpoint(msg)
    rule = verdict.get("rule", "")
    if "spam" in rule and "notspam" not in rule:
        add((5, "i filtri di iCloud la considerano spam"))
    if _score(verdict.get("malwarescore")) >= 50:
        add((5, "i filtri di iCloud sospettano un virus"))
    if _score(verdict.get("phishscore")) >= 50:
        add((4, "i filtri di iCloud sospettano un tentativo di phishing"))
    if _score(verdict.get("impostorscore")) >= 50:
        add((3, "i filtri di iCloud sospettano un mittente falsificato"))
    if _score(verdict.get("spamscore")) >= 80:
        add((3, "i filtri di iCloud le danno un punteggio di spam alto"))

    auth = msg.header("authentication-results").lower()
    if re.search(r"\bdmarc=fail\b", auth):
        add((3, "non supera il controllo antifalsificazione del dominio (DMARC)"))
    if re.search(r"\bspf=fail\b", auth):
        add((1, "è partita da un server non autorizzato dal mittente (SPF)"))
    if re.search(r"\bdkim=fail\b", auth) and not re.search(r"\bdkim=pass\b", auth):
        add((1, "la firma digitale del mittente non è valida (DKIM)"))

    name = msg.from_name
    domain = registrable_domain(msg.from_domain)
    for pattern, label, domains in _BRAND_PATTERNS:
        if pattern.search(name) and domain not in domains:
            shown = f"@{msg.from_domain}" if msg.from_domain else "un indirizzo mancante"
            add((4, f"il nome dice «{label}» ma l'indirizzo è {shown}"))
            break
    embedded = _ADDRESS_IN_NAME.search(name)
    if embedded and embedded.group(0).lower() != msg.from_addr:
        add((3, "il nome mostra un indirizzo diverso da quello reale"))

    tld = msg.from_domain.rsplit(".", 1)[-1] if msg.from_domain else ""
    if tld in _SUSPICIOUS_TLDS:
        add((1, f"il dominio .{tld} è molto usato dagli spammer"))

    phrases = {m.group(0).lower() for m in _SPAM_PHRASES.finditer(f"{msg.subject} {name}")}
    if phrases:
        shown = ", ".join(sorted(f"«{p}»" for p in phrases)[:3])
        add((min(4, len(phrases) + 1), f"usa frasi tipiche dello spam: {shown}"))

    letters = [c for c in msg.subject if c.isalpha()]
    shouting = len(letters) >= 12 and sum(c.isupper() for c in letters) / len(letters) > 0.7
    if shouting or msg.subject.count("!") >= 3 or "$$$" in msg.subject or "€€€" in msg.subject:
        add((1, "l'oggetto urla (maiuscole, punti esclamativi)"))
    if not msg.has_header("message-id"):
        add((1, "manca l'identificativo del messaggio"))
    if not msg.has_header("date"):
        add((1, "manca la data"))
    return signals


def _bulk_reasons(msg: MessageInfo) -> list[str]:
    reasons = []
    if msg.has_header("list-unsubscribe"):
        reasons.append("ha il link per disiscriversi")
    if msg.has_header("list-id"):
        reasons.append("arriva da una lista di distribuzione")
    if msg.header("precedence").strip().lower() in ("bulk", "list", "junk"):
        reasons.append("è un invio di massa")
    if msg.has_header("feedback-id") or msg.has_header("x-csa-complaints") or msg.has_header("x-campaign"):
        reasons.append("viene da una piattaforma di invii di massa")
    platform = next((name for header, name in _MARKETING_HEADERS.items() if msg.has_header(header)), None)
    mailer = msg.header("x-mailer").lower()
    platform = platform or next((name for key, name in _MARKETING_MAILERS.items() if key in mailer), None)
    if platform:
        reasons.append(f"è spedita con {platform}")
    if _score(_proofpoint(msg).get("bulkscore")) >= 50:
        reasons.append("iCloud la riconosce come posta di massa")
    return reasons


def _automated_reasons(msg: MessageInfo) -> list[str]:
    reasons = []
    auto = msg.header("auto-submitted").strip().lower()
    if (auto and auto != "no") or msg.has_header("x-auto-response-suppress"):
        reasons.append("è generata automaticamente")
    if _NOREPLY.match(msg.from_addr.split("@")[0]):
        reasons.append("il mittente non accetta risposte")
    service = next((name for header, name in _SENDING_SERVICE_HEADERS.items() if msg.has_header(header)), None)
    if service:
        reasons.append(f"è spedita da un servizio automatico ({service})")
    return reasons


def classify(msg: MessageInfo, context: Context = NO_CONTEXT) -> Classification:
    signals = spam_signals(msg)
    score = sum(weight for weight, _ in signals)
    known = msg.from_addr in context.known_contacts
    if known:
        score -= 10
    if score >= SPAM_THRESHOLD:
        reasons = tuple(text for _, text in sorted(signals, key=lambda s: -s[0]))
        return Classification("spam", score, reasons)
    if known:
        return Classification("personale", score, ("gli hai già scritto in passato",))

    domain = registrable_domain(msg.from_domain)
    if domain in SOCIAL_DOMAINS:
        return Classification("social", score, (f"arriva da un social network ({domain})",))

    bulk = _bulk_reasons(msg)
    automated = _automated_reasons(msg)
    promo = bool(_PROMO.search(msg.subject))
    purchase = bool(_PURCHASE.search(msg.subject))
    if purchase and not promo:
        return Classification("acquisti", score, (_PURCHASE_REASON, *bulk, *automated))
    if bulk:
        if promo:
            return Classification("promozioni", score, ("l'oggetto propone sconti o offerte", *bulk))
        return Classification("newsletter", score, tuple(bulk))
    if purchase:
        return Classification("acquisti", score, (_PURCHASE_REASON, *automated))
    if automated:
        return Classification("notifiche", score, tuple(automated))
    return Classification("personale", score, ("non ha i segni di un invio automatico o di massa",))
