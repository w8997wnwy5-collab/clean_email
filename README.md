# Bot pulizia email per iCloud

Un bot che si collega alla tua posta iCloud, capisce che cosa ti arriva
(spam, newsletter, promozioni, social, notifiche, acquisti, posta personale)
e ti **propone** regole e cartelle per tenerla in ordine. Decidi tu che cosa
approvare: il bot non tocca niente senza il tuo sì, e quello che fa si può
annullare.

Lo usi dall'iPhone con l'app gratuita **a-Shell**. Se vuoi, le regole che hai
approvato possono girare da sole ogni ora su GitHub, anche a telefono spento.

- [Com'è protetta la tua posta](#comè-protetta-la-tua-posta)
- [1. Crea la password per le app](#1-crea-la-password-per-le-app)
- [2. Installa il bot sull'iPhone](#2-installa-il-bot-sulliphone)
- [3. La prima pulizia](#3-la-prima-pulizia)
- [4. Il menu](#4-il-menu)
- [5. Pulizia automatica (facoltativa)](#5-pulizia-automatica-facoltativa)
- [6. Regole native su iCloud.com (facoltative)](#6-regole-native-su-icloudcom-facoltative)
- [Come decide le categorie](#come-decide-le-categorie)
- [Se qualcosa non va](#se-qualcosa-non-va)
- [Limiti da sapere](#limiti-da-sapere)
- [Per sviluppatori](#per-sviluppatori)

## Com'è protetta la tua posta

- **Mai la password dell'Apple ID.** Il bot usa una *password specifica per
  le app*: apre solo Mail, Contatti e Calendari, non può cambiare il tuo
  account e la puoi revocare in qualsiasi momento.
- **Connessione cifrata e verificata.** Il bot parla solo con il server di
  Apple `imap.mail.me.com` sulla porta 993, cifrato dal primo byte (TLS 1.2 o
  1.3), e controlla che il certificato sia valido e intestato a quel server.
  Se qualcosa non torna (una rete pubblica che intercetta, un certificato
  falso) si ferma **prima** di inviare la password. Non esiste un'opzione per
  spegnere questi controlli o per puntare il bot verso un altro server.
- **Legge solo le intestazioni.** Per capire che cos'è una mail gli bastano
  mittente, oggetto, data e poche altre intestazioni tecniche. Il testo delle
  mail e gli allegati non escono mai da iCloud.
- **Nessun programma di terzi.** Il bot usa solo Python e la sua libreria
  standard: niente pacchetti scaricati da Internet che potrebbero essere
  manomessi.
- **Le tue regole restano nella tua posta.** Questo repository è pubblico, per
  questo le regole (che contengono nomi di mittenti) non stanno qui ma in un
  messaggio nella cartella **Bot Email** della tua casella. Un messaggio
  falso con le stesse caratteristiche, spedito da qualcun altro, viene
  ignorato.
- **Niente cancellazioni definitive.** Il bot sposta le mail in una cartella,
  in **Indesiderata** o nel **Cestino** (che iCloud tiene per 30 giorni), o le
  segna come lette. Ogni azione finisce nel **registro** e l'ultima operazione
  si può **annullare**.
- **Le persone a cui scrivi non finiscono mai nello spam**, e puoi indicare
  mittenti **protetti** che nessuna regola tocca.
- **Sull'iPhone** la password resta nella cartella privata di a-Shell (nel
  portachiavi di iOS se usi Pythonista). **Su GitHub** sta nei *Secrets*
  cifrati, e i log pubblici mostrano solo numeri.

## 1. Crea la password per le app

1. Apri [account.apple.com](https://account.apple.com) e accedi.
2. Vai in **Accesso e sicurezza** → **Password specifiche per le app**.
3. Tocca **+**, chiamala per esempio «Bot email» e conferma.
4. Copia la password che compare: sono quattro gruppi di quattro lettere,
   `xxxx-xxxx-xxxx-xxxx`. Apple non te la mostrerà più: se la perdi, ne crei
   un'altra.

Per spegnere il bot del tutto basta revocare questa password nella stessa
pagina.

## 2. Installa il bot sull'iPhone

1. Installa l'app gratuita **a-Shell** dall'[App Store](https://apps.apple.com/ch/app/a-shell/id1473805438)
   (va bene anche *a-Shell mini*). È un piccolo terminale con Python già dentro.
2. Apri a-Shell e scrivi questi comandi, uno alla volta, premendo invio dopo
   ognuno:

   ```bash
   lg2 clone https://github.com/w8997wnwy5-collab/clean_email
   ```

   ```bash
   cd clean_email
   ```

   ```bash
   python3 bot.py
   ```

3. Al primo avvio il bot chiede il tuo indirizzo iCloud e la password per le
   app (incollala). In a-Shell la password resta visibile mentre la incolli:
   è normale, l'app non permette di nasconderla. Il bot prova subito la
   connessione e, se va, ti chiede se salvarla sul telefono così non devi
   reinserirla.

Le volte successive apri a-Shell e scrivi solo:

```bash
python3 ~/Documents/clean_email/bot.py
```

Per **aggiornare** il bot a una versione nuova cancella la cartella e
scaricala di nuovo, con questi tre comandi. Regole e password non si perdono:
non stanno in quella cartella.

```bash
cd ~/Documents
```

```bash
rm -rf clean_email
```

```bash
lg2 clone https://github.com/w8997wnwy5-collab/clean_email
```

Tieni a-Shell aperta mentre il bot lavora: se passi a un'altra app, iOS può
sospenderla dopo poco.

## 3. La prima pulizia

Nel menu scegli **1) Analizza la posta e proponi regole**. Il bot guarda le
ultime 1000 mail in arrivo e ti mostra quante sono di ogni tipo e chi te ne
manda di più. Poi propone, per esempio:

```text
💡 Proposte (decidi tu):
 1. Metti in Indesiderata lo spam sospetto (12 mail), ora e in futuro
      PayPal <secure@paypa1-verify.xyz>: il nome dice «PayPal» ma l'indirizzo è @paypa1-verify.xyz
 2. Sposta le newsletter nella cartella «Newsletter» (312 mail da 45 mittenti)
 3. Sposta le promozioni nella cartella «Promozioni» (120 mail da 20 mittenti)
 4. Nella cartella «Newsletter», metti nel Cestino le mail più vecchie di 30 giorni
Quali approvi? Numeri (es. 1 3), «tutte», o invio per nessuna:
```

Scrivi i numeri che vuoi (per esempio `1 2 4`), `tutte`, oppure premi invio
per non approvarne nessuna. Il bot ti chiede anche se vuoi buttare sempre
nel Cestino le mail di qualche mittente che non leggi mai.

Prima di toccare qualunque cosa ti mostra un'**anteprima** (quante mail, quali
mittenti, quali oggetti) e chiede conferma. Le cartelle che mancano le crea
lui. Se il risultato non ti piace, scegli **9) Annulla l'ultima operazione**.

Le regole valgono dall'alto in basso e vince la prima che corrisponde: il bot
le mette da solo in un ordine sensato (prima i mittenti che hai scelto tu,
poi lo spam, poi le categorie).

## 4. Il menu

| Voce | A che cosa serve |
| --- | --- |
| 1) Analizza la posta e proponi regole | Classifica la posta e propone regole da approvare |
| 2) Le mie regole | Elenca le regole; puoi spegnerle, riaccenderle o eliminarle |
| 3) Aggiungi una regola | Ti guida con domande: quali mail, che cosa farne |
| 4) Applica le regole adesso | Anteprima e poi applicazione delle regole salvate |
| 5) Pulizia una tantum | Come una regola, ma usata una volta sola e non salvata |
| 6) Cartelle | Elenca le cartelle con il numero di mail e di non lette |
| 7) Regole da copiare su iCloud.com | Vedi il [punto 6](#6-regole-native-su-icloudcom-facoltative) |
| 8) Cosa ha fatto il bot | Le ultime azioni, con mittente e oggetto |
| 9) Annulla l'ultima operazione | Rimette le mail dov'erano |
| 10) Verifica la connessione sicura | Mostra cifratura, certificato e server |

Se preferisci scrivere i comandi, `python3 bot.py --help` li elenca tutti. Per
esempio:

```bash
python3 bot.py aggiungi --da @zalando.ch --sposta Acquisti
```

```bash
python3 bot.py pulisci --categoria newsletter --piu-vecchie-di 30 --cestina
```

```bash
python3 bot.py proteggi @lavoro.ch
```

```bash
python3 bot.py regole --json
```

L'ultimo stampa le regole in formato JSON: è un buon backup da tenere nelle
Note.

## 5. Pulizia automatica (facoltativa)

Le regole che approvi valgono anche per la posta futura, ma qualcuno deve
applicarle. Hai due possibilità.

### Ogni ora con GitHub

GitHub esegue il bot ogni ora sui suoi server, anche quando il telefono è
spento. Da iPhone serve Safari, perché l'app GitHub non gestisce i segreti:
apri questo repository su github.com e, se serve, scegli **aA → Richiedi sito
desktop**.

1. **Settings → Secrets and variables → Actions → New repository secret**:
   crea `ICLOUD_EMAIL` con il tuo indirizzo iCloud e `ICLOUD_APP_PASSWORD`
   con la password per le app.
2. Nella stessa pagina apri la scheda **Variables** e crea la variabile
   `PULIZIA_AUTOMATICA` con valore `si`. Senza questa variabile il bot non
   parte da solo.
3. Per una prova: scheda **Actions** → **Regole email** → **Run workflow**,
   spunta «Solo prova» e avvia.

I log di GitHub sono pubblici come il repository, quindi il bot ci scrive
solo numeri («Regola 2: 5 mail»). I dettagli (quali mail, dove sono finite,
eventuali problemi) li trovi nel menu **8) Cosa ha fatto il bot** oppure nel
messaggio **Registro del bot** dentro la cartella **Bot Email**.

Per sicurezza, ogni ora il bot guarda solo la posta arrivata negli ultimi 7
giorni (le regole di pulizia, invece, cercano proprio le mail vecchie) e salta
una regola che all'improvviso toccherebbe più di 300 mail: se è giusto così,
applicala dal telefono con **4) Applica le regole adesso**. Gli orari sono quelli svizzeri; per cambiarli
crea la variabile `FUSO_ORARIO` (per esempio `Europe/Rome`). Se un giorno
iCloud accettasse il tuo account solo con il nome prima della @, aggiungi
anche il segreto `ICLOUD_USERNAME`.

GitHub può avviare il lavoro con qualche minuto di ritardo e, in un
repository pubblico, lo sospende dopo 60 giorni senza modifiche al
repository: ti avvisa per email e lo riattivi con un tocco in **Actions**.

### Dall'iPhone con Comandi rapidi

Se preferisci che la password resti solo sul telefono, puoi far partire il
bot da **Comandi rapidi**. Questo metodo non è ancora stato provato su un
iPhone vero.

1. Nell'app Comandi rapidi crea un comando con l'azione **Execute Command**
   di a-Shell e scrivi:

   ```bash
   python3 ~/Documents/clean_email/bot.py automatico
   ```

2. Nella scheda **Automazione** crea un'automazione **Ora del giorno** (per
   esempio ogni giorno alle 8) che esegue quel comando.

a-Shell si apre per un momento mentre il bot lavora.

## 6. Regole native su iCloud.com (facoltative)

iCloud non permette ai programmi di creare le sue regole: per questo il bot le
applica da sé. Le regole native hanno però un vantaggio: i server Apple le
applicano nell'istante in cui arriva la mail, anche a bot spento. Sanno
guardare solo il mittente, il destinatario o l'oggetto, una condizione per
regola.

La voce **7) Regole da copiare su iCloud.com** traduce le tue regole in un
elenco pronto da ricopiare su [icloud.com/mail](https://www.icloud.com/mail)
(**⚙︎ → Regole → Aggiungi una regola**; da iPhone con **Richiedi sito
desktop**). Per le regole basate su una categoria, come «tutte le newsletter»,
elenca i mittenti che il bot ha riconosciuto. Quelle che iCloud non sa fare,
come la pulizia delle mail vecchie, le lascia al bot.

## Come decide le categorie

Il bot guarda solo le intestazioni e ogni decisione ha i suoi motivi, che
vedi con `python3 bot.py analizza --dettagli`.

- **Spam sospetto**: somma degli indizi. Per esempio un nome che finge di
  essere una banca, un corriere, Apple o PayPal ma arriva da un altro dominio;
  controlli antifalsificazione (DMARC) falliti; i verdetti dei filtri di
  iCloud; frasi tipiche («account sospeso», «hai vinto», «pacco in
  giacenza»…); domini molto usati dagli spammer. Chi ha ricevuto una tua mail
  non è mai considerato spam.
- **Newsletter**: ha il link per disiscriversi, arriva da una lista o da una
  piattaforma di invii di massa.
- **Promozioni**: come le newsletter, ma con sconti, saldi o offerte
  nell'oggetto.
- **Acquisti**: l'oggetto parla di un ordine, una spedizione, una fattura o
  una ricevuta.
- **Social**: arriva da un social network (LinkedIn, Instagram, Facebook…).
- **Notifiche**: messaggi automatici, come codici di accesso o avvisi
  «no-reply».
- **Personali**: tutto il resto, cioè posta scritta da persone.

## Se qualcosa non va

- **«iCloud ha rifiutato l'accesso»**: controlla di usare la password per le
  app e non quella dell'Apple ID, e di non averla revocata. Alla prima
  configurazione, se l'indirizzo completo non va, il bot ti propone di
  riprovare con il solo nome prima della @, come suggerisce Apple per alcuni
  account.
- **«Il certificato del server non è valido»**: la rete che stai usando
  intercetta il traffico (succede con alcuni Wi-Fi pubblici, VPN o antivirus).
  Il bot si è fermato prima di inviare la password: cambia rete e riprova.
- **«La connessione con iCloud si è interrotta»**: riprova; tieni a-Shell
  aperta mentre lavora.
- **Il bot resta fermo dopo che hai incollato la password**: succedeva con la
  prima versione (1.0.0). Chiudi a-Shell dal multitasking (scorri verso
  l'alto dal fondo dello schermo e spingi via la sua finestra), riaprila e
  aggiorna il bot con i tre comandi del [punto 2](#2-installa-il-bot-sulliphone).
  Il menu deve mostrare «versione 1.0.1» o successiva.
- **Una regola ha sbagliato**: menu **9) Annulla l'ultima operazione**. Le
  mail finite nel Cestino restano recuperabili per 30 giorni anche dall'app
  Mail.
- **Hai cancellato per errore il messaggio delle regole**: recuperalo dal
  Cestino e rimettilo nella cartella **Bot Email**.
- **Su GitHub «Mancano i segreti»**: crea `ICLOUD_EMAIL` e
  `ICLOUD_APP_PASSWORD` come al [punto 5](#ogni-ora-con-github).

## Limiti da sapere

- Il bot non crea le regole dentro iCloud, perché Apple non lo permette: le
  applica lui, o te le prepara da copiare.
- Le categorie si basano su indizi e possono sbagliare: per questo c'è
  sempre l'anteprima, nulla parte senza il tuo sì, ci sono i mittenti protetti
  e l'annullamento.
- Il bot è stato provato su un server di posta di prova che imita iCloud
  (nomi delle cartelle e cifratura compresi), non ancora sulla tua casella
  vera né su un iPhone vero. Comincia con poche regole e guarda l'anteprima.

## Per sviluppatori

Serve Python 3.10 o più recente, senza altre dipendenze. I test usano un
server Dovecot temporaneo per provare la connessione cifrata e le operazioni
vere; senza Dovecot quei test vengono saltati.

```bash
sudo apt-get install dovecot-imapd
```

```bash
python3 -m unittest discover -s . -p 'test_*.py'
```

La struttura è descritta in [AGENTS.md](AGENTS.md).
