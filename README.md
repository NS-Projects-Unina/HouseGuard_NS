# HouseGuard_NS

![HouseGuard Logo](/images/logo/HouseGuard_Logo_Small.png?raw=true)

## Partecipanti

- Simone De Lucia M63001720
- Gabriel Covone M63001809
- De Prophetis Claudio M63001815

## Cosa è HouseGuard?

HouseGuard è una soluzione progettata per proteggere le reti domestiche dalle minacce informatiche quotidiane. L'obiettivo principale del progetto è tutelare gli utenti meno esperti, spesso più vulnerabili ai rischi della rete, fornendo un sistema di difesa automatizzato e intuitivo.

Il sistema si articola in due moduli

1. **Network Security**: Protezione dalla navigazione su siti malevoli e analisi proattiva di file sospetti per prevenire infezioni malware.
2. **VoIP Security**: Identificazione e blocco di chiamate spam o tentativi di truffa telefonica attraverso l'analisi granulare del protocollo SIP.

# HouseGuard_NetworkSecurity

HouseGuard_NetworkSecurity è il modulo dedicato alla protezione del perimetro di rete. L'obiettivo di questo modulo è quello di evitare che l'utente possa essere ingannato con file o siti sospetti, agendo come un gateway intelligente che analizza il traffico in transito. Attraverso l'integrazione di strumenti di intercettazione e analisi dinamica, il sistema è in grado di identificare minacce proattivamente prima che raggiungano i dispositivi finali.

## Architettura generale

(immagine architettura)

### MITMProxy `modulo`

Mitmproxy è il primo controllore del traffico : intercetta e valuta il traffico HTTP e HTTPS tramite l'utilizzo di un'estensione personalizzata.
L'analisi del traffico viene effettuata a vari livelli:

- Liste preinstallate: viene usata una whitelist e una blacklist preinstallate e generate dall'utente per la sua valutazione
- Cache: Recupera valutazioni passate per evitare di ripetere analisi
- Livello statico: vengono considerati vari aspetti del link senza visitarlo come
  - Validità del certificato: se è self-signed, non valido, o generato tramite ente grautito
  - Affidabilità dell'URL: come è scritto, viene analizzata la sua scrittura, evidenziando se sono presenti casi di typosquatting o presenza di caratteri acrilici
- Livello dinamico: viene visitato il sito per analizzarlo tramite CAPE
  Al termine dell'analisi del sito possono esserci tre eventualità

1. Il sito è considerato sicuro: il traffico viene fatto passare
2. Il sito è considerato sospetto: il traffico viene inoltrato a CAPE per effettuare analisi più approfondite
3. Il sito è considerato pericoloso: il traffico viene bloccato.

#### Analisi statica `modulo/staticLinkModule.py`

Questo modulo esegue un'analisi preliminare dell'URL senza visitarlo direttamente, permettendo una valutazione rapida della minaccia. I suoi componenti principali includono:

- **Validator di Certificati**: Controlla l'integrità del certificato SSL/TLS, verificando se è self-signed, scaduto o emesso da autorità non attendibili.
- **Analizzatore di URL**: Implementa algoritmi per il rilevamento di tecniche di inganno come il typosquatting e l'uso di caratteri omografi (es. caratteri cirillici).
- **Integrazione Intelligence Esterna**: Effettua controlli tramite API verso VirusTotal per ottenere una valutazione globale della sicurezza e integra liste specifiche per il phishing scaricate da Phishing Army.
- **Gestore Cache e Liste**: Interroga le blacklist/whitelist locali e recupera i risultati di analisi precedenti per minimizzare i tempi di risposta.

#### Updater `modulo/updater.py`

Il modulo `updater.py` ha il compito di mantenere aggiornate le risorse di sicurezza del sistema per garantire l'efficacia contro le nuove minacce. Le sue funzioni principali includono:

- **Sincronizzazione Liste**: Scarica e integra periodicamente aggiornamenti per le blacklist e whitelist da repository remoti e feed di intelligence.
- **Manutenzione Firme**: Aggiorna i database locali utilizzati per il riconoscimento di pattern malevoli e certificati revocati o compromessi.
- **Ottimizzazione Risorse**: Gestisce la pulizia della cache e la rotazione dei log per mantenere elevate le prestazioni del sistema di analisi.

### Estensione Mitmproxy `modulo/app.py`

L'estensione `app.py` rappresenta il core logico dell'integrazione con Mitmproxy, agendo come orchestratore per ogni richiesta HTTP/HTTPS intercettata. Le sue responsabilità principali includono:

- **Intercettazione e Routing**: Cattura il traffico in transito e coordina il flusso di esecuzione tra i vari moduli di analisi.
- **Decision Engine**: Valuta i risultati ottenuti da `staticLinkModule.py` e decide in tempo reale se autorizzare la connessione, bloccarla o inoltrare la richiesta a CAPE per un'analisi dinamica.
- **Gestione degli Eventi**: Gestisce il ciclo di vita delle richieste (request, response, error), iniettando risposte custom o pagine di blocco quando viene rilevata una minaccia.
- **Comunicazione Inter-Modulo**: Funge da ponte tra il proxy e il sistema di difesa attiva (Firewall), segnalando gli IP malevoli da isolare a livello di rete.

### CAPE (Analisi Dinamica) `cape_source`

CAPE è una sandbox open-source per l'analisi di file e URL sospetti in maniera approfondita, tramite l'utilizzo di uno snapshot di una macchina virtuale Windows. Questo per garantire che la sandbox sia sempre nello stesso stato.

Funzionamento:

1. **Isolamento**: L'URL viene aperto in una VM Windows sicura.
2. **Monitoraggio**: Vengono registrati file system, rete e processi.
3. **Verdetto**: Se il report indica "malevolo", il Proxy blocca la connessione e aggiorna il firewall.
4. **Rapporto**: Viene generato un rapporto dettagliato dell'analisi. Il rapporto viene comunicato poi al proxy tramite API.

### Firewall (Difesa Attiva) `conf_ssh`

Il sistema estende la protezione oltre il proxy, agendo direttamente sul Firewall dell'host Windows.
Quando una minaccia viene confermata, il modulo Linux stabilisce una connessione SSH sicura verso l'host Windows per applicare regole di blocco a livello di sistema operativo.

**Meccanismo:**

1. **Rilevamento**: Viene identificato un link o file malevolo.
2. **Azione Remota**: Viene inviato un comando `netsh advfirewall` all'host tramite SSH.
3. **Blocco Totale**: L'IP viene bloccato sia in entrata che in uscita su tutte le porte.

## Guida all'installazione

Il sistema è stato testato su Windows 11, con un ambiente WSL2 che esegue un immagine di Ubuntu 22.04 LTS.

### Firewall

Per consentire al modulo Linux di inviare comandi all'host Windows per la gestione del firewall, è necessario configurare il server OpenSSH:

1. **Installazione**:
   Aprire PowerShell come amministratore ed eseguire:
   
   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   ```
2. **Avvio del servizio**:
   Impostare l'avvio automatico e avviare il demone `sshd`:
   
   ```powershell
   Set-Service -Name sshd -StartupType 'Automatic'
   Start-Service sshd
   ```
3. **Regola di accesso**:
   Abilitare il traffico sulla porta 22 nel firewall di Windows:
   
   ```powershell
   New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
   ```

### Macchina virtuale

Per configurare la macchina virtuale Windows 10 necessaria per l'analisi dinamica, seguire i passaggi indicati:

1. **Download e Decompressione**:
   Scarica l'immagine disco `win10_vittima.qcow2` da [questo link](https://drive.google.com/file/d/1lFntYoGwtzFhvNu6kWv2nh68UyAX-J4l/view?usp=sharing) e posizionala nella directory delle immagini di Libvirt (solitamente `/var/lib/libvirt/images/`).
2. **Importazione in KVM**:
   Crea una nuova macchina virtuale tramite `virt-manager` o `virsh` utilizzando il file `.qcow2` come disco principale.
3. **Configurazione Rete**:
   Assicurati che la VM sia collegata alla rete virtuale corretta gestita dal modulo `rooter` di CAPE.
4. **Snapshot**:
   Avvia la VM, verifica che l'agent di CAPE sia in esecuzione automatica all'avvio e scatta uno snapshot chiamato `snapshot1`. Questo stato verrà ripristinato automaticamente dopo ogni analisi.

## Avvio del sistema

### Avvio del container

Vanno avviati i container con i database REDIS e PostgreSQL.

```
docker compose up -d
```

### Installazione delle dipendenze

Installare i pacchetti Python necessari:

```bash
pip install -r modulo/requirements.txt
```

### Componenti CAPE

Eseguire in terminali separati:

1. **Rooter** (Routing VM):
   
   ```bash
   cd ~/HouseGuard_NS/cape_source && source venv/bin/activate
   sudo python3 utils/rooter.py -g $USER
   ```
2. **Interfaccia Web**:
   
   ```bash
   cd ~/HouseGuard_NS/cape_source && source venv/bin/activate
   python3 web/manage.py runserver 0.0.0.0:8000
   ```
3. **Cuckoo (Core)**:
   
   ```bash
   cd ~/HouseGuard_NS/cape_source && source venv/bin/activate
   python3 cuckoo.py -d
   ```
4. **Guardian** (Generazione Report):
   
   ```bash
   cd ~/HouseGuard_NS/cape_source && source venv/bin/activate
   ./guardian.sh
   ```

