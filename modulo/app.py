from mitmproxy import http
import requests
import threading
from staticLinkModule import *
from updater import DAO, UpdaterThread
import os
import sys
import time
from dotenv import load_dotenv
from enum import Enum
import logging
from typing import Dict

from mitmproxy.log import ALERT
import subprocess


# Configs
#blacklist_url = "https://phishing.army/download/phishing_army_blocklist.txt"
#listFolder = "lists"

class PhishingValue(Enum):
    TRUSTED = 1
    SUSPECT = 2
    PHISHING = 3

class PhishingProxy:

    def buildBlockResponse(self, url):
        # Il tag Meta Refresh ricarica l'URL ogni 2 secondi
        html_block_content = f"""
        <html>
            <head>
                <title>URL Bloccato</title>
                <style>
                    body {{ font-family: sans-serif; text-align: center; padding-top: 50px; }}
                    .loader {{ font-size: 20px; color: #333; }}
                </style>
            </head>
            <body>
                <h1>URL malevolo rilevato</h1>
                <div>
                    <p>Target: {url}</p>
                </div>
            </body>
        </html>
        """

        blockResponse = http.Response.make(
            403,
            html_block_content,  # content
            {"Content-Type": "text/html"},  # headers
        )
        
        return blockResponse

    def buildWaitResponse(self, url):
        # Il tag Meta Refresh ricarica l'URL ogni 2 secondi
        html_waiting_content = f"""
        <html>
            <head>
                <title>Attendere</title>
                <meta http-equiv="refresh" content="2">
                <style>
                    body {{ font-family: sans-serif; text-align: center; padding-top: 50px; }}
                    .loader {{ font-size: 20px; color: #333; }}
                </style>
            </head>
            <body>
                <h1>Analisi dinamica in corso...</h1>
                <p class="loader">Attendere. Non chiudere la finestra.</p>
                <div>
                    <p>Target: {url}</p>
                </div>
            </body>
        </html>
        """

        waitResponse = http.Response.make(
                200,
                html_waiting_content,  # content
                {"Content-Type": "text/html"},  # headers
            )
        
        return waitResponse

    def get_windows_config(self):
        config = {}

        # 1. TROVA L'UTENTE WINDOWS
        try:
            user_output = subprocess.check_output(
                ["cmd.exe", "/c", "echo %USERNAME%"], 
                stderr=subprocess.DEVNULL
            ).decode().strip()
            config['user'] = user_output
        except Exception:
            config['user'] = "unknown"

        # 2. TROVA L'IP DI WINDOWS
        #Chiediamo alla tabella di routing di Linux
        try:
            route_output = subprocess.check_output(["ip", "route"]).decode()
            
            gateway_ip = "127.0.0.1"
            for line in route_output.splitlines():
                if "default via" in line:
                    parts = line.split()
                    # La terza parola è sempre l'IP del gateway (es. 172.20.0.1)
                    gateway_ip = parts[2]
                    break
                    
            config['ip'] = gateway_ip
            
        except Exception:
            config['ip'] = "127.0.0.1"

        return config  

    def log_print(self, *args):
        msg = " ".join(map(str, args))
        if hasattr(self, "print_logger"):
            self.print_logger.info(msg)

    def load(self, loader):
        # --- CARICAMENTO ROBUSTO .ENV ---
        def trova_e_carica_env():
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # Cerca il .env risalendo le cartelle (massimo 3 livelli)
            for _ in range(3):
                env_path = os.path.join(current_dir, ".env")
                if os.path.exists(env_path):
                    print(f"[*] Trovato file .env in: {env_path}")
                    load_dotenv(env_path)
                    return True
                current_dir = os.path.dirname(current_dir)
            
            # Se non lo trova, prova il caricamento standard
            print("[*] .env non trovato nelle directory superiori. Provo load_dotenv() standard...")
            load_dotenv()
            return False

        trova_e_carica_env()
        
        # DEBUG: Verifica caricamento chiavi (mascherate)
        vt_key = os.getenv('VIRUSTOTAL_APIKEY')
        CAPE_TOKEN = os.getenv('CAPE_APIKEY')
        print(f"[*] DEBUG VARS -> VT_KEY: {'OK (' + vt_key[:4] + '...)' if vt_key else 'MISSING'}, CAPE_KEY: {'OK' if CAPE_TOKEN else 'MISSING'}")

        if vt_key:
             vt_key = vt_key.strip()

        # Inizializzazione cache REDIS
        self.cache = DAO("REDIS_DB_CACHE").get_db_connection()
        self.cache.flushdb()

        CAPE_API_URL = "http://127.0.0.1:8000"
        
        self.cape_engine = CapeControl(CAPE_API_URL, CAPE_TOKEN)

        self.analyzable_contents = ["text/html"]

        #Inizializzazione attributi utente e ip di windows
        self.config_data= self.get_windows_config()
        self.user = self.config_data['user']
        self.ip = self. config_data['ip']

        # Inizializzazioni delle classi di controllo statico come attributi di istanza
        self.basic_control = BasicControl()
        self.certificate_control = CertificateControl()
        self.phishing_army = PhishingArmyControl()
        self.vt_engine = VirusTotalControl(api_key=vt_key)
        self.typo_control = TypoDetector(whitelist_name="whitelist")
        self.foreign_control = ForeignCharDetector()

        self.lastUpdate = time.time()

        self.phishing_army.load_data(True if not hasattr(self, 'lastUpdate') or (time.time() - self.lastUpdate) > 21600 else False)
        self.typo_control.load_data()


        # True Per vedere i log di qualsiasi URL,
        # False per i soli URL da analizzare approfonditamente
        self.debug_mode = True
        self.force_cape_analysis = False
 

        # --- CONFIGURAZIONE LOGGING DUAL SYSTEM ---
        base_dir = os.path.dirname(os.path.abspath(__file__))
        logs_dir = os.path.abspath(os.path.join(base_dir, "..", "logs"))
        try:
            os.makedirs(logs_dir, exist_ok=True)
        except Exception as e:
            pass # Gestione errore permessi

        # 1. Logger Analisi (mitmproxylog_UrlAnalyze.log)
        self.analyze_logger = logging.getLogger("UrlAnalyze")
        self.analyze_logger.handlers = [] 
        self.analyze_logger.propagate = True
        self.analyze_logger.setLevel(logging.INFO)
        if self.debug_mode:
            self.analyze_logger.setLevel(logging.DEBUG)
            
        try:
            analyze_path = os.path.join(logs_dir, "mitmproxylog_UrlAnalyze.log")
            analyze_handler = logging.FileHandler(analyze_path, mode='a', encoding='utf-8')
            analyze_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.analyze_logger.addHandler(analyze_handler)
        except Exception:
            pass

        # 2. Logger Stampe (mitmproxy_Prints.log)
        self.print_logger = logging.getLogger("Prints")
        self.print_logger.handlers = []
        self.print_logger.propagate = True
        self.print_logger.setLevel(logging.INFO)
        
        try:
            print_path = os.path.join(logs_dir, "mitmproxy_Prints.log")
            print_handler = logging.FileHandler(print_path, mode='a', encoding='utf-8')
            print_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
            self.print_logger.addHandler(print_handler)
        except Exception:
            pass

        # --- Avvio thread di aggiornamento periodico delle liste ---

        self.analyze_logger.info("Avvio updaters in corso...")

        pishing_army_updater = UpdaterThread(21600, self.phishing_army)
        pishing_army_updater.start()

        typosquatting_updater = UpdaterThread(120, self.typo_control)
        typosquatting_updater.start()

        self.analyze_logger.info("Updaters avviati")


    def blocca_indirizzo(self, port, indirizzo_target):
        self.log_print(f"🔒 Blocco traffico per {indirizzo_target}:{port}...")

        # --- REGOLA 1: BLOCCO ENTRATA (IN) ---
        rule_in = f"HouseGuard_BLOCK_IN_{indirizzo_target}_{port}"
        # Usiamo powershell.exe per interop WSL -> Windows
        # netsh va invocato direttamente come eseguibile Windows
        netsh_cmd = "netsh.exe"
        
        args_in = [
            netsh_cmd, "advfirewall", "firewall", "add", "rule",
            f"name={rule_in}",
            "dir=in",
            "action=block",
            "protocol=TCP",
            f"localport={port}",
            f"remoteip={indirizzo_target}" # Nota: remoteip blocca traffico da QUEL server, localip blocca porte SUL tuo pc
        ]

        # --- REGOLA 2: BLOCCO USCITA (OUT) ---
        rule_out = f"HouseGuard_BLOCK_OUT_{indirizzo_target}_{port}"
        args_out = [
            netsh_cmd, "advfirewall", "firewall", "add", "rule",
            f"name={rule_out}",
            "dir=out",
            "action=block",
            "protocol=TCP",
            f"remoteport={port}", # In uscita, blocchiamo la porta remota del server
            f"remoteip={indirizzo_target}"
        ]

        try:
            # 1. Pulizia preventiva (ignoriamo errori se non esiste)
            subprocess.run([netsh_cmd, "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([netsh_cmd, "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # 2. Applicazione Regole
            self.log_print(f"   -> Scrivendo regola INBOUND...")
            # check=True solleva eccezione se il comando fallisce (es. privilegi insufficienti)
            subprocess.run(args_in, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.log_print(f"   -> Scrivendo regola OUTBOUND...")
            subprocess.run(args_out, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.log_print("✅ Blocco firewall attivato con successo (Windows Interop).")
            
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.decode('cp850', errors='ignore') if e.stderr else "Nessun output di errore"
            self.log_print(f"❌ Errore comando Firewall: {err_msg}")
            self.log_print("   ⚠️  Assicurati che WSL sia avviato come AMMINISTRATORE.")
        except FileNotFoundError:
             self.log_print("❌ Errore: netsh.exe non trovato. Sei su WSL/Windows?")

        except subprocess.CalledProcessError as e:
            self.log_print(f"❌ Errore durante l'applicazione del firewall: {e}")

    def staticAnalysis_score(self, url, is_domain = False, use_virus_total = True) -> Dict[str, float]:
        """
        Invoca i controlli sull'URL o dominio fornito,
        elabora un punteggio per ogni risultato e li restituisce in un dizionario
        """
        scores = {}

        # Analisi certificato TLS

        if is_domain:
            scores["certs"] = 0
            try:
                certificate_analysis = self.certificate_control.analyze(url)
            except Exception as e:
                print(f"Errore durante l'analisi del certificato per {url}: {e}")
                certificate_analysis = {"status": "UNKNOWN"}
                scores.pop("certs")

            if certificate_analysis["status"] == "WARNING": 
                self.log_print(certificate_analysis)
                self.log_print("-" * 30)
                scores["certs"] += 50
            elif certificate_analysis["status"] == "DANGER":
                self.log_print(certificate_analysis)
                self.log_print("-" * 30)
                scores["certs"] += 100
        
        # Analisi database scaricabili(PhishingArmy)
        # Blocco istantaneo per ogni presenza rilevata

        if is_domain:
            check_phishing_army = self.phishing_army.check_url(url)
            self.log_print("   🎏  Controllo Phishing Army in corso...")
            if check_phishing_army:
                self.log_print(f"   🛑 RILEVATO DA PHISHING ARMY!")
                self.log_print(f"      Dominio bloccato: {check_phishing_army['domain_matched']}")
                scores["phishingarmy"] = 100
                return scores

        # Analisi Typosquatting
        # 0 se è dominio legittimo, altrimenti edit distance normalizzata da 0 a 100 

        if is_domain:
            typo_score = self.typo_control.get_typo_score(url)
            print("   🎏  Controllo typosquatting in corso...")
            scores["typo"] = typo_score[0]
        
        # Analisi caratteri stranieri
        # 0 se non ce ne sono, altrimenti conteggio normalizzato da 0 a 100

        if is_domain:
            foreign_score = self.foreign_control.analyze_domain(url)
            print("   🎏  Controllo caratteri stranieri in corso...")
            scores["foreign"] = foreign_score
        
        # Analisi effettuata da VirusTotal
        # VirusTotal effettua un rapporto tra voti maliziosi e voti totali
        # il punteggio è la normalizzazione dei voti maliziosi rispetto a
        # quelli totali in scala da 0 a 100
        
        if use_virus_total:

            scores["virustotal"] = 0

            self.log_print("   ☁️  Controllo VirusTotal in corso...")
            check_virus_total = self.vt_engine.check_url(url)

            if check_virus_total and check_virus_total.get('error'):
                if check_virus_total.get('quota_exceeded'):
                     self.log_print(f"   ⚠️ {check_virus_total['message']}")
                else:
                     self.log_print(f"   ⚠️ Errore VirusTotal: {check_virus_total['message']}")
                scores.pop("virustotal")
            elif check_virus_total and check_virus_total.get('detected'):
                self.log_print(f"   ☣️  RILEVATO DA VIRUSTOTAL!")
                self.log_print(f"      Punteggio: {check_virus_total['malicious_votes']}/{check_virus_total['total_votes']}")
                scores["virustotal"] += check_virus_total["malicious_votes"] / check_virus_total["total_votes"] * 100
            elif check_virus_total:
                self.log_print("   ✅ Pulito (VirusTotal).")
            else:
                self.log_print("   ⚠️ Errore/Quota VirusTotal o Errore API (Nessuna risposta).")
                scores.pop("virustotal")
            
        else:
             # Se non uso VirusTotal (es. risorsa non analizzabile), lo segnalo in debug
             pass 

        return scores

    # - se fidato -> lascio passare
    # - se sospetto -> lascio decidere a cape
    # - se sicuro phishing -> blocco a prescindere, e viene aggiunto in cache
    def staticAnalysis_detection(self, scores, domainDecision = None) -> PhishingValue:

        decision = "suspect"

        # Se è un URL si considera virustotal oltre alla decisione sul dominio
        if domainDecision:
            if "virustotal" in scores:
                if domainDecision == "block" or domainDecision == "suspect" and scores["virustotal"] > 10:
                    return domainDecision
                else:
                    if scores["virustotal"] <= 6:
                        decision = "pass"
                        return decision
            else:
                decision = "pass"
                return decision
        
        # Blocco immediato se Phishing Army o certificato self-signed
        if "phishingarmy" in scores or scores["certs"] == 100:
            decision = "block"
            return decision

        # Virustotal: tipicamente > 12 malevolo, ma ha falsi positivi
        # si riducono falsi positivi se il certificato non è a pagamento o se ci sono caratteri stranieri
        if "virustotal" in scores:
            if scores["virustotal"] > 18 or (scores["virustotal"] >= 10 and (scores["foreign"] != 0 or scores["certs"] != 0)):
                decision = "block"
                return decision

        # Analisi Typosquatting: tipicamente malevolo > 75 in poi, ma può avere falsi positivi
        # si riducono falsi positivi se il certificato non è a pagamento o se ci sono caratteri stranieri
        if scores["typo"] >= 70 and (scores["foreign"] != 0 or scores["certs"] != 0):
            decision = "block"
            return decision
        
        # Virustotal: tipicamente < 6 malevolo, ma ha falsi negativi per siti mai analizzati
        # si riducono falsi negativi se il certificato è a pagamento e se non c'é typosquatting
        if  "virustotal" in scores:
            if scores["virustotal"] <= 6 and scores["typo"] < 10 and scores["certs"] == 0:
                decision = "pass"
                return decision
        else:
            # Nel caso in cui non serve analisi approfondita si ha un approccio più lasco
            if scores["typo"] < 5 and scores["certs"] == 0:
                decision = "pass"
                return decision
    
        return decision

    def process_response(self, url, domain, is_root_path = False, deep_analyze = False) -> str:
        
        # --- Check su cache:
        #     Se l'URL è presente, si verifica se
        #     è in atto una analisi dinamica per l'url corrente
        #     o se la richiesta va bloccata o lasciata passare
        # Lista di domini che rompono la connessione con MITM (Certificate Pinning)
        # Questi non dovrebbero nemmeno essere intercettati, ma se lo sono, li lasciamo passare.
        
        # --- (1) Check su LISTE LOCALI (whitelist/blacklist)
        #     Hanno priorità assoluta sulla cache: se l'admin ha messo in WL, deve passare subito.
        if self.basic_control.checkWhitelist(domain):
            self.analyze_logger.debug("[Proxy] dominio in whitelist")
            return "pass" 
            
        if self.basic_control.checkWhitelist(url):
            self.analyze_logger.debug("[Proxy] URL in whitelist")
            return "pass"

        if self.basic_control.checkBlacklist(domain):
            self.analyze_logger.debug("[Proxy] dominio in blacklist")
            return "block"
        if self.basic_control.checkBlacklist(url):
            self.analyze_logger.debug("[Proxy] URL in blacklist")
            return "block"

        # --- (2) Check su CACHE (Redis)
        #     Se l'URL è presente, si verifica se è in atto una analisi dinamica
        #     o se la richiesta va bloccata o lasciata passare.
        
        decision = self.cache.get(url)
        if decision:
            self.analyze_logger.info(f"[Proxy] decision in cache {decision}")
            if decision == "processing":
                self.analyze_logger.debug("[Proxy] Analisi dinamica in corso")
            elif decision == "block":
                self.analyze_logger.info("[Proxy] URL bloccato da cache")
            return decision
            
        #     Se il dominio è presente ed è non fidato, si blocca
        decision = self.cache.get(domain)
        if decision:
            if decision == "block":
                self.analyze_logger.info("[Proxy] dominio bloccato da cache")
                return "block"
            elif decision == "pass":
                self.analyze_logger.debug("[Proxy] dominio non malevolo in cache")
                return "pass"

        # --- Effettua analisi statica
        
        domainDecision = self.cache.get(domain)
        if not domainDecision:
            # --- Effettua analisi statica del dominio
            scores = self.staticAnalysis_score(domain, is_domain = True, use_virus_total = deep_analyze)
            domainDecision = self.staticAnalysis_detection(scores)

            self.analyze_logger.info(f"[Proxy] Analisi statica del dominio completata. Scores: {scores}, decisione: {domainDecision}")

            #    Se il dominio è non fidato si blocca, altrimenti si continua
            #    Se il dominio è non fidato si blocca, altrimenti si continua
            if not self.force_cape_analysis and domainDecision == "pass":
                self.cache.set(domain, "pass")
                self.analyze_logger.debug("[Proxy] dominio non malevolo messo in cache")
                
            elif not self.force_cape_analysis and domainDecision == "block":
                self.cache.set(domain, "block")
                self.analyze_logger.info("[Proxy] dominio bloccato e messo in cache")
                return "block"
        
        # --- Effettua analisi statica dell'URL
        scores = self.staticAnalysis_score(url, is_domain = False, use_virus_total = deep_analyze and not is_root_path)
        decision = self.staticAnalysis_detection(scores, domainDecision)

        self.analyze_logger.info(f"[Proxy] Analisi statica dell'URL completata. Scores: {scores}, decisione: {decision}")

        if not self.force_cape_analysis and decision == "pass":
            self.cache.set(url, "pass")
            self.analyze_logger.debug("[Proxy] URL non malevolo messo in cache")
            return "pass"
        elif not self.force_cape_analysis and decision == "block":
            self.cache.set(url, "block")
            self.analyze_logger.info("[Proxy] URL bloccato e messo in cache")
            return "block"
        
        self.analyze_logger.debug("[Proxy] URL sospetto, inizio analisi dinamica...")

        # Si arriva qui se l'URL è sospetto
        # Si analizza l'URL solo se corrisponde ad una delle risorse specificate
        if deep_analyze:
            self.cache.set(url, "processing")
            # CORRETTO: target=self.dynamic_analysis per usare il metodo di istanza
            t = threading.Thread(target=self.dynamic_analysis, args=(url,domain,self.cache))
            t.start()

            return "processing"
        else:
            return "pass"

    # Intercetta la richiesta HTTP
    def response(self, flow: http.HTTPFlow) -> None:
        
        url = flow.request.pretty_url
        domain = flow.request.pretty_host
        path = flow.request.path

        if "virustotal.com" in domain:
            self.log_print(f"   ☁️  Richiesta verso VirusTotal intercettata: {url}")
            self.analyze_logger.info(f"[Proxy] Richiesta verso VirusTotal intercettata: {url}")
            return

        # --- Verifica in base al tipo di contenuto ricevuto
            # se serve una analisi approfondita.
            # Si verifica solo se lo status code è 2xx ma non
            # di 204 : No Content
        deep_analyze = False
        response_content_type = None
        status_code = flow.response.status_code
        if str(status_code)[0] == "2" and status_code != 204:
            deep_analyze = False
            response_content_type = flow.response.headers.get("Content-Type", None)
            if response_content_type:
                for content_type in self.analyzable_contents:
                    if content_type in response_content_type:
                        deep_analyze = True
        
        # Verifica se è root path
        isRootPath = False
        actualPath = ""
        if path:
            actualPath = path.split("?")[0]
            if actualPath in ["/", "/index.html", "/index.php"]:
                isRootPath = True

        logString = f"[Proxy] Ricevuta risposta da dominio {domain}\n" \
                + f"URL: {url}\n" \
                + f"È path di root: {isRootPath}\n" \
                + f"Content type: {response_content_type}\n" \
                + f"Analisi approndita richiesta: {deep_analyze}\n" \
                + f"-" * 30
        
        if not self.debug_mode:
            if deep_analyze:
                self.analyze_logger.setLevel(logging.DEBUG)
                self.analyze_logger.info(logString)
            else:
                self.analyze_logger.setLevel(logging.INFO)
        else:
            self.analyze_logger.debug(logString)
        
        # DEBUG
        deep_analyze = False

        decision = self.process_response(url, domain, is_root_path = isRootPath, deep_analyze=deep_analyze)

        if decision == "processing":
            flow.response = self.buildWaitResponse(url)
        elif decision == "block":
            flow.response = self.buildBlockResponse(url)
            indirizzo = flow.server_conn.peername[0]
            port = flow.server_conn.peername[1]
            self.blocca_indirizzo(port, indirizzo)
        elif decision == "pass":
            return
        
        
    # --- Analisi dinamica con CAPE
    def dynamic_analysis(self, url, domain, cache):
        decision = "pass"
        time.sleep(5)
        self.log_print("   📦 Invio a CAPE Sandbox Locale...")
    
        # 1. Invio
        task_id = self.cape_engine.submit_url(url)
        
        if task_id:
            self.log_print(f"   ✅ URL inviato. Task ID: {task_id}")
            
            # 2. Attesa attiva del risultato
            report = self.cape_engine.wait_for_report(task_id)
            
            if report:
                # 3. Analisi del Report JSON
                # CAPE assegna un 'malscore' da 0.0 a 10.0
                if report.get("error"):
                    self.log_print(f"   ⚠️ Impossibile determinare malignità (Errore CAPE: {report.get('reason')})")
                    self.log_print("   ➡️ Considero l'URL sospetto per precauzione (o lo ignoro, a tua scelta).")
                else:
                    
                    malscore = report.get('malscore', 0)
                    
                    self.log_print(f"\n   📊 RISULTATO ANALISI DINAMICA:")
                    self.log_print(f"      Punteggio Malignità: {malscore}/10.0")
                    
                    # Estrazione firme (comportamenti sospetti)
                    signatures = report.get('signatures', [])
                    if signatures:
                        self.log_print("      🚩 Comportamenti sospetti rilevati:")
                        for sig in signatures:
                            # Stampa nome e severità della firma
                            sig_name = sig.get('name')
                            sig_sev = sig.get('severity', 1)
                            self.log_print(f"         - [{sig_sev}/5] {sig_name}")
                            decision = "block"
                    else:
                        self.log_print("      ✅ Nessun comportamento sospetto rilevato.")
                        decision = "pass"

                # Logica di blocco basata sul punteggio CAPE
                if malscore >= 5.0:
                    self.log_print(f"   🛑 BLOCCO: Punteggio CAPE troppo alto!")
                    decision = "block"
                else:
                    self.log_print(f"   ✅ URL considerato sicuro da CAPE.")
                    decision = "pass"

            else:
                self.log_print("   ⚠️ Impossibile recuperare il report (Timeout o Errore).")

                
        else:
            self.log_print("   ❌ Errore nell'invio a CAPE.")

        self.log_print("-" * 40)


        # Si salva la decisione di CAPE nella cache
        self.analyze_logger.info(f"[Proxy] Analisi dinamica completata. Decisione: {decision}")
        cache.set(url, decision)
        return

addons = [PhishingProxy()]