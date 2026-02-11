from mitmproxy import http
import requests
import threading
from staticLinkModule import BasicControl,  CertificateControl, VirusTotalControl, PhishingArmyControl, CapeControl, TypoDetector, ForeignCharDetector
from updater import DAO, UpdaterThread
import os
import sys
import time
from dotenv import load_dotenv
from enum import Enum
import logging

from mitmproxy.log import ALERT


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

    def load(self, loader):
        load_dotenv()
        # formato del tipo {"posteitaliane.it : "pass", "postltaliane.it" : "block"}
        self.cache = DAO("REDIS_DB_CACHE").get_db_connection()
        self.cache.flushdb()

        CAPE_TOKEN = os.getenv('CAPE_API_KEY')
        CAPE_API_URL = "http://127.0.0.1:8000"
        
        self.cape_engine = CapeControl(CAPE_API_URL, CAPE_TOKEN)

        self.analyzable_contents = ["text/html"]

        #Inizializzazione attributi utente e ip di windows
        self.config_data= self.get_windows_config()
        self.user = self.config_data['user']
        self.ip = self. config_data['ip']

        # 
        whitelist_domains = ["google.com", "microsoft.com", "posteitaliane.it"]

        # Inizializzazioni delle classi di controllo statico come attributi di istanza
        self.basic_control = BasicControl()
        self.certificate_control = CertificateControl()
        self.phishing_army = PhishingArmyControl()
        self.vt_engine = VirusTotalControl(os.getenv("VIRUSTOTAL_API_KEY"))
        self.typo_control = TypoDetector(whitelist_domains)
        self.foreign_control = ForeignCharDetector()

        self.lastUpdate = time.time()

        self.phishing_army.load_data(True if not hasattr(self, 'lastUpdate') or (time.time() - self.lastUpdate) > 21600 else False)
        

        # True Per vedere i log di qualsiasi URL,
        # False per i soli URL da analizzare approfonditamente
        self.debug_mode = False

        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        if self.debug_mode:
            self.logger.setLevel(logging.DEBUG)

        self.logger.log(ALERT, "Avvio updaters in corso...")

        pishing_army_updater = UpdaterThread(21600, self.phishing_army)
        pishing_army_updater.start()

        self.logger.log(ALERT, "Updaters avviati")

    def blocca_indirizzo(self, port, indirizzo_target):
        print(f"🔒 Blocco traffico per {indirizzo_target}:{port}...")

        # --- REGOLA 1: BLOCCO ENTRATA (IN) ---
        rule_in = f"HouseGuard_BLOCK_IN_{indirizzo_target}_{port}"
        cmd_in = (
            f'netsh advfirewall firewall add rule '
            f'name="{rule_in}" '
            f'dir=in '           # Entrata
            f'action=block '     # Blocca
            f'protocol=TCP '    
            f'localport={port} '
            f'localip={indirizzo_target}'
        )

        # --- REGOLA 2: BLOCCO USCITA (OUT) ---
        rule_out = f"HouseGuard_BLOCK_OUT_{indirizzo_target}_{port}"
        cmd_out = (
            f'netsh advfirewall firewall add rule '
            f'name="{rule_out}" '
            f'dir=out '          # Uscita
            f'action=block '     # Blocca
            f'protocol=TCP '
            f'localport={port} '
            f'localip={indirizzo_target}'
        )

        try:
            # 1. Pulizia preventiva
            subprocess.run(["ssh", f"{self.user}@{self.ip}", f"netsh advfirewall firewall delete rule name=\"{rule_in}\""], stderr=subprocess.DEVNULL)
            subprocess.run(["ssh", f"{self.user}@{self.ip}", f"netsh advfirewall firewall delete rule name=\"{rule_out}\""], stderr=subprocess.DEVNULL)

            # 2. Applicazione Regole
            print(f"   -> Scrivendo regola INBOUND...")
            subprocess.run(["ssh", f"{self.user}@{self.ip}", cmd_in], check=True)
            
            print(f"   -> Scrivendo regola OUTBOUND...")
            subprocess.run(["ssh", f"{self.user}@{self.ip}", cmd_out], check=True)
            
            print("✅ Blocco attivato con successo.")

        except subprocess.CalledProcessError as e:
            print(f"❌ Errore durante l'applicazione del firewall: {e}")

    def staticAnalysis_score(self, url, is_domain = False, use_virus_total = True) -> float:
        # Sistema a punteggio: se viene superata una certa soglia, allora il link viene considerato sospetto
        scores = {}
        #TODO Analisi di scrittura del link (ancora da implementare)

        # Analisi certificati
        # - WARNING: certificato self-signed o emesso da ente gratuito (punteggio 50)
        # - DANGER: assenza di certificato (punteggio 100) 

        if is_domain:
            scores["certs"] = 0
            try:
                certificate_analysis = self.certificate_control.analyze(url)
            except Exception as e:
                print(f"Errore durante l'analisi del certificato per {url}: {e}")
                certificate_analysis = {"status": "UNKNOWN"}
                scores.pop("certs")

            if certificate_analysis["status"] == "WARNING": 
                print(certificate_analysis)
                print("-" * 30)
                scores["certs"] += 50
            elif certificate_analysis["status"] == "DANGER":
                print(certificate_analysis)
                print("-" * 30)
                scores["certs"] += 100

        # Analisi database scaricabili(PhishingArmy)
        # Blocco istantaneo per ogni presenza rilevata

        if is_domain:
            check_phishing_army = self.phishing_army.check_url(url)
            print("   🎏  Controllo Phishing Army in corso...")
            if check_phishing_army:
                print(f"   🛑 RILEVATO DA PHISHING ARMY!")
                print(f"      Dominio bloccato: {check_phishing_army['domain_matched']}")
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

            print("   ☁️  Controllo VirusTotal in corso...")
            check_virus_total = self.vt_engine.check_url(url)

            if check_virus_total and check_virus_total['detected']:
                print(f"   ☣️  RILEVATO DA VIRUSTOTAL!")
                print(f"      Punteggio: {check_virus_total['malicious_votes']}/{check_virus_total['total_votes']}")
                scores["virustotal"] += check_virus_total["malicious_votes"] / check_virus_total["total_votes"] * 100
            elif check_virus_total:
                print("   ✅ Pulito (VirusTotal).")
            else:
                print("   ⚠️ Errore/Quota VirusTotal.")
                scores.pop("virustotal")
            
            # Pausa obbligatoria per API Free (4 richieste/min)
            #time.sleep(15)
            time.sleep(5)

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
        decision = self.cache.get(url)
        if decision:
            self.logger.log(ALERT, f"[Proxy] decision in cache {decision}")
            if decision == "processing":
                self.logger.debug("[Proxy] Analisi dinamica in corso")
            elif decision == "block":
                self.logger.log(ALERT, "[Proxy] URL bloccato da cache")
            return decision
        #     Se il dominio è presente ed è non fidato, si blocca
        decision = self.cache.get(domain)
        if decision and decision == "block":
            self.logger.log(ALERT, "[Proxy] dominio bloccato da cache")
            return decision
    
        # --- Check su whitelist: se l'url o il dominio è presente,
        #     allora la richiesta può passare tranquillamente
        if self.basic_control.checkWhitelist(domain):
            self.logger.debug("[Proxy] dominio in whitelist")
            return
        if self.basic_control.checkWhitelist(url):
            self.logger.debug("[Proxy] URL in whitelist")
            return

        # --- Check su blacklist: se l'url o il dominio è presente, allora la richiesta viene bloccata
        if self.basic_control.checkBlacklist(domain):
            self.logger.debug("[Proxy] dominio in blacklist")
            return "block"
        if self.basic_control.checkBlacklist(url):
            self.logger.debug("[Proxy] URL in blacklist")
            return "block"

        # --- Effettua analisi statica
        
        domainDecision = self.cache.get(domain)
        if not domainDecision:
            # --- Effettua analisi statica del dominio
            scores = self.staticAnalysis_score(domain, is_domain = True, use_virus_total = deep_analyze)
            domainDecision = self.staticAnalysis_detection(scores)

            self.logger.log(ALERT, f"[Proxy] Analisi statica del dominio completata. Scores: {scores}, decisione: {domainDecision}")

            #    Se il dominio è non fidato si blocca, altrimenti si continua
            if domainDecision == "pass":
                self.cache.set(domain, "pass")
                self.logger.debug("[Proxy] dominio non malevolo messo in cache")
                
            elif domainDecision == "block":
                self.cache.set(domain, "block")
                self.logger.log(ALERT, "[Proxy] dominio bloccato e messo in cache")
                return "block"
        
        # --- Effettua analisi statica dell'URL
        scores = self.staticAnalysis_score(url, is_domain = False, use_virus_total = deep_analyze and not is_root_path)
        decision = self.staticAnalysis_detection(scores, domainDecision)

        self.logger.log(ALERT, f"[Proxy] Analisi statica dell'URL completata. Scores: {scores}, decisione: {decision}")

        if decision == "pass":
            self.cache.set(url, "pass")
            self.logger.debug("[Proxy] URL non malevolo messo in cache")
            return "pass"
        elif decision == "block":
            self.cache.set(url, "block")
            self.logger.log(ALERT, "[Proxy] URL bloccato e messo in cache")
            return "block"
        
        self.logger.debug("[Proxy] URL sospetto, inizio analisi dinamica...")

        # Si arriva qui se l'URL è sospetto
        # Si analizza l'URL solo se corrisponde ad una delle risorse specificate
        if deep_analyze:
            self.cache.set(url, "processing")
            t = threading.Thread(target=dynamic_analysis, args=(url,domain,self.cache))
            t.start()

            return "processing"
        else:
            return "pass"

    # Intercetta la richiesta HTTP
    def response(self, flow: http.HTTPFlow) -> None:
        
        url = flow.request.pretty_url
        domain = flow.request.pretty_host
        path = flow.request.path

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
        
        # --- Verifica se il path è la radice del dominio
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
                self.logger.setLevel(logging.DEBUG)
                self.logger.info(logString)
            else:
                self.logger.setLevel(logging.INFO)
        else:
            self.logger.debug(logString)

        decision = self.process_response(url, domain, is_root_path = isRootPath, deep_analyze=deep_analyze)

        if decision == "processing":
            flow.response = self.buildWaitResponse(url)
        elif decision == "block":
            flow.response = self.buildBlockResponse(url)
            indirizzo = flow.server_conn.peername[0]
            port = flow.server_conn.peername[1]
            #self.blocca_indirizzo(port, indirizzo)
        elif decision == "pass":
            return
        else:
            self.logger.error("[Proxy] Ricevuta decisione inattesa")
        
        
    # --- Analisi dinamica con CAPE
    def dynamic_analysis(self, url, domain, cache):
        decision = "pass"
        score = 0

        time.sleep(5)
        print("   📦 Invio a CAPE Sandbox Locale...")
    
        # 1. Invio
        task_id = cape_engine.submit_url(url)
        
        if task_id:
            print(f"   ✅ URL inviato. Task ID: {task_id}")
            
            # 2. Attesa attiva del risultato
            report = cape_engine.wait_for_report(task_id)
            
            if report:
                # 3. Analisi del Report JSON
                # CAPE assegna un 'malscore' da 0.0 a 10.0
                if report.get("error"):
                    print(f"   ⚠️ Impossibile determinare malignità (Errore CAPE: {report.get('reason')})")
                    print("   ➡️ Considero l'URL sospetto per precauzione (o lo ignoro, a tua scelta).")
                else:
                    
                    malscore = report.get('malscore', 0)
                    
                    print(f"\n   📊 RISULTATO ANALISI DINAMICA:")
                    print(f"      Punteggio Malignità: {malscore}/10.0")
                    
                    # Estrazione firme (comportamenti sospetti)
                    signatures = report.get('signatures', [])
                    if signatures:
                        print("      🚩 Comportamenti sospetti rilevati:")
                        for sig in signatures:
                            # Stampa nome e severità della firma
                            sig_name = sig.get('name')
                            sig_sev = sig.get('severity', 1)
                            print(f"         - [{sig_sev}/5] {sig_name}")
                            decision = "block"
                    else:
                        print("      ✅ Nessun comportamento sospetto rilevato.")
                        decision = "pass"

                # Logica di blocco basata sul punteggio CAPE
                if malscore >= 5.0:
                    print(f"   🛑 BLOCCO: Punteggio CAPE troppo alto!")
                    decision = "block"
                else:
                    print(f"   ✅ URL considerato sicuro da CAPE.")
                    decision = "pass"

            else:
                print("   ⚠️ Impossibile recuperare il report (Timeout o Errore).")

                
        else:
            print("   ❌ Errore nell'invio a CAPE.")

        print("-" * 40)
        
        # Si salva la decisione di CAPE nella cache
        self.logger.log(ALERT, f"[Proxy] Analisi dinamica completata. Score {score}, decisione: {decision}")
        cache.set(url, decision)
        return

addons = [PhishingProxy()]