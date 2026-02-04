from mitmproxy import http
import requests
import threading
from staticLinkModule import BasicControl,  CertificateControl, VirusTotalControl, PhishingArmyControl, PhishTankControl
import os
import sys
import time
from dotenv import load_dotenv
from enum import Enum

# Configs
#blacklist_url = "https://phishing.army/download/phishing_army_blocklist.txt"
#listFolder = "lists"

class PhishingValue(Enum):
    TRUSTED = 1
    SUSPECT = 2
    PHISHING = 3

class PhishingProxy:

    blockResponse = http.Response.make(
            403,
            b"URL bloccato",  # content
            {"Content-Type": "text/html"},  # headers
        )
    
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
                <p>Target: {url}</p>
            </body>
        </html>
        """

        waitResponse = http.Response.make(
                200,
                html_waiting_content,  # content
                {"Content-Type": "text/html"},  # headers
            )
        
        return waitResponse
    '''
    def getListFromURL(self, list_url, listName):
        """
        Carica lista da URL fornito e la salva in locale
        """

        with requests.get(list_url, stream = True) as response:
            response.raise_for_status()

            with open(listFolder + f"/{listName}.txt", 'w', encoding='utf-8') as f:
                for line in response.iter_lines(decode_unicode=True):
                    if line:
                        if not line.startswith('#'):
                            f.write(line + '\n')
    '''

    # TODO uso periodico di funzione di cui sopra per aggiornare una lista

    '''Implementato in StaticLinkModule
    def isInList(self, listName, domain) -> bool:
        """
        Verifica se un dominio è presente in una lista locale
        """
        found = False
        with open(listFolder + f"/{listName}.txt", "r") as listf:
            lines = listf.readlines()
            for row in lines:
                if row.find(domain) != -1:
                    found = True
                    return found
            return found
    '''
            
    def load(self, loader):
        load_dotenv()
        # formato del tipo {"posteitaliane.it : "pass", "postltaliane.it" : "block"}
        self.cache = {}
        self.processing_analysis = set()

        # Inizializzazioni delle classi di controllo statico come attributi di istanza
        self.basic_control = BasicControl()
        self.certificate_control = CertificateControl()
        self.phishing_army = PhishingArmyControl()
        self.phish_tank = PhishTankControl()
        self.vt_engine = VirusTotalControl(os.getenv("VIRUSTOTAL_API_KEY"))

        self.lastUpdate = time.time()

        self.phishing_army.load_data(True if not hasattr(self, 'lastUpdate') or (time.time() - self.lastUpdate) > 21600 else False)
        self.phish_tank.load_data(True if not hasattr(self, 'lastUpdate') or (time.time() - self.lastUpdate) > 3600 else False)

        # checkBlacklist(blacklist_url)
    
    def addEntryInCache(self, link, action):
        self.cache.append('link: ') + link + (', action: ')+ action

    def staticAnalysis_score(self, url) -> float:
        # Sistema a punteggio: se viene superata una certa soglia, allora il link viene considerato sospetto
        score = 0
        #TODO Analisi di scrittura del link (ancora da implementare)

        # Analisi certificati
        # - WARNING: certificato self-signed o emesso da ente gratuito (punteggio 50)
        # - DANGER: assenza di certificato (punteggio 100) 
        try:
            certificate_analysis = self.certificate_control.analyze(url)
        except Exception as e:
            print(f"Errore durante l'analisi del certificato per {url}: {e}")
            certificate_analysis = {"status": "UNKNOWN"}

        # --------------- COMMENTO - TODO
        # --------------- è da modificare il controllo dei certificati
        # --------------- consiglio di mettere WARNING per free-tier e DANGER per self-signed

        if certificate_analysis["status"] == "WARNING": 
            print(certificate_analysis)
            print("-" * 30)
            score += 50
        elif certificate_analysis["status"] == "DANGER":
            print(certificate_analysis)
            print("-" * 30)
            score += 100

        # Analisi database scaricabili(PhishingArmy, PhishTank implementati al momento)
        # 100 punti per ogni presenza rilevata

        check_phishing_army = self.phishing_army.check_url(url)
        print("   🎏  Controllo Phishing Army in corso...")
        if check_phishing_army:
            print(f"   🛑 RILEVATO DA PHISHING ARMY!")
            print(f"      Dominio bloccato: {check_phishing_army['domain_matched']}")
            return float('inf')

        print("   🐟  Controllo PhishTank in corso...")
        check_phish_tank = self.phish_tank.check_url(url)
        if check_phish_tank:
            print(f"   🛑 RILEVATO DA PHISHTANK!")
            print(f"      Target imitato: {check_phish_tank['target']}")
            return float('inf')
        
        # Analisi effettuata da VirusTotal
        # VirusTotal effettua un rapporto tra voti maliziosi e voti totali
        # il punteggio è la normalizzazione dei voti maliziosi rispetto a
        # quelli totali in scala da 0 a 100

        print("   ☁️  Controllo VirusTotal in corso...")
        check_virus_total = self.vt_engine.check_url(url)
        
        if check_virus_total and check_virus_total['detected']:
            print(f"   ☣️  RILEVATO DA VIRUSTOTAL!")
            print(f"      Punteggio: {check_virus_total['malicious_votes']}/{check_virus_total['total_votes']}")
            score += check_virus_total["malicious_votes"] / check_virus_total["total_votes"] * 100
        elif check_virus_total:
            print("   ✅ Pulito (VirusTotal).")
        else:
            print("   ⚠️ Errore/Quota VirusTotal.")
            
        # Pausa obbligatoria per API Free (4 richieste/min)
        time.sleep(15)

        return score

    # - minore di una soglia di minimo -> lascio passare
    # - compreso tra una soglia e l'altra -> lascio decidere a cape
    # - supera una soglia di massimo -> blocco a prescindere, e viene aggiunto in cache
    def staticAnalysis_detection(self, score) -> PhishingValue:
        ## DECISIONE SU SOGLIE

        decision = PhishingValue.SUSPECT

        if score > 50:
            decision = PhishingValue.PHISHING
        elif score <= 5:
            decision = PhishingValue.TRUSTED
        
        return decision

    # Intercetta la richiesta HTTP
    def request(self, flow: http.HTTPFlow) -> None:
        
        url = flow.request.pretty_url

        # --- Check su whitelist: se l'url è presente, allora la richiesta può passare tranquillamente
        if self.basic_control.checkWhitelist(url):
            return

        # --- Check su blacklist: se l'url è presente, allora la richiesta viene bloccata
        if self.basic_control.checkBlacklist(url):
            flow.response = blockResponse
            return
        # --- Check su cache: se l'url è presente, allora la richiesta viene bloccata
        if url in self.cache:
            if self.cache[url] == "block":
                flow.response = blockResponse
            return
        
        # --- Effettua analisi statica del link
        score = self.staticAnalysis_score(url)
        decision = self.staticAnalysis_detection(score)

        if decision == PhishingValue.TRUSTED:
            return
        elif decision == PhishingValue.PHISING:
            flow.response = blockResponse
            return

        if url in processing_analysis:
            waitResponse = buildWaitResponse(url)
            flow.response = waitResponse
            return

        domain = flow.request.host
        
        # Si arriva qui se l'URL è solo sospetto oppure se c'é un errore
        flow.response = buildWaitResponse(url)
        processing_analysis.add(url)
        t = threading.Thread(target=dynamic_analysis, args=(url,domain))
        t.start()
        
    # --- Analisi dinamica con CAPE
    def dynamic_analysis(self, url, domain):

        # TODO ... uso API di cape per l'analisi ...

        # Si salva la decisione di CAPE nella cache
        self.cache[url] = decision
        # Si attua la decisione di CAPE
        if decision == "block":
            flow.response = blockResponse
        
        processing_analysis.remove(url)
        return

addons = [PhishingProxy()]