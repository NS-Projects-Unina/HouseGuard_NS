import requests
import base64
import time
import json
import gzip
import shutil
import os
from urllib.parse import urlparse
import ssl
import socket
import re
import idna
import unicodedata
import logging
import textdistance
from collections import defaultdict
from functools import lru_cache


from updater import DAO

# --- LOGGING OVERRIDE ---
# Redirige tutte le chiamate a print() di questo modulo sul file di log 'mitmproxy_Prints.log'
# configurato in app.py. Questo permette di mantenere pulita la console.
def print(*args, **kwargs):
    # Ignora parametri speciali come 'end' o 'file' per forzare la scrittura nel log riga per riga
    msg = " ".join(map(str, args))
    logging.getLogger("Prints").info(msg)


# Funzioni di utilità condivise 
def get_clean_domain(url):
    """
    Estrae il dominio da un URL. Utile per Phishing Army.
    """
    if not url: return ""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        return urlparse(url).netloc.split(':')[0]
    except Exception:
        return ""

class BasicControl:

    def checkList(self, link, type_list): # Ho rinominato 'type' in 'type_list' per evitare conflitti con la keyword python
        # CALCOLO DEL PERCORSO ASSOLUTO
        # Trova la cartella dove si trova QUESTO file (staticLinkModule.py)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Unisce il percorso base con il nome del file (es. whitelist.txt)
        file_path = os.path.join(base_dir, f"{type_list}.txt")

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if link in line.strip(): 
                        return True
            return False
        except FileNotFoundError:
            # Opzionale: stampa un errore nei log di mitmproxy se il file manca
            print(f"ERRORE: File non trovato: {file_path}")
            return False
    
    def getList(self, type_list) -> list[str] | None:
        """
        Legge la lista con filename indicato e la restituisce come lista Python 
        """

        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        file_path = os.path.join(base_dir, f"{type_list}.txt")

        chosen_list = []
        
        print(f"📂 [Basic Control] Caricamento URLs {type_list} in memoria...")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                chosen_list = [
                    line.strip()
                    for line in f 
                    if line.strip() and not line.startswith('#')
                ]

            print(f"🔹 [Basic Control] {len(chosen_list)} URLs caricati da {type_list}.")

        except FileNotFoundError:
            print(f"❌ [Basic Control] File {type_list} non trovato: {file_path}")
            return None

        return chosen_list 
        
    def checkBlacklist(self, link):
        return self.checkList(link,'blacklist')
    def checkWhitelist(self, link):
        return self.checkList(link, 'whitelist')

class CertificateControl:
    def __init__(self):
        # Lista di CA note per offrire certificati gratuiti
        # Nota: Questa lista va mantenuta aggiornata.
        self.free_cas = [
            "Let's Encrypt",
            "ZeroSSL",
            "Cloudflare",
            "cPanel",
            "GoGetSSL",
            "Buypass"
        ]

    def analyze(self, hostname, port=443):
            # Timeout molto breve: se il server non risponde in 2 secondi, lasciamo perdere.
            timeout_seconds = 2 
            
            # Creiamo un contesto SSL che non verifica rigorosamente (per evitare errori interni)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                # Tenta la connessione con timeout stretto
                with socket.create_connection((hostname, port), timeout=timeout_seconds) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # Tenta di recuperare il certificato
                        cert = ssock.getpeercert(binary_form=True)
                        if not cert:
                            return {"status": "UNKNOWN", "reason": "Certificato vuoto o illeggibile"}
                        
                        # Se siamo qui, il server ha risposto. 
                        # Per ora, dato che stiamo usando CERT_NONE per velocità e stabilità,
                        # ritorniamo OK se c'è una risposta, oppure implementiamo logica complessa di parsing x509.
                        
                        # Per evitare blocchi, assumiamo che se risponde TLS è OK per l'analisi statica di base
                        return {"status": "OK", "reason": "Handshake TLS riuscito", "issuer": "Unknown (Fast Check)"}

            except socket.timeout:
                print(f"⚠️ Timeout analisi certificato per {hostname} (saltato)")
                return {"status": "UNKNOWN", "reason": "Timeout connessione"}
            except Exception as e:
                # Qualsiasi altro errore (es. connessione rifiutata) non deve bloccare la navigazione
                print(f"⚠️ Errore rapido certificato {hostname}: {e}")
                return {"status": "UNKNOWN", "reason": str(e)}

            except ssl.SSLCertVerificationError as e:
                # Se fallisce la verifica, non è detto che sia un attacco, potrebbe mancare la root CA locale.
                # Lo classifichiamo come WARNING invece di errore fatale.
                return {"status": "DANGER", "reason": f"Verifica SSL fallita (possibile self-signed o root mancante): {e}"}
            except Exception as e:
                return {"status": "ERROR", "reason": str(e)}

class PhishingArmyControl:
    def __init__(self, db_folder='.'):
        self.PA_URL = 'https://phishing.army/download/phishing_army_blocklist_extended.txt'
        self.DB_FILE = os.path.join(db_folder, 'phishing_army.txt')

        self.blocked_domains = DAO("REDIS_DB_BLACKLIST")

    def _download_db(self):
        print("🔄 [Phishing Army] Scaricamento aggiornamenti...")
        try:
            response = requests.get(self.PA_URL, stream=True)
            if response.status_code == 200:
                with open(self.DB_FILE, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                print("✅ [Phishing Army] Lista aggiornata.")
                return True
            else:
                print(f"❌ [Phishing Army] Errore download: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ [Phishing Army] Errore connessione: {e}")
            return False

    def load_data(self, force_update=False):
        blocked_domains = {}

        if force_update or not os.path.exists(self.DB_FILE):
            success = self._download_db()
            if not success and not os.path.exists(self.DB_FILE):
                return

        print("📂 [Phishing Army] Caricamento domini in memoria...")
        try:
            with open(self.DB_FILE, 'r', encoding='utf-8') as f:
                blocked_domains = {
                    line.strip() : "block"
                    for line in f 
                    if line.strip() and not line.startswith('#')
                }

            self.blocked_domains.load_data(blocked_domains)

            print(f"🔹 [Phishing Army] {len(blocked_domains)} domini caricati.")
        except Exception as e:
            print(f"❌ [Phishing Army] Errore lettura file: {e}")

    def check_url(self, url):
        if self.blocked_domains.is_empty():
            print("⚠️ [Phishing Army] DB vuoto. Esegui load_data() prima.")
            return None

        conn = self.blocked_domains.get_db_connection()
        
        target_domain = get_clean_domain(url)
        print(f"[Phishing Army] Analisi di {target_domain} in corso...")
        if conn.get(target_domain):
            conn.close()
            return {
                'detected': True,
                'source': 'Phishing Army',
                'domain_matched': target_domain,
                'details': 'Domain listed in Blocklist Extended'
            }
        return None


class VirusTotalControl:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
        
        # Gestione Quota (4 richieste/minuto, 500 richieste/giorno)
        self.request_count = 0
        self.last_reset_time = time.time()
        self.QUOTA_LIMIT = 4
        self.QUOTA_WINDOW = 60 # secondi
        
        # Quota giornaliera
        self.daily_count = 0
        self.daily_reset_time = time.time()
        self.DAILY_LIMIT = 500
        self.DAILY_WINDOW = 86400 # 24 ore

    def _url_to_id(self, url):
        try:
            return base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').strip("=")
        except Exception:
            return None

    def check_url(self, url):
        current_time = time.time()
        
        # 1. Controllo Reset Finestra Minuto
        if (current_time - self.last_reset_time) > self.QUOTA_WINDOW:
            self.request_count = 0
            self.last_reset_time = current_time
            
        # 2. Controllo Reset Finestra Giornaliera
        if (current_time - self.daily_reset_time) > self.DAILY_WINDOW:
            self.daily_count = 0
            self.daily_reset_time = current_time

        # 3. Controllo Limiti
        if self.daily_count >= self.DAILY_LIMIT:
             return {'error': True, 'quota_exceeded': True, 'message': 'Quota Giornaliera VirusTotal Esaurita (500 req/day). Controllo saltato.'}
        
        if self.request_count >= self.QUOTA_LIMIT:
            return {'error': True, 'quota_exceeded': True, 'message': 'Quota Minuto API superata (4 req/min). Controllo saltato.'}

        # 4. Incremento contatori (solo se procediamo)
        self.request_count += 1
        self.daily_count += 1

        url_id = self._url_to_id(url)
        if not url_id: return None

        try:
            # Bypass SSL verify per evitare errori "unable to get local issuer certificate"
            requests.packages.urllib3.disable_warnings() 
            response = requests.get(f"{self.base_url}/urls/{url_id}", headers=self.headers, verify=False)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                return {
                    'detected': (malicious + suspicious) > 0,
                    'source': 'VirusTotal',
                    'malicious_votes': malicious,
                    'suspicious_votes': suspicious,
                    'total_votes': sum(stats.values())
                }
            elif response.status_code == 404:
                return {'detected': False, 'source': 'VirusTotal', 'status': 'Unknown/New'}
            elif response.status_code == 429:
                return {'error': True, 'message': 'Quota API superata (429)'}
            else:
                return {'error': True, 'message': f'Status {response.status_code}: {response.text[:100]}'}
        except Exception as e:
            return {'error': True, 'message': f'Eccezione: {str(e)}'}
        return {'error': True, 'message': 'Nessun dato ritornato'}

class CapeControl:
    def __init__(self, api_url, api_token=None):
        self.api_url = api_url.rstrip('/')
        self.headers = {}
        if api_token:
            self.headers['Authorization'] = f"Token {api_token}"

    def submit_url(self, url):
            """Invia URL e ritorna il Task ID gestendo la lista 'task_ids'"""
            # Nota: Ho aggiunto 'timeout' per evitare blocchi infiniti se la rete cade
            endpoint = f"{self.api_url}/apiv2/tasks/create/url/"
            data = {'url': url, 'tags': 'win10'} 
            
            try:
                # Aggiungiamo un timeout di 10 secondi alla richiesta di invio
                response = requests.post(endpoint, data=data, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # --- LOGICA DI ESTRAZIONE AGGIORNATA ---
                    
                    # Caso 1: La struttura che hai ricevuto tu (data -> task_ids -> [24])
                    data_obj = result.get('data')
                    if isinstance(data_obj, dict):
                        task_ids = data_obj.get('task_ids')
                        if isinstance(task_ids, list) and len(task_ids) > 0:
                            return task_ids[0] # Prende il primo ID (es. 24)
                    
                    # Caso 2: Fallback (se cambia versione o formato)
                    task_id = result.get('task_id')
                    if task_id: return task_id

                    # Se arriviamo qui, stampiamo il debug per capire cosa manca
                    print(f"      ⚠️ Risposta CAPE non riconosciuta: {result}")
                    return None
                    
                else:
                    print(f"      ❌ Errore HTTP CAPE: {response.status_code}")
                    return None

            except Exception as e:
                print(f"      ❌ Eccezione connessione: {e}")
                return None

    def _get_status(self, task_id):
        """Controlla lo stato attuale del task"""
        endpoint = f"{self.api_url}/apiv2/tasks/view/{task_id}/"
        try:
            response = requests.get(endpoint, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                # Lo stato è solitamente in data['status']
                return data.get('data', {}).get('status')
        except:
            pass
        return None

    def wait_for_report(self, task_id, timeout=300):
            """Attende che l'analisi sia completa e scarica il report."""
            print(f"      ⏳ In attesa del report CAPE (Max {timeout}s)...")
            start_time = time.time()
            
            while (time.time() - start_time) < timeout:
                try:
                    # Chiediamo lo stato all'API
                    status_resp = requests.get(f"{self.api_url}/apiv2/tasks/view/{task_id}/", headers=self.headers)
                    if status_resp.status_code == 200:
                        data = status_resp.json().get("data", {})
                        status = data.get("status")
                        
                        # Feedback visivo (sovrascrive la riga precedente per pulizia)
                        print(f"      ... stato attuale: {status}", end="\r")
                        
                        # CASO 1: Successo
                        if status == "reported":
                            print("\n      📝 Analisi completata! Scaricamento report...")
                            return self._fetch_report(task_id)
                        
                        # CASO 2: Fallimenti noti
                        elif status in ["failed_analysis", "failed_processing", "failed_reporting"]:
                            print(f"\n      ❌ Errore Critico CAPE: Stato '{status}'.")
                            # Possiamo restituire un oggetto "finto" per non rompere il flusso
                            return {"malscore": 0.0, "error": True, "reason": status}
                        
                        # CASO 3: Ancora in corso
                        elif status in ["pending", "running", "completed", "starting"]:
                            time.sleep(5)
                            continue
                            
                        else:
                            print(f"\n      ⚠️ Stato sconosciuto: {status}")
                            
                except Exception as e:
                    print(f"\n      ❌ Errore connessione polling: {e}")
                    time.sleep(5)
                    
                time.sleep(2)
                
            print("\n      ⏰ Timeout attesa report scaduto.")
            return None

    def _fetch_report(self, task_id):
            """
            Scarica il report JSON finale usando l'API.
            """
            # Endpoint per scaricare il report in formato JSON
            endpoint = f"{self.api_url}/apiv2/tasks/get/report/{task_id}/json/"
            
            try:
                print(f"      📥 Richiesta report a: {endpoint}")
                response = requests.get(endpoint, headers=self.headers)
                
                if response.status_code == 200:
                    print("      ✅ Report scaricato con successo!")
                    return response.json()
                elif response.status_code == 404:
                    print("      ⚠️ Report non trovato (404). Forse il Guardian non ha ancora finito?")
                    return None
                else:
                    print(f"      ❌ Errore API Report ({response.status_code}): {response.text[:100]}")
                    return None
            except Exception as e:
                print(f"      ❌ Errore connessione durante download report: {e}")
            return None

class ForeignCharDetector:
    def __init__(self):
        # Whitelist caratteri sicuri (Latino base + numeri)
        # NOTA: Togliamo . e - dalla whitelist per gestirli separatamente nel conteggio
        self.safe_letters = set("abcdefghijklmnopqrstuvwxyz0123456789")
        self.ignored_symbols = set(".-") # Simboli strutturali da ignorare nel calcolo %

    def analyze_domain(self, domain):
        """
        Ritorna un punteggio da 0.0 a 100.0.
        Ignora punti e trattini per calcolare la percentuale pura sulle LETTERE.
        """
        foreign_count = 0
        valid_char_count = 0 # Conta solo lettere e numeri, ignora simboli
        decoded_domain = domain

        # 1. DECODIFICA PUNYCODE
        try:
            if "xn--" in domain:
                decoded_domain = idna.decode(domain)
        except idna.IDNAError:
            return 100.0 # Errore critico = Massimo rischio

        # Gestione stringa vuota
        if not decoded_domain: return 0.0

        # 2. ANALISI
        for char in decoded_domain.lower():
            
            # Se è un simbolo strutturale (. o -), lo ignoriamo dal calcolo statistico
            if char in self.ignored_symbols:
                continue
            
            # Se è una lettera/numero valido, incrementiamo il denominatore
            valid_char_count += 1

            # Se NON è nella whitelist delle lettere sicure, è straniero
            if char not in self.safe_letters:
                foreign_count += 1

        # 3. CALCOLO SCORE (Protezione divisione per zero)
        if valid_char_count == 0:
            return 0.0

        score = (foreign_count / valid_char_count) * 100.0
        return round(score, 2)

class TypoDetector:
    def __init__(self, whitelist_name):

        self.whitelist_name = whitelist_name

        self.load_data()
    
        # Mappa Leet Speak (Numeri -> Lettere)
        self.leet_map = str.maketrans({
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
            '6': 'b', '7': 't', '8': 'b', '$': 's', '@': 'a'
        })
        
        # Soglia minima per considerare qualcosa un "Typo" (Jaro-Winkler)
        self.min_similarity_threshold = 0.85

    def _extract_core(self, domain):
        #Estrae la parte centrale del dominio
        clean = domain.replace("www.", "").lower()
        if "." in clean:
            return clean.split(".")[0] 
        return clean
    
    def load_data(self, **_kwargs):
        whitelist_urls = BasicControl().getList(self.whitelist_name)

        # 1. SET per lookup istantaneo
        whitelist_domains = set()
        for url in whitelist_urls:
            domain = get_clean_domain(url)
            if domain not in whitelist_domains:
                whitelist_domains.add(domain)

        self.whitelist_set = whitelist_domains
        
        # 2. INDICE PER LUNGHEZZA per Typo Check
        self.len_index = defaultdict(list)
        
        # 3. SET DEI CORE per Combo Check
        self.whitelist_cores = set()

        # PRE-PROCESSING
        for domain in whitelist_domains:
            core = self._extract_core(get_clean_domain(domain))
            
            # Salviamo il core per i controlli successivi
            if len(core) > 2: # Ignoriamo domini cortissimi
                self.len_index[len(core)].append(core)
                self.whitelist_cores.add(core)
        

    # 4. CACHE MEMORY
    # Memorizza gli ultimi 2048 risultati. 
    @lru_cache(maxsize=2048)
    def get_typo_score(self, visited_domain):
        """
        Restituisce una tupla: (Score, Target_Imitato).
        Score: 0.0 (Sicuro) -> 100.0 (Pericolo).
        Target_Imitato: Nome del sito copiato (o None).
        """
        
        # A. Controllo Esatto
        if visited_domain in self.whitelist_set:
            return 0.0, None

        visited_core = self._extract_core(visited_domain)
        
        # B. Controllo Core Esatto
        if visited_core in self.whitelist_cores:
            return 0.0, None

        v_len = len(visited_core)

        # C. CONTROLLO COMBO-SQUATTING
        # Verifica se un marchio è contenuto interamente nel dominio visitato.
        if v_len > 4: # Evitiamo falsi positivi su stringhe corte
            for target_core in self.whitelist_cores:
                # Ignoriamo target troppo corti per evitare falsi allarmi
                if len(target_core) < 4: 
                    continue
                
                
                if target_core in visited_core:
                    # Rischio massimo: stanno usando il nome esatto del brand
                    return 100.0, target_core

        # D. CONTROLLO TYPOSQUATTING (Distanza Jaro-Winkler)
        
        # 1. Selezione Candidati (Length Pruning a +/- 2)
        candidates = []
        min_len = max(1, v_len - 2)
        max_len = v_len + 2
        
        for length in range(min_len, max_len + 1):
            if length in self.len_index:
                candidates.extend(self.len_index[length])
        
        if not candidates:
            return 0.0, None

        # 2. Normalizzazione Leet Speak
        visited_norm = visited_core.translate(self.leet_map)

        # 3. Calcolo Distanza
        max_similarity = 0.0
        best_target_match = None

        for target_core in candidates:
            score = textdistance.jaro_winkler(visited_norm, target_core)
            
            if score > max_similarity:
                max_similarity = score
                best_target_match = target_core
                
                # Exit Early: Se è quasi identico, inutile continuare
                if max_similarity > 0.98:
                    break

        # 4. Calcolo Finale Score
        if max_similarity < self.min_similarity_threshold:
            return 0.0, None
        
        return round(max_similarity * 100, 2), best_target_match

