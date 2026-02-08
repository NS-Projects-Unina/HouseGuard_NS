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

from updater import DAO


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


    def checkList(self, link, type):
        with open(f"{type}.txt", 'r') as f:
            list = [line.strip() for line in f]
        if link in list:
            return True
        else:
            return False
        
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
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {"error": "Nessun certificato trovato o validazione fallita"}

                    def get_value(field_list, key_name):
                        for item in field_list:
                            for sub_item in item:
                                if sub_item[0] == key_name:
                                    return sub_item[1]
                        return None

                    issuer_org = get_value(cert.get('issuer', []), 'organizationName')
                    issuer_cn = get_value(cert.get('issuer', []), 'commonName')
                    subject_cn = get_value(cert.get('subject', []), 'commonName')

                    print(f"--- Analisi per {hostname} ---")
                    print(f"Emittente (Issuer): {issuer_org} ({issuer_cn})")

                    is_self_signed = (issuer_cn == subject_cn) and (issuer_org == get_value(cert.get('subject', []), 'organizationName'))

                    if is_self_signed:
                        return {"status": "WARNING", "reason": "Certificato Self-Signed (Autofirmato)"}

                    if issuer_org:
                        for free_ca in self.free_cas:
                            if free_ca.lower() in issuer_org.lower():
                                return {"status": "WARNING", "reason": f"Certificato emesso da ente gratuito: {issuer_org}"}

                    return {"status": "OK", "reason": "Certificato standard/a pagamento", "issuer": issuer_org}

        except ssl.SSLCertVerificationError as e:
            return {"status": "DANGER", "reason": f"Verifica SSL fallita (probabile Self-Signed non trustato): {e.verify_message}"}
        except Exception as e:
            return {"status": "ERROR", "reason": str(e)}


class PhishTankControl:
    def __init__(self, db_folder='.'):
        self.PT_URL = 'http://data.phishtank.com/data/online-valid.json.gz'
        self.GZ_FILE = os.path.join(db_folder, 'phishtank.json.gz')
        self.JSON_FILE = os.path.join(db_folder, 'phishtank.json')

        self.database = DAO("REDIS_DB_BLACKLIST")

        # Header anti-blocco 403
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def _download_and_extract(self):
        print("🔄 [PhishTank] Scaricamento aggiornamenti...")
        try:
            response = requests.get(self.PT_URL, headers=self.headers, stream=True)
            if response.status_code == 200:
                with open(self.GZ_FILE, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                print("📦 [PhishTank] Decompressione database...")
                with gzip.open(self.GZ_FILE, 'rb') as f_in:
                    with open(self.JSON_FILE, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                print("✅ [PhishTank] Aggiornamento completato.")
                return True
            else:
                print(f"❌ [PhishTank] Errore download: Status {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ [PhishTank] Errore critico: {e}")
            return False

    def load_data(self, force_update=False):
        if force_update or not os.path.exists(self.JSON_FILE):
            success = self._download_and_extract()
            if not success and not os.path.exists(self.JSON_FILE):
                return

        print("📂 [PhishTank] Caricamento dati in memoria...")
        try:
            with open(self.JSON_FILE, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            
            database = {
                entry['url']: entry['target']
                for entry in raw_data
                if entry.get('verified') == 'yes' 
            }

            self.database.load_data(database)

            print(f"🔹 [PhishTank] {len(database)} URL caricati.")
        except Exception as e:
            print(f"❌ [PhishTank] Errore lettura JSON: {e}")

    def check_url(self, url):
        if self.database.is_empty():
            print("⚠️ [PhishTank] DB vuoto. Esegui load_data() prima.")
            return None
        conn = self.database.get_db_connection()

        target = conn.get(url)
        if target:
            return {
                'detected': True,
                'source': 'PhishTank',
                'target': target,
                'verified': True 
            }
        return None


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

    def _url_to_id(self, url):
        try:
            return base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').strip("=")
        except Exception:
            return None

    def check_url(self, url):
        url_id = self._url_to_id(url)
        if not url_id: return None

        try:
            response = requests.get(f"{self.base_url}/urls/{url_id}", headers=self.headers)
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
                print("⚠️ [VirusTotal] Quota API superata.")
        except Exception as e:
            print(f"❌ [VirusTotal] Errore: {e}")
        return None

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





