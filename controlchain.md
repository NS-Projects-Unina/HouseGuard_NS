# Catena di Controllo URL: HouseGuard_NS

Questo documento descrive il flusso decisionale utilizzato da **HouseGuard_NS** per analizzare e filtrare le richieste HTTP intercettate.

```ascii
                                    (Richiesta HTTP Intercettata)
                                              |
                                              v
+-----------------------------------------------------------------------------------------+
|                                  1. LISTE DI CONTROLLO                                  |
|  (File Locali)                                                                          |
|                                                                                         |
|  [Whitelist?] -------(Si)--------> [Decisione: PASS] ---------------------------------->| (Fine)
|        |                                                                                |
|       (No)                                                                              |
|        v                                                                                |
|  [Blacklist?] -------(Si)--------> [Decisione: BLOCK] --------------------------------->| (Fine)
+--------+--------------------------------------------------------------------------------+
         |
         v
+-----------------------------------------------------------------------------------------+
|                                    2. CONTROLLO CACHE                                   |
|  (Redis)                                                                                |
|                                                                                         |
|  [URL in Cache?] ----(Si)----> [Decisione: PASS / BLOCK / PROCESSING] ----------------->| (Fine)
|        |                                                                                |
|       (No)                                                                              |
|        v                                                                                |
|  [Dominio in Cache?] --(Si & Block)--> [Decisione: BLOCK] ----------------------------->| (Fine)
|        |                                                                                |
|       (No/Pass)                                                                         |
+--------+--------------------------------------------------------------------------------+
         |
         v
+-----------------------------------------------------------------------------------------+
|                            3. ANALISI STATICA (Punteggio)                               |
|                                                                                         |
|  A. Analisi DOMINIO:                                                                    |
|     1. Gestione Certificati (Self-signed? Free CA? Assente?)                            |
|     2. Phishing Army (Database locale) --> Se Trovato: BLOCK Immediato                  |
|     3. Typosquatting (Distanza da domini legittimi white-listed)                        |
|     4. Caratteri Stranieri (Omografi)                                                   |
|                                                                                         |
|     [Decisione Dominio] --(BLOCK)--> [Cache Dominio: BLOCK] --------------------------->| (Block)
|            |                                                                            |
|          (Pass)                                                                         |
|            v                                                                            |
|  B. Analisi URL Completo:                                                               |
|     1. VirusTotal API (Se DeepAnalyze=True)                                             |
|        [ Check Quota: 4/min, 500/day ]                                                  |
|        - Se Quota OK: Richiesta API                                                     |
|        - Se Quota KO: Skip (Warning)                                                    |
|                                                                                         |
|  [Calcolo Punteggio Totale (Certs + Typo + Foreign + VT)]                               |
|            |                                                                            |
|            +---> Punteggio Alto? ---------> [Decisione: BLOCK] ------------------------>| (Block)
|            |                                                                            |
|            +---> Punteggio Basso? --------> [Decisione: PASS] ------------------------->| (Pass)
|            |                                                                            |
|            v                                                                            |
|     (Punteggio Medio / "Suspect")                                                       |
+--------+--------------------------------------------------------------------------------+
         |
         v
+-----------------------------------------------------------------------------------------+
|                              4. ANALISI DINAMICA (Sandbox)                              |
|                                                                                         |
|  [Deep Analyze Richiesto?] --(No)--> [Decisione: PASS (Low Confidence)] --------------->| (Pass)
|            |                                                                            |
|           (Si)                                                                          |
|            v                                                                            |
|  [Invio a CAPE Sandbox]                                                                 |
|            |                                                                            |
|  [Stato: PROCESSING] ------------------------------------------------------------------>| (Wait Page)
|            |                                                                            |
|      (Thread Separato)                                                                  |
|            v                                                                            |
|      [Attesa Report CAPE]                                                               |
|            |                                                                            |
|      [Malscore > 5.0?] --(Si)--> [Update Cache: BLOCK] ----> [Firewall Windows BLOCK]   |
|            |                                                                            |
|           (No)                                                                          |
|            +-----------> [Update Cache: PASS]                                           |
+-----------------------------------------------------------------------------------------+
```
