#!/bin/bash

# ==============================================================================
# SCRIPT DI AVVIO HOUSEGUARD (Mitmproxy Nativo + Docker DBs)
# ==============================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- GESTIONE PERCORSI DINAMICA ---
# 1. Trova la cartella dove risiede questo script (es. /.../HouseGuard_NS/scripts)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# 2. Definisci la root del progetto (un livello sopra 'scripts')
PROJECT_ROOT="$SCRIPT_DIR/.."

# 3. Spostiamoci nella root del progetto per eseguire tutto correttamente
cd "$PROJECT_ROOT" || exit 1

echo -e "${YELLOW}[*] Root del progetto impostata a: $(pwd)${NC}"

# --- CONFIGURAZIONE PATH RELATIVA ALLA ROOT ---
SCRIPT_PATH="./modulo/app.py"

echo -e "${YELLOW}[*] Avvio dell'architettura di sicurezza...${NC}"

# Verifica script Python
if [ ! -f "$SCRIPT_PATH" ]; then
    echo -e "${RED}[!] Errore CRITICO: Non trovo il file $SCRIPT_PATH ${NC}"
    exit 1
fi

# Variabili d'Ambiente
export VIRUSTOTAL_API_KEY="LA_TUA_CHIAVE"
export REDIS_HOST="127.0.0.1"
export REDIS_PORT="6379"
export CAPE_API_URL="http://127.0.0.1:8000/apiv2/"
export CAPE_API_TOKEN="IL_TUO_TOKEN"

# Avvio Database (Docker) - Ora trova il docker-compose.yml perché siamo nella root
echo -e "${YELLOW}[*] Verifica dei container database...${NC}"
docker compose up -d --remove-orphans redis_db cape-db

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Fallito l'avvio dei container database.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Database attivi.${NC}"

#Avvio Mitmproxy (DA VENV)
echo -e "${YELLOW}[*] Avvio di Mitmproxy (venv) con modulo $SCRIPT_PATH...${NC}"

# Attiviamo il venv prima di lanciare il comando
source "$PROJECT_ROOT/venv/bin/activate"

# Ora 'mitmweb' userà quello installato nel venv, che vede il modulo 'redis'
mitmweb \
    -s "$SCRIPT_PATH" \
    --listen-host 0.0.0.0 \
    --listen-port 8080 \
    --web-host 0.0.0.0 \
    --web-port 8081 \
    --set connection_strategy=lazy \
    --set ssl_verify_upstream_cert=false \
    --set block_global=false