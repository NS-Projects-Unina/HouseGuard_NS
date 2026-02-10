#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- GESTIONE PERCORSI DINAMICA ---
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."
cd "$PROJECT_ROOT" || exit 1

echo -e "${RED}[*] Arresto dei servizi HouseGuard (WSL)...${NC}"

# 1. Uccidi Mitmproxy
if pkill -f "mitmweb" || pkill -f "mitmdump"; then
    echo -e "${GREEN}[+] Processo Mitmproxy terminato.${NC}"
else
    echo -e "${YELLOW}[!] Nessun processo Mitmproxy trovato.${NC}"
fi

# 2. Ferma i container Docker (trova docker-compose.yml grazie al cd iniziale)
echo -e "${RED}[*] Arresto dei database...${NC}"
docker compose stop redis_db cape-db

echo -e "${GREEN}[+] Servizi WSL arrestati correttamente.${NC}"