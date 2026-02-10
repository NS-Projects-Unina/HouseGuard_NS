#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Trova la cartella dove si trova questo script (scripts/) 
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

PROXY_ADDR="127.0.0.1:8080"

echo -e "${YELLOW}==============================================${NC}"
echo -e "${YELLOW}   AVVIO HOUSEGUARD (WIN + WSL)               ${NC}"
echo -e "${YELLOW}==============================================${NC}"

# 1. Proxy Windows
echo -e "${GREEN}[*] Windows: Attivazione Proxy...${NC}"
powershell.exe -Command "
\$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings';
Set-ItemProperty -Path \$regPath -Name ProxyServer -Value '$PROXY_ADDR';
Set-ItemProperty -Path \$regPath -Name ProxyEnable -Value 1;
Set-ItemProperty -Path \$regPath -Name ProxyOverride -Value 'localhost;127.0.0.1;<local>';
Write-Host '   -> Proxy Windows ATTIVATO' -ForegroundColor Green
"

# 2. Servizi WSL (Chiama lo script fratello nella stessa cartella)
echo -e "${GREEN}[*] WSL: Avvio servizi...${NC}"
"$SCRIPT_DIR/start_protection.sh"