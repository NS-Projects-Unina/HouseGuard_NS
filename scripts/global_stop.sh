#!/bin/bash

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo -e "${YELLOW}==============================================${NC}"
echo -e "${YELLOW}   ARRESTO HOUSEGUARD (WIN + WSL)             ${NC}"
echo -e "${YELLOW}==============================================${NC}"

# 1. Ferma WSL
"$SCRIPT_DIR/stop_protection.sh"

# 2. Disattiva Proxy Windows
echo -e "${YELLOW}[*] Windows: Disattivazione Proxy...${NC}"
powershell.exe -Command "
\$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings';
Set-ItemProperty -Path \$regPath -Name ProxyEnable -Value 0;
Write-Host '   -> Proxy Windows DISATTIVATO' -ForegroundColor Red
"