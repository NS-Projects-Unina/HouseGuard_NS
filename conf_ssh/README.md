Installare il server OpenSSH eseguendo il .msi

All'avvio della macchina avviare il server da PowerShell come amministratore:
Start-Service sshd

Sostituire il file sshd_config in C:\ProgramData\ssh\ con quello presente in questa cartella

Su WSL generare una coppia di chiavi:
ssh-keygen -t rsa

Configurazione Accesso Senza Password:
cat ~/.ssh/id_rsa.pub | ssh NomeUtente@IpWSL "powershell -Command \"New-Item -Force -ItemType Directory -Path C:\Users\UtenteWindows\.ssh; Add-Content -Force -Path C:\Users\UtenteWindows\.ssh\authorized_keys -Value \$Input\""

$path = "C:\Users\UtenteWindows\.ssh\authorized_keys"
icacls $path /inheritance:r /grant "UtenteWindows:F" /grant "SYSTEM:F"

Test:
ssh UtenteWSL@IpWsl