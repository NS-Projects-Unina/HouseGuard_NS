# Abilita il proxy di sistema su Windows puntando a Mitmproxy (localhost:8080)

$proxyServer = "127.0.0.1:8080"

Write-Host "Configurazione Proxy di Sistema su $proxyServer..."

# Imposta l'indirizzo del server proxy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value $proxyServer

# Abilita il proxy (1 = Abilitato)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1

# Disabilita l'uso dello script di configurazione automatica se presente
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name AutoConfigURL -Value ""

# Forza l'aggiornamento delle impostazioni (opzionale, a volte serve riavviare il browser)
Write-Host "Proxy abilitato. Le applicazioni che usano il proxy di sistema ora passeranno per Mitmproxy."
Write-Host "Assicurati che Mitmproxy sia in esecuzione sulla porta 8080."
