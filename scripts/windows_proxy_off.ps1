# Disabilita il proxy di sistema su Windows

Write-Host "Disabilitazione Proxy di Sistema..."

# Disabilita il proxy (0 = Disabilitato)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0

Write-Host "Proxy disabilitato. Torna alla connessione diretta."
