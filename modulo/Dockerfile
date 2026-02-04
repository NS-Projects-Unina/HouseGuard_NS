# Usa l'immagine ufficiale di Mitmproxy
FROM mitmproxy/mitmproxy

WORKDIR /home/mitmproxy

# Installa le dipendenze Python aggiuntive
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia TUTTI i file del modulo (app.py, staticLinkModule.py, liste, ecc.)
COPY . .

# Comando di avvio: lancia mitmdump con lo script
CMD ["mitmdump", "-s", "app.py", "--set", "block_global=false"]