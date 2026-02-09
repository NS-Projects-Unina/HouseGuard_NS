# Usa un'immagine base leggera di Python
FROM python:3.9-slim 

WORKDIR /home/mitmproxy

# --- AGGIUNTA FONDAMENTALE ---
# Aggiorniamo i certificati di root del sistema
RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates
# -----------------------------

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Espone la porta
EXPOSE 8080

# Comando di default (può essere sovrascritto dal docker-compose)
CMD ["mitmdump", "-s", "app.py", "--ssl-insecure", "--ignore-hosts", "^(.+\\.)?(brave\\.com|microsoft\\.com|googleapis\\.com|windowsupdate\\.com|visualstudio\\.com):443$"]