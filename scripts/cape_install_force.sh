#!/bin/bash

# Ottiene la directory dello script per gestire i percorsi in modo relativo
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# File dei requisiti e log errori
REQ_FILE="$SCRIPT_DIR/../requirements/requirements_cape.txt"
ERROR_FILE="$SCRIPT_DIR/../requirements/requirement_error.txt"

# Svuota il file degli errori se esiste già
> "$ERROR_FILE"

# Attiva l'ambiente virtuale
source "$SCRIPT_DIR/../venv/bin/activate"

# Verifica se il file esiste
if [ ! -f "$REQ_FILE" ]; then
    echo "❌ Errore: Il file $REQ_FILE non è stato trovato in questa cartella!"
    exit 1
fi

echo "🚀 Avvio installazione sequenziale (ignora errori)..."

# Legge il file riga per riga
while read -r line || [[ -n "$line" ]]; do
    # Rimuove spazi bianchi iniziali e finali
    line=$(echo "$line" | xargs)

    # Controlla se la riga non è vuota e non inizia con #
    if [[ -n "$line" ]] && [[ ! "$line" =~ ^# ]]; then
        echo "--------------------------------------------------"
        echo "📦 Tentativo installazione: $line"
        
        # Esegue l'installazione (usa la cache se disponibile)
        pip install "$line"

        # Verifica l'esito del comando precedente
        if [ $? -eq 0 ]; then
            echo "✅ Installato correttamente: $line"
        else
            echo ""
            echo "⚠️  ERRORE SU $line - SALVATO IN $ERROR_FILE"
            echo ""
            echo "$line" >> "$ERROR_FILE"
        fi
    fi
done < "$REQ_FILE"

echo "--------------------------------------------------"
echo "🏁 Procedura completata."