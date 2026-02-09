#!/bin/bash

# Configurazione API (Di solito è sulla porta 8000)
API_URL="http://127.0.0.1:8000"

echo "guardiano avviato. Modalità: Controllo Stato API."

# Troviamo l'ultimo ID presente per iniziare da lì
LAST_PROCESSED=$(ls storage/analyses/ | grep -E '^[0-9]+$' | sort -n | tail -n 1)
if [ -z "$LAST_PROCESSED" ]; then LAST_PROCESSED=0; fi

echo "   (Ultimo ID su disco: $LAST_PROCESSED)"

while true; do
    # 1. Trova il PROSSIMO ID
    NEXT_ID=$(ls storage/analyses/ | grep -E '^[0-9]+$' | sort -n | awk -v last="$LAST_PROCESSED" '$1 > last {print $1; exit}')

    if [ -n "$NEXT_ID" ]; then
        # 2. Chiediamo all'API lo stato (usando Python per leggere il JSON)
        #    Questo comando è molto più robusto di grep/cut
        RESPONSE=$(curl -s "$API_URL/apiv2/tasks/view/$NEXT_ID/")
        
        # Estraiamo lo status usando python on-the-fly
        STATUS=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('status', 'unknown'))")
        
        # DEBUG: Decommenta la riga sotto se vuoi vedere cosa risponde l'API
        # echo "   [DEBUG] Task $NEXT_ID Raw Status: '$STATUS'"

        if [ "$STATUS" == "completed" ]; then
            echo "⚡ Task $NEXT_ID completato! Avvio processing..."
            sleep 2
            
            # Lancia il processore
            python3 utils/process.py -r $NEXT_ID
            
            LAST_PROCESSED=$NEXT_ID
            echo "✅ Task $NEXT_ID report generato."
            echo "---------------------------------------------------"

        elif [ "$STATUS" == "reported" ]; then
            echo "⏭️  Task $NEXT_ID già reportato. Salto."
            LAST_PROCESSED=$NEXT_ID
            
        elif [ "$STATUS" == "failed" ]; then
            echo "❌ Task $NEXT_ID fallito. Salto."
            LAST_PROCESSED=$NEXT_ID
            
        elif [ "$STATUS" == "unknown" ]; then
             # Se status è vuoto o unknown, probabilmente l'API non ha ancora i dati
             # Non facciamo nulla e riproviamo al prossimo giro
             sleep 2
        else
            echo "⏳ Task $NEXT_ID stato: $STATUS... attendo."
            sleep 5
        fi
    else
        sleep 3
    fi
done