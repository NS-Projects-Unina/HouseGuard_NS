# HouseGuard_NS

## Partecipanti

- Simone De Lucia M63001720
- Gabriel Covone M63001809
- De Prophetis Claudio M63001815

Per utilizzare CAPE occorre:
avviare i container;
avviare rooter.py in un terminale:
cd ~/HouseGuard_NS/cape_source
source venv/bin/activate
sudo python3 utils/rooter.py -g $USER
avviare l'interfaccia web in un terminale:
cd ~/HouseGuard_NS/cape_source
source venv/bin/activate
python3 web/manage.py runserver 0.0.0.0:8000
avviare cuckoo.py in un terminale:
cd ~/HouseGuard_NS/cape_source
source venv/bin/activate
python3 cuckoo.py -d
Avviare guardian.sh, questo permette di generare i report una volta che CAPE finisce l'analisi
cd ~/HouseGuard_NS/cape_source
source venv/bin/activate
./guardian.sh

## Proxy (APLHA)

1. USARE WSL
2. creare un ambiente virtuale
3. installare le dipendenze
   
   ```pip install -r modulo/requirements.txt
   
   ```
4. Avviare lo script col comando `./scripts/global_start.sh`

