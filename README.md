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