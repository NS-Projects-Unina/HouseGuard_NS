Scarica il file win10_vittima.qcow2 dal seguente link: 
https://drive.google.com/file/d/1lFntYoGwtzFhvNu6kWv2nh68UyAX-J4l/view?usp=sharing

decomprimi:
tar -xzvf win10_vittima.tar.gz

sposta il file win10_vittima.qcow2 nella cartella delle immagini di KVM
sudo mv /percorso/del/tuo/download/win10_vittima.qcow2 /var/lib/libvirt/images/

esegui il comando per definire la VM usando il file XML fornito:
virsh define win10_vittima_config.xml

Lo snapshot "Snap1" è già contenuto nel file del disco, ma bisogna dire a KVM di leggerlo e registrarlo:
virsh snapshot-create win10_vittima --xmlfile win10_snapshot_Snap1.xml --redefine --current

ripristina lo snapshot per assicurarti che la VM sia nello stato pulito e pronta per l'analisi:
virsh snapshot-revert win10_vittima Snap1