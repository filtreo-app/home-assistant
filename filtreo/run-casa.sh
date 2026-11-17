#!/bin/sh
# Avvio di Filtreo SENZA Home Assistant (Jetson, NAS, computer di casa): stesso programma del Pi.
# Impostazioni in /data/opzioni.env (righe NOME=valore), per esempio:
#   FILTREO_DNS=192.168.1.20:53,100.124.14.118:53   (dove ascolta il DNS; vuoto = porta 53 ovunque)
#   FILTREO_RETI=100.64.0.0/10 192.168.1.0/24        (chi può aprire il pannello)
#   INGRESS_PORT=8446                                (porta del pannello)
#   FILTREO_CHIAVE=…                                 (chiave del widget; vuota = widget spento)
#   FILTREO_MOTORE=4000                              (porta di controllo del motore; altra = prove affiancate)
#   FILTREO_BASE=/data/blocky-base.yml               (config di Blocky di prima: upstream, nomi locali… restano)
set -e
DATA=/data
[ -f "$DATA/opzioni.env" ] && { set -a; . "$DATA/opzioni.env"; set +a; }
export FILTREO_DATA="$DATA"
export INGRESS_PORT="${INGRESS_PORT:-8446}"
export BARRA_PORT="${BARRA_PORT:-8447}"
export FILTREO_CHIAVE="${FILTREO_CHIAVE:-}"
export FILTREO_DNS="${FILTREO_DNS:-}"
export FILTREO_RETI="${FILTREO_RETI:-100.64.0.0/10 192.168.0.0/16 10.0.0.0/8 127.0.0.0/8}"
export INGRESSO_OK="127.0.0.1"
export FILTREO_SENZA_HA=1
log(){ echo "[filtreo $(date +%H:%M:%S)] $*"; }
# Codice: quello dell'immagine, oppure quello aggiornato da Casa in /data/codice/app (aggiornamento automatico: canale
# firmato, prova, ritorno indietro). aggiornamento.py --scegli chiude una prova interrotta e sceglie la cartella valida.
export FILTREO_CODICE_BASE="${FILTREO_CODICE_BASE:-$DATA/codice}"
export FILTREO_APP_INTERNA=/opt/filtreo/app
APP=/opt/filtreo/app
if [ -f /opt/filtreo/app/aggiornamento.py ]; then
  SCELTA="$(python3 /opt/filtreo/app/aggiornamento.py --scegli 2>/dev/null | tail -1)"
  if [ -n "$SCELTA" ] && [ -f "$SCELTA/filtreo_pannello.py" ]; then APP="$SCELTA"; fi
fi
[ "$APP" != /opt/filtreo/app ] && log "uso il codice aggiornato in $APP"
export FILTREO_APP="$APP"

mkdir -p "$DATA/liste" "$DATA/log" "$DATA/fonti"
for f in blocca.txt sblocca.txt bianca.txt lavoro-bianca.txt; do
  [ -f "$DATA/liste/$f" ] || cp "$APP/liste/$f" "$DATA/liste/$f"
done
cd "$APP"
if python3 filtreo_liste.py --prepara; then log "configurazione e liste pronte"
else log "preparazione non riuscita: uso la configurazione di prima"; [ -f "$DATA/blocky.yml" ] || cp "$APP/blocky.template.yml" "$DATA/blocky.yml"; fi
(
  while true; do
    /usr/bin/blocky --config "$DATA/blocky.yml" &
    echo $! > /tmp/blocky.pid
    wait $! || true
    log "Blocky si è fermato: riparte subito"
    sleep 0.5
  done
) &
i=0
while [ $i -lt 60 ]; do
  wget -q -O- http://127.0.0.1:${FILTREO_MOTORE:-4000}/api/blocking/status >/dev/null 2>&1 && { log "Blocky pronto"; break; }
  i=$((i+1)); sleep 1
done
log "pannello sulla porta $INGRESS_PORT"
exec python3 filtreo_pannello.py
