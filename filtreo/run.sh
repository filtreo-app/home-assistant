#!/usr/bin/with-contenv bashio
# Avvio di Filtreo: prepara /data, avvia Blocky (che si riavvia da solo), poi il pannello (ingress).
set -e

DATA=/data
export FILTREO_DATA="${DATA}"
export INGRESS_PORT=8099
export BARRA_PORT=8447

# Codice del pannello: se c'è una versione in /share/filtreo/app (aggiornamento automatico di Casa, o installatore
# in pochi secondi, senza ricostruire), usa quella; altrimenti quella dentro l'add-on.
# aggiornamento.py --scegli: chiude una prova di aggiornamento interrotta (torna alla versione di prima) e sceglie la
# cartella valida più recente. Se manca (immagine vecchia), la scelta di prima.
export FILTREO_CODICE_BASE=/share/filtreo
export FILTREO_APP_INTERNA=/opt/filtreo/app
APP=/opt/filtreo/app
SCELTA=""
if [ -f /opt/filtreo/app/aggiornamento.py ]; then
  SCELTA="$(python3 /opt/filtreo/app/aggiornamento.py --scegli 2>/dev/null | tail -1)"
fi
if [ -n "${SCELTA}" ] && [ -f "${SCELTA}/filtreo_pannello.py" ]; then
  APP="${SCELTA}"
  [ "${APP}" != /opt/filtreo/app ] && bashio::log.info "Pannello: uso la versione aggiornata in ${APP}."
elif [ -f /share/filtreo/app/filtreo_pannello.py ] && [ -f /share/filtreo/app/filtreo_liste.py ]; then
  if python3 -m py_compile /share/filtreo/app/filtreo_pannello.py /share/filtreo/app/filtreo_liste.py /share/filtreo/app/filtro.py 2>/dev/null; then
    APP=/share/filtreo/app
    bashio::log.info "Pannello: uso la versione aggiornata in /share/filtreo/app."
  else
    bashio::log.warning "La versione in /share/filtreo/app non è valida: uso quella interna."
  fi
fi

# Chiave per l'icona nella barra del Mac (la imposta l'installatore). Vuota = barra spenta.
CHIAVE=""
if bashio::config.has_value 'chiave_barra'; then
  CHIAVE="$(bashio::config 'chiave_barra')"
fi
export FILTREO_CHIAVE="${CHIAVE}"
if [ -n "${CHIAVE}" ]; then
  bashio::log.info "Icona barra Mac: attiva (porta ${BARRA_PORT}, protetta da chiave)."
fi

mkdir -p "${DATA}/liste" "${DATA}/log" "${DATA}/fonti"

# ── Paracadute (Cloudflare) e «fuori casa»: le impostazioni le porta il Mac (PARACADUTE-GIO.command) ──
# /data/opzioni.env (righe NOME=valore, solo i nomi qui sotto; indirizzi già controllati dalla casella):
#   FILTREO_PARACADUTE_URL=https://filtreo-paracadute-gio.<nome>.workers.dev   → i profili DNS usano il paracadute
#   FILTREO_DOH_URL=https://centrale-gio.taila9e0c5.ts.net:8443                → «fuori casa» acceso (/f/ e /p/)
# /data/segreti/cloudflare.env (CF_TOKEN, CF_ACCOUNT, CF_KV_NS; mai nei log) → le modalità seguono da sole.
if [ -f "${DATA}/opzioni.env" ]; then
  while IFS='=' read -r _k _v; do
    case "${_k}" in
      FILTREO_PARACADUTE_URL|FILTREO_DOH_URL|FILTREO_DOH_PORT) [ -n "${_v}" ] && export "${_k}=${_v}" ;;
    esac
  done < "${DATA}/opzioni.env"
fi
export FILTREO_SEGRETI_CF="${DATA}/segreti/cloudflare.env"
export FILTREO_CASELLA=/share/filtreo/consegna
export FILTREO_APP="${APP}"
# programma che copia le modalità nel paracadute: quello aggiornato in /share/filtreo/jetson se è valido
PJ=/opt/filtreo/jetson
if [ -f /share/filtreo/jetson/paracadute-sync.py ] && [ -f /share/filtreo/jetson/paracadute-addon.py ] \
   && python3 -m py_compile /share/filtreo/jetson/paracadute-sync.py /share/filtreo/jetson/paracadute-addon.py 2>/dev/null; then
  PJ=/share/filtreo/jetson
fi
export FILTREO_PARACADUTE_SYNC="${PJ}/paracadute-sync.py"
[ -n "${FILTREO_PARACADUTE_URL:-}" ] && bashio::log.info "Paracadute: attivo (${FILTREO_PARACADUTE_URL})."
[ -n "${FILTREO_DOH_URL:-}" ] && bashio::log.info "Fuori casa: attivo (${FILTREO_DOH_URL})."

# Liste personali: copiate solo se mancano, così non si sovrascrivono quelle di Giò.
for f in blocca.txt sblocca.txt bianca.txt lavoro-bianca.txt; do
  if [ ! -f "${DATA}/liste/${f}" ]; then
    cp "${APP}/liste/${f}" "${DATA}/liste/${f}"
  fi
done

# Config del motore e liste per dispositivo: le prepara il pannello (passaggio dalle versioni vecchie compreso).
cd "${APP}"
if python3 filtreo_liste.py --prepara; then
  bashio::log.info "Configurazione e liste pronte."
else
  bashio::log.warning "Preparazione non riuscita: uso la configurazione di prima."
  [ -f "${DATA}/blocky.yml" ] || cp "${APP}/blocky.template.yml" "${DATA}/blocky.yml"
fi

# Blocky in un ciclo: se si ferma (o il pannello lo riavvia dopo un cambio di dispositivi) riparte in 2 secondi.
bashio::log.info "Avvio Blocky (motore del filtro)..."
(
  while true; do
    /usr/bin/blocky --config "${DATA}/blocky.yml" &
    echo $! > /tmp/blocky.pid
    wait $! || true
    bashio::log.warning "Blocky si è fermato: riparte subito."
    sleep 0.5
  done
) &

for _i in $(seq 1 40); do
  if wget -q -O- "http://127.0.0.1:4000/api/blocking/status" >/dev/null 2>&1; then
    bashio::log.info "Blocky è pronto."
    break
  fi
  sleep 1
done

# Casella del paracadute: ogni 15 secondi un controllo leggerissimo; Python parte solo se il Mac ha lasciato qualcosa.
(
  mkdir -p "${FILTREO_CASELLA}" 2>/dev/null && chmod 700 "${FILTREO_CASELLA}" 2>/dev/null
  sleep 20
  python3 "${PJ}/paracadute-addon.py" --stato >/dev/null 2>&1
  while true; do
    for _f in "${FILTREO_CASELLA}"/cloudflare.env "${FILTREO_CASELLA}"/opzioni.env "${FILTREO_CASELLA}"/pannello-fuori.codice "${FILTREO_CASELLA}"/richiesta-*; do
      if [ -f "${_f}" ]; then
        python3 "${PJ}/paracadute-addon.py" --giro 2>&1 | while IFS= read -r _r; do echo "[filtreo] ${_r}"; done
        break
      fi
    done
    sleep 15
  done
) &

bashio::log.info "Avvio il pannello Filtreo (barra laterale)."
exec python3 filtreo_pannello.py
