# Filtreo add-on — Blocky (motore) + pannello Python, serviti via ingress di Home Assistant.
ARG BUILD_FROM

# Il binario di Blocky arriva dall'immagine ufficiale (multi-arch).
# Se il build fallisce su questo tag, cambia solo la riga sotto con un tag esistente
# da https://github.com/0xERR0R/blocky/pkgs/container/blocky  (es. :v0.35.0, :latest)
FROM ghcr.io/0xerr0r/blocky:v0.35.0 AS blocky

FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-yaml tzdata

# binario di Blocky (nell'immagine ufficiale sta in /app/blocky)
COPY --from=blocky /app/blocky /usr/bin/blocky

# applicazione: pannello + cervello + modello di config + liste
COPY app /opt/filtreo/app
# 3.2: ora di costruzione dell'immagine (RILASCIO.json): Casa sceglie tra questo codice e quello aggiornato da sola
# (/share/filtreo/app o /data/codice/app) il più recente. Vedi app/aggiornamento.py (_app_scelta).
RUN python3 -c "import json,time;json.dump({'rilascio':int(time.strftime('%Y%m%d%H%M',time.gmtime())),'origine':'immagine'},open('/opt/filtreo/app/RILASCIO.json','w'))"
# modello del widget per l'iPhone (il pannello lo dà già pronto: /pannello/widget)
COPY widget-iphone /opt/filtreo/widget-iphone
# paracadute (Cloudflare): copia delle modalità + casella per i messaggi del Mac
COPY jetson/paracadute-sync.py jetson/paracadute-addon.py /opt/filtreo/jetson/
COPY run.sh /run.sh
COPY run-casa.sh /run-casa.sh
RUN chmod a+x /run.sh /run-casa.sh /usr/bin/blocky

CMD [ "/run.sh" ]
