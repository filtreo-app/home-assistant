#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""applicazione.py — quanto ci mette un cambio ad avere effetto (e dire «Applico… circa N s»).

Ogni cambio (interruttore, modalità, dispositivo, permessi) apre un «lavoro» con inizia(); quando il motore lo ha
applicato (ricarica delle liste o riavvio) il lavoro si chiude con finisci(). Ogni chiusura finisce nel registro
/data/log/applicazioni.jsonl con la durata, e nello stato del pannello come
  applicazione: {in_corso, secondi_stimati, ultima_durata, testo, ...}
Cambi ravvicinati = un solo lavoro (la durata si conta dal primo).
"""
import json
import os
import threading
import time
from datetime import datetime

DATA = os.environ.get("FILTREO_DATA", "/data")
LOG = os.path.join(DATA, "log", "applicazioni.jsonl")
STIMA_BASE = {"ricarica": 8.0, "riavvio": 10.0}   # secondi, finché non ci sono misure vere
_l = threading.Lock()
_s = {"pendenti": 0, "da": 0.0, "tipo": "", "motivo": "", "attesa": 0.0, "durate": {}, "ultima": None}


def _carica():
    """le ultime misure vere (dal registro) servono per stimare i prossimi tempi."""
    try:
        with open(LOG, encoding="utf-8") as f:
            for r in f.readlines()[-40:]:
                j = json.loads(r)
                if j.get("ok") and j.get("tipo") in STIMA_BASE:
                    _s["durate"].setdefault(j["tipo"], []).append(float(j["durata"]))
        for k in _s["durate"]:
            _s["durate"][k] = _s["durate"][k][-5:]
    except (OSError, ValueError):
        pass


_carica()


def _stima(tipo):
    d = _s["durate"].get(tipo) or []
    return (sum(d) / len(d)) if d else STIMA_BASE.get(tipo, 8.0)


def inizia(tipo="ricarica", motivo="", attesa=0.0):
    """apre (o allarga) il lavoro in corso. tipo: «ricarica» (senza riavvio) o «riavvio»; attesa = secondi di preavviso prima del riavvio."""
    with _l:
        if _s["pendenti"] == 0:
            _s.update(da=time.time(), tipo=tipo, motivo=motivo, attesa=float(attesa or 0))
        else:
            if tipo == "riavvio":
                _s["tipo"] = "riavvio"
                _s["attesa"] = max(_s["attesa"], float(attesa or 0))
            if motivo and not _s["motivo"]:
                _s["motivo"] = motivo
        _s["pendenti"] += 1


def segna_riavvio(motivo=""):
    """un riavvio entra in un lavoro già aperto (es. una ricarica): il lavoro diventa «riavvio» e il motivo si vede nel registro."""
    with _l:
        if _s["pendenti"] > 0 and _s["tipo"] != "riavvio":
            _s["tipo"] = "riavvio"
            if motivo:
                _s["motivo"] = ((_s["motivo"] + " + ") if _s["motivo"] else "") + "riavvio: " + motivo


def preleva():
    """quanti lavori sono aperti adesso (chi applica li chiude con finisci(n) quando ha finito)."""
    with _l:
        return _s["pendenti"]


def finisci(n=None, ok=True):
    """chiude n lavori (tutti se n è None); quando non ne resta nessuno scrive la misura."""
    with _l:
        if _s["pendenti"] <= 0:
            return None
        n = _s["pendenti"] if n is None else min(int(n), _s["pendenti"])
        _s["pendenti"] -= n
        if _s["pendenti"] > 0:
            return None   # sono arrivati altri cambi nel frattempo: il lavoro continua
        durata = round(time.time() - _s["da"], 1)
        rec = {"ora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "tipo": _s["tipo"], "motivo": _s["motivo"][:80],
               "durata": durata, "ok": bool(ok)}
        if ok:
            d = _s["durate"].setdefault(_s["tipo"], [])
            d.append(durata)
            del d[:-5]
        _s["ultima"] = rec
        if rec["tipo"] == "riavvio":   # il riavvio si ricorda a parte: una ricarica subito dopo non lo deve far sparire
            _s["ultimo_riavvio"] = dict(rec, ts=time.time())
        _s["tipo"] = _s["motivo"] = ""
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        if os.path.exists(LOG) and os.path.getsize(LOG) > 400000:
            with open(LOG, encoding="utf-8") as f:
                resto = f.readlines()[-200:]
            with open(LOG, "w", encoding="utf-8") as f:
                f.writelines(resto)
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return rec


def stato():
    """dati per il pannello: {in_corso, secondi_stimati, ultima_durata, ...}."""
    with _l:
        in_corso = _s["pendenti"] > 0
        u = _s["ultima"]
        if in_corso:
            totale = _stima(_s["tipo"]) + (_s["attesa"] if _s["tipo"] == "riavvio" else 0)
            resta = max(1, int(round(totale - (time.time() - _s["da"]))))
        else:
            totale, resta = 0, 0
        ud = u["durata"] if u else None
        ur = _s.get("ultimo_riavvio")
        if in_corso:
            testo = "Applicazione in corso… circa %d s" % resta
        elif u:
            testo = ("Ultima modifica applicata in %s s" % (("%.0f" % ud) if ud >= 10 else ("%.1f" % ud).replace(".", ","))) if u["ok"] else "Impossibile applicare l’ultima modifica"
        else:
            testo = ""
        return {"in_corso": in_corso, "secondi_stimati": resta, "ultima_durata": ud,
                "tipo": _s["tipo"] if in_corso else (u["tipo"] if u else ""), "motivo": _s["motivo"] if in_corso else (u["motivo"] if u else ""),
                "ultima_ora": u["ora"] if u else "", "ultima_ok": u["ok"] if u else True,
                "con_riavvio": (_s["tipo"] == "riavvio") if in_corso else bool((u and u["tipo"] == "riavvio") or (ur and time.time() - ur["ts"] < 120)),
                "ultimo_riavvio_durata": ur["durata"] if ur else None, "testo": testo}
