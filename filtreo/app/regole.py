#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""regole.py — Filtreo 3.1: «Le tue regole» (prima «Sempre bloccati» / «Sempre consentiti»).

Le regole restano negli stessi file di sempre (nessuna migrazione, nessun formato nuovo):
  sempre bloccati   liste/blocca.txt                          («*.sito»)
  sempre consentiti liste/bianca.txt + liste/sblocca.txt + i siti aggiunti a liste/anti-rilevamento.txt
Accanto c'è solo un file di NOTE, regole-origini.json: per ogni regola da dove viene e quando è nata.
  {"bloccati": {"sito.it": {"origine": "registro", "quando": 1794712345.0}}, "consentiti": {…}}
Una regola senza nota (tutte quelle di prima della 3.1, o scritte a mano nei file) vale «a mano», data sconosciuta.

0.9.1 — regole a tempo («Consenti per 1 ora»): la nota può avere "scade" (secondi dal 1970). Casa la toglie da sola alla scadenza
(filtreo_pannello: giro ogni 30 secondi), anche con le app chiuse. Una regola aggiunta di nuovo senza durata diventa per sempre.

Origini: registro (dal registro delle richieste), sito (pagina «Sito bloccato» / «Un sito ti ha scoperto»),
         mano (scritta a mano), estensione (dall'estensione del browser), controllo («Sistema» dal controllo della protezione).
"""
import json
import os
import threading
import time
from datetime import datetime

import filtro

FILE = os.path.join(filtro.DATA, "regole-origini.json")
ORIGINI = {
    "registro": "Dal registro",
    "sito": "Dalla pagina «Sito bloccato»",
    "mano": "Aggiunta a mano",
    "estensione": "Dall’estensione",
    "controllo": "Dal controllo della protezione",
}
FRASI = {
    "bloccati": "Questi siti non si caricano mai, su tutti i dispositivi.",
    "consentiti": "Questi siti funzionano sempre, anche se una lista li blocca.",
}
FILE_CONSENTITI = ("bianca.txt", "sblocca.txt", "anti-rilevamento.txt")
_l = threading.Lock()


def origine_valida(o, di_serie="mano"):
    o = str(o or "").strip().lower()
    return o if o in ORIGINI else di_serie


def _leggi():
    try:
        d = json.load(open(FILE, encoding="utf-8"))
        if isinstance(d, dict):
            return {"bloccati": dict(d.get("bloccati") or {}), "consentiti": dict(d.get("consentiti") or {})}
    except (OSError, ValueError):
        pass
    return {"bloccati": {}, "consentiti": {}}


def _salva(d):
    tmp = FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        json.dump(d, h, ensure_ascii=False, indent=1)
    os.replace(tmp, FILE)


def segna(tipo, dominio, origine="mano", quando=None):
    """ricorda da dove viene una regola appena aggiunta (tipo: «bloccati» o «consentiti»). Mai un errore verso chi chiama."""
    d = filtro._dominio(dominio)
    if not d or tipo not in FRASI:
        return False
    try:
        with _l:
            x = _leggi()
            x[tipo][d] = {"origine": origine_valida(origine), "quando": float(quando or time.time())}
            altro = "consentiti" if tipo == "bloccati" else "bloccati"
            x[altro].pop(d, None)   # bloccare un sito toglie il permesso (e viceversa): la nota vecchia non serve più
            _salva(x)
        return True
    except OSError:
        return False


DURATA_MIN, DURATA_MAX = 60, 7 * 86400


def durata_valida(x):
    """secondi di una regola a tempo (60 s … 7 giorni) oppure None = per sempre / valore non valido."""
    try:
        n = int(float(x))
    except (TypeError, ValueError):
        return None
    return n if DURATA_MIN <= n <= DURATA_MAX else None


def imposta_scadenza(tipo, dominio, scade=None, origine="mano"):
    """scade = istante (secondi dal 1970) o None per togliere la scadenza. Crea la nota se manca."""
    d = filtro._dominio(dominio)
    if not d or tipo not in FRASI:
        return False
    try:
        with _l:
            x = _leggi()
            n = dict(x[tipo].get(d) or {"origine": origine_valida(origine), "quando": time.time()})
            if scade:
                n["scade"] = float(scade)
            else:
                n.pop("scade", None)
            x[tipo][d] = n
            _salva(x)
        return True
    except OSError:
        return False


def scadute(adesso=None):
    """[(tipo, dominio)] delle regole a tempo già scadute."""
    adesso = adesso or time.time()
    x = _leggi()
    out = []
    for tipo in ("consentiti", "bloccati"):
        for d, n in x[tipo].items():
            try:
                if n.get("scade") and float(n["scade"]) <= adesso:
                    out.append((tipo, d))
            except (TypeError, ValueError, AttributeError):
                continue
    return out


def dimentica(tipo, dominio):
    d = filtro._dominio(dominio)
    if not d or tipo not in FRASI:
        return False
    try:
        with _l:
            x = _leggi()
            if x[tipo].pop(d, None) is not None:
                _salva(x)
        return True
    except OSError:
        return False


def _voci(nome):
    out = []
    for r in filtro._righe(nome):
        r = r.strip()
        if not r or r.startswith("#"):
            continue
        d = filtro._dominio(r)
        if d and d not in out:
            out.append(d)
    return out


def _iso(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M:%S") if ts else ""
    except (TypeError, ValueError, OSError):
        return ""


def elenco(esche=(), scarti=None):
    """GET /pannello/regole. esche = siti di sistema di anti-rilevamento (non sono regole tue, non si mostrano);
    scarti = {dominio: motivo} permessi ignorati dal motore (pubblicità, o bloccati da te): si mostrano con il motivo."""
    note = _leggi()
    scarti = scarti or {}
    esche = {e.lstrip("*.") for e in esche}

    def voce(tipo, d, file):
        n = note[tipo].get(d) or {}
        o = origine_valida(n.get("origine"))
        v = {"dominio": d, "origine": o, "origine_nome": ORIGINI[o], "quando": _iso(n.get("quando")), "file": file,
             "valida": d not in scarti if tipo == "consentiti" else True,
             "scade": _iso(n.get("scade")) or None}   # 0.9.1: regola a tempo (ora di Casa), None = per sempre
        if tipo == "consentiti" and d in scarti:
            v["motivo"] = scarti[d]
        return v

    bloc = [voce("bloccati", d, "blocca.txt") for d in _voci("blocca.txt")]
    cons, visti = [], set()
    for nome in FILE_CONSENTITI:
        for d in _voci(nome):
            if d in visti or (nome == "anti-rilevamento.txt" and d in esche):
                continue
            visti.add(d)
            cons.append(voce("consentiti", d, nome))
    # le più recenti prima; quelle senza data (di prima della 3.1) in fondo, in ordine di file
    chiave = lambda v: v["quando"] or ""  # noqa: E731
    bloc.sort(key=chiave, reverse=True)
    cons.sort(key=chiave, reverse=True)
    return {"versione": 1,
            "bloccati": {"frase": FRASI["bloccati"], "voci": bloc, "n": len(bloc)},
            "consentiti": {"frase": FRASI["consentiti"], "voci": cons, "n": len(cons)},
            "origini": ORIGINI}
