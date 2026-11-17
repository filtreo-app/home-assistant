#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""estensione_nodo.py — quello che arriva dalle estensioni Filtreo del browser:
regole condivise («Blocca qualcosa», solo blocchi) e «Segnala un problema».
Stessa cosa su Jetson e Pi; i file stanno nella cartella dati del filtro."""
import json
import os
import re
import secrets
import time

import filtro

REGOLE_ESTENSIONE = os.path.join(filtro.DATA, "regole-estensione.txt")
SEGNALAZIONI = os.path.join(filtro.DATA, "segnalazioni.jsonl")
_FILE_CHIAVE = os.path.join(filtro.DATA, "chiave-nodo")


def chiave():
    """chiave che le estensioni leggono dal pannello (var KEY) e rimandano in X-Filtro."""
    k = os.environ.get("FILTREO_CHIAVE_NODO", "").strip()
    if k:
        return k
    try:
        k = open(_FILE_CHIAVE, encoding="utf-8").read().strip()
    except OSError:
        k = ""
    if not k:
        k = secrets.token_hex(24)
        with open(_FILE_CHIAVE, "w", encoding="utf-8") as h:
            h.write(k)
        os.chmod(_FILE_CHIAVE, 0o600)
    return k


def segnalazioni(tutte=False):
    out = []
    try:
        with open(SEGNALAZIONI, encoding="utf-8") as f:
            for r in f:
                try:
                    out.append(json.loads(r))
                except ValueError:
                    pass
    except FileNotFoundError:
        pass
    if not tutte:
        out = [x for x in out if not x.get("fatta")]
    return list(reversed(out))[:200]


def aggiungi_segnalazione(s):
    """«Segnala un problema» dalle estensioni (di Davide direttamente, di Giò tramite il modulo del sito Filtreo)."""
    if not isinstance(s, dict):
        return False, "formato sbagliato"
    pulita = {k: (str(s.get(k, ""))[:600] if not isinstance(s.get(k), list) else [str(x)[:120] for x in s.get(k)][:40])
              for k in ("quando", "problema", "nota", "pagina", "sito", "bloccati", "passati", "versione", "browser", "chi")}
    if not pulita["sito"] or not pulita["problema"]:
        return False, "Sito o problema mancante"
    gia = {(x.get("quando"), x.get("sito"), x.get("problema")) for x in segnalazioni(tutte=True)}
    if (pulita["quando"], pulita["sito"], pulita["problema"]) in gia:
        return True, "Già ricevuta"
    pulita["id"] = "%d" % (time.time() * 1000)
    with open(SEGNALAZIONI, "a", encoding="utf-8") as f:
        f.write(json.dumps(pulita, ensure_ascii=False) + "\n")
    return True, "ricevuta"


def segnalazione_fatta(sid):
    tutte = list(reversed(segnalazioni(tutte=True)))
    for x in tutte:
        if x.get("id") == sid:
            x["fatta"] = True
    tmp = SEGNALAZIONI + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for x in tutte:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
    os.replace(tmp, SEGNALAZIONI)
    return True, "segnata come fatta"
_RIGA_OK = re.compile(r"^[\x20-\x7e]{4,500}$")


def regole_estensione():
    try:
        with open(REGOLE_ESTENSIONE, encoding="utf-8") as f:
            return [r.strip() for r in f if r.strip() and not r.startswith("!")]
    except FileNotFoundError:
        return []


def aggiungi_regole_estensione(righe):
    """Solo blocchi (mai eccezioni: quelle restano nel browser di chi le fa)."""
    if not isinstance(righe, list):
        return False, "formato sbagliato"
    buone = []
    for r in righe[:500]:
        if not isinstance(r, str):
            continue
        r = r.strip()
        if not _RIGA_OK.match(r) or r.startswith(("!", "@@", "[")) or "#@#" in r:
            continue
        buone.append(r)
    ora = regole_estensione()
    nuove = [r for r in dict.fromkeys(buone) if r not in set(ora)]
    if nuove:
        tutte = (ora + nuove)[-5000:]
        tmp = REGOLE_ESTENSIONE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("! Regole condivise dalle estensioni Filtreo (Blocca qualcosa / Le mie regole)\n")
            f.write("\n".join(tutte) + "\n")
        os.replace(tmp, REGOLE_ESTENSIONE)
    return True, "%d regole nuove" % len(nuove)


