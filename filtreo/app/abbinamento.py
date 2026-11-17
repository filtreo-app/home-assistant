# -*- coding: utf-8 -*-
"""abbinamento.py — collegare un'app a Casa senza chiavi da copiare. Solo libreria standard.

  1. l'app (nella rete di casa, trovata Casa con Bonjour) chiama POST /pannello/abbina/inizia  {"nome": "iPhone di Davide"}
     → {"ok": true, "id": "<richiesta>", "scade_tra": 300}
  2. Casa mostra un codice di 6 cifre: nel pannello web (riquadro in basso), nelle app già collegate
     (GET /pannello/abbina/attese) e, se configurati, su Telegram e nelle notifiche di Home Assistant
  3. l'app manda il codice: POST /pannello/abbina/conferma  {"id": "…", "codice": "123456"}
     → {"ok": true, "chiave": "<chiave del dispositivo>", "dispositivo": "<id>", "nome": "…"}
  4. da qui l'app manda la chiave in ogni richiesta (Authorization: Bearer <chiave>, oppure X-Filtro: <chiave>) e il
     pannello la accetta da qualunque rete. In Impostazioni › App collegate ogni chiave si può rimuovere.

Sicurezza
  • il codice vale 5 minuti e una volta sola; al massimo 5 richieste in attesa;
  • 5 codici sbagliati (in tutto, su qualunque richiesta) → conferme bloccate per 10 minuti e richieste annullate;
  • su disco solo lo sha256 della chiave (DATA/abbinamenti.json, permessi 600): la chiave non si può rileggere.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

DATA = os.environ.get("FILTREO_DATA", "/data")
VALIDITA = 300
MAX_ATTESA = 5
ERRORI_MAX = 5
BLOCCO = 600
FINESTRA_ERRORI = 600

_lock = threading.Lock()
_richieste = {}          # id → {"nome", "codice", "scade", "ip", "creata"}
_errori = []             # istanti dei codici sbagliati
_blocco = {"fino": 0.0}
_notifica = []           # funzioni(testo, richiesta) chiamate a ogni richiesta nuova (Telegram, Home Assistant)
_uso_scritto = {}


def _file():
    return os.path.join(DATA, "abbinamenti.json")


def _hash(k):
    return hashlib.sha256(("filtreo-casa:" + k).encode("utf-8")).hexdigest()


def _leggi():
    try:
        with open(_file(), encoding="utf-8") as h:
            d = json.load(h)
        return d if isinstance(d, dict) and isinstance(d.get("chiavi"), list) else {"chiavi": []}
    except (OSError, ValueError):
        return {"chiavi": []}


def _scrivi(d):
    p = _file()
    try:
        fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            json.dump(d, h, ensure_ascii=False, indent=1)
        os.replace(p + ".tmp", p)
        return True
    except OSError:
        return False


def _pulisci(adesso):
    for k in [k for k, r in _richieste.items() if r["scade"] <= adesso]:
        _richieste.pop(k, None)
    while _errori and _errori[0] < adesso - FINESTRA_ERRORI:
        _errori.pop(0)


def _nome(n):
    n = re.sub(r"[\x00-\x1f<>\"]", "", str(n or "")).strip()[:40]
    return n or "Dispositivo"


def bloccato(adesso=None):
    """secondi che mancano alla fine del blocco (0 = nessun blocco)."""
    adesso = adesso or time.time()
    return max(0, int(round(_blocco["fino"] - adesso)))


def inizia(nome, ip="", adesso=None):
    adesso = adesso or time.time()
    with _lock:
        _pulisci(adesso)
        b = bloccato(adesso)
        if b:
            return 429, {"ok": False, "codice": "bloccato", "resta": b, "testo": "Troppi tentativi. Riprova tra %d min." % max(1, (b + 59) // 60)}
        if len(_richieste) >= MAX_ATTESA:
            return 429, {"ok": False, "codice": "troppe", "testo": "Troppe richieste in attesa. Riprova tra qualche minuto."}
        rid = secrets.token_urlsafe(12)
        r = {"nome": _nome(nome), "codice": "%06d" % secrets.randbelow(10 ** 6), "scade": adesso + VALIDITA, "ip": str(ip or "")[:45], "creata": adesso}
        _richieste[rid] = r
    for fn in list(_notifica):
        try:
            fn("Filtreo: codice per collegare «%s» a Casa: %s %s (vale 5 minuti)." % (r["nome"], r["codice"][:3], r["codice"][3:]), dict(r, id=rid))
        except Exception:
            pass
    return 200, {"ok": True, "id": rid, "scade_tra": VALIDITA, "testo": "Inserisci il codice mostrato da Casa"}


def attese(adesso=None):
    """le richieste in attesa con il loro codice: SOLO per chi è già autorizzato (pannello, app collegate)."""
    adesso = adesso or time.time()
    with _lock:
        _pulisci(adesso)
        return [{"id": k, "nome": r["nome"], "codice": r["codice"], "resta": int(r["scade"] - adesso)} for k, r in
                sorted(_richieste.items(), key=lambda x: x[1]["creata"])]


def rifiuta(rid):
    with _lock:
        return _richieste.pop(str(rid or ""), None) is not None


def conferma(rid, codice, ip="", adesso=None):
    adesso = adesso or time.time()
    codice = re.sub(r"\D", "", str(codice or ""))
    with _lock:
        _pulisci(adesso)
        b = bloccato(adesso)
        if b:
            return 429, {"ok": False, "codice": "bloccato", "resta": b, "testo": "Troppi tentativi. Riprova tra %d min." % max(1, (b + 59) // 60)}
        r = _richieste.get(str(rid or ""))
        if r is None:
            return 404, {"ok": False, "codice": "scaduta", "testo": "Richiesta scaduta. Riprova."}
        if len(codice) != 6 or not hmac.compare_digest(codice, r["codice"]):
            _errori.append(adesso)
            if len(_errori) >= ERRORI_MAX:
                _blocco["fino"] = adesso + BLOCCO
                _errori.clear()
                _richieste.clear()
                return 429, {"ok": False, "codice": "bloccato", "resta": BLOCCO, "testo": "Troppi tentativi. Riprova tra 10 min."}
            return 400, {"ok": False, "codice": "errato", "restano": ERRORI_MAX - len(_errori), "testo": "Codice non valido"}
        _richieste.pop(rid, None)
        _errori.clear()
        chiave = secrets.token_urlsafe(32)
        did = "app-" + secrets.token_hex(4)
        d = _leggi()
        d["chiavi"].append({"id": did, "nome": r["nome"], "hash": _hash(chiave), "creata": int(adesso), "usata": int(adesso), "ip": ip or r["ip"]})
        if not _scrivi(d):
            return 500, {"ok": False, "codice": "disco", "testo": "Impossibile salvare. Riprova."}
    return 200, {"ok": True, "chiave": chiave, "dispositivo": did, "nome": r["nome"], "testo": "Collegato a Casa"}


# 0.10 — «Collega da fuori casa»: il pannello di Casa (dentro Home Assistant, quindi solo chi è già autorizzato) crea un
# invito monouso di 15 minuti; il link filtreo://collega?ponte=…&invito=… apre l'app, che si collega passando da Filtreo Cloud.
INVITO_VALIDITA = 900
_inviti = {}


def invito(adesso=None):
    adesso = adesso or time.time()
    t = secrets.token_urlsafe(24)
    with _lock:
        for h in [h for h, r in _inviti.items() if r["scade"] < adesso]:
            _inviti.pop(h, None)
        if len(_inviti) >= MAX_ATTESA:
            _inviti.pop(min(_inviti, key=lambda h: _inviti[h]["scade"]), None)
        _inviti[_hash(t)] = {"scade": adesso + INVITO_VALIDITA}
    return t


def usa_invito(t, nome, ip="", adesso=None):
    adesso = adesso or time.time()
    with _lock:
        b = bloccato(adesso)
        if b:
            return 429, {"ok": False, "codice": "bloccato", "resta": b, "testo": "Troppi tentativi. Riprova tra %d min." % max(1, (b + 59) // 60)}
        r = _inviti.pop(_hash(str(t or "").strip()), None) if 20 <= len(str(t or "").strip()) <= 64 else None
        if r is None or r["scade"] < adesso:
            _errori.append(adesso)
            if len(_errori) >= ERRORI_MAX:
                _blocco["fino"] = adesso + BLOCCO
                _errori.clear()
            return 404, {"ok": False, "codice": "scaduto", "testo": "Invito scaduto o già usato. Creane uno nuovo dal pannello di Casa."}
        _errori.clear()
        chiave = secrets.token_urlsafe(32)
        did = "app-" + secrets.token_hex(4)
        n = _nome(nome)
        d = _leggi()
        d["chiavi"].append({"id": did, "nome": n, "hash": _hash(chiave), "creata": int(adesso), "usata": int(adesso), "ip": str(ip or "")[:45]})
        if not _scrivi(d):
            return 500, {"ok": False, "codice": "disco", "testo": "Impossibile salvare. Riprova."}
    return 200, {"ok": True, "chiave": chiave, "dispositivo": did, "nome": n, "testo": "Collegato a Casa"}


def con_codice_dns(codice, nome, ip, codici, adesso=None):
    """0.10.1 — un dispositivo che ha già il suo filtro personale (il codice segreto dentro il suo indirizzo DNS) si collega da
    solo, anche da lontano: il codice prova che è lui. codici = i codici validi di Casa. Errori contati come per le 6 cifre."""
    adesso = adesso or time.time()
    codice = str(codice or "").strip()
    with _lock:
        b = bloccato(adesso)
        if b:
            return 429, {"ok": False, "codice": "bloccato", "resta": b, "testo": "Troppi tentativi. Riprova tra %d min." % max(1, (b + 59) // 60)}
        ok = 16 <= len(codice) <= 80 and any(hmac.compare_digest(codice, str(c)) for c in codici)
        if not ok:
            _errori.append(adesso)
            if len(_errori) >= ERRORI_MAX:
                _blocco["fino"] = adesso + BLOCCO
                _errori.clear()
            return 404, {"ok": False, "codice": "sconosciuto", "testo": "Dispositivo sconosciuto."}
        _errori.clear()
        chiave = secrets.token_urlsafe(32)
        did = "app-" + secrets.token_hex(4)
        n = _nome(nome)
        d = _leggi()
        d["chiavi"].append({"id": did, "nome": n, "hash": _hash(chiave), "creata": int(adesso), "usata": int(adesso), "ip": str(ip or "")[:45]})
        if not _scrivi(d):
            return 500, {"ok": False, "codice": "disco", "testo": "Impossibile salvare. Riprova."}
    return 200, {"ok": True, "chiave": chiave, "dispositivo": did, "nome": n, "testo": "Collegato a Casa"}


def chiave_valida(k, ip=""):
    """la voce del dispositivo se la chiave è di un'app collegata, altrimenti None."""
    k = (k or "").strip()
    if len(k) < 32 or len(k) > 128:
        return None
    h = _hash(k)
    for x in _leggi()["chiavi"]:
        if hmac.compare_digest(h, str(x.get("hash") or "")):
            adesso = time.time()
            if adesso - _uso_scritto.get(x["id"], 0) > 600:   # «ultimo uso» scritto al massimo ogni 10 minuti
                _uso_scritto[x["id"]] = adesso
                with _lock:
                    d = _leggi()
                    for y in d["chiavi"]:
                        if y.get("id") == x["id"]:
                            y["usata"] = int(adesso)
                            if ip:
                                y["ip"] = ip
                    _scrivi(d)
            return x
    return None


def chiave_da_intestazioni(headers):
    """la chiave dell'app da «Authorization: Bearer …» o da «X-Filtro»."""
    a = (headers.get("Authorization") or "").strip()
    if a.lower().startswith("bearer "):
        return a[7:].strip()
    return (headers.get("X-Filtro") or "").strip()


def elenco():
    return [{"id": x.get("id"), "nome": x.get("nome"), "creata": x.get("creata"), "usata": x.get("usata"), "ip": x.get("ip", "")}
            for x in _leggi()["chiavi"]]


def revoca(did):
    with _lock:
        d = _leggi()
        prima = len(d["chiavi"])
        d["chiavi"] = [x for x in d["chiavi"] if x.get("id") != did]
        if len(d["chiavi"]) == prima:
            return False, "Dispositivo non trovato."
        ok = _scrivi(d)
        return ok, ("Rimosso" if ok else "Impossibile salvare. Riprova.")


def azzera_per_prove():
    with _lock:
        _richieste.clear()
        _errori.clear()
        _blocco["fino"] = 0.0
