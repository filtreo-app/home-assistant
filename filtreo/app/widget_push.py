"""0.10.5 — il widget dell'iPhone si aggiorna con un avviso di Casa (WidgetKit push, iOS 26), non chiedendo di continuo.

Risparmio di energia: l'iPhone non interroga mai Casa per niente. Casa manda un avviso silenzioso SOLO quando cambia
quello che il widget mostra:
  • subito: filtro acceso/spento, pausa iniziata/finita/cambiata (della Rete o di quel dispositivo), nuovo giorno;
  • i numeri: quando le bloccate di oggi crescono in modo visibile (almeno +5% e +20), e non più di una volta ogni 30 minuti.
Ogni avviso costa all'iPhone una sola lettura piccola. Un token che Apple rifiuta si dimentica da solo.
"""
import json, os, re, threading, time

STATO_SUBITO_MIN = 60          # tra due avvisi di stato: almeno 1 minuto
NUMERI_MIN = 30 * 60           # tra due avvisi per i numeri: almeno 30 minuti
CRESCITA_MIN = 20              # bloccate in più, almeno
CRESCITA_PERC = 0.05           # e almeno il 5%
SCADENZA = 30 * 24 * 3600      # un token non rinnovato da 30 giorni si dimentica

_l = threading.Lock()


def _leggi(f):
    try:
        with open(f, encoding="utf-8") as h:
            d = json.load(h)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _scrivi(f, d):
    tmp = f + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        json.dump(d, h)
    os.replace(tmp, f)
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass


def registra(f, dati, adesso=None):
    """POST /pannello/widget/registra {token, ambiente, dispositivo}. Ritorna (codice, risposta)."""
    tok = str(dati.get("token") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32,256}", tok):
        return 400, {"ok": False, "testo": "Dati non validi."}
    adesso = adesso or time.time()
    with _l:
        d = _leggi(f)
        vecchio = d.get(tok) or {}
        d[tok] = {"ambiente": "sandbox" if dati.get("ambiente") == "sandbox" else "production",
                  "dispositivo": str(dati.get("dispositivo") or "")[:80],
                  "visto": adesso, "firma": vecchio.get("firma", ""), "bloccate": vecchio.get("bloccate", 0),
                  "ultimo_stato": vecchio.get("ultimo_stato", 0), "ultimo_numeri": vecchio.get("ultimo_numeri", 0),
                  "inviati": vecchio.get("inviati", 0)}
        _scrivi(f, d)
    return 200, {"ok": True}


def firma_stato(st, pausa, dispositivo, giorno):
    """quello che il widget mostra oltre ai numeri: acceso, pausa della Rete, pausa di questo dispositivo, giorno."""
    rete = (pausa or {}).get("rete") or {}
    mia = ""
    rif = (dispositivo or "").lower()
    for p in (pausa or {}).get("dispositivi") or []:
        if rif and rif in (str(p.get("id", "")).lower(), str(p.get("nome", "")).lower()):
            mia = "%s|%s" % (p.get("fino_ms") or "", p.get("senza"))
    return "|".join([str(bool(st.get("acceso"))), str(bool(rete.get("attiva"))), str(rete.get("fino_ms") or ""), mia, giorno])


def decidi(rec, firma, bloccate, adesso):
    """None = niente avviso; altrimenti "stato" o "numeri"."""
    if firma != rec.get("firma"):
        if adesso - float(rec.get("ultimo_stato") or 0) >= STATO_SUBITO_MIN:
            return "stato"
        return None
    prima = int(rec.get("bloccate") or 0)
    crescita = bloccate - prima
    if crescita >= CRESCITA_MIN and crescita >= prima * CRESCITA_PERC and adesso - float(rec.get("ultimo_numeri") or 0) >= NUMERI_MIN:
        return "numeri"
    return None


def giro(f, leggi_stato, leggi_pausa, invia, adesso=None):
    """un giro: ritorna [(token, motivo, ok, errore)]. leggi_stato() → stato() di Casa; invia(token, payload, ambiente, tipo, priorita)."""
    adesso = adesso or time.time()
    with _l:
        d = _leggi(f)
        if not d:
            return []
        st = leggi_stato() or {}
        pausa = leggi_pausa() or {}
        bloccate = int(((st.get("oggi") or {}).get("bloccate")) or 0)
        giorno = time.strftime("%Y-%m-%d", time.localtime(adesso))
        fatti, cambiato = [], False
        for tok, rec in list(d.items()):
            if adesso - float(rec.get("visto") or 0) > SCADENZA:
                d.pop(tok, None); cambiato = True; continue
            firma = firma_stato(st, pausa, rec.get("dispositivo"), giorno)
            if not rec.get("firma"):            # primo giro: si prende nota, senza avvisare
                rec.update(firma=firma, bloccate=bloccate); cambiato = True; continue
            motivo = decidi(rec, firma, bloccate, adesso)
            if not motivo:
                continue
            ok, err = invia(tok, {"aps": {"content-changed": True}}, rec.get("ambiente", "production"), "widgets",
                            "10" if motivo == "stato" else "5")
            fatti.append((tok, motivo, ok, err))
            cambiato = True
            if ok:
                rec["inviati"] = int(rec.get("inviati") or 0) + 1
                rec["firma"], rec["bloccate"] = firma, bloccate
                rec["ultimo_stato" if motivo == "stato" else "ultimo_numeri"] = adesso
                if motivo == "stato":
                    rec["ultimo_numeri"] = adesso   # l'avviso di stato porta anche i numeri nuovi
            elif any(x in (err or "") for x in ("BadDeviceToken", "Unregistered", "ExpiredToken", "DeviceTokenNotForTopic")):
                d.pop(tok, None)
        if cambiato:
            _scrivi(f, d)
    return fatti
