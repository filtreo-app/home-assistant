import time
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtro.py — il "cervello" di Filtreo per il Pi di Giò (versione add-on Home Assistant).
Stesso motore di casa di Davide: Blocky. Qui i percorsi stanno sotto /data (persistente).

Funzioni usate dal pannello: blocca/sblocca/pausa/riprendi + _ricarica, _righe, _scrivi, _dominio.
"""
import json
import os
import re
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta

DATA = os.environ.get("FILTREO_DATA", "/data")
CASA = os.path.join(DATA)
LISTE = os.path.join(DATA, "liste")
REGISTRO = os.path.join(DATA, "log")
MOTORE = int(os.environ.get("FILTREO_MOTORE", "4000") or 4000)   # porta di controllo di Blocky
API = "http://127.0.0.1:%d" % MOTORE
MAX_PAUSA_MIN = 480
ORA_DOMANI = int(os.environ.get("FILTREO_DOMANI_ORA", "7") or 7)   # «Fino a domani» = alle ORA_DOMANI:00 locali del giorno dopo (0 = mezzanotte)


def fine_domani(adesso=None):
    """istante (secondi epoch) di «domani»: le ORA_DOMANI:00 locali (Europe/Rome) del giorno dopo; prima di quell'ora (es. 00:30)
    è stamattina. Una sola definizione per Rete, dispositivi, pannello e Cloud."""
    adesso = time.time() if adesso is None else adesso
    try:
        from zoneinfo import ZoneInfo
        ora = datetime.fromtimestamp(adesso, ZoneInfo("Europe/Rome"))
    except Exception:
        ora = datetime.fromtimestamp(adesso)
    dom = ora.replace(hour=ORA_DOMANI, minute=0, second=0, microsecond=0)
    if ora >= dom:
        dom = (ora + timedelta(days=1)).replace(hour=ORA_DOMANI, minute=0, second=0, microsecond=0)
    return dom.timestamp()


def _api(percorso, metodo="GET", attesa=8):
    try:
        req = urllib.request.Request(API + percorso, method=metodo)
        with urllib.request.urlopen(req, timeout=attesa) as r:
            return r.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return None, "errore %s: %s" % (e.code, e.read().decode("utf-8", "replace")[:150])
    except Exception as e:
        return None, str(e)[:150]


def _dominio(testo):
    t = (testo or "").strip().lower()
    t = re.sub(r"^[a-z]+://", "", t)
    t = t.split("/")[0].split("?")[0].split(":")[0]
    if t.startswith("*."):
        t = t[2:]
    t = t.strip(".")
    if re.fullmatch(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,24}", t):
        return t
    return None


def _righe(nome):
    try:
        return open(os.path.join(LISTE, nome), encoding="utf-8").read().splitlines()
    except OSError:
        return []


MODIFICHE = [0]   # quante volte un file delle liste è davvero cambiato (serve a non ricaricare per niente)


def _scrivi(nome, righe):
    p = os.path.join(LISTE, nome)
    nuovo = "\n".join(righe).rstrip("\n") + "\n"
    try:
        with open(p, encoding="utf-8") as f:
            if f.read() == nuovo:
                return False   # identico: non si riscrive e il motore non ha niente da ricaricare
    except OSError:
        pass
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(nuovo)
    os.replace(tmp, p)
    MODIFICHE[0] += 1
    return True


# Una ricarica alla volta: Blocky rilegge TUTTI i gruppi insieme (memoria doppia mentre lo fa) e, mentre lavora, risponde
# con le liste di prima (nessun buco). Più ricariche insieme = memoria che sale e, sui piccoli (Pi, Jetson), il sistema
# che uccide Blocky. Chi chiede mentre un'altra è in corso aspetta il suo turno; se nel frattempo ne è partita una dopo
# la sua richiesta, quella ha già visto i suoi file e non ne parte un'altra.
_rich = {"gen": 0, "fatto": 0, "mod": -1}
_mx = threading.Lock()
_un_giro = threading.Lock()


def da_ricaricare():
    """True se dopo l'ultima ricarica riuscita è cambiato qualche file delle liste."""
    return MODIFICHE[0] != _rich["mod"]


def _ricarica(attesa=900):
    with _mx:
        _rich["gen"] += 1
        mia = _rich["gen"]
    with _un_giro:
        if _rich["fatto"] >= mia:
            return True
        with _mx:
            partita, mod = _rich["gen"], MODIFICHE[0]
        _t, err = _api("/api/lists/refresh", "POST", attesa=attesa)
        if err is None:
            with _mx:
                _rich["fatto"], _rich["mod"] = partita, mod
        return err is None


def ricarica_async(motivo=""):
    """ricarica in sottofondo e torna subito (il pannello risponde senza aspettare; lo stato dice «Applico…»)."""
    import applicazione
    applicazione.inizia("ricarica", motivo)

    def lavoro():
        ok = False
        try:
            ok = _ricarica()
        finally:
            applicazione.finisci(1, ok)
    threading.Thread(target=lavoro, daemon=True).start()
    return True


def _modifica(dominio, aggiungi_a, togli_da):
    voce = "*." + dominio
    a = _righe(aggiungi_a)
    if voce not in [r.strip() for r in a]:
        a.append(voce)
        _scrivi(aggiungi_a, a)
    d = _righe(togli_da)
    nuove = [r for r in d if r.strip() != voce]
    if len(nuove) != len(d):
        _scrivi(togli_da, nuove)
    return ricarica_async("blocca/sblocca " + dominio) if da_ricaricare() else True


def sblocca(dominio):
    d = _dominio(dominio)
    if not d:
        return "Sito non valido. Inserisci solo il nome, per esempio sito.it"
    ok = _modifica(d, "sblocca.txt", "blocca.txt")
    return ("%s è consentito." % d) if ok else ("%s salvato. Impossibile ricaricare i filtri: riprova." % d)


def blocca(dominio):
    d = _dominio(dominio)
    if not d:
        return "Sito non valido. Inserisci solo il nome, per esempio sito.it"
    ok = _modifica(d, "blocca.txt", "sblocca.txt")
    return ("%s è bloccato. Per annullare: consenti %s" % (d, d)) if ok else ("%s salvato. Impossibile ricaricare i filtri." % d)


def annulla_blocco(dominio):
    d = _dominio(dominio)
    if not d:
        return False, "Sito non valido. Inserisci solo il nome, per esempio sito.it"
    righe = _righe("blocca.txt")
    nuove = [r for r in righe if r.strip() not in ("*." + d, d)]
    if len(nuove) == len(righe):
        return False, "%s non era tra i tuoi blocchi." % d
    _scrivi("blocca.txt", nuove)
    ok = ricarica_async("annulla blocco " + d) if da_ricaricare() else True
    return True, ("Annullato: %s ripristinato." % d) if ok else ("%s rimosso dai siti bloccati. Impossibile ricaricare i filtri: riprova." % d)


def pausa(minuti, gruppo=""):
    try:
        m = int(float(str(minuti).strip().replace(",", ".")))
    except (ValueError, TypeError):
        return "Durata della pausa non indicata."
    if m < 1:
        return "Durata minima della pausa: 1 minuto."
    m = min(m, MAX_PAUSA_MIN)
    _togli_timer()
    err = _api_riprova("/api/blocking/disable?duration=%dm" % m)
    if err:
        return "Impossibile mettere in pausa (%s)." % err
    fine = (datetime.now() + timedelta(minutes=m)).strftime("%H:%M")
    return "Filtro in pausa per %d min. Riprende alle %s." % (m, fine)


TIMER_FILE = os.path.join(DATA, "pausa-timer.json")   # riserva per le pause brevi (30 s) se Blocky non accetta «30s»


def _togli_timer():
    try:
        os.remove(TIMER_FILE)
    except OSError:
        pass


def _timer_resta():
    """secondi che mancano alla riattivazione programmata da noi (0 = nessun timer)"""
    try:
        with open(TIMER_FILE, encoding="utf-8") as f:
            return max(0, int(json.load(f)["fine"] - time.time() + 0.999))
    except Exception:
        return 0


def pausa_secondi(sec):
    """pausa breve (30 s). Prima la durata di Blocky («30s», formato Go); se non la accetta: pausa senza scadenza
    + riattivazione programmata qui (file pausa-timer.json, riletto da avvia_timer: regge ai riavvii)."""
    sec = max(1, int(sec))
    _togli_timer()
    # sempre la nostra riattivazione: Blocky con durate sotto il minuto non riporta il tempo che resta
    # (lo stato sembrerebbe «Senza scadenza»)
    err = _api_riprova("/api/blocking/disable")
    if err:
        return "Impossibile mettere in pausa (%s)." % err
    try:
        with open(TIMER_FILE, "w", encoding="utf-8") as f:
            json.dump({"fine": time.time() + sec}, f)
    except OSError:
        pass
    fine = (datetime.now() + timedelta(seconds=sec)).strftime("%H:%M:%S")
    return "Filtro in pausa per %d secondi. Riprende alle %s." % (sec, fine)


def _giro_timer():
    if os.path.exists(TIMER_FILE) and _timer_resta() == 0:
        _t, err = _api("/api/blocking/enable")
        if err is None:
            _togli_timer()


def avvia_timer():
    """controlla ogni 2 secondi la riattivazione programmata; se il pannello era spento alla scadenza, riaccende subito all'avvio"""
    def corri():
        while True:
            try:
                _giro_timer()
            except Exception:
                pass
            time.sleep(2)
    threading.Thread(target=corri, daemon=True).start()


def _api_riprova(percorso, volte=6):
    """lo scudo deve funzionare anche se il motore sta rileggendo le liste: qualche secondo di pazienza."""
    err = None
    for i in range(volte):
        _t, err = _api(percorso)
        if err is None:
            return None
        time.sleep(2)
    return err


def riprendi():
    _togli_timer()
    err = _api_riprova("/api/blocking/enable")
    return "Filtro attivo." if not err else ("Impossibile riprendere (%s)." % err)


def stato_api():
    t, err = _api("/api/blocking/status", attesa=4)
    try:
        b = json.loads(t) if t else {}
    except ValueError:
        b = {}
    acceso = bool(b.get("enabled", False)) and not b.get("disabledGroups")
    pausa_info = None
    if not err and not acceso:
        sec = _timer_resta() or int(b.get("autoEnableInSec") or 0)
        adesso = datetime.now()
        fine = adesso + timedelta(seconds=sec)
        pausa_info = {"fino": fine.strftime("%H:%M") if sec else "", "resta_sec": sec,
                      "fino_domani": bool(sec) and fine.date() != adesso.date(),
                      "senza_scadenza": (not b.get("enabled", False)) and not sec}
    if err and _timer_resta():   # motore occupato (sta rileggendo le liste) ma la pausa breve è nostra: la si conosce lo stesso
        sec = _timer_resta()
        acceso = False
        pausa_info = {"fino": (datetime.now() + timedelta(seconds=sec)).strftime("%H:%M"), "resta_sec": sec,
                      "fino_domani": False, "senza_scadenza": False}
    return {"raggiungibile": not err, "acceso": acceso, "pausa": pausa_info}
