#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ha_integrazione.py — Filtreo dentro Home Assistant (e, col ponte HomeKit di HA, dentro l'app Casa e Siri).

Cosa fa
  1. apre una piccola porta HTTP (default 8098) con chiave (token) a cui parla l'integrazione «Filtreo»
     di Home Assistant (cartella custom_components/filtreo, qui accanto): stato, pausa, riprendi, modalità;
  2. se Home Assistant è sullo stesso apparecchio (add-on: cartella /homeassistant montata), copia da sola
     l'integrazione in /homeassistant/custom_components/filtreo e vi lascia l'indirizzo e la chiave:
     in Home Assistant basta «Aggiungi integrazione → Filtreo» e un clic;
  3. risponde al pannello (Impostazioni → «Home Assistant e HomeKit»): /pannello/ha/stato.

Non tocca mai il filtro da solo: ogni azione la chiede Home Assistant. La chiave sta in <DATA>/ha-token
(solo il proprietario la legge) e non viene mai scritta nei log.

Si spegne con l'opzione dell'add-on `integrazione_ha: false` (in /data/options.json) o con FILTREO_HA=0.
Porta: FILTREO_HA_PORTA (default 8098). Ascolto: FILTREO_HA_ASCOLTO (default 0.0.0.0).
Pannello e motore arrivano dal modulo filtreo_pannello, passato a avvia(): nessun import circolare.
"""
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORTA = int(os.environ.get("FILTREO_HA_PORTA", "8098") or 8098)
ASCOLTO = os.environ.get("FILTREO_HA_ASCOLTO", "0.0.0.0")
QUI = os.path.dirname(os.path.abspath(__file__))
COMPONENTE = os.path.join(QUI, "custom_components", "filtreo")   # l'integrazione che viaggia con l'app
# Home Assistant, visto dall'add-on (map: homeassistant_config). Su Jetson non esiste.
CONFIG_HA = os.environ.get("FILTREO_HA_CONFIG", "/homeassistant")
CACHE_SEC = 15

_pan = None            # il modulo filtreo_pannello (stato, pausa, liste…)
_stato = {"t": 0.0, "v": None}
_blocco = threading.Lock()
_contatto = {"t": 0.0}   # ultima richiesta autenticata di Home Assistant
_falliti = {"n": 0, "t": 0.0}


# ───────────── chiave ─────────────
def _data():
    return getattr(getattr(_pan, "filtro", None), "DATA", None) or os.environ.get("FILTREO_DATA", "/data")


def token():
    """la chiave dell'integrazione: da FILTREO_HA_TOKEN, altrimenti il file <DATA>/ha-token (creato al primo avvio)."""
    t = os.environ.get("FILTREO_HA_TOKEN", "").strip()
    if t:
        return t
    p = os.path.join(_data(), "ha-token")
    try:
        with open(p, encoding="utf-8") as f:
            t = f.read().strip()
        if len(t) >= 16:
            return t
    except OSError:
        pass
    t = secrets.token_hex(24)
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(t + "\n")
        os.replace(p + ".tmp", p)
    except OSError:
        pass   # senza disco la chiave vale fino al riavvio: HA si ricollega con «Reimposta»
    return t


def _nodo():
    """identificativo stabile di questo nodo (non rivela la chiave)"""
    return hashlib.sha256(("filtreo-nodo:" + token()).encode()).hexdigest()[:12]


# ───────────── lo stato per Home Assistant ─────────────
def _cloudflare_attivo():
    """il paracadute su Cloudflare è collegato e ha parlato di recente (conti ritirati nelle ultime 6 ore)"""
    try:
        liste = _pan.liste
        if not (liste._para_script() and liste._para_segreti()):
            return False
        return time.time() - os.path.getmtime(os.path.join(_data(), "cloudflare-conti.json")) < 6 * 3600
    except Exception:
        return False


def raccogli():
    """tutto quello che serve alle entità, in un solo JSON (in cache 15 s: il registro del giorno si legge una volta)"""
    with _blocco:
        if _stato["v"] is not None and time.time() - _stato["t"] < CACHE_SEC:
            return _stato["v"]
    s = _pan.stato()
    o = s.get("oggi") or {}
    p = s.get("pausa") or None
    try:
        e = _pan.liste.elenco()
    except Exception:
        e = {"dispositivi": [], "modalita": []}
    def _nome_profilo(m):   # 0.10.4: lo stesso nome che mostrano le app («Personale», «Standard · personalizzato»)
        try:
            return _pan.livelli.etichetta(m) or m.get("nome") or m["id"]
        except Exception:
            return m.get("nome") or m["id"]

    def _sotto_profilo(m):
        try:
            return _pan.livelli.sotto(m)
        except Exception:
            return ""
    modalita = [{"id": m["id"], "nome": _nome_profilo(m), "sotto": _sotto_profilo(m)} for m in (e.get("modalita") or []) if m]
    if e.get("pausa"):
        modalita.append({"id": e["pausa"]["id"], "nome": e["pausa"].get("nome") or e["pausa"]["id"]})
    visti, ids = set(), []
    for m in modalita:   # un id una volta sola
        if m["id"] not in visti:
            visti.add(m["id"])
            ids.append(m)
    disp = [{"id": d["id"], "nome": d.get("nome") or d["id"], "proprie": bool(d.get("proprie")), "modo": d.get("modo") or ""}
            for d in (e.get("dispositivi") or [])]
    v = {
        "nodo": _nodo(),
        "versione": getattr(_pan, "VERSIONE", "") or "",
        "raggiungibile": bool(s.get("raggiungibile")),
        "acceso": bool(s.get("acceso")),
        "pausa": {"attiva": bool(p), "resta_sec": int((p or {}).get("resta_sec") or 0),
                  "senza_scadenza": bool((p or {}).get("senza_scadenza"))},
        "pausa_durata": s.get("pausa_durata") or "10m",
        "oggi": {"richieste": int(o.get("richieste") or 0), "bloccate": int(o.get("bloccate") or 0),
                 "percento": int(o.get("percento") or 0)},
        "dispositivi": disp,
        "modalita": ids,
        "cloudflare": _cloudflare_attivo(),
    }
    with _blocco:
        _stato["v"], _stato["t"] = v, time.time()
    return v


def _dimentica_cache():
    with _blocco:
        _stato["v"] = None


# ───────────── azioni (tutte passano dalle stesse funzioni del pannello) ─────────────
def azione_pausa(minuti):
    try:
        m = int(float(str(minuti).replace(",", ".")))
    except (ValueError, TypeError):
        return False, "Durata della pausa non indicata."
    if not 1 <= m <= _pan.filtro.MAX_PAUSA_MIN:
        return False, "Durata della pausa: da 1 a %d minuti." % _pan.filtro.MAX_PAUSA_MIN
    t = _pan.filtro.pausa(m)
    ok = t.startswith("Filtro in pausa")
    if ok:
        _pan._segna_pausa(m * 60)
        _pan.pausa_cambiata()
    return ok, t


def azione_spegni():
    """«interruttore su spento» = pausa con la durata che il pannello ricorda (scudo)"""
    t = _pan.pausa_scelta()
    return ("Filtro" in t and not t.startswith("Impossibile")), t


def azione_riprendi():
    t = _pan.pausa_cambiata(_pan.filtro.riprendi())
    return not t.startswith("Impossibile"), t


def azione_modo(did, mid):
    return _pan.liste.imposta_modo(did, mid)



# ───────────── 0.10.3: Home Assistant chiede il collegamento, tu lo consenti nel pannello (niente chiavi da copiare) ─────────────
# Vale per Home Assistant su un altro apparecchio (per esempio Casa sul Jetson e Home Assistant su un altro computer):
# Home Assistant trova Filtreo da solo (Bonjour), chiede il collegamento SOLO dalla rete di casa, e riceve la chiave
# solo dopo «Consenti» nel pannello di Filtreo (o in un'app già collegata). Con l'app dentro Home Assistant OS non serve:
# lì l'integrazione trova la chiave in collegamento.json.
import ipaddress  # noqa: E402

RICHIESTA_VALIDITA = 600
_richieste_ha = {}   # id → {"nome", "ip", "scade", "stato": attesa|consentito|rifiutato}
_lock_ha = threading.Lock()
_RETI_PRIVATE = [ipaddress.ip_network(r) for r in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                  "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


def _privato(ip):
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0])
        if getattr(a, "ipv4_mapped", None):
            a = a.ipv4_mapped
        return any(a in r for r in _RETI_PRIVATE)
    except ValueError:
        return False


def _pulisci_ha(adesso):
    for k in [k for k, r in _richieste_ha.items() if r["scade"] < adesso]:
        _richieste_ha.pop(k, None)


def chiedi_collegamento(nome, ip, adesso=None):
    adesso = adesso or time.time()
    if not _privato(ip):
        return 403, {"ok": False, "testo": "Collega Home Assistant dalla rete di casa."}
    with _lock_ha:
        _pulisci_ha(adesso)
        if sum(1 for r in _richieste_ha.values() if r["stato"] == "attesa") >= 3:
            return 429, {"ok": False, "testo": "Troppe richieste in attesa. Riprova tra qualche minuto."}
        rid = secrets.token_urlsafe(18)
        n = " ".join(str(nome or "Home Assistant").split())[:40] or "Home Assistant"
        _richieste_ha[rid] = {"nome": n, "ip": str(ip)[:45], "scade": adesso + RICHIESTA_VALIDITA, "stato": "attesa"}
    return 200, {"ok": True, "id": rid, "scade_tra": RICHIESTA_VALIDITA}


def esito_collegamento(rid, adesso=None):
    adesso = adesso or time.time()
    with _lock_ha:
        _pulisci_ha(adesso)
        r = _richieste_ha.get(str(rid or ""))
        if not r:
            return 404, {"stato": "scaduta"}
        if r["stato"] == "consentito":
            _richieste_ha.pop(rid, None)   # la chiave si consegna una volta sola
            return 200, {"stato": "consentito", "token": token(), "nodo": _nodo()}
        if r["stato"] == "rifiutato":
            _richieste_ha.pop(rid, None)
        return 200, {"stato": r["stato"]}


def richieste_ha(adesso=None):
    """per il pannello e le app già collegate (già autorizzati): le richieste di Home Assistant in attesa."""
    adesso = adesso or time.time()
    with _lock_ha:
        _pulisci_ha(adesso)
        return [{"id": k, "nome": r["nome"], "ip": r["ip"], "resta": int(r["scade"] - adesso)}
                for k, r in _richieste_ha.items() if r["stato"] == "attesa"]


def decidi_ha(rid, consenti):
    with _lock_ha:
        r = _richieste_ha.get(str(rid or ""))
        if not r or r["stato"] != "attesa":
            return False, "Richiesta scaduta"
        r["stato"] = "consentito" if consenti else "rifiutato"
        r["scade"] = time.time() + 120
    return True, ("Home Assistant collegato" if consenti else "Richiesta rifiutata")

# ───────────── la porta HTTP per Home Assistant ─────────────
class _H(BaseHTTPRequestHandler):
    server_version = "Filtreo-HA"

    def _json(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _chiave_ok(self):
        h = self.headers.get("Authorization", "")
        dato = h[7:].strip() if h.lower().startswith("bearer ") else ""
        if dato and hmac.compare_digest(dato.encode(), token().encode()):
            _contatto["t"] = time.time()
            return True
        if time.time() - _falliti["t"] > 60:
            _falliti["n"] = 0
        _falliti["n"] += 1
        _falliti["t"] = time.time()
        if _falliti["n"] > 5:
            time.sleep(1.5)   # chi prova chiavi a caso va piano
        self._json(401, {"errore": "chiave errata"})
        return False

    def do_GET(self):
        u = urlparse(self.path).path.rstrip("/")
        if u == "/ha/v1/salute":   # senza chiave: serve solo a capire «qui c'è Filtreo?»
            return self._json(200, {"ok": True, "filtreo": True, "versione": getattr(_pan, "VERSIONE", "") or ""})
        if u.startswith("/ha/v1/collega/"):   # 0.10.3: Home Assistant aspetta il «Consenti» (id segreto, chiave una volta sola)
            code, obj = esito_collegamento(u.rsplit("/", 1)[-1])
            return self._json(code, obj)
        if not self._chiave_ok():
            return
        if u == "/ha/v1/stato":
            try:
                return self._json(200, raccogli())
            except Exception as e:
                return self._json(500, {"errore": str(e)[:200]})
        return self._json(404, {"errore": "?"})

    def do_POST(self):
        if urlparse(self.path).path.rstrip("/") == "/ha/v1/collega":   # 0.10.3: richiesta di collegamento, solo dalla rete di casa
            try:
                n = int(self.headers.get("Content-Length") or 0)
                d = json.loads(self.rfile.read(min(n, 4096)) or b"{}") if n else {}
            except Exception:
                d = {}
            code, obj = chiedi_collegamento(d.get("nome") if isinstance(d, dict) else "", self.client_address[0])
            return self._json(code, obj)
        if not self._chiave_ok():
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path.rstrip("/")
        g = lambda k: q.get(k, [""])[0]  # noqa: E731
        try:
            if p == "/ha/v1/pausa":
                ok, t = azione_pausa(g("min"))
            elif p == "/ha/v1/spegni":
                ok, t = azione_spegni()
            elif p == "/ha/v1/riprendi":
                ok, t = azione_riprendi()
            elif p == "/ha/v1/modo":
                ok, t = azione_modo(g("id"), g("m"))
            else:
                return self._json(404, {"errore": "?"})
            _dimentica_cache()
            return self._json(200 if ok else 400, {"ok": ok, "testo": t})
        except Exception as e:
            return self._json(500, {"ok": False, "testo": str(e)[:200]})

    def log_message(self, *a):
        pass


# ───────────── installazione dell'integrazione in Home Assistant (solo add-on) ─────────────
def _versione_manifest(cartella):
    try:
        with open(os.path.join(cartella, "manifest.json"), encoding="utf-8") as f:
            return str(json.load(f).get("version", ""))
    except Exception:
        return ""


def _opzione_attiva():
    """opzione dell'add-on `integrazione_ha` (default sì); FILTREO_HA=0 la spegne anche su Jetson"""
    if os.environ.get("FILTREO_HA", "1").strip() in ("0", "no", "false"):
        return False
    try:
        with open("/data/options.json", encoding="utf-8") as f:
            return json.load(f).get("integrazione_ha", True) is not False
    except Exception:
        return True


def installa_integrazione():
    """copia custom_components/filtreo in Home Assistant e vi lascia collegamento.json (porta + chiave).
    Ritorna 'installata' | 'aggiornata' | 'gia' | 'assente' (HA non è qui) | 'errore'."""
    if not os.path.isdir(CONFIG_HA) or not os.path.isfile(os.path.join(COMPONENTE, "manifest.json")):
        return "assente"
    dest = os.path.join(CONFIG_HA, "custom_components", "filtreo")
    try:
        nuovo = _versione_manifest(COMPONENTE)
        esisteva = os.path.isfile(os.path.join(dest, "manifest.json"))
        esito = "gia"
        if not esisteva or _versione_manifest(dest) != nuovo:
            os.makedirs(dest, exist_ok=True)
            for radice, cartelle, files in os.walk(COMPONENTE):
                cartelle[:] = [c for c in cartelle if c != "__pycache__"]
                rel = os.path.relpath(radice, COMPONENTE)
                os.makedirs(os.path.join(dest, rel), exist_ok=True)
                for f in files:
                    if f.endswith(".pyc"):
                        continue
                    shutil.copyfile(os.path.join(radice, f), os.path.join(dest, rel, f))
            esito = "aggiornata" if esisteva else "installata"
        coll = os.path.join(dest, "collegamento.json")
        dati = {"porta": PORTA, "token": token(), "nodo": _nodo()}
        try:
            if json.load(open(coll, encoding="utf-8")) == dati:
                return esito
        except Exception:
            pass
        fd = os.open(coll + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(dati, f)
        os.replace(coll + ".tmp", coll)
        return esito
    except OSError as e:
        sys.stderr.write("Filtreo: non riesco a copiare l'integrazione in Home Assistant (%s)\n" % str(e)[:120])
        return "errore"


# ───────────── pannello: Impostazioni → «Home Assistant e HomeKit» ─────────────
def stato_pannello():
    attiva = _server["srv"] is not None
    inst = os.path.isfile(os.path.join(CONFIG_HA, "custom_components", "filtreo", "manifest.json"))
    ultimo = _contatto["t"]
    return {
        "attiva": attiva,
        "porta": PORTA,
        "in_ha": os.path.isdir(CONFIG_HA),          # add-on dentro Home Assistant
        "installata": inst,                          # l'integrazione è già nella cartella di HA
        "collegata": bool(ultimo) and time.time() - ultimo < 120,   # HA ha parlato nell'ultimo minuto
        "ultimo_contatto": int(ultimo) if ultimo else 0,
        "token": token() if attiva else "",
        "versione_integrazione": _versione_manifest(COMPONENTE),
    }


def pannello_get(h, u):
    """rotte GET del pannello: /pannello/ha/stato. `h` è il gestore HTTP del pannello (già filtrato da HA)."""
    if u == "/pannello/ha/stato":
        return h._json(200, stato_pannello())
    return h._json(404, {"errore": "pagina sconosciuta"})


# ───────────── avvio ─────────────
_server = {"srv": None}


def avvia(pannello):
    """chiamato una volta dal pannello all'avvio. Mai un errore: se qualcosa non va, il pannello va avanti da solo."""
    global _pan
    _pan = pannello
    if not _opzione_attiva():
        sys.stderr.write("Filtreo: integrazione Home Assistant spenta dalle opzioni\n")
        return False
    try:
        token()
        srv = ThreadingHTTPServer((ASCOLTO, PORTA), _H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        _server["srv"] = srv
        sys.stderr.write("Filtreo: porta per Home Assistant attiva sulla %d\n" % PORTA)
    except Exception as e:
        sys.stderr.write("Filtreo: porta per Home Assistant non attiva (%s)\n" % str(e)[:120])
        return False
    r = installa_integrazione()
    if r in ("installata", "aggiornata"):
        sys.stderr.write("Filtreo: integrazione %s in Home Assistant. Riavvia Home Assistant.\n" % r)
    return True
