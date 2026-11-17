#!/usr/bin/env python3
"""FILTREO — tiene il paracadute (Cloudflare) uguale a casa, SENZA nuovo deploy.

A ogni giro:
 1. legge la coda «cambi_in_attesa» (modalità cambiate dalla pagina di riserva mentre casa era spenta) e la applica
    nel pannello di casa (POST /pannello/modo), così casa e paracadute restano uguali; poi la svuota;
 2. ricalcola «impronta del codice → profilo» (lavoro | pulito | spento:<fino>:<dopo> | pausa; con la protezione famiglia
    il profilo ha il suffisso «+f»: lavoro+f, pulito+f) e, se è cambiato,
    lo scrive nel KV (chiave «codici»): il paracadute lo rilegge da solo entro circa un minuto;
 3. scrive «pannello» (impronta del codice del pannello da fuori casa, nome e indirizzo di casa: serve alla pagina
    di riserva) e «stato» (dispositivi, modalità, ora dell'ultimo contatto, numeri di oggi: serve alla pagina di riserva
    e al widget quando casa non risponde).
I codici segreti non escono mai: escono solo le loro impronte (sha256).
 4. pausa: la pausa del pannello (o lo «Spento») vale anche su Cloudflare, dove passano i profili dei telefoni. Lo script legge da Blocky
    com'è adesso la pausa e scrive nel KV la chiave «pausa» ({"attiva":true,"senza":false,"fino":<ms UTC>} oppure {"attiva":false}) SOLO se è
    cambiata rispetto a quanto ha già scritto: una scrittura per cambio (il KV gratis ne concede 1.000 al giorno). Il worker la legge
    al massimo ogni ~30 s e rispetta la scadenza anche se Casa è spenta; una pausa a tempo che finisce da sola non richiede nessuna scrittura.
    Se Blocky non risponde non si cambia niente. Le scritture che accendono la pausa sono al massimo 300 al giorno; quelle che la tolgono non hanno limite.

5. pausa del DISPOSITIVO: se un dispositivo ha il campo «pausa» in dispositivi.json (fino = secondi epoch, 0 = senza scadenza) i suoi codici ricevono
    «spento:<fino ms>:<profilo dopo>» (+ «:x» se il dispositivo non ha regole sue: il worker allora non chiede a Casa). Il worker rimette da solo il profilo
    di prima alla scadenza, anche con Casa spenta. Nessun nome o dato personale esce: solo l'orario di fine, dentro il profilo di un codice già anonimo (impronta).

Uso:
  paracadute-sync.py                    fa il giro (lo chiama il pannello dopo ogni cambio e ogni 10 minuti)
  paracadute-sync.py --forza            scrive nel KV anche se non è cambiato niente
  paracadute-sync.py --codici FILE      scrive solo il JSON dei codici in FILE (per paracadute-dati.sh), non tocca il KV
  paracadute-sync.py --solo-pausa       copia SOLO la pausa su Cloudflare (lo chiama il pannello quando la pausa comincia o finisce)
Opzioni per prove: --data DIR  --segreti FILE  --api URL  --pannello URL (pannello di casa, di solito http://127.0.0.1:8446)
  --url-casa URL (indirizzo pubblico di casa; di solito FILTREO_DOH_URL)

Segreti (una riga NOME=valore ciascuno; il file NON si stampa mai):
  ~/filtreo15/segreti/cloudflare.env   (nel contenitore del pannello: /segreti/cloudflare.env)
  CF_TOKEN=…     token API con il permesso «Workers KV Storage: Edit»
  CF_ACCOUNT=…   id dell'account Cloudflare (32 caratteri)
  CF_KV_NS=…     id del namespace FILTREO_KV (32 caratteri; lo scrive PARACADUTE.command)
  CF_CONTEGGI=…  segreto per leggere i conteggi dei blocchi di Cloudflare (lo scrive CLOUDFLARE-CONTEGGI.command)
Conteggi: a ogni giro (al massimo uno ogni 4 minuti) legge GET <paracadute>/conti e scrive data/cloudflare-conti.json
  ({giorno: {id dispositivo: {b: bloccate, r: richieste, o: [24 numeri, le bloccate per ora di Roma]}}}; «o» c'è solo col worker
  nuovo); il pannello li somma ai suoi. Se Cloudflare non risponde o il
  segreto manca, il file resta com'era (il pannello conta solo Casa) e non è un errore.
Se il file manca o è incompleto: non fa niente ed esce senza errore (il pannello non se ne accorge nemmeno).
Solo libreria standard di Python 3.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    import fcntl
except ImportError:  # non su Linux/Mac: niente lucchetto, va bene lo stesso
    fcntl = None

API = "https://api.cloudflare.com/client/v4"
PRINCIPALE = "casa"
ESA32 = re.compile(r"^[0-9a-f]{32}$")
OGNI_CONTI = 240   # i conteggi di Cloudflare si ritirano al massimo ogni 4 minuti
OGNI_STATO = 300   # «stato» (ora dell'ultimo contatto) si riscrive almeno ogni 5 minuti di giri, non di più
MAX_STATO_DISP = 40
TOLLERANZA_PAUSA_MS = 120000   # «fino» di Blocky balla di qualche secondo da una lettura all'altra: sotto i 2 minuti è la stessa pausa
SENZA_FINE_MS = 9999999999999  # «senza scadenza» di un dispositivo nel profilo del worker: una scadenza lontanissima (anno 2286)
MAX_PAUSE_AL_GIORNO = 300      # scritture che ACCENDONO la pausa, al giorno (le altre chiavi usano il resto del limite gratuito)


def _json(p, base):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return base


class DatiIllegibili(Exception):
    pass


def _json_obbligatorio(p, tipo, vuoto_se_manca=None):
    """i dati del filtro DEVONO leggersi: meglio non scrivere niente che mandare al paracadute profili sbagliati
    (per esempio un elenco vuoto mentre il pannello sta salvando = tutti i telefoni senza servizio)."""
    if vuoto_se_manca is not None and not os.path.exists(p):
        return vuoto_se_manca   # filtro appena installato: nessun profilo «fuori casa» ancora creato
    try:
        with open(p, encoding="utf-8") as f:
            x = json.load(f)
    except (OSError, ValueError):
        raise DatiIllegibili(os.path.basename(p))
    if not isinstance(x, tipo):
        raise DatiIllegibili(os.path.basename(p))
    return x


def calcola(D):
    """{impronta sha256 del codice: profilo} e {nome: profilo} (i nomi servono solo per il riepilogo)."""
    modi = {m["id"]: m for m in _json_obbligatorio(os.path.join(D, "modalita.json"), list) if isinstance(m, dict) and m.get("id")}
    disp = [d for d in _json_obbligatorio(os.path.join(D, "dispositivi.json"), list) if isinstance(d, dict)]
    dp = _json_obbligatorio(os.path.join(D, "dns-personale.json"), dict, {})
    princ = next((d for d in disp if d.get("principale")), None) or next((d for d in disp if d.get("id") == PRINCIPALE), {})

    def di_modo(modo):
        if modo in ("spento", "pausa"):
            return modo
        m = modi.get(modo) or {}
        if m.get("fuori") in ("pulito", "lavoro", "spento"):   # profili pronti per casa intelligente: il profilo più vicino (i .bin non sanno fare altro)
            p = m["fuori"]
        else:
            p = "lavoro" if m.get("lavoro") else "pulito"
        # «Protezione famiglia» (adulti e scommesse): suffisso «+f», il worker aggiunge famiglia.bin. «Senza filtro» resta senza.
        return p + "+f" if m.get("famiglia") and p != "spento" else p

    def base(x):
        """il profilo di un dispositivo senza la sua pausa"""
        modo = x.get("modo") or ""
        if modo == "spento" and x.get("spento_fino"):
            # con la scadenza: se casa si spegne, il paracadute rimette da solo la modalità di prima
            dopo = di_modo(x.get("modo_prima") or "")
            return "spento:%d:%s" % (int(float(x["spento_fino"]) * 1000), "pulito" if dopo == "spento" else dopo)
        return di_modo(modo)

    def profilo(did):
        d = next((d for d in disp if d.get("id") == did), {})
        x = d if d.get("proprie") else princ   # come a casa: chi non ha regole sue segue quelle del dispositivo principale
        # PAUSA DEL DISPOSITIVO (campo «pausa» di dispositivi.json: fino = secondi epoch, 0 = senza scadenza): il suo codice passa
        # senza filtro fino alla scadenza, poi torna da solo il profilo di prima (anche con casa spenta: lo decide il worker).
        # Per chi non ha regole sue («segue il principale») il quarto pezzo «:x» dice al worker di non chiedere a Casa: a Casa
        # quel dispositivo non ha un gruppo suo e la pausa non si vedrebbe.
        pz = d.get("pausa")
        if isinstance(pz, dict):
            try:
                fino = float(pz.get("fino") or 0)
            except (TypeError, ValueError):
                fino = -1
            if fino == 0 or fino > time.time():
                if d.get("proprie"):
                    dopo = di_modo(d.get("modo_prima") or "") if d.get("modo") == "spento" else di_modo(d.get("modo") or "")
                    forza = ""
                else:
                    dopo = base(princ)
                    dopo = dopo.split(":")[2] if dopo.startswith("spento:") and dopo.count(":") >= 2 else dopo
                    forza = ":x"
                return "spento:%d:%s%s" % (int(fino * 1000) if fino else SENZA_FINE_MS, "pulito" if dopo == "spento" else dopo, forza)
        return base(x)

    cod, nomi = {}, {}
    for n, v in dp.items():
        if isinstance(v, dict) and v.get("codice"):
            p = profilo(v.get("disp"))
            cod[hashlib.sha256(str(v["codice"]).encode()).hexdigest()] = p
            nomi[n] = p
    return cod, nomi


def calcola_stato(D, nome_casa=""):
    """quello che serve alla pagina di riserva: dispositivi (con le impronte dei loro codici), modalità. Niente codici."""
    modi = [m for m in _json_obbligatorio(os.path.join(D, "modalita.json"), list) if isinstance(m, dict) and m.get("id")]
    disp = [d for d in _json_obbligatorio(os.path.join(D, "dispositivi.json"), list) if isinstance(d, dict) and d.get("id")]
    dp = _json_obbligatorio(os.path.join(D, "dns-personale.json"), dict, {})
    dd = []
    for x in disp[:MAX_STATO_DISP]:
        y = {"id": str(x["id"]), "nome": str(x.get("nome") or x["id"]), "proprie": bool(x.get("proprie")),
             "principale": bool(x.get("principale")), "modo": str(x.get("modo") or "")}
        if x.get("modo_prima"):
            y["modo_prima"] = str(x["modo_prima"])
        if x.get("modo") == "spento" and x.get("spento_fino"):
            y["spento_fino"] = int(float(x["spento_fino"]) * 1000)
        pz = x.get("pausa")
        if isinstance(pz, dict):   # pausa del dispositivo ancora valida: la pagina di riserva la conosce (0 = senza scadenza)
            try:
                fino = float(pz.get("fino") or 0)
            except (TypeError, ValueError):
                fino = -1
            if fino == 0 or fino > time.time():
                y["pausa_fino"] = int(fino * 1000)
        dd.append(y)
    cd = {hashlib.sha256(str(v["codice"]).encode()).hexdigest(): str(v.get("disp") or "")
          for v in dp.values() if isinstance(v, dict) and v.get("codice")}
    try:
        minuti = int(os.environ.get("FILTREO_SPENTO_MINUTI", "60") or 60)
    except ValueError:
        minuti = 60
    return {"nome_casa": nome_casa or "Casa", "fuso": os.environ.get("TZ") or "Europe/Rome", "spento_minuti": minuti,
            "modalita": [{"id": str(m["id"]), "nome": str(m.get("nome") or m["id"]), "colore": str(m.get("colore") or "#2563EB"),
                          "lavoro": bool(m.get("lavoro")), "famiglia": bool(m.get("famiglia")),
                          "fuori": m["fuori"] if m.get("fuori") in ("pulito", "lavoro", "spento") else "",
                          "solo_permessi": bool(m.get("solo_permessi"))} for m in modi],
            "dispositivi": dd, "codici_disp": cd}


def barra_di_casa(pannello):
    """i numeri di oggi dal pannello di casa (stesso testo del widget), solo i conteggi: niente siti visitati."""
    try:
        with urllib.request.urlopen(pannello.rstrip("/") + "/pannello/barra", timeout=8) as r:
            t = r.read(50000).decode("utf-8", "replace")
    except Exception:
        return None
    b = {"disp": []}
    for riga in t.splitlines():
        k, _, v = riga.partition("=")
        if k in ("bloccate", "richieste", "percento", "casa", "cloudflare", "totale"):
            b[k] = int(v) if v.isdigit() else 0
        elif k == "ore" and re.fullmatch(r"[0-9,]{0,200}", v):
            b["ore"] = v
        elif k == "disp":
            p = v.split("|")
            if len(p) == 3 and p[1].isdigit() and p[2].isdigit():
                b["disp"].append([p[0][:40], int(p[1]), int(p[2])])
    return b if "bloccate" in b else None


def pannello_kv(D, url_casa, nome_casa):
    """{impronta del codice del pannello da fuori casa, nome e indirizzo di casa}; impronta vuota = link chiuso."""
    c = str(_json(os.path.join(D, "pannello-fuori.json"), {}).get("codice") or "")
    if not re.fullmatch(r"[a-f0-9]{32,64}", c) or not url_casa:
        return {"impronta": "", "nome_casa": nome_casa or "Casa", "url_casa": ""}
    return {"impronta": hashlib.sha256(c.encode()).hexdigest(), "nome_casa": nome_casa or "Casa", "url_casa": url_casa.rstrip("/")}


def ritira_conti(D, s, url_par, stato, forza=False):
    """legge i conteggi dei blocchi che Cloudflare ha fatto per dispositivo (GET <paracadute>/conti con il segreto CF_CONTEGGI)
    e li scrive in data/cloudflare-conti.json con l'id del dispositivo al posto dell'impronta del codice.
    Ritorna un testo breve per il riepilogo, oppure "". Mai un errore: se non va, il file resta com'era."""
    chiave = s.get("CF_CONTEGGI", "")
    if not chiave or not re.fullmatch(r"https://[a-z0-9.-]+", url_par or ""):
        return ""
    if not forza and time.time() - (stato.get("conti_quando") or 0) < OGNI_CONTI:
        return ""
    stato["conti_quando"] = time.time()
    try:
        req = urllib.request.Request(url_par.rstrip("/") + "/conti?giorni=8", headers={"Authorization": "Bearer " + chiave, "User-Agent": "Filtreo-paracadute"})
        with urllib.request.urlopen(req, timeout=15) as r:
            j = json.loads(r.read(500000))
        giorni = j.get("giorni") if isinstance(j, dict) else None
        if not isinstance(giorni, dict):
            return ""
        dp = _json(os.path.join(D, "dns-personale.json"), {})
        di = {hashlib.sha256(str(v["codice"]).encode()).hexdigest(): str(v.get("disp") or k)   # senza dispositivo: il nome della voce (es. «mac-davide»), mai «?»
              for k, v in dp.items() if isinstance(v, dict) and v.get("codice")}
        out = {}
        for g, per in giorni.items():
            if not re.fullmatch(r"\d{4}-\d\d-\d\d", g) or not isinstance(per, dict):
                continue
            for imp, v in per.items():
                if not isinstance(v, dict):
                    continue
                x = out.setdefault(g, {}).setdefault(di.get(imp) or "?", {"b": 0, "r": 0})
                x["b"] += int(v.get("b") or 0)
                x["r"] += int(v.get("r") or 0)
                o = v.get("o")   # bloccate per ora (24 numeri), se il worker è quello nuovo
                if isinstance(o, list) and len(o) == 24:
                    xo = x.setdefault("o", [0] * 24)
                    for i in range(24):
                        try:
                            xo[i] += max(0, int(o[i] or 0))
                        except (TypeError, ValueError):
                            pass
        p = os.path.join(D, "cloudflare-conti.json")
        with open(p + ".tmp", "w", encoding="utf-8") as f:
            json.dump({"aggiornato": int(time.time()), "oggi": str(j.get("oggi") or ""), "giorni": out}, f)
        os.replace(p + ".tmp", p)
        return "conteggi di Cloudflare ritirati (%d giorni)" % len(out)
    except Exception as e:  # Cloudflare giù, segreto sbagliato, JSON strano: si riprova al prossimo giro
        return "conteggi di Cloudflare non ritirati (%s)" % type(e).__name__


def testo(cod):
    return json.dumps(cod, sort_keys=True, separators=(",", ":"))


def leggi_segreti(p):
    s = {}
    try:
        with open(p, encoding="utf-8") as f:
            for r in f:
                r = r.strip()
                if not r or r.startswith("#") or "=" not in r:
                    continue
                k, v = r.split("=", 1)
                k = k.strip()
                if k.startswith("export "):
                    k = k[7:].strip()
                s[k] = v.strip().strip('"').strip("'")
    except OSError:
        return None
    return s


def trova_segreti(scelto):
    for p in (scelto, os.environ.get("FILTREO_SEGRETI_CF", ""), "/segreti/cloudflare.env",
              os.path.expanduser("~/filtreo15/segreti/cloudflare.env")):
        if p and os.path.isfile(p):
            return p
    return ""


def _kv(api, s, metodo, chiave, valore=None):
    """chiamata al KV di Cloudflare. Ritorna (codice http, corpo) oppure (0, nome dell'errore). Mai segreti nei messaggi."""
    url = "%s/accounts/%s/storage/kv/namespaces/%s/values/%s" % (api.rstrip("/"), s["CF_ACCOUNT"], s["CF_KV_NS"], urllib.parse.quote(chiave))
    req = urllib.request.Request(url, data=None if valore is None else valore.encode(), method=metodo,
                                 headers={"Authorization": "Bearer " + s["CF_TOKEN"], "Content-Type": "text/plain",
                                          "User-Agent": "Filtreo-paracadute"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read(200000)
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000)
    except Exception as e:  # rete giù, nome che non si risolve…
        return 0, type(e).__name__


def leggi_coda(api, s):
    """[cambi] dalla coda, [] se vuota; None se non si legge (allora non si tocca niente)."""
    codice, corpo = _kv(api, s, "GET", "cambi_in_attesa")
    if codice == 404:
        return []
    if codice != 200:
        return None
    try:
        x = json.loads(corpo or b"[]")
    except ValueError:
        return []
    return [c for c in x if isinstance(c, dict) and c.get("disp") and c.get("m")] if isinstance(x, list) else []


def applica_coda(pannello, coda):
    """applica i cambi nel pannello di casa, nell'ordine. Ritorna (id applicati o saltati, testi, casa raggiunta)."""
    fatti, testi = set(), []
    adesso = time.time() * 1000
    for c in sorted(coda, key=lambda c: c.get("quando") or 0):
        if c.get("m") == "spento" and (c.get("fino") or 0) and c["fino"] <= adesso:
            fatti.add(c.get("id"))   # «Senza filtro» già scaduto: casa resta com'era prima
            testi.append("saltato (Senza filtro già finito)")
            continue
        url = "%s/pannello/modo?%s" % (pannello.rstrip("/"), urllib.parse.urlencode({"id": c["disp"], "m": c["m"]}))
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=b"", method="POST"), timeout=20) as r:
                j = json.loads(r.read(20000) or b"{}")
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                return fatti, testi, False
            try:
                j = json.loads(e.read(20000) or b"{}")
            except ValueError:
                j = {}
        except Exception:
            return fatti, testi, False   # pannello di casa non raggiungibile: riprovo al prossimo giro
        fatti.add(c.get("id"))
        testi.append(str(j.get("testo") or "")[:120])
    return fatti, testi, True


def svuota_coda(api, s, fatti):
    """toglie dalla coda i cambi applicati (rileggo: se nel frattempo ne è arrivato uno nuovo, resta)."""
    ora = leggi_coda(api, s)
    if ora is None:
        return False
    resto = [c for c in ora if c.get("id") not in fatti]
    if resto:
        return 200 <= _kv(api, s, "PUT", "cambi_in_attesa", json.dumps(resto))[0] < 300
    codice = _kv(api, s, "DELETE", "cambi_in_attesa")[0]
    return 200 <= codice < 300 or codice == 404


def scrivi_kv(api, s, valore, chiave="codici"):
    """PUT …/storage/kv/namespaces/{ns}/values/<chiave>. Ritorna (ok, messaggio senza segreti)."""
    codice, corpo = _kv(api, s, "PUT", chiave, valore)
    if codice == 0:
        return False, "Cloudflare non raggiungibile (%s)" % corpo
    try:
        j = json.loads(corpo or b"{}")
    except ValueError:
        j = {}
    if 200 <= codice < 300 and j.get("success", True):
        return True, "ok"
    err = "; ".join(str(x.get("message", ""))[:120] for x in (j.get("errors") or []) if isinstance(x, dict))
    if codice in (401, 403):
        err = "token non valido o senza il permesso «Workers KV Storage: Edit»" + (" (%s)" % err if err else "")
    return False, "Cloudflare ha risposto %d: %s" % (codice, err or "errore")


def pausa_di_casa(motore, ora_ms=None):
    """come sta la pausa adesso, secondo Blocky: None = non lo so (Blocky non risponde: non si cambia niente),
    {"attiva": False}, {"attiva": True, "senza": True, "fino": 0} oppure {"attiva": True, "senza": False, "fino": ms UTC}."""
    ora_ms = int(time.time() * 1000) if ora_ms is None else ora_ms
    try:
        with urllib.request.urlopen(motore.rstrip("/") + "/api/blocking/status", timeout=4) as r:
            b = json.loads(r.read(20000))
    except Exception:
        return None
    if not isinstance(b, dict):
        return None
    sec = int(b.get("autoEnableInSec") or 0)
    abilitato = bool(b.get("enabled", False))
    if abilitato and not b.get("disabledGroups"):
        return {"attiva": False}
    if not abilitato and not sec:
        return {"attiva": True, "senza": True, "fino": 0}
    if sec > 0:
        return {"attiva": True, "senza": False, "fino": ora_ms + sec * 1000}
    return {"attiva": False}   # spenti solo alcuni gruppi, senza timer: non è la pausa del pannello


def pausa_efficace(p, ora_ms):
    """la pausa se vale ancora (senza scadenza, o con la scadenza nel futuro), altrimenti None."""
    if isinstance(p, dict) and p.get("attiva") and (p.get("senza") or int(p.get("fino") or 0) > ora_ms):
        return p
    return None


def pausa_uguale(a, b, ora_ms):
    """stessa pausa per il worker? Due pause finite o assenti sono uguali; due attive sono uguali se hanno lo stesso tipo e (a tempo) la stessa scadenza ±2 minuti."""
    a, b = pausa_efficace(a, ora_ms), pausa_efficace(b, ora_ms)
    if a is None or b is None:
        return a is None and b is None
    if bool(a.get("senza")) != bool(b.get("senza")):
        return False
    return bool(a.get("senza")) or abs(int(a["fino"]) - int(b["fino"])) <= TOLLERANZA_PAUSA_MS


def leggi_kv_pausa(api, s):
    """la pausa che c'è nel KV adesso: dict, {"attiva": False} se la chiave non c'è, None se non si legge."""
    codice, corpo = _kv(api, s, "GET", "pausa")
    if codice == 404:
        return {"attiva": False}
    if codice != 200:
        return None
    try:
        x = json.loads(corpo or b"{}")
    except ValueError:
        return {"attiva": False}
    return x if isinstance(x, dict) else {"attiva": False}


def passo_pausa(api, s, stato, motore, forza=False, ora_ms=None):
    """copia la pausa di Casa nel KV se è cambiata. Aggiorna stato["pausa"]. Ritorna un testo breve per il riepilogo, oppure ""."""
    ora_ms = int(time.time() * 1000) if ora_ms is None else ora_ms
    voluta = pausa_di_casa(motore, ora_ms)
    if voluta is None:
        return ""
    scritta = stato.get("pausa")
    if not isinstance(scritta, dict):   # non so cosa c'è nel KV (file di stato nuovo): lo leggo, una lettura non costa scritture
        scritta = leggi_kv_pausa(api, s)
        if scritta is None:
            return "pausa non copiata (KV non leggibile)"
    if not forza and pausa_uguale(voluta, scritta, ora_ms):
        stato["pausa"] = scritta
        return ""
    if voluta.get("attiva"):   # accendere: un tetto giornaliero; spegnere (tornare a filtrare) no, mai
        oggi = time.strftime("%Y-%m-%d")
        c = stato.get("pausa_scritture") if isinstance(stato.get("pausa_scritture"), dict) else {}
        if c.get("giorno") != oggi:
            c = {"giorno": oggi, "n": 0}
        if c["n"] >= MAX_PAUSE_AL_GIORNO:
            return "pausa non copiata (già %d scritture oggi)" % c["n"]
        c["n"] += 1
        stato["pausa_scritture"] = c
    voluta = dict(voluta, agg=ora_ms)
    ok, msg = scrivi_kv(api, s, json.dumps(voluta, sort_keys=True, separators=(",", ":")), "pausa")
    if not ok:
        return "pausa non copiata su Cloudflare: %s" % msg
    stato["pausa"] = voluta
    if not voluta["attiva"]:
        return "pausa finita: Cloudflare filtra di nuovo"
    return "pausa copiata su Cloudflare (%s)" % ("senza scadenza" if voluta.get("senza") else "fino alle %s" % time.strftime("%H:%M", time.localtime(voluta["fino"] / 1000)))


def main():
    a = argparse.ArgumentParser(description="Filtreo: modalità dei dispositivi → paracadute (Cloudflare KV)")
    a.add_argument("--data", default=os.environ.get("FILTREO_DATA") or os.path.expanduser("~/filtreo15/data"))
    a.add_argument("--segreti", default="")
    a.add_argument("--api", default=os.environ.get("FILTREO_CF_API") or API)
    a.add_argument("--codici", default="", help="scrive solo il JSON in questo file")
    a.add_argument("--forza", action="store_true")
    a.add_argument("--pubblica-versione", dest="pubblica_versione", nargs="?", const="auto", default="",
                   help="scrive su Cloudflare (chiave «versione») la versione più recente di Filtreo: X.Y.Z oppure, senza valore, quella del file VERSIONE. Lo fa il Mac quando rilascia")
    a.add_argument("--solo-pausa", dest="solo_pausa", action="store_true", help="copia solo la pausa su Cloudflare")
    a.add_argument("--motore", default=os.environ.get("FILTREO_MOTORE_URL") or "http://127.0.0.1:%s" % (os.environ.get("FILTREO_MOTORE") or "4000"),
                   help="indirizzo di controllo di Blocky (per leggere la pausa)")
    a.add_argument("--pannello", default=os.environ.get("FILTREO_PANNELLO_LOCALE") or "http://127.0.0.1:%s" % (os.environ.get("INGRESS_PORT") or "8446"))
    a.add_argument("--paracadute-url", dest="url_par", default=os.environ.get("FILTREO_PARACADUTE_URL", "").strip())
    a.add_argument("--url-casa", dest="url_casa", default=os.environ.get("FILTREO_DOH_URL", "").strip())
    o = a.parse_args()
    D = o.data
    if not o.url_casa or not o.url_par or not os.environ.get("FILTREO_NOME_CASA"):   # lanciato a mano (docker exec): le impostazioni stanno in opzioni.env
        try:
            for r in open(os.path.join(D, "opzioni.env"), encoding="utf-8"):
                k, _, v = r.strip().partition("=")
                v = v.strip().strip('"').strip("'")
                if k == "FILTREO_DOH_URL" and not o.url_casa:
                    o.url_casa = v
                elif k == "FILTREO_PARACADUTE_URL" and not o.url_par:
                    o.url_par = v
                elif k == "FILTREO_NOME_CASA" and v and not os.environ.get("FILTREO_NOME_CASA"):
                    os.environ["FILTREO_NOME_CASA"] = v
        except OSError:
            pass
    if o.pubblica_versione:   # lo fa il Mac quando rilascia: non servono i dati del filtro, solo i segreti di Cloudflare
        seg = trova_segreti(o.segreti)
        s = leggi_segreti(seg) if seg else None
        if not s or not s.get("CF_TOKEN") or not ESA32.match(s.get("CF_ACCOUNT", "")) or not ESA32.match(s.get("CF_KV_NS", "")):
            print("paracadute: mancano i segreti di Cloudflare (CF_TOKEN, CF_ACCOUNT, CF_KV_NS): versione non pubblicata")
            return 1
        v = o.pubblica_versione
        if v == "auto":
            v = ""
            for q in (os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app", "VERSIONE"), os.path.join(D, "..", "app", "VERSIONE")):
                try:
                    v = open(q, encoding="utf-8").read().strip()
                    break
                except OSError:
                    pass
        if not re.fullmatch(r"\d+\.\d+\.\d+", v or ""):
            print("paracadute: versione non valida (serve X.Y.Z): niente da fare")
            return 1
        corpo = json.dumps({"versione": v, "data": time.strftime("%Y-%m-%d")}, separators=(",", ":"))
        ok, msg = scrivi_kv(o.api, s, corpo, "versione")
        print("paracadute: versione %s %s" % (v, "pubblicata (i nodi la vedono da «Aggiornamenti»)" if ok else "NON pubblicata: " + msg))
        return 0 if ok else 1
    if not o.codici and not os.path.exists(os.path.join(D, "dns-personale.json")):
        print("paracadute: nessun DNS personale su questo filtro: niente da fare")
        return 0
    try:
        cod, nomi = ({}, {}) if o.solo_pausa else calcola(D)   # --solo-pausa non ha bisogno dei profili
    except DatiIllegibili as e:
        print("paracadute: ✖ dati del filtro non leggibili (%s): non scrivo niente" % e)
        return 1
    val = testo(cod)
    riepilogo = ", ".join("%s=%s" % x for x in sorted(nomi.items()))
    if o.codici:
        with open(o.codici + ".tmp", "w", encoding="utf-8") as f:
            f.write(val)
        os.replace(o.codici + ".tmp", o.codici)
        print("codici: %d (%s)" % (len(cod), riepilogo))
        return 0
    seg = trova_segreti(o.segreti)
    s = leggi_segreti(seg) if seg else None
    if not s:
        print("paracadute: manca il file dei segreti di Cloudflare: niente da fare")
        return 0
    if not s.get("CF_TOKEN") or not ESA32.match(s.get("CF_ACCOUNT", "")) or not ESA32.match(s.get("CF_KV_NS", "")):
        print("paracadute: file dei segreti incompleto (servono CF_TOKEN, CF_ACCOUNT, CF_KV_NS): niente da fare")
        return 0
    stato_p = os.path.join(D, "paracadute-kv.json")
    lucchetto = None
    if fcntl:
        try:
            lucchetto = open(os.path.join(D, ".paracadute-kv.lock"), "w")
            fcntl.flock(lucchetto, fcntl.LOCK_EX)   # un giro alla volta (pannello e prove a mano)
        except OSError:
            lucchetto = None
    stato = _json(stato_p, {})
    if stato.get("ns") != s["CF_KV_NS"]:
        stato = {}
    detto = []
    if o.solo_pausa:
        try:
            t = passo_pausa(o.api, s, stato, o.motore, o.forza)
        except Exception as e:  # la pausa su Cloudflare non deve mai dare un errore
            t = "pausa non copiata (%s)" % type(e).__name__
        stato["ns"] = s["CF_KV_NS"]
        try:
            with open(stato_p + ".tmp", "w", encoding="utf-8") as f:
                json.dump(stato, f)
            os.replace(stato_p + ".tmp", stato_p)
        except OSError:
            pass
        print(("paracadute: ✓ " + t) if t.startswith("pausa copiata") or t.startswith("pausa finita") else ("paracadute: " + (t or "pausa già a posto")))
        return 0
    t = ritira_conti(D, s, o.url_par, stato, o.forza)
    if t:
        detto.append(t)
    # 1) cambi fatti dalla pagina di riserva mentre casa era spenta → nel pannello di casa
    coda = leggi_coda(o.api, s)
    da_casa = bool(coda)
    if coda:
        fatti, testi, raggiunto = applica_coda(o.pannello, coda)
        if fatti:
            svuota_coda(o.api, s, fatti)
            detto.append("%d cambi fatti fuori casa copiati nel pannello (%s)" % (len(fatti), "; ".join(t for t in testi if t)))
        if not raggiunto:
            detto.append("pannello di casa non raggiungibile: %d cambi restano in coda" % (len(coda) - len(fatti)))
        try:
            cod, nomi = calcola(D)   # i dati sono cambiati: ricalcolo
        except DatiIllegibili as e:
            print("paracadute: ✖ dati del filtro non leggibili (%s): non scrivo niente" % e)
            return 1
        val = testo(cod)
        riepilogo = ", ".join("%s=%s" % x for x in sorted(nomi.items()))
    # 2) codici
    impr = hashlib.sha256(val.encode()).hexdigest()
    scritto = False
    if o.forza or da_casa or stato.get("impronta") != impr:
        ok, msg = scrivi_kv(o.api, s, val)
        if not ok:
            print("paracadute: ✖ non aggiornato: %s" % msg)
            return 1
        stato.update({"impronta": impr, "ns": s["CF_KV_NS"], "quando": time.strftime("%Y-%m-%d %H:%M:%S"), "profili": nomi})
        scritto = True
    # 3) pannello da fuori casa e stato per la pagina di riserva (se non vanno, i codici restano buoni)
    nome_casa = os.environ.get("FILTREO_NOME_CASA", "").strip() or "Casa"
    pk = pannello_kv(D, o.url_casa, nome_casa)
    pk_impr = hashlib.sha256(testo(pk).encode()).hexdigest()
    if o.forza or stato.get("pannello") != pk_impr:
        ok, msg = scrivi_kv(o.api, s, testo(pk), "pannello")
        if ok:
            stato["pannello"] = pk_impr
            stato["pannello_aperto"] = pk["impronta"]
            detto.append("pannello da fuori casa " + ("pronto" if pk["impronta"] else "chiuso"))
        else:
            detto.append("pannello da fuori casa non scritto: %s" % msg)
    try:
        st = calcola_stato(D, nome_casa)
    except DatiIllegibili:
        st = None
    if st is not None:
        st_impr = hashlib.sha256(testo(st).encode()).hexdigest()
        if o.forza or da_casa or scritto or stato.get("stato_impronta") != st_impr or time.time() - (stato.get("stato_quando") or 0) >= OGNI_STATO:
            st["barra"] = barra_di_casa(o.pannello)
            oggi = time.strftime("%Y-%m-%d")
            if st["barra"]:
                stato["barra"], stato["barra_giorno"] = st["barra"], oggi
            elif stato.get("barra_giorno") == oggi:
                st["barra"] = stato.get("barra")   # pannello occupato o già spento: tengo gli ultimi numeri di oggi
            st["ora"] = int(time.time() * 1000)
            ok, msg = scrivi_kv(o.api, s, testo(st), "stato")
            if ok:
                stato["stato_impronta"], stato["stato_quando"] = st_impr, time.time()
            else:
                detto.append("stato non scritto: %s" % msg)
    try:   # 4) la pausa (di solito già a posto: scrive solo se è cambiata)
        t = passo_pausa(o.api, s, stato, o.motore, o.forza)
        if t:
            detto.append(t)
    except Exception as e:
        detto.append("pausa non copiata (%s)" % type(e).__name__)
    try:
        with open(stato_p + ".tmp", "w", encoding="utf-8") as f:
            json.dump(stato, f)
        os.replace(stato_p + ".tmp", stato_p)
    except OSError:
        pass
    extra = (" · " + " · ".join(detto)) if detto else ""
    if scritto:
        print("paracadute: ✓ modalità copiate nel paracadute (%d codici: %s)%s" % (len(cod), riepilogo, extra))
    else:
        print("paracadute: già aggiornato (%d codici)%s" % (len(cod), extra))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # mai un errore che si porta dietro dettagli segreti
        print("paracadute: ✖ errore inatteso (%s)" % type(e).__name__)
        sys.exit(1)
