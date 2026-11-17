#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""aggiornamento.py — Casa si aggiorna da sola (canale di rilascio firmato). Solo libreria standard.

Come funziona (uguale nell'add-on di Home Assistant e nel Docker del Jetson)
  1. Di notte (di serie 04:30, ora locale) o con «Aggiorna ora»: legge <canale>/manifest.json e manifest.json.sig,
     verifica la firma ed25519 (stessa chiave e stesso schema delle Regole), controlla che il rilascio sia più nuovo
     di quello installato (un manifest vecchio, anche se firmato, non fa tornare indietro), scarica il pacchetto e ne
     verifica sha256 e dimensione.
  2. Estrae il pacchetto in una cartella NUOVA (BASE/.nuova-<rilascio>), controlla che i programmi si compilino.
  3. Prima prova la Casa di adesso (se già ora la prova non passa, per esempio senza Internet: rimanda).
  4. Scambia le cartelle: BASE/app → BASE/app-prima, la nuova → BASE/app (se prima c'era il codice dell'immagine,
     «prima» = interna: tornare indietro = togliere BASE/app).
  5. Il pannello si trasforma (exec, stesso processo: il contenitore non si ferma) nel GUARDIANO, che è la copia di
     questo file della versione di PRIMA (DATA/aggiornamento-guardia.py): prepara la config con il codice nuovo, riavvia
     il motore, avvia il pannello nuovo come processo figlio e PROVA: salute, risposta DNS, blocco di una pubblicità di
     prova, sito normale che passa. Tutto bene → il guardiano diventa il pannello nuovo. Una prova fallisce → torna alle
     cartelle di prima, riprepara, riavvia e diventa il pannello di prima. Il registro dice perché.
  6. Se Casa si spegne a metà prova (corrente, riavvio): all'avvio successivo run.sh/run-casa.sh (--scegli) e il pannello
     (avvia()) vedono «in prova» e tornano alla versione di prima.

Dove sta il codice aggiornato (BASE)
  Home Assistant: /share/filtreo (run.sh usa già /share/filtreo/app; /share/filtreo/jetson per il paracadute)
  Jetson (Docker): /data/codice  (= ~/filtreo15/data/codice sul Jetson; run-casa.sh lo sceglie se valido)
  FILTREO_CODICE_BASE cambia la cartella. FILTREO_APP_INTERNA = codice dell'immagine (di serie /opt/filtreo/app).

File (in DATA)
  aggiornamento.json        impostazioni: {"automatici": true, "ora": "04:30"}
  aggiornamento-stato.json  stato: ultima verifica, ultimo esito, prova in corso, tentativi per rilascio
  aggiornamento.log         registro leggibile (ultime 400 righe)

Uso a riga di comando
  aggiornamento.py --scegli            stampa la cartella del codice da usare all'avvio (e chiude una prova interrotta)
  aggiornamento.py --guardia           (interno) il guardiano della prova
  aggiornamento.py --controlla         legge il canale e stampa il manifest verificato
"""
import base64
import hashlib
import io
import json
import os
import py_compile
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from datetime import datetime

QUI = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("FILTREO_DATA", "/data")
INTERNA = os.environ.get("FILTREO_APP_INTERNA", "/opt/filtreo/app")
CANALE_DI_SERIE = "https://filtreo-canale.fullhd-david.workers.dev/casa"
CHIAVE_PUBBLICA = os.environ.get("FILTREO_CASA_PUB", "") or "yh8X6jdT/WUn+wdkz7tRMOEu00PNVuntQQiX96y43ac="   # = regole/regole-firma.pub
TIPO = "filtreo-casa"
MAX_MANIFEST = 64 * 1024
MAX_PACCHETTO = 60 * 1024 * 1024
ORA_DI_SERIE = "04:30"
PID_BLOCKY = os.environ.get("FILTREO_PID_BLOCKY", "/tmp/blocky.pid")
AGENTE = "Filtreo-Casa-Aggiornamento/1.0"
TENTATIVI_MAX = 3   # stesso rilascio che non passa la prova: si riprova al massimo 3 notti, poi si aspetta il prossimo
ESSENZIALI = ("filtreo_pannello.py", "filtreo_liste.py", "filtro.py", "pannello.html", "VERSIONE")
_VERS = re.compile(r"^\d+\.\d+\.\d+$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_PACCH = re.compile(r"^[A-Za-z0-9._-]{1,120}\.tar\.gz$")
_ORA = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def _base():
    b = os.environ.get("FILTREO_CODICE_BASE", "").strip()
    if b:
        return b
    if os.environ.get("SUPERVISOR_TOKEN") or (os.environ.get("FILTREO_SENZA_HA") != "1" and os.path.isdir("/share")):
        return "/share/filtreo"
    return os.path.join(DATA, "codice")


def _f(nome):
    return os.path.join(DATA, nome)


F_IMPOST = "aggiornamento.json"
F_STATO = "aggiornamento-stato.json"
F_LOG = "aggiornamento.log"
F_GUARDIA = "aggiornamento-guardia.py"
_lock = threading.Lock()
_in_corso = {"si": False, "fase": ""}


# ───────────── piccoli attrezzi ─────────────
def _leggi(p, vuoto):
    try:
        with open(p, encoding="utf-8") as h:
            x = json.load(h)
        return x if isinstance(x, type(vuoto)) else vuoto
    except (OSError, ValueError):
        return vuoto


def _scrivi(p, obj):
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p + ".tmp", "w", encoding="utf-8") as h:
            json.dump(obj, h, ensure_ascii=False, indent=1)
        os.replace(p + ".tmp", p)
        return True
    except OSError:
        return False


def registro(testo):
    """una riga nel registro leggibile (e nel log del contenitore)."""
    riga = "%s  %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), testo)
    try:
        sys.stderr.write("[filtreo aggiornamento] %s\n" % testo)
        sys.stderr.flush()
    except Exception:
        pass
    p = _f(F_LOG)
    try:
        righe = open(p, encoding="utf-8").read().splitlines()[-399:] if os.path.exists(p) else []
        righe.append(riga)
        with open(p + ".tmp", "w", encoding="utf-8") as h:
            h.write("\n".join(righe) + "\n")
        os.replace(p + ".tmp", p)
    except OSError:
        pass


def righe_registro(n=40):
    try:
        return open(_f(F_LOG), encoding="utf-8").read().splitlines()[-n:]
    except OSError:
        return []


def _stato():
    return _leggi(_f(F_STATO), {})


def _salva_stato(**k):
    s = _stato()
    s.update(k)
    _scrivi(_f(F_STATO), s)
    return s


def _esito(esito, testo, versione="", dettaglio=""):
    """«testo» va nelle app e nel pannello (parole semplici, LESSICO); «dettaglio» (il perché tecnico) nel registro e nello stato."""
    registro(testo + ((" — " + dettaglio) if dettaglio else ""))
    return _salva_stato(ultimo_esito={"esito": esito, "testo": testo, "dettaglio": dettaglio, "quando": int(time.time()), "versione": versione})


def _avvisa(testo):
    """Telegram (se configurato, come liste.avvisa): niente import del resto del programma, così vale anche nel guardiano."""
    d = os.environ.get("FILTREO_TG_DIR", "")
    if not d:
        return False
    try:
        import urllib.parse
        tok = open(os.path.join(d, ".tg_token"), encoding="utf-8").read().strip()
        chat = open(os.path.join(d, ".tg_owner"), encoding="utf-8").read().strip()
        urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % tok,
                               data=urllib.parse.urlencode({"chat_id": chat, "text": testo}).encode(), timeout=10).read()
        return True
    except Exception:
        return False


# ───────────── impostazioni ─────────────
def impostazioni():
    s = _leggi(_f(F_IMPOST), {})
    ora = str(s.get("ora") or ORA_DI_SERIE)
    return {"automatici": bool(s.get("automatici", True)), "ora": ora if _ORA.match(ora) else ORA_DI_SERIE}


def imposta(automatici=None, ora=None):
    s = _leggi(_f(F_IMPOST), {})
    if automatici is not None:
        s["automatici"] = bool(automatici)
    if ora is not None:
        if not _ORA.match(str(ora)):
            return False, "Ora non valida (formato 04:30)."
        s["ora"] = str(ora)
    if not _scrivi(_f(F_IMPOST), s):
        return False, "Impossibile salvare. Riprova."
    i = impostazioni()
    registro("impostazioni: aggiornamenti automatici %s, ora %s" % ("attivi" if i["automatici"] else "disattivati", i["ora"]))
    return True, ("Aggiornamenti automatici attivi · ogni notte alle %s" % i["ora"]) if i["automatici"] else "Aggiornamenti automatici disattivati"


def canale():
    u = (os.environ.get("FILTREO_CANALE_CASA", "") or _leggi(_f(F_IMPOST), {}).get("canale") or CANALE_DI_SERIE).strip().rstrip("/")
    if re.match(r"^https://[a-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?$", u, re.I) or re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?(/[A-Za-z0-9._~/-]*)?$", u):
        return u
    return CANALE_DI_SERIE


# ───────────── versione installata ─────────────
def rilascio_di(cartella):
    """{"versione", "rilascio" (numero AAAAMMGGhhmm, 0 = sconosciuto), "impronta"} del codice in una cartella."""
    r = _leggi(os.path.join(cartella, "RILASCIO.json"), {})
    try:
        v = open(os.path.join(cartella, "VERSIONE"), encoding="utf-8").read().strip()
    except OSError:
        v = ""
    try:
        n = int(r.get("rilascio") or 0)
    except (TypeError, ValueError):
        n = 0
    return {"versione": str(r.get("versione") or v), "rilascio": n, "impronta": str(r.get("impronta") or "")}


def installata():
    return rilascio_di(QUI)


# ───────────── canale: manifest firmato ─────────────
class ErroreCanale(Exception):
    pass


def _scarica(url, massimo, attesa=60):
    req = urllib.request.Request(url, headers={"User-Agent": AGENTE, "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=attesa) as r:
            dati = r.read(massimo + 1)
    except urllib.error.HTTPError as e:
        raise ErroreCanale("il canale ha risposto %s" % e.code)
    except Exception as e:
        raise ErroreCanale("canale non raggiungibile (%s)" % str(e)[:80])
    if len(dati) > massimo:
        raise ErroreCanale("file troppo grande dal canale")
    return dati


def controlla_manifest(dati, firma_b64, pub=None):
    """verifica firma e contenuto del manifest. Ritorna il dizionario o alza ErroreCanale con il motivo."""
    import firma_ed25519
    if not firma_ed25519.verifica_b64(pub or CHIAVE_PUBBLICA, dati, firma_b64 if isinstance(firma_b64, str) else firma_b64.decode("ascii", "replace")):
        raise ErroreCanale("firma NON valida: il pacchetto non è di Filtreo, niente installato")
    try:
        m = json.loads(dati.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ErroreCanale("manifest illeggibile")
    if not isinstance(m, dict) or m.get("tipo") != TIPO or m.get("schema") != 1:
        raise ErroreCanale("manifest di un altro tipo (non è un rilascio di Casa)")
    if not _VERS.match(str(m.get("versione") or "")):
        raise ErroreCanale("versione non valida nel manifest")
    if not isinstance(m.get("rilascio"), int) or not (200001010000 <= m["rilascio"] <= 299912312359):
        raise ErroreCanale("numero di rilascio non valido")
    if not _SHA.match(str(m.get("sha256") or "")) or not _PACCH.match(str(m.get("pacchetto") or "")):
        raise ErroreCanale("pacchetto o impronta non validi nel manifest")
    if not isinstance(m.get("byte"), int) or not (0 < m["byte"] <= MAX_PACCHETTO):
        raise ErroreCanale("dimensione del pacchetto non valida")
    return m


def leggi_canale(base=None):
    base = (base or canale()).rstrip("/")
    dati = _scarica(base + "/manifest.json", MAX_MANIFEST, 20)
    firma = _scarica(base + "/manifest.json.sig", 4096, 20)
    return controlla_manifest(dati, firma.decode("ascii", "replace"))


def controlla(base=None):
    """«Verifica»: legge il canale e dice se c'è un rilascio più nuovo. Mai un errore verso il pannello."""
    ins = installata()
    try:
        m = leggi_canale(base)
    except ErroreCanale as e:
        _salva_stato(ultima_verifica=int(time.time()), errore_verifica=str(e))
        return {"ok": False, "testo": "Impossibile verificare: %s." % e, "nuovo": False}
    nuovo = m["rilascio"] > ins["rilascio"]
    _salva_stato(ultima_verifica=int(time.time()), errore_verifica="",
                 disponibile={"versione": m["versione"], "rilascio": m["rilascio"], "data": str(m.get("data") or "")[:10]} if nuovo else None)
    return {"ok": True, "nuovo": nuovo, "manifest": m,
            "testo": ("Disponibile la versione %s" % m["versione"]) if nuovo else "Versione più recente installata"}


# ───────────── pacchetto ─────────────
def _estrai_sicuro(dati, dest):
    """estrae il tar.gz solo con cartelle e file normali, senza percorsi assoluti né «..», solo sotto app/ e jetson/."""
    with tarfile.open(fileobj=io.BytesIO(dati), mode="r:gz") as t:
        membri = t.getmembers()
        if len(membri) > 4000:
            raise ErroreCanale("pacchetto con troppi file")
        for x in membri:
            n = x.name
            if n.startswith("/") or ".." in n.split("/") or not (x.isfile() or x.isdir()):
                raise ErroreCanale("pacchetto con percorsi non ammessi (%s)" % n[:60])
            if n.split("/")[0] not in ("app", "jetson", "RILASCIO.json"):
                raise ErroreCanale("pacchetto con file fuori posto (%s)" % n[:60])
        for x in membri:
            p = os.path.join(dest, x.name)
            if x.isdir():
                os.makedirs(p, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with t.extractfile(x) as src, open(p, "wb") as out:
                shutil.copyfileobj(src, out)
            os.chmod(p, 0o755 if x.mode & 0o111 else 0o644)


def controlla_cartella(app):
    """i file essenziali ci sono e tutti i .py si compilano."""
    for n in ESSENZIALI:
        if not os.path.isfile(os.path.join(app, n)):
            return "manca %s" % n
    for n in sorted(os.listdir(app)):
        if n.endswith(".py"):
            try:
                py_compile.compile(os.path.join(app, n), cfile=os.path.join(DATA, ".pyc-prova"), doraise=True)
            except py_compile.PyCompileError as e:
                return "%s non si compila (%s)" % (n, str(e).splitlines()[-1][:80])
    try:
        os.remove(os.path.join(DATA, ".pyc-prova"))
    except OSError:
        pass
    return ""


def prepara_pacchetto(m, base=None):
    """scarica, verifica sha256, estrae in una cartella nuova. Ritorna il percorso (con app/ ed eventualmente jetson/)."""
    dati = _scarica((base or canale()).rstrip("/") + "/" + m["pacchetto"], MAX_PACCHETTO, 180)
    if len(dati) != m["byte"] or hashlib.sha256(dati).hexdigest() != m["sha256"]:
        raise ErroreCanale("sha256 del pacchetto diverso dal manifest: niente installato")
    B = _base()
    os.makedirs(B, exist_ok=True)
    dest = os.path.join(B, ".nuova-%d" % m["rilascio"])
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest)
    try:
        _estrai_sicuro(dati, dest)
        app = os.path.join(dest, "app")
        if not os.path.isdir(app):
            raise ErroreCanale("pacchetto senza cartella app")
        e = controlla_cartella(app)
        if e:
            raise ErroreCanale("pacchetto non valido: " + e)
        r = rilascio_di(app)
        if r["rilascio"] != m["rilascio"] or r["versione"] != m["versione"]:
            raise ErroreCanale("il pacchetto non corrisponde al manifest (rilascio %s)" % r["rilascio"])
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


# ───────────── cartelle: scambio e ritorno ─────────────
def _app_scelta():
    """la cartella del codice che si userebbe all'avvio:
    • BASE/app valida SENZA RILASCIO.json (messa a mano dall'installatore): come prima, ha la precedenza;
    • BASE/app valida CON RILASCIO.json (aggiornamento automatico): solo se non è più vecchia dell'immagine (le immagini
      hanno RILASCIO.json con l'ora di costruzione: dopo AGGIORNA-JETSON o un aggiornamento dell'add-on vince l'immagine);
    • altrimenti il codice dell'immagine."""
    a = os.path.join(_base(), "app")
    if os.path.isfile(os.path.join(a, "filtreo_pannello.py")) and not controlla_cartella(a):
        if not os.path.isfile(os.path.join(a, "RILASCIO.json")) or not os.path.isdir(INTERNA) \
                or rilascio_di(a)["rilascio"] >= rilascio_di(INTERNA)["rilascio"]:
            return a
    return INTERNA if os.path.isdir(INTERNA) else QUI


def scambia(nuova):
    """BASE/app → BASE/app-prima (o «interna»), nuova/app → BASE/app; jetson allo stesso modo. Ritorna com'era prima."""
    B = _base()
    a, ap = os.path.join(B, "app"), os.path.join(B, "app-prima")
    j, jp = os.path.join(B, "jetson"), os.path.join(B, "jetson-prima")
    prima = "cartella" if os.path.isfile(os.path.join(a, "filtreo_pannello.py")) and os.path.realpath(_app_scelta()) == os.path.realpath(a) else "interna"
    if os.path.isdir(a):
        shutil.rmtree(ap, ignore_errors=True)
        os.replace(a, ap)
    os.replace(os.path.join(nuova, "app"), a)
    jprima = jnuovo = False
    if os.path.isdir(os.path.join(nuova, "jetson")):
        if os.path.isdir(j):
            shutil.rmtree(jp, ignore_errors=True)
            os.replace(j, jp)
            jprima = True
        os.replace(os.path.join(nuova, "jetson"), j)
        jnuovo = True
    shutil.rmtree(nuova, ignore_errors=True)
    return {"prima": prima, "jetson_prima": jprima, "jetson_nuovo": jnuovo}


def torna_indietro(info):
    """rimette le cartelle di prima. Il codice che non è andato resta in BASE/app-scartata (per capire)."""
    B = _base()
    a, ap, sc = os.path.join(B, "app"), os.path.join(B, "app-prima"), os.path.join(B, "app-scartata")
    j, jp = os.path.join(B, "jetson"), os.path.join(B, "jetson-prima")
    shutil.rmtree(sc, ignore_errors=True)
    if os.path.isdir(a):
        os.replace(a, sc)
    if info.get("prima") == "cartella" and os.path.isdir(ap):
        os.replace(ap, a)
    if info.get("jetson_nuovo") and os.path.isdir(j):
        shutil.rmtree(j + "-scartata", ignore_errors=True)
        os.replace(j, j + "-scartata")
    if info.get("jetson_prima") and os.path.isdir(jp) and not os.path.exists(j):
        os.replace(jp, j)
    return _app_scelta()


# ───────────── prove (le stesse prima e dopo) ─────────────
def _porta_pannello():
    return int(os.environ.get("INGRESS_PORT", "8099") or 8099)


def _api():
    return "http://127.0.0.1:%d" % int(os.environ.get("FILTREO_MOTORE", "4000") or 4000)


def _get(url, attesa=4):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": AGENTE}), timeout=attesa) as r:
            return r.status, r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def chiedi_motore(dominio, attesa=6):
    """risposta del motore per un dominio: BLOCKED, RESOLVED, CACHED, … ("" = nessuna risposta)."""
    corpo = json.dumps({"query": dominio, "type": "A", "clientName": "filtreo-prova-aggiornamento"}).encode()
    try:
        req = urllib.request.Request(_api() + "/api/query", data=corpo, method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=attesa) as r:
            j = json.loads(r.read(20000).decode("utf-8", "replace"))
        return str(j.get("responseType") or j.get("reason") or "").upper()
    except Exception:
        return ""


def _lista_env(nome, di_serie):
    v = os.environ.get(nome, "")
    return [x for x in v.replace(",", " ").split() if x] or list(di_serie)


def motore_in_pausa():
    c, t = _get(_api() + "/api/blocking/status", 3)
    if c != 200:
        return None
    try:
        return not json.loads(t).get("enabled", True)
    except ValueError:
        return None


def prove(attesa_liste=None, figlio=None):
    """(ok, testo): salute del pannello, motore che risponde, blocco di una pubblicità di prova, siti normali che passano."""
    attesa_liste = attesa_liste if attesa_liste is not None else int(os.environ.get("FILTREO_ATTESA_PROVA", "300") or 300)
    pub = _lista_env("FILTREO_PROVA_PUB", ("ads.pubmatic.com", "ib.adnxs.com", "doubleclick.net"))
    siti = _lista_env("FILTREO_PROVA_SITI", ("www.wikipedia.org", "www.google.com"))
    fine = time.time() + 90
    while _get("http://127.0.0.1:%d/salute" % _porta_pannello(), 3)[0] != 200:
        if (figlio is not None and figlio.poll() is not None) or time.time() > fine:
            return False, "il pannello non risponde (salute)"
        time.sleep(1)
    fine = time.time() + 120
    while _get(_api() + "/api/blocking/status", 3)[0] != 200:
        if time.time() > fine:
            return False, "il motore non risponde"
        time.sleep(1)
    if motore_in_pausa():
        return False, "filtro in pausa: prova del blocco non possibile"
    fine = time.time() + attesa_liste
    while True:
        r = {d: chiedi_motore(d) for d in pub}
        if any(v == "BLOCKED" for v in r.values()):
            break
        if time.time() > fine:
            return False, "pubblicità di prova non bloccata (%s)" % ", ".join("%s=%s" % (d, v or "nessuna risposta") for d, v in r.items())
        if figlio is not None and figlio.poll() is not None:
            return False, "il pannello nuovo si è fermato durante la prova"
        time.sleep(3)
    for d in siti:
        v = ""
        for _i in range(3):
            v = chiedi_motore(d)
            if v and v != "BLOCKED":
                break
            time.sleep(2)
        if not v:
            return False, "nessuna risposta DNS per %s" % d
        if v == "BLOCKED":
            return False, "sito normale bloccato (%s)" % d
    if figlio is not None and figlio.poll() is not None:
        return False, "il pannello nuovo si è fermato"
    if _get("http://127.0.0.1:%d/salute" % _porta_pannello(), 3)[0] != 200:
        return False, "il pannello non risponde più (salute)"
    return True, "salute, DNS, blocco pubblicità e siti normali: tutto passa"


# ───────────── motore e pannello ─────────────
def _env(app):
    e = dict(os.environ)
    e["FILTREO_APP"] = app
    e.pop("FILTREO_IN_PROVA", None)
    return e


def prepara_config(app):
    try:
        r = subprocess.run([sys.executable, os.path.join(app, "filtreo_liste.py"), "--prepara"], cwd=app, env=_env(app),
                           capture_output=True, text=True, timeout=300)
        return r.returncode == 0, (r.stdout + r.stderr).strip().splitlines()[-1:] if (r.stdout + r.stderr).strip() else []
    except Exception as e:
        return False, [str(e)[:120]]


def _pid_motore():
    try:
        return int(open(PID_BLOCKY).read().strip())
    except (OSError, ValueError):
        return 0


def riavvia_motore(attesa=45):
    """Blocky gira nel ciclo di run.sh: fermarlo = riparte da solo con la config nuova. Aspetta che sia ripartito
    (numero di processo nuovo), così le prove parlano con il motore NUOVO e non con quello che si sta fermando."""
    pid = _pid_motore()
    if not pid:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return False
    fine = time.time() + attesa
    while time.time() < fine:
        time.sleep(0.5)
        nuovo = _pid_motore()
        if nuovo and nuovo != pid:
            try:
                os.kill(nuovo, 0)
                return True
            except OSError:
                pass
    return False


def diventa_pannello(app):
    """il processo diventa il pannello della cartella «app» (stesso PID: il contenitore non si ferma)."""
    registro("avvio il pannello da %s" % app)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os.chdir(app)
    os.execve(sys.executable, [sys.executable, os.path.join(app, "filtreo_pannello.py")], _env(app))


def _ferma(figlio):
    if figlio is None or figlio.poll() is not None:
        return
    try:
        figlio.terminate()
        figlio.wait(10)
    except Exception:
        try:
            figlio.kill()
            figlio.wait(5)
        except Exception:
            pass


# ───────────── il guardiano (versione di PRIMA, processo che sorveglia la prova) ─────────────
def _porta_ponte():
    """mentre il guardiano prepara la config e riavvia il motore nessun pannello ascolta: un piccolo server risponde
    /salute (il watchdog di Home Assistant non riavvia l'add-on) e «Aggiornamento in corso» a tutto il resto."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class P(BaseHTTPRequestHandler):
        def _r(self):
            ok = self.path.rstrip("/") == "/salute"
            b = json.dumps({"ok": True} if ok else {"ok": False, "testo": "Aggiornamento in corso…", "in_corso": True}).encode()
            self.send_response(200 if ok else 503)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Retry-After", "30")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        do_GET = do_POST = _r

        def log_message(self, *a):
            pass
    try:
        ThreadingHTTPServer.allow_reuse_address = True
        srv = ThreadingHTTPServer(("0.0.0.0", _porta_pannello()), P)
    except OSError:
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _chiudi_ponte(srv):
    if srv is not None:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass


def guardia():
    s = _stato()
    p = s.get("prova") or {}
    app = os.path.join(_base(), "app")
    versione = (p.get("a") or {}).get("versione", "")
    registro("prova della versione %s (rilascio %s) in corso" % (versione, (p.get("a") or {}).get("rilascio")))
    ok, motivo = True, ""
    figlio = None
    ponte = _porta_ponte()
    try:
        okp, coda = prepara_config(app)
        if not okp:
            ok, motivo = False, "preparazione della configurazione non riuscita (%s)" % " ".join(coda)[:120]
        else:
            riavvia_motore()
            _chiudi_ponte(ponte)
            ponte = None
            e = _env(app)
            e["FILTREO_IN_PROVA"] = "1"
            figlio = subprocess.Popen([sys.executable, os.path.join(app, "filtreo_pannello.py")], cwd=app, env=e)
            time.sleep(2)
            ok, motivo = prove(figlio=figlio)
    except Exception as ex:
        ok, motivo = False, "errore durante la prova (%s)" % str(ex)[:120]
    _ferma(figlio)
    _chiudi_ponte(ponte)
    if ok:
        _salva_stato(prova=None, installata={"versione": versione, "rilascio": (p.get("a") or {}).get("rilascio", 0)})
        _esito("aggiornato", "Casa aggiornata alla %s" % versione, versione, motivo)
        _avvisa("Filtreo: Casa aggiornata alla %s." % versione)
        diventa_pannello(app)
        return
    # non va: si torna alla versione di prima
    torna = torna_indietro(p.get("cartelle") or {})
    t = dict(s.get("tentativi") or {})
    k = str((p.get("a") or {}).get("rilascio", 0))
    t[k] = int(t.get(k, 0)) + 1
    _salva_stato(prova=None, tentativi=t)
    ponte = _porta_ponte()
    okp, _c = prepara_config(torna)
    riavvia_motore()
    _chiudi_ponte(ponte)
    _esito("tornato", "Aggiornamento alla %s non riuscito · Versione %s ripristinata" % (versione, (p.get("da") or {}).get("versione", "precedente")), versione, motivo)
    _avvisa("Filtreo: l'aggiornamento di Casa alla %s non è riuscito (%s). Ripristinata la versione di prima." % (versione, motivo))
    diventa_pannello(torna)


# ───────────── l'aggiornamento, dal pannello ─────────────
def aggiorna(base=None, manuale=False, esegui=True):
    """tutto il giro. Con esegui=False (prove) si ferma prima di diventare il guardiano e ritorna (ok, testo, info)."""
    if not _lock.acquire(blocking=False):
        return False, "Aggiornamento già in corso", None
    _in_corso.update(si=True, fase="verifica")
    try:
        if (_stato().get("prova") or {}).get("in_corso"):
            return False, "Aggiornamento già in corso", None
        ins = installata()
        registro("verifica del canale %s (installata %s, rilascio %s)%s" % (base or canale(), ins["versione"], ins["rilascio"], " · su richiesta" if manuale else ""))
        try:
            m = leggi_canale(base)
        except ErroreCanale as e:
            _salva_stato(ultima_verifica=int(time.time()), errore_verifica=str(e))
            _esito("errore", "Impossibile verificare", "", str(e))
            return False, "Impossibile verificare: %s." % e, None
        _salva_stato(ultima_verifica=int(time.time()), errore_verifica="")
        if m["rilascio"] <= ins["rilascio"]:
            _salva_stato(disponibile=None)
            if manuale:
                _esito("nessuno", "Versione più recente installata", ins["versione"])
            else:
                registro("nessun aggiornamento (installata %s)" % ins["versione"])
            return True, "Versione più recente installata", None
        _salva_stato(disponibile={"versione": m["versione"], "rilascio": m["rilascio"], "data": str(m.get("data") or "")[:10]})
        n = int((_stato().get("tentativi") or {}).get(str(m["rilascio"]), 0))
        if n >= TENTATIVI_MAX and not manuale:
            registro("la %s non ha passato la prova %d volte: si aspetta il prossimo rilascio" % (m["versione"], n))
            return False, "Versione %s non installabile su questa Casa" % m["versione"], None
        if motore_in_pausa():
            _esito("rimandato", "Aggiornamento alla %s rimandato · Filtro in pausa" % m["versione"], m["versione"])
            return False, "Filtro in pausa: aggiornamento rimandato", None
        _in_corso["fase"] = "download"
        registro("scarico la %s (rilascio %d, %d byte)" % (m["versione"], m["rilascio"], m["byte"]))
        try:
            nuova = prepara_pacchetto(m, base)
        except ErroreCanale as e:
            _esito("errore", "Impossibile aggiornare alla %s" % m["versione"], m["versione"], str(e))
            return False, "Impossibile aggiornare: %s." % e, None
        _in_corso["fase"] = "prova"
        okb, perche = prove(attesa_liste=60)
        if not okb:
            shutil.rmtree(nuova, ignore_errors=True)
            _esito("rimandato", "Aggiornamento alla %s rimandato · Nuovo tentativo la prossima notte" % m["versione"], m["versione"],
                   "la versione installata non passa la prova (%s)" % perche)
            return False, "Aggiornamento rimandato: %s" % perche, None
        # da qui la prova: la guardia è la copia di QUESTO file (versione di prima)
        shutil.copyfile(os.path.abspath(__file__), _f(F_GUARDIA))
        cart = scambia(nuova)
        _salva_stato(prova={"in_corso": True, "inizio": int(time.time()), "da": ins,
                            "a": {"versione": m["versione"], "rilascio": m["rilascio"], "impronta": m.get("impronta", "")},
                            "cartelle": cart})
        registro("codice nuovo al suo posto (prima: %s): prova con il guardiano" % cart["prima"])
        if not esegui:
            return True, "pronto per la prova", cart
        _avvisa("Filtreo: aggiornamento di Casa alla %s in corso. Internet si ferma per un minuto o due; se qualcosa non va torna alla versione di prima." % m["versione"])
        diventa_guardiano()
        return True, "Aggiornamento in corso", cart   # (non si arriva qui: exec)
    except Exception as e:
        _esito("errore", "Impossibile aggiornare", "", str(e)[:160])
        return False, "Impossibile aggiornare. Riprova.", None
    finally:
        _in_corso.update(si=False, fase="")
        _lock.release()


def diventa_guardiano():
    g = _f(F_GUARDIA)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    e = dict(os.environ)
    e.pop("FILTREO_IN_PROVA", None)
    # il guardiano importa firma_ed25519 solo per verificare: non serve durante la prova
    os.execve(sys.executable, [sys.executable, g, "--guardia"], e)


def avvia_ora():
    """POST /pannello/aggiornamento/ora: parte in sottofondo, la risposta torna subito."""
    if _in_corso["si"] or (_stato().get("prova") or {}).get("in_corso"):
        return False, "Aggiornamento già in corso"
    threading.Thread(target=aggiorna, kwargs={"manuale": True}, daemon=True).start()
    return True, "Verifica in corso…"


# ───────────── ogni minuto (dal giro dell'orologio del pannello) ─────────────
_giorno = {"fatto": ""}


def giro(adesso=None):
    i = impostazioni()
    if not i["automatici"]:
        return False
    t = adesso or datetime.now()
    oggi = t.strftime("%Y-%m-%d")
    if _giorno["fatto"] == oggi or _stato().get("ultimo_giro") == oggi:
        return False
    h, mi = (int(x) for x in i["ora"].split(":"))
    minuti = t.hour * 60 + t.minute - (h * 60 + mi)
    if not (0 <= minuti <= 30):   # entro mezz'ora dall'ora scelta (il pannello appena riavviato non salta la notte)
        return False
    _giorno["fatto"] = oggi
    _salva_stato(ultimo_giro=oggi)
    threading.Thread(target=aggiorna, daemon=True).start()
    return True


# ───────────── all'avvio ─────────────
def chiudi_prova_interrotta():
    """Casa ripartita mentre una prova era a metà: si torna alla versione di prima. Ritorna la cartella da usare o None."""
    p = _stato().get("prova") or {}
    if not p.get("in_corso"):
        return None
    torna = torna_indietro(p.get("cartelle") or {})
    _salva_stato(prova=None)
    _esito("tornato", "Aggiornamento alla %s interrotto · Versione precedente ripristinata" % (p.get("a") or {}).get("versione", ""),
           (p.get("a") or {}).get("versione", ""), "Casa ripartita durante la prova")
    return torna


def avvia():
    """dal pannello, all'avvio: chiude una prova interrotta (non quando è il pannello in prova del guardiano)."""
    if os.environ.get("FILTREO_IN_PROVA") == "1":
        return
    torna = chiudi_prova_interrotta()
    if torna and os.path.realpath(torna) != os.path.realpath(QUI):
        prepara_config(torna)
        riavvia_motore()
        diventa_pannello(torna)


# ───────────── per il pannello ─────────────
def stato_pannello():
    s = _stato()
    i = impostazioni()
    ins = installata()
    p = s.get("prova") or {}
    d = s.get("disponibile") or None
    if d and int(d.get("rilascio") or 0) <= ins["rilascio"]:
        d = None
    return {"versione": ins["versione"], "rilascio": ins["rilascio"], "impronta": ins["impronta"],
            "automatici": i["automatici"], "ora": i["ora"], "canale": canale(),
            "ultima_verifica": int(s.get("ultima_verifica") or 0), "errore_verifica": s.get("errore_verifica") or "",
            "ultimo_esito": s.get("ultimo_esito") or None, "disponibile": d,
            "in_corso": bool(_in_corso["si"] or p.get("in_corso")), "fase": _in_corso["fase"] or ("prova" if p.get("in_corso") else ""),
            "registro": righe_registro(30)}


def main(argv):
    if "--guardia" in argv:
        guardia()
        return 0
    if "--scegli" in argv:
        torna = chiudi_prova_interrotta()
        print(torna or _app_scelta())
        return 0
    if "--controlla" in argv:
        try:
            print(json.dumps(leggi_canale(), ensure_ascii=False, indent=1))
            return 0
        except ErroreCanale as e:
            print("✖ %s" % e)
            return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
