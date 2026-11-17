#!/usr/bin/env python3
"""FILTREO — la «casella» del paracadute dentro l'add-on di Home Assistant (Raspberry di Giò).

Sul Pi non c'è ~/filtreo15 e da fuori (Terminal & SSH) la cartella /data dell'add-on non si vede.
Per questo il Mac lascia i messaggi in una casella sulla cartella condivisa /share/filtreo/consegna
e l'add-on li prende da qui (run.sh guarda la casella ogni 15 secondi, solo con un «test -e»: niente memoria).

Messaggi che il Mac può lasciare (si scrivono prima come .tmp e poi si rinominano: arrivano interi):
  cloudflare.env          righe CF_TOKEN= / CF_ACCOUNT= / CF_KV_NS= / CF_CONTEGGI=   → /data/segreti/cloudflare.env (600)
                          il file nella casella viene svuotato subito (resta vuoto come «.ricevuto»)
  opzioni.env             righe FILTREO_PARACADUTE_URL= / FILTREO_DOH_URL= (solo indirizzi controllati)
                          → /data/opzioni.env (valgono dal prossimo avvio dell'add-on)
  pannello-fuori.codice   il codice del link «pannello da fuori casa» (40-64 cifre esadecimali) o «chiudi»
                          → /data/pannello-fuori.json (svuotato subito dalla casella)
  richiesta-esporta       (dentro: un numero qualsiasi) → dati del paracadute in /share/filtreo/paracadute-dati
  richiesta-sync          → paracadute-sync.py --forza (modalità copiate su Cloudflare)
  richiesta-profili       → crea (se mancano) i profili «fuori casa» degli iPhone/iPad e li lascia in
                            consegna/profili/ (il Mac li ritira e li svuota)
  richiesta-prova         (dentro: «numero url») → prova vera del paracadute contro il filtro di casa
Ogni richiesta lascia la risposta in esito-<nome>.txt (prima riga: lo stesso numero). In più stato.json.
Niente segreti in uscita: i codici restano nel Pi, verso fuori vanno solo le loro impronte (sha256).
Solo libreria standard di Python 3. Uso: paracadute-addon.py --giro | --esporta DIR | --stato
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DATA = os.environ.get("FILTREO_DATA", "/data")
CASELLA = os.environ.get("FILTREO_CASELLA", "/share/filtreo/consegna")
USCITA = os.environ.get("FILTREO_PARACADUTE_DATI", os.path.join(os.path.dirname(CASELLA.rstrip("/")), "paracadute-dati"))
QUI = os.path.dirname(os.path.abspath(__file__))
SYNC = os.environ.get("FILTREO_PARACADUTE_SYNC") or os.path.join(QUI, "paracadute-sync.py")
SEGRETI = os.environ.get("FILTREO_SEGRETI_CF") or os.path.join(DATA, "segreti", "cloudflare.env")
OPZIONI = os.path.join(DATA, "opzioni.env")
PANNELLO = "http://127.0.0.1:%s" % os.environ.get("INGRESS_PORT", "8099")
MOTORE = "http://127.0.0.1:%s" % os.environ.get("FILTREO_MOTORE", "4000")
APP = os.environ.get("FILTREO_APP", "/opt/filtreo/app")

ESA32 = re.compile(r"^[0-9a-f]{32}$")
TOKEN_OK = re.compile(r"^[A-Za-z0-9_-]{30,120}$")
CONTEGGI_OK = re.compile(r"^[A-Za-z0-9_-]{32,128}$")   # segreto di lettura dei conti di Cloudflare (CF_CONTEGGI)
# indirizzi ammessi: solo il paracadute su workers.dev e il nome Tailscale del nodo (porte che Funnel permette)
VALORI_OK = {
    "FILTREO_PARACADUTE_URL": re.compile(r"^https://filtreo-paracadute[a-z0-9-]{0,30}\.[a-z0-9-]{1,63}\.workers\.dev$"),
    "FILTREO_DOH_URL": re.compile(r"^https://[a-z0-9-]{1,63}\.[a-z0-9-]{1,63}\.ts\.net(:(443|8443|10000))?$"),
}


def scrivi_privato(p, testo, modo=0o600):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, modo)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(testo)
    os.chmod(p + ".tmp", modo)
    os.replace(p + ".tmp", p)


def leggi_righe(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read().splitlines()
    except OSError:
        return []


def coppie(righe):
    out = {}
    for r in righe:
        r = r.strip()
        if not r or r.startswith("#") or "=" not in r:
            continue
        k, v = r.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def unisci_env(p, nuovi, intestazione, modo):
    """aggiorna le righe NOME=valore di p (valore vuoto = toglie la riga), lascia il resto com'è."""
    rr = leggi_righe(p) or [intestazione]
    rr = [r for r in rr if r.split("=", 1)[0].strip() not in nuovi]
    rr += ["%s=%s" % (k, v) for k, v in nuovi.items() if v]
    scrivi_privato(p, "\n".join(rr) + "\n", modo)


def ritira(p):
    """il messaggio è stato letto: lo svuoto (così un segreto non resta sulla cartella condivisa) e lo segno ricevuto."""
    try:
        with open(p, "w"):
            pass
        os.replace(p, p + ".ricevuto")
    except OSError:
        pass


# ───────── messaggi ─────────
def msg_cloudflare(p):
    s = coppie(leggi_righe(p))
    ritira(p)
    nuovi = {}
    if TOKEN_OK.match(s.get("CF_TOKEN", "")):
        nuovi["CF_TOKEN"] = s["CF_TOKEN"]
    if CONTEGGI_OK.match(s.get("CF_CONTEGGI", "")):
        nuovi["CF_CONTEGGI"] = s["CF_CONTEGGI"]
    for k in ("CF_ACCOUNT", "CF_KV_NS"):
        if ESA32.match(s.get(k, "")):
            nuovi[k] = s[k]
    if not nuovi:
        return "casella: accesso a Cloudflare non valido, ignorato"
    os.makedirs(os.path.dirname(SEGRETI), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(SEGRETI), 0o700)
    unisci_env(SEGRETI, nuovi, "# Filtreo - accesso al paracadute su Cloudflare (non condividere questo file)", 0o600)
    return "casella: accesso a Cloudflare salvato (%s)" % ", ".join(sorted(k for k in nuovi if k not in ("CF_TOKEN", "CF_CONTEGGI")) + (["chiave"] if "CF_TOKEN" in nuovi else []) + (["conteggi"] if "CF_CONTEGGI" in nuovi else []))


def msg_opzioni(p):
    s = coppie(leggi_righe(p))
    ritira(p)
    nuovi = {}
    for k, regola in VALORI_OK.items():
        if k in s:
            v = s[k].rstrip("/")
            if v == "" or regola.match(v):
                nuovi[k] = v
    if not nuovi:
        return "casella: nessuna opzione valida"
    unisci_env(OPZIONI, nuovi, "# Filtreo - impostazioni (le scrive il Mac con PARACADUTE-GIO.command)", 0o600)
    return "casella: impostazioni salvate (%s): valgono dal prossimo avvio" % ", ".join(sorted(nuovi))


def msg_pannello_fuori(p):
    c = "".join(leggi_righe(p)).strip()
    ritira(p)
    f = os.path.join(DATA, "pannello-fuori.json")
    if c == "chiudi":
        if os.path.exists(f):
            os.makedirs(os.path.join(DATA, "_da_buttare"), exist_ok=True)
            os.replace(f, os.path.join(DATA, "_da_buttare", "pannello-fuori-%s.json" % time.strftime("%m%d%H%M%S")))
        return "casella: link del pannello da fuori casa chiuso"
    if not re.fullmatch(r"[a-f0-9]{40,64}", c):
        return "casella: codice del pannello da fuori casa non valido"
    scrivi_privato(f, json.dumps({"codice": c}) + "\n")
    return "casella: link del pannello da fuori casa pronto"


# ───────── dati del paracadute (come jetson/paracadute-dati.sh, ma per /data dell'add-on) ─────────
def esporta(D, O):
    os.makedirs(O, exist_ok=True)
    modi = {m["id"]: m for m in json.load(open(os.path.join(D, "modalita.json"), encoding="utf-8")) if isinstance(m, dict) and m.get("id")}
    disp = [d for d in json.load(open(os.path.join(D, "dispositivi.json"), encoding="utf-8")) if isinstance(d, dict)]
    cand = sorted((d for d in disp if d.get("proprie") and d.get("modo") in modi and not modi[d["modo"]].get("pre") and not modi[d["modo"]].get("solo_permessi")), key=lambda d: (bool(modi[d["modo"]].get("famiglia")), -len(modi[d["modo"]].get("fonti", []))))   # la base viene da una modalità SENZA protezione famiglia (se c'è)
    pul = next((d["id"] for d in cand if not modi[d["modo"]].get("lavoro")), None)
    lav = next((d["id"] for d in cand if modi[d["modo"]].get("lavoro")), None)
    sorg = pul or lav or next((d["id"] for d in disp if d.get("principale")), "casa")
    L = os.path.join(D, "liste")
    shutil.copyfile(os.path.join(L, "dev-%s.txt" % sorg), os.path.join(O, "liste.txt"))
    if lav and os.path.exists(os.path.join(L, "dev-%s-ok.txt" % lav)):
        shutil.copyfile(os.path.join(L, "dev-%s-ok.txt" % lav), os.path.join(O, "lavoro.txt"))
    else:
        open(os.path.join(O, "lavoro.txt"), "w").close()
    try:   # adulti e scommesse per i profili «+f» (lo scrive Casa: _scrivi_famiglia_paracadute); se manca, solo l'intestazione
        shutil.copyfile(os.path.join(L, "famiglia-paracadute.txt"), os.path.join(O, "famiglia.txt"))
    except OSError:
        open(os.path.join(O, "famiglia.txt"), "w").write("# protezione famiglia: nessun dato\n")

    def leggi(n):
        try:
            return open(os.path.join(L, n), encoding="utf-8").read()
        except OSError:
            return ""
    mai = {"firebaselogging.googleapis.com", "firebaselogging-pa.googleapis.com"}
    try:
        import ast
        for n in ast.parse(open(os.path.join(APP, "filtreo_liste.py"), encoding="utf-8").read()).body:
            if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "MAI_PERMESSI" for t in n.targets):
                mai = set(ast.literal_eval(n.value))
    except Exception:
        pass
    ok, no = leggi("manuale-ok.txt"), leggi("blocca.txt")
    acapo = lambda t: t if (not t or t.endswith("\n")) else t + "\n"  # noqa: E731
    open(os.path.join(O, "sempre_ok.txt"), "w").write(acapo(ok))
    open(os.path.join(O, "sempre_no.txt"), "w").write(acapo(no) + "# telemetria mai permessa\n" + "".join(x + "\n" for x in sorted(mai)))
    r = subprocess.run([sys.executable, SYNC, "--data", D, "--codici", os.path.join(O, "codici.json")],
                       capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(((r.stdout or "").strip().splitlines() or ["impronte non calcolate"])[-1])
    conta = lambda t: sum(1 for x in t.splitlines() if x.strip() and not x.strip().startswith(("#", "/")))  # noqa: E731
    righe = sum(1 for _ in open(os.path.join(O, "liste.txt"), encoding="utf-8", errors="replace"))
    return "dati pronti: liste da «%s» (%d righe) · lavoro da: %s · sempre permessi %d · sempre bloccati %d · %s" % (
        sorg, righe, lav or "nessuno", conta(ok), conta(no) + len(mai), (r.stdout or "").strip().splitlines()[-1].split(" (")[0])


# ───────── profili «fuori casa» per i telefoni (li crea il pannello stesso, da dentro l'add-on) ─────────
def _http(metodo, percorso, timeout=30):
    req = urllib.request.Request(PANNELLO + percorso, data=b"" if metodo == "POST" else None, method=metodo)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _dnsp():
    try:
        d = json.load(open(os.path.join(DATA, "dns-personale.json"), encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def profili():
    if not os.environ.get("FILTREO_DOH_URL"):
        return ["✖ il DNS fuori casa non è acceso nell'add-on (manca FILTREO_DOH_URL): riavvia l'add-on dopo PARACADUTE-GIO"]
    disp = [d for d in json.load(open(os.path.join(DATA, "dispositivi.json"), encoding="utf-8")) if isinstance(d, dict)]
    telefoni = [d for d in disp if re.search(r"iphone|ipad", (d.get("nome", "") + " " + d.get("id", "")).lower())]
    out = []
    if not telefoni:
        out.append("! nel pannello non vedo ancora un iPhone: crealo da Dispositivi (o rinominalo «iPhone») e rilancia")
    for d in telefoni:
        if not any(isinstance(v, dict) and v.get("disp") == d["id"] for v in _dnsp().values()):
            _http("POST", "/pannello/dnsp/crea?" + urllib.parse.urlencode({"disp": d["id"], "nome": d.get("nome") or d["id"]}), 90)
    cartella = os.path.join(CASELLA, "profili")
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    for n, v in sorted(_dnsp().items()):
        if not isinstance(v, dict) or v.get("disp") not in {d["id"] for d in telefoni}:
            continue
        b = _http("GET", "/pannello/dnsp/profilo?" + urllib.parse.urlencode({"n": n}))
        fd = os.open(os.path.join(cartella, "Filtreo-%s.mobileconfig" % n), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(b)
        par = os.environ.get("FILTREO_PARACADUTE_URL", "")
        out.append("✓ profilo %s pronto (%s)" % (n, "con il paracadute" if par and par.encode() in b else "SENZA paracadute"))
    return out


# ───────── prova vera: paracadute contro il filtro di casa (i codici restano qui) ─────────
FISSI = ["www.repubblica.it", "www.google.com", "www.youtube.com", "web.whatsapp.com", "www.apple.com",
         "ib.adnxs.com", "pubads.g.doubleclick.net", "region1.google-analytics.com", "script.hotjar.com",
         "connect.facebook.net", "www.googletagmanager.com", "app.pendo.io"]


def _domanda(n):
    return struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)


def _esito(d):
    if len(d) < 12:
        return "vuoto"
    return "bloccato" if d[7] and d[-4:] == bytes(4) else ("passa" if d[7] else ("inesistente" if d[3] & 15 == 3 else "vuoto"))


def _chiedi(url, n, timeout=10):
    t = time.time()
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, data=_domanda(n), headers={
            "Content-Type": "application/dns-message", "Accept": "application/dns-message", "User-Agent": "Filtreo-prova"}), timeout=timeout)
        return _esito(r.read()), int((time.time() - t) * 1000)
    except urllib.error.HTTPError as e:
        return "errore %d" % e.code, 0
    except Exception as e:
        return "errore %s" % type(e).__name__, 0


def prova(url):
    url = url.rstrip("/")
    if not VALORI_OK["FILTREO_PARACADUTE_URL"].match(url):
        return ["✖ indirizzo del paracadute non valido"], False
    out, ok = [], True
    r = _chiedi(url + "/d/codice-che-non-esiste-123456", "www.repubblica.it")
    g = r[0] == "errore 404"
    ok = ok and g
    out.append("%s il paracadute risponde (codice sconosciuto rifiutato: %s)" % ("✓" if g else "✖", r[0]))
    voci = [(n, v) for n, v in sorted(_dnsp().items()) if isinstance(v, dict) and v.get("codice")]
    if not voci:
        out.append("! nessun profilo «fuori casa» ancora: provo solo che risponda")
    try:
        pro = json.load(open(os.path.join(USCITA, "codici.json"), encoding="utf-8"))
    except (OSError, ValueError):
        pro = {}
    for n, v in voci:
        p = pro.get(hashlib.sha256(str(v["codice"]).encode()).hexdigest(), "?")
        uguali, tempi, diversi = 0, [], []
        for d in FISSI:
            a, ms = _chiedi(url + "/d/" + v["codice"], d)
            b, _ = _chiedi(MOTORE + "/dns-query/" + n, d, 6)
            tempi.append(ms)
            if a.startswith("errore"):
                diversi.append("%s (paracadute: %s)" % (d, a))
            elif (a == "bloccato") == (b == "bloccato"):
                uguali += 1
            else:
                diversi.append("%s (paracadute %s, casa %s)" % (d, a, b))
        med = sorted(tempi)[len(tempi) // 2]
        g = not diversi and med < 1500
        ok = ok and g
        out.append("%s %s (modalità copiata: %s): uguali a casa %d su %d · tempo medio %d ms" % ("✓" if g else "✖", n, p, uguali, len(FISSI), med))
        out += ["     diverso: " + x for x in diversi[:6]]
    return out, ok


# ───────── stato (per il Mac: niente segreti) ─────────
def stato():
    s = coppie(leggi_righe(SEGRETI))
    o = coppie(leggi_righe(OPZIONI))
    completi = bool(TOKEN_OK.match(s.get("CF_TOKEN", ""))) and bool(ESA32.match(s.get("CF_ACCOUNT", ""))) and bool(ESA32.match(s.get("CF_KV_NS", "")))
    try:
        k = json.load(open(os.path.join(DATA, "paracadute-kv.json"), encoding="utf-8"))
    except (OSError, ValueError):
        k = {}
    try:
        ver = open(os.path.join(APP, "VERSIONE"), encoding="utf-8").read().strip()
    except OSError:
        ver = ""
    x = {"quando": time.strftime("%Y-%m-%d %H:%M:%S"), "versione": ver,
         "chiave_cloudflare": "completa" if completi else ("senza chiave" if s.get("CF_KV_NS") else "manca"),
         "conteggi_chiave": bool(CONTEGGI_OK.match(s.get("CF_CONTEGGI", ""))),
         "paracadute_impostato": o.get("FILTREO_PARACADUTE_URL", ""), "paracadute_attivo": os.environ.get("FILTREO_PARACADUTE_URL", ""),
         "fuori_casa_impostato": o.get("FILTREO_DOH_URL", ""), "fuori_casa_attivo": os.environ.get("FILTREO_DOH_URL", ""),
         "pannello_fuori": os.path.exists(os.path.join(DATA, "pannello-fuori.json")),
         "profili_fuori_casa": len([1 for v in _dnsp().values() if isinstance(v, dict) and v.get("codice")]),
         "ultima_copia_modalita": k.get("quando", "")}
    os.makedirs(CASELLA, exist_ok=True)
    with open(os.path.join(CASELLA, "stato.json.tmp"), "w", encoding="utf-8") as f:
        json.dump(x, f, ensure_ascii=False, indent=1)
    os.replace(os.path.join(CASELLA, "stato.json.tmp"), os.path.join(CASELLA, "stato.json"))


def rispondi(nome, numero, righe):
    p = os.path.join(CASELLA, "esito-%s.txt" % nome)
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        f.write("%s\n" % numero + "".join(r + "\n" for r in righe))
    os.replace(p + ".tmp", p)


def giro():
    if not os.path.isdir(CASELLA):
        os.makedirs(CASELLA, exist_ok=True)
    log = []
    for nome, f in (("cloudflare.env", msg_cloudflare), ("opzioni.env", msg_opzioni), ("pannello-fuori.codice", msg_pannello_fuori)):
        p = os.path.join(CASELLA, nome)
        if os.path.isfile(p):
            try:
                log.append(f(p))
            except Exception as e:
                ritira(p)
                log.append("casella: %s non letto (%s)" % (nome, type(e).__name__))
    for azione in ("esporta", "sync", "profili", "prova"):
        p = os.path.join(CASELLA, "richiesta-" + azione)
        if not os.path.isfile(p):
            continue
        testo = " ".join(leggi_righe(p)).split()
        ritira(p)
        numero = testo[0] if testo else "0"
        try:
            if azione == "esporta":
                righe = [esporta(DATA, USCITA), "FATTO"]
            elif azione == "sync":
                r = subprocess.run([sys.executable, SYNC, "--data", DATA, "--segreti", SEGRETI, "--forza"],
                                   capture_output=True, text=True, timeout=90)
                righe = [((r.stdout or "").strip().splitlines() or ["paracadute: nessuna risposta"])[-1][:300], "FATTO" if r.returncode == 0 else "ERRORE"]
            elif azione == "profili":
                righe = profili() + ["FATTO"]
            else:
                rr, ok = prova(testo[1] if len(testo) > 1 else "")
                righe = rr + ["PARACADUTE_OK" if ok else "PARACADUTE_NON_OK", "FATTO"]
        except Exception as e:
            righe = ["✖ %s non riuscito (%s: %s)" % (azione, type(e).__name__, str(e)[:120]), "ERRORE"]
        rispondi(azione, numero, righe)
        log.append("casella: %s → %s" % (azione, righe[-1]))
    stato()
    return log


def main():
    a = argparse.ArgumentParser(description="Filtreo: casella del paracadute nell'add-on")
    a.add_argument("--giro", action="store_true")
    a.add_argument("--esporta", default="")
    a.add_argument("--stato", action="store_true")
    o = a.parse_args()
    if o.esporta:
        print(esporta(DATA, o.esporta))
        return 0
    if o.stato:
        stato()
        return 0
    for r in giro():
        print("Filtreo " + r, flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # mai dettagli segreti nei log
        print("Filtreo casella: errore inatteso (%s)" % type(e).__name__)
        sys.exit(1)
