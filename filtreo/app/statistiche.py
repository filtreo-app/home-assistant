#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""statistiche.py — Filtreo 3.1: UN endpoint per le statistiche, lo stesso dato per app, widget e pannello web.

  GET /pannello/statistiche?periodo=oggi|7g|30g[&disp=<id dispositivo>]

Risposta (JSON stabile, versione 1; i campi nuovi si aggiungono, quelli che ci sono non cambiano):
{
  "versione": 1,
  "periodo": "oggi",                      # oggi | 7g | 30g
  "da": "2026-11-15", "a": "2026-11-15",  # giorni compresi (ora di Casa)
  "dispositivo": null | {"id": "d-1", "nome": "iPhone di Giò"},
  "aggiornato": "2026-11-15T14:03:05",
  "totale": {"richieste": 1200, "bloccate": 180, "percentuale": 15.0, "casa": 150, "cloudflare": 30},
  "serie": {"passo": "ora" | "giorno",
            "punti": [{"etichetta": "14", "inizio": "2026-11-15T14:00", "richieste": 90, "bloccate": 12}, …]},
            # oggi: 24 punti (00…23); 7g/30g: un punto per giorno, il più vecchio per primo, giorni senza dati = 0
  "categorie": [{"id": "pubblicita", "nome": "Pubblicità", "bloccate": 120, "percentuale": 66.7}, …],
  "dispositivi": [{"id": "d-1", "nome": "…", "richieste": 600, "bloccate": 90, "percentuale": 15.0, "casa": 80, "cloudflare": 10}, …],
  "aziende": [{"nome": "Google", "gruppo": "Alphabet", "bloccate": 70, "percentuale": 38.9, "conosciuta": true,
               "domini": ["googleads.g.doubleclick.net", …]}, …],   # «chi ti segue di più»: le prime 10
  "completo": {"categorie": true},  # false = alcuni domini sono ancora da classificare (in sottofondo): riprova tra un minuto
  # 0.9.1 — solo con periodo=oggi: ieri, per il confronto esatto («+12% su ieri alla stessa ora») e il grafico ora per ora
  "ieri": {"giorno": "2026-11-14", "richieste": 1500, "bloccate": 210,
           "stessa_ora": {"richieste": 1100, "bloccate": 160},   # ieri da mezzanotte fino a quest'ora (l'ora in corso in proporzione)
           "ore": [{"richieste": 40, "bloccate": 6}, …]}          # 24 punti, come serie.punti
}
0.9.1 — ogni punto di «serie» può avere anche "aziende": [{"nome": "Google", "bloccate": 12}, …] (le prime 3 di quell'ora o di quel
giorno; assente se non c'è niente o se il giorno è stato letto da una versione di prima).
Da dove vengono i numeri: il registro di Blocky (/data/log/<giorno>_ALL.log, lo stesso di resoconto()/_giorno()) e i conteggi di
Filtreo Cloud (cloudflare-conti.json, gli stessi del resoconto). Le richieste delle prove di Filtreo (filtreo-prova-*) non contano.
Le categorie vengono dalla lista che ha bloccato il dominio (gruppi di livelli.py) e dalle tue regole; per i giorni passati si
classificano i 500 domini più bloccati di ogni dispositivo (il resto va in «Altro»). I blocchi fatti da Filtreo Cloud non hanno il
dominio: entrano nel totale, nei dispositivi e in una categoria a parte «Fuori casa».

Velocità: i giorni finiti si leggono una volta e restano in statistiche-giorni.json; il giorno di oggi si legge a pezzi (solo le righe
nuove dall'ultima volta); la risposta resta in memoria 15 secondi. La classificazione dei domini nuovi gira in sottofondo.
"""
import hashlib
import json
import os
import re
import threading
import time
from collections import Counter
from datetime import date, datetime, timedelta

import filtro
import livelli

AZIENDE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aziende.json")
CACHE_GIORNI = os.path.join(filtro.DATA, "statistiche-giorni.json")
CACHE_CATEGORIE = os.path.join(filtro.DATA, "statistiche-categorie.json")
PERIODI = {"oggi": 1, "7g": 7, "30g": 30}
MAX_DOM_DISP = 500      # domini bloccati tenuti per dispositivo nei giorni finiti
MAX_DOM = 3000          # domini bloccati tenuti in tutto, per giorno
TTL_RISPOSTA = 15.0
MOTIVO = re.compile(r"^(RESOLVED|CACHED|BLOCKED|CONDITIONAL|CUSTOMDNS|HOSTSFILE|FILTERED|NOTFQDN|SPECIAL)\b")
HOST = re.compile(r"^(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]{1,}\.?$", re.I)

ALTRI = "altri"
NOMI_CATEGORIE = dict(livelli.NOMI_GRUPPI, regole="Le tue regole", app="App bloccate", altro="Altro",
                      cloudflare="Fuori casa (Filtreo Cloud)")
# un dominio in più liste: vale la categoria più «specifica»
PRIORITA = ("regole", "app", "sicurezza", "famiglia", "telemetria", "tracciamento", "fastidi", "pubblicita")

_l = threading.RLock()
_collegati = {"conti_cf": lambda: {}, "ore_cf": lambda g=None: [0] * 24, "risolvi_cf": lambda k, dd=None, voci=None: None,
              "dispositivi": lambda: [], "nodo_ips": lambda: set(), "e_nodo": lambda x: False, "voci_dns": lambda: [],
              "fonte_file": lambda url: "", "fonti": lambda: [], "app_domini": lambda: set(), "fissi": lambda: ({}, set())}
_oggi = {"giorno": "", "percorso": "", "pos": 0, "agg": None, "mappa": None}
_risposte = {}
_az = {"t": None, "suffissi": None}


def collega(**fn):
    """il pannello passa le sue funzioni (registro dei dispositivi, conteggi di Cloudflare, file delle liste): niente import circolari."""
    _collegati.update({k: v for k, v in fn.items() if callable(v)})


# ───────────── aziende ─────────────
def _aziende():
    try:
        t = os.path.getmtime(AZIENDE_FILE)
    except OSError:
        t = 0
    if _az["t"] != t:
        suff = {}
        try:
            for a in json.load(open(AZIENDE_FILE, encoding="utf-8")).get("aziende", []):
                for d in a.get("domini", []):
                    suff[d.lower().strip(".")] = (a["nome"], a.get("gruppo", a["nome"]))
        except (OSError, ValueError, KeyError):
            pass
        _az.update(t=t, suffissi=suff)
    return _az["suffissi"]


def azienda_nota(dom):
    """(nome, gruppo) dell'azienda del dominio secondo aziende.json, o None."""
    p = (dom or "").lower().rstrip(".").split(".")
    suff = _aziende()
    for i in range(len(p) - 1):
        x = suff.get(".".join(p[i:]))
        if x:
            return x
    return None


def radice(dom):
    p = (dom or "").lower().rstrip(".").split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) >= 2 else (dom or "")


def azienda(dom):
    """{nome, gruppo, conosciuta}: dalla mappa; altrimenti il dominio radice (conosciuta = false)."""
    x = azienda_nota(dom)
    if x:
        return {"nome": x[0], "gruppo": x[1], "conosciuta": True}
    r = radice(dom)
    return {"nome": r, "gruppo": r, "conosciuta": False}


# ───────────── lettura del registro ─────────────
_mappa_memo = {"t": 0.0, "v": None}


def _mappa():
    """indirizzo → id dispositivo, nome DNS personale → id, id → nome. Il nodo stesso conta sul dispositivo «nodo».
    Resta in memoria 60 secondi (gli indirizzi del nodo si cercano anche fra le interfacce e Tailscale)."""
    with _l:
        if _mappa_memo["v"] is not None and time.time() - _mappa_memo["t"] < 60:
            return _mappa_memo["v"]
    v = _mappa_nuova()
    with _l:
        _mappa_memo.update(t=time.time(), v=v)
    return v


def _mappa_nuova():
    dd = _collegati["dispositivi"]() or []
    ip, nomi = {}, {}
    for x in dd:
        nomi[x["id"]] = x.get("nome", x["id"])
        for i in [x.get("ip")] + list(x.get("ips") or []):
            if i:
                ip[i] = x["id"]
    nodo = next((x for x in dd if _collegati["e_nodo"](x)), None)
    if nodo:
        for i in _collegati["nodo_ips"]() or ():
            ip.setdefault(i, nodo["id"])
    dns = {}
    for n, v in _collegati["voci_dns"]() or []:
        if isinstance(v, dict) and v.get("disp") in nomi:
            dns[n] = v["disp"]
    firma = hashlib.sha1(json.dumps([ip, dns], sort_keys=True).encode()).hexdigest()[:12]
    return {"ip": ip, "dns": dns, "nomi": nomi, "firma": firma}


def _vuoto():
    return {"r": 0, "b": 0, "ore_r": [0] * 24, "ore_b": [0] * 24, "disp": {}, "dom": Counter(), "az": Counter(),
            "az_ore": [Counter() for _ in range(24)]}


def _vuoto_disp():
    return {"r": 0, "b": 0, "ore_r": [0] * 24, "ore_b": [0] * 24, "dom": Counter(), "az": Counter(),
            "az_ore": [Counter() for _ in range(24)]}


def _riga(agg, riga, mappa):
    riga = riga.rstrip("\n")
    if not riga:
        return
    sep = "\t" if "\t" in riga else ("," if "," in riga else None)
    c = [x.strip().strip('"') for x in riga.split(sep)]
    if len(c) < 4:
        return
    r = next((k for k in range(1, len(c)) if MOTIVO.match(c[k])), None)
    if r is None:
        return
    nome_c = c[2] if len(c) > 2 else ""
    if nome_c.startswith("filtreo-prova-"):
        return
    chi = mappa["dns"].get(nome_c) or mappa["ip"].get(c[1]) or ALTRI
    o = c[0][11:13]
    ora = int(o) % 24 if o.isdigit() else None
    d = agg["disp"].get(chi)
    if d is None:
        d = agg["disp"][chi] = _vuoto_disp()
    agg["r"] += 1
    d["r"] += 1
    if ora is not None:
        agg["ore_r"][ora] += 1
        d["ore_r"][ora] += 1
    if c[r].startswith("BLOCKED"):
        dom = next((c[k].rstrip(".").lower() for k in range(r + 1, len(c)) if HOST.match(c[k])), None)
        if not dom:
            return
        agg["b"] += 1
        d["b"] += 1
        if ora is not None:
            agg["ore_b"][ora] += 1
            d["ore_b"][ora] += 1
        agg["dom"][dom] += 1
        d["dom"][dom] += 1
        a = azienda(dom)["nome"]
        agg["az"][a] += 1
        d["az"][a] += 1
        if ora is not None:
            agg["az_ore"][ora][a] += 1
            d["az_ore"][ora][a] += 1


def _leggi_giorno(percorso, mappa):
    agg = _vuoto()
    with open(percorso, encoding="utf-8", errors="replace") as f:
        for riga in f:
            _riga(agg, riga, mappa)
    return agg


def _a_json(agg, tronca=True):
    """aggregato → forma salvabile (domini tagliati ai più bloccati)."""
    def dom(c, n):
        return dict(c.most_common(n) if tronca else c.items())
    def ore_az(x):   # 0.9.1: le prime 3 aziende di ogni ora (bastano per le capsule sotto il grafico)
        return [dict(c.most_common(3)) for c in x.get("az_ore") or [Counter() for _ in range(24)]]
    return {"r": agg["r"], "b": agg["b"], "ore_r": agg["ore_r"], "ore_b": agg["ore_b"],
            "dom": dom(agg["dom"], MAX_DOM), "az": dict(agg["az"]), "az_ore": ore_az(agg),
            "disp": {k: {"r": v["r"], "b": v["b"], "ore_r": v["ore_r"], "ore_b": v["ore_b"], "dom": dom(v["dom"], MAX_DOM_DISP),
                         "az": dict(v["az"]), "az_ore": ore_az(v)} for k, v in agg["disp"].items()}}


def _prime_aziende(c, n=3):
    """{nome: bloccate} → [{"nome", "bloccate"}] delle prime n (per i punti del grafico)."""
    return [{"nome": k, "bloccate": int(v)} for k, v in Counter(c or {}).most_common(n) if v > 0]


def _oggi_agg():
    """il giorno di oggi: si leggono solo le righe arrivate dopo l'ultima volta (il file cresce e basta)."""
    g = date.today().isoformat()
    p = os.path.join(filtro.REGISTRO, "%s_ALL.log" % g)
    m = _mappa()
    with _l:
        if _oggi["giorno"] != g or _oggi["percorso"] != p or _oggi["agg"] is None or (_oggi["mappa"] or {}).get("firma") != m["firma"]:
            # giorno nuovo, oppure dispositivi cambiati (uno nuovo, un indirizzo in più): si rilegge da capo con la mappa giusta
            _oggi.update(giorno=g, percorso=p, pos=0, agg=_vuoto(), mappa=m)
        try:
            dim = os.path.getsize(p)
        except OSError:
            return _oggi["agg"]
        if dim < _oggi["pos"]:   # file ricominciato: si rilegge da capo
            _oggi.update(pos=0, agg=_vuoto(), mappa=m)
        if dim > _oggi["pos"]:
            with open(p, "rb") as f:
                f.seek(_oggi["pos"])
                pezzo = f.read(dim - _oggi["pos"])
            fine = pezzo.rfind(b"\n")
            if fine >= 0:   # solo righe intere: l'ultima a metà si legge la prossima volta
                for riga in pezzo[:fine + 1].decode("utf-8", "replace").split("\n"):
                    _riga(_oggi["agg"], riga, _oggi["mappa"])
                _oggi["pos"] += fine + 1
        return _oggi["agg"]


def _giorni_finiti(giorni):
    """{giorno: aggregato json} per i giorni finiti richiesti; quelli nuovi si leggono una volta e si salvano."""
    try:
        cache = json.load(open(CACHE_GIORNI, encoding="utf-8"))
        if not isinstance(cache, dict):
            cache = {}
    except (OSError, ValueError):
        cache = {}
    cambiata, mappa, out = False, None, {}
    for g in giorni:
        if g in cache:
            out[g] = cache[g]
            continue
        p = os.path.join(filtro.REGISTRO, "%s_ALL.log" % g)
        if not os.path.exists(p):
            continue
        mappa = mappa or _mappa()
        try:
            out[g] = cache[g] = _a_json(_leggi_giorno(p, mappa))
            cambiata = True
        except OSError:
            continue
    if cambiata:
        for k in sorted(cache)[:-31]:
            cache.pop(k, None)
        try:
            with open(CACHE_GIORNI + ".tmp", "w", encoding="utf-8") as h:
                json.dump(cache, h)
            os.replace(CACHE_GIORNI + ".tmp", CACHE_GIORNI)
        except OSError:
            pass
    return out


# ───────────── categorie dei domini bloccati (in sottofondo) ─────────────
_cat = {"impronta": None, "d": {}, "coda": set(), "lavora": False, "caricata": False}


def _impronta():
    ff = _collegati["fonti"]() or []
    h = hashlib.sha1()
    for f in ff:
        h.update(("%s|%s|%s|%s|%s\n" % (f.get("url"), f.get("aggiornata"), f.get("domini"), livelli.gruppo_fonte(f),
                                         f.get("attiva", True))).encode())
    for n in ("blocca.txt",):
        try:
            h.update(str(os.path.getmtime(os.path.join(filtro.LISTE, n))).encode())
        except OSError:
            pass
    return h.hexdigest()[:16]


def _carica_cat():
    if _cat["caricata"]:
        return
    _cat["caricata"] = True
    try:
        x = json.load(open(CACHE_CATEGORIE, encoding="utf-8"))
        _cat.update(impronta=x.get("impronta"), d=dict(x.get("d") or {}))
    except (OSError, ValueError):
        pass


def _salva_cat():
    try:
        d = dict(list(_cat["d"].items())[-20000:])
        with open(CACHE_CATEGORIE + ".tmp", "w", encoding="utf-8") as h:
            json.dump({"impronta": _cat["impronta"], "d": d}, h)
        os.replace(CACHE_CATEGORIE + ".tmp", CACHE_CATEGORIE)
    except OSError:
        pass


def _suffissi(d):
    p = d.split(".")
    return [".".join(p[i:]) for i in range(len(p) - 1)]


def classifica_ora(domini):
    """classifica SUBITO (legge le liste una alla volta, riga per riga: poca memoria). {dominio: id categoria}."""
    domini = [d for d in dict.fromkeys(domini) if d]
    cand = {}
    for d in domini:
        for s in _suffissi(d):
            cand.setdefault(s, []).append(d)
            cand.setdefault("*." + s, []).append(d)
    trovati = {d: set() for d in domini}
    fissi, regole = _collegati["fissi"]()   # ({dominio: categoria}, {domini delle tue regole})
    app = _collegati["app_domini"]() or set()
    for d in domini:
        ss = set(_suffissi(d))
        if ss & regole:
            trovati[d].add("regole")
        if ss & app:
            trovati[d].add("app")
        if d in fissi:
            trovati[d].add(fissi[d])
    for f in _collegati["fonti"]() or []:
        if not f.get("attiva", True):
            continue
        p = _collegati["fonte_file"](f["url"])
        if not p or not os.path.exists(p):
            continue
        g = livelli.gruppo_fonte(f)
        try:
            with open(p, encoding="utf-8", errors="replace") as h:
                for riga in h:
                    x = cand.get(riga.strip())
                    if x:
                        for d in x:
                            trovati[d].add(g)
        except OSError:
            continue
    return {d: next((c for c in PRIORITA if c in s), "altro") for d, s in trovati.items()}


def _lavoro_cat():
    try:
        while True:
            with _l:
                da = list(_cat["coda"])[:5000]
                if not da:
                    _cat["lavora"] = False
                    return
            esito = classifica_ora(da)
            with _l:
                _cat["d"].update(esito)
                _cat["coda"].difference_update(da)
                _salva_cat()
                _risposte.clear()
    except Exception as e:   # mai un errore verso il pannello: si riprova alla prossima richiesta
        print("Filtreo statistiche: classificazione non riuscita (%s)" % type(e).__name__, flush=True)
        with _l:
            _cat["lavora"] = False


def categorie_note(domini):
    """{dominio: categoria} per quelli già classificati; gli altri vanno in coda (sottofondo). Ritorna (note, mancano)."""
    with _l:
        _carica_cat()
        imp = _impronta()
        if imp != _cat["impronta"]:   # liste cambiate: si riclassifica tutto (in sottofondo)
            _cat.update(impronta=imp, d={})
        note = {d: _cat["d"][d] for d in domini if d in _cat["d"]}
        mancano = [d for d in domini if d not in _cat["d"]]
        if mancano:
            _cat["coda"].update(mancano)
            if not _cat["lavora"]:
                _cat["lavora"] = True
                threading.Thread(target=_lavoro_cat, daemon=True).start()
        return note, len(mancano)


# ───────────── la risposta ─────────────
def _giorni_periodo(periodo, oggi=None):
    oggi = oggi or date.today()
    n = PERIODI[periodo]
    return [(oggi - timedelta(days=i)).isoformat() for i in range(n - 1, -1, -1)]


def _pc(b, r):
    return round(100.0 * b / r, 1) if r else 0.0


def _cf_per_id(giorno_cf, mappa):
    """{id dispositivo | «altri»: [bloccate, richieste]} dei conteggi di Cloudflare di un giorno."""
    dd = _collegati["dispositivi"]() or []
    per_nome = {x.get("nome"): x["id"] for x in dd}
    out = {}
    for k, v in (giorno_cf or {}).items():
        did = k if k in mappa["nomi"] else per_nome.get(_collegati["risolvi_cf"](k, dd, None)) or ALTRI
        x = out.setdefault(did, [0, 0])
        x[0] += int(v[0])
        x[1] += int(v[1])
    return out


def statistiche(periodo="oggi", disp=None):
    """il JSON documentato in testa al file. periodo non valido → «oggi». disp sconosciuto → ValueError."""
    periodo = periodo if periodo in PERIODI else "oggi"
    chiave = (periodo, disp or "")
    with _l:
        x = _risposte.get(chiave)
        if x and time.time() - x[0] < TTL_RISPOSTA:
            return x[1]
    mappa = _mappa()
    if disp and disp not in mappa["nomi"]:
        raise ValueError("dispositivo sconosciuto")
    giorni = _giorni_periodo(periodo)
    oggi = giorni[-1]
    dati = _giorni_finiti([g for g in giorni if g != oggi])
    with _l:
        dati[oggi] = _a_json(_oggi_agg(), tronca=False)
    cf = _collegati["conti_cf"]() or {}

    def scegli(agg):   # tutto o solo il dispositivo chiesto
        if not disp:
            return agg
        return (agg.get("disp") or {}).get(disp) or {"r": 0, "b": 0, "ore_r": [0] * 24, "ore_b": [0] * 24, "dom": {}, "az": {}}

    tot_r = tot_b = cf_r = cf_b = 0
    punti, per_disp, dom, az = [], {}, Counter(), Counter()
    dom_az = {}
    for g in giorni:
        agg = dati.get(g) or {"r": 0, "b": 0, "ore_r": [0] * 24, "ore_b": [0] * 24, "dom": {}, "az": {}, "disp": {}}
        s = scegli(agg)
        cfg = _cf_per_id(cf.get(g, {}), mappa)
        if disp:
            cfg = {disp: cfg.get(disp, [0, 0])}
        cb, cr = sum(v[0] for v in cfg.values()), sum(v[1] for v in cfg.values())
        tot_r += s["r"] + cr
        tot_b += s["b"] + cb
        cf_r += cr
        cf_b += cb
        if periodo != "oggi":
            pt = {"etichetta": g[8:10] + "/" + g[5:7], "inizio": g + "T00:00", "richieste": s["r"] + cr, "bloccate": s["b"] + cb}
            pa = _prime_aziende(s.get("az"))
            if pa:
                pt["aziende"] = pa
            punti.append(pt)
        else:
            ore_cf = _collegati["ore_cf"](g) if not disp else [0] * 24   # le ore di Cloudflare non sono per dispositivo
            az_ore = s.get("az_ore") or []
            for h in range(24):
                pt = {"etichetta": "%02d" % h, "inizio": "%sT%02d:00" % (g, h),
                      "richieste": s["ore_r"][h] + ore_cf[h], "bloccate": s["ore_b"][h] + ore_cf[h]}
                pa = _prime_aziende(az_ore[h] if h < len(az_ore) else None)
                if pa:
                    pt["aziende"] = pa
                punti.append(pt)
        dom.update(s.get("dom") or {})
        az.update(s.get("az") or {})
        righe = (agg.get("disp") or {}) if not disp else {disp: s}
        for k, v in righe.items():
            x = per_disp.setdefault(k, {"r": 0, "b": 0, "cf_b": 0, "cf_r": 0})
            x["r"] += v["r"]
            x["b"] += v["b"]
        for k, v in cfg.items():
            x = per_disp.setdefault(k, {"r": 0, "b": 0, "cf_b": 0, "cf_r": 0})
            x["cf_b"] += v[0]
            x["cf_r"] += v[1]
    # categorie: dai domini bloccati (quelli tenuti); il resto (giorni passati, domini oltre i primi 500) è «Altro»
    note, mancano = categorie_note(list(dom))
    cat = Counter()
    for d, n in dom.items():
        cat[note.get(d, "altro")] += n
    resto = (tot_b - cf_b) - sum(dom.values())
    if resto > 0:
        cat["altro"] += resto
    if cf_b:
        cat["cloudflare"] += cf_b
    for d, n in dom.most_common(2000):
        a = azienda(d)["nome"]
        dom_az.setdefault(a, [])
        if len(dom_az[a]) < 3:
            dom_az[a].append(d)
    righe_az = []
    for nome, n in az.most_common(10):
        esempio = (dom_az.get(nome) or [""])[0]
        info = azienda(esempio) if esempio else {"nome": nome, "gruppo": nome, "conosciuta": False}
        righe_az.append({"nome": nome, "gruppo": info["gruppo"] if info["nome"] == nome else nome, "bloccate": n,
                         "percentuale": _pc(n, tot_b - cf_b), "conosciuta": bool(azienda_nota(esempio)) if esempio else False,
                         "domini": dom_az.get(nome, [])})
    righe_d = []
    for k, v in per_disp.items():
        r, b = v["r"] + v["cf_r"], v["b"] + v["cf_b"]
        if not r and not b:
            continue
        righe_d.append({"id": k if k != ALTRI else None, "nome": mappa["nomi"].get(k, "Altri dispositivi"), "richieste": r,
                        "bloccate": b, "percentuale": _pc(b, r), "casa": v["b"], "cloudflare": v["cf_b"]})
    righe_d.sort(key=lambda x: (x["id"] is None, -x["bloccate"], x["nome"]))
    out = {
        "versione": 1, "periodo": periodo, "da": giorni[0], "a": oggi,
        "dispositivo": {"id": disp, "nome": mappa["nomi"][disp]} if disp else None,
        "aggiornato": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "totale": {"richieste": tot_r, "bloccate": tot_b, "percentuale": _pc(tot_b, tot_r), "casa": tot_b - cf_b, "cloudflare": cf_b},
        "serie": {"passo": "ora" if periodo == "oggi" else "giorno", "punti": punti},
        "categorie": [{"id": c, "nome": NOMI_CATEGORIE.get(c, c), "bloccate": n, "percentuale": _pc(n, tot_b)}
                      for c, n in cat.most_common() if n > 0],
        "dispositivi": righe_d,
        "aziende": righe_az,
        "completo": {"categorie": mancano == 0},
    }
    if periodo == "oggi":
        out["ieri"] = _ieri(oggi, mappa, cf, scegli, disp)
    with _l:
        _risposte[chiave] = (time.time(), out)
    return out


def _ieri(oggi, mappa, cf, scegli, disp, adesso=None):
    """0.9.1 — ieri per il confronto con oggi: totale, fino a quest'ora (l'ora in corso in proporzione ai minuti) e 24 ore."""
    adesso = adesso or datetime.now()
    g = (date.fromisoformat(oggi) - timedelta(days=1)).isoformat()
    agg = _giorni_finiti([g]).get(g) or {"r": 0, "b": 0, "ore_r": [0] * 24, "ore_b": [0] * 24, "disp": {}}
    s = scegli(agg)
    cfg = _cf_per_id(cf.get(g, {}), mappa)
    if disp:
        cfg = {disp: cfg.get(disp, [0, 0])}
    cb, cr = sum(v[0] for v in cfg.values()), sum(v[1] for v in cfg.values())
    ore_cf = _collegati["ore_cf"](g) if not disp else [0] * 24
    ore = [{"richieste": int(s["ore_r"][h]) + int(ore_cf[h]), "bloccate": int(s["ore_b"][h]) + int(ore_cf[h])} for h in range(24)]
    h, f = adesso.hour, adesso.minute / 60.0
    sr = sum(o["richieste"] for o in ore[:h]) + ore[h]["richieste"] * f
    sb = sum(o["bloccate"] for o in ore[:h]) + ore[h]["bloccate"] * f
    # le richieste di Cloudflare non hanno le ore: per «fino a quest'ora» si contano in proporzione alle bloccate
    tb = sum(o["bloccate"] for o in ore)
    extra_r = (cr - sum(ore_cf)) if cr > sum(ore_cf) else 0
    if extra_r and tb:
        sr += extra_r * (sb / tb)
    return {"giorno": g, "richieste": int(s["r"]) + cr, "bloccate": int(s["b"]) + cb,
            "stessa_ora": {"richieste": int(round(sr)), "bloccate": int(round(sb))}, "ore": ore}


def avvia(ogni=30):
    """in sottofondo: legge le righe nuove di oggi ogni «ogni» secondi e i giorni finiti una volta, così la prima richiesta
    (app, widget) non aspetta la lettura di un registro da centinaia di migliaia di righe."""
    def giro():
        time.sleep(5)
        while True:
            try:
                _oggi_agg()
                _giorni_finiti([g for g in _giorni_periodo("30g")[:-1]])
            except Exception as e:   # mai fermarsi: alla prossima richiesta si riprova
                print("Filtreo statistiche: lettura in sottofondo non riuscita (%s)" % type(e).__name__, flush=True)
            time.sleep(ogni)
    threading.Thread(target=giro, daemon=True).start()
