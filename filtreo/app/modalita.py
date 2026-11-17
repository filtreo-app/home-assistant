#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""modalita.py — le MODALITÀ di Filtreo (Lavoro, Standard, … e «Senza filtro»).

Una modalità è un insieme di regole con un nome scelto dall'utente:
  {id, nome, colore, fonti: [url delle liste accese], lavoro: [servizi che passano sempre],
   auto: {giorni: [0..6], da: "09:00", a: "18:00", poi: <id>, dispositivi: [<id disp>]}}
«Senza filtro» (SPENTO) è fissa: non blocca niente e si riaccende da sola dopo TORNA_DOPO minuti.

Ogni dispositivo con regole sue ha un campo «modo». Cambiare modalità riscrive solo le liste
di quel dispositivo e le ricarica: niente riavvio del filtro, vale a casa e fuori casa.
Il nome della modalità è solo un'etichetta: rinominarla non cambia le regole.
"""
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime

import filtro

FILE = os.path.join(filtro.DATA, "modalita.json")
STATO_AUTO = os.path.join(filtro.DATA, "modalita-auto.json")
SERVIZI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "servizi-lavoro.json")
SERVIZI_CASA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "servizi-casa.json")
PREDEFINITE_FILE = os.path.join(filtro.DATA, "modalita-predefinite.json")   # quali profili pronti sono già stati creati (una volta sola)
SPENTO = "spento"
NOME_SPENTO = "Senza filtro"
PAUSA = "pausa"
NOME_PAUSA = "Blocco connessione"
FAMIGLIA = os.path.join(filtro.DATA, "famiglia.json")
STATO_NANNA = os.path.join(filtro.DATA, "famiglia-orari.json")
APP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app-bloccabili.json")
TORNA_DOPO = int(os.environ.get("FILTREO_SPENTO_MINUTI", "60") or 60)
COLORI = ("#2563EB", "#12924A", "#D97706", "#9333EA", "#DB2777", "#0891B2", "#65A30D")
_blocco = threading.RLock()

# categorie delle liste: il nome che vede l'utente e come riconoscerle dal nome/link
CATEGORIE = [
    ("pubblicita", "Pubblicità", ""),
    ("telemetria", "Telemetria di TV e dispositivi", r"native"),
    ("tracciatori", "Tracciamento", r"track|privacy|spy|telemetr|analytic|easyprivacy"),
    ("truffe", "Siti pericolosi", r"malware|phish|scam|fraud|threat|tif|badware|virus|urlhaus|crypto"),
    ("social", "Social network", r"social|facebook|tiktok|instagram"),
    ("adulti", "Contenuti per adulti", r"porn|adult|nsfw|xxx"),
    ("scommesse", "Scommesse", r"gambl|betting|casino|scommess"),
]
# liste consigliate quando una categoria non ne ha ancora (si scaricano al primo uso)
CONSIGLIATE = {
    "truffe": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini.txt",
    "social": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
    "adulti": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    "scommesse": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.mini.txt",
}

# «Protezione famiglia» (interruttore separato, vale con qualsiasi livello): blocca le liste delle categorie qui sotto.
# Le liste sono le stesse «consigliate» di adulti e scommesse (nessun URL nuovo). Se non ci sono già fra i filtri, si seminano
# DORMIENTI (come le liste per marca): si scaricano solo quando una modalità con la protezione accesa è in uso.
CAT_PROTEZIONE = ("adulti", "scommesse")
FONTI_PROTEZIONE = [
    ("Protezione famiglia · Contenuti per adulti", CONSIGLIATE["adulti"], "adulti"),
    ("Protezione famiglia · Scommesse", CONSIGLIATE["scommesse"], "scommesse"),
]
# strumenti di lavoro sempre consentiti nel livello «Personale» (id di servizi-lavoro.json): Meta, Google Ads, Analytics, Tag Manager, LinkedIn, Hotjar
STRUMENTI_PERSONALE = ["meta", "google-ads", "ga4", "gtm", "linkedin", "hotjar"]


# ───────── profili pronti per casa intelligente, IoT, server e IA locale ─────────
# liste HaGeZi «Native Tracker» (una per marca), verificate dal vivo il 13/11/2026: ognuna risponde 200 ed è in formato «*.sito»
_HZ = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.%s.txt"
FONTI_CASA = [
    ("Telemetria · Samsung", _HZ % "samsung"), ("Telemetria · LG webOS", _HZ % "lgwebos"), ("Telemetria · Amazon", _HZ % "amazon"),
    ("Telemetria · Roku", _HZ % "roku"), ("Telemetria · Xiaomi", _HZ % "xiaomi"), ("Telemetria · Apple", _HZ % "apple"),
    ("Telemetria · Huawei", _HZ % "huawei"), ("Telemetria · Oppo e Realme", _HZ % "oppo-realme"), ("Telemetria · Vivo", _HZ % "vivo"),
    ("Telemetria · TikTok", _HZ % "tiktok"), ("Telemetria · Windows e Office", _HZ % "winoffice"),
]
URL_PRO = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt"
_URL = {n.split(" · ")[1]: u for n, u in FONTI_CASA}
# telemetria nota di editor, sistemi e NVIDIA che non sta in una lista pubblica affidabile: scritta a mano
TELEMETRIA_SERVER = ["vortex.data.microsoft.com", "mobile.events.data.microsoft.com", "dc.services.visualstudio.com",
                     "telemetry.gfe.nvidia.com", "events.gfe.nvidia.com", "popcon.ubuntu.com", "daisy.ubuntu.com",
                     "metrics.ubuntu.com", "telemetry.nextjs.org"]
PREDEFINITE = [
    {"id": "m-tv", "pre": "tv", "nome": "TV e casse", "colore": "#9333EA", "genere": "tv",
     "descr": "Blocca pubblicità e telemetria di TV e assistenti vocali. Film, musica e aggiornamenti restano consentiti.",
     "fonti": [URL_PRO] + [_URL[k] for k in ("Samsung", "LG webOS", "Amazon", "Roku", "Xiaomi", "Apple", "Huawei", "Oppo e Realme", "Vivo", "TikTok", "Windows e Office")],
     "passa": ["netflix", "youtube", "prime", "disney", "raiplay", "mediaset", "spotify", "alexa", "google-casa", "agg-samsung", "agg-lg",
               "agg-apple", "agg-roku", "agg-xiaomi", "agg-huawei"], "fuori": "pulito"},
    {"id": "m-iot", "pre": "iot", "nome": "Telecamere e sensori", "colore": "#0891B2", "genere": "iot",
     "descr": "Blocca la telemetria dei produttori. Con «Solo indirizzi consentiti» comunicano solo con le eccezioni.",
     "fonti": [_URL[k] for k in ("Samsung", "Amazon", "Xiaomi", "Apple", "Huawei", "Oppo e Realme", "Vivo")],
     "passa": [], "fuori": "pulito"},
    {"id": "m-isolato", "pre": "isolato", "nome": "Isolato", "colore": "#DB2777", "genere": "",
     "descr": "Raggiunge solo Casa, Home Assistant, l'ora di rete e i siti nelle eccezioni. Tutto il resto è bloccato.",
     "fonti": [], "passa": [], "solo_permessi": True, "fuori": "pulito"},
    {"id": "m-server", "pre": "server", "nome": "Server e IA locale", "colore": "#12924A", "genere": "server",
     "descr": "Blocca solo la telemetria nota. Hugging Face, Ollama, GitHub, Docker, pacchetti e aggiornamenti sempre consentiti.",
     "fonti": [_URL["Windows e Office"]], "blocca": TELEMETRIA_SERVER,
     "passa": ["huggingface", "ollama", "github", "docker", "pypi", "npm", "apt", "homebrew", "tailscale", "cloudflare", "nvidia"], "fuori": "spento"},
]
GENERE_PRE = {p["genere"]: p["id"] for p in PREDEFINITE if p["genere"]}


def profilo_fuori(m):
    """che profilo usa il paracadute di Cloudflare (fuori casa, senza Tailscale) per questa modalità: il più vicino fra
    «lavoro», «pulito», «spento» (il worker non sa fare «solo indirizzi permessi», né liste per marca)."""
    if m.get("id") == SPENTO:
        return "spento"
    if m.get("id") == PAUSA:
        return "pausa"
    if m.get("fuori") in ("pulito", "lavoro", "spento"):
        return m["fuori"]
    return "lavoro" if m.get("lavoro") else "pulito"


def semina(fonti_urls):
    """crea i profili pronti che mancano (una volta sola per profilo: se poi li elimini non tornano).
    fonti_urls = i link delle liste già nel pannello. Ritorna True se ha scritto."""
    with _blocco:
        try:
            fatti = json.load(open(PREDEFINITE_FILE, encoding="utf-8"))
        except (OSError, ValueError):
            fatti = []
        mm = _leggi()
        if not os.path.exists(FILE):
            return False   # prima parte la migrazione
        nuovi = False
        for p in PREDEFINITE:
            if p["id"] in fatti:
                continue
            fatti.append(p["id"])
            nuovi = True
            if any(x["id"] == p["id"] or x["nome"].lower() == p["nome"].lower() for x in mm):
                continue
            m = {k: (list(v) if isinstance(v, list) else v) for k, v in p.items() if k not in ("genere",)}
            m["fonti"] = [u for u in p["fonti"] if u in fonti_urls]
            m.setdefault("blocca", [])
            m.setdefault("bianca", [])
            m.setdefault("famiglia", False)
            m["app"], m["lavoro"], m["auto"] = [], [], None
            mm.append(m)
        if nuovi:
            _salva(mm)
            tmp = PREDEFINITE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as h:
                json.dump(fatti, h)
            os.replace(tmp, PREDEFINITE_FILE)
        return nuovi


def categoria(fonte):
    """la categoria di una lista: quella scelta, altrimenti indovinata dal nome e dal link."""
    if fonte.get("categoria") in {c[0] for c in CATEGORIE}:
        return fonte["categoria"]
    testo = ("%s %s" % (fonte.get("nome", ""), fonte.get("url", ""))).lower()
    for cid, _n, rx in CATEGORIE[1:]:
        if re.search(rx, testo):
            return cid
    return "pubblicita"


def servizi():
    try:
        return json.load(open(SERVIZI_FILE, encoding="utf-8"))
    except (OSError, ValueError):
        return {"servizi": [], "modelli": []}


def servizi_casa():
    """servizi di casa intelligente e server che possono restare sempre aperti (servizi-casa.json)."""
    try:
        return json.load(open(SERVIZI_CASA_FILE, encoding="utf-8"))
    except (OSError, ValueError):
        return {"servizi": [], "modelli": []}


def domini_casa(ids):
    out = set()
    for s in servizi_casa()["servizi"]:
        if s["id"] in ids:
            out |= {d.lower() for d in s["domini"]}
    return out


def domini_utente(lista):
    """domini scritti dall'utente (lista bianca / lista nera di un profilo): solo nomi veri, minuscoli, senza doppioni."""
    out = []
    for r in lista or []:
        d = filtro._dominio(str(r))
        if d and d not in out:
            out.append(d)
    return out[:500]


def app_bloccabili():
    try:
        return json.load(open(APP_FILE, encoding="utf-8"))["app"]
    except (OSError, ValueError, KeyError):
        return []


def domini_app(ids):
    out = set()
    for a in app_bloccabili():
        if a["id"] in ids:
            out |= {d.lower() for d in a["domini"]}
    return out


def domini_lavoro(ids):
    out = set()
    for s in servizi()["servizi"]:
        if s["id"] in ids:
            out |= {d.lower() for d in s["domini"]}
    return out


def _leggi():
    try:
        d = json.load(open(FILE, encoding="utf-8"))
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _salva(mm):
    tmp = FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        json.dump(mm, h, ensure_ascii=False, indent=1)
    os.replace(tmp, FILE)


NOMI_VECCHI = {"Pulito": "Standard"}   # nomi di serie di prima → nomi di serie di adesso (solo il nome: gli id non cambiano)
NOMI_MIGRATI = os.path.join(filtro.DATA, "modalita-nomi-migrati.json")


def migra_nomi():
    """una tantum all'avvio: le modalità col nome ESATTAMENTE uguale a un vecchio nome di serie prendono il nuovo;
    i nomi scelti dall'utente restano. Id e valori interni non cambiano. Ritorna quante ne ha rinominate."""
    with _blocco:
        if os.path.exists(NOMI_MIGRATI):
            return 0
        mm = _leggi()
        n = 0
        for m in mm:
            nuovo = NOMI_VECCHI.get(m.get("nome"))
            if nuovo:
                m["nome"] = nuovo
                n += 1
        try:
            if n:
                _salva(mm)
            with open(NOMI_MIGRATI, "w", encoding="utf-8") as h:
                json.dump({"rinominate": n, "quando": time.time()}, h)
        except OSError:
            return 0
        return n


NOMI_LIVELLI = {"Massimo": ("Rigoroso", True), "Lavoro": ("Personale", False)}   # nome di serie di prima → (nome nuovo, accendi «Protezione famiglia»)
LIVELLI_MIGRATI = os.path.join(filtro.DATA, "modalita-livelli-migrati.json")


def migra_livelli():
    """una tantum all'avvio (dopo migra_nomi): nuovo modello dei livelli. Solo i nomi ESATTAMENTE uguali a quelli di serie di prima:
      «Massimo» (= Standard + adulti + scommesse) → «Rigoroso» con Protezione famiglia accesa (stesse liste di prima, protezione uguale o maggiore);
      «Lavoro» → «Personale» (stesse liste e stessi strumenti di lavoro consentiti, niente aggiunto: cosa blocca non cambia;
      i sei strumenti di serie, STRUMENTI_PERSONALE, sono per i «Personale» nuovi).
    Gli id non cambiano (dispositivi, orari e persone continuano a puntare alla stessa modalità). Se il nome nuovo è già preso da un'altra
    modalità resta il nome vecchio (la protezione famiglia si accende comunque). I nomi scelti dall'utente restano. Ritorna quante ne ha toccate."""
    with _blocco:
        if os.path.exists(LIVELLI_MIGRATI) or not os.path.exists(FILE):
            return 0
        mm = _leggi()
        n, dettagli = 0, []
        for m in mm:
            nuovo = NOMI_LIVELLI.get(m.get("nome"))
            if not nuovo:
                continue
            nome, fam = nuovo
            preso = any(x is not m and str(x.get("nome", "")).lower() == nome.lower() for x in mm)
            vecchio = m["nome"]
            if not preso:
                m["nome"] = nome
            if fam:
                m["famiglia"] = True
            n += 1
            dettagli.append({"id": m.get("id"), "da": vecchio, "a": m["nome"], "famiglia": bool(m.get("famiglia"))})
        try:
            if n:
                _salva(mm)
            with open(LIVELLI_MIGRATI, "w", encoding="utf-8") as h:
                json.dump({"toccate": n, "dettagli": dettagli, "quando": time.time()}, h, ensure_ascii=False)
        except OSError:
            return 0
        return n


def imposta_famiglia(mid, attiva):
    """accende o spegne «Protezione famiglia» su una modalità. Ritorna (ok, testo, cambiata)."""
    if mid in (SPENTO, PAUSA):
        return False, "«%s» non ha la protezione famiglia: non filtra niente." % (NOME_SPENTO if mid == SPENTO else NOME_PAUSA), False
    with _blocco:
        mm = _leggi()
        m = next((x for x in mm if x["id"] == mid), None)
        if not m:
            return False, "Profilo non trovato. Ricarica la pagina e riprova.", False
        attiva = bool(attiva)
        if bool(m.get("famiglia")) == attiva:
            return True, "«%s»: protezione famiglia già %s." % (m["nome"], "accesa" if attiva else "spenta"), False
        m["famiglia"] = attiva
        _salva(mm)
        return True, "«%s»: protezione famiglia %s." % (m["nome"], "accesa" if attiva else "spenta"), True


def elenco():
    return _leggi()


def trova(mid):
    if mid == SPENTO:
        return {"id": SPENTO, "nome": NOME_SPENTO, "colore": "#8A919C", "fonti": [], "lavoro": [], "app": [], "fissa": True}
    if mid == PAUSA:
        return {"id": PAUSA, "nome": NOME_PAUSA, "colore": "#475569", "fonti": [], "lavoro": [], "app": [], "fissa": True, "nascosta": True}
    return next((m for m in _leggi() if m["id"] == mid), None)


def migra(dispositivi, fonti, principale):
    """primo avvio della 1.5: una modalità per ogni dispositivo con regole sue, con le liste che aveva.
    Chi aveva gli strumenti di lavoro → «Lavoro», il primo degli altri → «Standard». Ritorna True se ha scritto."""
    with _blocco:
        if os.path.exists(FILE):
            return False
        mm, nomi = [], set()
        tutti_lavoro = [s["id"] for s in servizi()["servizi"] if s["id"] in
                        next((x["servizi"] for x in servizi()["modelli"] if x["id"] == "marketing"), [])]
        for x in dispositivi:
            if not x.get("proprie"):
                continue
            g = x["id"]
            ff = [f["url"] for f in fonti if g in f.get("dispositivi", [principale])]
            if x.get("lavoro") and "Lavoro" not in nomi:
                nome = "Lavoro"
            elif not x.get("lavoro") and "Standard" not in nomi:
                nome = "Standard"
            else:
                nome = "Regole di %s" % x.get("nome", g)
            nomi.add(nome)
            m = {"id": "m-" + secrets.token_hex(3), "nome": nome, "colore": COLORI[len(mm) % len(COLORI)],
                 "fonti": ff, "lavoro": tutti_lavoro if x.get("lavoro") else [], "auto": None}
            # stessa lista di regole di una modalità già creata: la riuso
            gemella = next((y for y in mm if sorted(y["fonti"]) == sorted(ff) and y["lavoro"] == m["lavoro"]), None)
            if gemella:
                x["modo"] = gemella["id"]
                continue
            mm.append(m)
            x["modo"] = m["id"]
        if not mm:
            mm.append({"id": "m-" + secrets.token_hex(3), "nome": "Standard", "colore": COLORI[1],
                       "fonti": [f["url"] for f in fonti], "lavoro": [], "auto": None})
        _salva(mm)
        return True


def _pulisci_auto(a, validi_modi, validi_disp):
    if not isinstance(a, dict) or not a.get("attivo"):
        return None
    giorni = sorted({int(g) for g in a.get("giorni", []) if str(g).isdigit() and 0 <= int(g) <= 6})
    ok_ora = lambda s: bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", s or ""))  # noqa: E731
    if not giorni or not ok_ora(a.get("da")) or not ok_ora(a.get("a")):
        return None
    poi = a.get("poi") if a.get("poi") in validi_modi else None
    return {"attivo": True, "giorni": giorni, "da": a["da"], "a": a["a"], "poi": poi,
            "dispositivi": [d for d in a.get("dispositivi", []) if d in validi_disp]}


def salva_modo(dati, fonti_valide, disp_validi):
    """crea o aggiorna una modalità. dati = {id?, nome, colore, fonti, lavoro, auto}."""
    nome = re.sub(r"\s+", " ", str(dati.get("nome") or "")).strip()[:30]
    if not nome:
        return False, "Inserisci un nome per il profilo.", None
    if nome.lower() in (NOME_SPENTO.lower(), NOME_PAUSA.lower()):
        return False, "«%s» esiste già e non è modificabile." % nome, None
    validi_servizi = {s["id"] for s in servizi()["servizi"]}
    with _blocco:
        mm = _leggi()
        mid = dati.get("id") or ""
        m = next((x for x in mm if x["id"] == mid), None)
        if any(x["nome"].lower() == nome.lower() and x is not m for x in mm):
            return False, "Esiste già un profilo «%s»." % nome, None
        if m is None:
            m = {"id": "m-" + secrets.token_hex(3), "colore": COLORI[len(mm) % len(COLORI)]}
            mm.append(m)
        m["nome"] = nome
        col = str(dati.get("colore") or m.get("colore") or COLORI[0])
        m["colore"] = col if re.fullmatch(r"#[0-9A-Fa-f]{6}", col) else COLORI[0]
        if "fonti" in dati:
            m["fonti"] = [u for u in dati["fonti"] if u in fonti_valide]
        m.setdefault("fonti", list(fonti_valide))
        if "lavoro" in dati:
            m["lavoro"] = [s for s in dati["lavoro"] if s in validi_servizi]
        m.setdefault("lavoro", [])
        if "app" in dati:
            validi_app = {a["id"] for a in app_bloccabili()}
            m["app"] = [a for a in dati["app"] if a in validi_app]
        m.setdefault("app", [])
        if "passa" in dati:
            validi_casa = {s["id"] for s in servizi_casa()["servizi"]}
            m["passa"] = [s for s in dati["passa"] if s in validi_casa]
        if "bianca" in dati:
            m["bianca"] = domini_utente(dati["bianca"])
        if "blocca" in dati:
            m["blocca"] = domini_utente(dati["blocca"])
        if "solo_permessi" in dati:
            m["solo_permessi"] = bool(dati["solo_permessi"])
        if "famiglia" in dati:
            m["famiglia"] = bool(dati["famiglia"])
        m.setdefault("famiglia", False)
        for k in ("passa", "bianca", "blocca"):
            m.setdefault(k, [])
        if "auto" in dati:
            m["auto"] = _pulisci_auto(dati["auto"], {x["id"] for x in mm} | {SPENTO, PAUSA}, disp_validi)
        if m.get("livello") and "fonti" in dati:
            # 3.1: chi scrive le liste per intero (pannello web, app 3.0) → si ricavano le differenze dal livello di partenza
            import livelli
            livelli.ricalcola_diff(m)
        _salva(mm)
        return True, "«%s» salvato." % nome, m["id"]


def togli_modo(mid, in_uso):
    with _blocco:
        mm = _leggi()
        if mid in (SPENTO, PAUSA) or not any(x["id"] == mid for x in mm):
            return False, "Profilo non eliminabile."
        if len(mm) <= 1:
            return False, "È richiesto almeno un profilo."
        if in_uso:
            return False, "In uso da: %s. Assegna prima un altro profilo." % ", ".join(in_uso)
        _salva([x for x in mm if x["id"] != mid])
        return True, "Profilo eliminato."


# ───────── orari automatici ─────────
def _dentro(a, ora):
    if ora.weekday() not in a["giorni"]:
        return False
    hm = ora.strftime("%H:%M")
    return a["da"] <= hm < a["a"] if a["da"] <= a["a"] else (hm >= a["da"] or hm < a["a"])


def decisioni_automatiche(ora=None):
    """cosa cambiare adesso per via degli orari: lista di (id dispositivo, id modalità).
    Scatta solo quando si entra o si esce dalla fascia, così un cambio a mano nel mezzo resta."""
    ora = ora or datetime.now()
    try:
        st = json.load(open(STATO_AUTO, encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    out, nuovo = [], {}
    for m in _leggi():
        a = m.get("auto")
        if not a:
            continue
        den = _dentro(a, ora)
        for d in a.get("dispositivi", []):
            k = "%s|%s" % (m["id"], d)
            nuovo[k] = den
            if k in st and st[k] != den:
                if den:
                    out.append((d, m["id"]))
                elif a.get("poi"):
                    out.append((d, a["poi"]))
    if nuovo != st:
        tmp = STATO_AUTO + ".tmp"
        with open(tmp, "w", encoding="utf-8") as h:
            json.dump(nuovo, h)
        os.replace(tmp, STATO_AUTO)
    return out


def scaduto(x, adesso=None):
    """«Senza filtro» dura TORNA_DOPO minuti: poi torna la modalità di prima."""
    return x.get("modo") == SPENTO and x.get("spento_fino") and (adesso or time.time()) >= x["spento_fino"]


# ───────── famiglia: persone con i loro dispositivi, regole e «a nanna» ─────────
def persone():
    try:
        d = json.load(open(FAMIGLIA, encoding="utf-8"))
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _salva_persone(pp):
    tmp = FAMIGLIA + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        json.dump(pp, h, ensure_ascii=False, indent=1)
    os.replace(tmp, FAMIGLIA)


def salva_persona(dati, disp_validi):
    """{id?, nome, colore, dispositivi, modo, nanna: {attivo, da, a, giorni}}"""
    nome = re.sub(r"\s+", " ", str(dati.get("nome") or "")).strip()[:30]
    if not nome:
        return False, "Inserisci il nome.", None
    ok_ora = lambda x: bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", x or ""))  # noqa: E731
    with _blocco:
        pp = persone()
        p = next((x for x in pp if x["id"] == dati.get("id")), None)
        if p is None:
            p = {"id": "p-" + secrets.token_hex(3), "colore": COLORI[(len(pp) + 3) % len(COLORI)]}
            pp.append(p)
        p["nome"] = nome
        col = str(dati.get("colore") or p.get("colore"))
        p["colore"] = col if re.fullmatch(r"#[0-9A-Fa-f]{6}", col) else COLORI[3]
        if "dispositivi" in dati:
            altri = {d for x in pp if x is not p for d in x.get("dispositivi", [])}
            p["dispositivi"] = [d for d in dati["dispositivi"] if d in disp_validi and d not in altri]
        p.setdefault("dispositivi", [])
        if "modo" in dati:
            p["modo"] = dati["modo"] if trova(dati["modo"] or "") else ""
        n = dati.get("nanna") if "nanna" in dati else p.get("nanna")
        if isinstance(n, dict) and n.get("attivo") and ok_ora(n.get("da")) and ok_ora(n.get("a")):
            giorni = sorted({int(g) for g in n.get("giorni", list(range(7))) if str(g).isdigit() and 0 <= int(g) <= 6}) or list(range(7))
            p["nanna"] = {"attivo": True, "da": n["da"], "a": n["a"], "giorni": giorni}
        else:
            p["nanna"] = None
        _salva_persone(pp)
        return True, "«%s» salvato." % nome, p["id"]


def togli_persona(pid):
    with _blocco:
        pp = persone()
        if not any(x["id"] == pid for x in pp):
            return False, "Persona non trovata."
        _salva_persone([x for x in pp if x["id"] != pid])
        return True, "Persona rimossa. I dispositivi mantengono il profilo."


def decisioni_nanna(ora=None):
    """[(id dispositivo, id modalità)] da cambiare per «a nanna»: entra → Blocco connessione, esce → la sua modalità."""
    ora = ora or datetime.now()
    try:
        st = json.load(open(STATO_NANNA, encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    out, nuovo = [], {}
    for p in persone():
        n = p.get("nanna")
        if not n:
            continue
        den = _dentro(n, ora)
        nuovo[p["id"]] = den
        if p["id"] in st and st[p["id"]] != den:
            for d in p.get("dispositivi", []):
                out.append((d, PAUSA if den else (p.get("modo") or "")))
    if nuovo != st:
        tmp = STATO_NANNA + ".tmp"
        with open(tmp, "w", encoding="utf-8") as h:
            json.dump(nuovo, h)
        os.replace(tmp, STATO_NANNA)
    return out
