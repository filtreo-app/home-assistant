#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtreo_liste.py — liste di blocco e dispositivi di Filtreo (versione Giò, add-on Home Assistant).

Idea:
- ogni lista (anche Hagezi e OISD) è una «fonte» scaricata dal pannello e tenuta in /data/fonti/;
- ogni GRUPPO ha un suo file /data/liste/dev-<gruppo>.txt = unione delle fonti accese per quel gruppo;
- il gruppo «casa» è quello del dispositivo principale (il Mac) e di tutti i dispositivi che lo seguono;
- un dispositivo con «liste sue» ha un gruppo tutto suo.
Cambiare quali liste valgono dove = riscrivere i file dev-*.txt e ricaricare al volo (nessun riavvio).
Dare le liste sue a un dispositivo nuovo = cambiare la config del motore = riavvio di Blocky (pochi secondi).
"""
import glob
import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import date, datetime, timedelta

import applicazione as appl
import filtro
import livelli
import modalita

DATA = filtro.DATA
LISTE = filtro.LISTE
FONTI_DIR = os.path.join(DATA, "fonti")
FONTI_JSON = os.path.join(DATA, "fonti.json")
DISP_JSON = os.path.join(DATA, "dispositivi.json")
CONFIG = os.path.join(DATA, "blocky.yml")
MODELLO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocky.template.yml")
PID_BLOCKY = "/tmp/blocky.pid"
PRINCIPALE = "casa"
OGNI_ORE = 12
MAX_BYTE = 40 * 1024 * 1024
ECCEZIONI_FILE = ("bianca.txt", "sblocca.txt", "anti-rilevamento.txt")
ANTI = "anti-rilevamento.txt"
# file «esca» che i rilevatori di adblock provano a caricare: se rispondono, il sito non si accorge del filtro
ANTI_BASE = [  # solo i file che CONTROLLANO, non quelli che mostrano annunci (quelli restano bloccati)
    "pagead2.googlesyndication.com", "static.doubleclick.net", "adservice.google.com",
    "www.googletagservices.com", "imasdk.googleapis.com", "c.amazon-adsystem.com",
    "cdn.carbonads.com", "static.criteo.net",
]
ANTI_VECCHIE = {"tpc.googlesyndication.com", "googleads.g.doubleclick.net", "securepubads.g.doubleclick.net",
                "partner.googleadservices.com", "fundingchoicesmessages.google.com", "srv.carbonads.net",
                "acceptable.a-ads.com", "ad.a-ads.com", "cdn.adsafeprotected.com"}
NOMI_JSON = "/share/filtreo/nomi.json"   # nomi dei dispositivi presi da Tailscale (li scrive l'installatore dal Mac)
IGNORA_IP = re.compile(r"^(127\.|172\.30\.|::1$|0\.0\.0\.0$)")

PRESET = [
    ("Hagezi Pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt"),
    ("OISD Big", "https://big.oisd.nl/"),
    ("AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
    ("AdGuard Tracciamento", "https://filters.adtidy.org/extension/ublock/filters/3.txt"),
    ("EasyList", "https://easylist.to/easylist/easylist.txt"),
    ("EasyPrivacy", "https://easylist.to/easylist/easyprivacy.txt"),
    ("EasyList Italia", "https://easylist-downloads.adblockplus.org/easylistitaly.txt"),
    ("uBlock – Privacy", "https://ublockorigin.github.io/uAssets/filters/privacy.txt"),
    ("Peter Lowe", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
    ("Hagezi Pop-up Ads", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads.txt"),
    ("Elementi di disturbo · AdGuard Cookie", "https://filters.adtidy.org/extension/ublock/filters/18.txt"),
    ("Elementi di disturbo · AdGuard Popup", "https://filters.adtidy.org/extension/ublock/filters/19.txt"),
    ("Elementi di disturbo · AdGuard Banner app", "https://filters.adtidy.org/extension/ublock/filters/20.txt"),
    ("Elementi di disturbo · AdGuard Altri", "https://filters.adtidy.org/extension/ublock/filters/21.txt"),
    ("Elementi di disturbo · Fanboy Annoyances", "https://secure.fanboy.co.nz/fanboy-annoyance.txt"),
    ("Elementi di disturbo · EasyList Cookie", "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt"),
    ("Siti pericolosi · Hagezi TIF medio", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium.txt"),
    ("Siti pericolosi · URLhaus malware", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt"),
    ("Siti pericolosi · Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt"),
    ("Siti pericolosi · uBlock Badware", "https://ublockorigin.github.io/uAssets/filters/badware.txt"),
    ("Siti pericolosi · Truffe", "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt"),
]

# liste tolte dalle pronte perché non contengono nulla di utile per il DNS (comparivano col triangolo ⚠)
RITIRATE = {"https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt"}

_blocco = threading.Lock()      # chi tocca fonti.json / dispositivi.json (operazioni brevi: niente download qui dentro)
_scrittura = threading.Lock()   # chi riscrive i file dev-*.txt per il motore
_da_applicare = threading.Event()
_lavoratore = {"attivo": False}
_tentativi = {"n": 0}
protetto = lambda d: False  # noqa: E731  (lo imposta il pannello)
giri_extra = []   # funzioni chiamate dal giro di ogni minuto (avvisi su Telegram): niente cron nuovi

_ABP = re.compile(r"^\|\|([a-z0-9*._-]+)\^(?:\$(.*))?$")
_DOM = re.compile(r"^(?:\*\.)?([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)\.?$")
_OPZ_OK = {"", "third-party", "3p", "all", "important", "document", "doc", "popup", "first-party", "1p"}
_NOME_OK = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+[a-z][a-z0-9-]*[a-z0-9]$")  # nomi veri: niente «-728.90»
_IP_HOSTS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255"}
_NO = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"}


# ───────────── file di stato ─────────────
def _leggi(p, vuoto):
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return vuoto


def _salva(p, obj):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        json.dump(obj, h, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


def fonti():
    return _leggi(FONTI_JSON, [])


def dispositivi():
    d = _leggi(DISP_JSON, None)
    if not d:
        d = [{"id": PRINCIPALE, "nome": "Mac", "ip": "", "proprie": True, "principale": True}]
    return d


RE_NODO = re.compile(r"jetson|raspberry|\bpi\b|-pi\b|home ?assistant|\bhass\b|\bnodo\b", re.I)   # «server» e «nas» sono un genere a parte (vedi genere)
_RE_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]{3,45}$")


def e_nodo(x):
    """il dispositivo è il nodo stesso (Casa)? Vale il campo «tipo» se c'è, altrimenti il nome."""
    t = (x.get("tipo") or "").lower()
    return t == "nodo" if t in ("nodo", "android", "altro", "tv", "iot", "server") else bool(RE_NODO.search(x.get("nome") or ""))


def nodo_ips():
    """tutti gli indirizzi del nodo stesso: interfacce locali (anche 100.x di Tailscale), 127.0.0.1, l'indirizzo del contenitore,
    quelli su cui ascolta il DNS (FILTREO_DNS), FILTREO_NODO_IPS, il nome del nodo nell'elenco di Tailscale, gli indirizzi
    scritti sul dispositivo di genere «nodo». Mai un'eccezione: se una fonte manca, si usano le altre."""
    out = set()
    try:   # interfacce locali (con la rete del contenitore «host» ci sono anche quelle del Jetson)
        blocco, ultimo = open("/proc/net/fib_trie", encoding="utf-8").read().split("\n"), None
        for i, r in enumerate(blocco):
            m = re.search(r"\|-- (\d+\.\d+\.\d+\.\d+)\s*$", r)
            if m:
                ultimo = m.group(1)
            elif "/32 host LOCAL" in r and ultimo:
                out.add(ultimo)
    except OSError:
        pass
    try:
        out.update(i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None))
    except OSError:
        pass
    for v in re.split(r"[ ,]+", os.environ.get("FILTREO_DNS", "") + "," + os.environ.get("FILTREO_NODO_IPS", "")):
        v = v.strip()
        v = re.sub(r"^\[(.*)\](?::\d+)?$", r"\1", v) if v.startswith("[") else (v.rsplit(":", 1)[0] if v.count(":") == 1 else v)
        if v:
            out.add(v)
    try:
        nomi = {socket.gethostname().split(".")[0].lower()}
    except OSError:
        nomi = set()
    try:
        dd = dispositivi()
    except Exception:
        dd = []
    for x in dd:
        if e_nodo(x):
            nomi.add((x.get("nome") or "").strip().lower())
            out.update(i for i in [x.get("ip")] + list(x.get("ips") or []) if i)
    nomi.discard("")
    try:
        out.update(ip for ip, n in nomi_tailscale().items() if n.strip().lower().split(".")[0] in nomi)
    except Exception:
        pass
    out.update(("127.0.0.1", "::1"))
    return {i for i in out if i and _RE_IP.match(i) and i not in ("0.0.0.0", "::")}


def ip_noti(dd=None):
    """indirizzi che hanno già un posto: quelli dei dispositivi registrati (ip e ips) e quelli del nodo stesso."""
    out = set(nodo_ips())
    for x in (dispositivi() if dd is None else dd):
        out.update(i for i in [x.get("ip")] + list(x.get("ips") or []) if i)
    return out


def gruppi():
    """gruppi che hanno liste proprie: il principale + i dispositivi con «liste sue»."""
    return [x["id"] for x in dispositivi() if x.get("proprie")]


# ───────────── lettura delle liste ─────────────
def estrai_domini(testo):
    out = set()
    for r in testo.splitlines():
        r = r.strip().lower()
        if not r or r[0] in "!#[" or r.startswith("@@") or "##" in r or "#@#" in r or "#?#" in r or "#$#" in r:
            continue
        r = r.split(" #")[0].strip()
        m = _ABP.match(r)
        jolly = False   # «||sito^» e «*.sito» vogliono dire «il sito e tutti i suoi sotto-indirizzi»
        if m:
            if not set((m.group(2) or "").split(",")) <= _OPZ_OK:
                continue
            d = m.group(1)
            jolly = True
        else:
            p = r.split()
            if len(p) >= 2 and p[0] in _IP_HOSTS:
                d = p[1]
            elif len(p) == 1:
                d = p[0]
            else:
                continue
        if "*" in d.lstrip("*."):
            continue
        jolly = jolly or d.startswith("*.")
        m2 = _DOM.match(d)
        if not m2:
            continue
        d = m2.group(1)
        if d in _NO or re.fullmatch(r"[0-9.]+", d) or protetto(d) or not _NOME_OK.match(d):
            continue
        out.add("*." + d if jolly else d)
    # il motore blocca un nome scritto semplice SOLO uguale: «*.sito» copre anche www.sito, region1.sito…
    return {d for d in out if d.startswith("*.") or "*." + d not in out}


_ECC = re.compile(r"^@@\|\|([a-z0-9*._-]+)\^\|?(?:\$(.*))?$")


MAI_ECCEZIONE = (  # indirizzi che mostrano pubblicità: nessuna eccezione di nessuna lista li fa passare
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adnxs.com", "criteo.com", "criteo.net",
    "amazon-adsystem.com", "pubmatic.com", "rubiconproject.com", "openx.net", "taboola.com", "outbrain.com",
    "adsrvr.org", "smartadserver.com", "casalemedia.com", "teads.tv", "yieldmo.com", "33across.com",
    "adform.net", "moatads.com", "scorecardresearch.com", "quantserve.com", "media.net", "adsafeprotected.com",
)
ESCHE_OK = {"pagead2.googlesyndication.com", "static.doubleclick.net", "www.googletagservices.com"}


def _pubblicita(d):
    if d in ESCHE_OK:
        return False
    return any(d == p or d.endswith("." + p) for p in MAI_ECCEZIONE)


def estrai_eccezioni(testo):
    """righe @@||dominio^ delle liste: i loro autori dicono «non bloccarlo» (spesso per i rilevatori di adblock)."""
    out = set()
    for r in testo.splitlines():
        r = r.strip().lower()
        if not r.startswith("@@"):
            continue
        m = _ECC.match(r.split(" #")[0])
        if not m:
            continue
        opz = set((m.group(2) or "").split(",")) - {""}
        if opz - {"important"}:  # solo eccezioni «per tutto»: quelle per script/pagine valgono nei browser, non nel DNS
            continue
        d = m.group(1).lstrip("*.")
        if "*" in d or not _DOM.match(d) or _pubblicita(d):
            continue
        out.add(d)
    return out


def _righe_pulite(nome):
    return [r.strip() for r in filtro._righe(nome) if r.strip() and not r.strip().startswith("#")]


def _eccezioni(con_scarti=False):
    """permessi scritti a mano o dal pannello (bianca, sblocca, anti-rilevamento), già PULITI:
    - mai un indirizzo che mostra pubblicità (un permesso così vale per tutti i siti e tutti i dispositivi);
    - mai qualcosa che hai bloccato a mano (il blocco vince sempre), né un dominio «padre» di un tuo blocco.
    con_scarti=True ritorna anche {dominio: motivo} per i permessi ignorati (li mostra il pannello)."""
    bloccati = {r.lstrip("*.").lower() for r in _righe_pulite("blocca.txt")}
    s, scarti = set(), {}
    for nome in ECCEZIONI_FILE:
        for r in _righe_pulite(nome):
            d = (r[2:] if r.startswith("*.") else r).lower()
            if _pubblicita(d) or d in SENTINELLE:
                scarti[d] = "dominio pubblicitario: non consentibile"
            elif d in bloccati or any(b.endswith("." + d) for b in bloccati):
                scarti[d] = "bloccato da una regola personale: prevale il blocco"
            else:
                s.add(d)
    return (s, scarti) if con_scarti else s


def pulisci_eccezioni():
    """toglie DAVVERO dai file i permessi su indirizzi pubblicitari (non valevano già più):
    così il pannello mostra solo eccezioni vere. Quelli tolti restano scritti in eccezioni-tolte.txt."""
    tolti = []
    with _scrittura:
        for nome in ECCEZIONI_FILE:
            rr = filtro._righe(nome)
            nn = []
            for r in rr:
                x = r.strip()
                d = (x[2:] if x.startswith("*.") else x).lower()
                if x and not x.startswith("#") and (_pubblicita(d) or d in SENTINELLE):
                    tolti.append("%s\t%s\t%s" % (datetime.now().strftime("%Y-%m-%d %H:%M"), nome, x))
                else:
                    nn.append(r)
            if nn != rr:
                filtro._scrivi(nome, nn)
    if tolti:
        with open(os.path.join(DATA, "eccezioni-tolte.txt"), "a", encoding="utf-8") as f:
            f.write("\n".join(tolti) + "\n")
    return len(tolti)


def permessi_puliti(domini):
    """stesso filtro per gli altri permessi (eccezioni delle liste, esche)."""
    bloccati = {r.lstrip("*.").lower() for r in _righe_pulite("blocca.txt")}
    return {d for d in domini if not _pubblicita(d) and d not in SENTINELLE
            and d not in bloccati and not any(b.endswith("." + d) for b in bloccati)}


def _coperto(d, ecc):
    p = d.split(".")
    return any(".".join(p[i:]) in ecc for i in range(len(p) - 1))


def _file(url):
    return os.path.join(FONTI_DIR, hashlib.sha1(url.encode()).hexdigest()[:16] + ".txt")


def _scarica(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Filtreo/1.3 (filtro DNS di casa)"})
    with urllib.request.urlopen(req, timeout=120) as r:
        dati = r.read(MAX_BYTE + 1)
    if len(dati) > MAX_BYTE:
        raise ValueError("lista troppo grande")
    return dati.decode("utf-8", "replace")


def _nome(url, testo):
    m = re.search(r"^\s*[!#]\s*title\s*:\s*(.+)$", testo[:4000], re.I | re.M)
    return m.group(1).strip()[:60] if m else (url.rstrip("/").split("/")[-1][:60] or url[:60])


def _aggiorna(f):
    try:
        testo = _scarica(f["url"])
        dom = estrai_domini(testo)
        if not dom:
            f["errore"] = "Nessun dominio utilizzabile"
            return False
        os.makedirs(FONTI_DIR, exist_ok=True)
        tmp = _file(f["url"]) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as h:
            h.write("\n".join(sorted(dom)) + "\n")
        os.replace(tmp, _file(f["url"]))
        ecc = estrai_eccezioni(testo)
        with open(_file(f["url"]) + ".ecc2", "w", encoding="utf-8") as h:
            h.write("\n".join(sorted(ecc)) + ("\n" if ecc else ""))
        f.update(nome=f.get("nome") or _nome(f["url"], testo), domini=len(dom),
                 aggiornata=datetime.now().strftime("%d/%m %H:%M"), errore="")
        return True
    except Exception as e:
        f["errore"] = "Impossibile scaricare (%s)" % str(e)[:80]
        return False


# ───────────── file per Blocky ─────────────
LAVORO = "lavoro-bianca.txt"
# in «Pausa internet» passano solo i servizi che tengono vivo il telefono (avvisi, ora, aggiornamenti di sicurezza)
PAUSA_PASSA = {"push.apple.com", "time.apple.com", "time.google.com", "captive.apple.com", "connectivitycheck.gstatic.com",
               "mtalk.google.com", "icloud.com", "apple.com", "ts.net", "tailscale.com"}   # siti di lavoro in più (scritti a mano), oltre ai servizi scelti nella modalità


def _prepara_modalita():
    """alla prima partenza della 1.5 crea le modalità dalle regole che c'erano."""
    dd = dispositivi()
    if modalita.migra(dd, fonti(), PRINCIPALE):
        _salva(DISP_JSON, dd)
    modalita.migra_nomi()   # una tantum: «Pulito» (nome di serie di prima) → «Standard»; i nomi scelti dall'utente restano
    modalita.migra_livelli()   # una tantum: «Massimo» → «Rigoroso» + protezione famiglia, «Lavoro» → «Personale» (id invariati)
    ff = fonti()
    livelli.migra(ff)       # una tantum (3.1): livello di partenza + differenze; «Personale» = Standard modificato (fonti invariate)
    livelli.riallinea(ff)   # «fonti» delle modalità con un livello = preimpostato + differenze (liste nuove dei gruppi del livello comprese)


# ───────────── liste «per marca» dei profili pronti: dormono finché nessun dispositivo usa un profilo che le vuole ─────────────
_tentati_casa = {}                    # url -> ultimo tentativo di scarico (niente giri a vuoto se la rete non c'è)
_giro_casa_lock = threading.Lock()


def _urls_casa():
    return {u for _n, u in modalita.FONTI_CASA}


def _scaricata(url):
    return os.path.exists(_file(url)) and os.path.exists(_file(url) + ".ecc2")


def _in_uso(url):
    """qualche gruppo (dispositivo con regole sue, principale compreso) ha un profilo che usa questa lista?"""
    return any(url in modo_di(g).get("fonti", []) for g in gruppi())


def _da_scaricare(f):
    """le liste «per marca» si scaricano solo se un profilo in uso le vuole; tutte le altre come sempre."""
    return not f.get("casa") or _in_uso(f["url"])


def _assegna_casa():
    """«dispositivi» di ogni lista per marca = i gruppi il cui profilo la usa (vuoto se nessuno): mai associata al principale
    per caso. Chiamare con _blocco preso (o da solo all'avvio). Ritorna True se ha scritto."""
    ff = fonti()
    casa, uso, cambiato = _urls_casa(), {}, False
    for g in gruppi():
        for u in modo_di(g).get("fonti", []):
            uso.setdefault(u, []).append(g)
    for f in ff:
        if f["url"] in casa or f.get("seme"):   # liste per marca e liste seminate dalla protezione famiglia (dormienti)
            if not f.get("casa"):
                f["casa"], cambiato = True, True
            if f.get("dispositivi") != uso.get(f["url"], []):
                f["dispositivi"], cambiato = uso.get(f["url"], []), True
    if cambiato:
        _salva(FONTI_JSON, ff)
    return cambiato


def _scarica_casa_in_uso():
    """parte (in sottofondo, mai bloccante) lo scarico delle liste per marca che un profilo in uso vuole e che mancano.
    Riprova al massimo ogni 30 minuti. Ritorna True se è partito."""
    try:
        ora = time.time()
        da = [f for f in fonti() if f.get("casa") and not _scaricata(f["url"]) and _in_uso(f["url"])
              and ora - _tentati_casa.get(f["url"], 0) > 1800]
        if not da or not _giro_casa_lock.acquire(blocking=False):
            return False
        for f in da:
            _tentati_casa[f["url"]] = ora

        def giro():
            try:
                _aggiorna_fonti(da)
            except Exception as e:
                print("Filtreo: liste per marca non scaricate (%s)" % type(e).__name__, flush=True)
            finally:
                _giro_casa_lock.release()
        threading.Thread(target=giro, daemon=True).start()
        return True
    except Exception:
        return False


def _semina_casa():
    """SOLO all'avvio (prepara), prima che parta qualunque altro filo: profili pronti per casa intelligente (TV e casse,
    Telecamere e sensori, Isolato, Server e IA locale). Le liste «Native Tracker» entrano fra le fonti DORMIENTI (dispositivi vuoti,
    non scaricate) e si associano/scaricano solo per i gruppi la cui modalità le usa. Ripara chi ha già la versione sbagliata
    (liste per marca associate al principale)."""
    with _blocco:
        ff = fonti()
        urls = {f["url"] for f in ff}
        nuove = [(n, u) for n, u in modalita.FONTI_CASA if u not in urls]
        for n, u in nuove:
            ff.append({"url": u, "nome": n, "attiva": True, "dispositivi": [], "categoria": "telemetria", "casa": True})
        # «Protezione famiglia»: liste di adulti e scommesse. Chi le ha già fra i filtri (stesso link) non ne riceve altre:
        # le altre nascono dormienti (si scaricano solo se una modalità con la protezione accesa è in uso)
        nuove_f = [(n, u, c) for n, u, c in modalita.FONTI_PROTEZIONE if u not in urls]
        for n, u, c in nuove_f:
            ff.append({"url": u, "nome": n, "attiva": True, "dispositivi": [], "categoria": c, "casa": True, "seme": "famiglia"})
        if nuove or nuove_f:
            _salva(FONTI_JSON, ff)
            urls |= {u for _n, u in nuove} | {u for _n, u, _c in nuove_f}
        modalita.semina(urls)
        _assegna_casa()


def fonti_di(m):
    """le liste che una modalità usa davvero: le sue e, con «Protezione famiglia» accesa, anche tutte quelle
    delle categorie adulti e scommesse (le sue liste restano com'erano: la protezione si somma, non toglie niente)."""
    sue = list(m.get("fonti", []))
    if m.get("famiglia") and m.get("id") not in (modalita.SPENTO, modalita.PAUSA):
        for f in fonti():
            if f["url"] not in sue and modalita.categoria(f) in modalita.CAT_PROTEZIONE:
                sue.append(f["url"])
    return sue


def modo_di(g):
    """la modalità in uso sul gruppo g (= dispositivo con regole sue). «fonti» comprende già quelle della protezione famiglia."""
    x = next((y for y in dispositivi() if y["id"] == g), {})
    m = modalita.trova(x.get("modo") or "")
    if not m:
        mm = modalita.elenco()
        m = mm[0] if mm else {"id": "", "nome": "", "fonti": [f["url"] for f in fonti()], "lavoro": []}
    return dict(m, fonti=fonti_di(m))


ISOLATO_BASE = {   # sempre raggiungibili da un dispositivo isolato: la rete di casa, Tailscale e l'ora
    "local", "lan", "home.arpa", "homeassistant", "ts.net", "tailscale.com",
    "pool.ntp.org", "ntp.org", "time.cloudflare.com", "time.google.com", "time.apple.com", "time.windows.com",
    "time.nist.gov", "ntp.ubuntu.com", "time.android.com",
}


def _base_isolato():
    """Casa (il suo nome pubblico, se c'è), Home Assistant, ora (NTP) e Tailscale."""
    out = set(ISOLATO_BASE)
    h = re.sub(r"^https?://", "", os.environ.get("FILTREO_DOH_URL", "").strip()).split("/")[0].split(":")[0].lower()
    if h and _NOME_OK.match(h):
        out.add(h)
    return out


def _stretto(g):
    """il gruppo g è in un profilo «solo indirizzi permessi» (Isolato)?"""
    m = modo_di(g)
    return bool(m.get("solo_permessi")) and m.get("id") not in (modalita.SPENTO, modalita.PAUSA)


def _scrivi_gruppi():
    """riscrive dev-<gruppo>.txt per ogni gruppo. Ritorna i gruppi scritti."""
    if not filtro._righe(ANTI):
        filtro._scrivi(ANTI, ["# siti «esca» dei rilevatori di adblock: permessi così i siti non si accorgono del filtro"] + ANTI_BASE)
    else:  # 1.3.1 permetteva anche indirizzi che mostrano annunci: li tolgo
        rr = filtro._righe(ANTI)
        nn = [r for r in rr if r.strip().lstrip("*.") not in ANTI_VECCHIE]
        if nn != rr:
            filtro._scrivi(ANTI, nn)
    ecc = _eccezioni()
    # permessi tuoi per il gruppo «manuale» (tutti i dispositivi): solo quelli puliti
    filtro._scrivi("manuale-ok.txt", ["# permessi tuoi (bianca + sblocca + anti-rilevamento) senza pubblicità e senza ciò che hai bloccato"]
                  + sorted((set(ecc) | set(lettori_sempre_ok())) - MAI_PERMESSI))
    cache = {}
    scritti = []
    _prepara_modalita()
    vecchie = _vecchie_per_gruppo()
    for g in gruppi():
        m = modo_di(g)
        _scrivi_vecchie(g, m, vecchie)
        if m["id"] == modalita.SPENTO:
            # «Senza filtro»: niente blocchi delle liste (la lista nera resta: è «bloccati sempre»)
            filtro._scrivi("dev-%s-ok.txt" % g, ["# gruppo %s: senza filtro" % g])
            filtro._scrivi("dev-%s.txt" % g, ["# gruppo %s: senza filtro (modalità «%s»)" % (g, modalita.NOME_SPENTO)])
            scritti.append(g)
            continue
        if m["id"] == modalita.PAUSA:
            # «Pausa internet» (famiglia, a nanna): si ferma tutto, tranne quello che serve al telefono per funzionare
            filtro._scrivi("dev-%s-ok.txt" % g, ["# gruppo %s: pausa internet" % g] + sorted(PAUSA_PASSA))
            filtro._scrivi("dev-%s.txt" % g, ["# gruppo %s: pausa internet (tutto fermo)" % g, "/.*/"])
            scritti.append(g)
            continue
        if m.get("solo_permessi"):
            # «Isolato» (o «solo indirizzi permessi»): fermo tutto TRANNE Casa, Home Assistant, l'ora e la lista bianca del profilo.
            # Nessun permesso «di tutti» (il gruppo manuale non si applica: vedi _config_testo).
            extra = _base_isolato() | set(modalita.domini_utente(m.get("bianca"))) | modalita.domini_casa(m.get("passa", []))
            filtro._scrivi("dev-%s-ok.txt" % g, ["# gruppo %s: solo indirizzi permessi (Casa, ora, lista bianca del profilo)" % g]
                          + sorted(extra | {"*." + d for d in extra}))
            filtro._scrivi("dev-%s.txt" % g, ["# gruppo %s: solo indirizzi permessi (tutto fermo, tranne la lista bianca)" % g, "/.*/"])
            scritti.append(g)
            continue
        sue = set(m.get("fonti", []))
        extra = modalita.domini_casa(m.get("passa", [])) | set(modalita.domini_utente(m.get("bianca")))
        tutti = set()
        ok = {r.lstrip("*.") for r in _righe_pulite(ANTI)}
        for f in fonti():
            if f.get("attiva", True) and f["url"] in sue:
                try:
                    ok |= {x.strip() for x in open(_file(f["url"]) + ".ecc2", encoding="utf-8") if x.strip()}
                except OSError:
                    pass
        ok = permessi_puliti(ok) | ecc
        ok |= permessi_puliti(video_di_serie() | _video_permessi_tutti()) | set(lettori_sempre_ok())   # lettori video: file del lettore e «Fai partire il video»
        if m.get("lavoro"):
            # strumenti di lavoro (Ads Manager, pixel, Analytics…): passano SEMPRE in questa modalità,
            # anche se sono indirizzi pubblicitari. Gli stessi servizi del profilo lavoro dell'estensione.
            ok |= modalita.domini_lavoro(m["lavoro"]) | {r.lstrip("*.").lower() for r in _righe_pulite(LAVORO)}
        ok |= extra   # servizi sempre aperti e lista bianca del profilo (TV, server…)
        ok -= MAI_PERMESSI   # la telemetria «mai permessa» non entra mai tra i permessi, neanche in Lavoro
        filtro._scrivi("dev-%s-ok.txt" % g, ["# gruppo %s: esche dei rilevatori + eccezioni delle liste + permessi tuoi (puliti)" % g]
                      + sorted(ok | {"*." + d for d in extra}))
        for f in fonti():
            if not f.get("attiva", True) or f["url"] not in sue:
                continue
            if f["url"] not in cache:
                try:
                    cache[f["url"]] = set(x.strip() for x in open(_file(f["url"]), encoding="utf-8") if x.strip())
                except OSError:
                    cache[f["url"]] = set()
            tutti |= cache[f["url"]]
        tutti |= SENTINELLE   # i grandi indirizzi pubblicitari sono bloccati sempre, qualunque lista sia accesa
        ok -= MAI_PERMESSI
        tutti |= MAI_PERMESSI
        app = modalita.domini_app(m.get("app", [])) | set(modalita.domini_utente(m.get("blocca")))
        if app:   # app e giochi (e blocchi del profilo) bloccati in questa modalità: vincono anche sugli strumenti di lavoro
            ok = {d for d in ok if not any(d == a or d.endswith("." + a) for a in app)}
            filtro._scrivi("dev-%s-ok.txt" % g, ["# gruppo %s: esche dei rilevatori + eccezioni delle liste + permessi tuoi (puliti)" % g]
                          + sorted(ok | {"*." + d for d in extra if d in ok}))
        tutti = {d for d in tutti if d in MAI_PERMESSI or (not protetto(d.lstrip("*.")) and not _coperto(d.lstrip("*."), ok))}
        tutti = {d for d in tutti if d.startswith("*.") or "*." + d not in tutti}
        tutti |= app | {"*." + a for a in app}
        filtro._scrivi("dev-%s.txt" % g, ["# gruppo %s: generato dal pannello (non modificare a mano)" % g] + sorted(tutti))
        scritti.append(g)
    _scrivi_famiglia_paracadute()
    return scritti


FILE_FAMIGLIA_CLOUD = "famiglia-paracadute.txt"


def _scrivi_famiglia_paracadute():
    """per il paracadute (Cloudflare): le liste di adulti e scommesse in un file solo, lo stesso contenuto che Casa applica con la
    protezione famiglia. Non è una lista del motore: si scrive a parte e non fa ricaricare niente. Vuoto (solo intestazione)
    se nessuna modalità ha la protezione accesa."""
    righe = ["# protezione famiglia: liste di adulti e scommesse (per il paracadute; vuoto se nessuna modalità la usa)"]
    try:
        if any(m.get("famiglia") for m in modalita.elenco()):
            tutti = set()
            for f in fonti():
                if f.get("attiva", True) and modalita.categoria(f) in modalita.CAT_PROTEZIONE:
                    try:
                        tutti |= {x.strip() for x in open(_file(f["url"]), encoding="utf-8") if x.strip()}
                    except OSError:
                        pass
            righe += sorted(d for d in tutti if not protetto(d.lstrip("*.")))
        p = os.path.join(LISTE, FILE_FAMIGLIA_CLOUD)
        nuovo = "\n".join(righe) + "\n"
        try:
            if open(p, encoding="utf-8").read() == nuovo:
                return
        except OSError:
            pass
        with open(p + ".tmp", "w", encoding="utf-8") as h:
            h.write(nuovo)
        os.replace(p + ".tmp", p)
    except Exception as e:   # un file in più per il paracadute non deve mai fermare le liste di casa
        print("Filtreo: file famiglia per il paracadute non scritto (%s)" % type(e).__name__, flush=True)


_NOSTRI = ("dev-", "importate.txt", "blocca.txt", "sblocca.txt", "bianca.txt", "lavoro-bianca.txt", "manuale-ok.txt", "anti-rilevamento.txt")


def _locali(vv):
    return [v for v in (vv or []) if isinstance(v, str) and not v.startswith("http") and "\n" not in v
            and not any(n in os.path.basename(v) for n in _NOSTRI)]


def _vecchie_info(b):
    """dalla config di prima: (gruppi extra, extra nel gruppo default, {dispositivo: (liste nere locali, liste bianche locali)}).
    Dipende solo dalla config di prima e dai dispositivi, MAI dalla modalità."""
    bb = (b or {}).get("blocking") or {}
    den0, al0 = bb.get("denylists") or {}, bb.get("allowlists") or {}
    gest = set(x.strip() for x in os.environ.get("FILTREO_BASE_GESTITI", "lavoro,tv,nessun-blocco").split(",") if x.strip())
    princ_vecchio = os.environ.get("FILTREO_BASE_PRINCIPALE", "lavoro")
    gestiti = gest | {"manuale", "sblocca", modalita.SPENTO} | set(gruppi())
    extra = [g for g in den0 if g not in gestiti and _locali(den0[g])]
    extra_def = [g for g in ((bb.get("clientGroupsBlock") or {}).get("default") or []) if g in extra]
    per_g = {}
    dd = {x["id"]: x for x in dispositivi()}
    for g in gruppi():
        vg = (dd.get(g) or {}).get("base") or (princ_vecchio if g == PRINCIPALE else g)
        den_f = list(_locali(den0.get(vg))) if vg in den0 else []
        for e in extra_def:
            den_f += [v for v in _locali(den0[e]) if v not in den_f]
        al_f = list(_locali(al0.get(vg))) if vg in al0 else []
        per_g[g] = (den_f, al_f)
    return extra, extra_def, per_g


def _vecchie_per_gruppo():
    """come _vecchie_info ma legge FILTREO_BASE; {} se non c'è (chi non ha gruppi vecchi non cambia)."""
    base = os.environ.get("FILTREO_BASE", "")
    if not base or not os.path.exists(base):
        return {}
    try:
        import yaml
        b = yaml.safe_load(open(base, encoding="utf-8")) or {}
    except Exception:
        return {}
    return _vecchie_info(b)[2]


def _righe_vecchie(files):
    out, visti = [], set()
    for f in files:
        try:
            for r in open(f, encoding="utf-8"):
                r = r.strip()
                if r and r not in visti:
                    visti.add(r)
                    out.append(r)
        except OSError:
            pass
    return out


def _scrivi_vecchie(g, m, per_g):
    """contenuto dei file «vecchie» del gruppo: vuoti in Senza filtro / Pausa / Isolato; liste nere vecchie altrimenti;
    liste bianche vecchie solo nelle modalità con strumenti di lavoro."""
    den_f, al_f = per_g.get(g, ([], []))
    ferma = m["id"] in (modalita.SPENTO, modalita.PAUSA) or bool(m.get("solo_permessi"))
    if den_f:
        r = [] if ferma else _righe_vecchie(den_f)
        filtro._scrivi("dev-%s-vecchie.txt" % g, ["# gruppo %s: liste locali della config di prima (vuoto se la modalità non le usa)" % g] + r)
    if al_f:
        r = _righe_vecchie(al_f) if (not ferma and m.get("lavoro")) else []
        filtro._scrivi("dev-%s-vecchie-ok.txt" % g, ["# gruppo %s: permessi locali della config di prima (solo modalità lavoro)" % g] + r)


def _config_testo():
    t = open(MODELLO, encoding="utf-8").read()
    deny, allow, cli = [], [], []
    for g in gruppi():
        deny.append("    %s:\n      - %s/dev-%s.txt" % (g, LISTE, g))
        allow.append("    %s:\n      - %s/dev-%s-ok.txt" % (g, LISTE, g))
    for x in dispositivi():
        ips = [i for i in ([x.get("ip")] + list(x.get("ips") or [])) if i]
        if not ips or x.get("principale"):
            continue
        g = x["id"] if x.get("proprie") else PRINCIPALE
        for ip in dict.fromkeys(ips):
            if IGNORA_IP.match(ip):
                # 127.x = il filtro stesso: da lì arrivano anche le domande «fuori casa» (via la porta DoH),
                # che devono seguire il nome del dispositivo, non questo indirizzo
                continue
            cli.append('    "%s":\n      - %s\n      - manuale' % (ip, g))
    # DNS personale (fuori casa): un nome per dispositivo e uno per ogni modalità
    import dns_personale
    dd = {x["id"]: x for x in dispositivi()}

    def gruppo_di(did):
        x = dd.get(did) or {}
        return x["id"] if x.get("proprie") else PRINCIPALE
    cli.extend(dns_personale.righe_config(gruppo_di))
    # nomi di prova (solo dal pannello, per il «Controllo della protezione»): uno per gruppo
    for g in gruppi():
        cli.append('    "filtreo-prova-%s":\n      - %s\n      - manuale' % (g, g))
    # dove ascolta il DNS: di serie la porta 53 ovunque (Pi); sul Jetson indirizzi precisi (FILTREO_DNS="ip:53,ip:53")
    for g in gruppi():   # «Isolato»: niente permessi di tutti (gruppo «manuale»), solo la sua lista bianca
        if _stretto(g):
            cli = [c.replace("      - %s\n      - manuale" % g, "      - %s" % g) for c in cli]
    asc = [x.strip() for x in os.environ.get("FILTREO_DNS", "").split(",") if re.fullmatch(r"[0-9a-fA-F.:\[\]]*:?\d{1,5}", x.strip())]
    dns = "53" if not asc else "\n" + "\n".join("    - %s" % x for x in asc)
    t = t.replace("__DNS__", dns).replace("__MOTORE__", str(filtro.MOTORE))
    t = (t.replace("__GRUPPI_BLOCCO__", "\n".join(deny))
          .replace("__GRUPPI_PERMESSI__", "\n".join(allow))
          .replace("__DISPOSITIVI__", "\n".join(cli)))
    return _con_base(t)


def _base_blocchi(y, b):
    """liste della config di prima che non sono «fonti» del pannello (Regole Filtreo, liste locali, gruppi extra):
    restano attive come prima. Gruppi gestiti prima a mano (FILTREO_BASE_GESTITI, di serie lavoro,tv,nessun-blocco)
    diventano i dispositivi del pannello; gli altri gruppi della config di prima si aggiungono a tutti i dispositivi
    filtrati. Mai ai dispositivi in «Senza filtro»."""
    bb = (b or {}).get("blocking") or {}
    if not bb:
        return
    gest = set(x.strip() for x in os.environ.get("FILTREO_BASE_GESTITI", "lavoro,tv,nessun-blocco").split(",") if x.strip())
    princ_vecchio = os.environ.get("FILTREO_BASE_PRINCIPALE", "lavoro")
    yb = y["blocking"]
    den0, al0 = bb.get("denylists") or {}, bb.get("allowlists") or {}
    extra, extra_def, per_g = _vecchie_info(b)
    for g in extra:
        yb["denylists"][g] = _locali(den0[g])
        if g in al0 and _locali(al0[g]):
            yb["allowlists"][g] = _locali(al0[g])
    # Le liste «vecchie» dei dispositivi stanno in file SEMPRE presenti (dev-<g>-vecchie.txt / -vecchie-ok.txt):
    # la config non dipende dalla modalità (un interruttore non riavvia mai il motore), la modalità decide
    # solo il CONTENUTO dei file (_scrivi_gruppi).
    for g, (den_f, al_f) in per_g.items():
        if den_f:
            yb["denylists"].setdefault(g, []).append("%s/dev-%s-vecchie.txt" % (LISTE, g))
        if al_f:
            yb["allowlists"].setdefault(g, []).append("%s/dev-%s-vecchie-ok.txt" % (LISTE, g))
    if extra_def:
        dev = set(gruppi())
        for k, gg in yb["clientGroupsBlock"].items():
            # chi ha un gruppo-dispositivo prende i gruppi extra dal suo file «vecchie» (contenuto per modalità)
            if isinstance(gg, list) and not (set(gg) & dev) and "spento" not in gg:
                gg += [g for g in extra_def if g not in gg]


BASE_TIENI = ("upstreams", "bootstrapDns", "customDNS", "conditional", "clientLookup", "caching", "filtering", "ede", "specialUseDomains")


def _con_base(t):
    """FILTREO_BASE = config di Blocky che c'era prima (Jetson): le sue parti di rete restano uguali
    (upstream, nomi locali, Tailscale…). Liste e dispositivi li decide sempre Filtreo."""
    base = os.environ.get("FILTREO_BASE", "")
    if not base or not os.path.exists(base):
        return t
    try:
        import yaml
        b = yaml.safe_load(open(base, encoding="utf-8")) or {}
        y = yaml.safe_load(t)
    except Exception as e:
        print("Filtreo: config di base non letta (%s): uso quella di serie" % str(e)[:100], flush=True)
        return t
    for k in BASE_TIENI:
        if k in b:
            y[k] = b[k]
    _base_blocchi(y, b)
    _nodo_pubblico(y)
    zona = ((y.get("customDNS") or {}).get("zone")) or ""
    if y.get("customDNS") is not None:
        extra = [r for r in ('use-application-dns.net. 300 IN TXT "filtreo"', 'mask.icloud.com. 300 IN TXT "filtreo"',
                             'mask-h2.icloud.com. 300 IN TXT "filtreo"',
                             'controllo-filtreo.fullhd-david.workers.dev. 30 IN A 192.0.2.77') if r.split()[0] not in zona]
        if extra:
            if "$ORIGIN" not in zona:
                zona = "$ORIGIN .\n$TTL 300\n" + zona
            y["customDNS"]["zone"] = zona.rstrip("\n") + "\n" + "\n".join(extra) + "\n"
    return "# GENERATO DA FILTREO (base: %s)\n" % os.path.basename(base) + yaml.safe_dump(y, sort_keys=False, allow_unicode=True, width=200)


def _nodo_pubblico(y):
    """il nome pubblico del nodo (link del pannello e DNS fuori casa) va risolto come lo vede internet:
    se la config lo manda all'indirizzo interno di Tailscale (100.x), chi ha Tailscale spento non lo raggiunge."""
    h = re.sub(r"^https?://", "", os.environ.get("FILTREO_DOH_URL", "").strip()).split("/")[0].split(":")[0].lower()
    if not h:
        return
    cd = y.get("customDNS") or {}
    for k in list((cd.get("mapping") or {}).keys()):
        if h == k.lower().rstrip(".") or h.endswith("." + k.lower().rstrip(".")):
            cd["mapping"].pop(k)
    up = [u for u in ((y.get("upstreams") or {}).get("groups") or {}).get("default", []) if isinstance(u, str)]
    cond = y.get("conditional") or {}
    if up and any(h == k.lower() or h.endswith("." + k.lower()) for k in (cond.get("mapping") or {})):
        cond["mapping"][h] = ",".join(up)


def _garantisci_file_gruppi():
    """3.1 (bug del banco «liste sue»): la config nomina /data/liste/dev-<g>.txt e dev-<g>-ok.txt per OGNI gruppo; con un dispositivo
    nuovo quei file nascevano solo dopo, nel lavoro in sottofondo, e un avvio del motore in quel momento (riavvio, guardia, lista
    nuova) partiva con un gruppo senza file. Ora la config non nomina mai un file che non c'è: chi manca nasce come copia di quelli del
    principale (stesse regole con cui parte un dispositivo nuovo) e poi _scrivi_gruppi lo riscrive giusto.
    Creato solo «se manca» (os.link non sovrascrive): mai sopra un file vero scritto nel frattempo."""
    pr = next((x["id"] for x in dispositivi() if x.get("principale")), PRINCIPALE)
    n = 0
    for g in gruppi():
        for suf in ("", "-ok"):
            p = os.path.join(LISTE, "dev-%s%s.txt" % (g, suf))
            if os.path.exists(p):
                continue
            fonte = os.path.join(LISTE, "dev-%s%s.txt" % (pr, suf))
            tmp = "%s.nuovo-%d" % (p, os.getpid())
            try:
                try:
                    with open(fonte, "rb") as a, open(tmp, "wb") as b:
                        b.write(a.read())
                except OSError:
                    with open(tmp, "w", encoding="utf-8") as b:
                        b.write("# gruppo %s: in preparazione\n" % g)
                try:
                    os.link(tmp, p)
                    n += 1
                except OSError:
                    pass   # nel frattempo l'ha scritto qualcun altro: vale il suo
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    return n


def scrivi_config():
    """scrive la config del motore; ritorna True se è cambiata."""
    os.makedirs(LISTE, exist_ok=True)
    _garantisci_file_gruppi()
    nuovo = _config_testo()
    vuota = os.path.join(LISTE, "vuota.txt")
    if not os.path.exists(vuota):
        open(vuota, "w").close()
    try:
        vecchio = open(CONFIG, encoding="utf-8").read()
    except OSError:
        vecchio = ""
    if nuovo == vecchio:
        return False
    tmp = CONFIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        h.write(nuovo)
    try:   # la config di prima resta accanto: serve a capire cosa ha causato un riavvio
        with open(CONFIG + ".prima", "w", encoding="utf-8") as h:
            h.write(vecchio)
    except OSError:
        pass
    os.replace(tmp, CONFIG)
    return True


# Avvisi sul telefono (Telegram), se configurati: FILTREO_TG_DIR = cartella con .tg_token e .tg_owner
# (sul Jetson è quella di Lumen, montata in sola lettura). Vuota = nessun avviso (Pi di Giò).
ATTESA_RIAVVIO = int(os.environ.get("FILTREO_ATTESA_RIAVVIO", "0") or 0)
_riavvio = {"previsto": 0.0}


def avvisa(testo):
    d = os.environ.get("FILTREO_TG_DIR", "")
    if not d:
        return False
    try:
        tok = open(os.path.join(d, ".tg_token"), encoding="utf-8").read().strip()
        chat = open(os.path.join(d, ".tg_owner"), encoding="utf-8").read().strip()
        import urllib.parse
        import urllib.request
        dati = urllib.parse.urlencode({"chat_id": chat, "text": testo}).encode()
        urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % tok, data=dati, timeout=10).read()
        return True
    except Exception:
        return False


def riavvia_motore_con_avviso(motivo="modifica"):
    """con FILTREO_ATTESA_RIAVVIO (es. 60 sul Jetson): avviso sul telefono, poi riavvio. Più cambi ravvicinati = un riavvio."""
    if ATTESA_RIAVVIO <= 0:
        return riavvia_motore(motivo)
    if _riavvio["previsto"] > time.time():
        return True
    _riavvio["previsto"] = time.time() + ATTESA_RIAVVIO
    avvisa("Filtreo: riavvio del filtro tra %d secondi per applicare: %s. Connessione sospesa per alcuni secondi." % (ATTESA_RIAVVIO, motivo))

    def dopo():
        time.sleep(ATTESA_RIAVVIO)
        _riavvio["previsto"] = 0.0
        riavvia_motore(motivo)
    threading.Thread(target=dopo, daemon=True).start()
    return True


# ───────────── riavvio «veloce»: il DNS torna in pochi secondi ─────────────
# Blocky, quando parte, apre la porta ma risponde solo DOPO aver letto tutte le liste (con milioni di righe sul Pi sono
# decine di secondi: internet fermo). Quindi prima del riavvio i file dev-*.txt GRANDI vengono sostituiti da un file
# con un solo commento: Blocky parte in 2-3 secondi e risponde subito (i permessi e i gruppi «Isolato»/«Pausa», piccoli,
# restano veri). Appena risponde, i file veri tornano al loro posto e una ricarica (che non ferma mai il DNS: Blocky
# cambia le liste di ogni gruppo tutte in una volta, quando ha finito di leggerle) rimette i blocchi. Per qualche
# secondo, solo sui gruppi grandi, passa la pubblicità: meglio di una casa senza internet.
STUB_MARCA = "# FILTREO-STUB: liste vere in arrivo (avvio rapido)"
STUB_SOGLIA = 200 * 1024
_stub = {}                       # file dev-*.txt sostituito -> dove aspetta la versione vera
_riavvio_in_corso = {"fino": 0.0}


def _metti_stub():
    n = 0
    with _scrittura:
        for p in glob.glob(os.path.join(LISTE, "dev-*.txt")):
            if p.endswith("-ok.txt") or p in _stub:
                continue
            try:
                if os.path.getsize(p) < STUB_SOGLIA:
                    continue
                pieno = p + ".pieno"
                os.replace(p, pieno)
                with open(p, "w", encoding="utf-8") as h:
                    h.write(STUB_MARCA + "\n")
                _stub[p] = pieno
                n += 1
            except OSError:
                pass
    return n


def _ripristina_stub():
    """rimette le liste vere. Se qualcuno ha già riscritto il file (cambio nel frattempo), vale quello nuovo."""
    n = 0
    with _scrittura:
        for p, pieno in list(_stub.items()):
            try:
                with open(p, encoding="utf-8") as h:
                    ancora_stub = h.readline().startswith(STUB_MARCA)
                if ancora_stub:
                    os.replace(pieno, p)
                    filtro.MODIFICHE[0] += 1
                    n += 1
                else:
                    os.remove(pieno)
            except OSError:
                pass
            _stub.pop(p, None)
    return n


def motore_pronto(attesa=2):
    t, err = filtro._api("/api/blocking/status", attesa=attesa)
    return err is None


ATTESA_PRONTO = int(os.environ.get("FILTREO_ATTESA_PRONTO", "120") or 120)   # secondi massimi perché il motore riparta da solo
BLOCKY_OUT = os.path.join(DATA, "blocky.out")


def _vivo(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True   # esiste ma non è nostro: lo si considera vivo


def _pid_ora():
    try:
        return int(open(PID_BLOCKY).read().strip())
    except (OSError, ValueError):
        return 0


def _ultimo_errore_motore():
    """l'ultima riga di errore che Blocky ha scritto (blocky.out), per il registro della guardia. "" se non c'è."""
    try:
        with open(BLOCKY_OUT, "rb") as f:
            f.seek(max(0, os.path.getsize(BLOCKY_OUT) - 8000))
            righe = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return ""
    for r in reversed(righe):
        if re.search(r"level=(error|fatal)|panic|can't|cannot|invalid|errore", r, re.I):
            return r.strip()[-220:]
    return ""


def _aspetta_ripartenza(pid_vecchio, secondi):
    """aspetta che un processo NUOVO risponda. Ritorna (pronto, crollato): crollato = il motore nuovo è morto appena partito
    (il ciclo che lo rilancia ha già cambiato processo più volte, o quello nuovo non c'è più): con questa config non parte."""
    fine = time.time() + secondi
    nuovi = []
    t0 = time.time()
    while time.time() < fine:
        p = _pid_ora() or pid_vecchio
        if p != pid_vecchio and p not in nuovi:
            nuovi.append(p)
        if p != pid_vecchio and motore_pronto():
            return True, False
        if time.time() - t0 > 6 and (len(nuovi) >= 2 or (nuovi and not _vivo(nuovi[-1]))):
            time.sleep(1)
            if motore_pronto():
                return True, False
            return False, True
        time.sleep(0.3)
    return motore_pronto(), False


def _torna_config_prima():
    """la config nuova fa crollare il motore a ogni avvio: si rimette quella di prima (che funzionava) e la nuova resta in
    blocky.yml.rifiutata per capire cosa non va. Mai la configurazione minima della guardia. Ritorna True se il motore riparte."""
    try:
        prima = open(CONFIG + ".prima", encoding="utf-8").read()
        nuova = open(CONFIG, encoding="utf-8").read()
    except OSError:
        return False
    if not prima.strip() or prima == nuova or prima.startswith("# CONFIGURAZIONE MINIMA"):
        return False
    errore = _ultimo_errore_motore()
    try:
        with open(CONFIG + ".rifiutata", "w", encoding="utf-8") as h:
            h.write(nuova)
        with open(CONFIG + ".tmp", "w", encoding="utf-8") as h:
            h.write(prima)
        os.replace(CONFIG + ".tmp", CONFIG)
    except OSError:
        return False
    _guardia_registra("Configurazione nuova rifiutata dal filtro: rimessa quella di prima (%s)" % (errore or "nessun errore scritto"))
    _guardia_avvisa("La configurazione nuova non fa partire il filtro: rimessa quella di prima. Dettagli in blocky.yml.rifiutata.")
    p = _pid_ora()
    if p:
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass
    pronto, _c = _aspetta_ripartenza(p, 40)
    return pronto


def riavvia_motore(motivo="modifica", forza=False):
    """Blocky gira in un ciclo in run.sh: fermarlo = ripartirà da solo con la config nuova. Ritorna subito;
    il lavoro (e la sua durata) si chiude da solo quando il motore risponde e le liste vere sono tornate."""
    try:
        pid = int(open(PID_BLOCKY).read().strip())
    except (OSError, ValueError):
        pid = 0
    if not pid:
        appl.finisci(None, False)
        return False
    if appl.preleva() == 0:
        appl.inizia("riavvio", motivo)
    else:
        appl.segna_riavvio(motivo)
    n = appl.preleva()
    _riavvio_in_corso["fino"] = time.time() + 150
    _metti_stub()
    try:
        os.kill(pid, signal.SIGKILL if forza else signal.SIGTERM)
    except OSError:
        _ripristina_stub()
        _riavvio_in_corso["fino"] = 0.0
        appl.finisci(n, False)
        return False

    def dopo():
        ok = False
        t0 = time.time()
        try:
            time.sleep(0.5)
            if not forza:
                # il motore di prima deve uscire: se dopo 8 secondi è ancora vivo (chiusura bloccata) lo si ferma di colpo,
                # altrimenti il ciclo di run.sh non fa partire quello nuovo e la casa resta senza DNS
                fine_uscita = time.time() + 8
                while time.time() < fine_uscita and _vivo(pid) and _pid_ora() in (0, pid):
                    time.sleep(0.2)
                if _vivo(pid) and _pid_ora() in (0, pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                        _guardia_registra("Riavvio: il filtro non si chiudeva da 8 secondi, fermato di colpo")
                    except OSError:
                        pass
            ok, crollato = _aspetta_ripartenza(pid, ATTESA_PRONTO)
            if not ok and crollato:
                ok = _torna_config_prima()
            if _stub:
                _ripristina_stub()
            if ok and filtro.da_ricaricare():
                ok = filtro._ricarica()
        except Exception as e:
            print("Filtreo: riavvio veloce non riuscito: %s" % str(e)[:150], flush=True)
        finally:
            _riavvio_in_corso["fino"] = 0.0
            if not ok and not _g["giu_da"]:
                # la guardia conta da quando il DNS è giù (inizio del riavvio), non da adesso: niente altri 150 s di attesa
                _g["giu_da"] = t0
            appl.finisci(n, ok)
    threading.Thread(target=dopo, daemon=True).start()
    return True


def _applica(config_cambiata=False, motivo=""):
    """rende effettivi i cambi. Se cambia la config del motore: riavvio veloce (vedi sopra).
    Altrimenti SENZA riavvio: si riscrivono i file e si ricarica in sottofondo (un solo lavoratore, più richieste
    ravvicinate = un solo giro; se nessun file è cambiato non si ricarica niente), così il pannello risponde subito
    anche con liste da milioni di righe. Ogni applicazione è misurata: vedi applicazione.py."""
    _scarica_casa_in_uso()   # liste per marca che un profilo in uso vuole e mancano: in sottofondo
    if config_cambiata and _lavoratore["attivo"]:
        # la riscrittura dei file (secondi, con liste enormi) e il riavvio vanno in sottofondo: il pannello risponde subito
        appl.inizia("riavvio", motivo or "modifica", ATTESA_RIAVVIO)

        def lavoro():
            try:
                with _scrittura:
                    _scrivi_gruppi()
            except Exception as e:
                print("Filtreo: riscrittura liste non riuscita: %s" % str(e)[:150], flush=True)
            riavvia_motore_con_avviso(motivo or "modifica")
        threading.Thread(target=lavoro, daemon=True).start()
        return
    if config_cambiata or not _lavoratore["attivo"]:
        if config_cambiata:
            appl.inizia("riavvio", motivo or "modifica", ATTESA_RIAVVIO)
        with _scrittura:
            _scrivi_gruppi()
        if config_cambiata:
            riavvia_motore_con_avviso(motivo or "modifica")
        elif filtro.da_ricaricare():
            filtro.ricarica_async(motivo or "modifica")
        return
    appl.inizia("ricarica", motivo or "modifica")
    _da_applicare.set()


def _giro_lavoratore():
    while True:
        _da_applicare.wait()
        time.sleep(1)           # raccoglie i clic ravvicinati in un solo giro
        _da_applicare.clear()
        n = appl.preleva()
        ok = False
        try:
            with _scrittura:
                _scrivi_gruppi()
            ok = filtro._ricarica() if filtro.da_ricaricare() else True   # niente di cambiato = niente da rileggere
        except Exception as e:  # il lavoratore non deve mai morire
            print("Filtreo: aggiornamento liste non riuscito: %s" % str(e)[:150], flush=True)
        if ok:
            _tentativi["n"] = 0
            appl.finisci(n, True)
        elif _tentativi["n"] < 20:  # motore occupato o in riavvio: riprovo (per ~5 minuti)
            _tentativi["n"] += 1
            time.sleep(3 if _tentativi["n"] <= 5 else 15)
            _da_applicare.set()
        else:
            _tentativi["n"] = 0
            appl.finisci(None, False)


# ───────────── guardia del motore: la casa non resta mai senza DNS ─────────────
# Ogni 2 secondi si prova Blocky (API e una vera domanda DNS). Se non risponde da più di 10 secondi:
#   1) lo si ferma di colpo e lo si fa ripartire con l'avvio rapido (liste grandi sostituite da un file vuoto);
#   2) se dopo altri 20 secondi ancora niente (config rotta, memoria finita, liste troppo grandi): si scrive una
#      configurazione MINIMA (stesse porte, solo DNS a monte, nessuna lista) e si fa ripartire: la casa naviga
#      senza filtro invece di restare senza internet. Ogni 10 minuti si riprova con la configurazione vera.
# Tutto va nel registro /data/log/guardia.jsonl (con la memoria usata da Blocky) e, dove c'è, su Telegram.
GUARDIA_SOGLIA = float(os.environ.get("FILTREO_GUARDIA_SECONDI", "10") or 10)
GUARDIA_ATTIVA = os.environ.get("FILTREO_GUARDIA", "1") != "0"
GUARDIA_LOG = os.path.join(DATA, "log", "guardia.jsonl")
CONFIG_MINIMA = """# CONFIGURAZIONE MINIMA di emergenza (scritta dalla guardia): solo DNS a monte, nessuna lista.
ports:
  dns: __DNS__
  http: 127.0.0.1:__MOTORE__

upstreams:
  groups:
    default:
      - 1.1.1.1
      - 9.9.9.9
      - 8.8.8.8
  strategy: parallel_best
  timeout: 2s

caching:
  minTime: 5m
  maxTime: 30m

log:
  level: info
  format: text
"""
_g = {"giu_da": 0.0, "passo": 0, "riavvii": 0, "minima": False, "minima_da": 0.0, "ultimo": "", "avviso": 0.0}


def _dns_ascolto():
    asc = [x.strip() for x in os.environ.get("FILTREO_DNS", "").split(",") if re.fullmatch(r"[0-9a-fA-F.:\[\]]*:?\d{1,5}", x.strip())]
    return "53" if not asc else "\n" + "\n".join("    - %s" % x for x in asc)


def _indirizzi_dns():
    """dove provare il DNS: gli indirizzi di FILTREO_DNS, altrimenti 127.0.0.1:53."""
    out = []
    for x in [y.strip() for y in os.environ.get("FILTREO_DNS", "").split(",") if y.strip()]:
        if x.startswith("["):
            continue   # IPv6: ci si accontenta degli altri
        h, _s, porta = x.rpartition(":")
        if not h:
            h, porta = "127.0.0.1", x.lstrip(":")
        if h in ("0.0.0.0", ""):
            h = "127.0.0.1"
        try:
            out.append((h, int(porta)))
        except ValueError:
            pass
    return out or [("127.0.0.1", 53)]


def dns_risponde(attesa=1.5):
    """True se Blocky risponde a una domanda DNS vera (qualunque risposta va bene, anche «non esiste»)."""
    q = b"\x4f\x21\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x08filtreo-g\x07invalid\x00" + b"\x00\x01\x00\x01"
    for h, porta in _indirizzi_dns():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(attesa)
        try:
            s.sendto(q, (h, porta))
            r, _a = s.recvfrom(1024)
            if len(r) >= 12 and r[:2] == q[:2]:
                return True
        except OSError:
            pass
        finally:
            s.close()
    return False


def _rss_motore():
    try:
        pid = int(open(PID_BLOCKY).read().strip())
        for r in open("/proc/%d/status" % pid):
            if r.startswith("VmRSS:"):
                return int(r.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _guardia_registra(evento, giu=0.0):
    rec = {"ora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "evento": evento, "giu_s": round(giu, 1), "rss_mb": _rss_motore(),
           "minima": _g["minima"]}
    _g["ultimo"] = "%s %s" % (rec["ora"][11:16], evento)
    print("Filtreo guardia: %s (giù da %.0f s)" % (evento, giu), flush=True)
    try:
        os.makedirs(os.path.dirname(GUARDIA_LOG), exist_ok=True)
        if os.path.exists(GUARDIA_LOG) and os.path.getsize(GUARDIA_LOG) > 200000:
            righe = open(GUARDIA_LOG, encoding="utf-8").readlines()[-100:]
            open(GUARDIA_LOG, "w", encoding="utf-8").writelines(righe)
        with open(GUARDIA_LOG, "a", encoding="utf-8") as h:
            h.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _guardia_avvisa(testo):
    if time.time() - _g["avviso"] > 600:
        _g["avviso"] = time.time()
        threading.Thread(target=avvisa, args=("Filtreo: " + testo,), daemon=True).start()


def _scrivi_config_minima():
    t = CONFIG_MINIMA.replace("__DNS__", _dns_ascolto()).replace("__MOTORE__", str(filtro.MOTORE))
    tmp = CONFIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        h.write(t)
    os.replace(tmp, CONFIG)


def _passo_guardia():
    """un controllo. Ritorna True se il motore risponde."""
    ok = motore_pronto(2) and dns_risponde()
    adesso = time.time()
    if ok:
        if _g["giu_da"]:
            _guardia_registra("Filtro di nuovo disponibile", adesso - _g["giu_da"])
        _g.update(giu_da=0.0, passo=0)
        if _g["minima"] and adesso - _g["minima_da"] > 600:   # emergenza: ogni 10 minuti riprovo con la configurazione vera
            _g.update(minima=False)
            _guardia_registra("Nuovo tentativo con la configurazione completa")
            scrivi_config()
            appl.inizia("riavvio", "ritorno alla configurazione vera")
            riavvia_motore("ritorno alla configurazione vera")
        return True
    if _riavvio_in_corso["fino"] > adesso:   # riavvio voluto in corso: ha già i suoi tempi
        return False
    if not _g["giu_da"]:
        _g["giu_da"] = adesso
    giu = adesso - _g["giu_da"]
    if giu > GUARDIA_SOGLIA and _g["passo"] == 0:
        _g.update(passo=1, riavvii=_g["riavvii"] + 1)
        _guardia_registra("Filtro non disponibile: riavvio in corso", giu)
        _guardia_avvisa("Filtro non disponibile da %d secondi: riavviato." % giu)
        riavvia_motore("guardia", forza=True)
    elif giu > GUARDIA_SOGLIA + 20 and _g["passo"] == 1:
        _g.update(passo=2, minima=True, minima_da=adesso)
        _guardia_registra("Filtro ancora non disponibile: configurazione minima (senza filtri)", giu)
        _guardia_avvisa("Impossibile riavviare il filtro: attiva la configurazione minima (connessione attiva, senza blocchi). Nuovo tentativo tra 10 minuti.")
        _scrivi_config_minima()
        riavvia_motore("Controllo: configurazione minima", forza=True)
    return False


def _giro_guardia():
    time.sleep(40)   # lascia finire l'avvio
    while True:
        time.sleep(2)
        try:
            _passo_guardia()
        except Exception as e:  # la guardia non deve mai morire
            print("Filtreo guardia: %s" % str(e)[:120], flush=True)


def stato_guardia():
    return {"attiva": GUARDIA_ATTIVA, "riavvii": _g["riavvii"], "minima": _g["minima"], "ultimo": _g["ultimo"], "memoria_mb": _rss_motore()}


# ───────────── azioni del pannello ─────────────
def aggiungi(url):
    url = (url or "").strip()
    if not re.match(r"^https?://[^\s/]+\.[^\s]+$", url):
        return False, "Incolla il link completo della lista (comincia con https://)."
    if any(f["url"] == url for f in fonti()):
        return True, "Filtro già importato."
    f = {"url": url, "attiva": True, "dispositivi": gruppi()}
    if not _aggiorna(f):  # il download avviene FUORI dal blocco: il pannello resta libero
        return False, "Non importato: %s." % f.get("errore", "errore")
    with _blocco:
        ff = fonti()
        if any(x["url"] == url for x in ff):
            return True, "Filtro già importato."
        f["dispositivi"] = [g for g in f["dispositivi"] if g in set(gruppi())] or [PRINCIPALE]
        ff.append(f)
        _salva(FONTI_JSON, ff)
        _prepara_modalita()
        for m in modalita.elenco():   # una lista nuova vale in tutte le modalità (si toglie da «Modalità»)
            modalita.salva_modo({"id": m["id"], "nome": m["nome"], "fonti": m.get("fonti", []) + [url]},
                                [x["url"] for x in ff], {x["id"] for x in dispositivi()})
        _applica()
    return True, "Importato «%s»: %s domini. Attivo entro 2 minuti su tutti i dispositivi. Ambito modificabile con «Gestisci»." % (
        f["nome"], format(f["domini"], ",d").replace(",", "."))


def imposta(url, attiva, categoria=None):
    with _blocco:
        ff = fonti()
        trovate = [f for f in ff if f["url"] == url]
        if not trovate:
            return False, "Filtro non trovato. Ricarica la pagina e riprova."
        for f in trovate:  # anche eventuali doppioni dello stesso link
            if attiva is not None:
                f["attiva"] = bool(attiva)
            if categoria in {c[0] for c in modalita.CATEGORIE}:
                f["categoria"] = categoria
        _salva(FONTI_JSON, ff)
        _applica()
    if attiva is None:
        return True, "Salvato"
    return True, ("Filtro %s. Effetto entro 2 minuti." % ("attivato" if attiva else "disattivato"))


def imposta_molte(attiva, categoria=None):
    """«Attiva tutti» / «Disattiva tutti»: tutte le liste (o solo quelle di una categoria) in un colpo solo, con UNA sola applicazione
    (non una per lista). Le liste per marca dei profili pronti («dormienti») le gestiscono i profili: qui non si toccano."""
    cat_note = {c[0] for c in modalita.CATEGORIE}
    with _blocco:
        ff = fonti()
        scelte = [f for f in ff if not f.get("casa") and (
            not categoria or (modalita.categoria(f) == categoria if categoria != "__" else modalita.categoria(f) not in cat_note))]
        if not scelte:
            return False, "Nessun filtro da modificare."
        cambiate = 0
        for f in scelte:
            if bool(f.get("attiva")) != bool(attiva):
                f["attiva"] = bool(attiva)
                cambiate += 1
        if cambiate:
            _salva(FONTI_JSON, ff)
            _applica()   # una volta sola, qualunque sia il numero di liste
    if not cambiate:
        return True, "Tutti già %s." % ("attivi" if attiva else "disattivati")
    return True, "%s %d %s. Si applicano tutte insieme." % ("Attivi" if attiva else "Disattivati", cambiate, "lista" if cambiate == 1 else "liste")


def aggiungi_consigliata(cat):
    url = modalita.CONSIGLIATE.get(cat)
    if not url:
        return False, "Nessun filtro consigliato per questa categoria. Aggiungi un indirizzo."
    ok, t = aggiungi(url)
    if ok:
        imposta(url, None, cat)
    return ok, t


def togli(url):
    with _blocco:
        ff = fonti()
        rest = [f for f in ff if f["url"] != url]
        if len(rest) == len(ff):
            return True, "Filtro non trovato."
        _salva(FONTI_JSON, rest)
        for coda in ("", ".ecc2", ".ecc"):
            try:
                os.remove(_file(url) + coda)
            except OSError:
                pass
        _applica()
    return True, "Filtro rimosso da tutti i dispositivi."


def _nuovo_id(dd):
    n = 1
    ids = {x["id"] for x in dd}
    while "d-%d" % n in ids:
        n += 1
    return "d-%d" % n


# ───────────── che cosa è un dispositivo (dal campo «tipo», altrimenti dal nome) ─────────────
_RE_SERVER = re.compile(r"server|\bnas\b|ollama|\bgpu\b|workstation|proxmox|docker|ubuntu|debian|linux|synology|qnap|truenas|unraid|\bvps\b|homelab|\bllm\b", re.I)
_RE_TV = re.compile(r"\btv\b|televis|smart ?tv|chromecast|fire ?(?:tv|stick)|apple ?tv|roku|\bshield\b|webos|tizen|bravia|soundbar|\bcass[ae]\b|speaker|\becho\b|alexa|homepod|sonos|google ?home|nest ?(?:hub|mini|audio)|decoder|sky ?q|console|playstation|\bps[345]\b|xbox|nintendo|\bswitch\b", re.I)
_RE_IOT = re.compile(r"telecamer|camera|\bcam\b|webcam|sensor|\bpres[ae]\b|\bplug\b|shelly|sonoff|tuya|\bhue\b|zigbee|z-?wave|matter|termostat|thermostat|lampad|\blamp|\bluce\b|\bluci\b|serratur|citofon|doorbell|\bring\b|ezviz|reolink|hikvision|\btapo\b|yeelight|robot|aspirapolvere|roomba|roborock|stampante|printer|\besp\d*|tasmota|wled|meross|switchbot|eufy|arlo|wyze|blink|\bnest\b|\biot\b", re.I)
_RE_ANDROID = re.compile(r"android|pixel|galaxy|samsung|xiaomi|redmi|poco|\bmi ?\d|oneplus|huawei|honor|oppo|motorola|\bmoto\b|nokia", re.I)
GENERI = ("nodo", "android", "altro", "tv", "iot", "server")
_QUALE = {"tv": "una TV o una cassa intelligente", "iot": "una telecamera, un sensore o un dispositivo di casa intelligente", "server": "un server"}


def genere(x):
    """che cosa è il dispositivo: «nodo» (Casa stessa), «server», «tv», «iot», «android» o «altro».
    Vale il campo «tipo» se c'è, altrimenti il nome."""
    t = (x.get("tipo") or "").lower()
    if t in GENERI:
        return t
    nome = x.get("nome") or ""
    for g, rx in (("nodo", RE_NODO), ("server", _RE_SERVER), ("tv", _RE_TV), ("iot", _RE_IOT), ("android", _RE_ANDROID)):
        if rx.search(nome):
            return g
    return "altro"


def proposta(x):
    """il profilo pronto adatto a un dispositivo (TV → «TV e casse», …), o None. Il nome è quello attuale del profilo
    (l'utente può averlo rinominato); niente proposta se il dispositivo lo usa già."""
    g = genere(x)
    mid = modalita.GENERE_PRE.get(g)
    m = modalita.trova(mid) if mid else None
    if not m or (x.get("proprie") and x.get("modo") == mid):
        return None
    return {"genere": g, "modo": mid, "nome": m["nome"],
            "testo": ("Tipo rilevato: TV. Applicare «%s»?" % m["nome"]) if g == "tv" else ("Tipo rilevato: %s. Applicare «%s»?" % (_QUALE[g], m["nome"]))}


def accetta_proposta(did):
    """«Sì, usa …»: dà al dispositivo le regole sue (se seguiva il principale) e gli mette il profilo proposto."""
    x = next((y for y in dispositivi() if y["id"] == did), None)
    if not x:
        return False, "Dispositivo non trovato."
    pr = proposta(x)
    if not pr:
        return False, "Nessuna proposta per questo dispositivo."
    if not x.get("proprie"):
        ok, t = modifica_disp(did, proprie=True)
        if not ok:
            return ok, t
    return imposta_modo(did, pr["modo"])


def registra(ip, nome, proprie, modo=None):
    """un dispositivo nuovo: segue il principale oppure liste sue (= riavvio breve del motore).
    modo = profilo scelto (solo con liste sue), per esempio quello proposto dal pannello."""
    ip = (ip or "").strip()
    if not ip or IGNORA_IP.match(ip):
        return False, "Dispositivo non valido."
    with _blocco:
        dd = dispositivi()
        if any(x.get("ip") == ip or ip in (x.get("ips") or []) for x in dd):
            return True, "Già registrato."
        if ip in nodo_ips():
            return False, "Questo dispositivo è Casa: non si aggiunge all’elenco."
        nuovo = {"id": _nuovo_id(dd), "nome": (nome or ip)[:40], "ip": ip, "proprie": bool(proprie)}
        if nuovo["proprie"]:
            nuovo["modo"] = next((y.get("modo") for y in dd if y.get("principale")), "") or ""
            if modo and modalita.trova(modo) and modo not in (modalita.SPENTO, modalita.PAUSA):
                nuovo["modo"] = modo
        dd.append(nuovo)
        _salva(DISP_JSON, dd)
        if nuovo["proprie"]:
            # parte con le stesse liste del principale
            ff = fonti()
            for f in ff:
                if PRINCIPALE in f.get("dispositivi", [PRINCIPALE]) and nuovo["id"] not in f.get("dispositivi", []):
                    f["dispositivi"] = f.get("dispositivi", [PRINCIPALE]) + [nuovo["id"]]
            _salva(FONTI_JSON, ff)
        _assegna_casa()   # le liste per marca vanno solo a chi ha un profilo che le usa
        sue = modo_di(nuovo["id"]).get("fonti", []) if nuovo["proprie"] else []
        servono = any(f.get("casa") and f["url"] in sue and not _scaricata(f["url"]) for f in fonti())
        cambiata = scrivi_config()
        if not servono:
            _applica(config_cambiata=cambiata)
    if nuovo["proprie"] and servono:   # liste da scaricare: rispondo subito, il resto (riavvio compreso) va in sottofondo
        threading.Thread(target=_applica, kwargs={"config_cambiata": cambiata}, daemon=True).start()
        return True, "«%s» ha filtri propri: preparazione dei filtri per marca in corso… Il filtro si aggiorna automaticamente." % nuovo["nome"]
    if nuovo["proprie"]:
        return True, "«%s» ha filtri propri (per ora quelli del %s). Filtro riavviato." % (nuovo["nome"], _nome_principale())
    return True, "«%s» segue le regole del %s." % (nuovo["nome"], _nome_principale())


def registra_profilo(nome, tipo="altro"):
    """un telefono che usa il profilo (DNS cifrato) e non ha un indirizzo di casa da riconoscere: lo registro senza indirizzo,
    segue il principale. Se un dispositivo con quel nome c'è già, lo riuso. Ritorna (ok, id del dispositivo)."""
    nome = re.sub(r"\s+", " ", (nome or "").strip())[:40]
    if not nome:
        return False, "Inserisci un nome per il dispositivo."
    with _blocco:
        dd = dispositivi()
        x = next((y for y in dd if (y.get("nome") or "").strip().lower() == nome.lower()), None)
        if x:
            return True, x["id"]
        x = {"id": _nuovo_id(dd), "nome": nome, "ip": "", "proprie": False, "tipo": tipo}
        dd.append(x)
        _salva(DISP_JSON, dd)
    return True, x["id"]


def modifica_disp(did, nome=None, proprie=None, ips=None, proprietario=None):
    with _blocco:
        dd = dispositivi()
        x = next((y for y in dd if y["id"] == did), None)
        if not x:
            return False, "Dispositivo non trovato."
        if nome is not None and nome.strip():
            x["nome"] = nome.strip()[:40]
        if proprietario is not None:   # «proprietario»: può mettere in pausa tutta la Rete (vedi imposta_proprietario)
            if proprietario:
                x["proprietario"] = True
            else:
                x.pop("proprietario", None)
        config = False
        if proprie is not None and not x.get("principale") and bool(proprie) != bool(x.get("proprie")):
            x["proprie"] = bool(proprie)
            if x["proprie"]:   # parte con la modalità del principale
                x["modo"] = next((y.get("modo") for y in dd if y.get("principale")), "") or x.get("modo", "")
            config = True
        if ips is not None:
            nuovi = [i.strip() for i in ips if re.fullmatch(r"[0-9a-fA-F:.]{3,45}", i.strip())][:6]
            if nuovi != list(x.get("ips") or []):
                x["ips"] = nuovi
                config = True
        _salva(DISP_JSON, dd)
        if config:
            _assegna_casa()
        cambiata = scrivi_config() if config else False
        if config:
            _applica(config_cambiata=cambiata)
    return True, "Salvato" + (" Il filtro si riavvia per alcuni secondi." if cambiata else "")


def imposta_modo(did, mid, da_orario=False, pausa=None):
    """cambia la modalità di un dispositivo con regole sue. Niente riavvio: si riscrivono le sue
    liste e si ricaricano (pochi secondi). Vale a casa e fuori casa.
    pausa = {fino, inizio, da, durata} (solo con mid == «spento»): è la pausa del dispositivo (vedi pausa_dispositivo):
    «Senza filtro» con la SUA scadenza (fino = secondi epoch, 0 = senza scadenza) invece dei TORNA_DOPO minuti.
    Qualsiasi altro cambio di modalità chiude la pausa."""
    m = modalita.trova(mid)
    if not m:
        return False, "Livello non valido."
    solo_scadenza = False
    with _blocco:
        dd = dispositivi()
        x = next((y for y in dd if y["id"] == did), None)
        if not x:
            return False, "Dispositivo non trovato."
        if not x.get("proprie"):
            return False, "«%s» segue le regole del %s: attiva «Profilo proprio» per assegnare un livello." % (x["nome"], _nome_principale())
        if x.get("modo") == mid:
            if mid == modalita.SPENTO and pausa is not None:   # già senza filtro: cambia solo la scadenza, i file delle liste sono già giusti
                x["pausa"] = pausa
                if pausa.get("fino"):
                    x["spento_fino"] = pausa["fino"]
                else:
                    x.pop("spento_fino", None)
                _salva(DISP_JSON, dd)
                solo_scadenza = True
            else:
                return True, "«%s» è già in «%s»." % (x["nome"], m["nome"])
        else:
            if mid == modalita.SPENTO:
                if x.get("modo") not in (modalita.SPENTO, modalita.PAUSA):
                    x["modo_prima"] = x.get("modo") or ""
                if pausa is not None:
                    x["pausa"] = pausa
                    if pausa.get("fino"):
                        x["spento_fino"] = pausa["fino"]
                    else:
                        x.pop("spento_fino", None)
                else:
                    x.pop("pausa", None)
                    x["spento_fino"] = time.time() + modalita.TORNA_DOPO * 60
            elif mid == modalita.PAUSA:
                if x.get("modo") not in (modalita.SPENTO, modalita.PAUSA):
                    x["modo_prima"] = x.get("modo") or ""
                x.pop("spento_fino", None)
                x.pop("pausa", None)
            else:
                x.pop("spento_fino", None)
                x.pop("modo_prima", None)
                x.pop("pausa", None)
            x["modo"] = mid
            _salva(DISP_JSON, dd)
            _assegna_casa()
            cambiata = scrivi_config()   # «Isolato» toglie il gruppo «manuale» al dispositivo: la config cambia solo se serve
            _applica(config_cambiata=cambiata, motivo="pausa del dispositivo" if pausa is not None else "cambio di livello")
    sincronizza_paracadute()   # anche fuori casa senza Tailscale (paracadute su Cloudflare), entro ~1 minuto
    if solo_scadenza:
        return True, "«%s»: scadenza aggiornata." % x["nome"]
    if mid == modalita.SPENTO:
        if pausa is not None:
            return True, "«%s» in pausa." % x["nome"]
        return True, "«%s» senza filtro per %d minuti. Ripristino automatico." % (x["nome"], modalita.TORNA_DOPO)
    if mid == modalita.PAUSA:
        return True, "«%s» · Blocco connessione attivo" % x["nome"]
    if any(f.get("casa") and f["url"] in fonti_di(m) and not _scaricata(f["url"]) for f in fonti()):
        return True, "«%s» è in «%s»: preparazione dei filtri in corso (alcuni minuti)." % (x["nome"], m["nome"])
    return True, "«%s» è in «%s»: attivo entro pochi secondi, su qualsiasi rete." % (x["nome"], m["nome"])


# ───────────── pausa per dispositivo e «proprietario» ─────────────
# La pausa di un dispositivo è «Senza filtro» (modalità interna «spento») con la SUA scadenza, salvata nel file dei dispositivi
# (dispositivi.json → campo «pausa»: {fino, inizio, da, durata}; fino = secondi epoch, 0 = senza scadenza). Niente timer in memoria:
# ogni 2 secondi un giro legge il file e riporta il dispositivo alla modalità di prima appena la scadenza passa (anche subito
# all'avvio, se il pannello era spento alla scadenza). Cambia solo il gruppo del dispositivo (riscrittura + ricarica delle liste,
# come ogni cambio di modalità): il motore non si riavvia e gli altri dispositivi non vedono niente.
# Un dispositivo che «segue il principale» non ha un gruppo suo: a Casa non si può isolare senza riavviare il motore, quindi la
# pausa si accetta solo se ha un DNS personale (fuori casa / Cloud), dove ogni codice ha il suo profilo.
DURATE_PAUSA = ("30s", "10m", "1h", "domani", "senza")
SEC_PAUSA = {"30s": 30, "10m": 600, "1h": 3600}
MAX_PROLUNGA_MIN = 1440


def cerca_disp(rif, dd=None):
    """un dispositivo per id, nome (senza maiuscole) o indirizzo."""
    r = str(rif or "").strip()
    if not r:
        return None
    dd = dispositivi() if dd is None else dd
    x = next((y for y in dd if y.get("id") == r), None)
    if x:
        return x
    x = next((y for y in dd if (y.get("nome") or "").strip().lower() == r.lower()), None)
    if x:
        return x
    return next((y for y in dd if r in [y.get("ip")] + list(y.get("ips") or [])), None)


def _ha_dns_personale(did):
    try:
        import dns_personale as dnsp
        return any(v.get("disp") == did for _n, v in dnsp.voci())
    except Exception:
        return False


def pausa_attiva_di(x, ora=None):
    """la pausa del dispositivo se vale ancora, altrimenti None."""
    p = x.get("pausa") if isinstance(x, dict) else None
    if not isinstance(p, dict):
        return None
    try:
        fino = float(p.get("fino") or 0)
    except (TypeError, ValueError):
        return None
    return p if (fino == 0 or fino > (time.time() if ora is None else ora)) else None


def pause_dispositivi(ora=None):
    """[{id, nome, fino (epoch s o None), senza, da, inizio, durata, casa, cloud}] di chi è in pausa adesso."""
    ora = time.time() if ora is None else ora
    out = []
    for x in dispositivi():
        p = pausa_attiva_di(x, ora)
        if not p:
            continue
        fino = float(p.get("fino") or 0)
        out.append({"id": x["id"], "nome": x.get("nome", ""), "fino": fino or None, "senza": fino == 0, "da": p.get("da", ""),
                    "inizio": p.get("inizio"), "durata": p.get("durata", ""), "casa": bool(x.get("proprie")), "cloud": _ha_dns_personale(x["id"])})
    return out


def pausa_dispositivo(rif, durata, da="", ora=None):
    """mette in pausa un dispositivo. Ritorna (ok, testo, codice HTTP, codice errore)."""
    ora = time.time() if ora is None else ora
    if durata not in DURATE_PAUSA:
        return False, "Durata non valida.", 400, "durata_non_valida"
    sec = 0 if durata == "senza" else (max(1, int(filtro.fine_domani(ora) - ora)) if durata == "domani" else SEC_PAUSA[durata])
    with _blocco:
        x = cerca_disp(rif)
        if not x:
            return False, "Dispositivo non trovato.", 404, "dispositivo_non_trovato"
        did, proprie = x["id"], bool(x.get("proprie"))
        if not proprie and not _ha_dns_personale(did):
            return False, "«%s» segue le regole del %s e non ha un DNS personale: a Casa non si può mettere in pausa da solo. Attiva «Profilo proprio»." % (x.get("nome"), _nome_principale()), 409, "dispositivo_non_filtrabile"
        pz = {"fino": round(ora + sec, 3) if sec else 0, "inizio": round(ora, 3), "da": str(da or "")[:40], "durata": durata}
        nome = x.get("nome", "")
    if proprie:
        ok, t = imposta_modo(did, modalita.SPENTO, pausa=pz)
        if not ok:
            return False, t, 409, "pausa_non_applicata"
    else:
        with _blocco:
            dd = dispositivi()
            y = next((z for z in dd if z["id"] == did), None)
            if not y:
                return False, "Dispositivo non trovato.", 404, "dispositivo_non_trovato"
            y["pausa"] = pz
            _salva(DISP_JSON, dd)
        sincronizza_paracadute()
    if durata == "senza":
        return True, "«%s» senza filtro fino alla ripresa." % nome, 200, None
    return True, "«%s» in pausa fino alle %s." % (nome, datetime.fromtimestamp(pz["fino"]).strftime("%H:%M")), 200, None


def prolunga_pausa_dispositivo(rif, minuti, ora=None):
    ora = time.time() if ora is None else ora
    try:
        m = int(float(str(minuti).strip().replace(",", ".")))
    except (TypeError, ValueError):
        return False, "Indica di quanti minuti prolungare.", 400, "minuti_non_validi"
    if not 1 <= m <= MAX_PROLUNGA_MIN:
        return False, "Si può prolungare da 1 a %d minuti." % MAX_PROLUNGA_MIN, 400, "minuti_non_validi"
    with _blocco:
        dd = dispositivi()
        x = cerca_disp(rif, dd)
        if not x:
            return False, "Dispositivo non trovato.", 404, "dispositivo_non_trovato"
        p = pausa_attiva_di(x, ora)
        if not p:
            return False, "«%s» non è in pausa." % x.get("nome"), 409, "non_in_pausa"
        if not float(p.get("fino") or 0):
            return False, "«%s» è già senza scadenza." % x.get("nome"), 409, "gia_senza_scadenza"
        p["fino"] = round(float(p["fino"]) + m * 60, 3)
        if x.get("proprie") and x.get("modo") == modalita.SPENTO:
            x["spento_fino"] = p["fino"]
        _salva(DISP_JSON, dd)
        nome, fino = x.get("nome", ""), p["fino"]
    sincronizza_paracadute()
    return True, "«%s» in pausa fino alle %s." % (nome, datetime.fromtimestamp(fino).strftime("%H:%M")), 200, None


def _fine_pausa(did):
    """chiude la pausa di un dispositivo: torna la modalità di prima. True se c'era qualcosa da fare."""
    with _blocco:
        dd = dispositivi()
        x = next((y for y in dd if y["id"] == did), None)
        if not x or "pausa" not in x:
            return False
        if not (x.get("proprie") and x.get("modo") == modalita.SPENTO):
            x.pop("pausa", None)   # senza gruppo suo (vale solo sul DNS personale), o già cambiato a mano
            _salva(DISP_JSON, dd)
            cloud = True
            prima = None
        else:
            cloud = False
            prima = x.get("modo_prima") or ""
            if not modalita.trova(prima) or prima in (modalita.SPENTO, modalita.PAUSA):
                mm = modalita.elenco()
                prima = mm[0]["id"] if mm else ""
    if cloud:
        sincronizza_paracadute()
        return True
    if prima:
        imposta_modo(did, prima)   # chiude anche la pausa e avvisa il paracadute
    else:
        with _blocco:
            dd = dispositivi()
            x = next((y for y in dd if y["id"] == did), None)
            if x:
                x.pop("pausa", None)
                _salva(DISP_JSON, dd)
    return True


def riprendi_dispositivo(rif):
    with _blocco:
        x = cerca_disp(rif)
        if not x:
            return False, "Dispositivo non trovato.", 404, "dispositivo_non_trovato"
        did, nome, presente = x["id"], x.get("nome", ""), "pausa" in x
    if not presente:
        return True, "«%s» non era in pausa." % nome, 200, None
    _fine_pausa(did)
    return True, "«%s» è di nuovo protetto." % nome, 200, None


def _giro_pause():
    """ogni 2 secondi: le pause dei dispositivi scadute finiscono (anche quelle scadute mentre il pannello era spento)."""
    while True:
        try:
            ora = time.time()
            for x in dispositivi():
                p = x.get("pausa")
                if p is None:
                    continue
                if not isinstance(p, dict) or pausa_attiva_di(x, ora) is None:
                    _fine_pausa(x["id"])
        except Exception as e:   # il giro non deve mai fermarsi
            print("Filtreo: giro delle pause: %s" % str(e)[:150], flush=True)
        time.sleep(2)


def imposta_proprietario(rif, valore):
    """marca (o smarca) un dispositivo come «proprietario»: solo da lì si può mettere in pausa tutta la Rete.
    Finché nessuno è marcato la Rete si può mettere in pausa da ovunque (com'era prima)."""
    with _blocco:
        dd = dispositivi()
        x = cerca_disp(rif, dd)
        if not x:
            return False, "Dispositivo non trovato.", 404, "dispositivo_non_trovato"
        if bool(valore):
            x["proprietario"] = True
        else:
            x.pop("proprietario", None)
        _salva(DISP_JSON, dd)
        return True, "«%s» %s." % (x.get("nome"), "è proprietario" if valore else "non è più proprietario"), 200, None


def proprietari(dd=None):
    return [x for x in (dispositivi() if dd is None else dd) if x.get("proprietario")]


def usano(mid):
    return [x["nome"] for x in dispositivi() if x.get("proprie") and mid in (x.get("modo"), x.get("modo_prima"))]


def salva_modalita(dati):
    ok, t, mid = modalita.salva_modo(dati, [f["url"] for f in fonti()], {x["id"] for x in dispositivi()})
    if ok:
        with _blocco:
            _assegna_casa()
        _applica(config_cambiata=scrivi_config())
        sincronizza_paracadute()   # una modalità può diventare (o smettere di essere) «di lavoro»
    return ok, t, mid


def togli_modalita(mid):
    return modalita.togli_modo(mid, usano(mid))


# ───────────── 3.1: livello come punto di partenza e gruppi di categorie (logica in livelli.py) ─────────────
def modo_principale():
    """l'id della modalità del dispositivo principale (quella che seguono tutti quelli senza liste proprie)."""
    pr = next((x for x in dispositivi() if x.get("principale")), {"id": PRINCIPALE})
    return modo_di(pr["id"]).get("id", "")


def _dopo_cambio_modalita(motivo):
    """come dopo «Salva» di una modalità: liste per marca a chi le usa, liste riscritte e ricaricate, paracadute avvisato."""
    with _blocco:
        _assegna_casa()
    _applica(config_cambiata=scrivi_config(), motivo=motivo)
    sincronizza_paracadute()


def livello_torna(mid, livello=None):
    ok, t = livelli.torna(mid or modo_principale(), livello)
    if ok:
        _dopo_cambio_modalita("torna al livello")
    return ok, t


def gruppi_di(mid=None):
    mid = mid or modo_principale()
    m = modalita.trova(mid)
    if not m or m.get("fissa"):
        return None
    return livelli.stato_gruppi(m, fonti_di(m), fonti())


def gruppo_imposta(mid, gid, attiva):
    ok, t = livelli.imposta_gruppo(mid or modo_principale(), gid, attiva)
    if ok:
        _dopo_cambio_modalita("gruppo %s" % gid)
    return ok, t


def riga_imposta(mid, url, attiva):
    ok, t = livelli.imposta_riga(mid or modo_principale(), url, attiva)
    if ok:
        _dopo_cambio_modalita("filtro del livello")
    return ok, t


def famiglia_stato(mid):
    """«Protezione famiglia» di una modalità: acceso o spento e le liste che entrano in gioco (con il loro stato di scarico)."""
    m = modalita.trova(mid)
    if not m or m.get("fissa"):
        return None
    liste_fam = [f for f in fonti() if modalita.categoria(f) in modalita.CAT_PROTEZIONE]
    return {"id": m["id"], "nome": m["nome"], "famiglia": bool(m.get("famiglia")),
            "categorie": [c[1] for c in modalita.CATEGORIE if c[0] in modalita.CAT_PROTEZIONE],
            "liste": [{"nome": f.get("nome", ""), "categoria": modalita.categoria(f), "attiva": f.get("attiva", True),
                       "scaricata": _scaricata(f["url"]), "domini": f.get("domini", 0)} for f in liste_fam],
            "ricerca_sicura": False}   # NON è un'impostazione: Blocky non sa farla per dispositivo (vedi PIANO.md)


def imposta_famiglia(mid, attiva):
    """accende/spegne «Protezione famiglia» su una modalità: stesse liste per tutti i dispositivi che la usano, senza riavvio
    (si riscrivono le liste e si ricaricano). Vale a casa e, con il paracadute, fuori casa."""
    ok, t, cambiata = modalita.imposta_famiglia(mid, attiva)
    if not ok or not cambiata:
        return ok, t
    with _blocco:
        _assegna_casa()
    _applica(config_cambiata=scrivi_config(), motivo="protezione famiglia")
    sincronizza_paracadute()
    m = modalita.trova(mid) or {}
    if attiva and any(f.get("casa") and f["url"] in fonti_di(m) and not _scaricata(f["url"]) for f in fonti()):
        return True, t + " Preparazione delle liste in corso (alcuni minuti)."
    return True, t + " Attiva entro pochi secondi."


def _giro_orologio():
    """ogni minuto: «Senza filtro» scaduto torna com'era, e gli orari automatici delle modalità.
    (ogni cambio passa da imposta_modo, che avvisa anche il paracadute; in più ogni 10 minuti un controllo
    di sicurezza: scrive su Cloudflare solo se qualcosa è davvero cambiato)."""
    giri = 0
    while True:
        time.sleep(60)
        giri += 1
        if giri % 10 == 0:
            sincronizza_paracadute()
        for fn in list(giri_extra):
            try:
                fn()
            except Exception as e:  # un controllo che sbaglia non ferma l'orologio
                print("Filtreo (giro extra): %s" % type(e).__name__, flush=True)
        try:
            for x in dispositivi():
                if modalita.scaduto(x):
                    prima = x.get("modo_prima") or ""
                    if not modalita.trova(prima):
                        mm = modalita.elenco()
                        prima = mm[0]["id"] if mm else ""
                    if prima:
                        ok, t = imposta_modo(x["id"], prima)
                        avvisa("Filtreo: %s" % t)
            for did, mid in modalita.decisioni_nanna():
                if not mid:
                    mid = next((y.get("modo_prima") for y in dispositivi() if y["id"] == did), "") or ""
                if mid:
                    ok, t = imposta_modo(did, mid, da_orario=True)
                    print("Filtreo (a nanna): %s" % t, flush=True)
            for did, mid in modalita.decisioni_automatiche():
                ok, t = imposta_modo(did, mid, da_orario=True)
                if ok:
                    print("Filtreo (orario): %s" % t, flush=True)
        except Exception as e:  # l'orologio non deve mai fermarsi
            print("Filtreo: orologio modalità: %s" % str(e)[:150], flush=True)


# ───────────── paracadute (Cloudflare): le modalità seguono da sole, senza nuovo deploy ─────────────
# Dopo ogni cambio di modalità lancia paracadute-sync.py (in un thread, mai bloccante, mai un errore per il pannello):
# ricalcola «impronta del codice → profilo» e, se è cambiato, lo scrive nel KV di Cloudflare. Se manca il file dei
# segreti (token di Cloudflare) non fa niente.
_para = {"lucchetto": threading.Lock(), "ancora": False}


def _para_script():
    qui = os.path.dirname(os.path.abspath(__file__))
    for p in (os.environ.get("FILTREO_PARACADUTE_SYNC", ""), os.path.join(qui, "..", "jetson", "paracadute-sync.py"),
              os.path.join(qui, "paracadute-sync.py")):
        if p and os.path.isfile(p):
            return os.path.abspath(p)
    return ""


def _para_segreti():
    for p in (os.environ.get("FILTREO_SEGRETI_CF", ""), "/segreti/cloudflare.env",
              os.path.expanduser("~/filtreo15/segreti/cloudflare.env")):
        if p and os.path.isfile(p):
            return p
    return ""


def sincronizza_paracadute():
    """True se è partito un aggiornamento del paracadute (in sottofondo)."""
    try:
        s, seg = _para_script(), _para_segreti()
        if not s or not seg:
            return False
        threading.Thread(target=_giro_paracadute, args=(s, seg), daemon=True).start()
        return True
    except Exception:  # il pannello non deve mai accorgersene
        return False


def _giro_paracadute(s, seg):
    if not _para["lucchetto"].acquire(blocking=False):
        _para["ancora"] = True   # ne sta già girando uno: rifà un giro appena finisce
        return
    try:
        while True:
            _para["ancora"] = False
            try:
                r = subprocess.run([sys.executable, s, "--data", DATA, "--segreti", seg],
                                   capture_output=True, text=True, timeout=60)
                riga = ((r.stdout or "").strip().splitlines() or [""])[-1]
                if r.returncode or "✓" in riga:
                    print("Filtreo: %s" % riga[:200], flush=True)
            except Exception as e:
                print("Filtreo: paracadute non aggiornato (%s)" % type(e).__name__, flush=True)
            if not _para["ancora"]:
                break
    except Exception:
        pass
    finally:
        _para["lucchetto"].release()
    if _para["ancora"]:   # chiesto proprio mentre finivo: un altro giro
        _giro_paracadute(s, seg)


# ───────────── pausa anche su Cloudflare ─────────────
# Quando la pausa (o lo «Spento») comincia o finisce, una sola chiamata a paracadute-sync.py --solo-pausa scrive nel KV
# la scadenza (chiave «pausa»): il worker la legge al massimo ogni ~30 s. Mai più di una scrittura per cambio (lo script
# confronta con quello che ha già scritto). Se il token o lo script mancano non succede niente: la pausa resta solo su Casa.
_para_pausa = {"lucchetto": threading.Lock(), "ancora": False}


def sincronizza_pausa():
    """True se è partita la scrittura (in sottofondo). Mai un errore per il pannello."""
    try:
        s, seg = _para_script(), _para_segreti()
        if not s or not seg:
            return False
        threading.Thread(target=_giro_pausa, args=(s, seg), daemon=True).start()
        return True
    except Exception:
        return False


def _giro_pausa(s, seg):
    if not _para_pausa["lucchetto"].acquire(blocking=False):
        _para_pausa["ancora"] = True   # un'altra scrittura sta girando: ne rifà una appena finisce (leggerà lo stato più recente)
        return
    ancora = False
    try:
        while True:
            _para_pausa["ancora"] = False
            try:
                r = subprocess.run([sys.executable, s, "--solo-pausa", "--data", DATA, "--segreti", seg],
                                   capture_output=True, text=True, timeout=60)
                riga = ((r.stdout or "").strip().splitlines() or [""])[-1]
                if r.returncode or "✓" in riga:
                    print("Filtreo: %s" % riga[:200], flush=True)
            except Exception as e:
                print("Filtreo: pausa non copiata su Cloudflare (%s)" % type(e).__name__, flush=True)
            if not _para_pausa["ancora"]:
                break
    except Exception:
        pass
    finally:
        _para_pausa["lucchetto"].release()
        ancora = _para_pausa["ancora"]
    if ancora:
        _giro_pausa(s, seg)


def dimentica(did):
    with _blocco:
        dd = dispositivi()
        x = next((y for y in dd if y["id"] == did), None)
        if not x or x.get("principale"):
            return False, "Elemento non rimovibile."
        dd = [y for y in dd if y["id"] != did]
        _salva(DISP_JSON, dd)
        ff = fonti()
        for f in ff:
            f["dispositivi"] = [g for g in f.get("dispositivi", []) if g != did]
        _salva(FONTI_JSON, ff)
        _assegna_casa()
        for suf in ("", "-vecchie", "-vecchie-ok"):
            try:
                os.remove(os.path.join(LISTE, "dev-%s%s.txt" % (did, suf)))
            except OSError:
                pass
        cambiata = scrivi_config()
        _applica(config_cambiata=cambiata)
    return True, "Rimosso. Se si ricollega, ricompare tra i nuovi."


def _nome_principale():
    return next((x["nome"] for x in dispositivi() if x.get("principale")), "Mac")


def visti(giorni=3):
    """dispositivi che hanno usato il filtro negli ultimi giorni: ip -> (nome, ultima ora, richieste)."""
    out = {}
    for i in range(giorni):
        f = os.path.join(filtro.REGISTRO, "%s_ALL.log" % (date.today() - timedelta(days=i)).isoformat())
        try:
            righe = open(f, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        for r in righe:
            sep = "\t" if "\t" in r else ","
            c = [x.strip().strip('"') for x in r.split(sep)]
            if len(c) < 3 or not c[1] or IGNORA_IP.match(c[1]):
                continue
            ip = c[1]
            nome = c[2] if c[2] and not re.match(r"^(RESOLVED|CACHED|BLOCKED)", c[2]) else ""
            v = out.setdefault(ip, [nome, c[0][:16], 0])
            v[2] += 1
            if c[0][:16] > v[1]:
                v[1] = c[0][:16]
            if nome and not v[0]:
                v[0] = nome
    return out


# telemetria che nessuna eccezione delle liste deve far passare (il filtro di prima la bloccava)
MAI_PERMESSI = {"firebaselogging.googleapis.com", "firebaselogging-pa.googleapis.com"}

SENTINELLE = {  # grandi indirizzi pubblicitari: se un dispositivo filtrato li raggiunge, qualcosa non va
    "googleads.g.doubleclick.net", "securepubads.g.doubleclick.net", "tpc.googlesyndication.com",
    "ad.doubleclick.net", "pubads.g.doubleclick.net", "ib.adnxs.com", "bidder.criteo.com",
    "aax.amazon-adsystem.com", "ads.pubmatic.com", "fastlane.rubiconproject.com", "hbopenbid.pubmatic.com",
    "an.facebook.com", "ads.yahoo.com", "adservice.google.it",
}


def sentinella(minuti=30):
    """dispositivi filtrati che negli ultimi minuti hanno RAGGIUNTO pubblicità nota: filtro scavalcato o lista sbagliata."""
    da = (datetime.now() - timedelta(minutes=minuti)).strftime("%Y-%m-%d %H:%M:%S")
    f = os.path.join(filtro.REGISTRO, "%s_ALL.log" % date.today().isoformat())
    try:
        righe = open(f, encoding="utf-8", errors="replace").read().splitlines()[-40000:]
    except OSError:
        return []
    nomi = {x.get("ip"): x.get("nome") for x in dispositivi() if x.get("ip")}
    nomi_ts = nomi_tailscale()
    sistemati = _sistemati()
    out = {}
    ultima = {}   # (ip, dominio) -> l'ultima richiesta era bloccata?
    for r in righe:
        c = [v.strip().strip('"') for v in r.split("\t" if "\t" in r else ",")]
        if len(c) < 6 or c[0][:19] < da or IGNORA_IP.match(c[1] or "0.0.0.0"):
            continue
        d = c[5].rstrip(".").lower()
        m = re.match(r"^[A-Z]+ \((.+?)\.?\)$", c[5])
        if m:
            d = m.group(1).lower()
        if d not in SENTINELLE:
            continue
        k = (c[1], d)
        bloccata = any(v.startswith("BLOCKED") for v in c[3:9])
        ultima[k] = bloccata
        if bloccata or c[0][:19] < sistemati.get(d, ""):
            continue   # bloccata, oppure passata prima di «Sistema»
        out[k] = out.get(k, 0) + 1
    # se dopo è arrivata bloccata, il problema è già risolto: niente allarme rosso
    out = {k: n for k, n in out.items() if not ultima.get(k)}
    return [{"ip": ip, "nome": nomi.get(ip) or nomi_ts.get(ip) or ip, "dominio": d, "volte": n, "perche": perche_passa(d)}
            for (ip, d), n in sorted(out.items(), key=lambda kv: -kv[1])][:10]


def _file_sistemati():
    return os.path.join(filtro.DATA, "sistemati.json")


def _sistemati():
    """dominio -> ora di «Sistema» (le richieste di prima non fanno più scattare l'allarme)."""
    try:
        v = json.load(open(_file_sistemati(), encoding="utf-8"))
        return {str(k): str(t) for k, t in v.items()} if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _segna_sistemato(d):
    v = _sistemati()
    v[d] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmp = _file_sistemati() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(v, f)
    os.replace(tmp, _file_sistemati())


def _chi_permette(d):
    """quali permessi (file tuoi o eccezioni delle liste) coprono questo dominio."""
    p = d.split(".")
    padri = {".".join(p[i:]) for i in range(len(p) - 1)}
    chi = []
    for nome in ECCEZIONI_FILE:
        for r in _righe_pulite(nome):
            x = (r[2:] if r.startswith("*.") else r).lower()
            if x in padri:
                chi.append((nome, x))
    for f in fonti():
        try:
            for x in open(_file(f["url"]) + ".ecc2", encoding="utf-8"):
                if x.strip() in padri:
                    chi.append(("filtro «%s»" % (f.get("nome") or f["url"]), x.strip()))
        except OSError:
            pass
    return chi


def perche_passa(d):
    """spiegazione in italiano semplice del perché un indirizzo pubblicitario è passato."""
    try:
        t, err = filtro._api("/api/blocking/status", attesa=3)
        st = json.loads(t) if t and not err else {}
        if isinstance(st, dict) and st.get("enabled") is False:
            return "filtro in pausa"
    except Exception:
        pass
    chi = _chi_permette(d)
    if chi:
        nomi = {"bianca.txt": "le eccezioni", "sblocca.txt": "«sblocca»", "anti-rilevamento.txt": "«Filtreo rilevato dal sito»"}
        return "consentito da %s (%s): non più valido con la versione attuale" % (nomi.get(chi[0][0], chi[0][0]), chi[0][1])
    return "consentito prima dell'ultimo aggiornamento dei filtri: ora bloccato"


def sistema(dominio):
    """«Sistema» dalla sentinella: toglie i permessi che coprono il dominio e lo blocca."""
    d = filtro._dominio(dominio)
    if not d:
        return False, "Sito non valido."
    p = d.split(".")
    padri = {".".join(p[i:]) for i in range(len(p) - 1)}
    with _scrittura:
        for nome in ECCEZIONI_FILE:
            rr = filtro._righe(nome)
            nn = [r for r in rr if (r.strip()[2:] if r.strip().startswith("*.") else r.strip()).lower() not in padri]
            if nn != rr:
                filtro._scrivi(nome, nn)
        b = filtro._righe("blocca.txt")
        if "*." + d not in [r.strip() for r in b]:
            b.append("*." + d)
            filtro._scrivi("blocca.txt", b)
    with _blocco:
        _applica()
    _segna_sistemato(d)
    return True, "%s è bloccato su tutti i dispositivi." % d


def applica_permessi():
    """dopo un blocca/sblocca/eccezione: riscrive i permessi puliti e ricarica."""
    with _blocco:
        _applica()


_MOTIVO_R = re.compile(r"^(RESOLVED|CACHED|BLOCKED|CONDITIONAL|CUSTOMDNS|HOSTSFILE|FILTERED|NOTFQDN|SPECIAL)\b")
_HOST_R = re.compile(r"^(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]{1,}\.?$", re.I)


def registro(n=300, ip="", cerca="", solo=""):
    """le ultime richieste (come il registro di AdGuard): ora, dispositivo, indirizzo, bloccata o passata e perché."""
    f = os.path.join(filtro.REGISTRO, "%s_ALL.log" % date.today().isoformat())
    if not os.path.exists(f):   # a cavallo di mezzanotte o con fuso diverso: il registro più recente
        cand = sorted(glob.glob(os.path.join(filtro.REGISTRO, "*.log")), key=os.path.getmtime)
        f = cand[-1] if cand else f
    try:
        with open(f, "rb") as h:
            h.seek(0, 2)
            dim = h.tell()
            h.seek(max(0, dim - 6 * 1024 * 1024))
            righe = h.read().decode("utf-8", "replace").splitlines()[1:]
    except OSError:
        return []
    nomi = {x.get("ip"): x.get("nome") for x in dispositivi() if x.get("ip")}
    nomi_ts = nomi_tailscale()
    cerca = (cerca or "").strip().lower()
    out = []
    for riga in reversed(righe):
        sep = "\t" if "\t" in riga else ","
        c = [x.strip().strip('"') for x in riga.split(sep)]
        if len(c) < 4 or (ip and c[1] != ip):
            continue
        r = next((k for k in range(1, len(c)) if _MOTIVO_R.match(c[k])), None)
        if r is None:
            continue
        dom = ""
        for k in range(r + 1, len(c)):   # «A (sito.it.)» oppure «sito.it»
            m = re.match(r"^[A-Z0-9]+ \((.+?)\.?\)$", c[k])
            if m:
                dom = m.group(1).lower()
                break
            if _HOST_R.match(c[k]):
                dom = c[k].rstrip(".").lower()
                break
        if not dom or (cerca and cerca not in dom):
            continue
        bloccata = c[r].startswith("BLOCKED")
        if solo == "bloccate" and not bloccata or solo == "passate" and bloccata:
            continue
        chi = nomi.get(c[1]) or nomi_ts.get(c[1]) or ("Home Assistant" if IGNORA_IP.match(c[1] or "0.0.0.0") else c[1])
        out.append({"ora": c[0][11:19], "ip": c[1], "dispositivo": chi,
                    "dominio": dom, "bloccata": bloccata, "motivo": c[r][:60],
                    "pubblicita": _pubblicita(dom) or dom in SENTINELLE})
        if len(out) >= n:
            break
    return out


def chi_chiama(ips, nomi=(), n=15):
    """i domini più richiesti da un dispositivo oggi (indirizzi di casa e nomi del suo profilo «fuori casa»),
    con quante volte sono stati bloccati: per capire cosa fa una TV o una presa.
    Ritorna {richieste, bloccate, domini: [{dominio, richieste, bloccate}]}."""
    ips, nomi = {i for i in ips if i}, {x for x in nomi if x}
    vuoto = {"richieste": 0, "bloccate": 0, "domini": []}
    if not ips and not nomi:
        return vuoto
    f = os.path.join(filtro.REGISTRO, "%s_ALL.log" % date.today().isoformat())
    if not os.path.exists(f):
        cand = sorted(glob.glob(os.path.join(filtro.REGISTRO, "*.log")), key=os.path.getmtime)
        f = cand[-1] if cand else f
    conta, tot, blo = {}, 0, 0
    try:
        with open(f, "rb") as h:
            h.seek(0, 2)
            dim = h.tell()
            h.seek(max(0, dim - 12 * 1024 * 1024))
            righe = h.read().decode("utf-8", "replace").splitlines()[1:]
    except OSError:
        return vuoto
    for riga in righe:
        c = [x.strip().strip('"') for x in riga.split("\t" if "\t" in riga else ",")]
        if len(c) < 4 or not (c[1] in ips or c[2] in nomi):
            continue
        r = next((k for k in range(1, len(c)) if _MOTIVO_R.match(c[k])), None)
        if r is None:
            continue
        dom = ""
        for k in range(r + 1, len(c)):
            m = re.match(r"^[A-Z0-9]+ \((.+?)\.?\)$", c[k])
            if m:
                dom = m.group(1).lower()
                break
            if _HOST_R.match(c[k]):
                dom = c[k].rstrip(".").lower()
                break
        if not dom:
            continue
        v = conta.setdefault(dom, [0, 0])
        v[0] += 1
        tot += 1
        if c[r].startswith("BLOCKED"):
            v[1] += 1
            blo += 1
    top = sorted(conta.items(), key=lambda kv: (-kv[1][0], kv[0]))[:max(1, min(50, n))]
    return {"richieste": tot, "bloccate": blo,
            "domini": [{"dominio": d, "richieste": v[0], "bloccate": v[1]} for d, v in top]}


def nomi_tailscale():
    try:
        return {k: v for k, v in json.load(open(NOMI_JSON, encoding="utf-8")).items() if isinstance(v, str)}
    except (OSError, ValueError):
        return {}


def _bloccati_recenti(ip, minuti):
    """{dominio: volte} di tutto ciò che il filtro ha fermato a quell'indirizzo negli ultimi minuti (senza scartare niente)."""
    da = (datetime.now() - timedelta(minutes=minuti)).strftime("%Y-%m-%d %H:%M:%S")
    f = os.path.join(filtro.REGISTRO, "%s_ALL.log" % date.today().isoformat())
    conta = {}
    try:
        righe = open(f, encoding="utf-8", errors="replace").read().splitlines()[-20000:]
    except OSError:
        return conta
    for r in righe:
        c = [v.strip().strip('"') for v in r.split("\t" if "\t" in r else ",")]
        if len(c) < 6 or c[1] != ip or c[0][:19] < da:
            continue
        if not any(v.startswith("BLOCKED") for v in c[3:9]):
            continue
        d = c[5].rstrip(".").lower()
        m = re.match(r"^[A-Z]+ \((.+?)\.?\)$", c[5])
        if m:
            d = m.group(1).lower().lstrip("*.")
        if d:
            conta[d] = conta.get(d, 0) + 1
    return conta


def scoperti(ip, minuti=5):
    """domini bloccati a quell'indirizzo negli ultimi minuti (per sistemare un sito che ti ha scoperto)."""
    conta = {d: n for d, n in _bloccati_recenti(ip, minuti).items() if not protetto(d) and not _pubblicita(d) and d not in SENTINELLE}
    gia = {r.lstrip("*.") for r in _righe_pulite(ANTI)}
    return [{"dominio": d, "volte": n} for d, n in sorted(conta.items(), key=lambda kv: -kv[1]) if d not in gia][:25]


# ───────────── lettori video: «Il video non parte?» ─────────────
# lettori-video.json (lo stesso elenco dell'estensione, controllato da npm test): SOLO lettori e CDN di lettori, mai pubblicità.
#  - «serie»: indirizzi esatti dei lettori, lasciati passare in ogni profilo con il filtro acceso (mai i sottodomini di misura);
#  - «Fai partire il video» dall'estensione: i pezzi del lettore fermati su un sito si ricordano in video-siti.json
#    (la rete DNS non vede il sito: il permesso vale per quell'indirizzo del lettore su tutti i dispositivi, e si toglie con «Annulla»).
LETTORI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lettori-video.json")
VIDEO_SITI = os.path.join(DATA, "video-siti.json")
MAX_SITI_VIDEO = 200
_LET = {"t": None, "d": None}


def _rx(t):
    try:
        return re.compile(t, re.I) if t else None
    except re.error:
        return None


def _lettori():
    """il file dei lettori, riletto solo se è cambiato."""
    try:
        m = os.path.getmtime(LETTORI_FILE)
    except OSError:
        m = None
    if _LET["d"] is not None and _LET["t"] == m:
        return _LET["d"]
    dati = _leggi(LETTORI_FILE, {}) if m is not None else {}
    L = dati.get("lettori") or []
    mai = dati.get("mai") or {}
    _LET["d"] = {
        "lettori": [(l.get("nome", ""), [x.lower() for x in l.get("domini", [])]) for l in L],
        "serie": sorted({x.lower() for l in L for x in l.get("serie", [])}),
        "serie_nome": {x.lower(): l.get("nome", "") for l in L for x in l.get("serie", [])},
        "sempre_ok": {(v.get("dominio") or "").lower().strip(".*"): v.get("perche", "") for v in (dati.get("sempre_ok") or {}).get("voci", []) if isinstance(v, dict) and v.get("dominio")},
        "misure": [(x.lower(), l.get("nome", "")) for l in L for x in l.get("misure", [])],
        "mai": [x.lower() for x in mai.get("domini", [])],
        "re_mai": _rx(mai.get("parole")),
        "re_misura": _rx(dati.get("misura_parole")),
    }
    _LET["t"] = m
    return _LET["d"]


def _sotto(h, d):
    return h == d or h.endswith("." + d)


def classifica_video(dominio):
    """('lettore'|'misura'|'altro', nome del lettore). Pubblicità e misure non sono MAI pezzi del lettore."""
    L = _lettori()
    h = (dominio or "").lower().strip(".")
    if not h or _pubblicita(h) or h in SENTINELLE or any(_sotto(h, d) for d in L["mai"]) or (L["re_mai"] and L["re_mai"].search(h)):
        return "altro", ""
    for d, nome in L["misure"]:
        if _sotto(h, d):
            return "misura", nome
    for nome, doms in L["lettori"]:
        if any(_sotto(h, d) for d in doms):
            if L["re_misura"] and L["re_misura"].search(h):
                return "misura", nome
            return "lettore", nome
    return "altro", ""


def video_di_serie():
    """indirizzi esatti dei lettori che passano di serie (solo quelli che la classificazione riconosce come lettore)."""
    return {d for d in _lettori()["serie"] if classifica_video(d)[0] == "lettore"}


def lettori_sempre_ok():
    """{indirizzo: perché} dei lettori video che il Filtro di rete NON blocca mai (Casa e Cloudflare):
    gli SDK dei lettori (es. imasdk.googleapis.com) e gli indirizzi esatti dei lettori. Mai spot né misure
    (il DNS non può consegnare un sostituto: si lascia passare il lettore e si bloccano i server che servono gli spot).
    Un blocco a mano (blocca.txt) e gli indirizzi pubblicitari vincono sempre."""
    L = _lettori()
    out = {d: m for d, m in L["sempre_ok"].items() if d}
    for d in video_di_serie():
        out.setdefault(d, "file del lettore %s" % (L["serie_nome"].get(d) or "video"))
    buoni = permessi_puliti(set(out))
    return {d: m for d, m in sorted(out.items()) if d in buoni}


def _video_siti():
    dati = _leggi(VIDEO_SITI, {})
    return dati if isinstance(dati, dict) else {}


def _video_permessi_tutti():
    out = set()
    for doms in _video_siti().values():
        if isinstance(doms, list):
            out |= {d for d in doms if isinstance(d, str) and classifica_video(d)[0] == "lettore"}
    return out


def video_bloccati(ip, sito="", minuti=10):
    """cosa ha fermato la rete a questo dispositivo negli ultimi minuti, con i pezzi del lettore riconosciuti."""
    conta = _bloccati_recenti(ip, minuti)
    righe = []
    for d, n in sorted(conta.items(), key=lambda kv: -kv[1])[:80]:
        tipo, nome = classifica_video(d)
        righe.append({"dominio": d, "volte": n, "tipo": tipo, "lettore": nome})
    vistosi = [r for r in righe if r["tipo"] != "altro"] + [r for r in righe if r["tipo"] == "altro"][:12]
    s = filtro._dominio(sito) or ""
    return {"domini": vistosi, "permessi": (_video_siti().get(s) or [])[:30] if s else []}


def permetti_video(sito, domini):
    """«Fai partire il video»: lascia passare SOLO i pezzi di lettore indicati (mai pubblicità né misure)."""
    s = filtro._dominio(sito)
    if not s:
        return False, "Sito non valido."
    buoni = []
    for x in list(domini or [])[:30]:
        d = filtro._dominio(x) if isinstance(x, str) else None
        if d and d not in buoni and classifica_video(d)[0] == "lettore":
            buoni.append(d)
    if not buoni:
        return False, "Nessun componente del lettore video da consentire: pubblicità e misurazioni restano bloccate."
    with _blocco:
        dati = _video_siti()
        if s not in dati and len(dati) >= MAX_SITI_VIDEO:
            return False, "Limite di siti con lettore consentito raggiunto. Rimuovine uno."
        dati[s] = sorted(set(d for d in (dati.get(s) or []) if isinstance(d, str)) | set(buoni))[:30]
        _salva(VIDEO_SITI, dati)
        _applica()
    return True, "Componenti del lettore consentiti su Casa per %s (%s): valgono per tutti i dispositivi. Ricarica la pagina." % (s, ", ".join(buoni))


def annulla_video(sito):
    s = filtro._dominio(sito)
    if not s:
        return False, "Sito non valido."
    with _blocco:
        dati = _video_siti()
        if s in dati:
            del dati[s]
            _salva(VIDEO_SITI, dati)
            _applica()
    return True, "Permessi del lettore rimossi per %s." % s


def permetti_anti(dominio):
    d = filtro._dominio(dominio)
    if not d:
        return False, "Sito non valido."
    if _pubblicita(d) or d in SENTINELLE:
        return False, "%s mostra pubblicità: non lo permetto (varrebbe per tutti i siti). Per quel sito usa «AdBlocker rilevato» nell'estensione Filtreo." % d
    rr = filtro._righe(ANTI)
    if d not in [r.strip() for r in rr]:
        rr.append(d)
        filtro._scrivi(ANTI, rr)
    with _blocco:
        _applica()
    return True, "%s consentito. Ricarica la pagina tra 2 minuti." % d


def _principale_da_mac():
    """l'installatore gira sul Mac di Giò e ne scrive l'indirizzo: il principale senza indirizzo diventa quel Mac."""
    try:
        mac = json.load(open(NOMI_JSON, encoding="utf-8")).get("_mac", "")
    except (OSError, ValueError, AttributeError):
        return
    if not mac:
        return
    with _blocco:
        dd = dispositivi()
        pr = next((x for x in dd if x.get("principale")), None)
        if pr is None or pr.get("ip") or any(x.get("ip") == mac for x in dd):
            return
        pr["ip"] = mac
        nome = nomi_tailscale().get(mac)
        if nome and pr.get("nome") in ("Mac", "", None):
            pr["nome"] = nome
        _salva(DISP_JSON, dd)


def rendi_principale(did):
    """lo sceglie solo il padrone dal pannello: il dispositivo indicato prende il posto del principale
    (le liste del principale restano quelle), il vecchio principale diventa «fa come»."""
    with _blocco:
        dd = dispositivi()
        pr = next((x for x in dd if x.get("principale")), None)
        x = next((y for y in dd if y["id"] == did), None)
        if pr is None or x is None or x is pr:
            return False, "Dispositivo non trovato."
        ff = fonti()
        for f in ff:  # le «liste sue» del nuovo principale spariscono: valgono quelle del principale
            f["dispositivi"] = [g for g in f.get("dispositivi", [PRINCIPALE]) if g != x["id"]]
        _salva(FONTI_JSON, ff)
        vecchio_ip, vecchio_nome = pr.get("ip", ""), pr.get("nome", "")
        pr["ip"], pr["nome"] = x.get("ip", ""), x.get("nome", "")
        if vecchio_ip:
            x["ip"], x["nome"], x["proprie"] = vecchio_ip, vecchio_nome, False
        else:
            dd = [y for y in dd if y is not x]
        _salva(DISP_JSON, dd)
        _assegna_casa()
        cambiata = scrivi_config()
        _applica(config_cambiata=cambiata)
    return True, "«%s» è il dispositivo principale. I dispositivi collegati ne seguono le regole." % pr["nome"]


def elenco():
    dd = dispositivi()
    noti = ip_noti(dd)   # mai proporre come «nuovo» un dispositivo già registrato (ip e ips) né il nodo stesso
    vv = visti()
    tsn = nomi_tailscale()
    nuovi = [{"ip": ip, "nome": tsn.get(ip) or v[0], "ultimo": v[1][11:16] if len(v[1]) >= 16 else v[1], "richieste": v[2]}
             for ip, v in sorted(vv.items(), key=lambda kv: -kv[1][2]) if ip not in noti]
    for n in nuovi:
        n["genere"] = genere(n)
        n["proposta"] = proposta(n)
    for x in dd:
        ii = [i for i in [x.get("ip")] + list(x.get("ips") or []) if i and i in vv]
        if e_nodo(x):   # le richieste fatte dal nodo a sé stesso contano sul nodo
            ii += [i for i in nodo_ips() if i in vv and i not in ii]
        if ii:
            x["ultimo"] = max(vv[i][1] for i in ii)[11:16]
    uso_url = {u for g in gruppi() for u in modo_di(g).get("fonti", [])}
    ff = [{"url": f["url"], "nome": f.get("nome", ""), "domini": f.get("domini", 0), "aggiornata": f.get("aggiornata", ""),
           "errore": f.get("errore", ""), "attiva": f.get("attiva", True), "categoria": modalita.categoria(f),
           "dormiente": bool(f.get("casa")) and f["url"] not in uso_url}
          for f in fonti()]
    for x in dd:
        if x.get("ip") and tsn.get(x["ip"]):
            x["nome_ts"] = tsn[x["ip"]]
    pr = next((x for x in dd if x.get("principale")), {})
    _prepara_modalita()
    mm = modalita.elenco()
    ff_tutte = fonti()
    for x in dd:
        if x.get("proprie"):
            x["modo"] = modo_di(x["id"])["id"]
        x["genere"] = genere(x)
        x["proposta"] = proposta(x)
        if x.get("spento_fino"):
            x["spento_min"] = max(0, int((x["spento_fino"] - time.time()) / 60))
    return {"fonti": ff, "dispositivi": dd, "nuovi": nuovi[:12], "gruppi": gruppi(),
            "senza_principale": not pr.get("ip"),
            # 3.1: ogni modalità dice anche da che livello parte e se è «modificata» (livello, modificato, etichetta: vedi livelli.scheda)
            "modalita": [dict(m, fuori_profilo=modalita.profilo_fuori(m), famiglia=bool(m.get("famiglia")), **livelli.scheda(m, ff_tutte))
                         for m in mm] + [modalita.trova(modalita.SPENTO)],
            "pausa": modalita.trova(modalita.PAUSA),
            "app": [{"id": a["id"], "nome": a["nome"]} for a in modalita.app_bloccabili()],
            "famiglia": modalita.persone(),
            "categorie": [{"id": c[0], "nome": c[1], "consigliata": bool(modalita.CONSIGLIATE.get(c[0]))} for c in modalita.CATEGORIE],
            "servizi": [{"id": x["id"], "nome": x["nome"]} for x in modalita.servizi()["servizi"]],
            "servizi_casa": [{"id": x["id"], "nome": x["nome"]} for x in modalita.servizi_casa()["servizi"]],
            "spento_minuti": modalita.TORNA_DOPO}


# ───────────── avvio, passaggio dalla versione 1.2, aggiornamenti ─────────────
def _chiave(f):
    """stessa lista = stesso link (senza differenze di http/https, maiuscole, «/» finale)
    oppure stesso nome mostrato nel pannello (stessa lista presa da due indirizzi diversi)."""
    u = f["url"].strip()
    u = re.sub(r"^http://", "https://", u, flags=re.I)
    m = re.match(r"^(https://[^/]+)(.*)$", u, flags=re.I)
    u = (m.group(1).lower() + m.group(2)) if m else u
    n = (f.get("nome") or "").strip().lower()
    coda = u.rstrip("/").split("/")[-1].split("?")[0].lower()
    if not n or n == coda[:60]:
        return u.rstrip("/"), ""  # nome ricavato dal link (es. «filter.txt»): non basta per dire che è la stessa lista
    return u.rstrip("/"), n + "|" + coda  # stesso nome E stesso file (es. due indirizzi di easyprivacy.txt)


def _senza_doppioni(ff):
    """unisce le voci doppie di fonti.json (causa dell'interruttore «che torna acceso»: si spegneva
    una copia e l'altra restava accesa). Se una copia era spenta, la lista unita resta spenta."""
    tenute, per_url, per_nome, tolti = [], {}, {}, 0
    for f in ff:
        u, n = _chiave(f)
        prima = per_url.get(u) or (per_nome.get(n) if n else None)
        if prima is None:
            tenute.append(f)
            per_url[u] = f
            if n:
                per_nome[n] = f
            continue
        tolti += 1
        ds = list(prima.get("dispositivi", [PRINCIPALE]))
        ds += [g for g in f.get("dispositivi", [PRINCIPALE]) if g not in ds]
        prima["dispositivi"] = ds  # riaccendendola, torna dove era
        if not f.get("attiva", True):  # la copia spenta è la scelta di chi usa il pannello
            prima["attiva"] = False
        per_url[u] = prima
    return tenute, tolti


def prepara():
    """all'avvio, PRIMA di Blocky: passaggio dalla 1.2 e config/file pronti."""
    os.makedirs(FONTI_DIR, exist_ok=True)
    ff = fonti()
    cambiato = False
    for f in ff:  # liste importate con la 1.2: valgono per il principale
        if "dispositivi" not in f:
            f["dispositivi"], cambiato = [PRINCIPALE], True
        if "attiva" not in f:
            f["attiva"], cambiato = True, True
    urls = {f["url"] for f in ff}
    segno = os.path.join(DATA, ".preset-1.3")
    if not os.path.exists(segno):  # una volta sola: liste pronte (Hagezi e OISD erano nella config, ora sono liste come le altre)
        for nome, url in PRESET:
            if url not in urls:
                ff.append({"url": url, "nome": nome, "attiva": True, "dispositivi": [PRINCIPALE]})
                cambiato = True
        open(segno, "w").close()
    vuote = [f for f in ff if f["url"] in RITIRATE and not f.get("domini")]
    ff = [f for f in ff if f not in vuote]
    ff, tolti = _senza_doppioni(ff)
    cambiato = cambiato or tolti > 0 or bool(vuote)
    if cambiato or not os.path.exists(FONTI_JSON):
        _salva(FONTI_JSON, ff)
    if not os.path.exists(DISP_JSON):
        _salva(DISP_JSON, dispositivi())
    pulisci_eccezioni()
    _prepara_modalita()   # migrazione dalla 1.5 (crea modalita.json se manca)
    _semina_casa()        # profili pronti + liste per marca dormienti (solo qui, mai da dentro un blocco)
    scrivi_config()
    _scrivi_gruppi()


_META = ("nome", "domini", "aggiornata", "errore")


def _aggiorna_fonti(elenco):
    """scarica le liste una alla volta FUORI dal blocco; per ognuna rilegge fonti.json e aggiorna
    SOLO i dati della lista (nome, domini, data, errore): mai «attiva» né «dispositivi».
    Così un interruttore cambiato nel frattempo dal pannello non viene mai sovrascritto."""
    ultimo = time.time()
    for x in elenco:
        f = {"url": x["url"], "nome": x.get("nome", "")}
        _aggiorna(f)
        with _blocco:
            ff = fonti()
            for y in ff:
                if y["url"] == f["url"]:
                    for k in _META:
                        if k in f:
                            y[k] = f[k]
            _salva(FONTI_JSON, ff)
        if time.time() - ultimo > 60:  # installazione nuova: il filtro lavora già con le liste arrivate
            _applica(motivo="aggiornamento liste")
            ultimo = time.time()
    if elenco:
        _applica(motivo="aggiornamento liste")


def _ciclo():
    # prima: scarica le liste che non hanno ancora i domini (nuove, passate dalla 1.2, o eccezioni del vecchio formato)
    mancanti = [f for f in fonti() if (not os.path.exists(_file(f["url"])) or not os.path.exists(_file(f["url"]) + ".ecc2")) and _da_scaricare(f)]
    _aggiorna_fonti(mancanti)
    segno = os.path.join(DATA, ".formato-1.5.1")
    if not os.path.exists(segno):   # 1.5.1: «||sito^» blocca anche i sotto-indirizzi → rileggo tutte le liste una volta
        _aggiorna_fonti([f for f in fonti() if f not in mancanti and _da_scaricare(f)])
        open(segno, "w").close()
    while True:
        time.sleep(OGNI_ORE * 3600)
        _aggiorna_fonti([f for f in fonti() if _da_scaricare(f)])


def avvia(fn_protetto):
    global protetto
    protetto = fn_protetto
    _lavoratore["attivo"] = True
    threading.Thread(target=_giro_lavoratore, daemon=True).start()
    threading.Thread(target=_giro_orologio, daemon=True).start()
    threading.Thread(target=_giro_pause, daemon=True).start()
    threading.Thread(target=_ciclo, daemon=True).start()
    if GUARDIA_ATTIVA:
        threading.Thread(target=_giro_guardia, daemon=True).start()
    # appena acceso: copia nel pannello i cambi fatti fuori casa (pagina di riserva) mentre era spento
    t = threading.Timer(20, sincronizza_paracadute)
    t.daemon = True
    t.start()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--prepara":
        try:
            import filtreo_pannello as _p
            protetto = _p._protetto
        except Exception:
            pass
        prepara()
        print("config e liste pronte")


def salva_persona(dati):
    ok, t, pid = modalita.salva_persona(dati, {x["id"] for x in dispositivi() if not x.get("principale")})
    if ok and dati.get("modo"):
        p = next((x for x in modalita.persone() if x["id"] == pid), {})
        for d in p.get("dispositivi", []):
            x = next((y for y in dispositivi() if y["id"] == d), {})
            if x.get("proprie") and x.get("modo") != p["modo"]:
                imposta_modo(d, p["modo"])
    return ok, t, pid
