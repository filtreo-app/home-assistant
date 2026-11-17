#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtreo_pannello.py — il pannello di Filtreo per il Pi di Giò (add-on Home Assistant).
Stessa pagina del Filtreo di Davide. Servito tramite l'ingress di Home Assistant:
Giò lo apre dalla barra laterale (HA fa già l'autenticazione, niente chiave da digitare).

Calcola lo stato leggendo il registro di Blocky (CSV in /data/log), così è autonomo.
"""
import base64
import glob
import hmac
import json
import os
import time
import re
import sys
import threading
from collections import Counter, deque
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import applicazione  # noqa: E402  (tempi di ogni applicazione: «Applico… N s»)
import filtro  # noqa: E402
import filtreo_liste as liste  # noqa: E402  (liste di blocco e dispositivi)
import dns_personale as dnsp  # noqa: E402  (DNS cifrato fuori casa + modalità)
import estensione_nodo as est  # noqa: E402  (regole e segnalazioni dalle estensioni)
import modalita  # noqa: E402  (modalità e famiglia)
import righe_nuove as rn  # noqa: E402  (aggiornamenti, copia di sicurezza, avvisi su Telegram)
import ha_integrazione as ha  # noqa: E402  (Home Assistant e HomeKit: porta con chiave + integrazione)
import livelli  # noqa: E402  (3.1: livello come punto di partenza, gruppi di categorie)
import regole  # noqa: E402  (3.1: «Le tue regole» con origine e data)
import statistiche as stat  # noqa: E402  (3.1: /pannello/statistiche, un dato solo per app, widget e pannello)
import aggiornamento as agg  # noqa: E402  (Casa si aggiorna da sola: canale firmato, prova, ritorno indietro)
import abbinamento as abb  # noqa: E402  (app collegate con codice di 6 cifre, senza chiavi da copiare)
import mdns  # noqa: E402  (Casa si fa trovare: Bonjour _filtreo._tcp)
import ponte  # noqa: E402  (0.10: app ↔ Casa da qualsiasi rete, senza Tailscale)
import apns  # noqa: E402  (0.9.4: notifiche push di Apple per l'Attività della pausa)

PORTA = int(os.environ.get("INGRESS_PORT", "8099"))
# Il pannello risponde SOLO a Home Assistant (ingress): nessun accesso diretto dalla rete.
INGRESSO_OK = set(os.environ.get("INGRESSO_OK", "172.30.32.2 127.0.0.1").split())
# Senza Home Assistant (Jetson): il pannello risponde anche alle reti di casa e di Tailscale indicate qui.
import ipaddress  # noqa: E402
RETI_OK = []
# 0.10: Tailscale non serve più (le app da fuori casa passano dal ponte con la loro chiave); la sua rete resta accettata solo per
# compatibilità con le installazioni di prima, finché ogni app non è collegata con il codice di 6 cifre.
for _r in os.environ.get("FILTREO_RETI", "100.64.0.0/10 127.0.0.0/8").split():
    try:
        RETI_OK.append(ipaddress.ip_network(_r, strict=False))
    except ValueError:
        pass


def _rete_ok(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in r for r in RETI_OK)
    except ValueError:
        return False
# Porta per l'icona nella barra del Mac: protetta da chiave (vuota = spenta).
PORTA_BARRA = int(os.environ.get("BARRA_PORT", "8447"))
CHIAVE_BARRA = os.environ.get("FILTREO_CHIAVE", "").strip()
CONFIG = os.path.join(filtro.DATA, "blocky.yml")
BIANCA = "bianca.txt"
MOTIVO = re.compile(r"^(RESOLVED|CACHED|BLOCKED|CONDITIONAL|CUSTOMDNS|HOSTSFILE|FILTERED|NOTFQDN|SPECIAL)\b")
HOST = re.compile(r"^(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]{1,}\.?$", re.I)

# Domini che non si bloccano MAI a mano (romperebbero servizi di uso quotidiano).
PROTETTI = (
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com", "youtube.com",
    "apple.com", "icloud.com", "mzstatic.com", "microsoft.com", "office.com", "live.com",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net", "whatsapp.com",
    "linkedin.com", "cloudflare.com", "akamai.net", "amazonaws.com",
)


def _protetto(d):
    return bool(d) and any(d == p or d.endswith("." + p) for p in PROTETTI)


def blocca_guard(dominio, origine="mano"):
    d = filtro._dominio(dominio)
    if d and _protetto(d):
        return "%s non viene bloccato: è un servizio di base, necessario ad app e accessi." % d
    t = filtro.blocca(dominio)
    if d:
        regole.segna("bloccati", d, origine)   # 3.1: da dove viene la regola e quando
    liste.applica_permessi()   # il blocco vince su ogni permesso: riscrivo i permessi puliti
    return t


def sblocca_guard(dominio, origine="mano"):
    d = filtro._dominio(dominio)
    if d and (liste._pubblicita(d) or d in liste.SENTINELLE):
        return "%s non viene consentito: dominio pubblicitario, varrebbe per tutti i siti e i dispositivi. Se un sito non funziona, usa «Filtreo rilevato dal sito» nell'estensione." % d
    t = filtro.sblocca(dominio)
    if d:
        regole.segna("consentiti", d, origine)
    liste.applica_permessi()
    return t


def annulla_blocco(dominio):
    """Toglie un blocco fatto a mano (blocca.txt) senza aggiungere un permesso."""
    ok, t = filtro.annulla_blocco(dominio)
    if ok:
        regole.dimentica("bloccati", dominio)
        liste.applica_permessi()   # i permessi puliti tornano com'erano
    return ok, t


def eccezione(azione, dominio, origine="mano"):
    """«Eccezioni · mai bloccate» (bianca.txt)."""
    d = filtro._dominio(dominio)
    if not d:
        return False, "Sito non valido. Inserisci solo il nome, per esempio sito.it"
    rr = filtro._righe(BIANCA)
    pul = [r.strip() for r in rr]
    if azione == "aggiungi":
        if liste._pubblicita(d) or d in liste.SENTINELLE:
            return False, "%s mostra pubblicità: non lo metto tra le eccezioni (varrebbe per tutti i siti)." % d
        if d not in pul and "*." + d not in pul:
            rr.append(d)
            filtro._scrivi(BIANCA, rr)
            regole.segna("consentiti", d, origine)
        liste.applica_permessi()
        return True, "%s è sempre consentito." % d
    if azione == "togli":
        nn = [r for r in rr if r.strip() not in (d, "*." + d)]
        for nome in ("sblocca.txt", "anti-rilevamento.txt"):
            x = filtro._righe(nome)
            y = [r for r in x if r.strip() not in (d, "*." + d)]
            if y != x:
                filtro._scrivi(nome, y)
        filtro._scrivi(BIANCA, nn)
        regole.dimentica("consentiti", d)
        liste.applica_permessi()
        return True, "Eccezione rimossa per %s." % d
    return False, "Azione non valida."


def togli_scadute(adesso=None):
    """0.9.1 — toglie le regole a tempo scadute (consentiti e bloccati). Ritorna quante."""
    n = 0
    for tipo, d in regole.scadute(adesso):
        try:
            ok, _t = annulla_blocco(d) if tipo == "bloccati" else eccezione("togli", d)
        except Exception:
            ok = False
        if not ok:
            regole.dimentica(tipo, d)   # la regola non c'è più nei file: basta la nota
        n += 1
        print("Filtreo: regola a tempo scaduta, tolta (%s %s)" % (tipo, d), flush=True)
    return n


def giro_regole_a_tempo(ogni=30):
    time.sleep(10)
    while True:
        try:
            togli_scadute()
        except Exception as e:   # mai fermarsi
            print("Filtreo: controllo delle regole a tempo non riuscito (%s)" % type(e).__name__, flush=True)
        time.sleep(ogni)


# ───────────── stato dal registro di Blocky ─────────────
def _oggi_file():
    """Il file del giorno; se col nome atteso non c'è, prende il .log più recente."""
    atteso = os.path.join(filtro.REGISTRO, "%s_ALL.log" % date.today().isoformat())
    if os.path.exists(atteso):
        return atteso
    cand = sorted(glob.glob(os.path.join(filtro.REGISTRO, "*_ALL.log")) or
                  glob.glob(os.path.join(filtro.REGISTRO, "*.log")))
    return cand[-1] if cand else atteso


def _ora(campo):
    m = re.search(r"\b(\d{2}:\d{2})\b", campo or "")
    return m.group(1) if m else ""


AZIENDE = (
    ("Google", ("google", "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
                "googletagmanager.com", "gvt1.com", "gvt2.com", "googleapis.com", "gstatic.com", "app-measurement.com",
                "youtube.com", "ytimg.com", "googlevideo.com", "1e100.net")),
    ("Meta", ("facebook.com", "facebook.net", "fbcdn.net", "instagram.com", "whatsapp.net", "fbsbx.com")),
    ("Amazon", ("amazon.", "amazon-adsystem.com", "amazonaws.com", "media-amazon.com")),
    ("Apple", ("apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com")),
    ("Microsoft", ("microsoft.com", "bing.com", "clarity.ms", "msn.com", "live.com", "office.com", "azure")),
    ("TikTok", ("tiktok", "byteoversea.com", "ibytedtech.com")),
    ("Datadog", ("datadoghq",)),
    ("Comscore", ("scorecardresearch.com",)),
    ("Criteo", ("criteo.",)),
    ("X / Twitter", ("twitter.com", "x.com", "twimg.com")),
)


def azienda(dom):
    """3.1: prima la mappa aziende.json (stessa di /pannello/statistiche), poi le regole di prima."""
    nota = stat.azienda_nota(dom)
    if nota:
        return nota[0]
    d = (dom or "").lower()
    for nome, pezzi in AZIENDE:
        for p in pezzi:
            if (p.endswith(".") and ("." + p in "." + d or d.startswith(p))) or d == p or d.endswith("." + p) or (p.isalpha() and p in d):
                return nome
    parti = d.split(".")
    if len(parti) >= 3 and len(parti[-1]) == 2 and parti[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parti[-3:])
    return ".".join(parti[-2:]) if len(parti) >= 2 else d


def _nomi_dispositivi():
    """indirizzo -> nome del dispositivo, con tutti gli indirizzi (ip e ips); quelli del nodo stesso contano sul dispositivo «nodo»."""
    try:
        dd = liste.dispositivi()
        out = {}
        for x in dd:
            for i in [x.get("ip")] + list(x.get("ips") or []):
                if i:
                    out[i] = x["nome"]
        nodo = next((x for x in dd if liste.e_nodo(x)), None)
        if nodo:
            for i in liste.nodo_ips():
                out.setdefault(i, nodo["nome"])
        return out
    except Exception:
        return {}


AVVIO = time.time()   # quando è partito il pannello (= il filtro)


def conti_cloudflare():
    """i blocchi che Cloudflare ha fatto da sé (dispositivo fuori casa filtrato dal paracadute): {giorno: {id dispositivo: [bloccate, richieste]}}.
    Li ritira paracadute-sync.py (data/cloudflare-conti.json). Se il file manca o Cloudflare non risponde: {} (cloudflare = 0, nessun errore).
    Le bloccate per ora stanno a parte (ore_cloudflare)."""
    try:
        with open(os.path.join(filtro.DATA, "cloudflare-conti.json"), encoding="utf-8") as f:
            g = json.load(f).get("giorni")
        out = {}
        for giorno, per in (g if isinstance(g, dict) else {}).items():
            for did, v in (per if isinstance(per, dict) else {}).items():
                out.setdefault(giorno, {})[did] = [max(0, int(v.get("b") or 0)), max(0, int(v.get("r") or 0))]
        return out
    except Exception:
        return {}


def ore_cloudflare(giorno=None):
    """le bloccate di Cloudflare per ora di Roma, oggi: lista di 24 numeri (tutti 0 se il file manca o il worker è il vecchio)."""
    out = [0] * 24
    try:
        with open(os.path.join(filtro.DATA, "cloudflare-conti.json"), encoding="utf-8") as f:
            g = (json.load(f).get("giorni") or {}).get(giorno or date.today().isoformat()) or {}
        for v in g.values():
            o = v.get("o") if isinstance(v, dict) else None
            if isinstance(o, list) and len(o) == 24:
                for i in range(24):
                    out[i] += max(0, int(o[i] or 0))
    except Exception:
        pass
    return out


def _slug_nome(x):
    return re.sub(r"[^a-z0-9]+", "-", str(x or "").lower()).strip("-")


def risolvi_cf(chiave, dd=None, voci=None):
    """nome del dispositivo del pannello a cui appartiene la chiave di un conteggio di Cloudflare. La chiave può essere l'id del
    dispositivo, il nome del DNS personale («mac-davide», anche se non è legato a nessun dispositivo) o un nome scritto in altro modo
    («Mac di Davide»): si abbina per id, per voce del DNS personale, per nome uguale e infine per parole (tutte le parole del nome
    del dispositivo comprese nella chiave, solo se il dispositivo è uno solo). Nessun nome scritto a mano. Altrimenti None."""
    chiave = str(chiave or "")
    if not chiave or chiave == "?":
        return None
    try:
        dd = liste.dispositivi() if dd is None else dd
    except Exception:
        dd = []
    if voci is None:
        try:
            voci = list(dnsp.voci())
        except Exception:
            voci = []
    ids = {x.get("id"): x.get("nome") for x in dd if x.get("id")}
    if chiave in ids:
        return ids[chiave]
    etichetta = None
    for n, v in voci:
        if n == chiave and isinstance(v, dict):
            if v.get("disp") in ids:
                return ids[v["disp"]]
            etichetta = v.get("nome") or n
    s = _slug_nome(chiave)
    for x in dd:
        if s and s in (_slug_nome(x.get("id")), _slug_nome(x.get("nome"))):
            return x.get("nome")
    parole = set(s.split("-")) - {"di", "del", "della", "de", ""}
    cand = [x for x in dd if x.get("nome") and (set(_slug_nome(x["nome"]).split("-")) - {"di", "del", "della", "de", ""})
            and (set(_slug_nome(x["nome"]).split("-")) - {"di", "del", "della", "de", ""}) <= parole]
    if len(cand) == 1:
        return cand[0]["nome"]
    return etichetta


def _cf_per_nome(giorni):
    """{nome dispositivo: [bloccate, richieste]} sommando i giorni dati."""
    try:
        dd = liste.dispositivi()
    except Exception:
        dd = []
    try:
        voci = list(dnsp.voci())
    except Exception:
        voci = []
    cf = conti_cloudflare()
    out = {}
    for g in giorni:
        for did, v in cf.get(g, {}).items():
            d = out.setdefault(risolvi_cf(did, dd, voci) or "Altri", [0, 0])
            d[0] += v[0]
            d[1] += v[1]
    return out


def stato():
    tot = bloc = 0
    perdisp = {}
    ore = [0] * 24
    chi = Counter()
    nomi = _nomi_dispositivi()
    ultime = deque(maxlen=60)
    top = Counter()
    tempi = deque(maxlen=5000)   # millisecondi delle ultime risposte (colonna prima del motivo)
    try:
        with open(_oggi_file(), encoding="utf-8", errors="replace") as f:
            for riga in f:
                riga = riga.rstrip("\n")
                if not riga:
                    continue
                sep = "\t" if "\t" in riga else ("," if "," in riga else None)
                c = [x.strip().strip('"') for x in riga.split(sep)]
                if len(c) < 4:
                    continue
                r = next((k for k in range(1, len(c)) if MOTIVO.match(c[k])), None)
                if r is None:
                    continue
                dom = next((c[k].rstrip(".") for k in range(r + 1, len(c)) if HOST.match(c[k])), None)
                if r >= 1 and c[r - 1].isdigit():
                    tempi.append(int(c[r - 1]))
                nome = nomi.get(c[1]) or "Altri"
                d = perdisp.setdefault(nome, [0, 0])
                tot += 1
                d[0] += 1
                if c[r].startswith("BLOCKED") and dom:
                    bloc += 1
                    d[1] += 1
                    ora = _ora(c[0])
                    ultime.append((ora, nome, dom))
                    top[dom] += 1
                    chi[azienda(dom)] += 1
                    if ora[:2].isdigit():
                        ore[int(ora[:2]) % 24] += 1
    except OSError:
        pass
    s = filtro.stato_api()
    # Cloudflare: i blocchi fatti fuori casa dal paracadute si sommano a quelli di Casa (campi casa, cloudflare, totale)
    cf = _cf_per_nome([date.today().isoformat()])
    casa_bloc, cf_bloc = bloc, sum(v[0] for v in cf.values())
    tot += sum(v[1] for v in cf.values())
    bloc += cf_bloc
    righe_d = {}
    for n, v in perdisp.items():
        righe_d[n] = {"nome": n, "richieste": v[0], "casa": v[1], "cloudflare": 0}
    for n, v in cf.items():
        r = righe_d.setdefault(n, {"nome": n, "richieste": 0, "casa": 0, "cloudflare": 0})
        r["richieste"] += v[1]
        r["cloudflare"] += v[0]
    for r in righe_d.values():
        r["totale"] = r["bloccate"] = r["casa"] + r["cloudflare"]
    s["oggi"] = {"richieste": tot, "bloccate": bloc, "percento": round(100 * bloc / tot) if tot else 0,
                 "casa": casa_bloc, "cloudflare": cf_bloc, "totale": bloc}
    s["dispositivi"] = sorted(righe_d.values(), key=lambda r: (r["nome"] == "Altri", -r["totale"]))[:6]
    ore_cf = ore_cloudflare()
    s["ore_casa"] = ore
    s["ore_cloudflare"] = ore_cf
    s["ore"] = [a + b for a, b in zip(ore, ore_cf)]   # = totale (Casa + Cloudflare)
    s["pausa_durata"] = durata_ricordata()
    if s.get("pausa"):
        s["pausa"]["totale_sec"] = _totale_pausa(s["pausa"].get("resta_sec") or 0)
    s["chi_di_piu"] = [n for n, _ in chi.most_common(3)]
    vis, ult = set(), []
    for ora, nome, dom in reversed(ultime):
        if dom not in vis:
            vis.add(dom)
            ult.append({"ora": ora, "dispositivo": nome, "dominio": dom, "chi": azienda(dom)})
        if len(ult) == 12:
            break
    s["ultime"] = ult
    s["top"] = [{"dominio": d, "volte": v, "chi": azienda(d)} for d, v in top.most_common(6)]
    if tempi:   # le risposte già in memoria valgono 0 ms: le conto come 1 ms, così il numero è onesto e non «0»
        t = sorted(max(1, x) for x in tempi)
        s["veloce_ms"] = t[len(t) // 2]
        s["in_memoria"] = round(100 * sum(1 for x in tempi if x == 0) / len(tempi))
    sec = int(time.time() - AVVIO)
    s["acceso_da"] = ("%d giorni" % (sec // 86400) if sec >= 172800 else "1 giorno" if sec >= 86400
                      else "%d ore" % (sec // 3600) if sec >= 7200 else "1 ora" if sec >= 3600 else "%d minuti" % max(1, sec // 60))
    s["aggiornato"] = datetime.now().strftime("%H:%M:%S")
    s["applicazione"] = applicazione.stato()   # {in_corso, secondi_stimati, ultima_durata, testo, ...}: «Applico… circa N s»
    s["motore"] = liste.stato_guardia()
    return s


# ───────────── pausa: durata ricordata (lo scudo si preme) ─────────────
DURATE = (("30s", "30 secondi"), ("10m", "10 minuti"), ("1h", "1 ora"), ("domani", "Fino a domani"), ("senza", "Senza scadenza"))
DURATA_FILE = os.path.join(filtro.DATA, "pausa-durata.json")
PAUSA_FILE = os.path.join(filtro.DATA, "pausa-corrente.json")


def durata_ricordata():
    try:
        with open(DURATA_FILE, encoding="utf-8") as f:
            k = json.load(f).get("durata")
        return k if k in dict(DURATE) else "10m"
    except Exception:
        return "10m"


def imposta_durata(k):
    if k not in dict(DURATE):
        return False
    try:
        with open(DURATA_FILE, "w", encoding="utf-8") as f:
            json.dump({"durata": k}, f)
        return True
    except OSError:
        return False


NUVOLA_FILE = os.path.join(filtro.DATA, "pausa-nuvola.json")


def pausa_cambiata(testo=None):
    """la pausa (o lo «Spento») è cominciata o finita: la scadenza va anche su Cloudflare, dove stanno i profili dei telefoni.
    Ricordo qui com'è adesso (file pausa-nuvola.json) e avviso paracadute-sync.py --solo-pausa (una scrittura nel KV,
    in sottofondo). Se il token o lo script mancano non succede niente: la pausa resta solo su Casa. Mai un errore.
    Ritorna il testo ricevuto, così si usa dentro i return."""
    try:
        s = filtro.stato_api()
        p = s.get("pausa") if s.get("raggiungibile") else None
        rec = {"attiva": bool(p), "senza": bool(p and p.get("senza_scadenza")),
               "fino": int((time.time() + int(p.get("resta_sec") or 0)) * 1000) if p and not p.get("senza_scadenza") else 0,
               "quando": int(time.time() * 1000)}
        tmp = NUVOLA_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        os.replace(tmp, NUVOLA_FILE)
    except Exception:
        pass
    try:
        liste.sincronizza_pausa()
    except Exception:
        pass
    return testo


def _segna_pausa(secondi, da=""):
    """ricorda quanto durava la pausa appena iniziata (serve all'arco dello scudo) e chi l'ha avviata (campo «da»)"""
    try:
        with open(PAUSA_FILE, "w", encoding="utf-8") as f:
            json.dump({"totale": int(secondi), "fine": time.time() + int(secondi), "senza": int(secondi) == 0, "da": str(da or "")[:40],
                       "inizio": time.time()}, f)
    except OSError:
        pass


def _totale_pausa(resta):
    try:
        with open(PAUSA_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if abs((d["fine"] - time.time()) - resta) < 45 and d["totale"] >= resta:
            return int(d["totale"])
    except Exception:
        pass
    return int(resta)


def _minuti_a_domani():
    """minuti fino a «domani» (vedi filtro.fine_domani: di serie le 07:00 locali del giorno dopo)"""
    return max(1, -(-int(filtro.fine_domani() - time.time()) // 60))


def pausa_scelta(k=None, da=""):
    """mette in pausa per la durata scelta (o per l'ultima ricordata): 30s, 10m, 1h, domani, senza (Senza scadenza).
    da = chi l'ha avviata (nome del dispositivo), per l'API della pausa."""
    k = k if k in dict(DURATE) else durata_ricordata()
    if k == "30s":
        t = filtro.pausa_secondi(30)
        if t.startswith("Filtro in pausa"):
            _segna_pausa(30, da)
            pausa_cambiata()
        return t
    if k == "senza":
        filtro._togli_timer()
        _t, err = filtro._api("/api/blocking/disable")
        if err:
            return "Impossibile disattivare il filtro (%s)." % err
        _segna_pausa(0, da)
        return pausa_cambiata("Filtro disattivato fino alla ripresa.")
    if k == "domani":
        m = _minuti_a_domani()
        filtro._togli_timer()
        _t, err = filtro._api("/api/blocking/disable?duration=%dm" % m)
        if err:
            return "Impossibile mettere in pausa (%s)." % err
        _segna_pausa(m * 60, da)
        return pausa_cambiata("Filtro in pausa fino a domani alle %02d:00." % filtro.ORA_DOMANI)
    m = 60 if k == "1h" else 10
    t = filtro.pausa(m)
    if t.startswith("Filtro in pausa"):
        _segna_pausa(m * 60, da)
        pausa_cambiata()
    return t


# ───────────── API unica della pausa: Questo dispositivo · Rete ─────────────
#   GET  /pannello/pausa/stato      → {rete:{fino,da,…}, dispositivi:[{nome,fino,da,…}], …}
#   POST /pannello/pausa            {ambito:"dispositivo"|"rete", dispositivo, durata:"30s"|"10m"|"1h"|"domani"|"senza"} → stato
#   POST /pannello/pausa/prolunga   {ambito, dispositivo, minuti} → stato
#   POST /pannello/pausa/riprendi   {ambito, dispositivo} → stato
# (corpo JSON, oppure gli stessi nomi nella query). Gli endpoint di prima (/pannello/pausa?min=, ?d=, /pannello/pausa/durata,
# /pannello/riprendi, /barra/pausa…) restano com'erano.
# Rete: al massimo «Fino a domani» (mai «senza»), e solo da un dispositivo «proprietario» (se nessuno è marcato: da ovunque).
PAUSA_RETE_STRETTA = os.environ.get("FILTREO_PAUSA_RETE_STRETTA", "0") == "1"   # 1 = le stesse regole anche per gli endpoint di prima


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def disp_da_ip(ip):
    """il dispositivo registrato che ha questo indirizzo (come fa già il pannello per l'estensione), oppure None."""
    if not ip:
        return None
    return next((x for x in liste.dispositivi() if ip == x.get("ip") or ip in (x.get("ips") or [])), None)


def _pausa_rete_info():
    """com'è la pausa della Rete adesso, dalla pausa di Blocky + il file che ricorda chi l'ha avviata."""
    s = filtro.stato_api()
    if not s.get("raggiungibile"):
        return None, False
    p = s.get("pausa")
    if not p:
        return {"attiva": False, "fino": None, "fino_ms": None, "resta_sec": 0, "senza": False, "da": ""}, True
    senza = bool(p.get("senza_scadenza"))
    resta = int(p.get("resta_sec") or 0)
    fino = None if senza else time.time() + resta
    da = ""
    try:
        with open(PAUSA_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if (senza and d.get("senza")) or (not senza and not d.get("senza") and abs((d.get("fine", 0) - time.time()) - resta) < 90):
            da = str(d.get("da") or "")
    except Exception:
        pass
    return {"attiva": True, "fino": _iso(fino), "fino_ms": int(fino * 1000) if fino else None, "resta_sec": resta, "senza": senza, "da": da}, True


def pausa_stato(chi=None):
    """lo stato unico: la Rete e i dispositivi in pausa. chi = (ip, dispositivo, via_ingresso) di chi chiede (per «puoi_rete»)."""
    rete, ok = _pausa_rete_info()
    dispositivi = []
    for p in liste.pause_dispositivi():
        resta = 0 if p["senza"] else max(0, int(p["fino"] - time.time() + 0.999))
        dispositivi.append({"id": p["id"], "nome": p["nome"], "fino": _iso(p["fino"]), "fino_ms": int(p["fino"] * 1000) if p["fino"] else None,
                            "resta_sec": resta, "senza": p["senza"], "da": p["da"], "durata": p["durata"], "casa": p["casa"], "cloud": p["cloud"]})
    out = {"ok": True, "raggiungibile": ok, "ora": _iso(time.time()),
           "rete": rete if rete is not None else {"attiva": False, "fino": None, "fino_ms": None, "resta_sec": 0, "senza": False, "da": ""},
           "dispositivi": dispositivi, "ci_sono_proprietari": bool(liste.proprietari())}
    if chi is not None:
        out["puoi_rete"] = regola_rete(chi) is None
        out["chiamante"] = {"nome": chi[1].get("nome", "") if chi[1] else "", "proprietario": bool(chi[1] and chi[1].get("proprietario"))}
    return out


def regola_rete(chi, durata=None):
    """None se chi chiede può mettere in pausa la Rete (con questa durata); altrimenti (codice HTTP, risposta)."""
    if durata == "senza":
        return 400, {"ok": False, "codice": "senza_non_ammesso_rete", "testo": "La Rete si può mettere in pausa al massimo fino a domani, non senza scadenza."}
    if not liste.proprietari():
        return None   # nessun proprietario marcato: come prima, da ovunque
    ip, x, via_ingresso = chi
    if x is not None and x.get("proprietario"):
        return None
    if x is None and via_ingresso:
        return None   # Home Assistant (già autenticato) senza un dispositivo riconoscibile: amministratore
    return 403, {"ok": False, "codice": "solo_proprietario", "testo": "Solo un dispositivo proprietario può mettere in pausa tutta la Rete."}


def pausa_api(percorso, dati, chi):
    """percorso: /pannello/pausa | /pannello/pausa/prolunga | /pannello/pausa/riprendi. Ritorna (codice HTTP, JSON)."""
    ambito = str(dati.get("ambito") or "").strip().lower()
    if ambito not in ("dispositivo", "rete"):
        return 400, {"ok": False, "codice": "ambito_non_valido", "testo": "Ambito non valido: «dispositivo» oppure «rete»."}
    da = chi[1].get("nome", "") if chi[1] else "Pannello"
    rif = dati.get("dispositivo")
    azione = percorso.rsplit("/", 1)[-1]
    if ambito == "dispositivo":
        if not str(rif or "").strip():
            return 400, {"ok": False, "codice": "dispositivo_mancante", "testo": "Indica il dispositivo (nome o indirizzo)."}
        if azione == "prolunga":
            ok, t, code, err = liste.prolunga_pausa_dispositivo(rif, dati.get("minuti"))
        elif azione == "riprendi":
            ok, t, code, err = liste.riprendi_dispositivo(rif)
        else:
            ok, t, code, err = liste.pausa_dispositivo(rif, str(dati.get("durata") or "").strip().lower(), da)
        if not ok:
            return code, {"ok": False, "codice": err, "testo": t}
        return 200, dict(pausa_stato(chi), testo=t)
    # ── Rete ──
    if azione == "riprendi":   # riprendere è sempre permesso: rimette la protezione
        t = pausa_cambiata(filtro.riprendi())
        try:
            os.remove(PAUSA_FILE)
        except OSError:
            pass
        if t.startswith("Impossibile"):
            return 502, {"ok": False, "codice": "motore_non_raggiungibile", "testo": t}
        return 200, dict(pausa_stato(chi), testo=t)
    if azione == "prolunga":
        negata = regola_rete(chi)
        if negata:
            return negata
        try:
            m = int(float(str(dati.get("minuti")).strip().replace(",", ".")))
        except (TypeError, ValueError):
            return 400, {"ok": False, "codice": "minuti_non_validi", "testo": "Indica di quanti minuti prolungare."}
        if not 1 <= m <= liste.MAX_PROLUNGA_MIN:
            return 400, {"ok": False, "codice": "minuti_non_validi", "testo": "Si può prolungare da 1 a %d minuti." % liste.MAX_PROLUNGA_MIN}
        rete, ok = _pausa_rete_info()
        if not ok:
            return 502, {"ok": False, "codice": "motore_non_raggiungibile", "testo": "Il filtro non risponde: riprova tra poco."}
        if not rete["attiva"]:
            return 409, {"ok": False, "codice": "non_in_pausa", "testo": "La Rete non è in pausa."}
        if rete["senza"]:
            return 409, {"ok": False, "codice": "gia_senza_scadenza", "testo": "La Rete è già senza scadenza."}
        tetto = max(1, int(filtro.fine_domani() - time.time()))
        totale = rete["resta_sec"] + m * 60
        limitata = totale > tetto
        totale = min(totale, tetto)
        t = _rete_applica(totale, rete["da"] or da)
        if t.startswith("Impossibile"):
            return 502, {"ok": False, "codice": "motore_non_raggiungibile", "testo": t}
        return 200, dict(pausa_stato(chi), testo=t, limitata=limitata)
    durata = str(dati.get("durata") or "").strip().lower()
    if durata not in ("30s", "10m", "1h", "domani", "senza"):
        return 400, {"ok": False, "codice": "durata_non_valida", "testo": "Durata non valida."}
    negata = regola_rete(chi, durata)
    if negata:
        return negata
    t = pausa_scelta(durata, da)
    if t.startswith("Impossibile"):
        return 502, {"ok": False, "codice": "motore_non_raggiungibile", "testo": t}
    return 200, dict(pausa_stato(chi), testo=t)


# ───────────── 0.9.4: Attività in tempo reale della pausa sull'iPhone, chiusa e aggiornata da Casa (APNs) ─────────────
# POST /pannello/pausa/attivita {token, ambito, dispositivo, ambiente: production|sandbox, inizio_ms, fine_ms}
# Un giro ogni 5 secondi confronta ogni Attività registrata con la pausa vera: pausa finita (ripresa da qualsiasi parte o scaduta)
# → «end»; scadenza cambiata (+10 min da un altro dispositivo) → «update». Senza chiave APNs non succede niente.
ATTIVITA_FILE = os.path.join(filtro.DATA, "attivita-push.json")
_l_att = threading.Lock()


def _attivita_leggi():
    try:
        d = json.load(open(ATTIVITA_FILE, encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _attivita_scrivi(d):
    tmp = ATTIVITA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        json.dump(d, h)
    os.replace(tmp, ATTIVITA_FILE)
    try:
        os.chmod(ATTIVITA_FILE, 0o600)
    except OSError:
        pass


def attivita_registra(dati):
    tok = str(dati.get("token") or "").strip().lower()
    ambito = str(dati.get("ambito") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32,256}", tok) or ambito not in ("dispositivo", "rete"):
        return 400, {"ok": False, "testo": "Dati non validi."}
    try:
        inizio = float(dati.get("inizio_ms") or 0) / 1000.0
        fine = float(dati.get("fine_ms") or 0) / 1000.0
    except (TypeError, ValueError):
        return 400, {"ok": False, "testo": "Dati non validi."}
    rec = {"ambito": ambito, "dispositivo": str(dati.get("dispositivo") or "")[:80],
           "ambiente": "sandbox" if dati.get("ambiente") == "sandbox" else "production",
           "inizio": inizio or time.time(), "fine": fine, "creata": time.time()}
    with _l_att:
        d = _attivita_leggi()
        d = {k: v for k, v in d.items() if time.time() - float(v.get("creata") or 0) < 9 * 3600}   # iOS le tiene al massimo 8 ore
        d[tok] = rec
        _attivita_scrivi(d)
    return 200, {"ok": True, "push": bool(apns.impostazioni())}


def _pausa_di(st, rec):
    """la pausa che l'Attività racconta, com'è adesso: (attiva, fine in secondi o None se senza scadenza, da)."""
    if rec["ambito"] == "rete":
        r = st.get("rete") or {}
        if not r.get("attiva"):
            return False, None, ""
        return True, (r.get("fino_ms") or 0) / 1000.0 or None, r.get("da") or ""
    rif = rec.get("dispositivo", "").lower()
    for p in st.get("dispositivi") or []:
        if rif and rif in (str(p.get("id", "")).lower(), str(p.get("nome", "")).lower()):
            attiva = p.get("senza") or (p.get("resta_sec") or 0) > 0
            return bool(attiva), (p.get("fino_ms") or 0) / 1000.0 or None, p.get("da") or ""
    return False, None, ""


def controlla_attivita(invia=None, adesso=None):
    """un giro: ritorna [(token, evento, esito)] (per le prove)."""
    invia = invia or apns.invia
    adesso = adesso or time.time()
    with _l_att:
        d = _attivita_leggi()
        if not d:
            return []
        st = pausa_stato()
        fatti, cambiato = [], False
        for tok, rec in list(d.items()):
            attiva, fine, da = _pausa_di(st, rec)
            if adesso - float(rec.get("creata") or 0) > 9 * 3600:
                d.pop(tok, None)
                cambiato = True
                continue
            if not attiva or (fine and fine <= adesso):
                ok, motivo = invia(tok, apns.carico_fine(rec["inizio"], rec["fine"] or adesso, rec["ambito"], adesso), rec["ambiente"])
                fatti.append((tok, "end", ok, motivo))
                d.pop(tok, None)
                cambiato = True
            elif fine and abs(fine - float(rec.get("fine") or 0)) > 2:
                ok, motivo = invia(tok, apns.carico_aggiorna(rec["inizio"], fine, rec["ambito"], da, adesso), rec["ambiente"])
                fatti.append((tok, "update", ok, motivo))
                rec["fine"] = fine
                cambiato = True
                if not ok and ("BadDeviceToken" in motivo or "Unregistered" in motivo or "ExpiredToken" in motivo):
                    d.pop(tok, None)
        if cambiato:
            _attivita_scrivi(d)
    for tok, ev, ok, motivo in fatti:
        print("Filtreo: Attività della pausa → %s %s%s" % (ev, "inviato" if ok else "non inviato", "" if ok else " (%s)" % motivo), flush=True)
    return fatti


def giro_attivita(ogni=5):
    time.sleep(8)
    while True:
        try:
            if os.path.exists(ATTIVITA_FILE):
                controlla_attivita()
        except Exception as e:   # mai fermarsi
            print("Filtreo: controllo delle Attività non riuscito (%s)" % type(e).__name__, flush=True)
        time.sleep(ogni)


def _rete_applica(sec, da):
    """mette la Rete in pausa per sec secondi da adesso (usato da «prolunga»)."""
    sec = max(1, int(sec))
    if sec < 60:
        t = filtro.pausa_secondi(sec)
    else:
        m = -(-sec // 60)
        filtro._togli_timer()
        _t, err = filtro._api("/api/blocking/disable?duration=%dm" % m)
        if err:
            return "Impossibile mettere in pausa (%s)." % err
        t = "Filtro in pausa fino alle %s." % (datetime.now() + timedelta(seconds=sec)).strftime("%H:%M")
    if t.startswith("Filtro in pausa"):
        _segna_pausa(sec, da)
        pausa_cambiata()
    return t


# ───────────── resoconto (ultimi giorni) e controllo della protezione ─────────────
RES_CACHE = os.path.join(filtro.DATA, "resoconto-cache.json")


def _giorno(percorso, nomi_ip, nomi_dns):
    tot = bloc = 0
    perdisp, aziende, visti_ip, visti_nome = {}, Counter(), set(), set()
    with open(percorso, encoding="utf-8", errors="replace") as f:
        for riga in f:
            c = riga.rstrip("\n").split("\t")
            if len(c) < 6:
                continue
            r = next((k for k in range(1, len(c)) if MOTIVO.match(c[k])), None)
            if r is None:
                continue
            nome_c = c[2].strip() if len(c) > 2 else ""
            if nome_c.startswith("filtreo-prova-"):
                continue
            dom = next((c[k].rstrip(".") for k in range(r + 1, len(c)) if HOST.match(c[k])), None)
            visti_ip.add(c[1])
            if nome_c in nomi_dns:
                visti_nome.add(nome_c)
            chi = nomi_dns.get(nome_c) or nomi_ip.get(c[1]) or "Altri"
            d = perdisp.setdefault(chi, [0, 0])
            tot += 1
            d[0] += 1
            if c[r].startswith("BLOCKED") and dom:
                bloc += 1
                d[1] += 1
                aziende[azienda(dom) or "Altri"] += 1
    return {"richieste": tot, "bloccate": bloc, "dispositivi": perdisp, "aziende": dict(aziende.most_common(12)),
            "ip": sorted(visti_ip), "nomi": sorted(visti_nome)}


def resoconto(giorni=7):
    """riassunto dei giorni scorsi dal registro: i giorni finiti si calcolano una volta e restano in cache."""
    giorni = max(1, min(30, giorni))
    try:
        cache = json.load(open(RES_CACHE, encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    nomi_ip = _nomi_dispositivi()
    dd = {x["id"]: x["nome"] for x in liste.dispositivi()}
    nomi_dns = {n: dd.get(v.get("disp"), n) for n, v in dnsp.voci()}
    oggi = date.today().isoformat()
    out, cambiata = [], False
    for f in sorted(glob.glob(os.path.join(filtro.REGISTRO, "*_ALL.log")))[-giorni:]:
        g = os.path.basename(f)[:10]
        if g != oggi and g in cache:
            out.append(dict(cache[g], giorno=g))
            continue
        try:
            v = _giorno(f, nomi_ip, nomi_dns)
        except OSError:
            continue
        if g != oggi:
            cache[g] = v
            cambiata = True
        out.append(dict(v, giorno=g))
    if cambiata:
        for k in sorted(cache)[:-31]:
            cache.pop(k, None)
        try:
            with open(RES_CACHE + ".tmp", "w", encoding="utf-8") as h:
                json.dump(cache, h)
            os.replace(RES_CACHE + ".tmp", RES_CACHE)
        except OSError:
            pass
    # Cloudflare: si somma ai blocchi di Casa giorno per giorno (la cache dei giorni finiti resta solo di Casa)
    giorni_cf = conti_cloudflare()
    dd_cf = liste.dispositivi()
    voci_cf = list(dnsp.voci())
    tot = bl = bl_casa = bl_cf = 0
    perd, perd_cf, az = Counter(), Counter(), Counter()
    righe = []
    for x in out:
        cf = giorni_cf.get(x["giorno"], {})
        cfb, cfr = sum(v[0] for v in cf.values()), sum(v[1] for v in cf.values())
        righe.append({"giorno": x["giorno"], "richieste": x["richieste"] + cfr, "bloccate": x["bloccate"] + cfb,
                      "casa": x["bloccate"], "cloudflare": cfb, "totale": x["bloccate"] + cfb})
        tot += x["richieste"] + cfr
        bl_casa += x["bloccate"]
        bl_cf += cfb
        for k, v in x["dispositivi"].items():
            perd[k] += v[1]
        for did, v in cf.items():
            perd_cf[risolvi_cf(did, dd_cf, voci_cf) or "Altri"] += v[0]
        az.update(x["aziende"])
    bl = bl_casa + bl_cf
    nomi_d = set(perd) | set(perd_cf)
    dett = sorted(({"nome": k, "bloccate": perd[k] + perd_cf[k], "casa": perd[k], "cloudflare": perd_cf[k], "totale": perd[k] + perd_cf[k]}
                   for k in nomi_d if k != "Altri"), key=lambda d: -d["totale"])[:8]
    return {"giorni": righe,
            "richieste": tot, "bloccate": bl, "casa": bl_casa, "cloudflare": bl_cf, "totale": bl, "percento": round(100 * bl / tot) if tot else 0,
            "dispositivi": dett,
            "aziende": [{"nome": k, "volte": v} for k, v in az.most_common(8) if k != "Altri"],
            "visti_ip": sorted({i for x in out for i in x["ip"]}), "visti_nomi": sorted({n for x in out for n in x["nomi"]})}


def _chiedi_doh_dettaglio(nome_client, dominio, volte=2):
    """una domanda vera al motore come se arrivasse dal dispositivo di prova. Ritorna (esito, dettaglio):
    esito «bloccato» | «passa» | «errore»; dettaglio dice PERCHÉ «errore» (motore che non risponde, codice HTTP, SERVFAIL…).
    Un secondo tentativo dopo mezzo secondo: un motore che sta rileggendo le liste non è un guasto."""
    import struct
    import urllib.error as ue
    import urllib.request as ur
    q = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(x)]) + x.encode() for x in dominio.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
    det = ""
    for i in range(max(1, volte)):
        if i:
            time.sleep(0.5)
        try:
            d = ur.urlopen(ur.Request(filtro.API + "/dns-query/" + nome_client, data=q, headers={"Content-Type": "application/dns-message"}), timeout=6).read()
        except ue.HTTPError as e:
            det = "risposta HTTP %s dal filtro" % e.code
            continue
        except Exception as e:
            det = "il filtro non risponde (%s)" % str(getattr(e, "reason", None) or type(e).__name__)[:60]
            continue
        if len(d) < 12:
            det = "risposta troppo corta"
            continue
        if (d[3] & 15) == 2:
            det = "il filtro ha risposto SERVFAIL (DNS a monte non raggiungibile?)"
            continue
        an = struct.unpack(">H", d[6:8])[0]
        return ("bloccato" if an and d[-4:] == bytes(4) else "passa"), ""
    return "errore", det


def _chiedi_doh(nome_client, dominio):
    return _chiedi_doh_dettaglio(nome_client, dominio)[0]


PROVA_PUB = ("ads.pubmatic.com", "ib.adnxs.com")      # pubblicità vera: sempre bloccata (anche con strumenti di lavoro)
PROVA_SITO = ("www.wikipedia.org", "www.google.com")   # siti normali: devono passare


def genere(x):
    """che cosa è il dispositivo, per gli avvisi e le icone: «nodo» (Casa stessa), «server», «tv», «iot», «android» o «altro».
    Vale il campo «tipo» se c'è, altrimenti il nome (le regole stanno in filtreo_liste.genere)."""
    return liste.genere(x)


def _coperto_da(d, voci):
    p = d.split(".")
    return any(v in voci or "*." + v in voci for v in (".".join(p[i:]) for i in range(len(p) - 1)))


def regole_prova(g):
    """che cosa dicono le REGOLE del gruppo g (non una richiesta): (la pubblicità di prova è nell'elenco dei blocchi e non tra i permessi?,
    il nome «filtreo-prova-g» è nella config del filtro?). Serve a capire se una prova «passa» per colpa delle regole o della prova."""
    def voci(nome):
        try:
            return {r.strip().lower() for r in open(os.path.join(liste.LISTE, nome), encoding="utf-8") if r.strip() and not r.startswith("#")}
        except OSError:
            return None
    den, ok = voci("dev-%s.txt" % g), voci("dev-%s-ok.txt" % g)
    blocca = den is not None and all(("/.*/" in den or _coperto_da(d, den)) and not (ok and _coperto_da(d, ok)) for d in PROVA_PUB)
    try:
        # la config può avere il nome tra virgolette (modello) o senza (riscritta con la config di base del Jetson)
        mappato = re.search(r"^\s*[\"']?filtreo-prova-%s[\"']?\s*:" % re.escape(g), open(CONFIG, encoding="utf-8").read(), re.M) is not None
    except OSError:
        mappato = False
    permessa = bool(ok) and any(_coperto_da(d, ok) for d in PROVA_PUB)
    return blocca, mappato, permessa


def controllo():
    """per ogni dispositivo: rete di casa (visto oggi/di recente), fuori casa (profilo usato), prova vera del blocco."""
    r = resoconto(7)
    ip_visti, nomi_visti = set(r["visti_ip"]), set(r["visti_nomi"])
    try:
        oggi = _giorno(_oggi_file(), {}, {n: n for n, _ in dnsp.voci()})
        ip_oggi, nomi_oggi = set(oggi["ip"]), set(oggi["nomi"])
    except OSError:
        ip_oggi, nomi_oggi = set(), set()
    prof = {}
    for n, v in dnsp.voci():
        prof.setdefault(v.get("disp"), []).append(n)
    cache_prova = {}
    out = []
    for x in liste.dispositivi():
        g = x["id"] if x.get("proprie") else next((y["id"] for y in liste.dispositivi() if y.get("principale")), "casa")
        if g not in cache_prova:
            pub_d = [_chiedi_doh_dettaglio("filtreo-prova-" + g, d) for d in PROVA_PUB]
            sit_d = [_chiedi_doh_dettaglio("filtreo-prova-" + g, d) for d in PROVA_SITO]
            pub, sit = [x[0] for x in pub_d], [x[0] for x in sit_d]
            cache_prova[g] = {"pubblicita": "ok" if all(p == "bloccato" for p in pub) else ("errore" if "errore" in pub else "no"),
                              "internet": "ok" if all(p == "passa" for p in sit) else ("errore" if all(p == "errore" for p in sit) else "no"),
                              "dettaglio": next((x[1] for x in pub_d + sit_d if x[1]), "")}
        ips = [i for i in [x.get("ip")] + list(x.get("ips") or []) if i]
        casa = "oggi" if ips and set(ips) & ip_oggi else ("settimana" if ips and set(ips) & ip_visti else ("mai" if ips else "nessuno"))
        nn = prof.get(x["id"], [])
        fuori = "nessuno" if not nn else ("oggi" if set(nn) & nomi_oggi else ("settimana" if set(nn) & nomi_visti else "mai"))
        senza = x.get("modo") in ("spento",) if x.get("proprie") else False
        gen = genere(x)
        avvisi = []
        if senza:
            avvisi.append("In «Senza filtro»: non protetto finché non viene ripristinato il livello.")
        if gen == "nodo":
            pass   # è Casa stessa: niente avvisi «fuori casa»
        elif gen in ("tv", "iot", "server"):
            # restano in casa: solo l'avviso «non lo vedo da una settimana»
            if casa == "mai":
                avvisi.append("Nessuna richiesta da 7 giorni: dispositivo inattivo, oppure usa un filtro di rete proprio (frequente in TV e telecamere).")
        elif gen == "android":
            if casa == "mai":
                avvisi.append("Nessuna richiesta da 7 giorni: dispositivo inattivo, oppure un'altra app (VPN, altro blocco pubblicità) ha la precedenza.")
            if dnsp.attivo() or nn:
                avvisi.append("Fuori casa: su Android serve un'app di Filtreo (in arrivo).")
        else:
            if casa == "mai" and fuori in ("nessuno", "mai"):
                avvisi.append("Nessuna richiesta da 7 giorni: dispositivo inattivo, fuori casa senza configurazione, oppure un'altra app (VPN, altro blocco pubblicità) ha la precedenza.")
            if nn and fuori == "mai":
                avvisi.append("Configurazione «fuori casa» creata ma mai utilizzata: va installata sul dispositivo (oppure una VPN attiva ha la precedenza).")
            if not nn and dnsp.attivo():
                avvisi.append("Non protetto fuori casa: crea la configurazione dalle impostazioni del dispositivo.")
        p = dict(cache_prova[g])
        if p["pubblicita"] == "errore" and p["internet"] == "errore" and not senza:
            # nessuna risposta alla prova di questo gruppo: si dice perché (e se il nome di prova è già nella config del filtro)
            _b, mappato, _p = regole_prova(g)
            avvisi.append("Prova non eseguita: %s%s. Riprova tra un minuto." % (
                p.get("dettaglio") or "il filtro non ha risposto",
                "" if mappato else "; il nome di prova del dispositivo non è ancora nella configurazione del filtro"))
        if p["pubblicita"] == "no" and not senza:
            # prima di dare l'allarme: le regole del gruppo (liste scritte e nome di prova nella config) dicono la stessa cosa?
            blocca, mappato, permessa = regole_prova(g)
            nome_m = liste.modo_di(g).get("nome", "")
            if not mappato:
                p["pubblicita"] = "errore"
                avvisi.append("Test non eseguito: il nome di prova del dispositivo non è ancora nella configurazione del filtro (aggiornamento al prossimo riavvio).")
            elif blocca:
                # le regole bloccano ma la richiesta di prova è passata: non è «pubblicità che passa col suo dispositivo»
                p["pubblicita"] = "errore"
                avvisi.append("Test non conclusivo: le regole «%s» bloccano la pubblicità, ma la richiesta di prova è stata consentita. Filtri forse non ancora ricaricati: riprova tra 1 minuto." % nome_m
                              if gen != "nodo" else
                              "Test non conclusivo: le regole «%s» di Casa bloccano la pubblicità, ma la richiesta di prova è stata consentita. Filtri forse non ancora ricaricati: riprova tra 1 minuto." % nome_m)
            elif permessa:
                # non è un guasto: un permesso (strumenti di lavoro o permesso scritto a mano) copre l'indirizzo di prova
                p["pubblicita"] = "errore"
                avvisi.append("Test non conclusivo: un indirizzo di prova è tra i servizi consentiti di «%s». Il resto della pubblicità è bloccato." % nome_m
                              if gen != "nodo" else
                              "Test non conclusivo: Casa è in «%s», dove un indirizzo di prova è tra i servizi consentiti." % nome_m)
            else:
                avvisi.append("Test di blocco non superato: i filtri del livello «%s» non bloccano la pubblicità. Verifica livello e filtri." % nome_m)
        if p["internet"] == "no" and not liste._stretto(g):   # «Isolato» blocca i siti normali per scelta
            avvisi.append("Test non superato: un sito comune risulta bloccato. Verifica siti bloccati e filtri.")
        out.append({"id": x["id"], "nome": x["nome"], "casa": casa, "fuori": fuori, "pubblicita": "spento" if senza else p["pubblicita"],
                    "internet": p["internet"], "avvisi": avvisi, "genere": gen, "prova_dettaglio": p.get("dettaglio", "")})
    return {"dispositivi": out, "quando": datetime.now().strftime("%H:%M")}


# ───────────── config (liste, eccezioni, ecc.) ─────────────
def _leggi_config():
    try:
        testo = open(CONFIG, encoding="utf-8").read()
    except OSError:
        return {}
    try:
        import yaml  # type: ignore
        y = yaml.safe_load(testo) or {}
        blk = y.get("blocking") or {}
        den = blk.get("denylists") or {}
        refresh = ((blk.get("loading") or {}).get("refreshPeriod")) or "12h"
        liste = {g: [s for s in (v or []) if isinstance(s, str) and s.startswith("http")] for g, v in den.items()}
        cust = (y.get("customDNS") or {}).get("zone") or ""
        regole = re.findall(r"^\s*([a-z0-9.*_-]+)\.\s", cust, re.M)
        return {"liste": {g: u for g, u in liste.items() if u}, "refresh": refresh, "regole": regole}
    except Exception:
        refresh = (re.search(r"refreshPeriod:\s*(\S+)", testo) or [None, "12h"])[1]
        urls = [u for u in re.findall(r"-\s*(https?://\S+)", testo) if "dns-query" not in u]
        return {"liste": {"casa": urls} if urls else {}, "refresh": refresh, "regole": []}


def _nome_lista(url):
    base = url.rstrip("/").split("/")[-1].replace(".txt", "")
    return {"pro": "Hagezi Pro", "tif.medium": "TIF medio", "tif.mini": "TIF mini",
            "light": "Hagezi Light", "oisd_small": "OISD Small"}.get(base, base)


def _lista_file(nome):
    return [r.strip() for r in filtro._righe(nome) if r.strip() and not r.strip().startswith("#")]


def config_json():
    e = liste.elenco()
    return {"refresh": "12h", "fonti": e["fonti"], "disp": e["dispositivi"], "nuovi": e["nuovi"], "gruppi": e["gruppi"],
            "senza_principale": e.get("senza_principale", False), "sentinella": liste.sentinella(),
            "manuale": _lista_file("blocca.txt"),
            "eccezioni": sorted(x for x in set(_lista_file(BIANCA)) | set(_lista_file("sblocca.txt")) | set(_lista_file("anti-rilevamento.txt"))
                               if x.lstrip("*.") not in liste.ESCHE_OK),
            "esche": sorted(liste.ESCHE_OK),
            "ignorate": liste._eccezioni(con_scarti=True)[1],
            "dnsp": dnsp_stato(),
            "modalita": e["modalita"], "categorie": e["categorie"], "servizi": e["servizi"], "servizi_casa": e["servizi_casa"], "spento_minuti": e["spento_minuti"],
            "pausa": e["pausa"], "app": e["app"], "famiglia": e["famiglia"], "fuori": _pannello_fuori(),
            "widget": bool(CHIAVE_BARRA and _modello_widget()),
            "avvisi": rn.avvisi_stato(), "versione_nodo": rn.stato_versione(), "copia_quando": rn.ultima_copia()}


def estensione_stato(ip):
    """cosa deve fare l'estensione del browser su QUESTO dispositivo (riconosciuto dall'indirizzo):
    la stessa modalità scelta nel pannello. Così il pannello è uno solo."""
    e = liste.elenco()
    d = next((x for x in e["dispositivi"] if ip and (x.get("ip") == ip or ip in (x.get("ips") or []))), None)
    if not d:
        d = next((x for x in e["dispositivi"] if x.get("principale")), {})
    if d and not d.get("proprie"):   # «fa come il principale»
        d = next((x for x in e["dispositivi"] if x.get("principale")), d)
    m = liste.modo_di(d["id"]) if d.get("id") else {}
    s = stato()
    pausa = s.get("pausa") or None
    nomi = {x["id"]: x["nome"] for x in e.get("servizi") or []}
    aperti = [nomi.get(i, i) for i in (m.get("lavoro") or [])]
    # chi filtra questo dispositivo (come nella pagina del dispositivo): Casa, oppure Cloudflare se ha il suo profilo
    chi = "cloudflare" if d.get("id") and liste.genere(d) not in ("nodo", "android") and any(v.get("disp") == d["id"] for _n, v in dnsp.voci()) else "casa"
    return {"versione": VERSIONE, "dispositivo": d.get("nome", ""), "modo": m.get("nome", ""),
            "lavoro": bool(m.get("lavoro")), "fuori": _pannello_fuori(), "bloccate_oggi": int(((s.get("oggi") or {}).get("bloccate")) or 0),
            "acceso": bool(s.get("acceso")), "pausa_fino": (pausa or {}).get("fino", "") if pausa else "",
            "chi": chi, "casa_risponde": bool(s.get("raggiungibile", True)),
            "strumenti": aperti}


def chi_chiama_disp(did):
    """domini più richiesti oggi da un dispositivo: dai suoi indirizzi di casa e dai nomi dei suoi profili «fuori casa»."""
    x = next((y for y in liste.dispositivi() if y["id"] == did), None)
    if not x:
        return {"richieste": 0, "bloccate": 0, "domini": []}
    ips = [i for i in [x.get("ip")] + list(x.get("ips") or []) if i]
    if liste.e_nodo(x):
        ips += [i for i in liste.nodo_ips() if i not in ips]
    nomi = [n for n, v in dnsp.voci() if v.get("disp") == did]
    return liste.chi_chiama(ips, nomi)


def _bloccate_oggi():
    try:
        return int(((stato().get("oggi") or {}).get("bloccate")) or 0)
    except Exception:
        return 0


def _codice_fuori():
    try:
        c = json.load(open(os.path.join(liste.DATA, "pannello-fuori.json"), encoding="utf-8")).get("codice", "")
    except (OSError, ValueError):
        return ""
    return c if re.fullmatch(r"[a-f0-9]{32,64}", c or "") else ""


def _paracadute_conosce(c):
    """il paracadute sa già di questo link? (lo scrive paracadute-sync.py: solo l'impronta, mai il codice)"""
    try:
        st = json.load(open(os.path.join(liste.DATA, "paracadute-kv.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return False
    import hashlib
    return bool(c) and st.get("pannello_aperto") == hashlib.sha256(c.encode()).hexdigest()


def _pannello_fuori():
    """link segreto del pannello per fuori casa (lo crea il nodo: jetson/pannello-fuori-casa.sh).
    Se il paracadute lo conosce, il link passa dal paracadute: con casa accesa porta al pannello di casa,
    con casa spenta apre la pagina di riserva. Altrimenti è il link diretto di casa."""
    c = _codice_fuori()
    if not c:
        return ""
    if dnsp.PARACADUTE and _paracadute_conosce(c):
        return "%s/p/%s/" % (dnsp.PARACADUTE, c)
    base = os.environ.get("FILTREO_DOH_URL", "").strip().rstrip("/")
    return "%s/p/%s/" % (base, c) if base else ""


# ───────────── widget per l'iPhone (Scriptable), già pronto da scaricare ─────────────
def _modello_widget():
    qui = os.path.dirname(os.path.abspath(__file__))
    for p in (os.environ.get("FILTREO_WIDGET_MODELLO", ""), os.path.join(qui, "..", "widget-iphone", "Filtreo.js"),
              os.path.join(qui, "widget-iphone", "Filtreo.js"), "/opt/filtreo/widget-iphone/Filtreo.js"):
        # (nell'add-on il pannello aggiornato gira da /share/filtreo/app: il modello resta dentro l'add-on)
        if p and os.path.isfile(p):
            return p
    return ""


def widget_pronto():
    """il file Filtreo.js con gli indirizzi di questo nodo già dentro. None se il widget non si può fare."""
    m = _modello_widget()
    if not m or not CHIAVE_BARRA:
        return None
    base = os.environ.get("FILTREO_WIDGET_BASE", "").strip().rstrip("/")
    if not base:   # nome Tailscale del nodo (dall'indirizzo pubblico) + porta della barra
        h = re.sub(r"^https?://", "", os.environ.get("FILTREO_DOH_URL", "").strip()).split("/")[0].split(":")[0]
        base = "http://%s:%d" % (h, PORTA_BARRA) if h else ""
    c = _codice_fuori()
    fuori = "%s/p/%s" % (dnsp.PARACADUTE, c) if dnsp.PARACADUTE and c else ""
    pannello = (fuori + "/") if fuori else (_pannello_fuori() or "")
    t = open(m, encoding="utf-8").read()
    for k, v in (("__BASE__", base), ("__BASE_FUORI__", fuori), ("__CHIAVE__", CHIAVE_BARRA), ("__PANNELLO__", pannello)):
        if v:
            t = t.replace('"%s"' % k, json.dumps(v), 1)
    return t


# ───────────── pagina dal QR: /pannello/telefono (iPhone o Android) ─────────────
# La apre l'assistente di installazione con un codice QR. Riconosce il telefono dall'user agent (con il link per passare all'altro).
# iPhone: profilo (creato qui se manca), widget, Safari pulito. Android: istruzioni per Tailscale. Stessa grafica del pannello;
# il carattere Figtree non si duplica: lo serve /pannello/figtree.woff2, estratto dalla pagina del pannello.
# Tutti i link sono relativi: funziona uguale da Home Assistant, dal Tailscale diretto e dal link fuori casa /p/<codice>/.
TELEFONO = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "telefono.html"), encoding="utf-8").read()
_font = {"b": None}
_IC_SCARICA = ('<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" '
               'stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>'
               '<polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>')
LINK_SCRIPTABLE = "https://apps.apple.com/it/app/scriptable/id1405459188"
LINK_USERSCRIPTS = "https://apps.apple.com/it/app/userscripts/id1463298887"


def font_figtree():
    """i byte di Figtree (woff2), presi dal pannello: nessuna copia del carattere da tenere allineata. None se non si trova."""
    if _font["b"] is None:
        m = re.search(r"url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)", PAGINA)
        try:
            _font["b"] = base64.b64decode(m.group(1)) if m else b""
        except Exception:
            _font["b"] = b""
    return _font["b"] or None


def _userscript():
    """percorso di filtreo.user.js (Filtro web) se questo filtro può servirlo, altrimenti ''. Non si copia: si legge dove sta."""
    qui = os.path.dirname(os.path.abspath(__file__))
    for p in (os.environ.get("FILTREO_USERSCRIPT", ""), os.path.join(qui, "..", "estensione", "safari-userscript", "filtreo.user.js"),
              os.path.join(qui, "..", "..", "..", "estensione", "safari-userscript", "filtreo.user.js"),   # dal progetto, a Mac
              os.path.join(qui, "safari-userscript", "filtreo.user.js"), "/opt/filtreo/safari-userscript/filtreo.user.js"):
        if p and os.path.isfile(p):
            return p
    return ""


def telefono_per(user_agent, scelta=""):
    """«iphone» o «android»: vale la scelta esplicita (?per=…), poi l'user agent; tutto il resto (Mac, computer) vede la pagina dell'iPhone."""
    if scelta in ("iphone", "android"):
        return scelta
    return "android" if re.search(r"android", user_agent or "", re.I) else "iphone"


def pagina_telefono(per):
    t = TELEFONO
    # tengo solo la parte del telefono giusto
    altro = "android" if per == "iphone" else "iphone"
    t = re.sub(r"<!--#%s-->.*?<!--/#%s-->\n?" % (altro, altro), "", t, flags=re.S)
    t = re.sub(r"<!--/?#(iphone|android)-->\n?", "", t)
    if dnsp.attivo():
        b_prof = '<button type="button" class="btn pri" id="profilo" data-nome="iPhone">%s<span>Installa la configurazione</span></button>' % _IC_SCARICA
    else:
        b_prof = ('<span class="btn" aria-disabled="true">%s<span>Installa la configurazione</span></span>'
                  '<p class="d2">Configurazione non ancora attiva su questa Casa.</p>') % _IC_SCARICA
    if widget_pronto() is not None:
        b_wid = '<a class="btn" href="widget" download="Filtreo.js">%s<span>Scarica il widget</span></a>' % _IC_SCARICA
    else:
        b_wid = '<span class="btn" aria-disabled="true">%s<span>Scarica il widget</span></span>' % _IC_SCARICA
    n_wid = ('<span style="display:block">Serve l’app gratuita <a href="%s" target="_blank" rel="noopener noreferrer">Scriptable</a>.</span>'
             '<span style="display:block">La trovi sull’App Store.</span>') % LINK_SCRIPTABLE
    if _userscript():
        b_saf = '<a class="btn" href="safari/filtreo.user.js">%s<span>Scarica per Safari</span></a>' % _IC_SCARICA
        n_saf = ('<span style="display:block">Serve l’app gratuita <a href="%s" target="_blank" rel="noopener noreferrer">Userscripts</a>.</span>'
                 '<span style="display:block">La trovi sull’App Store.</span>') % LINK_USERSCRIPTS
    else:
        b_saf = '<span class="btn" aria-disabled="true">%s<span>Scarica per Safari</span></span>' % _IC_SCARICA
        n_saf = ('Il file «filtreo.user.js» si trova nella cartella «estensione/safari-userscript» di Filtreo, sul Mac: invialo all’iPhone '
                 'con AirDrop e salvalo in File › iPhone › Userscripts. Nella stessa cartella c’è «COME-INSTALLARE.md». '
                 'Richiede l’app gratuita <a href="%s" target="_blank" rel="noopener noreferrer">Userscripts</a>.') % LINK_USERSCRIPTS
    titolo = "Filtreo su Android" if per == "android" else "Filtreo su iPhone"
    for k, v in (("__BTN_PROFILO__", b_prof), ("__BTN_WIDGET__", b_wid), ("__NOTA_WIDGET__", n_wid), ("__BTN_SAFARI__", b_saf),
                 ("__NOTA_SAFARI__", n_saf), ("__TITOLO__", titolo), ("__VERSIONE__", VERSIONE)):
        t = t.replace(k, v)
    return t


def telefono_profilo(nome):
    """«Installa il profilo»: se il dispositivo (nome tipo «iPhone», genere «altro») non c'è lo creo, poi creo il suo profilo
    se manca (come fa il pannello). Ritorna (ok, testo, nome del profilo). Se il profilo c'era già lo riuso: niente doppioni."""
    nome = re.sub(r"\s+", " ", (nome or "iPhone").strip())[:40] or "iPhone"
    if not dnsp.attivo():
        return False, "Configurazione non ancora attiva su questa Casa.", ""
    ok, did = liste.registra_profilo(nome, "altro")
    if not ok:
        return False, did, ""
    voce = next((n for n, v in dnsp.voci() if v.get("disp") == did), "")
    if not voce:
        ok, t = dnsp_crea(did, nome)
        if not ok:
            return False, t, ""
        voce = next((n for n, v in dnsp.voci() if v.get("disp") == did), "")
    return (True, "", voce) if voce else (False, "Impossibile creare la configurazione. Riprova.", "")


def dnsp_stato():
    if not dnsp.attivo():
        return {"attivo": False}
    return {"attivo": True, "voci": [{"nome": n, "etichetta": v.get("nome") or n, "disp": v.get("disp", "")} for n, v in dnsp.voci()]}


def dnsp_crea(disp, nome):
    if disp not in {x["id"] for x in liste.dispositivi()}:
        return False, "Seleziona il dispositivo da cui copiare le regole."
    ok, n = dnsp.crea(disp, nome)
    if not ok:
        return ok, n
    cambiata = liste.scrivi_config()
    liste._applica(config_cambiata=cambiata)
    liste.sincronizza_paracadute()   # il nuovo codice vale subito anche nel paracadute
    return True, "Creato «%s»: scarica la configurazione e installala sul dispositivo." % n


def dnsp_togli(n):
    ok, t = dnsp.togli(n)
    if ok:
        liste._applica(config_cambiata=liste.scrivi_config())
        liste.sincronizza_paracadute()
    return ok, t


# ───────────── http (via ingress HA) ─────────────
class H(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _html(self, code, s):
        b = s.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _chiamante(self):
        """(ip, dispositivo registrato o None, via_ingresso): chi sta chiedendo. Da Home Assistant (ingresso) l'indirizzo vero del
        dispositivo arriva in X-Forwarded-For; da fuori dall'ingresso conta solo l'indirizzo della connessione (non si può falsificare)."""
        ip = self.client_address[0]
        via = ip in INGRESSO_OK
        if via:
            xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
            if re.fullmatch(r"[0-9a-fA-F:.]{3,45}", xff):
                ip = xff
        return ip, disp_da_ip(ip), via

    def _puo_cambiare_proprietari(self):
        """senza proprietari: chiunque apra il pannello. Con proprietari: un dispositivo proprietario (o Home Assistant, già autenticato)."""
        if not liste.proprietari():
            return True
        ip, x, via = self._chiamante()
        return bool((x is not None and x.get("proprietario")) or (x is None and via))

    def _corpo_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if 0 < n <= 4000:
                d = json.loads(self.rfile.read(n) or b"{}")
                return d if isinstance(d, dict) else {}
        except (ValueError, OSError):
            pass
        return {}

    def _da_estensione(self):
        """la richiesta porta la chiave che il pannello dà alle estensioni (X-Filtro)?"""
        k = self.headers.get("X-Filtro") or ""
        return bool(k) and hmac.compare_digest(k.encode(), est.chiave().encode())

    def _app_collegata(self):
        """la voce dell'app collegata se la richiesta porta la sua chiave (Authorization: Bearer … o X-Filtro), altrimenti None."""
        k = abb.chiave_da_intestazioni(self.headers)
        return abb.chiave_valida(k, self.client_address[0]) if k else None

    def _da_ha(self):
        if self.client_address[0] in INGRESSO_OK or _rete_ok(self.client_address[0]):
            return True
        if self._app_collegata():   # app collegata con il codice di 6 cifre: vale da qualunque rete
            return True
        sys.stderr.write("Filtreo: rifiutato accesso diretto da %s\n" % self.client_address[0])
        self._json(403, {"errore": "Apri Filtreo da Home Assistant."})
        return False

    def _segna_ponte(self):
        """0.10: richiesta arrivata dal ponte (Filtreo Cloud) → è come da Internet: nessuna fiducia per indirizzo, vale solo la chiave."""
        if self.headers.get("X-Filtreo-Via-Ponte"):
            self.client_address = ("0.0.0.0", 0)
            return True
        return False

    def do_GET(self):
        self._segna_ponte()
        u = urlparse(self.path).path.rstrip("/")
        if u == "/salute":
            return self._json(200, {"ok": True})
        if not self._da_ha():
            return
        if u in ("", "/pannello"):
            return self._html(200, PAGINA.replace("__VERSIONE__", VERSIONE).replace("__CHIAVE_NODO__", est.chiave()))
        if u == "/pannello/regole/estensione":
            return self._json(200, {"righe": est.regole_estensione()})
        if u == "/pannello/segnalazioni":
            return self._json(200, {"segnalazioni": est.segnalazioni()})
        if u == "/salute":
            return self._json(200, {"ok": True})
        if u == "/pannello/stato":
            return self._json(200, stato())
        if u == "/pannello/statistiche":   # 3.1: vedi statistiche.py (JSON documentato in testa al file)
            q = parse_qs(urlparse(self.path).query)
            try:
                return self._json(200, stat.statistiche(q.get("periodo", ["oggi"])[0], q.get("disp", [""])[0] or None))
            except ValueError as e:
                return self._json(404, {"ok": False, "codice": "dispositivo_non_trovato", "testo": "Dispositivo non trovato (%s)." % e})
        if u == "/pannello/livelli":   # 3.1: i tre livelli e, per ogni modalità, da che livello parte e se è «modificata»
            return self._json(200, livelli.panoramica(liste.modo_principale(), liste.fonti()))
        if u == "/pannello/livello/differenze":   # 3.1: ?modo=<id> (vuoto = quello del principale)
            mid = parse_qs(urlparse(self.path).query).get("modo", [""])[0] or liste.modo_principale()
            m = modalita.trova(mid)
            if not m or m.get("fissa"):
                return self._json(404, {"ok": False, "testo": "Profilo non trovato."})
            return self._json(200, dict({"modo": mid, "nome": m.get("nome", "")}, **livelli.scheda(m, liste.fonti()),
                                        differenze=livelli.differenze(m, liste.fonti())))
        if u == "/pannello/gruppi":   # 3.1: categorie a gruppi con stato tutto/niente/parziale, ?modo=<id>
            g = liste.gruppi_di(parse_qs(urlparse(self.path).query).get("modo", [""])[0] or None)
            return self._json(200, g) if g else self._json(404, {"ok": False, "testo": "Profilo non trovato."})
        if u == "/pannello/regole":   # 3.1: «Le tue regole» con origine e data
            return self._json(200, regole.elenco(liste.ESCHE_OK | set(liste.ANTI_BASE), liste._eccezioni(con_scarti=True)[1]))
        if u == "/pannello/copia":   # «Scarica copia»: un JSON da conservare (mai chiavi o codici dei profili)
            b = json.dumps(rn.copia(), ensure_ascii=False, indent=1).encode()
            rn.segna_copia()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="Filtreo-copia-%s.json"' % date.today().isoformat())
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        mf = re.fullmatch(r"/pannello/modalita/([A-Za-z0-9_-]{1,40})/famiglia", u)
        if mf:   # «Protezione famiglia» di un profilo: acceso/spento e liste che usa
            r = liste.famiglia_stato(mf.group(1))
            return self._json(200 if r else 404, dict(r, ok=True) if r else {"ok": False, "testo": "Profilo non trovato."})
        if u == "/pannello/versione":
            return self._json(200, rn.stato_versione())
        if u == "/pannello/aggiornamento":   # Casa automatica: versione, interruttore, ultima verifica, ultimo esito, registro
            return self._json(200, agg.stato_pannello())
        if u == "/pannello/abbina/attese":   # codici delle richieste in attesa (pannello e app già collegate)
            return self._json(200, {"attese": abb.attese(), "ha": ha.richieste_ha()})
        if u == "/pannello/abbina/elenco":   # Impostazioni › App collegate
            return self._json(200, {"app": abb.elenco()})
        if u == "/pannello/casa":   # chi è questa Casa (lo legge l'app dopo averla trovata con Bonjour)
            return self._json(200, casa_info())
        if u == "/pannello/avvisi":
            return self._json(200, rn.avvisi_stato())
        if u == "/pannello/pausa/stato":
            return self._json(200, pausa_stato(self._chiamante()))
        if u == "/pannello/pausa/durata":
            return self._json(200, {"durata": durata_ricordata(), "scelte": [{"id": i, "nome": n} for i, n in DURATE]})
        if u == "/pannello/registro":
            q = parse_qs(urlparse(self.path).query)
            g = lambda k: q.get(k, [""])[0]  # noqa: E731
            try:
                n = max(20, min(1000, int(g("n") or 300)))
            except ValueError:
                n = 300
            return self._json(200, {"righe": liste.registro(n, g("ip"), g("q"), g("solo"))})
        if u == "/pannello/scoperti":
            ip = parse_qs(urlparse(self.path).query).get("ip", [""])[0]
            return self._json(200, {"domini": liste.scoperti(ip)})
        if u == "/pannello/video/bloccati":   # «Il video non parte?»: cosa ha fermato la rete a questo dispositivo, con i pezzi del lettore
            sito = parse_qs(urlparse(self.path).query).get("sito", [""])[0]
            return self._json(200, liste.video_bloccati(self.client_address[0], sito))
        if u == "/pannello/proposta":   # che profilo pronto propone Filtreo per un dispositivo con questo nome (o tipo)
            qq = parse_qs(urlparse(self.path).query)
            x = {"nome": qq.get("nome", [""])[0], "tipo": qq.get("tipo", [""])[0]}
            return self._json(200, {"genere": liste.genere(x), "proposta": liste.proposta(x)})
        if u == "/pannello/chi-chiama":   # «Domini più contattati» per un dispositivo
            qq = parse_qs(urlparse(self.path).query)
            return self._json(200, chi_chiama_disp(qq.get("id", [""])[0]))
        if u == "/pannello/estensione/stato":
            return self._json(200, estensione_stato(self.client_address[0]))
        if u == "/pannello/dnsp/profilo":
            n = parse_qs(urlparse(self.path).query).get("n", [""])[0]
            b = dnsp.profilo(n)
            if not b:
                return self._json(404, {"errore": "profilo sconosciuto"})
            self.send_response(200)
            self.send_header("Content-Type", "application/x-apple-aspen-config")
            self.send_header("Content-Disposition", 'attachment; filename="Filtreo-%s.mobileconfig"' % n)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        if u == "/pannello/resoconto":
            try:
                g = int(parse_qs(urlparse(self.path).query).get("giorni", ["7"])[0])
            except ValueError:
                g = 7
            return self._json(200, resoconto(g))
        if u == "/pannello/controllo":
            return self._json(200, controllo())
        if u == "/pannello/barra":   # lo stesso testo della barra del Mac e del widget (anche dal link fuori casa)
            b = testo_barra().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        if u == "/pannello/widget":   # il widget per l'iPhone già pronto: si aggiorna riscaricandolo
            t = widget_pronto()
            if t is None:
                return self._json(404, {"errore": "Widget non disponibile: chiave della barra mancante (FILTREO_CHIAVE)."})
            b = t.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="Filtreo.js"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        if u == "/pannello/telefono":   # la pagina del codice QR dell'assistente
            parsed = urlparse(self.path)
            if parsed.path.endswith("/"):   # i link della pagina sono relativi: senza barra finale valgono ovunque (anche sotto /p/<codice>/)
                self.send_response(302)
                self.send_header("Location", "../telefono" + ("?" + parsed.query if parsed.query else ""))
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            per = telefono_per(self.headers.get("User-Agent", ""), parse_qs(parsed.query).get("per", [""])[0])
            return self._html(200, pagina_telefono(per))
        if u == "/pannello/figtree.woff2":
            b = font_figtree()
            if not b:
                return self._json(404, {"errore": "carattere non disponibile"})
            self.send_response(200)
            self.send_header("Content-Type", "font/woff2")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        if u == "/pannello/safari/filtreo.user.js":   # «Filtro web»: il file sta già nella cartella dell'estensione, si serve da lì
            f = _userscript()
            if not f:
                return self._json(404, {"errore": "File non disponibile su questa Casa"})
            b = open(f, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        if u.startswith("/pannello/ha/"):   # Impostazioni: «Home Assistant e HomeKit»
            return ha.pannello_get(self, u)
        if u == "/pannello/config":
            try:
                return self._json(200, config_json())
            except Exception as e:
                return self._json(500, {"errore": str(e)[:200]})
        return self._json(404, {"errore": "pagina sconosciuta"})

    def do_POST(self):
        via_ponte = self._segna_ponte()
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path.rstrip("/")
        if p == "/pannello/abbina/codice-dns":   # 0.10.1: l'app col suo filtro personale si ricollega da sola, anche da lontano
            d = self._corpo_json()
            codici = [v.get("codice") for v in dnsp._leggi().values() if isinstance(v, dict) and v.get("codice")]
            code, obj = abb.con_codice_dns(d.get("codice"), d.get("nome"), "ponte" if via_ponte else self.client_address[0], codici)
            if obj.get("ok"):
                obj.update(casa_info())
            return self._json(code, obj)
        if p == "/pannello/abbina/invito/usa":   # 0.10: l'invito monouso creato dal pannello (vale anche da fuori, dal ponte)
            d = self._corpo_json()
            code, obj = abb.usa_invito(d.get("invito"), d.get("nome"), "ponte" if via_ponte else self.client_address[0])
            if obj.get("ok"):
                obj.update(casa_info())
            return self._json(code, obj)
        if via_ponte and p.startswith("/pannello/abbina/") and p != "/pannello/abbina/revoca":   # il codice si dà solo in casa
            return self._json(403, {"ok": False, "codice": "solo_in_casa", "testo": "Collega l'app dalla rete di casa."})
        if p == "/pannello/abbina/inizia":   # aperto a tutta la rete: il codice lo vede solo chi è già autorizzato
            d = self._corpo_json()
            code, obj = abb.inizia(d.get("nome") or q.get("nome", [""])[0], self.client_address[0])
            return self._json(code, obj)
        if p == "/pannello/abbina/conferma":   # aperto: 5 codici sbagliati → 10 minuti di blocco
            d = self._corpo_json()
            code, obj = abb.conferma(d.get("id") or q.get("id", [""])[0], d.get("codice") or q.get("codice", [""])[0], self.client_address[0])
            if obj.get("ok"):
                obj.update(casa_info())
                _ha_notifica_togli()
            return self._json(code, obj)
        if not self._da_ha():
            return
        try:
            if p == "/pannello/aggiornamento/ora":
                ok, t = agg.avvia_ora()
                return self._json(200 if ok else 409, {"ok": ok, "testo": t, "aggiornamento": agg.stato_pannello()})
            if p == "/pannello/aggiornamento/imposta":
                d = self._corpo_json()
                a = d.get("automatici", q.get("automatici", [None])[0])
                ok, t = agg.imposta(None if a is None else str(a).lower() in ("1", "true", "si", "sì"), d.get("ora") or q.get("ora", [None])[0])
                return self._json(200 if ok else 400, {"ok": ok, "testo": t, "aggiornamento": agg.stato_pannello()})
            if p == "/pannello/abbina/invito":   # 0.10: «Collega un'app da fuori casa» (solo dal pannello / Home Assistant)
                pi = casa_info().get("ponte") or {}
                if not (pi.get("collegata") and pi.get("indirizzo")):
                    return self._json(409, {"ok": False, "testo": "Filtreo Cloud non è collegato a Casa in questo momento. Riprova tra un minuto."})
                from urllib.parse import quote
                t = abb.invito()
                return self._json(200, {"ok": True, "scade_tra": abb.INVITO_VALIDITA,
                                        "link": "filtreo://collega?ponte=%s&invito=%s" % (quote(pi["indirizzo"], safe=""), t)})
            if p in ("/pannello/ha/consenti", "/pannello/ha/rifiuta"):   # 0.10.3: Home Assistant chiede di collegarsi
                ok, testo = ha.decidi_ha((self._corpo_json().get("id")) or q.get("id", [""])[0], p.endswith("consenti"))
                return self._json(200 if ok else 404, {"ok": ok, "testo": testo})
            if p == "/pannello/abbina/rifiuta":
                ok = abb.rifiuta((self._corpo_json().get("id")) or q.get("id", [""])[0])
                return self._json(200 if ok else 404, {"ok": ok, "testo": "Richiesta rifiutata" if ok else "Richiesta scaduta"})
            if p == "/pannello/abbina/revoca":
                ok, t = abb.revoca((self._corpo_json().get("id")) or q.get("id", [""])[0])
                return self._json(200 if ok else 404, {"ok": ok, "testo": t, "app": abb.elenco()})
            if p == "/pannello/pausa/attivita":   # 0.9.4: token dell'Attività in tempo reale della pausa
                code, obj = attivita_registra(self._corpo_json())
                return self._json(code, obj)
            if p in ("/pannello/pausa", "/pannello/pausa/prolunga", "/pannello/pausa/riprendi"):
                dati = self._corpo_json()
                for k in ("ambito", "dispositivo", "durata", "minuti"):
                    if k in q:
                        dati.setdefault(k, q[k][0])
                if p != "/pannello/pausa" or dati.get("ambito"):   # API unica; senza «ambito» resta la pausa di prima (sotto)
                    code, obj = pausa_api(p, dati, self._chiamante())
                    return self._json(code, obj)
                if PAUSA_RETE_STRETTA:   # facoltativo: le regole della Rete valgono anche per la pausa di prima
                    negata = regola_rete(self._chiamante(), q.get("d", [""])[0] or None)
                    if negata:
                        return self._json(negata[0], negata[1])
            # 3.1: «origine» = registro | sito | mano | estensione | controllo (vedi regole.py). Senza: a mano, o «estensione» se
            # chi chiama ha la chiave delle estensioni
            org = regole.origine_valida(q.get("origine", [""])[0], "estensione" if self._da_estensione() else "mano")
            if p == "/pannello/blocca":
                return self._json(200, {"ok": True, "testo": blocca_guard(q.get("d", [""])[0], org)})
            if p == "/pannello/sblocca":
                return self._json(200, {"ok": True, "testo": sblocca_guard(q.get("d", [""])[0], org)})
            if p == "/pannello/annulla_blocco":
                ok, t = annulla_blocco(q.get("d", [""])[0])
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/eccezione":
                ok, t = eccezione(q.get("azione", [""])[0], q.get("d", [""])[0], org)
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/pausa/durata":
                k = q.get("v", [""])[0]
                if not imposta_durata(k):
                    return self._json(400, {"ok": False, "testo": "Durata non valida."})
                if q.get("applica", [""])[0] == "1" and PAUSA_RETE_STRETTA:
                    negata = regola_rete(self._chiamante(), k)
                    if negata:
                        return self._json(negata[0], negata[1])
                testo = pausa_scelta(k) if q.get("applica", [""])[0] == "1" else "Durata della pausa: %s." % dict(DURATE)[k].lower()
                return self._json(200, {"ok": True, "testo": testo, "durata": k})
            if p == "/pannello/pausa":
                if "sec" in q and q["sec"][0].strip() == "30":   # barra e widget: pausa breve di 30 secondi
                    return self._json(200, {"ok": True, "testo": pausa_scelta("30s")})
                if "min" in q:   # compatibile con il widget e la barra del Mac: durata in minuti
                    t = filtro.pausa(q["min"][0])
                    try:
                        if t.startswith("Filtro in pausa"):
                            _segna_pausa(min(int(float(q["min"][0].replace(",", "."))), filtro.MAX_PAUSA_MIN) * 60)
                            pausa_cambiata()
                    except ValueError:
                        pass
                    return self._json(200, {"ok": True, "testo": t})
                return self._json(200, {"ok": True, "testo": pausa_scelta(q.get("d", [""])[0])})
            if p == "/pannello/riprendi":
                return self._json(200, {"ok": True, "testo": pausa_cambiata(filtro.riprendi())})
            g1 = lambda k, d="": q.get(k, [d])[0]  # noqa: E731
            if p == "/pannello/versione/controlla":
                return self._json(200, rn.controlla_versione())
            if p == "/pannello/avvisi/imposta":
                ok, t = rn.avvisi_imposta(g1("k"), g1("v") == "1")
                return self._json(200 if ok else 400, {"ok": ok, "testo": t, "avvisi": rn.avvisi_stato()})
            if p == "/pannello/avvisi/prova":
                ok, t = rn.avvisi_prova()
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p in ("/pannello/copia/anteprima", "/pannello/copia/ripristina"):
                n = int(self.headers.get("Content-Length") or 0)
                if n > rn.MAX_BYTE_COPIA:
                    return self._json(413, {"ok": False, "testo": "File troppo grande: non è una copia di Filtreo."})
                try:
                    dati = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return self._json(400, {"ok": False, "testo": "File non leggibile. Seleziona una copia scaricata da Filtreo."})
                if p.endswith("anteprima"):
                    a = rn.anteprima(dati)
                    return self._json(200 if a.get("ok") else 400, a)
                ok, t = rn.ripristina(dati)
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/fonti/aggiungi":
                ok, t = liste.aggiungi(g1("url"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/fonti/togli":
                ok, t = liste.togli(g1("url"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/fonti/imposta-molte":   # «Attiva tutti» / «Disattiva tutti»: una sola applicazione
                if g1("attiva") not in ("0", "1"):
                    return self._json(400, {"ok": False, "testo": "Azione non specificata."})
                ok, t = liste.imposta_molte(g1("attiva") == "1", g1("categoria") or None)
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/fonti/imposta":
                at = g1("attiva")
                ok, t = liste.imposta(g1("url"), None if at == "" else at == "1", g1("categoria") or None)
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/disp/registra":
                ok, t = liste.registra(g1("ip"), g1("nome"), g1("proprie") == "1", g1("modo") or None)
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/disp/modifica":
                pr = g1("proprie")
                ips = q.get("ips", [None])[0]
                po = g1("proprietario")
                if po != "" and not self._puo_cambiare_proprietari():
                    return self._json(403, {"ok": False, "codice": "solo_proprietario", "testo": "Solo un dispositivo proprietario può cambiare i proprietari."})
                ok, t = liste.modifica_disp(g1("id"), nome=q.get("nome", [None])[0], proprie=(None if pr == "" else pr == "1"),
                                            ips=(None if ips is None else [i for i in re.split(r"[ ,]+", ips) if i]),
                                            proprietario=(None if po == "" else po == "1"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/disp/proprietario":   # ?id=<id|nome|ip>&v=1|0 (oppure corpo {"dispositivo": …, "proprietario": true|false})
                dati = self._corpo_json()
                rif = dati.get("dispositivo") or g1("id") or g1("dispositivo")
                v = dati.get("proprietario", g1("v"))
                if isinstance(v, str):
                    v = {"1": True, "true": True, "0": False, "false": False}.get(v.strip().lower())
                if not isinstance(v, bool):
                    return self._json(400, {"ok": False, "codice": "valore_non_valido", "testo": "Indica se marcarlo proprietario (v=1) o no (v=0)."})
                if not self._puo_cambiare_proprietari():
                    return self._json(403, {"ok": False, "codice": "solo_proprietario", "testo": "Solo un dispositivo proprietario può cambiare i proprietari."})
                ok, t, code, err = liste.imposta_proprietario(rif, v)
                return self._json(code, {"ok": ok, "testo": t, "codice": err} if not ok else dict(pausa_stato(self._chiamante()), testo=t, proprietari=[x["nome"] for x in liste.proprietari()]))
            if p == "/pannello/disp/proposta":   # «Applica «TV e casse»»
                ok, t = liste.accetta_proposta(g1("id"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/disp/principale":
                ok, t = liste.rendi_principale(g1("id"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/disp/dimentica":
                ok, t = liste.dimentica(g1("id"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p in ("/pannello/regole/estensione", "/pannello/segnalazioni", "/pannello/video", "/pannello/video/annulla"):
                if not hmac.compare_digest((self.headers.get("X-Filtro") or "").encode(), est.chiave().encode()):
                    return self._json(403, {"ok": False, "testo": "chiave"})
                n = int(self.headers.get("Content-Length") or 0)
                if n > 200000:
                    return self._json(413, {"ok": False, "testo": "troppo grande"})
                corpo = json.loads(self.rfile.read(n) or b"{}")
                if p == "/pannello/segnalazioni":
                    ok, t = est.aggiungi_segnalazione(corpo)
                elif p == "/pannello/video":
                    ok, t = liste.permetti_video(corpo.get("sito"), corpo.get("domini"))
                elif p == "/pannello/video/annulla":
                    ok, t = liste.annulla_video(corpo.get("sito"))
                else:
                    ok, t = est.aggiungi_regole_estensione(corpo.get("righe"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/segnalazioni/fatta":
                ok, t = est.segnalazione_fatta(q.get("id", [""])[0])
                return self._json(200, {"ok": ok, "testo": t})
            if p == "/pannello/telefono/profilo":   # «Installa il profilo» dalla pagina del QR
                ok, testo, n = telefono_profilo(q.get("nome", ["iPhone"])[0])
                return self._json(200 if ok else 400, {"ok": ok, "testo": testo, "n": n})
            if p == "/pannello/dnsp/crea":
                ok, t = dnsp_crea(q.get("disp", [""])[0], q.get("nome", [""])[0])
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/modo":
                ok, t = liste.imposta_modo(g1("id"), g1("m"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/modalita/salva":
                n = int(self.headers.get("Content-Length") or 0)
                if n > 50000:
                    return self._json(413, {"ok": False, "testo": "troppo grande"})
                ok, t, mid = liste.salva_modalita(json.loads(self.rfile.read(n) or b"{}"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t, "id": mid})
            if p == "/pannello/famiglia/salva":
                n = int(self.headers.get("Content-Length") or 0)
                if n > 20000:
                    return self._json(413, {"ok": False, "testo": "troppo grande"})
                ok, t, pid = liste.salva_persona(json.loads(self.rfile.read(n) or b"{}"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t, "id": pid})
            if p == "/pannello/famiglia/togli":
                ok, t = modalita.togli_persona(g1("id"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            mf = re.fullmatch(r"/pannello/modalita/([A-Za-z0-9_-]{1,40})/famiglia", p)
            if mf:   # accende/spegne la protezione famiglia: ?attiva=1|0 oppure corpo {"attiva": true|false}
                a = q.get("attiva", [None])[0]
                if a is None:
                    n = int(self.headers.get("Content-Length") or 0)
                    corpo = json.loads(self.rfile.read(n) or b"{}") if 0 < n <= 2000 else {}
                    a = corpo.get("attiva") if isinstance(corpo, dict) else None
                if isinstance(a, str):
                    a = {"1": True, "true": True, "0": False, "false": False}.get(a.strip().lower())
                if not isinstance(a, bool):
                    return self._json(400, {"ok": False, "testo": "Indica se accendere o spegnere (attiva=1 oppure 0)."})
                ok, t = liste.imposta_famiglia(mf.group(1), a)
                return self._json(200 if ok else 400, dict(ok=ok, testo=t, famiglia=bool((modalita.trova(mf.group(1)) or {}).get("famiglia"))))
            if p == "/pannello/modalita/togli":
                ok, t = liste.togli_modalita(g1("id"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/fonti/consigliata":
                ok, t = liste.aggiungi_consigliata(g1("cat"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/dnsp/togli":
                ok, t = dnsp_togli(q.get("n", [""])[0])
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/sistema":
                ok, t = liste.sistema(g1("d"))
                if ok:
                    regole.segna("bloccati", g1("d"), "controllo")
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/anti":   # «Un sito ti ha scoperto»
                ok, t = liste.permetti_anti(g1("d"))
                if ok:
                    regole.segna("consentiti", g1("d"), regole.origine_valida(g1("origine"), "sito"))
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            # ───── 3.1: livelli, gruppi, regole ─────
            if p == "/pannello/livello/torna":   # ?modo=<id>[&livello=base|standard|rigoroso]
                ok, t = liste.livello_torna(g1("modo") or None, g1("livello") or None)
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/gruppi/imposta":   # ?modo=<id>&gruppo=<id>&attiva=1|0 → tutto il gruppo sì/no
                if g1("attiva") not in ("0", "1"):
                    return self._json(400, {"ok": False, "testo": "Indica attiva=1 oppure 0."})
                ok, t = liste.gruppo_imposta(g1("modo") or None, g1("gruppo"), g1("attiva") == "1")
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p == "/pannello/gruppi/riga":   # ?modo=<id>&url=<lista>&attiva=1|0 → una riga del gruppo
                if g1("attiva") not in ("0", "1"):
                    return self._json(400, {"ok": False, "testo": "Indica attiva=1 oppure 0."})
                ok, t = liste.riga_imposta(g1("modo") or None, g1("url"), g1("attiva") == "1")
                return self._json(200 if ok else 400, {"ok": ok, "testo": t})
            if p in ("/pannello/regole/aggiungi", "/pannello/regole/togli"):   # {tipo: bloccati|consentiti, dominio, origine}
                dati = self._corpo_json()
                tipo = dati.get("tipo") or g1("tipo")
                dom = dati.get("dominio") or g1("d")
                o = regole.origine_valida(dati.get("origine") or g1("origine"), org)
                if tipo not in ("bloccati", "consentiti"):
                    return self._json(400, {"ok": False, "testo": "Tipo non valido: bloccati oppure consentiti."})
                if p.endswith("aggiungi"):
                    if tipo == "bloccati":
                        t = blocca_guard(dom, o)
                        ok = filtro._dominio(dom) is not None and not _protetto(filtro._dominio(dom) or "")
                    else:
                        ok, t = eccezione("aggiungi", dom, o)
                    # 0.9.1 — regola a tempo: {"durata_sec": 3600} («Consenti per 1 ora»); senza durata = per sempre
                    dur = regole.durata_valida(dati.get("durata_sec") or g1("durata_sec"))
                    if ok:
                        regole.imposta_scadenza(tipo, dom, time.time() + dur if dur else None, o)
                        if dur:
                            t = "%s %s per %s." % (filtro._dominio(dom), "consentito" if tipo == "consentiti" else "bloccato",
                                                   "1 ora" if dur == 3600 else ("%d minuti" % (dur // 60) if dur < 7200 else "%d ore" % (dur // 3600)))
                else:
                    ok, t = annulla_blocco(dom) if tipo == "bloccati" else eccezione("togli", dom)
                return self._json(200 if ok else 400, dict(regole.elenco(liste.ESCHE_OK | set(liste.ANTI_BASE), liste._eccezioni(con_scarti=True)[1]),
                                                        ok=ok, testo=t))
            if p == "/pannello/refresh":
                ok = filtro._ricarica()
                return self._json(200, {"ok": ok, "testo": "Filtri ricaricati" if ok else "Impossibile ricaricare i filtri."})
        except Exception as e:
            return self._json(500, {"ok": False, "testo": str(e)[:200]})
        return self._json(404, {"errore": "azione sconosciuta"})

    def log_message(self, *a):
        pass


# ───────────── porta per l'icona nella barra del Mac (con chiave) ─────────────
def testo_barra():
    s = stato()
    o = s.get("oggi") or {}
    righe = [
        "raggiungibile=%d" % (1 if s.get("raggiungibile") else 0),
        "acceso=%d" % (1 if s.get("acceso") else 0),
        "pausa_fino=%s" % ((s.get("pausa") or {}).get("fino", "") if s.get("pausa") else ""),
        "pausa_fino_ts=%d" % (int(time.time()) + int((s.get("pausa") or {}).get("resta_sec") or 0) if (s.get("pausa") or {}).get("resta_sec") else 0),   # istante (secondi epoch): il widget lo mostra nell'ora del telefono
        "agg_ts=%d" % int(time.time()),
        "pausa_resta=%d" % int((s.get("pausa") or {}).get("resta_sec") or 0),   # secondi che mancano: vale in ogni fuso
        "pausa_totale=%d" % int((s.get("pausa") or {}).get("totale_sec") or 0),
        "pausa_senza=%d" % (1 if (s.get("pausa") or {}).get("senza_scadenza") else 0),
        "bloccate=%d" % int(o.get("bloccate") or 0),   # = totale: Casa + Cloudflare
        "richieste=%d" % int(o.get("richieste") or 0),
        "percento=%d" % int(o.get("percento") or 0),
        "casa=%d" % int(o.get("casa") or 0),
        "cloudflare=%d" % int(o.get("cloudflare") or 0),
        "totale=%d" % int(o.get("totale") or o.get("bloccate") or 0),
    ]
    for x in (s.get("ultime") or [])[:8]:
        righe.append("ult=%s %s" % (x.get("ora", ""), x.get("dominio", "")))
    for x in (s.get("top") or [])[:5]:
        righe.append("top=%s %s" % (x.get("volte", 0), x.get("dominio", "")))
    for x in (s.get("dispositivi") or [])[:4]:
        righe.append("disp=%s|%d|%d" % (x["nome"].replace("|", " "), x["bloccate"], x["richieste"]))
        righe.append("disp_split=%s|%d|%d" % (x["nome"].replace("|", " "), x.get("casa", 0), x.get("cloudflare", 0)))
    righe.append("ore=" + ",".join(str(n) for n in (s.get("ore") or [0] * 24)))   # totale (Casa + Cloudflare)
    righe.append("ore_casa=" + ",".join(str(n) for n in (s.get("ore_casa") or [0] * 24)))
    righe.append("ore_cloudflare=" + ",".join(str(n) for n in (s.get("ore_cloudflare") or [0] * 24)))
    righe.append("chi=" + ", ".join(s.get("chi_di_piu") or []))
    righe.append("agg=" + datetime.now().strftime("%H:%M"))
    righe.append("versione=%s" % VERSIONE)
    return "\n".join(righe) + "\n"


class B(BaseHTTPRequestHandler):
    def _testo(self, code, t):
        b = t.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _chiave_ok(self):
        k = self.headers.get("X-Filtro", "")
        if CHIAVE_BARRA and hmac.compare_digest(k.encode(), CHIAVE_BARRA.encode()):
            return True
        self._testo(403, "chiave errata\n")
        return False

    def do_GET(self):
        if not self._chiave_ok():
            return
        if urlparse(self.path).path.rstrip("/") == "/barra":
            return self._testo(200, testo_barra())
        if urlparse(self.path).path.rstrip("/") == "/widget":   # il widget nuovo, già pronto (lo ritira il Mac)
            t = widget_pronto()
            return self._testo(200, t) if t else self._testo(404, "Widget non disponibile\n")
        return self._testo(404, "?\n")

    def do_POST(self):
        if not self._chiave_ok():
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path.rstrip("/")
        try:
            if p == "/barra/pausa":
                if q.get("sec", [""])[0].strip() == "30":
                    return self._testo(200, pausa_scelta("30s") + "\n")
                if q.get("d", [""])[0] in dict(DURATE):   # barra e widget: stesse scelte del pannello
                    return self._testo(200, pausa_scelta(q["d"][0]) + "\n")
                t = filtro.pausa(q.get("min", ["10"])[0])
                if t.startswith("Filtro in pausa"):
                    pausa_cambiata()
                return self._testo(200, t + "\n")
            if p == "/barra/riprendi":
                return self._testo(200, pausa_cambiata(filtro.riprendi()) + "\n")
        except Exception as e:
            return self._testo(500, str(e)[:200] + "\n")
        return self._testo(404, "?\n")

    def log_message(self, *a):
        pass


def _versione():
    try:
        v = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSIONE"), encoding="utf-8").read().strip()
        return "v" + v if re.fullmatch(r"\d+\.\d+\.\d+", v) else ""
    except OSError:
        return ""


VERSIONE = _versione()

# la pagina del pannello sta in pannello.html (stessa cartella): uguale su Pi e Jetson
PAGINA = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "pannello.html"), encoding="utf-8").read()


def casa_id():
    """id fisso di questa Casa (per riconoscerla tra più Case trovate in rete): creato una volta in DATA/casa-id."""
    p = os.path.join(filtro.DATA, "casa-id")
    try:
        v = open(p, encoding="utf-8").read().strip()
        if re.fullmatch(r"[0-9a-f]{12}", v):
            return v
    except OSError:
        pass
    v = os.urandom(6).hex()
    try:
        open(p, "w", encoding="utf-8").write(v + "\n")
    except OSError:
        pass
    return v


def casa_nome():
    try:
        x = next((d for d in liste.dispositivi() if d.get("principale")), None)
        return (os.environ.get("FILTREO_MDNS_NOME") or (x or {}).get("nome") or "Casa").strip()[:40] or "Casa"
    except Exception:
        return "Casa"


ANNUNCIO = {"a": None}
PONTE = {"p": None}


def casa_info():
    a = ANNUNCIO["a"]
    p = PONTE["p"]
    return {"casa_id": casa_id(), "casa_nome": casa_nome(), "versione": VERSIONE.lstrip("v"), "porta": PORTA,
            "ha": bool(os.environ.get("SUPERVISOR_TOKEN")), "annuncio": a.stato() if a else {"attivo": False},
            # 0.10: l'indirizzo da fuori casa per le app (con la loro chiave), senza Tailscale
            "ponte": p.stato() if p else {"attivo": False, "collegata": False, "indirizzo": ""}}


def _ha_chiama(servizio, dati):
    """servizio di Home Assistant tramite il Supervisor (serve homeassistant_api: true nell'add-on). Mai un errore."""
    tok = os.environ.get("SUPERVISOR_TOKEN", "")
    if not tok:
        return False
    try:
        import urllib.request
        r = urllib.request.Request("http://supervisor/core/api/services/persistent_notification/" + servizio, method="POST",
                                   data=json.dumps(dati).encode(), headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
        urllib.request.urlopen(r, timeout=6).read()
        return True
    except Exception:
        return False


def _ha_notifica(testo, r):
    _ha_chiama("create", {"notification_id": "filtreo_abbina", "title": "Filtreo · Collega un dispositivo",
                          "message": "Codice per «%s»: **%s %s** (vale 5 minuti). Inseriscilo nell'app Filtreo." % (r["nome"], r["codice"][:3], r["codice"][3:])})


def _ha_notifica_togli():
    threading.Thread(target=_ha_chiama, args=("dismiss", {"notification_id": "filtreo_abbina"}), daemon=True).start()


abb._notifica.append(lambda testo, r: threading.Thread(target=liste.avvisa, args=(testo,), daemon=True).start())
abb._notifica.append(lambda testo, r: threading.Thread(target=_ha_notifica, args=(testo, r), daemon=True).start())

rn.collega(resoconto=resoconto)
stat.collega(conti_cf=conti_cloudflare, ore_cf=ore_cloudflare, risolvi_cf=risolvi_cf, dispositivi=liste.dispositivi,
             nodo_ips=liste.nodo_ips, e_nodo=liste.e_nodo, voci_dns=lambda: list(dnsp.voci()), fonte_file=liste._file,
             fonti=liste.fonti, app_domini=lambda: {d.lower() for a in modalita.app_bloccabili() for d in a.get("domini", [])},
             fissi=lambda: (dict({d: "pubblicita" for d in liste.SENTINELLE}, **{d: "telemetria" for d in liste.MAI_PERMESSI}),
                            {r.lstrip("*.").lower() for r in liste._righe_pulite("blocca.txt")}))


# ───────────── 0.10.3: avviso «Collega Filtreo» in Home Assistant + Filtreo rilevato tra i dispositivi ─────────────
AVVISO_COLLEGA = {"scade": 0.0, "attivo": False, "link": "", "da_conf": None, "n": None, "fino": 0.0}
AVVISO_VALIDITA = 7 * 86400


def _supervisor(metodo, percorso, dati=None):
    """chiamata al Supervisor di Home Assistant. Mai un errore: ritorna True se è andata."""
    tok = os.environ.get("SUPERVISOR_TOKEN", "")
    if not tok:
        return False
    try:
        import urllib.request
        r = urllib.request.Request("http://supervisor" + percorso, method=metodo, data=json.dumps(dati or {}).encode(),
                                   headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
        urllib.request.urlopen(r, timeout=8).read()
        return True
    except Exception:
        return False


def link_collega(indirizzo, invito):
    """la pagina di Filtreo Cloud che apre l'app con l'invito (dopo il #: non arriva mai a nessun server)."""
    from urllib.parse import quote
    base = indirizzo.split("/casa/")[0].rstrip("/")
    return "%s/collega#ponte=%s&invito=%s" % (base, quote(indirizzo, safe=""), invito)


def testo_avviso_collega(link, integrazione_da_configurare, collegati=0):
    if collegati:
        t = ("Filtreo è collegato a %d %s.\n\n"
             "**Per collegare un altro dispositivo** (per esempio il Mac), apri questo avviso su quel dispositivo e tocca "
             "[Collega Filtreo](%s). Il collegamento è nuovo, si usa una sola volta e funziona anche fuori casa.\n\n"
             "Questo avviso si chiude da solo tra 24 ore." % (collegati, "dispositivo" if collegati == 1 else "dispositivi", link))
    else:
        t = ("FiltreoCasa è attivo.\n\n"
             "**Collega l'app Filtreo:** apri questo avviso sull'iPhone o sul Mac dove hai installato Filtreo e tocca "
             "[Collega Filtreo](%s). Funziona anche fuori casa.\n\n"
             "Il collegamento vale 7 giorni e si usa una sola volta." % link)
    if integrazione_da_configurare:
        t += ("\n\n**Filtreo tra i dispositivi di Home Assistant:** riavvia Home Assistant una volta "
              "(Impostazioni › menu ⋮ › Riavvia Home Assistant). Poi in Impostazioni › Dispositivi e servizi "
              "Filtreo compare tra i dispositivi rilevati: premi Configura, poi Invia.")
    return t


def giro_avviso_collega():
    """ogni 30 s, solo dentro Home Assistant OS. Finché nessuna app è collegata tiene in Home Assistant l'avviso
    «Collega Filtreo» con un invito valido. Dopo il primo collegamento lo rinnova con un invito nuovo (per il Mac o un
    altro dispositivo) e lo chiude da solo dopo 24 ore."""
    if not os.environ.get("SUPERVISOR_TOKEN"):
        return
    _supervisor("POST", "/discovery", {"service": "filtreo", "config": {"porta": ha.PORTA}})   # Dispositivi e servizi › Rilevato
    A = AVVISO_COLLEGA
    while True:
        try:
            pi = casa_info().get("ponte") or {}
            n = len(abb.elenco())
            hs = ha.stato_pannello()
            da_conf = bool(hs.get("in_ha")) and not hs.get("collegata")
            adesso = time.time()
            ponte_ok = bool(pi.get("collegata") and pi.get("indirizzo"))
            if n == 0 and ponte_ok:
                nuovo = adesso > A["scade"] - 3600 or not A.get("link")
                if nuovo or A["da_conf"] != da_conf or A.get("n") != 0:
                    if nuovo:
                        A["link"] = link_collega(pi["indirizzo"], abb.invito(validita=AVVISO_VALIDITA))
                        A["scade"] = adesso + AVVISO_VALIDITA
                    if _ha_chiama("create", {"notification_id": "filtreo_collega", "title": "Filtreo · Collega l'app",
                                             "message": testo_avviso_collega(A["link"], da_conf)}):
                        A.update(attivo=True, da_conf=da_conf, n=0, fino=0.0)
            elif n > 0 and A["attivo"]:
                if not A.get("fino"):
                    A["fino"] = adesso + 86400
                if adesso > A["fino"]:
                    if _ha_chiama("dismiss", {"notification_id": "filtreo_collega"}):
                        A.update(attivo=False, scade=0.0, link="", fino=0.0, n=None)
                elif (A.get("n") != n or A["da_conf"] != da_conf) and ponte_ok:
                    if A.get("n") != n:
                        A["link"] = link_collega(pi["indirizzo"], abb.invito(validita=86400))
                    if _ha_chiama("create", {"notification_id": "filtreo_collega", "title": "Filtreo · Collega l'app",
                                             "message": testo_avviso_collega(A["link"], da_conf, n)}):
                        A.update(n=n, da_conf=da_conf)
        except Exception as e:
            sys.stderr.write("Filtreo: avviso di collegamento (%s)\n" % type(e).__name__)
        time.sleep(30)


if __name__ == "__main__":
    agg.avvia()   # prova di aggiornamento interrotta (Casa ripartita a metà)? torna alla versione di prima prima di tutto
    liste.giri_extra.append(rn.giro)
    liste.giri_extra.append(agg.giro)   # aggiornamento automatico di notte (ora in Impostazioni, di serie 04:30)   # avvisi su Telegram: dentro il giro di ogni minuto che c'è già
    liste.avvia(_protetto)
    filtro.avvia_timer()   # riattivazione programmata della pausa di 30 secondi (solo se Blocky non accetta «30s»)
    stat.avvia()   # 3.1: statistiche lette in sottofondo (risposte sempre veloci)
    threading.Thread(target=giro_regole_a_tempo, daemon=True).start()   # 0.9.1: «Consenti per 1 ora» scade da solo
    threading.Thread(target=giro_attivita, daemon=True).start()          # 0.9.4: Attività della pausa chiusa anche ad app chiusa
    ha.avvia(sys.modules[__name__])   # porta con chiave per l'integrazione di Home Assistant (mai un errore)
    if CHIAVE_BARRA:
        srv_b = ThreadingHTTPServer(("0.0.0.0", PORTA_BARRA), B)
        threading.Thread(target=srv_b.serve_forever, daemon=True).start()
        sys.stderr.write("Filtreo: barra del Mac attiva sulla porta %d\n" % PORTA_BARRA)
    if dnsp.URL_PUBBLICO:
        porta_doh = int(os.environ.get("FILTREO_DOH_PORT", "8448"))
        srv_d = ThreadingHTTPServer((os.environ.get("FILTREO_DOH_ASCOLTO", "127.0.0.1"), porta_doh), dnsp.Porta)
        threading.Thread(target=srv_d.serve_forever, daemon=True).start()
        sys.stderr.write("Filtreo: DNS fuori casa attivo sulla porta %d (%s)\n" % (porta_doh, dnsp.URL_PUBBLICO))
    srv = ThreadingHTTPServer(("0.0.0.0", PORTA), H)
    if os.environ.get("FILTREO_IN_PROVA") != "1":   # durante la prova di un aggiornamento l'annuncio lo fa il pannello definitivo
        try:
            ANNUNCIO["a"] = mdns.Annuncio(PORTA, VERSIONE, casa_nome(), casa_id(),
                                          extra={"ha": ha.PORTA, "nodo": ha._nodo()} if ha._server["srv"] else None)
            ANNUNCIO["a"].avvia()
        except Exception as e:
            sys.stderr.write("Filtreo: annuncio in rete non avviato (%s)\n" % type(e).__name__)
        try:   # 0.10: il ponte verso Filtreo Cloud (le app da fuori casa, senza Tailscale)
            PONTE["p"] = ponte.Ponte(PORTA)
            PONTE["p"].avvia()
        except Exception as e:
            sys.stderr.write("Filtreo: ponte non avviato (%s)\n" % type(e).__name__)
        threading.Thread(target=giro_avviso_collega, daemon=True).start()   # 0.10.3: «Collega Filtreo» in Home Assistant
    srv.serve_forever()
