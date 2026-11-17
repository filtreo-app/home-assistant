# -*- coding: utf-8 -*-
"""righe_nuove.py — le righe di Impostazioni che nei mockup 2.0 non avevano ancora una funzione:
  1. Aggiornamenti: versione installata e confronto con la più recente (file «versione.json» del paracadute di Cloudflare);
  2. Copia di sicurezza: «Scarica copia» (JSON) e «Ripristina» (anteprima, poi conferma). MAI chiavi, token o codici dei profili;
  3. Avvisi su Telegram: filtro riavviato, Casa non risponde, riepilogo settimanale (si controllano nel giro di ogni minuto
     che il pannello ha già: niente cron nuovi).
Solo libreria standard. Nessuna funzione qui lancia un errore verso il pannello: ritornano sempre un testo comprensibile."""
import json
import os
import re
import threading
import time
from datetime import date, datetime

import filtro
import filtreo_liste as liste
import modalita

DATA = filtro.DATA
QUI = os.path.dirname(os.path.abspath(__file__))
COLLEGA = {"resoconto": None}   # lo imposta il pannello: serve solo al riepilogo settimanale


def collega(resoconto=None):
    COLLEGA["resoconto"] = resoconto


def _leggi(p, vuoto):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return vuoto


def _scrivi_json(p, obj):
    try:
        with open(p + ".tmp", "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        os.replace(p + ".tmp", p)
        return True
    except OSError:
        return False


def _num(n):
    return format(int(n or 0), ",d").replace(",", ".")


# ───────────────────────── 1. aggiornamenti ─────────────────────────
VERSIONE_RE = re.compile(r"^\d+\.\d+\.\d+$")
FILE_CONTROLLO = os.path.join(DATA, "versione-controllo.json")


def versione_installata():
    try:
        v = open(os.path.join(QUI, "VERSIONE"), encoding="utf-8").read().strip()
        return v if VERSIONE_RE.match(v) else ""
    except OSError:
        return ""


def _tupla(v):
    return tuple(int(x) for x in v.split("."))


def _fonte_versione():
    """dove sta la versione più recente: FILTREO_VERSIONE_URL, altrimenti «versione.json» del paracadute (Cloudflare) di chi installa."""
    u = os.environ.get("FILTREO_VERSIONE_URL", "").strip()
    if not u:
        base = os.environ.get("FILTREO_PARACADUTE_URL", "").strip().rstrip("/")
        u = base + "/versione.json" if base else ""
    return u if re.match(r"^https://[a-z0-9.-]+(/[^\s]*)?$", u, re.I) else ""


def come_si_aggiorna():
    if os.environ.get("SUPERVISOR_TOKEN"):
        return "In Home Assistant: Impostazioni › Componenti aggiuntivi › Filtreo › «Aggiorna»."
    return "Dal Mac: apri l'installatore di Filtreo e seleziona «Aggiorna». Il filtro si riavvia per alcuni secondi."


def _stato_versione(ins, ultima, data, errore):
    r = {"installata": ins, "ultima": ultima or "", "data": data or "", "errore": errore or "",
         "controllata": int(time.time()) if ultima else 0, "come": come_si_aggiorna()}
    r["nuova"] = bool(ins and ultima and _tupla(ultima) > _tupla(ins))
    if r["nuova"]:
        r["testo"] = "Disponibile la versione %s." % ultima
    elif ultima:
        r["testo"] = "Filtreo %s · Aggiornato" % ins
    else:
        r["testo"] = errore or "Impossibile verificare."
    return r


def stato_versione():
    """quello che si sa senza rete: la versione installata e l'ultimo controllo riuscito (se c'è)."""
    ins = versione_installata()
    c = _leggi(FILE_CONTROLLO, {})
    ult = c.get("ultima") if isinstance(c, dict) and VERSIONE_RE.match(str(c.get("ultima") or "")) else ""
    r = _stato_versione(ins, ult, str(c.get("data") or "")[:10] if isinstance(c, dict) else "", "")
    r["controllata"] = int(c.get("quando") or 0) if isinstance(c, dict) and ult else 0
    if not ult:
        r["testo"] = "Filtreo %s." % ins if ins else "Versione non disponibile."
    return r


def controlla_versione(url=None, attesa=6):
    """«Verifica»: un solo giro di rete, con attesa breve. Mai un errore: se la rete manca o la fonte non è impostata
    ritorna lo stato con un testo chiaro e niente da aggiornare. Niente aggiornamento automatico."""
    ins = versione_installata()
    u = url if url is not None else _fonte_versione()
    if not u:
        return dict(_stato_versione(ins, "", "", "Impossibile verificare: indirizzo di Filtreo Cloud non configurato."), nuova=False)
    try:
        import urllib.request
        req = urllib.request.Request(u, headers={"User-Agent": "Filtreo-nodo", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=attesa) as r:
            j = json.loads(r.read(4000).decode("utf-8", "replace"))
        v = str(j.get("versione") or "") if isinstance(j, dict) else ""
        if not VERSIONE_RE.match(v):
            raise ValueError("risposta")
        data = str(j.get("data") or "")[:10]
    except Exception:
        s = stato_versione()
        s["errore"] = "Impossibile verificare: rete o Filtreo Cloud non disponibili. Riprova."
        if not s.get("ultima"):
            s["testo"] = s["errore"]
        return s
    _scrivi_json(FILE_CONTROLLO, {"ultima": v, "data": data, "quando": int(time.time())})
    return _stato_versione(ins, v, data, "")


# ───────────────────────── 2. copia di sicurezza ─────────────────────────
FORMATO = "filtreo-copia"
SCHEMA = 1
FILE_COPIA = os.path.join(DATA, "copia-ultima.json")
LISTE_DOMINI = (("consentiti", "bianca.txt"), ("sbloccati", "sblocca.txt"), ("anti_rilevamento", "anti-rilevamento.txt"), ("bloccati", "blocca.txt"))
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
COLORE_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
DOM_RE = re.compile(r"^(\*\.)?[a-z0-9_]([a-z0-9_.-]{0,250}[a-z0-9_])?$")
URL_RE = re.compile(r"^https?://[^\s/]+\.[^\s]+$")
IP_RE = re.compile(r"^[0-9a-fA-F:.]{3,45}$")
SEGRETO_RE = re.compile(r"codice|token|chiave|segret|password|secret|cf_|apikey", re.I)
MAX_BYTE_COPIA = 400000


def _senza_segreti(x):
    """rete di sicurezza: nella copia non entra mai un campo che somigli a una chiave."""
    if isinstance(x, dict):
        return {k: _senza_segreti(v) for k, v in x.items() if not SEGRETO_RE.search(str(k))}
    if isinstance(x, list):
        return [_senza_segreti(v) for v in x]
    return x


def _righe_file(nome):
    return [r.strip() for r in filtro._righe(nome) if r.strip() and not r.strip().startswith("#")]


def _modo_stabile(x):
    m = x.get("modo") or ""
    if m in (modalita.SPENTO, modalita.PAUSA):   # «senza filtro» e pausa sono a tempo: nella copia vale la modalità di prima
        m = x.get("modo_prima") or ""
    return m


def copia():
    """tutto ciò che hai scelto, e niente che dia accesso: dispositivi, modalità, liste scelte, eccezioni, blocchi, famiglia."""
    dispositivi = []
    for x in liste.dispositivi():
        d = {"id": x.get("id"), "nome": x.get("nome", ""), "ip": x.get("ip", ""), "ips": list(x.get("ips") or []),
             "proprie": bool(x.get("proprie")), "principale": bool(x.get("principale")), "modo": _modo_stabile(x)}
        if x.get("tipo"):
            d["tipo"] = x["tipo"]
        if x.get("proprietario"):
            d["proprietario"] = True
        dispositivi.append(d)
    fonti = [{"url": f.get("url"), "nome": f.get("nome", ""), "attiva": f.get("attiva", True), "categoria": f.get("categoria") or "",
              "dispositivi": list(f.get("dispositivi") or [])} for f in liste.fonti()]
    mod = [{k: m.get(k) for k in ("id", "nome", "colore", "fonti", "lavoro", "app", "auto", "passa", "bianca", "blocca", "solo_permessi", "famiglia", "pre", "descr", "fuori",
                                  "livello") if k in m} for m in modalita.elenco()]   # 3.1: «livello» (le differenze si ricavano dalle liste)
    out = {"formato": FORMATO, "schema": SCHEMA, "versione": versione_installata(), "creata": datetime.now().strftime("%Y-%m-%d %H:%M"),
           "dispositivi": dispositivi, "modalita": mod, "fonti": fonti, "famiglia": modalita.persone(),
           "pausa_durata": _leggi(os.path.join(DATA, "pausa-durata.json"), {}).get("durata") or ""}
    for chiave, nome in LISTE_DOMINI:
        out[chiave] = _righe_file(nome)
    return _senza_segreti(out)


def segna_copia():
    _scrivi_json(FILE_COPIA, {"quando": int(time.time())})


def ultima_copia():
    q = _leggi(FILE_COPIA, {}).get("quando")
    return int(q) if isinstance(q, (int, float)) else 0


def _txt(v, n):
    return re.sub(r"\s+", " ", str(v or "")).strip()[:n]


def _normalizza(d):
    """controlla e ripulisce un file di copia: ritorna la stessa forma di copia(). ValueError con un testo chiaro se non va."""
    if not isinstance(d, dict) or d.get("formato") != FORMATO:
        raise ValueError("Questo file non è una copia di Filtreo.")
    if not isinstance(d.get("schema"), int) or d["schema"] > SCHEMA:
        raise ValueError("Questa copia viene da una versione di Filtreo più nuova: aggiorna prima il filtro.")
    d = _senza_segreti(d)
    lista = lambda k: d.get(k) if isinstance(d.get(k), list) else []   # noqa: E731
    out = {"formato": FORMATO, "schema": SCHEMA, "versione": _txt(d.get("versione"), 12), "creata": _txt(d.get("creata"), 20)}
    ids_d = []
    dd = []
    for x in lista("dispositivi"):
        if not isinstance(x, dict) or not ID_RE.match(str(x.get("id") or "")) or x["id"] in ids_d:
            continue
        ids_d.append(x["id"])
        ip = str(x.get("ip") or "").strip()
        ips = [str(i).strip() for i in (x.get("ips") or []) if isinstance(i, str) and IP_RE.match(i.strip())][:8]
        dd.append({"id": x["id"], "nome": _txt(x.get("nome"), 40) or x["id"], "ip": ip if IP_RE.match(ip) else "", "ips": ips,
                   "proprie": bool(x.get("proprie")), "principale": bool(x.get("principale")), "modo": _txt(x.get("modo"), 40)})
        if x.get("tipo") in ("nodo", "android", "altro"):
            dd[-1]["tipo"] = x["tipo"]
        if x.get("proprietario") is True:
            dd[-1]["proprietario"] = True
    out["dispositivi"] = dd
    ff, urls = [], []
    for f in lista("fonti"):
        u = _txt(f.get("url") if isinstance(f, dict) else "", 300)
        if not URL_RE.match(u) or u in urls:
            continue
        urls.append(u)
        ff.append({"url": u, "nome": _txt(f.get("nome"), 60), "attiva": bool(f.get("attiva", True)),
                   "categoria": f.get("categoria") if f.get("categoria") in {c[0] for c in modalita.CATEGORIE} else "",
                   "dispositivi": [i for i in (f.get("dispositivi") or []) if i in ids_d]})
    out["fonti"] = ff
    servizi = {s["id"] for s in modalita.servizi()["servizi"]}
    app = {a["id"] for a in modalita.app_bloccabili()}
    casa = {s["id"] for s in modalita.servizi_casa()["servizi"]}
    mm, ids_m = [], []
    for m in lista("modalita"):
        if not isinstance(m, dict) or not ID_RE.match(str(m.get("id") or "")) or m["id"] in ids_m or m["id"] in (modalita.SPENTO, modalita.PAUSA):
            continue
        nome = _txt(m.get("nome"), 30)
        if not nome:
            continue
        ids_m.append(m["id"])
        mm.append({"id": m["id"], "nome": nome, "colore": m["colore"] if COLORE_RE.match(str(m.get("colore") or "")) else modalita.COLORI[0],
                   "fonti": [u for u in (m.get("fonti") or []) if u in urls], "lavoro": [s for s in (m.get("lavoro") or []) if s in servizi],
                   "app": [a for a in (m.get("app") or []) if a in app], "auto": m.get("auto") if isinstance(m.get("auto"), dict) else None,
                   "passa": [s for s in (m.get("passa") or []) if s in casa], "bianca": modalita.domini_utente(m.get("bianca") if isinstance(m.get("bianca"), list) else []),
                   "blocca": modalita.domini_utente(m.get("blocca") if isinstance(m.get("blocca"), list) else []), "solo_permessi": bool(m.get("solo_permessi")),
                   "famiglia": bool(m.get("famiglia")),
                   "pre": m.get("pre") if m.get("pre") in ("tv", "iot", "isolato", "server") else "", "descr": _txt(m.get("descr"), 200),
                   "fuori": m.get("fuori") if m.get("fuori") in ("pulito", "lavoro", "spento") else "",
                   "livello": m.get("livello") if m.get("livello") in ("base", "standard", "rigoroso") else ""})
    out["modalita"] = mm
    pp, ids_p = [], []
    for p in lista("famiglia"):
        if not isinstance(p, dict) or not ID_RE.match(str(p.get("id") or "")) or p["id"] in ids_p or not _txt(p.get("nome"), 30):
            continue
        ids_p.append(p["id"])
        n = p.get("nanna") if isinstance(p.get("nanna"), dict) else None
        pp.append({"id": p["id"], "nome": _txt(p.get("nome"), 30), "colore": p["colore"] if COLORE_RE.match(str(p.get("colore") or "")) else modalita.COLORI[3],
                   "dispositivi": [i for i in (p.get("dispositivi") or []) if i in ids_d], "modo": _txt(p.get("modo"), 40), "nanna": n})
    out["famiglia"] = pp
    out["pausa_durata"] = d.get("pausa_durata") if d.get("pausa_durata") in ("10m", "1h", "domani", "senza") else ""
    for chiave, _nome in LISTE_DOMINI:
        v, visti = [], set()
        for r in lista(chiave):
            r = str(r).strip().lower()
            if DOM_RE.match(r) and "." in r and r not in visti:
                visti.add(r)
                v.append(r)
        out[chiave] = v[:5000]
    return out


def _filtra_domini(chiave, righe, gia=()):
    """la logica di blocco non cambia: niente permessi per indirizzi pubblicitari, niente blocchi a servizi di base.
    Le righe che ci sono già nel file (per esempio le esche di base) restano com'erano: non sono un cambiamento."""
    ok, scartate = [], []
    for r in righe:
        d = r[2:] if r.startswith("*.") else r
        if r in gia:
            ok.append(r)
        elif chiave in ("consentiti", "sbloccati", "anti_rilevamento") and (liste._pubblicita(d) or d in liste.SENTINELLE):
            scartate.append(r)
        elif chiave == "bloccati" and liste.protetto(d):
            scartate.append(r)
        else:
            ok.append(r)
    return ok, scartate


def _differenze(nuovo, adesso):
    """cosa cambierebbe: [{voce, testo, dettagli[]}] e se cambia qualcosa."""
    righe, cambia = [], False

    def per_id(voce, a, b, chiave, nome, campi):
        nonlocal cambia
        cur = {x[chiave]: x for x in b}
        nuovi = [x[nome] for x in a if x[chiave] not in cur]
        cam = [x[nome] for x in a if x[chiave] in cur and any(x.get(c) != cur[x[chiave]].get(c) for c in campi)]
        parti = []
        if nuovi:
            parti.append("%d %s" % (len(nuovi), "nuovo" if len(nuovi) == 1 else "nuovi"))
        if cam:
            parti.append("%d %s" % (len(cam), "cambiato" if len(cam) == 1 else "cambiati"))
        if parti:
            cambia = True
        righe.append({"voce": voce, "testo": ", ".join(parti) or "Nessuna differenza", "dettagli": (nuovi + cam)[:8], "cambia": bool(parti)})

    per_id("Dispositivi", nuovo["dispositivi"], adesso["dispositivi"], "id", "nome", ("nome", "proprie", "modo"))
    per_id("Filtri selezionati", nuovo["fonti"], adesso["fonti"], "url", "nome", ("attiva", "categoria", "dispositivi"))
    per_id("Profili", nuovo["modalita"], adesso["modalita"], "id", "nome", ("nome", "colore", "fonti", "lavoro", "app", "auto", "passa", "bianca", "blocca", "solo_permessi", "famiglia"))
    per_id("Famiglia", nuovo["famiglia"], adesso["famiglia"], "id", "nome", ("nome", "dispositivi", "modo", "nanna"))
    for chiave, voce in (("consentiti", "Siti consentiti"), ("sbloccati", "Siti consentiti"), ("anti_rilevamento", "Siti con Filtreo rilevato"), ("bloccati", "Siti bloccati")):
        a, b = set(nuovo[chiave]), set(adesso[chiave])
        agg, tol = sorted(a - b), (sorted(b - a) if chiave != "anti_rilevamento" else [])
        parti = []
        if agg:
            parti.append("%d da aggiungere" % len(agg))
        if tol:
            parti.append("%d da togliere" % len(tol))
        if parti:
            cambia = True
        righe.append({"voce": voce, "testo": ", ".join(parti) or "Nessuna differenza", "dettagli": (agg + tol)[:8], "cambia": bool(parti)})
    return righe, cambia


def anteprima(dati):
    """cosa cambierà se si ripristina questo file. Non scrive niente."""
    try:
        n = _normalizza(dati)
    except ValueError as e:
        return {"ok": False, "testo": str(e)}
    righe, cambia = _differenze(n, _normalizza(copia()))
    note = []
    for chiave, _f in LISTE_DOMINI:
        _ok, sc = _filtra_domini(chiave, n[chiave], _righe_file(_f))
        if sc:
            note.append("%d voci in «%s» non si possono ripristinare (pubblicità o servizi di base)." % (len(sc), chiave.replace("_", " ")))
    return {"ok": True, "testo": "Copia del %s%s." % (n["creata"] or "?", (", Filtreo " + n["versione"]) if n["versione"] else ""),
            "voci": righe, "cambia": cambia, "note": note}


def ripristina(dati, applica=True):
    """applica la copia. Aggiunge e aggiorna dispositivi, liste, modalità e famiglia (non toglie niente); le liste di siti
    (consentiti, bloccati) diventano esattamente quelle della copia. Ritorna (ok, testo)."""
    try:
        n = _normalizza(dati)
    except ValueError as e:
        return False, str(e)
    righe, cambia = _differenze(n, _normalizza(copia()))
    if not cambia:
        return True, "Nessuna modifica: configurazione già identica alla copia."
    nuove_fonti = []
    ids_d = {x["id"] for x in liste.dispositivi()} | {x["id"] for x in n["dispositivi"]}
    with liste._blocco:
        # modalità (prima: i dispositivi e la famiglia le nominano)
        with modalita._blocco:
            mm = modalita._leggi()
            idx = {m["id"]: m for m in mm}
            urls = {f["url"] for f in liste.fonti()} | {f["url"] for f in n["fonti"]}
            ids_m = set(idx) | {m["id"] for m in n["modalita"]} | {modalita.SPENTO, modalita.PAUSA}
            for m in n["modalita"]:
                cur = idx.get(m["id"])
                if cur is None:
                    cur = {"id": m["id"]}
                    mm.append(cur)
                cur.update({"nome": m["nome"], "colore": m["colore"], "fonti": [u for u in m["fonti"] if u in urls], "lavoro": m["lavoro"], "app": m["app"],
                            "passa": m["passa"], "bianca": m["bianca"], "blocca": m["blocca"], "solo_permessi": m["solo_permessi"],
                            "famiglia": m["famiglia"]})
                for k in ("pre", "descr", "fuori"):
                    if m[k]:
                        cur[k] = m[k]
                cur["auto"] = modalita._pulisci_auto(m["auto"], ids_m, ids_d) if m["auto"] else None
                # 3.1: le liste della copia sono la verità; il livello (della copia, o quello che c'era) e le differenze si ricavano da lì,
                # altrimenti il riallineamento dei livelli rimetterebbe le liste di prima del ripristino
                if m.get("livello"):
                    cur["livello"] = m["livello"]
                if cur.get("livello"):
                    import livelli
                    livelli.ricalcola_diff(cur)
            modalita._salva(mm)
        # dispositivi
        dd = liste.dispositivi()
        idx = {x["id"]: x for x in dd}
        ha_principale = any(x.get("principale") for x in dd)
        for x in n["dispositivi"]:
            cur = idx.get(x["id"])
            modo = x["modo"] if (x["modo"] in ids_m and x["modo"] not in (modalita.SPENTO, modalita.PAUSA)) else ""
            if cur is None:
                if x["ip"] and any(y.get("ip") == x["ip"] for y in dd):
                    continue   # quell'indirizzo è già di un altro dispositivo
                cur = {"id": x["id"]}
                if x["principale"] and not ha_principale:
                    cur["principale"] = True
                    ha_principale = True
                dd.append(cur)
                idx[x["id"]] = cur
            cur["nome"] = x["nome"]
            cur["proprie"] = x["proprie"] or bool(cur.get("principale"))
            if x["ip"]:
                cur["ip"] = x["ip"]
            else:
                cur.setdefault("ip", "")
            if x["ips"]:
                cur["ips"] = x["ips"]
            if x.get("tipo"):
                cur["tipo"] = x["tipo"]
            if x.get("proprietario"):
                cur["proprietario"] = True
            if cur["proprie"] and modo and cur.get("modo") not in (modalita.SPENTO, modalita.PAUSA):
                cur["modo"] = modo
        liste._salva(liste.DISP_JSON, dd)
        # liste scelte
        ff = liste.fonti()
        idx = {f["url"]: f for f in ff}
        for x in n["fonti"]:
            cur = idx.get(x["url"])
            if cur is None:
                cur = {"url": x["url"], "nome": x["nome"]}
                ff.append(cur)
                nuove_fonti.append(cur)
            cur["attiva"] = x["attiva"]
            cur["dispositivi"] = x["dispositivi"] or cur.get("dispositivi") or [liste.PRINCIPALE]
            if x["categoria"]:
                cur["categoria"] = x["categoria"]
        liste._salva(liste.FONTI_JSON, ff)
    # famiglia
    pp = modalita.persone()
    idx = {p["id"]: p for p in pp}
    for p in n["famiglia"]:
        cur = idx.get(p["id"])
        if cur is None:
            cur = {"id": p["id"]}
            pp.append(cur)
        ok_ora = lambda s: bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", s or ""))   # noqa: E731
        nn = p["nanna"]
        nanna = None
        if isinstance(nn, dict) and nn.get("attivo") and ok_ora(nn.get("da")) and ok_ora(nn.get("a")):
            nanna = {"attivo": True, "da": nn["da"], "a": nn["a"],
                     "giorni": sorted({int(g) for g in nn.get("giorni", range(7)) if str(g).isdigit() and 0 <= int(g) <= 6}) or list(range(7))}
        cur.update({"nome": p["nome"], "colore": p["colore"], "dispositivi": p["dispositivi"],
                    "modo": p["modo"] if p["modo"] in ids_m else "", "nanna": nanna})
    modalita._salva_persone(pp)
    # siti
    for chiave, nome in LISTE_DOMINI:
        ok, _sc = _filtra_domini(chiave, n[chiave], _righe_file(nome))
        if chiave == "anti_rilevamento":   # i file «esca» di base restano sempre
            ok = sorted(set(ok) | set(_righe_file(nome)))
        elif chiave == "consentiti":       # le esche fisse stanno nello stesso file: non si perdono
            ok = ok + [r for r in _righe_file(nome) if r.lstrip("*.") in liste.ESCHE_OK and r not in ok]
        filtro._scrivi(nome, ok)
    if n["pausa_durata"]:
        _scrivi_json(os.path.join(DATA, "pausa-durata.json"), {"durata": n["pausa_durata"]})
    if applica:
        try:
            cambiata = liste.scrivi_config()
            liste._applica(config_cambiata=cambiata)
            liste.sincronizza_paracadute()
            if nuove_fonti:
                threading.Thread(target=liste._aggiorna_fonti, args=(nuove_fonti,), daemon=True).start()
        except Exception:
            pass
    return True, "Copia ripristinata. Il filtro si aggiorna in pochi secondi%s." % (", le liste nuove si scaricano in sottofondo" if nuove_fonti else "")


# ───────────────────────── 3. avvisi su Telegram ─────────────────────────
FILE_AVVISI = os.path.join(DATA, "avvisi.json")
FILE_AVVISI_STATO = os.path.join(DATA, "avvisi-stato.json")
VOCI_AVVISI = (
    ("riavvio", "Filtro riavviato", "Avviso al riavvio del filtro.", True),
    ("casa", "Casa non disponibile", "Avviso quando Casa non è disponibile per alcuni minuti e alla ripresa.", True),
    ("riepilogo", "Riepilogo settimanale", "Ogni lunedì mattina, i dati dei 7 giorni.", False),
)
SPIEGA_TELEGRAM = ("Richiede un bot di Telegram: crealo con @BotFather, salva codice del bot e numero della chat in una cartella "
                   "(file «.tg_token» e «.tg_owner») e indicala nelle opzioni del filtro (FILTREO_TG_DIR). "
                   "Dopo il riavvio gli avvisi sono attivabili.")
ATTESA_CASA_SEC = 180
MIN_TRA_RIAVVII_SEC = 600


def telegram_ok():
    """c'è una configurazione Telegram usabile? Si guarda solo se i due file ci sono e non sono vuoti: i valori non si leggono qui."""
    d = os.environ.get("FILTREO_TG_DIR", "").strip()
    try:
        return bool(d) and all(os.path.getsize(os.path.join(d, n)) > 0 for n in (".tg_token", ".tg_owner"))
    except OSError:
        return False


def _impostazioni():
    s = _leggi(FILE_AVVISI, {})
    return s if isinstance(s, dict) else {}


def avvisi_stato():
    tg, s = telegram_ok(), _impostazioni()
    voci = [{"id": i, "nome": n, "descrizione": d, "attivo": bool(tg and s.get(i, pre))} for i, n, d, pre in VOCI_AVVISI]
    return {"telegram": tg, "voci": voci, "attivi": sum(1 for v in voci if v["attivo"]), "spiega": "" if tg else SPIEGA_TELEGRAM}


def avvisi_imposta(chiave, valore):
    if chiave not in {v[0] for v in VOCI_AVVISI}:
        return False, "Avviso non valido."
    if not telegram_ok():
        return False, "Telegram non configurato: avvisi disattivati."
    s = _impostazioni()
    s[chiave] = bool(valore)
    if not _scrivi_json(FILE_AVVISI, s):
        return False, "Impossibile salvare. Riprova."
    nome = next(v[1] for v in VOCI_AVVISI if v[0] == chiave)
    return True, "«%s» %s." % (nome, "acceso" if valore else "spento")


def avvisi_prova():
    if not telegram_ok():
        return False, "Telegram non configurato."
    ok = liste.avvisa("Filtreo: messaggio di prova. Avvisi configurati.")
    return ok, "Messaggio inviato" if ok else "Impossibile inviare. Verifica bot e chat."


_mem = {"pid": None, "riavvio_atteso": 0.0, "ultimo_riavvio": 0.0}


def _pid_motore():
    try:
        return int(open(liste.PID_BLOCKY).read().strip())
    except (OSError, ValueError):
        return None


def testo_riepilogo(resoconto, oggi=None):
    """il testo del riepilogo settimanale: gli ultimi 7 giorni finiti (oggi, che è a metà, non si conta)."""
    oggi = oggi or date.today().isoformat()
    try:
        j = resoconto(8)
    except Exception:
        return ""
    gg = [g for g in (j.get("giorni") or []) if g.get("giorno") and g["giorno"] < oggi][-7:]
    if not gg:
        return ""
    bl, ca, cf, ri = (sum(int(g.get(k) or 0) for g in gg) for k in ("bloccate", "casa", "cloudflare", "richieste"))
    t = "Filtreo · 7 giorni: %s richieste bloccate" % _num(bl)
    if cf:
        t += " (Casa %s · Filtreo Cloud %s)" % (_num(ca), _num(cf))
    if ri:
        t += ", il %d%% del traffico" % round(100 * bl / ri)
    t += "."
    d0 = (j.get("dispositivi") or [None])[0]
    if d0 and d0.get("nome"):
        t += " Dispositivo con più blocchi: «%s»." % d0["nome"]
    az = [a["nome"] for a in (j.get("aziende") or [])[:3] if a.get("nome")]
    if az:
        t += " Domini più bloccati: %s." % ", ".join(az)
    return t


def giro(adesso=None):
    """una volta al minuto (lo chiama il giro dell'orologio del pannello). Mai un errore, nessun cron nuovo.
    Senza Telegram non fa niente."""
    if not telegram_ok():
        return []
    ora = adesso if adesso is not None else time.time()
    imp = _impostazioni()
    st = _leggi(FILE_AVVISI_STATO, {})
    st = st if isinstance(st, dict) else {}
    mandati = []

    def attivo(k):
        return bool(imp.get(k, next(p for i, _n, _d, p in VOCI_AVVISI if i == k)))

    def manda(testo):
        ok = liste.avvisa(testo)
        if ok:
            mandati.append(testo)
        return ok

    su = filtro.stato_api().get("raggiungibile")
    # Casa non risponde
    if not su:
        if not st.get("giu_da"):
            st["giu_da"] = ora
        if attivo("casa") and not st.get("giu_avvisato") and ora - st["giu_da"] >= ATTESA_CASA_SEC:
            if manda("Filtreo: Casa non disponibile da alcuni minuti. Filtreo Cloud continua a filtrare i dispositivi configurati."):
                st["giu_avvisato"] = True
    else:
        if st.get("giu_avvisato") and attivo("casa"):
            manda("Filtreo: Casa di nuovo disponibile.")
        st.pop("giu_da", None)
        st.pop("giu_avvisato", None)
    # filtro riavviato: il motore ha cambiato numero di processo (ripartito) e ora risponde
    pid = _pid_motore()
    if pid is not None and _mem["pid"] is not None and pid != _mem["pid"]:
        _mem["riavvio_atteso"] = ora
    if pid is not None:
        _mem["pid"] = pid
    if _mem["riavvio_atteso"] and su:
        _mem["riavvio_atteso"] = 0.0
        if attivo("riavvio") and ora - _mem["ultimo_riavvio"] >= MIN_TRA_RIAVVII_SEC:
            if manda("Filtreo: filtro riavviato e attivo."):
                _mem["ultimo_riavvio"] = ora
    # riepilogo settimanale: lunedì dalle 9, una volta per settimana, al massimo un tentativo all'ora
    dt = datetime.fromtimestamp(ora)
    sett = "%d-W%02d" % dt.isocalendar()[:2]
    if attivo("riepilogo") and dt.weekday() == 0 and dt.hour >= 9 and st.get("riepilogo") != sett and ora - (st.get("riepilogo_tentato") or 0) >= 3600:
        st["riepilogo_tentato"] = ora
        r = COLLEGA.get("resoconto")
        t = testo_riepilogo(r, dt.date().isoformat()) if r else ""
        if t and manda(t):
            st["riepilogo"] = sett
    _scrivi_json(FILE_AVVISI_STATO, st)
    return mandati
