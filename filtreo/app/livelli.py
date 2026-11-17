#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""livelli.py — Filtreo 3.1: il livello è un PUNTO DI PARTENZA, non una gabbia. E le categorie a GRUPPI.

Livelli preimpostati (si sceglie uno, poi si cambia quello che si vuole):
  base      «Base»      Pubblicità + Sicurezza
  standard  «Standard»  + Tracciamento                (consigliato)
  rigoroso  «Rigoroso»  + Fastidi (avvisi cookie, pop-up, widget)
La «Protezione famiglia» resta un interruttore a parte (vale con qualsiasi livello) e non conta come modifica.
La Telemetria per marca e i gruppi Famiglia/Social non sono in nessun livello: si aggiungono a mano (o con i profili pronti).

Come si memorizza (modalita.json, dentro la modalità che i dispositivi usano già):
  "livello": "standard"                       il preimpostato da cui parte
  "diff": {"fonti_piu": [url…], "fonti_meno": [url…]}   SOLO le differenze sulle liste
  le altre differenze sono i campi che il preimpostato ha vuoti: lavoro, app, blocca, bianca, passa, solo_permessi.
  "fonti" resta scritto per intero (= preimpostato + più − meno): è una copia calcolata, la tengono aggiornata
  riallinea() e ricalcola_diff(). Così tutto il resto del motore (liste per gruppo, paracadute, app vecchie) non cambia.
Una modalità senza «livello» (TV e casse, Isolato, profili creati a mano) resta com'era: niente «modificato».

Stato «modificato»: almeno una differenza → etichetta «Standard · modificato»; «Torna a Standard» le toglie tutte.

«Personale» (scelta motivata): NON si cancella e non cambia id. Diventa «Standard modificato» (livello = standard, differenze
calcolate dalle sue liste e dai suoi strumenti di lavoro): cosa blocca resta identico, i dispositivi restano lì, e le app
2.x/3.0 che cercano il profilo per nome («Personale») continuano a trovarlo. Le app 3.1 mostrano l'etichetta calcolata.

Gruppi di categorie (Filtri 3.1): Pubblicità, Tracciamento, Sicurezza, Fastidi, Famiglia, Telemetria per marca.
Ogni gruppo: stato «tutto» / «niente» / «parziale» (n su m) e l'azione «tutto il gruppo sì/no» (sulla modalità scelta).
"""
import json
import os
import re
import time

import filtro
import modalita

FONTI_JSON = os.path.join(filtro.DATA, "fonti.json")
MIGRATI = os.path.join(filtro.DATA, "modalita-livelli-31.json")

# (id, nome, frase)
GRUPPI = [
    ("pubblicita", "Pubblicità", "Annunci, banner e pop-up pubblicitari."),
    ("tracciamento", "Tracciamento", "Chi registra cosa fai su siti e app."),
    ("sicurezza", "Sicurezza", "Truffe, malware e siti pericolosi."),
    ("fastidi", "Fastidi", "Avvisi sui cookie, pop-up e widget dei social."),
    ("famiglia", "Famiglia", "Contenuti per adulti, scommesse e social network."),
    ("telemetria", "Telemetria per marca", "Dati che TV, telefoni e sistemi mandano al produttore."),
]
NOMI_GRUPPI = {g[0]: g[1] for g in GRUPPI}
# «Fastidi»: le liste «Elementi di disturbo» (cookie, pop-up, banner delle app) e le «annoyance» di Fanboy/EasyList
_RX_FASTIDI = re.compile(r"elementi di disturbo|annoyance|cookiemonster|fanboy-social", re.I)

LIVELLI = [
    ("base", "Base", ("pubblicita", "sicurezza"), "Pubblicità e siti pericolosi."),
    ("standard", "Standard", ("pubblicita", "sicurezza", "tracciamento"), "Pubblicità, tracciamento e siti pericolosi."),
    ("rigoroso", "Rigoroso", ("pubblicita", "sicurezza", "tracciamento", "fastidi"), "Anche avvisi sui cookie, pop-up e widget."),
]
_LIV = {x[0]: x for x in LIVELLI}
# nomi e id usati prima (app 2.x/3.0: base, pulito, massimo, lavoro) → livello 3.1
ALIAS = {"base": "base", "standard": "standard", "pulito": "standard", "rigoroso": "rigoroso", "massimo": "rigoroso",
         "personale": "standard", "lavoro": "standard"}
# campi che nel preimpostato sono vuoti: se non lo sono, sono differenze
CAMPI_EXTRA = ("lavoro", "app", "blocca", "bianca", "passa")


def norma_livello(x):
    """«Standard», «pulito», «massimo»… → id del livello 3.1 (o None)."""
    return ALIAS.get(re.sub(r"\s+", "", str(x or "")).lower())


def _fonti():
    try:
        d = json.load(open(FONTI_JSON, encoding="utf-8"))
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def gruppo_fonte(f):
    """il gruppo 3.1 di una lista (dalla sua categoria; «Fastidi» dal nome)."""
    c = modalita.categoria(f)
    if c in ("adulti", "scommesse", "social"):
        return "famiglia"
    if c == "telemetria":
        return "telemetria"
    if c == "truffe":
        return "sicurezza"
    if c == "tracciatori":
        return "tracciamento"
    if _RX_FASTIDI.search("%s %s" % (f.get("nome", ""), f.get("url", ""))):
        return "fastidi"
    return "pubblicita"


def fonti_livello(liv, ff=None):
    """le liste del preimpostato: tutte quelle (non dormienti per marca/famiglia) dei gruppi del livello."""
    x = _LIV.get(liv)
    if not x:
        return []
    ff = _fonti() if ff is None else ff
    return [f["url"] for f in ff if not f.get("casa") and gruppo_fonte(f) in x[2]]


def _diff(m):
    d = m.get("diff")
    if not isinstance(d, dict):
        d = {}
    return {"fonti_piu": [u for u in d.get("fonti_piu", []) if isinstance(u, str)],
            "fonti_meno": [u for u in d.get("fonti_meno", []) if isinstance(u, str)]}


def materializza(m, ff=None):
    """riscrive m["fonti"] = preimpostato + più − meno (solo liste che esistono). True se è cambiata."""
    liv = m.get("livello")
    if liv not in _LIV:
        return False
    ff = _fonti() if ff is None else ff
    esistenti = {f["url"] for f in ff}
    d = _diff(m)
    nuove = (set(fonti_livello(liv, ff)) | set(d["fonti_piu"])) - set(d["fonti_meno"])
    ordine = [f["url"] for f in ff if f["url"] in nuove and f["url"] in esistenti]
    if ordine != list(m.get("fonti") or []):
        m["fonti"] = ordine
        return True
    return False


def ricalcola_diff(m, ff=None):
    """dopo che qualcuno ha scritto m["fonti"] per intero (pannello web, app 3.0): ricava più/meno dal preimpostato."""
    liv = m.get("livello")
    if liv not in _LIV:
        return
    ff = _fonti() if ff is None else ff
    pre, ora = set(fonti_livello(liv, ff)), set(m.get("fonti") or [])
    m["diff"] = {"fonti_piu": [f["url"] for f in ff if f["url"] in ora - pre],
                 "fonti_meno": [f["url"] for f in ff if f["url"] in pre - ora]}


def differenze(m, ff=None):
    """le differenze di una modalità dal suo livello, con i nomi da mostrare. {} se non ha un livello."""
    liv = m.get("livello")
    if liv not in _LIV:
        return {}
    ff = _fonti() if ff is None else ff
    per = {f["url"]: f for f in ff}
    d = _diff(m)

    def riga(u):
        f = per.get(u, {"url": u})
        return {"url": u, "nome": f.get("nome", "") or u, "gruppo": gruppo_fonte(f) if u in per else ""}
    out = {"fonti_piu": [riga(u) for u in d["fonti_piu"] if u in per],
           "fonti_meno": [riga(u) for u in d["fonti_meno"] if u in per]}
    for k in CAMPI_EXTRA:
        out[k] = list(m.get(k) or [])
    out["solo_permessi"] = bool(m.get("solo_permessi"))
    out["n"] = len(out["fonti_piu"]) + len(out["fonti_meno"]) + sum(len(out[k]) for k in CAMPI_EXTRA) + (1 if out["solo_permessi"] else 0)
    return out


def etichetta(m, ff=None):
    """«Standard», «Standard · modificato», oppure il nome della modalità se non parte da un livello."""
    liv = m.get("livello")
    if liv not in _LIV:
        return m.get("nome", "")
    return _LIV[liv][1] + (" · modificato" if differenze(m, ff).get("n") else "")


def scheda(m, ff=None):
    """i campi 3.1 di una modalità (si aggiungono a quelli di sempre nelle risposte del pannello)."""
    ff = _fonti() if ff is None else ff
    liv = m.get("livello") if m.get("livello") in _LIV else None
    d = differenze(m, ff) if liv else {}
    return {"livello": liv, "livello_nome": _LIV[liv][1] if liv else "", "modificato": bool(d.get("n")),
            "n_differenze": int(d.get("n") or 0), "etichetta": etichetta(m, ff),
            "alias": m.get("nome", "") if liv and m.get("nome", "").lower() != _LIV[liv][1].lower() else ""}


# ───────────── lettura e scrittura (dentro modalita.json) ─────────────
def _cerca(mm, mid):
    return next((x for x in mm if x.get("id") == mid), None)


def riallinea(ff=None):
    """per ogni modalità con un livello: «fonti» = preimpostato + differenze (se una lista nuova entra in un gruppo del livello,
    entra da sola). Chiamata prima di riscrivere le liste. Ritorna quante modalità ha aggiornato."""
    ff = _fonti() if ff is None else ff
    with modalita._blocco:
        mm = modalita._leggi()
        n = sum(1 for m in mm if materializza(m, ff))
        if n:
            modalita._salva(mm)
    return n


def migra(ff=None):
    """una tantum (3.1): dà un livello alle modalità di serie e crea i preimpostati che mancano. Niente cambia in quello che si blocca:
      «Base» → base, «Standard»/«Pulito» → standard, «Rigoroso»/«Massimo» → rigoroso, «Personale»/«Lavoro» → standard (modificato);
      le differenze si ricavano dalle liste che la modalità ha OGGI (fonti invariate).
    Poi, se nessuna modalità parte da un livello, la crea (es. «Base» su Casa non c'era): non la usa nessuno finché non la si sceglie.
    Ritorna il riassunto ({} se già fatta)."""
    with modalita._blocco:
        if os.path.exists(MIGRATI) or not os.path.exists(modalita.FILE):
            return {}
        ff = _fonti() if ff is None else ff
        mm = modalita._leggi()
        fatte, create = [], []
        for m in mm:
            if m.get("livello") or m.get("id") in (modalita.SPENTO, modalita.PAUSA):
                continue
            liv = norma_livello(m.get("nome"))
            if not liv:
                continue
            m["livello"] = liv
            ricalcola_diff(m, ff)   # dalle liste di adesso: «fonti» non cambia
            fatte.append({"id": m["id"], "nome": m.get("nome"), "livello": liv, "differenze": differenze(m, ff).get("n", 0)})
        for liv, nome, _g, descr in LIVELLI:
            if any(x.get("livello") == liv for x in mm):
                continue
            if any(str(x.get("nome", "")).lower() == nome.lower() for x in mm):
                continue
            nuova = {"id": "m-%s" % liv, "nome": nome, "colore": modalita.COLORI[len(mm) % len(modalita.COLORI)], "livello": liv,
                     "diff": {}, "fonti": [], "lavoro": [], "app": [], "passa": [], "bianca": [], "blocca": [], "famiglia": False,
                     "auto": None, "descr": descr}
            if _cerca(mm, nuova["id"]):
                nuova["id"] = "m-%s-%d" % (liv, int(time.time()) % 100000)
            materializza(nuova, ff)
            mm.append(nuova)
            create.append({"id": nuova["id"], "nome": nome})
        modalita._salva(mm)
        rias = {"quando": time.time(), "livelli": fatte, "create": create}
        with open(MIGRATI + ".tmp", "w", encoding="utf-8") as h:
            json.dump(rias, h, ensure_ascii=False)
        os.replace(MIGRATI + ".tmp", MIGRATI)
        return rias


def panoramica(principale_modo="", ff=None):
    """GET /pannello/livelli: i tre livelli e, per ogni modalità, da che livello parte e se è modificata."""
    ff = _fonti() if ff is None else ff
    mm = modalita._leggi()
    return {"livelli": [{"id": l, "nome": n, "gruppi": list(g), "descr": d, "n_liste": len(fonti_livello(l, ff)),
                         "modalita": next((m["id"] for m in mm if m.get("livello") == l and not differenze(m, ff).get("n")), "")}
                        for l, n, g, d in LIVELLI],
            "modalita": [dict({"id": m["id"], "nome": m.get("nome", ""), "colore": m.get("colore", "")}, **scheda(m, ff)) for m in mm],
            "principale": principale_modo}


def torna(mid, livello=None):
    """«Torna a Standard»: toglie tutte le differenze (liste, strumenti, app, siti del profilo). Con livello= cambia anche il punto
    di partenza (es. da Standard a Rigoroso). Protezione famiglia, orari, nome e colore restano. Ritorna (ok, testo)."""
    with modalita._blocco:
        mm = modalita._leggi()
        m = _cerca(mm, mid)
        if not m:
            return False, "Profilo non trovato. Ricarica la pagina e riprova."
        liv = norma_livello(livello) if livello else m.get("livello")
        if liv not in _LIV:
            return False, "Livello non valido: scegli Base, Standard o Rigoroso."
        m["livello"] = liv
        m["diff"] = {}
        for k in CAMPI_EXTRA:
            m[k] = []
        m["solo_permessi"] = False
        materializza(m, _fonti())
        modalita._salva(mm)
        return True, "«%s» è di nuovo %s." % (m.get("nome", ""), _LIV[liv][1])


def _scrivi_fonti(mid, cambia):
    """applica cambia(m, set_fonti) → nuovo set di fonti; ricalcola le differenze. Ritorna (ok, testo, m)."""
    ff = _fonti()
    with modalita._blocco:
        mm = modalita._leggi()
        m = _cerca(mm, mid)
        if not m or m.get("id") in (modalita.SPENTO, modalita.PAUSA):
            return False, "Profilo non trovato o non modificabile.", None
        esistenti = {f["url"] for f in ff}
        nuove = cambia(m, set(m.get("fonti") or [])) & esistenti
        m["fonti"] = [f["url"] for f in ff if f["url"] in nuove]
        ricalcola_diff(m, ff)
        modalita._salva(mm)
        return True, "", dict(m)


def urls_gruppo(gid, ff=None):
    ff = _fonti() if ff is None else ff
    return [f["url"] for f in ff if gruppo_fonte(f) == gid]


def imposta_gruppo(mid, gid, attiva):
    """«tutto il gruppo sì/no» sulla modalità mid. Famiglia: accende/spegne anche la Protezione famiglia (adulti e scommesse
    la seguono). Ritorna (ok, testo)."""
    if gid not in NOMI_GRUPPI:
        return False, "Gruppo non valido."
    uu = set(urls_gruppo(gid))
    if not uu:
        return False, "Nessun filtro in «%s». Aggiungine uno da Filtri." % NOMI_GRUPPI[gid]
    ok, t, m = _scrivi_fonti(mid, lambda m, s: (s | uu) if attiva else (s - uu))
    if not ok:
        return ok, t
    if gid == "famiglia":
        modalita.imposta_famiglia(mid, bool(attiva))
    return True, "«%s»: %s %s." % (m.get("nome", ""), NOMI_GRUPPI[gid], "attivo" if attiva else "spento")


def imposta_riga(mid, url, attiva):
    """una sola lista sì/no nella modalità mid. Ritorna (ok, testo)."""
    ff = _fonti()
    f = next((x for x in ff if x["url"] == url), None)
    if not f:
        return False, "Filtro non trovato. Ricarica la pagina e riprova."
    ok, t, m = _scrivi_fonti(mid, lambda m, s: (s | {url}) if attiva else (s - {url}))
    if not ok:
        return ok, t
    if not attiva and modalita.categoria(f) in modalita.CAT_PROTEZIONE and m.get("famiglia"):
        # con la Protezione famiglia accesa adulti e scommesse restano comunque: lo si dice invece di fingere
        return True, "«%s» tolto, ma resta attivo con la Protezione famiglia accesa." % (f.get("nome") or url)
    return True, "«%s» %s." % (f.get("nome") or url, "attivo" if attiva else "spento")


def stato_gruppi(m, fonti_effettive, ff=None):
    """GET /pannello/gruppi: i gruppi con stato tutto/niente/parziale (n di m) e le righe.
    fonti_effettive = le liste che la modalità usa davvero (con la Protezione famiglia: filtreo_liste.fonti_di)."""
    ff = _fonti() if ff is None else ff
    usate = set(fonti_effettive)
    out = []
    for gid, nome, frase in GRUPPI:
        righe = [{"url": f["url"], "nome": f.get("nome", "") or f["url"], "attiva": f["url"] in usate,
                  "globale": bool(f.get("attiva", True)), "dormiente": bool(f.get("casa")) and f["url"] not in usate,
                  "domini": int(f.get("domini") or 0), "categoria": modalita.categoria(f)}
                 for f in ff if gruppo_fonte(f) == gid]
        n = sum(1 for r in righe if r["attiva"])
        tot = len(righe)
        stato = "niente" if n == 0 else ("tutto" if n == tot else "parziale")
        out.append({"id": gid, "nome": nome, "frase": frase, "stato": stato, "attive": n, "totale": tot,
                    "testo": ("%d su %d" % (n, tot)) if tot else "nessun filtro",
                    "nel_livello": bool(m.get("livello") in _LIV and gid in _LIV[m["livello"]][2]), "righe": righe})
    return {"modo": m.get("id"), "nome": m.get("nome", ""), **scheda(m, ff), "famiglia": bool(m.get("famiglia")), "gruppi": out}
