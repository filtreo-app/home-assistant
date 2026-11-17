#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""importa_nodo.py — porta le impostazioni del vecchio pannello del Jetson (~/filtro) nella 1.5.

  python3 importa_nodo.py <cartella vecchia ~/filtro> <cartella dati 1.5>

Legge soltanto la cartella vecchia (non la cambia). Scrive nella cartella nuova:
dispositivi, liste, permessi e blocchi a mano, DNS fuori casa (stessi codici: i profili già
installati continuano a funzionare), config di base di Blocky (upstream, nomi locali).
Stampa un riassunto senza codici segreti.
"""
import json
import os
import shutil
import sys

PRINCIPALE_NUOVO = "casa"


def leggi(p, d):
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return d


def salva(p, obj):
    with open(p + ".tmp", "w", encoding="utf-8") as h:
        json.dump(obj, h, ensure_ascii=False, indent=1)
    os.replace(p + ".tmp", p)


def ascolto_dns(testo):
    """da «ports: dns: …» della config di Blocky (senza bisogno di yaml)."""
    import re
    righe = testo.splitlines()
    for i, r in enumerate(righe):
        if re.match(r"^ports:\s*$", r):
            for j in range(i + 1, len(righe)):
                if righe[j].strip() and not righe[j].startswith(" "):
                    break
                m = re.match(r"^\s+dns:\s*(.*)$", righe[j])
                if m:
                    v = m.group(1).strip().strip("'\"")
                    if v:
                        return [x.strip().strip("'\"") for x in v.strip("[]").split(",") if x.strip()]
                    out = []
                    for k in range(j + 1, len(righe)):
                        mm = re.match(r"^\s+-\s*(.+)$", righe[k])
                        if not mm:
                            break
                        out.append(mm.group(1).strip().strip("'\""))
                    return out
    return []


def importa(vecchia, nuova):
    os.makedirs(os.path.join(nuova, "liste"), exist_ok=True)
    os.makedirs(os.path.join(nuova, "fonti"), exist_ok=True)
    os.makedirs(os.path.join(nuova, "log"), exist_ok=True)
    rapporto = []
    dd = leggi(os.path.join(vecchia, "dispositivi.json"), [])
    pr = next((x for x in dd if x.get("modo") == "principale"), None)
    vecchio_pr = pr["id"] if pr else "lavoro"
    mappa = {vecchio_pr: PRINCIPALE_NUOVO}

    # ── modalità: una per gruppo vecchio (stesse liste, strumenti di lavoro se aveva lavoro-bianca)
    import secrets
    ff = leggi(os.path.join(vecchia, "fonti.json"), [])
    serv = leggi(os.path.join(os.path.dirname(os.path.abspath(__file__)), "servizi-lavoro.json"), {"servizi": [], "modelli": []})
    marketing = next((m["servizi"] for m in serv["modelli"] if m["id"] == "marketing"), [])
    modi, modo_di_gruppo, nomi_usati = [], {}, set()
    colori = ["#2563EB", "#12924A", "#D97706", "#9333EA", "#DB2777", "#0891B2"]
    for x in dd:
        if x.get("modo") not in ("principale", "proprie"):
            continue
        fonti = sorted(f["url"] for f in ff if x["id"] in f.get("dispositivi", []))
        lavoro = marketing if "lavoro-bianca.txt" in (x.get("bianche") or []) else []
        gemella = next((m for m in modi if sorted(m["fonti"]) == fonti and m["lavoro"] == lavoro), None)
        if gemella:
            modo_di_gruppo[x["id"]] = gemella["id"]
            continue
        nome = "Lavoro" if lavoro and "Lavoro" not in nomi_usati else ("Standard" if not lavoro and x.get("modo") == "principale" else "Regole di %s" % x.get("nome", x["id"]))
        nomi_usati.add(nome)
        m = {"id": "m-" + secrets.token_hex(3), "nome": nome, "colore": colori[len(modi) % len(colori)],
             "fonti": fonti, "lavoro": lavoro, "auto": None}
        modi.append(m)
        modo_di_gruppo[x["id"]] = m["id"]
    # «Standard»: tutte le liste del principale, senza strumenti di lavoro (per navigare e basta)
    if pr and not any(m["nome"] == "Standard" for m in modi):
        fp = sorted(f["url"] for f in ff if pr["id"] in f.get("dispositivi", []))
        if fp:
            modi.append({"id": "m-" + secrets.token_hex(3), "nome": "Standard", "colore": colori[len(modi) % len(colori)],
                         "fonti": fp, "lavoro": [], "auto": None})
    if not modi:
        modi.append({"id": "m-" + secrets.token_hex(3), "nome": "Standard", "colore": colori[1], "fonti": [f["url"] for f in ff], "lavoro": [], "auto": None})
    salva(os.path.join(nuova, "modalita.json"), modi)

    # ── dispositivi
    nuovi = []
    for x in dd:
        ips = [i for i in (x.get("ips") or ([x["ip"]] if x.get("ip") else [])) if i and not i.startswith(("127.", "::1"))]
        nid = mappa.get(x["id"], x["id"])
        y = {"id": nid, "nome": x.get("nome") or nid, "ip": ips[0] if ips else "", "ips": ips[1:],
             "proprie": x.get("modo") in ("principale", "proprie")}
        if x.get("modo") == "principale":
            y["principale"] = True
        if y["proprie"]:
            y["modo"] = modo_di_gruppo.get(x["id"], modi[0]["id"])
            y["base"] = x.get("vecchio") or vecchio_pr   # da quale gruppo della config di prima prendeva le liste locali
        if x.get("modo") == "off":   # «nessun filtro» per sempre (senza scadenza)
            y["proprie"] = True
            y["modo"] = "spento"
        nuovi.append(y)
        rapporto.append("dispositivo %-18s %s%s" % (y["nome"][:18], "principale · " if y.get("principale") else "",
                        "senza filtro" if y.get("modo") == "spento" else (next(m["nome"] for m in modi if m["id"] == y["modo"]) if y["proprie"] else "fa come il principale")))
    if not any(y.get("principale") for y in nuovi):
        nuovi.insert(0, {"id": PRINCIPALE_NUOVO, "nome": "Mac", "ip": "", "proprie": True, "principale": True, "modo": modi[0]["id"]})
    salva(os.path.join(nuova, "dispositivi.json"), nuovi)

    # ── liste (si riscaricano da sole; qui solo l'elenco)
    nf = []
    for f in ff:
        nf.append({k: f[k] for k in ("url", "nome", "attiva", "domini", "aggiornata") if k in f})
        nf[-1]["dispositivi"] = [mappa.get(g, g) for g in f.get("dispositivi", [])]
        if "attiva" not in nf[-1]:
            nf[-1]["attiva"] = not str(f.get("stato", "")).startswith("spenta")
    salva(os.path.join(nuova, "fonti.json"), nf)
    rapporto.append("liste di blocco: %d (si riscaricano alla partenza)" % len(nf))

    # ── blocchi e permessi a mano
    lv = os.path.join(vecchia, "liste")
    for nome in ("blocca.txt", "sblocca.txt", "bianca.txt", "anti-rilevamento.txt", "lavoro-bianca.txt"):
        if os.path.exists(os.path.join(lv, nome)):
            shutil.copy2(os.path.join(lv, nome), os.path.join(nuova, "liste", nome))
            n = sum(1 for r in open(os.path.join(lv, nome), encoding="utf-8", errors="replace") if r.strip() and not r.startswith("#"))
            rapporto.append("%-22s %d righe" % (nome, n))
    altre = sorted({b for x in dd for b in (x.get("bianche") or []) if b not in ("lavoro-bianca.txt",)})
    if altre:   # liste bianche personali in più: unite alla lista bianca
        righe = []
        for b in altre:
            p = os.path.join(lv, b)
            if os.path.exists(p):
                righe += [r.strip() for r in open(p, encoding="utf-8", errors="replace") if r.strip() and not r.startswith("#")]
        if righe:
            pb = os.path.join(nuova, "liste", "bianca.txt")
            gia = set(r.strip() for r in open(pb, encoding="utf-8")) if os.path.exists(pb) else set()
            with open(pb, "a", encoding="utf-8") as h:
                for r in righe:
                    if r not in gia:
                        h.write(r + "\n")
            rapporto.append("liste bianche in più unite alla lista bianca: %s" % ", ".join(altre))

    # ── regole e segnalazioni delle estensioni del browser
    for nome in ("regole-estensione.txt", "segnalazioni.jsonl"):
        p = os.path.join(vecchia, nome)
        if os.path.exists(p):
            shutil.copy2(p, os.path.join(nuova, nome))
            rapporto.append("estensioni: %s copiato" % nome)

    # ── DNS fuori casa: stessi codici
    dp = leggi(os.path.join(vecchia, "dns-personale.json"), {})
    nd = {}
    for n, v in dp.items():
        if not isinstance(v, dict) or not v.get("codice"):
            continue
        come = v.get("come", "")
        x = next((y for y in nuovi if come and (y.get("ip") == come or come in (y.get("ips") or []))), None)
        nd[n] = {"codice": v["codice"], "disp": (x or {}).get("id", PRINCIPALE_NUOVO), "nome": (x or {}).get("nome", n)}
        rapporto.append("fuori casa: %-14s → regole di %s (stesso codice)" % (n, nd[n]["nome"]))
    if nd:
        salva(os.path.join(nuova, "dns-personale.json"), nd)
        os.chmod(os.path.join(nuova, "dns-personale.json"), 0o600)

    # ── config di base di Blocky (upstream, nomi locali, Tailscale…)
    for cand in ("config.base.yml", "config.yml"):
        p = os.path.join(vecchia, "config", cand)
        if os.path.exists(p):
            shutil.copy2(p, os.path.join(nuova, "blocky-base.yml"))
            rapporto.append("config di base: %s" % cand)
            asc = ascolto_dns(open(p, encoding="utf-8").read())
            if asc:
                open(os.path.join(nuova, "dns-ascolto.txt"), "w").write(",".join(asc) + "\n")
                rapporto.append("il DNS ascolta su: %s" % ", ".join(asc))
            break
    open(os.path.join(nuova, ".preset-1.3"), "w").close()   # niente liste «di serie» aggiunte: ci sono le sue
    return rapporto


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    for r in importa(os.path.expanduser(sys.argv[1]), os.path.expanduser(sys.argv[2])):
        print("  " + r)
