#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dns_personale.py — DNS cifrato personale (fuori casa) con modalità istantanee.

Ogni dispositivo protetto «fuori casa» ha un indirizzo segreto: https://<nodo>/f/<codice>.
Questo modulo fa da porta d'ingresso (DoH): riceve la domanda e la passa a Blocky col nome
del dispositivo, così valgono le sue regole e la sua MODALITÀ (che si cambia senza riavvii).

Uguale su Pi (Home Assistant) e Jetson. L'indirizzo pubblico del nodo si imposta con
FILTREO_DOH_URL (es. https://jetson-orin.tail532390.ts.net); vuoto = funzione spenta.
"""
import hmac
import json
import os
import plistlib
import re
import secrets
import threading
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler

import filtro

FILE = os.path.join(filtro.DATA, "dns-personale.json")
URL_PUBBLICO = os.environ.get("FILTREO_DOH_URL", "").strip().rstrip("/")
PARACADUTE = os.environ.get("FILTREO_PARACADUTE_URL", "").strip().rstrip("/")   # Cloudflare: gira a casa, se casa è giù filtra da sé
if not PARACADUTE:
    # 0.10 — senza un Cloud proprio: Filtreo Cloud (lo stesso del ponte). I codici ci arrivano dal ponte (ponte.py): i dispositivi
    # sono filtrati su qualsiasi rete, senza Tailscale e senza indirizzo pubblico di Casa.
    try:
        import ponte as _ponte
        PARACADUTE = _ponte.cloud()
    except Exception:
        PARACADUTE = ""


def attivo():
    """c'è un indirizzo per i dispositivi fuori casa: Filtreo Cloud (di solito) o l'indirizzo pubblico di Casa."""
    return bool(PARACADUTE or URL_PUBBLICO)
BLOCKY_DOH = filtro.API + "/dns-query/"
SPENTO = "spento"
NOME_OK = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")
_blocco = threading.Lock()
_cache = {"t": 0.0, "d": {}}


def _leggi():
    try:
        d = json.load(open(FILE, encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _salva(d):
    tmp = FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        json.dump(d, h, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, FILE)
    _cache["t"] = 0.0


def _attuale():
    """lettura con cache di 2 s: il proxy risponde a migliaia di domande senza rileggere il file."""
    import time
    if time.time() - _cache["t"] > 2:
        _cache["d"] = _leggi()
        _cache["t"] = time.time()
    return _cache["d"]


def voci():
    out = []
    for n, v in _leggi().items():
        if isinstance(v, dict) and NOME_OK.match(n) and v.get("codice"):
            out.append((n, v))
    return out


# ───────── per la configurazione di Blocky ─────────
def righe_config(gruppo_di):
    """righe YAML di clientGroupsBlock: ogni dispositivo col DNS personale usa le regole (e quindi
    la MODALITÀ) del dispositivo a cui è legato. gruppo_di(id_dispositivo) -> gruppo."""
    righe = []
    for n, v in voci():
        righe.append('    "%s":\n      - %s\n      - manuale' % (n, gruppo_di(v.get("disp", ""))))
    return righe


# ───────── gestione dal pannello ─────────
def _slug(t):
    s = re.sub(r"[^a-z0-9]+", "-", (t or "").lower()).strip("-")[:38]
    return s if len(s) >= 3 else "disp-" + secrets.token_hex(3)


def crea(disp, nome):
    if not attivo():
        return False, "Protezione fuori casa non attiva: Filtreo Cloud non configurato."
    with _blocco:
        d = _leggi()
        n = base = _slug(nome)
        i = 2
        while n in d:
            n = "%s-%d" % (base, i)
            i += 1
        d[n] = {"codice": secrets.token_urlsafe(18).replace("-", "a").replace("_", "b"),
                "disp": disp, "nome": (nome or n)[:40]}
        _salva(d)
    return True, n


def togli(n):
    with _blocco:
        d = _leggi()
        if n not in d:
            return False, "Dispositivo sconosciuto."
        del d[n]
        _salva(d)
    return True, "Rimosso. La configurazione non è più valida e va rimossa anche dal dispositivo."


def indirizzo(codice):
    """l'indirizzo DNS cifrato che va nel profilo: il paracadute se c'è, altrimenti casa."""
    return "%s/d/%s" % (PARACADUTE, codice) if PARACADUTE else "%s/f/%s" % (URL_PUBBLICO, codice)


def profilo(n):
    """il file .mobileconfig da installare su iPhone/Mac (contiene l'indirizzo segreto)."""
    v = dict(voci()).get(n)
    if not v or not attivo():
        return None
    nome = v.get("nome") or n
    p = {
        "PayloadType": "Configuration", "PayloadVersion": 1,
        "PayloadIdentifier": "it.filtreo.dns." + n, "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": "Filtreo — " + nome,
        "PayloadDescription": "Protezione Filtreo in tutte le app, su qualsiasi rete. Si rimuove da Impostazioni.",
        "PayloadOrganization": "Filtreo", "PayloadRemovalDisallowed": False,
        "PayloadScope": "System",   # macOS 26+: il DNS deve valere per tutto il Mac (iOS lo ignora)
        "PayloadContent": [{
            "PayloadType": "com.apple.dnsSettings.managed", "PayloadVersion": 1,
            "PayloadIdentifier": "it.filtreo.dns." + n + ".doh", "PayloadUUID": str(uuid.uuid4()).upper(),
            "PayloadDisplayName": "Filtro di rete Filtreo",
            "DNSSettings": {"DNSProtocol": "HTTPS", "ServerURL": indirizzo(v["codice"])},
        }],
    }
    return plistlib.dumps(p)


def destinazione(codice):
    """dal codice segreto al nome con cui chiedere a Blocky (secondo la modalità). None = sconosciuto."""
    for n, v in _attuale().items():
        if isinstance(v, dict) and v.get("codice") and hmac.compare_digest(str(v["codice"]), codice):
            return n
    return None


# ───────── la porta d'ingresso DoH ─────────
class Porta(BaseHTTPRequestHandler):
    """https://<nodo>/f/<codice> arriva qui (via Tailscale Funnel o simili) e va a Blocky."""
    protocol_version = "HTTP/1.1"

    def _inoltra(self, corpo):
        parti = self.path.split("?", 1)
        m = re.fullmatch(r"/f/([A-Za-z0-9]{16,64})/?", parti[0])
        dest = destinazione(m.group(1)) if m else None
        if not dest:
            return self._fine(404, b"", "text/plain")
        url = BLOCKY_DOH + dest + ("?" + parti[1] if len(parti) > 1 else "")
        req = urllib.request.Request(url, data=corpo, method="POST" if corpo is not None else "GET",
                                     headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                return self._fine(r.status, r.read(), r.headers.get("Content-Type", "application/dns-message"))
        except urllib.error.HTTPError as e:
            return self._fine(e.code, b"", "text/plain")
        except Exception:
            return self._fine(502, b"", "text/plain")

    def _fine(self, code, b, tipo):
        self.send_response(code)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._inoltra(None)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 4096:
            return self._fine(400, b"", "text/plain")
        self._inoltra(self.rfile.read(n))

    def log_message(self, *a):
        pass
