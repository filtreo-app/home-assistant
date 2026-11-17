# -*- coding: utf-8 -*-
"""ponte.py — 0.10: Casa raggiungibile dalle app su qualsiasi rete, SENZA Tailscale, porte aperte o domini.

Casa apre lei (in uscita, come un browser) una connessione WebSocket verso Filtreo Cloud:  wss://<cloud>/ponte/<id>
Le app chiamano  https://<cloud>/casa/<id>/pannello/…  con la loro chiave (codice di 6 cifre); il Cloud passa la richiesta qui,
Casa la gira al suo pannello (127.0.0.1) con l'intestazione X-Filtreo-Via-Ponte, e il pannello la tratta come una richiesta
da Internet: vale SOLO la chiave dell'app (niente fiducia per indirizzo, niente abbinamento). Solo libreria standard.

DATA/segreti/ponte.json  {"id": 32 cifre esadecimali, "segreto": 64 cifre esadecimali}  (creato al primo avvio, permessi 600)
FILTREO_PONTE_URL        il Cloud (di serie Filtreo Cloud); vuoto o «0» = ponte spento
"""
import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from urllib.parse import urlparse

DATA = os.environ.get("FILTREO_DATA", "/data")
CLOUD_DI_SERIE = "https://filtreo-paracadute.fullhd-david.workers.dev"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_RISPOSTA = 700 * 1024


def _file():
    return os.path.join(DATA, "segreti", "ponte.json")


def identita():
    """{"id", "segreto"}: creati una volta sola."""
    p = _file()
    try:
        d = json.load(open(p, encoding="utf-8"))
        if len(str(d.get("id", ""))) == 32 and len(str(d.get("segreto", ""))) == 64:
            return d
    except (OSError, ValueError):
        pass
    d = {"id": os.urandom(16).hex(), "segreto": os.urandom(32).hex()}
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        os.chmod(os.path.dirname(p), 0o700)
    except OSError:
        pass
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as h:
        json.dump(d, h)
    os.replace(p + ".tmp", p)
    return d


def cloud():
    v = os.environ.get("FILTREO_PONTE_URL", "").strip().rstrip("/")
    if v in ("0", "no", "spento"):
        return ""
    return v or os.environ.get("FILTREO_PARACADUTE_URL", "").strip().rstrip("/") or CLOUD_DI_SERIE


def indirizzo_app():
    """quello che le app usano da fuori casa: https://<cloud>/casa/<id>"""
    c = cloud()
    return ("%s/casa/%s" % (c, identita()["id"])) if c else ""


# ───────────── WebSocket minimo (client, RFC 6455) ─────────────
class _WS:
    def __init__(self, sock):
        self.s = sock
        self.l = threading.Lock()

    def manda(self, testo, opcode=1):
        dati = testo.encode() if isinstance(testo, str) else testo
        maschera = os.urandom(4)
        n = len(dati)
        testa = bytes([0x80 | opcode])
        if n < 126:
            testa += bytes([0x80 | n])
        elif n < 65536:
            testa += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            testa += bytes([0x80 | 127]) + struct.pack(">Q", n)
        corpo = bytes(b ^ maschera[i % 4] for i, b in enumerate(dati))
        with self.l:
            self.s.sendall(testa + maschera + corpo)

    def _leggi(self, n):
        b = b""
        while len(b) < n:
            x = self.s.recv(n - len(b))
            if not x:
                raise ConnectionError("chiusa")
            b += x
        return b

    def ricevi(self):
        """(opcode, dati) di un messaggio intero (frammenti riuniti)."""
        pezzi, op0 = b"", None
        while True:
            a, b = self._leggi(2)
            fin, op = a & 0x80, a & 0x0F
            n = b & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._leggi(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._leggi(8))[0]
            if n > 2 * 1024 * 1024:
                raise ConnectionError("messaggio troppo grande")
            mask = self._leggi(4) if b & 0x80 else None
            dati = self._leggi(n) if n else b""
            if mask:
                dati = bytes(x ^ mask[i % 4] for i, x in enumerate(dati))
            if op >= 8:   # controllo: arriva anche in mezzo ai frammenti
                return op, dati
            if op0 is None:
                op0 = op
            pezzi += dati
            if fin:
                return op0, pezzi


def apri(base, id_, segreto, attesa=15):
    u = urlparse(base)
    host, porta = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    grezzo = socket.create_connection((host, porta), timeout=attesa)
    s = ssl.create_default_context().wrap_socket(grezzo, server_hostname=host) if u.scheme == "https" else grezzo
    chiave = base64.b64encode(os.urandom(16)).decode()
    percorso = (u.path.rstrip("/") or "") + "/ponte/" + id_
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\nX-Filtreo-Ponte: %s\r\nUser-Agent: Filtreo-Casa\r\n\r\n"
               % (percorso, host if porta in (80, 443) else "%s:%d" % (host, porta), chiave, segreto)).encode())
    testa = b""
    while b"\r\n\r\n" not in testa:
        x = s.recv(4096)
        if not x:
            raise ConnectionError("il Cloud ha chiuso")
        testa += x
        if len(testa) > 16384:
            raise ConnectionError("risposta non valida")
    righe = testa.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
    if " 101 " not in righe[0] + " ":
        raise PermissionError(righe[0][:80])
    atteso = base64.b64encode(hashlib.sha1(chiave.encode() + GUID).digest()).decode()
    if not any(r.lower().startswith("sec-websocket-accept:") and r.split(":", 1)[1].strip() == atteso for r in righe):
        raise ConnectionError("stretta di mano non valida")
    s.settimeout(75)
    return _WS(s)


_sync = {"m": None}


def impronte_app():
    """0.10.1 — le impronte (sha256) delle chiavi delle app collegate, come le tiene abbinamento.py. Mai le chiavi."""
    try:
        import abbinamento
        return [x.get("hash") for x in abbinamento._leggi()["chiavi"] if x.get("hash")]
    except Exception:
        return []


def calcola_codici():
    """{impronta: profilo} con la stessa funzione di paracadute-sync.py (calcola). None se non si può calcolare."""
    if _sync["m"] is None:
        import importlib.util
        qui = os.path.dirname(os.path.abspath(__file__))
        for p in (os.environ.get("FILTREO_PARACADUTE_SYNC", ""), os.path.join(qui, "..", "jetson", "paracadute-sync.py"),
                  os.path.join(qui, "paracadute-sync.py"), "/share/filtreo/jetson/paracadute-sync.py", "/opt/filtreo/jetson/paracadute-sync.py"):
            if p and os.path.isfile(p):
                spec = importlib.util.spec_from_file_location("filtreo_paracadute_sync", p)
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                _sync["m"] = m
                break
    if _sync["m"] is None:
        return None
    cod, _nomi = _sync["m"].calcola(DATA)
    return cod


# ───────────── il ponte ─────────────
class Ponte:
    def __init__(self, porta_pannello):
        self.porta = porta_pannello
        self.collegata = False
        self.ultimo_errore = ""
        self.richieste = 0
        self._stop = threading.Event()

    def stato(self):
        return {"attivo": bool(cloud()), "collegata": self.collegata, "indirizzo": indirizzo_app() if cloud() else "",
                "richieste": self.richieste, "errore": self.ultimo_errore}

    def avvia(self):
        if not cloud():
            return False
        threading.Thread(target=self._giro, daemon=True).start()
        return True

    def ferma(self):
        self._stop.set()

    def _giro(self):
        attesa = 5
        while not self._stop.is_set():
            ident = identita()
            try:
                ws = apri(cloud(), ident["id"], ident["segreto"])
                self.collegata, self.ultimo_errore, attesa = True, "", 5
                sys.stderr.write("Filtreo: Casa collegata a Filtreo Cloud (ponte)\n")
                battito = threading.Thread(target=self._battito, args=(ws,), daemon=True)
                battito.start()
                threading.Thread(target=self._codici, args=(ws,), daemon=True).start()
                while not self._stop.is_set():
                    op, dati = ws.ricevi()
                    if op == 8:
                        raise ConnectionError("chiusa dal Cloud")
                    if op == 9:
                        ws.manda(dati, 10)
                        continue
                    if op != 1:
                        continue
                    try:
                        m = json.loads(dati.decode())
                    except ValueError:
                        continue
                    if m.get("tipo") == "richiesta":
                        threading.Thread(target=self._servi, args=(ws, m), daemon=True).start()
            except PermissionError as e:
                self.ultimo_errore = "accesso negato (%s)" % e
                attesa = 600   # segreto rifiutato: inutile insistere ogni 5 secondi
            except Exception as e:
                self.ultimo_errore = type(e).__name__
            if self.collegata:
                sys.stderr.write("Filtreo: ponte interrotto (%s): mi ricollego\n" % (self.ultimo_errore or "fine"))
                attesa = 1   # 0.10.2: era collegata e si è chiusa: si riprova subito (le app non devono vedere «Casa non disponibile»)
            self.collegata = False
            self._stop.wait(attesa)
            attesa = min(120, attesa * 2)

    def _codici(self, ws):
        """0.10 — i codici DNS dei dispositivi (impronta → profilo, gli stessi di paracadute-sync.py) a Filtreo Cloud: così i
        dispositivi di questa Casa sono filtrati su qualsiasi rete, anche senza Tailscale e senza un Cloud proprio.
        Solo quando cambiano (controllo ogni 20 s) e comunque ogni 30 minuti. Nessun nome esce: solo impronte e profili."""
        ultimo, quando = None, 0.0
        while self.collegata and not self._stop.is_set():
            try:
                voci = calcola_codici()
                app = impronte_app()
                firma = hashlib.sha256(json.dumps([voci, app], sort_keys=True).encode()).hexdigest()
                if voci is not None and (firma != ultimo or time.time() - quando > 1800):
                    ws.manda(json.dumps({"tipo": "codici", "voci": voci}))
                    ws.manda(json.dumps({"tipo": "app", "voci": app}))   # 0.10.1: le app collegate ritrovano Casa da sole
                    ultimo, quando = firma, time.time()
            except OSError:
                return
            except Exception as e:
                self.ultimo_errore = "codici: %s" % type(e).__name__
            self._stop.wait(20)

    def _battito(self, ws):
        while self.collegata and not self._stop.is_set():
            time.sleep(30)
            try:
                ws.manda('{"tipo":"ping"}')
            except OSError:
                return

    def _servi(self, ws, m):
        self.richieste += 1
        codice, contenuto, corpo = 502, "application/json; charset=utf-8", b'{"ok":false,"testo":"Casa non risponde."}'
        try:
            percorso = str(m.get("percorso") or "/")
            if not percorso.startswith("/") or "\r" in percorso or "\n" in percorso:
                raise ValueError("percorso")
            dati = base64.b64decode(m.get("corpo") or "")
            intest = {k: v for k, v in (m.get("intestazioni") or {}).items()
                      if k.lower() in ("authorization", "x-filtro", "content-type", "accept") and "\n" not in str(v)}
            intest["X-Filtreo-Via-Ponte"] = "1"
            c = http.client.HTTPConnection("127.0.0.1", self.porta, timeout=18)
            c.request(str(m.get("metodo") or "GET").upper()[:8], percorso, body=dati or None, headers=intest)
            r = c.getresponse()
            corpo = r.read(MAX_RISPOSTA + 1)
            codice, contenuto = r.status, r.getheader("Content-Type") or contenuto
            c.close()
            if len(corpo) > MAX_RISPOSTA:
                codice, corpo = 413, b'{"ok":false,"testo":"Risposta troppo grande per il ponte."}'
        except Exception:
            pass
        try:
            ws.manda(json.dumps({"tipo": "risposta", "id": m.get("id"), "codice": codice, "contenuto": contenuto,
                                 "corpo": base64.b64encode(corpo).decode()}))
        except OSError:
            pass
