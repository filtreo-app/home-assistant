# -*- coding: utf-8 -*-
"""apns.py — 0.9.4: notifiche push di Apple (APNs) da Casa, per chiudere e aggiornare l'Attività in tempo reale della pausa
sull'iPhone anche quando l'app è chiusa (pausa ripresa dal Mac, dal pannello o scaduta). Solo libreria standard:
  • firma ES256 (ECDSA P-256 + SHA-256) del token JWT, in Python puro (la chiave .p8 di Apple, PKCS#8);
  • una richiesta HTTP/2 minima verso api.push.apple.com (APNs accetta solo HTTP/2): prefazione, SETTINGS, HEADERS (HPACK
    letterale senza Huffman), DATA, lettura della risposta (:status e «reason»).
Chiave: DATA/segreti/apns.p8 + DATA/segreti/apns.json {"key_id", "team_id", "topic"} (mai nei log, mai stampata).
"""
import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import struct
import threading
import time

DATA = os.environ.get("FILTREO_DATA", "/data")
HOST = {"production": "api.push.apple.com", "sandbox": "api.sandbox.push.apple.com"}

# ───────────── P-256 ─────────────
_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_A = _P - 3
_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _somma(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % _P == 0:
            return None
        l = (3 * p[0] * p[0] + _A) * pow(2 * p[1], -1, _P) % _P
    else:
        l = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (l * l - p[0] - q[0]) % _P
    return x, (l * (p[0] - x) - p[1]) % _P


def _per(k, p):
    r = None
    while k:
        if k & 1:
            r = _somma(r, p)
        p = _somma(p, p)
        k >>= 1
    return r


def chiave_da_p8(testo):
    """il numero segreto d (32 byte) dalla chiave .p8 di Apple (PEM, PKCS#8 con ECPrivateKey dentro)."""
    righe = [r.strip() for r in testo.strip().splitlines() if r.strip() and not r.startswith("-----")]
    der = base64.b64decode("".join(righe))
    i = der.find(b"\x02\x01\x01\x04\x20")   # ECPrivateKey: version 1, OCTET STRING di 32 byte
    if i < 0:
        raise ValueError("chiave .p8 non riconosciuta")
    d = int.from_bytes(der[i + 5:i + 37], "big")
    if not 1 <= d < _N:
        raise ValueError("chiave .p8 non valida")
    return d


def firma_es256(d, messaggio):
    z = int.from_bytes(hashlib.sha256(messaggio).digest(), "big")
    while True:
        k = secrets.randbelow(_N - 1) + 1
        r = _per(k, _G)[0] % _N
        if not r:
            continue
        s = pow(k, -1, _N) * (z + r * d) % _N
        if s:
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verifica_es256(pub, messaggio, firma):
    """solo per le prove: pub = (x, y)."""
    r, s = int.from_bytes(firma[:32], "big"), int.from_bytes(firma[32:], "big")
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    z = int.from_bytes(hashlib.sha256(messaggio).digest(), "big")
    w = pow(s, -1, _N)
    pt = _somma(_per(z * w % _N, _G), _per(r * w % _N, pub))
    return pt is not None and pt[0] % _N == r


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ───────────── chiave e token ─────────────
_jwt = {"t": "", "quando": 0.0, "kid": ""}
_l = threading.Lock()


def impostazioni(data=None):
    """{"key_id", "team_id", "topic", "d"} oppure None se la chiave non c'è."""
    base = os.path.join(data or DATA, "segreti")
    try:
        cfg = json.load(open(os.path.join(base, "apns.json"), encoding="utf-8"))
        d = chiave_da_p8(open(os.path.join(base, "apns.p8"), encoding="utf-8").read())
        if not (cfg.get("key_id") and cfg.get("team_id")):
            return None
        return {"key_id": cfg["key_id"], "team_id": cfg["team_id"], "topic": cfg.get("topic") or "it.filtreo.ios", "d": d}
    except (OSError, ValueError, KeyError):
        return None


def token_jwt(imp, adesso=None):
    """JWT ES256 per APNs, rifatto ogni 40 minuti (Apple lo vuole tra 20 e 60)."""
    adesso = adesso or time.time()
    with _l:
        if _jwt["t"] and _jwt["kid"] == imp["key_id"] and adesso - _jwt["quando"] < 2400:
            return _jwt["t"]
        testa = _b64u(json.dumps({"alg": "ES256", "kid": imp["key_id"]}, separators=(",", ":")).encode())
        corpo = _b64u(json.dumps({"iss": imp["team_id"], "iat": int(adesso)}, separators=(",", ":")).encode())
        firma = firma_es256(imp["d"], (testa + "." + corpo).encode())
        _jwt.update(t=testa + "." + corpo + "." + _b64u(firma), quando=adesso, kid=imp["key_id"])
        return _jwt["t"]


# ───────────── HTTP/2 minimo ─────────────
def _intero(n, prefisso, bit=7):
    massimo = (1 << bit) - 1
    if n < massimo:
        return bytes([prefisso | n])
    out = [prefisso | massimo]
    n -= massimo
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def _letterale(nome, valore):
    """HPACK: letterale senza indicizzazione, nome nuovo, niente Huffman."""
    n, v = nome.encode(), valore.encode()
    return b"\x00" + _intero(len(n), 0) + n + _intero(len(v), 0) + v


def _frame(tipo, flag, flusso, dati=b""):
    return struct.pack(">I", len(dati))[1:] + bytes([tipo, flag]) + struct.pack(">I", flusso) + dati


_HUFF_CIFRE = {"00000": "0", "00001": "1", "00010": "2", "011001": "3", "011010": "4", "011011": "5",
               "011100": "6", "011101": "7", "011110": "8", "011111": "9"}
_STATICI = {8: 200, 9: 204, 10: 206, 11: 304, 12: 400, 13: 404, 14: 500}


def _stato_da_hpack(blocco):
    """:status della risposta (Apple lo mette per primo). None se non si capisce."""
    if not blocco:
        return None
    b0 = blocco[0]
    if b0 & 0x80:   # campo indicizzato
        return _STATICI.get(b0 & 0x7F)
    idx = b0 & 0x3F if b0 & 0x40 else b0 & 0x0F
    if idx != 8 or len(blocco) < 2:
        return None
    h, n = blocco[1] & 0x80, blocco[1] & 0x7F
    v = blocco[2:2 + n]
    if not h:
        try:
            return int(v.decode())
        except ValueError:
            return None
    bit, cifre, cur = "".join(format(x, "08b") for x in v), "", ""
    for c in bit:
        cur += c
        if cur in _HUFF_CIFRE:
            cifre += _HUFF_CIFRE[cur]
            cur = ""
            if len(cifre) == 3:
                break
    return int(cifre) if len(cifre) == 3 else None


def _leggi(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x:
            raise ConnectionError("connessione chiusa")
        b += x
    return b


def richiesta_h2(host, percorso, intestazioni, corpo, attesa=10):
    """POST HTTP/2 su un flusso solo. Ritorna (stato, corpo)."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    with socket.create_connection((host, 443), timeout=attesa) as grezzo:
        with ctx.wrap_socket(grezzo, server_hostname=host) as s:
            if s.selected_alpn_protocol() != "h2":
                raise ConnectionError("il server non parla HTTP/2")
            blocco = (_letterale(":method", "POST") + _letterale(":scheme", "https") + _letterale(":path", percorso)
                      + _letterale(":authority", host) + b"".join(_letterale(k, v) for k, v in intestazioni))
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + _frame(4, 0, 0) + _frame(1, 4, 1, blocco) + _frame(0, 1, 1, corpo))
            stato, risposta, fine = None, b"", time.time() + attesa
            while time.time() < fine:
                testa = _leggi(s, 9)
                lun = int.from_bytes(testa[:3], "big")
                tipo, flag, flusso = testa[3], testa[4], int.from_bytes(testa[5:9], "big") & 0x7FFFFFFF
                dati = _leggi(s, lun) if lun else b""
                if tipo == 4 and not flag & 1:
                    s.sendall(_frame(4, 1, 0))                     # SETTINGS → ACK
                elif tipo == 6 and not flag & 1:
                    s.sendall(_frame(6, 1, 0, dati))               # PING → risposta
                elif tipo == 7:
                    raise ConnectionError("il server ha chiuso (GOAWAY)")
                elif tipo == 3 and flusso == 1:
                    raise ConnectionError("richiesta annullata dal server")
                elif tipo == 1 and flusso == 1:
                    i = 0
                    if flag & 8:
                        pad, i = dati[0], 1
                        dati = dati[:len(dati) - pad]
                    if flag & 0x20:
                        i += 5
                    stato = _stato_da_hpack(dati[i:])
                    if flag & 1:
                        return stato, risposta
                elif tipo == 0 and flusso == 1:
                    i = 0
                    if flag & 8:
                        dati = dati[1:len(dati) - dati[0]]
                    risposta += dati
                    if flag & 1:
                        return stato, risposta
            raise TimeoutError("nessuna risposta")


def invia(token, payload, ambiente="production", tipo="liveactivity", imp=None, priorita="10"):
    """manda una notifica. Ritorna (ok, motivo). Mai un errore verso chi chiama."""
    imp = imp or impostazioni()
    if not imp:
        return False, "chiave APNs mancante"
    if not token or any(c not in "0123456789abcdefABCDEF" for c in token):
        return False, "token non valido"
    argomento = imp["topic"] + (".push-type.liveactivity" if tipo == "liveactivity" else "")
    try:
        stato, corpo = richiesta_h2(HOST.get(ambiente, HOST["production"]), "/3/device/" + token.lower(),
                                    [("authorization", "bearer " + token_jwt(imp)), ("apns-topic", argomento),
                                     ("apns-push-type", tipo), ("apns-priority", priorita), ("content-type", "application/json")],
                                    json.dumps(payload, separators=(",", ":")).encode())
    except (OSError, ConnectionError, TimeoutError, ValueError) as e:
        return False, "rete: %s" % type(e).__name__
    if stato == 200:
        return True, ""
    try:
        motivo = json.loads(corpo.decode() or "{}").get("reason") or ""
    except ValueError:
        motivo = ""
    return False, "%s %s" % (stato, motivo)


# ───────────── l'Attività della pausa ─────────────
RIF_2001 = 978307200   # le date di ActivityKit nel JSON: secondi dal 1/1/2001


def stato_attivita(inizio, fine, ambito, da=""):
    return {"inizio": inizio - RIF_2001, "fine": fine - RIF_2001, "ambito": ambito, "da": da}


def carico_fine(inizio, fine, ambito, adesso=None):
    adesso = int(adesso or time.time())
    return {"aps": {"timestamp": adesso, "event": "end", "dismissal-date": adesso,
                    "content-state": stato_attivita(inizio, min(fine, adesso), ambito)}}


def carico_aggiorna(inizio, fine, ambito, da="", adesso=None):
    adesso = int(adesso or time.time())
    return {"aps": {"timestamp": adesso, "event": "update", "stale-date": int(fine),
                    "content-state": stato_attivita(inizio, fine, ambito, da)}}
