# -*- coding: utf-8 -*-
"""firma_ed25519.py — firma e verifica ed25519 (RFC 8032) in Python puro, solo libreria standard.

Serve a Casa (add-on di Home Assistant e Docker del Jetson), dove pynacl non c'è: verifica il manifest firmato del canale
di rilascio con la STESSA chiave pubblica e lo STESSO schema delle Regole (firma = base64 dei 64 byte, sui byte esatti
del file). La firma (sign) c'è solo per le prove e come riserva sul Mac se manca pynacl: sul Mac si usa pynacl.

Non è a tempo costante: va bene per VERIFICARE dati pubblici (il manifest); per firmare si preferisce pynacl.
"""
import base64
import hashlib

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _recupera_x(y, segno):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if segno else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != segno:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recupera_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)
_ZERO = (0, 1, 1, 0)


def _somma(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    Dd = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _per(s, punto):
    q = _ZERO
    while s > 0:
        if s & 1:
            q = _somma(q, punto)
        punto = _somma(punto, punto)
        s >>= 1
    return q


def _uguali(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _comprimi(p):
    zi = _inv(p[2])
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decomprimi(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    segno = y >> 255
    y &= (1 << 255) - 1
    x = _recupera_x(y, segno)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _h(*parti):
    return int.from_bytes(hashlib.sha512(b"".join(parti)).digest(), "little")


def _segreto(seme):
    h = hashlib.sha512(seme).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def pubblica(seme):
    """chiave pubblica (32 byte) dal seme privato (32 byte)."""
    a, _ = _segreto(seme)
    return _comprimi(_per(a, _G))


def firma(seme, dati):
    """firma (64 byte) dei byte esatti di «dati» con il seme privato di 32 byte."""
    if len(seme) != 32:
        raise ValueError("seme di 32 byte")
    a, prefisso = _segreto(seme)
    A = _comprimi(_per(a, _G))
    r = _h(prefisso, dati) % _L
    R = _comprimi(_per(r, _G))
    k = _h(R, A, dati) % _L
    s = (r + k * a) % _L
    return R + int.to_bytes(s, 32, "little")


def verifica(pub, dati, sig):
    """True se «sig» (64 byte) è la firma ed25519 di «dati» con la chiave pubblica «pub» (32 byte). Mai un errore."""
    try:
        if len(pub) != 32 or len(sig) != 64:
            return False
        A = _decomprimi(pub)
        R = _decomprimi(sig[:32])
        if A is None or R is None:
            return False
        s = int.from_bytes(sig[32:], "little")
        if s >= _L:
            return False
        k = _h(sig[:32], pub, dati) % _L
        return _uguali(_per(s, _G), _somma(R, _per(k, A)))
    except Exception:
        return False


def verifica_b64(pub_b64, dati, sig_b64):
    """come verifica(), con chiave e firma in base64 (il formato di regole-firma.pub e di manifest.json.sig)."""
    try:
        return verifica(base64.b64decode(pub_b64.strip(), validate=True), dati, base64.b64decode(sig_b64.strip(), validate=True))
    except Exception:
        return False
