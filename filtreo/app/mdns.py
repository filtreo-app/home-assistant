# -*- coding: utf-8 -*-
"""mdns.py — Casa si fa trovare: annuncio Bonjour/mDNS «_filtreo._tcp» del pannello. Solo libreria standard.

Le app (iPhone, Mac) cercano «_filtreo._tcp» con NWBrowser e trovano Casa senza indirizzi da scrivere.
  servizio:  <Filtreo nome>._filtreo._tcp.local  →  SRV <host>.local:<porta del pannello>
  TXT:       v=<versione> · nome=<nome di Casa> · id=<id fisso di Casa> · porta=<porta> · abbina=1 · percorso=/pannello
  host:      filtreo-<nome macchina>.local → A <indirizzo di casa>

Come annuncia
  1. se c'è avahi-publish e il bus di sistema di avahi (raro dentro un contenitore): lo usa;
  2. altrimenti un piccolo risponditore in Python: si unisce al gruppo 224.0.0.251:5353 (SO_REUSEADDR/SO_REUSEPORT,
     convive con avahi e con lo zeroconf di Home Assistant), annuncia all'avvio (3 volte) e ogni 5 minuti, e risponde
     SOLO alle domande per _filtreo._tcp, per il proprio nome di servizio e per il proprio nome host.
  Serve la rete dell'host: l'add-on di HA ha host_network: true; sul Jetson il contenitore gira con --network host.

Impostazioni (variabili d'ambiente)
  FILTREO_MDNS=0        spento · =python solo il risponditore Python · =avahi solo avahi-publish
  FILTREO_MDNS_IP       indirizzo da annunciare (di serie: quello con cui la macchina esce verso la rete di casa)
  FILTREO_MDNS_NOME     nome mostrato (di serie: «Casa»)
"""
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

GRUPPO = "224.0.0.251"
PORTA_MDNS = 5353
SERVIZIO = "_filtreo._tcp.local"
ELENCO = "_services._dns-sd._udp.local"
T_A, T_PTR, T_TXT, T_SRV, T_ANY = 1, 12, 16, 33, 255
TTL = 120


def _nome_dns(nome):
    out = b""
    for parte in nome.rstrip(".").split("."):
        b = parte.encode("utf-8")[:63]
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _leggi_nome(dati, i, profondita=0):
    """(nome in minuscolo, posizione dopo il nome) con i puntatori di compressione."""
    parti = []
    fine = None
    salti = 0
    while True:
        if i >= len(dati):
            raise ValueError("nome troncato")
        n = dati[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            if i + 1 >= len(dati) or salti > 20:
                raise ValueError("puntatore non valido")
            if fine is None:
                fine = i + 2
            i = ((n & 0x3F) << 8) | dati[i + 1]
            salti += 1
            continue
        i += 1
        parti.append(dati[i:i + n].decode("utf-8", "replace"))
        i += n
    return ".".join(parti).lower(), (fine if fine is not None else i)


def domande(dati):
    """[(nome, tipo, unicast)] di un pacchetto mDNS di domanda; [] se è una risposta o non si legge."""
    try:
        if len(dati) < 12:
            return []
        _id, flag, qd = struct.unpack(">HHH", dati[:6])
        if flag & 0x8000:
            return []
        out, i = [], 12
        for _ in range(min(qd, 30)):
            nome, i = _leggi_nome(dati, i)
            tipo, classe = struct.unpack(">HH", dati[i:i + 4])
            i += 4
            out.append((nome, tipo, bool(classe & 0x8000)))
        return out
    except (ValueError, struct.error):
        return []


def _rr(nome, tipo, dati, ttl=TTL, flush=True):
    classe = 0x8001 if flush else 0x0001
    return _nome_dns(nome) + struct.pack(">HHIH", tipo, classe, ttl, len(dati)) + dati


def _txt(voci):
    out = b""
    for k, v in voci.items():
        b = ("%s=%s" % (k, v)).encode("utf-8")[:255]
        out += bytes([len(b)]) + b
    return out or b"\x00"


def ip_locale():
    ip = os.environ.get("FILTREO_MDNS_IP", "").strip()
    if ip:
        return ip
    for dest in (("192.168.255.255", 9), (GRUPPO, PORTA_MDNS), ("10.255.255.255", 9)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(dest)
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127.") and not ip.startswith("100."):
                return ip
        except OSError:
            pass
    return ""


def _etichetta(t, n=40):
    t = re.sub(r"[^A-Za-z0-9-]+", "-", t or "").strip("-").lower()
    return (t or "casa")[:n]


class Annuncio:
    def __init__(self, porta, versione="", nome="", id_casa="", extra=None):
        self.porta = int(porta)
        self.extra = {str(k): v for k, v in (extra or {}).items() if v not in (None, "")}   # 0.10.3: «ha» (porta) e «nodo»
        self.nome = (nome or os.environ.get("FILTREO_MDNS_NOME", "") or "Casa").strip()[:40]
        self.versione = (versione or "").lstrip("v")
        self.id_casa = id_casa
        # 0.10.6: nome d'istanza unico per ogni Casa (due Case nella stessa rete non si coprono a vicenda); il nome da
        # mostrare resta nel TXT «nome»
        coda = re.sub(r"[^0-9A-Za-z]", "", str(id_casa or ""))[:4]
        self.istanza = (("Filtreo %s %s" % (self.nome, coda)).strip())[:60] + "." + SERVIZIO
        self.host = "filtreo-%s.local" % _etichetta(socket.gethostname())
        self.ip = ""
        self.modo = ""
        self._sock = None
        self._proc = None
        self._stop = threading.Event()
        self.inviati = 0
        self.risposte = 0

    # ── contenuto ──
    def voci_txt(self):
        return dict({"v": self.versione, "nome": self.nome, "id": self.id_casa, "porta": self.porta, "abbina": 1, "percorso": "/pannello"},
                    **self.extra)

    def risposta(self, ttl=TTL, solo=None, ident=0, eco=b""):
        """pacchetto di risposta: PTR + SRV + TXT + A (o solo quelli in «solo»)."""
        ris = []
        if solo is None or T_PTR in solo:
            ris.append(_rr(SERVIZIO, T_PTR, _nome_dns(self.istanza), ttl, flush=False))
        if solo is None or T_SRV in solo:
            ris.append(_rr(self.istanza, T_SRV, struct.pack(">HHH", 0, 0, self.porta) + _nome_dns(self.host), ttl))
        if solo is None or T_TXT in solo:
            ris.append(_rr(self.istanza, T_TXT, _txt(self.voci_txt()), ttl))
        if (solo is None or T_A in solo) and self.ip:
            try:
                ris.append(_rr(self.host, T_A, socket.inet_aton(self.ip), ttl))
            except OSError:
                pass
        qd = 1 if eco else 0
        return struct.pack(">HHHHHH", ident, 0x8400, qd, len(ris), 0, 0) + eco + b"".join(ris)

    def cosa_rispondere(self, dd):
        """dato l'elenco delle domande, i tipi di record da mandare (insieme vuoto = non riguarda Casa)."""
        voglio = set()
        ist, host = self.istanza.lower(), self.host.lower()
        for nome, tipo, _u in dd:
            if nome == SERVIZIO.lower() and tipo in (T_PTR, T_ANY):
                voglio |= {T_PTR, T_SRV, T_TXT, T_A}
            elif nome == ELENCO and tipo in (T_PTR, T_ANY):
                voglio |= {"elenco"}
            elif nome == ist and tipo in (T_SRV, T_TXT, T_ANY):
                voglio |= {T_SRV, T_TXT, T_A} if tipo == T_ANY else {tipo, T_A} if tipo == T_SRV else {T_TXT}
            elif nome == host and tipo in (T_A, T_ANY):
                voglio |= {T_A}
        return voglio

    # ── rete ──
    def _apri(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s.bind(("", PORTA_MDNS))
        iface = socket.inet_aton(self.ip) if self.ip else socket.inet_aton("0.0.0.0")
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GRUPPO) + iface)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        if self.ip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, iface)
            except OSError:
                pass
        s.settimeout(1.0)
        return s

    def _manda(self, pacchetto, dove=None):
        try:
            self._sock.sendto(pacchetto, dove or (GRUPPO, PORTA_MDNS))
            self.inviati += 1
        except OSError:
            pass

    def _elenco(self):
        return struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + _rr(ELENCO, T_PTR, _nome_dns(SERVIZIO), TTL, flush=False)

    def _giro(self):
        prossimo = [time.time(), time.time() + 1, time.time() + 3]
        while not self._stop.is_set():
            ora = time.time()
            if prossimo and ora >= prossimo[0]:
                prossimo.pop(0)
                nip = ip_locale()
                if nip and nip != self.ip:
                    self.ip = nip
                self._manda(self.risposta())
                if not prossimo:
                    prossimo.append(ora + 300)
            try:
                dati, da = self._sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                time.sleep(1)
                continue
            dd = domande(dati)
            if not dd:
                continue
            voglio = self.cosa_rispondere(dd)
            if not voglio:
                continue
            self.risposte += 1
            if "elenco" in voglio:
                self._manda(self._elenco())
                voglio.discard("elenco")
                if not voglio:
                    continue
            if da[1] != PORTA_MDNS:   # domanda «semplice» (non da un risponditore mDNS): risposta diretta, con la domanda
                ident = struct.unpack(">H", dati[:2])[0]
                _n, fine = _leggi_nome(dati, 12)
                self._manda(self.risposta(solo=voglio, ident=ident, eco=dati[12:fine + 4]), da)
            elif any(u for _n, _t, u in dd):
                self._manda(self.risposta(solo=voglio), da)
                self._manda(self.risposta(solo=voglio))
            else:
                self._manda(self.risposta(solo=voglio))

    def _avahi(self):
        bus = any(os.path.exists(p) for p in ("/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket"))
        if not (shutil.which("avahi-publish") and bus):
            return False
        txt = ["%s=%s" % (k, v) for k, v in self.voci_txt().items()]
        try:
            self._proc = subprocess.Popen(["avahi-publish", "-s", self.istanza.split("." + SERVIZIO)[0], "_filtreo._tcp", str(self.porta)] + txt,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)
            return self._proc.poll() is None
        except OSError:
            return False

    def avvia(self):
        """parte in sottofondo. Ritorna il modo usato («avahi», «python») o «» se l'annuncio non è possibile. Mai un errore."""
        scelta = os.environ.get("FILTREO_MDNS", "").strip().lower()
        if scelta in ("0", "no", "spento"):
            return ""
        self.ip = ip_locale()
        if scelta in ("", "avahi") and self._avahi():
            self.modo = "avahi"
        elif scelta in ("", "python"):
            try:
                self._sock = self._apri()
            except OSError as e:
                sys.stderr.write("Filtreo: annuncio in rete non disponibile (%s)\n" % e)
                return ""
            threading.Thread(target=self._giro, daemon=True).start()
            self.modo = "python"
        if self.modo:
            sys.stderr.write("Filtreo: Casa si annuncia in rete come «%s» (%s, porta %d, %s)\n" % (self.istanza.split("._")[0], self.modo, self.porta, self.ip or "indirizzo automatico"))
        return self.modo

    def ferma(self):
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.terminate()
            except OSError:
                pass
        if self._sock is not None:
            try:
                self._manda(self.risposta(ttl=0))   # «arrivederci»: le app tolgono Casa dall'elenco subito
                self._sock.close()
            except OSError:
                pass

    def stato(self):
        return {"attivo": bool(self.modo), "modo": self.modo, "servizio": "_filtreo._tcp", "nome": self.istanza.split("._")[0],
                "host": self.host, "ip": self.ip, "porta": self.porta}


def domanda(nome=SERVIZIO, tipo=T_PTR, ident=0):
    """pacchetto di domanda (per le prove e per cercare Casa da riga di comando)."""
    return struct.pack(">HHHHHH", ident, 0, 1, 0, 0, 0) + _nome_dns(nome) + struct.pack(">HH", tipo, 1)


def leggi_risposta(dati):
    """{"ptr": [...], "srv": {nome: (host, porta)}, "txt": {nome: {k: v}}, "a": {host: ip}} da un pacchetto di risposta."""
    out = {"ptr": [], "srv": {}, "txt": {}, "a": {}}
    try:
        _id, flag, qd, an, ns, ar = struct.unpack(">HHHHHH", dati[:12])
        i = 12
        for _ in range(qd):
            _n, i = _leggi_nome(dati, i)
            i += 4
        for _ in range(an + ns + ar):
            nome, i = _leggi_nome(dati, i)
            tipo, _c, _ttl, ln = struct.unpack(">HHIH", dati[i:i + 10])
            i += 10
            rd = dati[i:i + ln]
            if tipo == T_PTR:
                out["ptr"].append(_leggi_nome(dati, i)[0])
            elif tipo == T_SRV:
                out["srv"][nome] = (_leggi_nome(dati, i + 6)[0], struct.unpack(">H", rd[4:6])[0])
            elif tipo == T_TXT:
                d, j = {}, 0
                while j < len(rd):
                    n = rd[j]
                    k, _s, v = rd[j + 1:j + 1 + n].decode("utf-8", "replace").partition("=")
                    if k:
                        d[k] = v
                    j += 1 + n
                out["txt"][nome] = d
            elif tipo == T_A and ln == 4:
                out["a"][nome] = socket.inet_ntoa(rd)
            i += ln
    except (ValueError, struct.error, IndexError):
        pass
    return out


def cerca(attesa=3.0, porta_locale=0):
    """cerca Casa nella rete (domanda «semplice» da una porta qualsiasi): [{nome, host, porta, ip, txt}]."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.bind(("", porta_locale))
    s.settimeout(0.5)
    s.sendto(domanda(ident=0x1F17), (GRUPPO, PORTA_MDNS))
    fine, trovati = time.time() + attesa, {}
    while time.time() < fine:
        try:
            dati, _da = s.recvfrom(9000)
        except socket.timeout:
            continue
        r = leggi_risposta(dati)
        for ist, (host, porta) in r["srv"].items():
            trovati[ist] = {"nome": ist.split("._")[0], "host": host, "porta": porta, "ip": r["a"].get(host, ""), "txt": r["txt"].get(ist, {})}
    s.close()
    return list(trovati.values())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cerca":
        for x in cerca():
            print("%s · http://%s:%s · %s" % (x["nome"], x["ip"] or x["host"], x["porta"], x["txt"]))
    else:
        a = Annuncio(int(sys.argv[1]) if len(sys.argv) > 1 else 8099, "0.0.0", "Prova", "prova")
        print(a.avvia() or "annuncio non disponibile")
        time.sleep(600)
