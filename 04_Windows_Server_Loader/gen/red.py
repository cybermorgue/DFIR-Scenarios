"""Fuentes de red: log del cortafuegos fw01 y captura del IDS ids01."""
import socket
import struct

from .const import INT01_IP, KB_PUBLIC, TRIAGE_T
from .winfmt import TICKS, ft2dt, ft2unix, sec

FW_HEADER = ["fecha_utc", "accion", "regla", "proto", "origen", "puerto_origen", "destino", "puerto_destino", "nat",
             "bytes_enviados", "bytes_recibidos", "duracion_s"]


def _ts(ft):
    return ft2dt(ft).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def fw01_log(sim):
    """Una línea por conexión que toca a int01. En las entrantes el destino es la IP pública y `nat` la interna."""
    rows = []
    for c in sim.net_log:
        if c.start > TRIAGE_T:
            continue
        inbound = c.src != INT01_IP
        dst = KB_PUBLIC if inbound else c.dst
        nat = "-" if c.action == "deny" else (INT01_IP if inbound else KB_PUBLIC)
        rows.append((c.start, [_ts(c.start), c.action, c.rule, c.proto, c.src, c.sport, dst, c.dport, nat,
                               c.bytes_out, c.bytes_in, f"{(c.end - c.start) / TICKS:.3f}"]))
    rows.sort(key=lambda r: r[0])
    return "\n".join([",".join(FW_HEADER)] + [",".join(str(x) for x in r[1]) for r in rows]) + "\n"


# ----------------------------------------------------------------------- pcap
MAC_CLIENT = bytes.fromhex("005056a1c3e4")
MAC_GW = bytes.fromhex("00505692d1f7")


def _cksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f">{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _frame(src, dst, sport, dport, seq, ack, flags, payload=b"", options=b"", ip_id=0, ttl=128, from_client=True):
    s_ip, d_ip = socket.inet_aton(src), socket.inet_aton(dst)
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, ((20 + len(options)) // 4) << 4,
                      flags, 64240, 0, 0) + options
    seg = hdr + payload
    csum = _cksum(s_ip + d_ip + struct.pack(">BBH", 0, 6, len(seg)) + seg)
    seg = seg[:16] + struct.pack(">H", csum) + seg[18:]
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), ip_id & 0xFFFF, 0x4000, ttl, 6, 0, s_ip, d_ip)
    ip = ip[:10] + struct.pack(">H", _cksum(ip)) + ip[12:]
    macs = MAC_GW + MAC_CLIENT if from_client else MAC_CLIENT + MAC_GW
    return macs + b"\x08\x00" + ip + seg


def ids_pcap(conn, handshake, stage3_head):
    """Sesión int01 -> :8084 guardada por Suricata: tres vías, saludo de 40 bytes, la cabecera de la fase 3 y cierre."""
    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
    c_ip, s_ip, cp, sp = conn.src, conn.dst, conn.sport, conn.dport
    c_seq, s_seq = 0x2A4F9C11, 0x7B3E01D5
    t0 = ft2unix(conn.start)
    rtt = 0.038
    pk = []
    ident = [0x3A10, 0x0000]

    def put(t, from_client, **kw):
        i = ident[0 if from_client else 1]
        ident[0 if from_client else 1] += 1
        a = (c_ip, s_ip, cp, sp) if from_client else (s_ip, c_ip, sp, cp)
        pk.append((t, _frame(*a, ip_id=i, ttl=128 if from_client else 54, from_client=from_client, **kw)))

    opt_syn = bytes.fromhex("020405b401030308" "0402" "0101")
    put(t0, True, seq=c_seq, ack=0, flags=SYN, options=opt_syn)
    put(t0 + rtt, False, seq=s_seq, ack=c_seq + 1, flags=SYN | ACK, options=bytes.fromhex("020405b4" "0402" "0101" "01030307"))
    c_seq += 1
    s_seq += 1
    put(t0 + rtt + 0.0002, True, seq=c_seq, ack=s_seq, flags=ACK)
    t = t0 + rtt + 0.0011
    put(t, True, seq=c_seq, ack=s_seq, flags=PSH | ACK, payload=handshake)
    c_seq += len(handshake)
    t += rtt
    put(t, False, seq=s_seq, ack=c_seq, flags=ACK)
    for n, off in enumerate(range(0, len(stage3_head), 1460), 1):
        chunk = stage3_head[off:off + 1460]
        t += 0.00013
        put(t, False, seq=s_seq, ack=c_seq, flags=ACK | (PSH if off + 1460 >= len(stage3_head) else 0), payload=chunk)
        s_seq += len(chunk)
        if n % 2 == 0:
            put(t + rtt, True, seq=c_seq, ack=s_seq, flags=ACK)
    t += rtt + 0.0004
    put(t, True, seq=c_seq, ack=s_seq, flags=FIN | ACK)
    put(t + rtt, False, seq=s_seq, ack=c_seq + 1, flags=FIN | ACK)
    put(t + rtt + 0.0002, True, seq=c_seq + 1, ack=s_seq + 1, flags=ACK)
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, data in pk:
        sec_, us = divmod(int(round(ts * 1_000_000)), 1_000_000)
        out += struct.pack("<IIII", sec_, us, len(data), len(data)) + data
    return bytes(out)
