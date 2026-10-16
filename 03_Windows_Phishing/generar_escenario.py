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
