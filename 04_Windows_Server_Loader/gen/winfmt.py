"""Formatos nativos de Windows (tiempo FILETIME, EVTX y colmenas regf).

Copiado del generador del escenario 03 sin cambios de comportamiento: cada escenario es
autocontenido. EVTX según libevtx (J. Metz) y python-evtx (W. Ballenthin); regf según libregf.
"""
import hashlib
import struct
import uuid
import zlib
from datetime import datetime, timedelta, timezone

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
        if len(self.buf) + len(rec) > self.SIZE - 8:        # libevtx descarta un registro que acaba en el último byte
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
        self.cls = None

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
        entry = {"k": k, "nk": nk, "parent": parent, "nm": nm, "vlist": None, "vks": [], "lh": None, "kids": [],
                 "cls": cell(len(k.cls) * 2) if k.cls else None}
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
                         e["vlist"][1] if e["vlist"] else 0xFFFFFFFF, sk[1], e["cls"][1] if e["cls"] else 0xFFFFFFFF,
                         max_sub, 0, max_vn, max_vd, 0, len(e["nm"]), len(k.cls) * 2 if k.cls else 0) + e["nm"]
        put(e["nk"], nk)
        if e["cls"]:
            put(e["cls"], k.cls.encode("utf-16-le"))
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
