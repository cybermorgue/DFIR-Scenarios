import csv
import email
import io
import re
import struct
from email import policy

import pytest

from gen import payloads
from gen.const import INT01_IP, KB_PUBLIC, OP_IP, TRIAGE_T
from gen.intel import access_log, aviso_cert_eml, ficha_muestras, index_html
from gen.mirth import mirth_log, mirth_properties
from gen.red import fw01_log, ids_pcap
from gen.sim import Sim
from gen.timeline import attack, background
from gen.winfmt import ft2dt

from gen.const import START_T


@pytest.fixture(scope="module")
def run():
    s = Sim()
    background(s, START_T, TRIAGE_T)
    return s, attack(s)


def frames(pcap):
    assert struct.unpack_from("<IHHiIII", pcap, 0)[0] == 0xA1B2C3D4
    assert struct.unpack_from("<I", pcap, 20)[0] == 1
    off, out = 24, []
    while off < len(pcap):
        _, _, cl, _ = struct.unpack_from("<IIII", pcap, off)
        out.append(pcap[off + 16: off + 16 + cl])
        off += 16 + cl
    return out


def cksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f">{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


@pytest.fixture(scope="module")
def pcap(run):
    sim, info = run
    return ids_pcap(info["stage3_conn"], payloads.handshake(), payloads.stage3(payloads.STAGE3_SIZE)[:65536])


def test_pcap_parsea(pcap):
    fr = frames(pcap)
    assert len(fr) > 40
    first = None
    for f in fr:
        ihl = (f[14] & 0xF) * 4
        tcp = f[14 + ihl:]
        pay = tcp[(tcp[12] >> 4) * 4:]
        if pay and f[26:30] == bytes(map(int, INT01_IP.split("."))):
            first = pay
            break
    assert first == payloads.handshake()


def test_checksums_tcp(pcap):
    for f in frames(pcap):
        ip = f[14:34]
        assert cksum(ip) == 0
        seg = f[34:]
        pseudo = f[26:34] + struct.pack(">BBH", 0, 6, len(seg))
        assert cksum(pseudo + seg) == 0


def test_accesslog_ordenado_y_formato(run):
    sim, _ = run
    txt = access_log(sim)
    lines = txt.splitlines()
    rx = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6} \| GET \| \S+ \S+ \| UA=.*$")
    assert all(rx.match(l) for l in lines)
    assert [l[:26] for l in lines] == sorted(l[:26] for l in lines)
    assert any(f"| {KB_PUBLIC} /client64.exe | UA=curl/7.55.1" in l and l.startswith("2026-10-04T19:18:3") for l in lines)
    assert "sysupdate" not in txt and "45.134.213.215" not in txt and "203.0.113.77 /access.log" in txt
    assert lines[-1] < "2026-10-16T08:37:59"


def test_index_sin_sysupdate():
    h = index_html()
    assert "sysupdate" not in h.lower()
    for n in ("OneDrive.exe", "client64.exe", "run.ps1", "run2.ps1", "bootstrap_enc.txt", "server.py", "access.log"):
        assert f'href="{n}"' in h


def test_fw_cubre_sysmon3_externos(run):
    sim, _ = run
    rows = list(csv.DictReader(io.StringIO(fw01_log(sim))))
    assert rows and list(rows[0]) == ["fecha_utc", "accion", "regla", "proto", "origen", "puerto_origen", "destino",
                                      "puerto_destino", "nat", "bytes_enviados", "bytes_recibidos", "duracion_s"]
    assert [r["fecha_utc"] for r in rows] == sorted(r["fecha_utc"] for r in rows)
    keys = {(r["origen"], r["puerto_origen"], r["destino"], r["puerto_destino"]) for r in rows}
    ext = [e for e in sim.ev["Sysmon"] if e.eid == 3]
    assert ext
    for e in ext:
        d = {n: v for n, _, v in e.data}
        assert (d["SourceIp"], str(d["SourcePort"]), d["DestinationIp"], str(d["DestinationPort"])) in keys


def test_aviso_cert():
    m = email.message_from_bytes(aviso_cert_eml(), policy=policy.default)
    assert m["Date"] == "Mon, 19 Oct 2026 09:10:00 +0200"
    body = m.get_body().get_content()
    assert KB_PUBLIC in body and OP_IP in body and ":8090" in body


def test_ficha_y_mirth(run):
    sim, _ = run
    assert "ad07d54b62359749b7a32c265e19e5f36cd4962cf957ea6c0fb07ceddb702230" in ficha_muestras()
    log = mirth_log(sim)
    assert "/api/server/version" in log and "XStream" in log and "2026-10-04 18:52:48" in log
    assert "https.port = 8443" in mirth_properties()
