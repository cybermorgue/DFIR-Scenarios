#!/usr/bin/env python3
"""Genera las evidencias del escenario 04 (servidor de integración comprometido y loader en memoria).

Todo es sintético y determinista. Las muestras del atacante no se incluyen: el shellcode va neutralizado
y la fase 3 es un buffer ficticio. Uso: python generar_escenario.py [directorio_de_salida]
"""
import os
import sys

from gen import payloads
from gen.const import BASE, OP_IP, START_T, TRIAGE_T
from gen.hives import HIVE_COPY, INSTALL, build_amcache, build_software, build_system
from gen.intel import access_log, aviso_cert_eml, ficha_muestras, index_html
from gen.kape import evtx_files, kape_zip
from gen.mirth import mirth_log, mirth_properties
from gen.red import fw01_log, ids_pcap
from gen.sim import CH, Sim
from gen.timeline import attack, background, triage_session
from gen.winfmt import T, sec

OPENDIR = f"opendir_{OP_IP}_8090"


def simulate():
    sim = Sim()
    background(sim, START_T, TRIAGE_T)
    sim.attack_info = attack(sim)
    triage_session(sim)
    for ch in CH:
        sim.ev[ch].sort(key=lambda e: e.ft)
    return sim


def triage_files(sim):
    files, deferred = dict(evtx_files(sim)), {}
    t0 = TRIAGE_T + sec(50.0)
    for i, p in enumerate(sorted(files)):
        deferred[p] = t0 + sec(i * 6.3)
    mirth = mirth_log(sim).splitlines(keepends=True)
    cut = next(i for i, l in enumerate(mirth) if l[:16] >= "INFO  2026-10-03" or l[6:16] >= "2026-10-03")
    base = "C/Program Files/Mirth Connect/"
    files[base + "logs/mirth.log.1"] = ("".join(mirth[:cut]).encode(), INSTALL + sec(5400), T(3, 6, 12, 40.0))
    files[base + "logs/mirth.log"] = ("".join(mirth[cut:]).encode(), T(3, 6, 12, 41.0), TRIAGE_T - sec(3600))
    files[base + "conf/mirth.properties"] = (mirth_properties().encode(), INSTALL + sec(5400), INSTALL + sec(5400))
    cfg = "C/Windows/System32/config/"
    hives = {cfg + "SYSTEM": (build_system(sim), INSTALL, T(13, 8, 31, 21.0), HIVE_COPY["SYSTEM"]),
             cfg + "SOFTWARE": (build_software(sim), INSTALL, T(13, 8, 35, 9.2), HIVE_COPY["SOFTWARE"]),
             "C/Windows/appcompat/Programs/Amcache.hve": (build_amcache(sim), INSTALL + sec(900),
                                                           T(19, 11, 19, 58.0), HIVE_COPY["Amcache"])}
    for p, (d, c, m, ct) in hives.items():
        files[p] = (d, c, m)
        deferred[p] = ct
        for ext, dt in ((".LOG1", 0.3), (".LOG2", 0.5)):
            files[p + ext] = (b"", c, c)
            deferred[p + ext] = ct + sec(dt)
    return files, deferred


def write(root, rel, data):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    return rel


def main(out_dir=None):
    out = out_dir or BASE
    sim = simulate()
    info = sim.attack_info
    files, deferred = triage_files(sim)
    write(out, "triage/INT01_triage.zip", kape_zip(sim, files, deferred))
    write(out, "red/fw01_2026-09-01_2026-10-19.log", fw01_log(sim))
    write(out, "red/ids01_alerta_2026-10-04_8084.pcap",
          ids_pcap(info["stage3_conn"], payloads.handshake(), payloads.stage3(payloads.STAGE3_SIZE)[:65536]))
    write(out, "inteligencia/aviso_CERT_2026-10-19.eml", aviso_cert_eml())
    write(out, f"inteligencia/{OPENDIR}/index.html", index_html())
    write(out, f"inteligencia/{OPENDIR}/access.log", access_log(sim))
    write(out, f"inteligencia/{OPENDIR}/ficha_muestras.md", ficha_muestras())
    return sim


if __name__ == "__main__":
    s = main(sys.argv[1] if len(sys.argv) > 1 else None)
    print("Escenario 04 generado:", {ch: len(s.ev[ch]) for ch in CH})
