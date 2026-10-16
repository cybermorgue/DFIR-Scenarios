import io
import zipfile

from gen.const import CMD
from gen.winfmt import T, ft2dt

ARBOL = {
    "triage/INT01_triage.zip",
    "red/fw01_2026-09-01_2026-10-19.log",
    "red/ids01_alerta_2026-10-04_8084.pcap",
    "inteligencia/aviso_CERT_2026-10-19.eml",
    "inteligencia/opendir_104.234.26.225_8090/index.html",
    "inteligencia/opendir_104.234.26.225_8090/access.log",
    "inteligencia/opendir_104.234.26.225_8090/ficha_muestras.md",
}
EN_EL_ZIP = {
    "C/Windows/System32/winevt/Logs/Security.evtx", "C/Windows/System32/winevt/Logs/System.evtx",
    "C/Windows/System32/winevt/Logs/Application.evtx",
    "C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
    "C/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
    "C/Windows/System32/winevt/Logs/Windows PowerShell.evtx",
    "C/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx",
    "C/Windows/System32/config/SYSTEM", "C/Windows/System32/config/SOFTWARE",
    "C/Windows/appcompat/Programs/Amcache.hve",
    "C/Program Files/Mirth Connect/logs/mirth.log", "C/Program Files/Mirth Connect/conf/mirth.properties",
}


def test_arbol_de_salidas(salidas):
    assert {k for k in salidas if "!" not in k} == ARBOL


def test_zip_contiene_el_triage(salidas):
    z = zipfile.ZipFile(io.BytesIO(salidas["triage/INT01_triage.zip"]))
    names = set(z.namelist())
    for n in EN_EL_ZIP:
        assert "INT01/" + n in names, n
    assert "INT01/C/Windows/Prefetch/" in names and not [n for n in names if n.startswith("INT01/C/Windows/Prefetch/") and n != "INT01/C/Windows/Prefetch/"]
    assert [n for n in names if n.endswith("_ConsoleLog.txt")] and [n for n in names if n.endswith("_CopyLog.csv")]


def test_consolelog_sin_mft(salidas):
    log = next(v for k, v in salidas.items() if k.endswith("_ConsoleLog.txt")).decode()
    for t in ("EventLogs", "RegistryHives", "Amcache", "Prefetch", "MirthConnect"):
        assert t in log
    assert "$MFT" not in log and "$J" not in log and "SRUM" not in log.upper()


def test_it_lanza_kape_en_la_sesion_de_triage(salidas, sim_final):
    s1 = [{n: v for n, _, v in e.data} for e in sim_final.ev["Sysmon"] if e.eid == 1]
    k = [x for x in s1 if x["Image"].endswith("kape.exe")]
    assert len(k) == 1 and k[0]["ParentImage"] == CMD
    assert ft2dt(sim_final.execs[k[0]["Image"].lower()][0][0]).date().isoformat() == "2026-10-19"
