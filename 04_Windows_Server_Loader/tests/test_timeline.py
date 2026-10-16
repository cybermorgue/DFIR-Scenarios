import pytest

from gen.const import ARDEAL_IP, JTORRES_SID, REBOOT_T, START_T, TRIAGE_T
from gen.sim import Sim
from gen.timeline import background
from gen.winfmt import FT, TICKS, ft2dt


def f(ev):
    return {n: v for n, _, v in ev.data}


@pytest.fixture(scope="module")
def sim():
    s = Sim()
    background(s, START_T, TRIAGE_T)
    return s


def test_mllp_solo_laborables(sim):
    mllp = [c for c in sim.net_log if c.dport == 6661]
    assert len(mllp) > 500
    for c in mllp:
        d = ft2dt(c.start)
        assert c.src == ARDEAL_IP and d.weekday() < 5 and 7 <= d.hour < 18
    # el 12/10 es fiesta nacional: Ardeal no envía
    assert not [c for c in mllp if ft2dt(c.start).date().isoformat() == "2026-10-12"]


def test_rdp_martes(sim):
    rdp = [f(e) for e in sim.ev["Security"] if e.eid == 4624 and f(e).get("LogonType") == 10]
    assert len(rdp) >= 6
    for x in rdp:
        assert x["TargetUserSid"] == JTORRES_SID
    tues = {ft2dt(e.ft).weekday() for e in sim.ev["Security"] if e.eid == 4624 and f(e).get("LogonType") == 10}
    assert tues == {1}


def test_sin_windows_update(sim):
    assert not [e for e in sim.ev["System"] if e.provider == "Microsoft-Windows-WindowsUpdateClient"]
    r1074 = [e for e in sim.ev["System"] if e.eid == 1074]
    assert len(r1074) == 2
    assert abs(r1074[1].ft - REBOOT_T) < TICKS and "adm.jtorres" in f(r1074[1])["param7"]
    assert ft2dt(r1074[0].ft).date().isoformat() == "2026-09-15"


def test_escaneos_a_8443(sim):
    scans = [c for c in sim.net_log if c.dport == 8443]
    days = {ft2dt(c.start).date() for c in scans}
    assert len(days) >= 45 and len(scans) >= 45 * 30


def test_logs_cubren_la_ventana(sim):
    first = min(e.ft for e in sim.ev["Sysmon"])
    assert first < FT(2026, 9, 2)
    assert max(e.ft for e in sim.ev["Sysmon"]) <= TRIAGE_T


def test_userinit_cuelga_de_winlogon(sim):
    ui = [f(e) for e in sim.ev["Sysmon"] if e.eid == 1 and f(e)["Image"].endswith("userinit.exe")]
    assert ui and all(x["ParentImage"].endswith("winlogon.exe") for x in ui)


def test_application_tiene_actividad(sim):
    app = [e for e in sim.ev["Application"]]
    assert len(app) > 40
    assert {e.provider for e in app} >= {"Microsoft-Windows-Security-SPP"}


def test_el_ataque_no_salta_en_un_recuento_diario():
    from collections import Counter
    from statistics import median
    from gen.timeline import attack
    sim = Sim()
    background(sim, START_T, TRIAGE_T)
    attack(sim)
    for ch, ratio in (("Sysmon", 3.0), ("Security", 3.0)):
        por_dia = Counter(ft2dt(e.ft).date() for e in sim.ev[ch])
        mediana = median(por_dia[d] for d in por_dia if d.isoformat() < "2026-10-04")
        assert por_dia[ft2dt(FT(2026, 10, 4)).date()] / mediana < ratio, (ch, mediana)
    assert len([e for e in sim.ev["Security"] if e.eid == 4624]) > 1500
