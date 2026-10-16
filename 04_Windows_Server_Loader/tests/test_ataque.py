import re

import pytest

from gen.const import (CSC, CVTRES, FUENTES, INT01_IP, KB_PUBLIC, ONEDRIVE, ONESYNC, OP_IP, BUCKET_IP,
                       REBOOT_T, START_T, TRIAGE_T)
from gen.sim import Sim
from gen.timeline import attack, background
from gen.winfmt import FT, TICKS, sec

RX = re.compile(r"^(\S+) \| GET \| (\S+) (\S+) \| UA=(.*)$")


def f(ev):
    return {n: v for n, _, v in ev.data}


def iso2ft(s):
    d, t = s.split("T")
    y, mo, dd = map(int, d.split("-"))
    h, mi, ss = t.split(":")
    return FT(y, mo, dd, int(h), int(mi), float(ss))


@pytest.fixture(scope="module")
def run():
    s = Sim()
    background(s, START_T, TRIAGE_T)
    info = attack(s)
    return s, info


def s1(sim):
    return [f(e) for e in sim.ev["Sysmon"] if e.eid == 1]


def test_secuencia_http_kelbrook(run):
    sim, _ = run
    lines = [RX.match(l).groups() for l in open(FUENTES + "/access_real_saneado.log", encoding="utf-8")
             if RX.match(l) and RX.match(l).group(2) == KB_PUBLIC]
    assert len(lines) == 13
    s3 = [(e.ft, f(e)) for e in sim.ev["Sysmon"] if e.eid == 3 and f(e)["DestinationPort"] == 8090]
    for ts, ip, path, ua in lines:
        t = iso2ft(ts)
        assert [x for ft, x in s3 if 0 <= t - ft <= TICKS], (ts, path)
    assert [h[2] for h in sim.http_log] == ["/client64.exe"]


def test_cadena_de_procesos(run):
    sim, _ = run
    ps = [x for x in s1(sim) if x["Image"].endswith("powershell.exe") and "104.234.26.225" in x["CommandLine"]]
    assert len(ps) == 5 and all(x["ParentImage"].endswith("cmd.exe") for x in ps)
    cmds = [x for x in s1(sim) if x["Image"].endswith("cmd.exe") and x["ParentImage"].endswith("mcservice.exe")]
    assert len(cmds) >= 6
    agent = [x for x in s1(sim) if x["Image"].endswith("winpty-agent.exe")]
    assert agent and agent[0]["ParentImage"] == ONEDRIVE
    tar = [x for x in s1(sim) if x["Image"].endswith("tar.exe")]
    assert tar and tar[0]["ParentImage"].endswith("cmd.exe")
    sh = [x for x in s1(sim) if x["Image"] == ONESYNC and x["ParentImage"].endswith("services.exe")]
    assert len(sh) == 2          # arranque del servicio el 04/10 y tras el reinicio del 13/10


def test_tres_compilaciones_fallidas(run):
    sim, _ = run
    assert len([x for x in s1(sim) if x["Image"] == CSC]) == 3
    assert not [x for x in s1(sim) if x["Image"] == CVTRES]
    assert not [e for e in sim.ev["PSOp"] if e.eid == 4100]


def test_runps1_termina(run):
    sim, _ = run
    ps = [x for x in s1(sim) if x["Image"].endswith("powershell.exe") and "/run.ps1" in x["CommandLine"]]
    ended = {f(e)["ProcessId"] for e in sim.ev["Sysmon"] if e.eid == 5}
    assert len(ps) == 2 and all(x["ProcessId"] in ended for x in ps)
    ps2 = [x for x in s1(sim) if x["Image"].endswith("powershell.exe") and "/run2.ps1" in x["CommandLine"]]
    assert len(ps2) == 1 and ps2[0]["ProcessId"] not in ended


def test_scriptblocks_reales(run):
    sim, _ = run
    texts = [f(e)["ScriptBlockText"] for e in sim.ev["PSOp"] if e.eid == 4104]
    assert sum('[DllImport(""kernel32"")]' in t for t in texts) == 3
    assert any("addtype-err-" in t for t in texts)


def test_no_hay_sysmon8(run):
    sim, _ = run
    assert not [e for e in sim.ev["Sysmon"] if e.eid in (8, 10)]


def test_exfil_desde_onesynchost(run):
    sim, info = run
    up = [c for c in sim.net_log if c.dst == BUCKET_IP and c.pid == info["onesync_pid"] and c.bytes_out >= info["mc_tgz_size"]]
    assert len(up) == 1
    assert 180_000_000 <= info["mc_tgz_size"] <= 260_000_000
    assert not [x for x in s1(sim) if x["Image"].endswith("curl.exe") and "aliyuncs" in x["CommandLine"]]
    polls = [c for c in sim.net_log if c.dst == BUCKET_IP]
    assert len(polls) > 60 and max(c.start for c in polls) <= TRIAGE_T


def test_onedrive_sin_exit_hasta_reinicio(run):
    sim, info = run
    od = [x for x in s1(sim) if x["Image"] == ONEDRIVE]
    assert len(od) == 1 and od[0]["OriginalFileName"] == "ldr_win3.exe"
    assert od[0]["Hashes"].startswith("MD5=215336E9270941186AC2BCA89425E49B,SHA256=AD07D54B")
    assert not [e for e in sim.ev["Sysmon"] if e.eid == 5 and f(e)["Image"] == ONEDRIVE]


def test_stage3_conn(run):
    sim, info = run
    c = info["stage3_conn"]
    assert c.dst == OP_IP and c.dport == 8084 and c.bytes_in >= 8_000_000 and c.bytes_out >= 40


def test_servicio_instalado(run):
    sim, _ = run
    e = [f(x) for x in sim.ev["System"] if x.eid == 7045]
    assert len(e) == 1 and e[0]["ImagePath"] == ONESYNC
