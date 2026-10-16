from gen.const import CMD, CSC, CVTRES, POWERSHELL, OP_IP
from gen.sim import Sim
from gen.winfmt import T


def f(ev):
    return {n: v for n, _, v in ev.data}


def nuevo():
    sim = Sim()
    sim.boot(T(1, 6, 0, 0.0))
    return sim


def test_spawn_emite_sysmon1_y_4688():
    sim = nuevo()
    p = sim.spawn(T(4, 18, 52, 48.0), CMD, "cmd.exe /c whoami", sim.procs["mcservice"], "system")
    s1 = [f(e) for e in sim.ev["Sysmon"] if e.eid == 1 and f(e)["ProcessId"] == p.pid]
    s4688 = [f(e) for e in sim.ev["Security"] if e.eid == 4688 and f(e)["NewProcessId"] == p.pid]
    assert len(s1) == 1 and len(s4688) == 1
    assert s1[0]["CommandLine"] == s4688[0]["CommandLine"] == "cmd.exe /c whoami"
    assert s1[0]["ParentImage"].endswith("mcservice.exe")


def test_net_registra_conn():
    sim = nuevo()
    p = sim.spawn(T(4, 18, 53, 40.0), POWERSHELL, "powershell -nop", sim.procs["mcservice"], "system")
    c = sim.net(T(4, 18, 53, 40.1), p, OP_IP, 8090, bytes_out=210, bytes_in=3200, dur=0.3)
    assert c in sim.net_log and c.dst == OP_IP and c.dport == 8090 and c.bytes_in == 3200
    s3 = [f(e) for e in sim.ev["Sysmon"] if e.eid == 3]
    assert s3[-1]["DestinationIp"] == OP_IP and s3[-1]["SourcePort"] == c.sport


def test_addtype_fallido():
    sim = nuevo()
    ps = sim.spawn(T(4, 18, 53, 40.0), POWERSHELL, "powershell -nop", sim.procs["mcservice"], "system")
    sim.addtype_compile(T(4, 18, 53, 40.7), ps, fails=True)
    s1 = [f(e) for e in sim.ev["Sysmon"] if e.eid == 1]
    csc = [x for x in s1 if x["Image"] == CSC]
    assert len(csc) == 1 and csc[0]["ParentImage"] == POWERSHELL
    assert not [x for x in s1 if x["Image"] == CVTRES]
    created = {f(e)["TargetFilename"] for e in sim.ev["Sysmon"] if e.eid == 11}
    deleted = {f(e)["TargetFilename"] for e in sim.ev["Sysmon"] if e.eid == 26}
    tmp = [x for x in created if x.lower().startswith("c:\\windows\\temp\\")]
    assert {x.rsplit(".", 1)[-1] for x in tmp} == {"cs", "cmdline", "out", "err"}
    assert set(tmp) <= deleted and not [x for x in created if x.endswith(".dll")]


def test_addtype_correcto_lanza_cvtres():
    sim = nuevo()
    ps = sim.spawn(T(4, 18, 53, 40.0), POWERSHELL, "powershell -nop", sim.procs["mcservice"], "system")
    sim.addtype_compile(T(4, 18, 53, 40.7), ps, fails=False)
    s1 = [f(e) for e in sim.ev["Sysmon"] if e.eid == 1]
    assert [x for x in s1 if x["Image"] == CVTRES and x["ParentImage"] == CSC]


def test_4104_largo_se_parte():
    sim = nuevo()
    ps = sim.spawn(T(4, 18, 53, 40.0), POWERSHELL, "powershell -nop", sim.procs["mcservice"], "system")
    sim.ps_session(T(4, 18, 53, 40.2), ps, "A" * 40000)
    sb = [f(e) for e in sim.ev["PSOp"] if e.eid == 4104]
    assert [x["MessageNumber"] for x in sb] == [1, 2, 3] and {x["MessageTotal"] for x in sb} == {3}
    assert "".join(x["ScriptBlockText"] for x in sb) == "A" * 40000


def test_service_install():
    sim = nuevo()
    path = r"C:\ProgramData\Microsoft\OneDrive\Sync\OneSyncHost.exe"
    sim.service_install(T(4, 19, 19, 5.0), "OneSyncHost", "OneDrive Sync Host", path, "auto start", "LocalSystem")
    e7045 = [f(e) for e in sim.ev["System"] if e.eid == 7045]
    e4697 = [f(e) for e in sim.ev["Security"] if e.eid == 4697]
    assert e7045 and e7045[0]["ImagePath"] == path and e7045[0]["ServiceName"] == "OneDrive Sync Host"
    assert e4697 and e4697[0]["ServiceFileName"] == path


def test_http_log():
    sim = nuevo()
    sim.http(T(4, 19, 18, 30.5), "/client64.exe", "curl/7.55.1")
    assert sim.http_log == [(T(4, 19, 18, 30.5), "192.0.2.25", "/client64.exe", "curl/7.55.1")]


def test_ventanas_de_registro_por_arranque():
    sim = Sim()
    sim.boot(T(1, 6, 0, 0.0))
    mc1 = sim.procs["mcservice"]
    sim.shutdown(T(13, 8, 31, 0.0), "system", "Otro (planeado)")
    sim.boot(T(13, 8, 33, 0.0))
    # un evento emitido después de construir los dos arranques, con fecha del primero, se registra
    p = sim.spawn(T(4, 18, 52, 48.0), CMD, "cmd.exe /c whoami", sim.procs_at(T(4, 18, 52, 48.0))["mcservice"], "system")
    assert sim.procs_at(T(4, 18, 52, 48.0))["mcservice"] is mc1 and sim.procs["mcservice"] is not mc1
    assert [e for e in sim.ev["Sysmon"] if e.eid == 1 and f(e)["ProcessId"] == p.pid]
    # en el hueco del reinicio no se registra nada
    q = sim.spawn(T(13, 8, 32, 0.0), CMD, "cmd.exe", mc1, "system")
    assert not [e for e in sim.ev["Sysmon"] if e.eid == 1 and f(e)["ProcessId"] == q.pid]


def test_eventos_del_primer_arranque_usan_su_ventana():
    sim = Sim()
    sim.boot(T(1, 6, 0, 0.0))
    first = sim.boots[0]
    sim.shutdown(T(13, 8, 31, 0.0), "system", "Otro (planeado)")
    sim.boot(T(13, 8, 33, 0.0))
    t = T(4, 19, 19, 5.0)
    p = sim.spawn(t, CMD, "cmd.exe", sim.procs_at(t)["mcservice"], "system")
    assert p.lguid == sim.logon_guid(first["t"], 0x3E7)
    sim.service_install(t, "OneSyncHost", "OneDrive Sync Host", r"C:\x\a.exe", "auto start", "LocalSystem")
    e7045 = [e for e in sim.ev["System"] if e.eid == 7045][0]
    assert e7045.pid == first["procs"]["services"].pid


def test_pids_se_reinician_con_cada_arranque():
    sim = Sim()
    sim.boot(T(1, 6, 0, 0.0))
    for i in range(200):
        sim.spawn(T(1, 7, 0, i * 1.0), CMD, "cmd.exe", sim.procs["mcservice"], "system", log=False)
    sim.shutdown(T(13, 8, 31, 0.0), "system", "Otro (planeado)")
    sim.boot(T(13, 8, 33, 0.0))
    assert len(sim.pids) < 40
