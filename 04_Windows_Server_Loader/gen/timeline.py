"""Línea temporal de int01: ruido de fondo (background) y ataque (attack)."""
from .const import (ARDEAL_IP, CMD, DOMAIN, FQDN, HOLIDAYS, HOST, JTORRES_SID, JTORRES_WS_IP, KB_PUBLIC,
                    MCSERVICE, MS_UPDATE_IP, NAS_IP, REBOOT_T, USERS)
from .sim import GUIDS
from .winfmt import FT, EvtType as S, TICKS, ft2dt, sec

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
