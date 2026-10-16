"""Motor de simulación de int01 (adaptado de la clase Sim del escenario 03).

Cada evento se emite una sola vez desde la línea temporal; los escritores de cada fuente
(EVTX, colmenas, fw01, PCAP, access.log) leen de este mismo estado.
"""
import hashlib
import random
import string
import struct
import uuid
from dataclasses import dataclass

from .const import (CMD, CSC, CVTRES, DOMAIN, FQDN, HOST, IMG, INT01_IP, KB_PUBLIC, MCSERVICE, PS_VER,
                    USERS, hashes)
from .winfmt import Event, EvtType as S, ft2unix, iso, sec

SYSMON_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
SEC_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
MACHINE_GUID_PART = 0x4B1D0C30
GUIDS = {
    "Microsoft-Windows-Kernel-General": "{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}",
    "Microsoft-Windows-Kernel-Power": "{331c3b3a-2005-44c2-ac5e-77220c37d6b4}",
    "Service Control Manager": "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
    "User32": "{b0aa8734-56f7-41cc-b2f4-de228e98b946}",
    "Microsoft-Windows-PowerShell": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
    "Microsoft-Windows-Windows Defender": "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}",
    "Microsoft-Windows-Eventlog": "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
}
CH = ("Security", "System", "Application", "Sysmon", "PSOp", "PS", "Defender")
CHANNEL_NAME = {"Security": "Security", "System": "System", "Application": "Application",
                "Sysmon": "Microsoft-Windows-Sysmon/Operational",
                "PSOp": "Microsoft-Windows-PowerShell/Operational", "PS": "Windows PowerShell",
                "Defender": "Microsoft-Windows-Windows Defender/Operational"}
INTEGRITY_SID = {"System": "S-1-16-16384", "High": "S-1-16-12288", "Medium": "S-1-16-8192"}
SB_CHUNK = 16000          # 4104 parte los bloques largos en mensajes de este tamaño


@dataclass(eq=False)
class Conn:
    start: int
    end: int
    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    bytes_out: int
    bytes_in: int
    action: str
    rule: str
    nat_src: str
    pid: int = 0


class Proc:
    __slots__ = ("pid", "guid", "image", "cmd", "parent", "user", "logon", "lguid", "session",
                 "integrity", "start", "end", "cwd")

    @property
    def name(self):
        return self.image.rsplit("\\", 1)[-1]


class Sim:
    def __init__(self, seed=1004):
        self.ev = {c: [] for c in CH}
        self.rng = random.Random(seed)
        self.execs = {}              # imagen (minúsculas) -> [(t, Proc)]
        self.pids = set()
        self.procs = {}              # nombre lógico -> Proc del arranque actual
        self.logons = {}             # clave de usuario -> (id, guid)
        self.boot_t = None
        self.boots = []              # [{"t", "sysmon", "audit", "end", "procs", "sysmon_pid", "lsass_pid"}]
        self.sysmon_pid = 0
        self.lsass_pid = 0
        self.running = []            # procesos vivos (para cerrarlos en el apagado)
        self.net_log = []            # [Conn]
        self.http_log = []           # [(ft, ip_origen, ruta, user_agent)]
        self.files = {}              # ruta -> (ctime, mtime, size)
        self.reg = []                # (t, clave, valor, tipo, dato) para las colmenas
        self.shutdowns = []          # [(t, usuario, motivo)]
        self.ps_seq = 1

    # --------------------------------------------------------------- utilidades
    def tid(self):
        return self.rng.randrange(400, 12000, 4)

    def new_pid(self):
        while True:
            p = self.rng.randrange(600, 16000, 4)
            if p not in self.pids:
                self.pids.add(p)
                return p

    def proc_guid(self, t, pid):
        u = int(ft2unix(t))
        return "{%08x-%04x-%04x-%04x-%012x}" % (MACHINE_GUID_PART, u & 0xFFFF, u >> 16,
                                               (pid * 0x9E37) & 0xFFFF, 0x1000 + (pid >> 2))

    def logon_guid(self, t, lid):
        u = int(ft2unix(t))
        b = struct.pack("<Q", lid)
        return "{%08x-%04x-%04x-%s-%s}" % (MACHINE_GUID_PART, u & 0xFFFF, u >> 16, b[:2].hex(), b[2:].hex())

    def user_str(self, ukey):
        sid, name, dom, _ = USERS[ukey]
        return f"{dom}\\{name}"

    def logon_id(self, ukey):
        if USERS[ukey][3] is not None:
            return USERS[ukey][3]
        return self.logons[ukey][0]

    def rand_name(self, n=8):
        return "".join(self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))

    # --------------------------------------------------------------- emisores básicos
    def add(self, ch, ev):
        ev.channel = CHANNEL_NAME[ch]
        self.ev[ch].append(ev)

    def boot_at(self, t):
        """Arranque que cubre el instante t (None si el equipo estaba apagado)."""
        for b in reversed(self.boots):
            if b["t"] <= t and (b["end"] is None or t < b["end"]):
                return b
        return None

    def procs_at(self, t):
        b = self.boot_at(t)
        return b["procs"] if b else {}

    def sysmon(self, t, eid, ver, fields):
        b = self.boot_at(t)
        if b is None or t < b["sysmon"]:
            return
        self.add("Sysmon", Event(t, "Microsoft-Windows-Sysmon", eid, fields, guid=SYSMON_GUID, ver=ver,
                                 task=eid, pid=b["sysmon_pid"], tid=self.rng.choice((2884, 3012, 3460, 4216)),
                                 user="S-1-5-18"))

    def sec(self, t, eid, task, fields, ver=0, pid=None, kw=0x8020000000000000):
        b = self.boot_at(t)
        if b is None or t < b["audit"]:
            return
        self.add("Security", Event(t, "Microsoft-Windows-Security-Auditing", eid, fields, guid=SEC_GUID,
                                   ver=ver, level=0, task=task, kw=kw,
                                   pid=b["lsass_pid"] if pid is None else pid, tid=self.tid()))

    def sys(self, t, provider, eid, fields, ch="System", guid=None, esn=None, qual=None, ver=0, level=4,
            task=0, opcode=0, kw=0x8000000000000000, pid=None, user=None, activity=None):
        self.add(ch, Event(t, provider, eid, fields, guid=guid, esn=esn, qual=qual, ver=ver, level=level,
                           task=task, opcode=opcode, kw=kw,
                           pid=self.rng.choice((4, 668, 1012, 1388)) if pid is None else pid,
                           tid=self.tid(), user=user, activity=activity))

    # --------------------------------------------------------------- ciclo de vida del equipo
    def boot(self, t):
        """Arranque en frío de Server 2019: procesos base, servicios, Sysmon y Mirth."""
        self.boot_t = t
        self.pids = set()            # cada arranque tiene su propio espacio de PIDs
        self.procs = {}
        self.running = []
        b = {"t": t, "audit": t + sec(4.2), "sysmon": t + sec(6.8), "end": None, "procs": self.procs,
             "sysmon_pid": 0, "lsass_pid": 0}
        self.boots.append(b)
        self.logons = {}
        self.sys(t + sec(0.5), "Microsoft-Windows-Kernel-General", 12, [
            ("MajorVersion", S.U32, 10), ("MinorVersion", S.U32, 0), ("BuildVersion", S.U32, 17763),
            ("QfeVersion", S.U32, 6054), ("ServiceVersion", S.U32, 0), ("BootMode", S.U32, 0),
            ("StartTime", S.FT, t)], guid=GUIDS["Microsoft-Windows-Kernel-General"], ver=1, level=4,
            task=0, kw=0x8000000000000080, pid=4, user="S-1-5-18")
        base = [("smss", r"C:\Windows\System32\smss.exe", r"\SystemRoot\System32\smss.exe", None, 0.9),
                ("csrss", r"C:\Windows\System32\csrss.exe", r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows", "smss", 1.6),
                ("wininit", r"C:\Windows\System32\wininit.exe", "wininit.exe", "smss", 1.7),
                ("winlogon", r"C:\Windows\System32\winlogon.exe", "winlogon.exe", "smss", 1.8),
                ("services", r"C:\Windows\System32\services.exe", r"C:\Windows\system32\services.exe", "wininit", 2.1),
                ("lsass", r"C:\Windows\System32\lsass.exe", r"C:\Windows\system32\lsass.exe", "wininit", 2.2)]
        for key, img, cmd, par, dt in base:
            self.spawn(t + sec(dt), img, cmd, self.procs.get(par), "system", key=key, log=False)
        self.lsass_pid = b["lsass_pid"] = self.procs["lsass"].pid
        self.sec(b["audit"], 4608, 12288, [], pid=self.lsass_pid)
        self.sys(t + sec(5.0), "EventLog", 6009, [(None, S.STR, "10.00."), (None, S.STR, "17763"),
                                                  (None, S.STR, "Multiprocessor Free"), (None, S.STR, "0")],
                 esn="EventLog", qual=0x8000, pid=0)
        self.sys(t + sec(5.0), "EventLog", 6005, [], esn="EventLog", qual=0x8000, pid=0)
        svc = self.procs["services"]
        sm = self.spawn(t + sec(6.5), r"C:\Windows\Sysmon64.exe", r"C:\Windows\Sysmon64.exe", svc, "system",
                        key="sysmon", log=False)
        self.sysmon_pid = b["sysmon_pid"] = sm.pid
        for key, cmd, ukey, dt in [("svc_dcom", "-k DcomLaunch -p", "system", 7.1),
                                   ("svc_rpcss", "-k RPCSS -p", "network", 7.3),
                                   ("svc_eventlog", "-k LocalServiceNetworkRestricted -p -s EventLog", "local", 7.6),
                                   ("svc_netsvcs", "-k netsvcs -p -s Schedule", "system", 8.0),
                                   ("svc_dns", "-k NetworkService -p -s Dnscache", "network", 8.4),
                                   ("svc_termsvc", "-k NetworkService -s TermService", "network", 9.1),
                                   ("svc_winmgmt", "-k netsvcs -p -s Winmgmt", "system", 9.4)]:
            self.spawn(t + sec(dt), r"C:\Windows\System32\svchost.exe",
                       r"C:\Windows\system32\svchost.exe " + cmd, svc, ukey, key=key)
        plat = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0"
        self.spawn(t + sec(10.2), plat + r"\MsMpEng.exe", '"' + plat + r'\MsMpEng.exe"', svc, "system",
                   key="msmpeng")
        mc = self.spawn(t + sec(12.8), MCSERVICE, '"' + MCSERVICE + '"', svc, "system", key="mcservice",
                        cwd=r"C:\Program Files\Mirth Connect" + "\\")
        for name in ("Sysmon64", "Servicio Antivirus de Microsoft Defender", "Mirth Connect Service",
                     "Servicios de Escritorio remoto"):
            self.sys(t + sec(13.5 + self.rng.random()), "Service Control Manager", 7036,
                     [("param1", S.STR, name), ("param2", S.STR, "en ejecución"),
                      ("Binary", S.BIN, name.encode("utf-16-le")[:16])],
                     guid=GUIDS["Service Control Manager"], esn="Service Control Manager", qual=16384,
                     kw=0x8080000000000000, pid=svc.pid)
        return mc

    def shutdown(self, t, ukey, reason, comment="", process=r"C:\Windows\system32\shutdown.exe"):
        """Reinicio ordenado: 1074 con el proceso, el usuario y el motivo, 6006 y fin de registro."""
        sid, name, dom, _ = USERS[ukey]
        self.sys(t, "User32", 1074, [
            ("param1", S.STR, f"{process} ({HOST})"), ("param2", S.STR, HOST),
            ("param3", S.STR, reason), ("param4", S.STR, "0x80040001"), ("param5", S.STR, "Reiniciar"),
            ("param6", S.STR, comment), ("param7", S.STR, f"{dom}\\{name}")],
            guid=GUIDS["User32"], esn="User32", qual=0x8000, kw=0x8080000000000000, user=sid)
        self.sys(t + sec(21.0), "EventLog", 6006, [], esn="EventLog", qual=0x8000, pid=0)
        self.shutdowns.append((t, ukey, reason))
        self.boot_at(t)["end"] = t + sec(22.0)
        for p in self.running:
            if p.end is None:
                p.end = t + sec(21.5)      # mueren con el apagado; Sysmon ya no registra su 5
        self.running = []

    # --------------------------------------------------------------- procesos
    def spawn(self, t, image, cmd, parent, ukey, integrity="System", session=None, cwd=None, life=None,
              rule="-", key=None, log=True):
        p = Proc()
        p.pid, p.image, p.cmd, p.parent, p.user = self.new_pid(), image, cmd, parent, ukey
        p.start, p.end = t, None
        p.session = session if session is not None else (0 if ukey in ("system", "local", "network") else 2)
        p.integrity = integrity
        p.cwd = cwd or (r"C:\Windows\system32" + "\\")
        p.guid = self.proc_guid(t, p.pid)
        lid = self.logon_id(ukey)
        p.logon = lid
        b = self.boot_at(t)
        p.lguid = self.logons[ukey][1] if ukey in self.logons else self.logon_guid(b["t"] if b else self.boot_t or t, lid)
        self.execs.setdefault(image.lower(), []).append((t, p))
        self.running.append(p)
        if key:
            self.procs[key] = p
        if log:
            self._log_spawn(t, p, rule)
        if life:
            self.exit(p, t + sec(life))
        return p

    def _log_spawn(self, t, p, rule):
        ver, desc, prod, comp, orig = IMG.get(p.image.lower(), ("-", "-", "-", "-", "-"))
        md5, sha256, imp, _ = hashes(p.image)
        par = p.parent
        self.sysmon(t, 1, 5, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image), ("FileVersion", S.STR, ver),
            ("Description", S.STR, desc), ("Product", S.STR, prod), ("Company", S.STR, comp),
            ("OriginalFileName", S.STR, orig), ("CommandLine", S.STR, p.cmd), ("CurrentDirectory", S.STR, p.cwd),
            ("User", S.STR, self.user_str(p.user)), ("LogonGuid", S.GUID, p.lguid), ("LogonId", S.HEX64, p.logon),
            ("TerminalSessionId", S.U32, p.session), ("IntegrityLevel", S.STR, p.integrity),
            ("Hashes", S.STR, f"MD5={md5},SHA256={sha256},IMPHASH={imp}"),
            ("ParentProcessGuid", S.GUID, par.guid if par else "{00000000-0000-0000-0000-000000000000}"),
            ("ParentProcessId", S.U32, par.pid if par else 4),
            ("ParentImage", S.STR, par.image if par else "System"),
            ("ParentCommandLine", S.STR, par.cmd if par else ""),
            ("ParentUser", S.STR, self.user_str(par.user) if par else "NT AUTHORITY\\SYSTEM")])
        cu = par.user if par else "system"
        csid, cname, cdom, _ = USERS[cu]
        if cu == "system":
            cname, cdom = HOST + "$", DOMAIN
        tsid, tname, tdom, _ = USERS[p.user]
        same = cu == p.user
        self.sec(t, 4688, 13312, [
            ("SubjectUserSid", S.SID, csid), ("SubjectUserName", S.STR, cname), ("SubjectDomainName", S.STR, cdom),
            ("SubjectLogonId", S.HEX64, self.logon_id(cu)), ("NewProcessId", S.HEX64, p.pid),
            ("NewProcessName", S.STR, p.image), ("TokenElevationType", S.STR, "%%1936"),
            ("ProcessId", S.HEX64, par.pid if par else 4), ("CommandLine", S.STR, p.cmd),
            ("TargetUserSid", S.SID, "S-1-0-0" if same else tsid),
            ("TargetUserName", S.STR, "-" if same else tname),
            ("TargetDomainName", S.STR, "-" if same else tdom),
            ("TargetLogonId", S.HEX64, 0 if same else p.logon),
            ("ParentProcessName", S.STR, par.image if par else ""),
            ("MandatoryLabel", S.SID, INTEGRITY_SID.get(p.integrity, "S-1-16-16384"))], ver=2, pid=4)

    def exit(self, p, t):
        if p.end is not None:
            return
        if p in self.running:
            self.running.remove(p)
        p.end = t
        self.sysmon(t, 5, 3, [("RuleName", S.STR, "-"), ("UtcTime", S.STR, iso(t, 3)),
                              ("ProcessGuid", S.GUID, p.guid), ("ProcessId", S.U32, p.pid),
                              ("Image", S.STR, p.image), ("User", S.STR, self.user_str(p.user))])

    def console(self, t, p):
        """conhost.exe que Windows lanza para un proceso de consola sin consola heredada."""
        return self.spawn(t + sec(0.004), r"C:\Windows\System32\conhost.exe",
                          r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1", p, p.user)

    # --------------------------------------------------------------- red
    def net(self, t, p, dst_ip, dport, *, bytes_out, bytes_in, dur, dst_host="-", sport=None, proto="tcp",
            log=True, rule="DMZ-OUT", action="allow"):
        """Conexión saliente de int01: Sysmon 3 (si la config la registra) y una línea en fw01."""
        sp = sport or self.rng.randint(49700, 65000)
        if log:
            self.sysmon(t, 3, 5, [
                ("RuleName", S.STR, "technique_id=T1071,technique_name=Standard Application Layer Protocol"),
                ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
                ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image), ("User", S.STR, self.user_str(p.user)),
                ("Protocol", S.STR, proto), ("Initiated", S.BOOL, True), ("SourceIsIpv6", S.BOOL, False),
                ("SourceIp", S.STR, INT01_IP), ("SourceHostname", S.STR, FQDN), ("SourcePort", S.U16, sp),
                ("SourcePortName", S.STR, "-"), ("DestinationIsIpv6", S.BOOL, False),
                ("DestinationIp", S.STR, dst_ip), ("DestinationHostname", S.STR, dst_host),
                ("DestinationPort", S.U16, dport),
                ("DestinationPortName", S.STR, {443: "https", 80: "http", 53: "domain"}.get(dport, "-"))])
        c = Conn(t, t + sec(dur), INT01_IP, sp, dst_ip, dport, proto, bytes_out, bytes_in, action, rule,
                 KB_PUBLIC, p.pid if p else 0)
        self.net_log.append(c)
        return c

    def inbound(self, t, src_ip, sport, dport, *, bytes_in, bytes_out, dur, rule, action="allow"):
        """Conexión entrante publicada en fw01 hacia int01 (Mirth no la registra en Sysmon)."""
        c = Conn(t, t + sec(dur), src_ip, sport, KB_PUBLIC if action == "deny" else INT01_IP, dport, "tcp",
                 bytes_in, bytes_out, action, rule, KB_PUBLIC)
        self.net_log.append(c)
        return c

    def http(self, t, ruta, ua):
        self.http_log.append((t, KB_PUBLIC, ruta, ua))

    def dns(self, t, p, name, ips, status="0"):
        res = "".join(f"::ffff:{ip};" for ip in ips) if ips else "-"
        self.sysmon(t, 22, 5, [
            ("RuleName", S.STR, "-"), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("QueryName", S.STR, name), ("QueryStatus", S.STR, status),
            ("QueryResults", S.STR, res), ("Image", S.STR, p.image), ("User", S.STR, self.user_str(p.user))])

    # --------------------------------------------------------------- ficheros y registro
    def fcreate(self, t, p, path, size=0, rule="-"):
        self.files[path] = (t, t, size)
        self.sysmon(t, 11, 2, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image), ("TargetFilename", S.STR, path),
            ("CreationUtcTime", S.STR, iso(t, 3)), ("User", S.STR, self.user_str(p.user))])

    def fdelete(self, t, p, path, is_exe=False, rule="-"):
        h = hashlib.sha256(path.lower().encode()).hexdigest().upper()
        self.files.pop(path, None)
        self.sysmon(t, 26, 5, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("User", S.STR, self.user_str(p.user)), ("Image", S.STR, p.image),
            ("TargetFilename", S.STR, path), ("Hashes", S.STR, f"SHA256={h}"), ("IsExecutable", S.BOOL, is_exe)])

    def fexe(self, t, p, path, rule="-"):
        md5, sha256, imp, _ = hashes(path)
        self.sysmon(t, 29, 5, [
            ("RuleName", S.STR, rule), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("User", S.STR, self.user_str(p.user)), ("Image", S.STR, p.image),
            ("TargetFilename", S.STR, path), ("Hashes", S.STR, f"MD5={md5},SHA256={sha256},IMPHASH={imp}")])

    def regset(self, t, p, target, details, rule="-"):
        self.sysmon(t, 13, 2, [
            ("RuleName", S.STR, rule), ("EventType", S.STR, "SetValue"), ("UtcTime", S.STR, iso(t, 3)),
            ("ProcessGuid", S.GUID, p.guid), ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image),
            ("TargetObject", S.STR, target), ("Details", S.STR, details), ("User", S.STR, self.user_str(p.user))])

    def image_load(self, t, p, dll, signed=True, signature="Microsoft Windows"):
        ver, desc, prod, comp, orig = IMG.get(dll.lower(), ("-", "-", "-", "-", "-"))
        md5, sha256, imp, _ = hashes(dll)
        self.sysmon(t, 7, 3, [
            ("RuleName", S.STR, "-"), ("UtcTime", S.STR, iso(t, 3)), ("ProcessGuid", S.GUID, p.guid),
            ("ProcessId", S.U32, p.pid), ("Image", S.STR, p.image), ("ImageLoaded", S.STR, dll),
            ("FileVersion", S.STR, ver), ("Description", S.STR, desc), ("Product", S.STR, prod),
            ("Company", S.STR, comp), ("OriginalFileName", S.STR, orig),
            ("Hashes", S.STR, f"MD5={md5},SHA256={sha256},IMPHASH={imp}"),
            ("Signed", S.STR, "true" if signed else "false"), ("Signature", S.STR, signature if signed else "-"),
            ("SignatureStatus", S.STR, "Valid" if signed else "Unavailable"),
            ("User", S.STR, self.user_str(p.user))])

    # --------------------------------------------------------------- servicios
    def service_install(self, t, name, display, image_path, start_type, account, ukey="system"):
        sid, uname, dom, _ = USERS[ukey]
        self.sys(t, "Service Control Manager", 7045, [
            ("ServiceName", S.STR, display), ("ImagePath", S.STR, image_path),
            ("ServiceType", S.STR, "servicio en modo usuario"), ("StartType", S.STR, start_type),
            ("AccountName", S.STR, account)], guid=GUIDS["Service Control Manager"],
            esn="Service Control Manager", qual=16384, kw=0x8080000000000000,
            pid=self.procs_at(t)["services"].pid if "services" in self.procs_at(t) else None, user=sid)
        self.sec(t, 4697, 12289, [
            ("SubjectUserSid", S.SID, sid), ("SubjectUserName", S.STR, HOST + "$" if ukey == "system" else uname),
            ("SubjectDomainName", S.STR, DOMAIN if ukey == "system" else dom),
            ("SubjectLogonId", S.HEX64, self.logon_id(ukey)), ("ServiceName", S.STR, name),
            ("ServiceFileName", S.STR, image_path), ("ServiceType", S.HEX32, 0x10),
            ("ServiceStartType", S.U32, 2 if start_type == "auto start" else 3), ("ServiceAccount", S.STR, account)])

    # --------------------------------------------------------------- PowerShell
    def ps_session(self, t, p, script_text, path=""):
        """Arranque del motor (400/600/40961/40962/53504) y el primer bloque (4104) de una sesión."""
        r = self.rng
        host_id, runspace = str(uuid.UUID(int=r.getrandbits(128))), str(uuid.UUID(int=r.getrandbits(128)))
        act = "{" + str(uuid.UUID(int=r.getrandbits(128))).upper() + "}"
        sid = USERS[p.user][0]
        seq0 = self.ps_seq

        def detail(extra, seq):
            return (f"\t{extra}\r\n\r\n\tSequenceNumber={seq}\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion={PS_VER}\r\n"
                    f"\tHostId={host_id}\r\n\tHostApplication={p.cmd}\r\n\tEngineVersion={PS_VER}\r\n"
                    f"\tRunspaceId={runspace}\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n"
                    f"\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=")
        psg = GUIDS["Microsoft-Windows-PowerShell"]
        self.sys(t + sec(0.05), "Microsoft-Windows-PowerShell", 40961, [], ch="PSOp", guid=psg, ver=1, task=4,
                 opcode=1, kw=0x0, pid=p.pid, user=sid, activity=act)
        for i, prov in enumerate(("Registry", "Alias", "Environment", "FileSystem", "Function", "Variable")):
            self.sys(t + sec(0.30 + i * 0.002), "PowerShell", 600, [
                (None, S.STR, prov), (None, S.STR, "Started"),
                (None, S.STR, detail(f"ProviderName={prov}\r\n\tNewProviderState=Started", seq0 + i))],
                ch="PS", esn="PowerShell", qual=0, task=6, kw=0x80000000000000, pid=0)
        self.sys(t + sec(0.33), "PowerShell", 400, [
            (None, S.STR, "Available"), (None, S.STR, "None"),
            (None, S.STR, detail("NewEngineState=Available\r\n\tPreviousEngineState=None", seq0 + 6))],
            ch="PS", esn="PowerShell", qual=0, task=4, kw=0x80000000000000, pid=0)
        self.sys(t + sec(0.36), "Microsoft-Windows-PowerShell", 53504,
                 [("param1", S.STR, str(p.pid)), ("param2", S.STR, "DefaultAppDomain")], ch="PSOp", guid=psg,
                 ver=1, task=111, opcode=10, kw=0x0, pid=p.pid, user=sid, activity=act)
        self.sys(t + sec(0.41), "Microsoft-Windows-PowerShell", 40962, [], ch="PSOp", guid=psg, ver=1, task=4,
                 opcode=2, kw=0x0, pid=p.pid, user=sid, activity=act)
        self.ps_seq = seq0 + 8
        self.ps_block(t + sec(0.52), p, script_text, path, act)
        return act

    def ps_block(self, t, p, text, path="", activity=None):
        """4104 de un bloque de script, partido en mensajes de SB_CHUNK caracteres si hace falta."""
        sid = USERS[p.user][0]
        sbid = str(uuid.UUID(int=self.rng.getrandbits(128)))
        parts = [text[i:i + SB_CHUNK] for i in range(0, len(text), SB_CHUNK)] or [""]
        for n, part in enumerate(parts, 1):
            self.sys(t + sec(0.0004 * n), "Microsoft-Windows-PowerShell", 4104, [
                ("MessageNumber", S.U32, n), ("MessageTotal", S.U32, len(parts)), ("ScriptBlockText", S.STR, part),
                ("ScriptBlockId", S.STR, sbid), ("Path", S.STR, path)], ch="PSOp",
                guid=GUIDS["Microsoft-Windows-PowerShell"], ver=1, level=5 if len(parts) == 1 else 3, task=2,
                opcode=15, kw=0x0, pid=p.pid, user=sid, activity=activity)

    def ps_end(self, t, p):
        """403: el motor se detiene al salir del proceso."""
        self.sys(t, "PowerShell", 403, [(None, S.STR, "Stopped"), (None, S.STR, "Available"),
                                        (None, S.STR, f"\tNewEngineState=Stopped\r\n\tPreviousEngineState=Available\r\n\r\n"
                                                      f"\tSequenceNumber={self.ps_seq}\r\n\r\n\tHostApplication={p.cmd}")],
                 ch="PS", esn="PowerShell", qual=0, task=4, kw=0x80000000000000, pid=0)
        self.ps_seq += 1
        self.exit(p, t + sec(0.02))

    def addtype_compile(self, t, ps, fails):
        """Add-Type en Windows PowerShell 5.1: CodeDom escribe el .cs y el .cmdline y lanza csc.exe.

        Si el C# no compila (bug del here-string), csc.exe no llega a cvtres.exe ni genera la DLL.
        """
        base = r"C:\Windows\TEMP" + "\\" + self.rand_name()
        cs, cmdline, out, err = base + ".0.cs", base + ".cmdline", base + ".out", base + ".err"
        self.fcreate(t, ps, cs, 412)
        self.fcreate(t + sec(0.002), ps, cmdline, 680)
        csc = self.spawn(t + sec(0.006), CSC, f'"{CSC}" /noconfig /fullpaths @"{cmdline}"', ps, ps.user,
                         cwd=r"C:\Windows\system32" + "\\")
        self.console(t + sec(0.006), csc)
        dur = 0.41 if fails else 0.63
        if not fails:
            dll = base + ".dll"
            res, cvt = r"C:\Windows\TEMP\RES" + self.rand_name(4).upper() + ".tmp", \
                       r"c:\Windows\Temp\CSC" + self.rand_name(32).upper() + ".TMP"
            cv = self.spawn(t + sec(0.41), CVTRES,
                            f'{CVTRES} /NOLOGO /READONLY /MACHINE:IX86 "/OUT:{res}" "{cvt}"', csc, ps.user)
            self.exit(cv, t + sec(0.47))
            self.fcreate(t + sec(0.58), csc, dll, 3584)
        self.fcreate(t + sec(dur - 0.01), ps, out, 0 if not fails else 1536)
        self.fcreate(t + sec(dur - 0.01), ps, err, 0)
        self.exit(csc, t + sec(dur))
        for i, f in enumerate((cs, cmdline, out, err)):
            self.fdelete(t + sec(dur + 0.01 + i * 0.001), ps, f)
        return dur
