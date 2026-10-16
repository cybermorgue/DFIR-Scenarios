"""Constantes del escenario 04: activos, cuentas, instantes clave y metadatos de imagen.

Las muestras reales (OneDrive.exe, client64.exe y winpty) toman sus hashes de
fuentes/hashes_muestras.json; el resto de imágenes llevan hashes estables derivados de su ruta.
"""
import hashlib
import json
import os

from .winfmt import T, FT

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUENTES = os.path.join(BASE, "fuentes")

# ----------------------------------------------------------------------- red y equipos
HOST = "INT01"
DOMAIN = "KELBROOK"
FQDN = "int01.kelbrook.internal"
INT01_IP = "10.20.30.30"
DC_IP = "10.20.30.3"
DNS_IP = "10.20.30.2"
FW_IP = "10.20.30.1"
IDS_IP = "10.20.30.250"
KB_PUBLIC = "192.0.2.25"
OP_IP = "104.234.26.225"
ARDEAL_IP = "198.51.100.140"
CERT_IP = "203.0.113.77"
JTORRES_WS_IP = "10.20.30.55"
BUCKET_HOST = "kb7f3-hk-sync-0926.oss-cn-hongkong.aliyuncs.com"
BUCKET_IP = "203.0.113.180"

# ----------------------------------------------------------------------- tiempo (UTC)
T0 = T(4, 18, 53, 40.126109)            # primera línea real de la víctima en el access.log
REBOOT_T = T(13, 8, 31, 0.0)            # reinicio manual de adm.jtorres
CERT_T = T(19, 7, 10, 0.0)              # aviso del CERT (09:10 hora local)
TRIAGE_T = T(19, 11, 20, 0.0)           # recogida con KAPE
START_T = FT(2026, 9, 1)                # inicio de la ventana simulada

OS_BUILD = "17763.6054"
PS_VER = "5.1.17763.6054"
PS_UA = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.6054"

# ----------------------------------------------------------------------- cuentas
DOMAIN_SID = "S-1-5-21-3021476520-1873542967-2461890375"
JTORRES_SID = DOMAIN_SID + "-1115"
USERS = {
    "system":  ("S-1-5-18", "SYSTEM", "NT AUTHORITY", 0x3E7),
    "local":   ("S-1-5-19", "LOCAL SERVICE", "NT AUTHORITY", 0x3E5),
    "network": ("S-1-5-20", "NETWORK SERVICE", "NT AUTHORITY", 0x3E4),
    "jtorres": (JTORRES_SID, "adm.jtorres", DOMAIN, None),
}

# ----------------------------------------------------------------------- rutas clave
MIRTH_DIR = r"C:\Program Files\Mirth Connect"
MCSERVICE = MIRTH_DIR + r"\mcservice.exe"
ONEDRIVE = r"C:\ProgramData\Microsoft\OneDrive\OneDrive.exe"
ONESYNC = r"C:\ProgramData\Microsoft\OneDrive\Sync\OneSyncHost.exe"
WINPTY_DIR = r"C:\Windows\Temp\winpty-0.4.3-a1f37c2e"
WINPTY_AGENT = WINPTY_DIR + r"\winpty-agent.exe"
WINPTY_DLL = WINPTY_DIR + r"\winpty.dll"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
CVTRES = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe"
CMD = r"C:\Windows\System32\cmd.exe"

# ----------------------------------------------------------------------- metadatos de imagen
# (FileVersion, Description, Product, Company, OriginalFileName)
MS = "Microsoft Corporation"
WINP = "Microsoft® Windows® Operating System"
WV = "10.0.17763.6054 (WinBuild.160101.0800)"
IMG = {}


def _img(path, desc, orig, product=WINP, company=MS, ver=WV):
    IMG[path.lower()] = (ver, desc, product, company, orig)


for _p, _d, _o in [
    (r"C:\Windows\System32\smss.exe", "Windows Session Manager", "smss.exe"),
    (r"C:\Windows\System32\csrss.exe", "Client Server Runtime Process", "CSRSS.Exe"),
    (r"C:\Windows\System32\wininit.exe", "Windows Start-Up Application", "WinInit.exe"),
    (r"C:\Windows\System32\winlogon.exe", "Windows Logon Application", "WINLOGON.EXE"),
    (r"C:\Windows\System32\services.exe", "Services and Controller app", "services.exe"),
    (r"C:\Windows\System32\lsass.exe", "Local Security Authority Process", "lsass.exe"),
    (r"C:\Windows\System32\svchost.exe", "Host Process for Windows Services", "svchost.exe"),
    (r"C:\Windows\System32\LogonUI.exe", "Windows Logon User Interface Host", "logonui.exe"),
    (r"C:\Windows\System32\dwm.exe", "Desktop Window Manager", "dwm.exe"),
    (r"C:\Windows\System32\rdpclip.exe", "RDP Clipboard Monitor", "rdpclip.exe"),
    (r"C:\Windows\System32\userinit.exe", "Userinit Logon Application", "USERINIT.EXE"),
    (r"C:\Windows\explorer.exe", "Windows Explorer", "EXPLORER.EXE"),
    (r"C:\Windows\System32\taskhostw.exe", "Host Process for Windows Tasks", "taskhostw.exe"),
    (r"C:\Windows\System32\conhost.exe", "Console Window Host", "CONHOST.EXE"),
    (CMD, "Windows Command Processor", "Cmd.Exe"),
    (r"C:\Windows\System32\whoami.exe", "whoami - displays logged on user information", "whoami.exe"),
    (r"C:\Windows\System32\HOSTNAME.EXE", "Hostname APP", "hostname.exe"),
    (r"C:\Windows\System32\ipconfig.exe", "IP Configuration Utility", "ipconfig.exe"),
    (r"C:\Windows\System32\systeminfo.exe", "Displays system information", "sysinfo.exe"),
    (r"C:\Windows\System32\quser.exe", "Query User Utility", "quser.exe"),
    (r"C:\Windows\System32\tasklist.exe", "Lists the current running tasks", "tasklist.exe"),
    (r"C:\Windows\System32\NETSTAT.EXE", "TCP/IP Netstat Command", "netstat.exe"),
    (r"C:\Windows\System32\net.exe", "Net Command", "net.exe"),
    (r"C:\Windows\System32\net1.exe", "Net Command", "net1.exe"),
    (r"C:\Windows\System32\nltest.exe", "Microsoft® Logon Server Test Utility", "nltestrk.exe"),
    (r"C:\Windows\System32\tar.exe", "bsdtar archive tool", "bsdtar"),
    (r"C:\Windows\System32\curl.exe", "The curl executable", "curl.exe"),
    (r"C:\Windows\System32\shutdown.exe", "Windows Shutdown and Annotation Tool", "shutdown.exe"),
    (r"C:\Windows\System32\wbem\WmiPrvSE.exe", "WMI Provider Host", "Wmiprvse.exe"),
    (r"C:\Windows\System32\CompatTelRunner.exe", "Microsoft Compatibility Telemetry", "CompatTelRunner.exe"),
    (r"C:\Windows\System32\sppsvc.exe", "Microsoft Software Protection Platform Service", "sppsvc.exe"),
    (r"C:\Windows\System32\mstsc.exe", "Remote Desktop Connection", "mstsc.exe"),
    (POWERSHELL, "Windows PowerShell", "PowerShell.EXE"),
]:
    _img(_p, _d, _o)
_img(CSC, "Visual C# Command Line Compiler", "csc.exe", "Microsoft® .NET Framework",
     ver="4.8.3761.0 built by: NET48REL1")
_img(CVTRES, "Microsoft® Resource File To COFF Object Conversion Utility", "CVTRES.EXE",
     "Microsoft® .NET Framework", ver="14.10.25028.0 built by: VCTOOLSD15RTM")
_img(r"C:\Windows\System32\mscoree.dll", ".NET Runtime Execution Engine", "mscoree.dll", ver="10.0.17763.6054 (WinBuild.160101.0800)")
_img(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll", "Microsoft .NET Runtime Common Language Runtime - WorkStation",
     "clr.dll", "Microsoft® .NET Framework", ver="4.8.3761.0 built by: NET48REL1")
_img(r"C:\Windows\Sysmon64.exe", "System activity monitor", "Sysmon.exe", "Sysinternals Sysmon",
     "Sysinternals - www.sysinternals.com", "15.15")
_DEF = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0"
_img(_DEF + r"\MsMpEng.exe", "Antimalware Service Executable", "MsMpEng.exe",
     ver="4.18.25090.3009 (a62c7e3d1e2f4f87fa5b3e8a7f0c3d1b9e5a2f40)")
_img(_DEF + r"\MpCmdRun.exe", "Microsoft Malware Protection Command Line Utility", "MpCmdRun.exe",
     ver="4.18.25090.3009 (a62c7e3d1e2f4f87fa5b3e8a7f0c3d1b9e5a2f40)")
_img(MCSERVICE, "Mirth Connect Service", "mcservice.exe", "Mirth Connect", "NextGen Healthcare", "4.4.0.3221")
_img(MIRTH_DIR + r"\mcmanager.exe", "Mirth Connect Server Manager", "mcmanager.exe", "Mirth Connect",
     "NextGen Healthcare", "4.4.0.3221")
_img(r"C:\Program Files\Mirth Connect Administrator Launcher\launcher.exe", "Mirth Connect Administrator Launcher",
     "launcher.exe", "Mirth Connect Administrator Launcher", "NextGen Healthcare", "1.4.2.0")
_img(r"C:\Program Files\Mirth Connect Administrator Launcher\jre\bin\javaw.exe", "OpenJDK Platform binary",
     "javaw.exe", "OpenJDK Platform 17.0.8", "Eclipse Adoptium", "17.0.8.0")
# Muestras del atacante: metadatos reales (ldr_win3.exe sin empresa ni descripción; client64 sin recurso de versión)
IMG[ONEDRIVE.lower()] = ("0.0.0.0", "-", "-", "-", "ldr_win3.exe")
IMG[ONESYNC.lower()] = ("-", "-", "-", "-", "-")
IMG[WINPTY_AGENT.lower()] = ("-", "-", "-", "-", "-")
IMG[WINPTY_DLL.lower()] = ("-", "-", "-", "-", "-")

# ----------------------------------------------------------------------- hashes
with open(os.path.join(FUENTES, "hashes_muestras.json"), encoding="utf-8") as _f:
    MUESTRAS = json.load(_f)
_REAL = {ONEDRIVE.lower(): "OneDrive.exe", ONESYNC.lower(): "client64.exe",
         WINPTY_AGENT.lower(): "winpty-agent.exe", WINPTY_DLL.lower(): "winpty.dll"}


def sample(path):
    """Ficha real de la muestra para esa ruta, o None si no es una muestra."""
    k = _REAL.get(path.lower())
    return MUESTRAS[k] if k else None


def hashes(path):
    """(MD5, SHA256, IMPHASH) en mayúsculas como Sysmon y SHA1 en minúsculas como Amcache."""
    s = sample(path)
    if s:
        return s["md5"].upper(), s["sha256"].upper(), s.get("imphash", "0" * 32).upper(), s["sha1"]
    seed = path.lower().encode()
    return (hashlib.md5(seed + b"md5").hexdigest().upper(), hashlib.sha256(seed + b"sha").hexdigest().upper(),
            hashlib.md5(seed + b"imp").hexdigest().upper(), hashlib.sha1(seed + b"sha1").hexdigest())

for _p, _d, _o, _prod, _comp, _v in [
    (r"C:\Windows\System32\Robocopy.exe", "Microsoft Robocopy", "robocopy.exe", WINP, MS, WV),
    (r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe", "VMware Tools Core Service", "vmtoolsd.exe",
     "VMware Tools", "VMware, Inc.", "12.3.5.46049"),
]:
    _img(_p, _d, _o, _prod, _comp, _v)

NAS_IP = "10.20.30.40"
MS_UPDATE_IP = "203.0.113.10"       # CDN de firmas de Defender (IP de documentación)
HOLIDAYS = {(10, 12)}               # Fiesta Nacional de España
