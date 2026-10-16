"""Colmenas de int01 tal y como las copia KAPE el 19/10: SYSTEM, SOFTWARE y Amcache."""
import hashlib
import struct
import zlib

from .const import (HOST, IMG, MCSERVICE, MIRTH_DIR, ONESYNC, REBOOT_T, TRIAGE_T, hashes, sample)
from .winfmt import (FT, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ, RegKey, T,
                     ft2dt, ft2unix, reg_sd, sec, write_hive)

INSTALL = FT(2023, 11, 14, 10, 22, 31.0)          # instalación de Server 2019 en la VM
SERVICE_T = T(4, 19, 19, 5.0)                      # alta del servicio OneSyncHost
UBR_DATE = FT(2024, 7, 9, 17, 0, 0.0)              # última actualización instalada (julio de 2024)
SD_MACHINE = reg_sd("S-1-5-32-544", "S-1-5-18", [("S-1-5-18", 0xF003F, 3), ("S-1-5-32-544", 0xF003F, 3),
                                                  ("S-1-5-32-545", 0x20019, 3), ("S-1-15-2-1", 0x20019, 3)])
# la copia de cada colmena se hace durante el triage (el 19/10 entre las 11:20 y las 11:30)
HIVE_COPY = {"SYSTEM": TRIAGE_T + sec(95.4), "SOFTWARE": TRIAGE_T + sec(105.2), "Amcache": TRIAGE_T + sec(120.6)}


def failure_actions(reset=86400, restarts=3, delay_ms=60000):
    """SERVICE_FAILURE_ACTIONS tal y como queda en el registro: reinicio del servicio tras 60 s, tres veces."""
    out = struct.pack("<IIIII", reset, 0, 0, restarts, 20)
    return out + b"".join(struct.pack("<II", 1, delay_ms) for _ in range(restarts))


def shimcache(entries):
    """AppCompatCache de Windows 10/Server 2019 (cabecera 0x34, entradas '10ts')."""
    out = bytearray(struct.pack("<I", 0x34) + b"\0" * 0x30)
    for path, mtime in entries:
        p = path.encode("utf-16-le")
        body = struct.pack("<H", len(p)) + p + struct.pack("<QI", mtime, 0)
        out += b"10ts" + struct.pack("<II", zlib.crc32(p) & 0xFFFFFFFF, len(body)) + body
    return bytes(out)


def _mtime(sim, img):
    """Fecha de modificación del fichero: la real si el ataque lo creó; si no, la del parche de julio de 2024."""
    for path, (_, mt, _) in sim.files.items():
        if path.lower() == img:
            return mt
    return UBR_DATE if img.startswith("c:\\windows") else INSTALL + sec(3600)


def build_system(sim):
    root = RegKey("CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}", INSTALL)
    root.key("Select", INSTALL).set("Current", REG_DWORD, 1).set("Default", REG_DWORD, 1) \
        .set("Failed", REG_DWORD, 0).set("LastKnownGood", REG_DWORD, 1)
    cs = root.key("ControlSet001", INSTALL)
    cs.key(r"Control\ComputerName\ComputerName", INSTALL + sec(600)).set("ComputerName", REG_SZ, HOST)
    tz = cs.key(r"Control\TimeZoneInformation", INSTALL + sec(300))
    tz.set("Bias", REG_DWORD, 0).set("TimeZoneKeyName", REG_SZ, "UTC").set("ActiveTimeBias", REG_DWORD, 0)
    # ShimCache: se persiste al apagar, así que refleja hasta el reinicio del 13/10 (OneDrive.exe sí está)
    cs.key(r"Control\Windows", REBOOT_T).set("ShutdownTime", REG_BINARY, struct.pack("<Q", REBOOT_T + sec(21.0)))
    seen = {}
    for img, runs in sim.execs.items():
        before = [t for t, _ in runs if t < REBOOT_T]
        if before:
            seen[img] = max(before)
    order = sorted(seen.items(), key=lambda x: -x[1])[:96]
    entries = [(sim.execs[i][0][1].image, _mtime(sim, i)) for i, _ in order]
    cs.key(r"Control\Session Manager\AppCompatCache", REBOOT_T + sec(21.0)) \
        .set("AppCompatCache", REG_BINARY, shimcache(entries))
    svc = cs.key("Services", INSTALL)
    svc.key("Mirth Connect Service", INSTALL + sec(5400)).set("Type", REG_DWORD, 0x10).set("Start", REG_DWORD, 2) \
        .set("ErrorControl", REG_DWORD, 1).set("ImagePath", REG_EXPAND_SZ, f'"{MCSERVICE}"') \
        .set("DisplayName", REG_SZ, "Mirth Connect Service").set("ObjectName", REG_SZ, "LocalSystem")
    svc.key("Sysmon64", FT(2025, 1, 20, 9, 5, 12.0)).set("Type", REG_DWORD, 0x10).set("Start", REG_DWORD, 2) \
        .set("ErrorControl", REG_DWORD, 1).set("ImagePath", REG_EXPAND_SZ, r"C:\Windows\Sysmon64.exe") \
        .set("DisplayName", REG_SZ, "Sysmon64").set("ObjectName", REG_SZ, "LocalSystem")
    svc.key("OneSyncHost", SERVICE_T).set("Type", REG_DWORD, 0x10).set("Start", REG_DWORD, 2) \
        .set("ErrorControl", REG_DWORD, 1).set("ImagePath", REG_EXPAND_SZ, ONESYNC) \
        .set("DisplayName", REG_SZ, "OneDrive Sync Host").set("ObjectName", REG_SZ, "LocalSystem") \
        .set("FailureActions", REG_BINARY, failure_actions())
    return write_hive(root, "SYSTEM", SD_MACHINE, seq=4123)


def build_software(sim):
    root = RegKey("CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}", INSTALL)
    cv = root.key(r"Microsoft\Windows NT\CurrentVersion", UBR_DATE)
    for k, v in (("ProductName", "Windows Server 2019 Standard"), ("EditionID", "ServerStandard"),
                 ("InstallationType", "Server"), ("CurrentBuild", "17763"), ("CurrentBuildNumber", "17763"),
                 ("CurrentVersion", "6.3"), ("ReleaseId", "1809"), ("SystemRoot", r"C:\Windows"),
                 ("RegisteredOwner", "Kelbrook Medical"), ("BuildLab", "17763.rs5_release.180914-1434")):
        cv.set(k, REG_SZ, v)
    cv.set("UBR", REG_DWORD, 6054).set("CurrentMajorVersionNumber", REG_DWORD, 10) \
        .set("CurrentMinorVersionNumber", REG_DWORD, 0)
    cv.set("InstallDate", REG_DWORD, int(ft2unix(INSTALL))).set("InstallTime", REG_QWORD, INSTALL)
    un = root.key(r"Microsoft\Windows\CurrentVersion\Uninstall", INSTALL)
    un.key("Mirth Connect_is1", INSTALL + sec(5400)).set("DisplayName", REG_SZ, "Mirth Connect") \
        .set("DisplayVersion", REG_SZ, "4.4.0").set("Publisher", REG_SZ, "NextGen Healthcare") \
        .set("InstallLocation", REG_SZ, MIRTH_DIR + "\\")
    root.key(r"Microsoft\Windows Defender\Exclusions\Paths", INSTALL + sec(5500)).set(MIRTH_DIR + "\\", REG_DWORD, 0)
    wu = root.key(r"Policies\Microsoft\Windows\WindowsUpdate", INSTALL + sec(900))
    wu.set("WUServer", REG_SZ, "http://wsus01.kelbrook.internal:8530") \
        .set("WUStatusServer", REG_SZ, "http://wsus01.kelbrook.internal:8530")
    wu.key("AU", INSTALL + sec(900)).set("UseWUServer", REG_DWORD, 1).set("NoAutoUpdate", REG_DWORD, 0)
    root.key(r"Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", INSTALL + sec(2600)) \
        .set("EnableScriptBlockLogging", REG_DWORD, 1)
    return write_hive(root, r"\SystemRoot\System32\Config\SOFTWARE", SD_MACHINE, seq=8817)


def _link_date(path, s):
    if s is not None and s.get("timestamp"):
        return ft2dt(FT(1970, 1, 1) + int(s["timestamp"]) * 10_000_000).strftime("%m/%d/%Y %H:%M:%S")
    if s is not None:
        return "01/01/1970 00:00:00"
    return ft2dt(UBR_DATE - sec(86400 * 30)).strftime("%m/%d/%Y %H:%M:%S")


def build_amcache(sim):
    cutoff = HIVE_COPY["Amcache"]
    root = RegKey("{11517B7C-E79D-4e20-961B-75A811715ADD}", INSTALL)
    r = root.key("Root", INSTALL)
    iaf = r.key("InventoryApplicationFile", cutoff)
    for img, runs in sorted(sim.execs.items()):
        ts = [t for t, _ in runs if t <= cutoff]
        if not ts:
            continue
        real = runs[0][1].image
        name = real.rsplit("\\", 1)[1]
        md5, sha256, imp, sha1 = hashes(real)
        s = sample(real)
        ver, desc, prod, comp, orig = IMG.get(img, ("", "", "", "", name))
        lph = hashlib.md5(img.encode()).hexdigest()[:16]
        k = iaf.key(f"{name.lower()}|{lph}", min(ts) + sec(1.7))
        is_os = img.startswith(r"c:\windows")
        size = s["size"] if s else int(sha1[:5], 16) * 4 + 40960
        v = ver.split(" ")[0] if ver not in ("-", "") else ""
        k.set("ProgramId", REG_SZ, "0000f519feec486de87ed73cb92d3cac802400000000" if is_os
              else "0006" + hashlib.sha1(prod.encode()).hexdigest()[:36] + "0000ffff")
        k.set("FileId", REG_SZ, "0000" + sha1).set("LowerCaseLongPath", REG_SZ, img)
        k.set("LongPathHash", REG_SZ, f"{name.lower()}|{lph}").set("Name", REG_SZ, name)
        k.set("OriginalFileName", REG_SZ, "" if orig == "-" else orig.lower())
        k.set("Publisher", REG_SZ, "" if comp in ("-", "") else comp.lower()).set("Version", REG_SZ, v)
        k.set("BinFileVersion", REG_SZ, v).set("BinaryType", REG_SZ, "pe64_amd64")
        k.set("ProductName", REG_SZ, "" if prod == "-" else prod.lower()).set("ProductVersion", REG_SZ, v)
        k.set("LinkDate", REG_SZ, _link_date(real, s)).set("Size", REG_QWORD, size)
        k.set("Usn", REG_QWORD, 0x1A2B0000 + int(sha1[:6], 16)).set("IsOsComponent", REG_DWORD, 1 if is_os else 0)
    return write_hive(root, r"\??\C:\Windows\AppCompat\Programs\Amcache.hve", SD_MACHINE, seq=2210)
