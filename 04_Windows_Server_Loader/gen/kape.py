"""Paquete de triage tal y como lo deja KAPE: ZIP con ConsoleLog, CopyLog y el árbol de ficheros copiados."""
import hashlib
import io
import struct
import zipfile

from .const import FQDN, HOST, TRIAGE_T
from .winfmt import FT, TICKS, ft2dt, ft2unix, sec, write_evtx

ROOT = HOST + "/"
TDEST = r"E:\triage" + "\\" + HOST
KAPE_END = TRIAGE_T + sec(171.4)
LOG_CUT = TRIAGE_T + sec(45.0)               # los EVTX se copian después y llegan hasta aquí
WINEVT = "C/Windows/System32/winevt/Logs/"
EVTX_FILES = {"Security": "Security.evtx", "System": "System.evtx", "Application": "Application.evtx",
              "Sysmon": "Microsoft-Windows-Sysmon%4Operational.evtx",
              "PSOp": "Microsoft-Windows-PowerShell%4Operational.evtx", "PS": "Windows PowerShell.evtx",
              "Defender": "Microsoft-Windows-Windows Defender%4Operational.evtx"}
INSTALL = FT(2023, 11, 14, 10, 22, 31.0)
TARGETS = [("EventLogs", "5b4f6a2c-91d3-4e87-a0c6-3f7d28e1b9a4", r"Windows\EventLogs"),
           ("RegistryHives", "c3a91e57-2b6f-4d08-8e41-7a5d90f2c6b3", r"Windows\RegistryHives"),
           ("Amcache", "e8d27b04-6a1c-4f93-b5e0-1c4a8d3f7926", r"Windows\Amcache"),
           ("Prefetch", "0f6c3e9b-d472-4a15-9b87-52e1a6c4d830", r"Windows\Prefetch"),
           ("MirthConnect", "7a19c5d3-8e20-4b6f-a3d1-94f0b2e7c658", r"Custom\MirthConnect")]


def is_dst(ft):
    return FT(2026, 3, 29, 1) <= ft < FT(2026, 10, 25, 1)


def ntfs_extra(mtime, atime, ctime):
    return struct.pack("<HHIHHQQQ", 0x000A, 32, 0, 1, 24, mtime, atime, ctime)


def evtx_files(sim):
    """EVTX de los siete canales cortados en LOG_CUT -> {ruta_en_zip: (bytes, creado, modificado)}."""
    out = {}
    for ch, fname in EVTX_FILES.items():
        evs = sorted((e for e in sim.ev[ch] if e.ft <= LOG_CUT), key=lambda e: e.ft)
        data, _, _ = write_evtx(evs, FQDN, 1)
        out[WINEVT + fname] = (data, INSTALL + sec(600), evs[-1].ft if evs else INSTALL + sec(600))
    return out


def _fmt(ft):
    return ft2dt(ft).strftime("%Y-%m-%d %H:%M:%S.") + f"{ft % TICKS:07d}"


def kape_zip(sim, files, deferred_at=None):
    """files: {ruta_en_zip: (bytes, creado, modificado)}. Las rutas de deferred_at (ruta -> hora de copia) son
    ficheros bloqueados que KAPE copia al final; el resto se copia seguido. El ZIP lleva las horas locales de Madrid."""
    deferred_at = deferred_at or {}
    items, prev = [], None
    for p in sorted((p for p in files if p not in deferred_at), key=str.lower):
        d, c, m = files[p]
        ct = (TRIAGE_T + sec(2.0)) if prev is None else prev + sec(0.004 + len(d) / 4e7)
        prev = ct
        items.append((p, d, c, m, ct, False))
    for p in sorted(deferred_at, key=lambda p: deferred_at[p]):
        d, c, m = files[p]
        items.append((p, d, c, m, deferred_at[p], True))
    csv = ["CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration"]
    defer, copied = [], []
    for p, d, c, m, ct, df in items:
        src = "C:\\" + p[2:].replace("/", "\\")
        dest = TDEST + "\\" + p.replace("/", "\\")
        csv.append(f'{_fmt(ct)},{src},{dest},{len(d)},{hashlib.sha1(d).hexdigest().upper()},{df},{_fmt(c)},{_fmt(m)},'
                   f'{_fmt(ct)},00:00:00.{str(int(len(d) / 9e5 * 1e7 + 12000)).zfill(7)}')
        if df:
            defer.append(f"Deferring '{src}' due to IOException...")
            copied.append(f"Copied deferred file '{src}' to '{dest}'. Hashing source file...")
    console = "\r\n".join(
        ["KAPE version 1.3.0.2, Author: Eric Zimmerman, Contact: https://www.kroll.com/kape (kape@kroll.com)", "",
         r"KAPE directory: E:\KAPE",
         r"Command line:   --tsource C: --tdest E:\triage\INT01 --target EventLogs,RegistryHives,Amcache,Prefetch,MirthConnect", "",
         "System info: Machine name: INT01, 64-bit: True, User: adm.jtorres OS: Windows10 (10.0.17763)", "",
         "Using Target operations", r"Creating target destination directory 'E:\triage\INT01'",
         f"Found {len(TARGETS)} targets. Expanding targets to file list..."]
        + [f"Target '{n}' with Id '{g}' found in 'E:\\KAPE\\Targets\\{rel}.tkape'" for n, g, rel in TARGETS]
        + [f"Found {len(items)} files in 1.402 seconds. Beginning copy..."]
        + ["  " + x for x in defer] + [f"Deferred file count: {len(defer)}. Copying locked files..."]
        + ["  " + x for x in copied]
        + [f"Copied {len(items)} (Deduplicated: 0 (0 B)) out of {len(items)} files in {(KAPE_END - TRIAGE_T) / TICKS:.4f} seconds. "
           "See '*_CopyLog.csv' in the VHDX, VHD, Zip, or target destination directory for complete copy details", "",
           f"Total execution time: {(KAPE_END - TRIAGE_T) / TICKS + 0.31:.4f} seconds", ""])
    stamp = ft2dt(TRIAGE_T).strftime("%Y-%m-%dT%H%M%S")
    entries = {}
    for p, d, c, m, ct, _ in items:
        rel = ROOT + p
        entries[rel] = (d, c, m, ct)
        parts = rel.split("/")
        for i in range(1, len(parts)):
            dp = "/".join(parts[:i]) + "/"
            prev_e = entries.get(dp)
            entries[dp] = (None, TRIAGE_T + sec(1.9), max(ct, prev_e[2]) if prev_e else ct, KAPE_END)
    entries[ROOT + "C/Windows/Prefetch/"] = (None, TRIAGE_T + sec(1.9), TRIAGE_T + sec(2.0), KAPE_END)
    entries[ROOT + f"{stamp}_ConsoleLog.txt"] = (console.encode("utf-8"), TRIAGE_T, KAPE_END, KAPE_END)
    entries[ROOT + f"{stamp}_CopyLog.csv"] = (("\r\n".join(csv) + "\r\n").encode("utf-8"), KAPE_END,
                                              KAPE_END + sec(0.2), KAPE_END + sec(0.2))
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for rel in sorted(entries, key=str.lower):
            d, c, m, a = entries[rel]
            local = ft2dt(m + (sec(7200) if is_dst(m) else sec(3600)))
            zi = zipfile.ZipInfo(rel, date_time=local.timetuple()[:6])
            zi.create_system = 0
            zi.extra = ntfs_extra(m, a, c) + struct.pack("<HHBI", 0x5455, 5, 1, int(ft2unix(m)))
            if d is None:
                zi.external_attr = 0x10
                z.writestr(zi, b"")
            else:
                zi.external_attr = 0x20
                zi.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(zi, d)
    return bio.getvalue()
