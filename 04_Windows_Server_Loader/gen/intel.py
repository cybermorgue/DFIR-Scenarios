"""Material de inteligencia: access.log del operador, listado del open directory, ficha de muestras y aviso del CERT."""
import os
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone

from .const import CERT_IP, FUENTES, KB_PUBLIC, MUESTRAS, OP_IP
from .winfmt import ft2dt


def _iso6(ft):
    return ft2dt(ft).strftime("%Y-%m-%dT%H:%M:%S.%f")


def access_log(sim):
    """access.log real saneado más las peticiones propias del escenario (la descarga de client64.exe)."""
    with open(os.path.join(FUENTES, "access_real_saneado.log"), encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f if l.strip()]
    lines += [f"{_iso6(t)} | GET | {ip} {ruta} | UA={ua}" for t, ip, ruta, ua in sim.http_log]
    lines.sort(key=lambda l: l[:26])
    return "\n".join(lines) + "\n"


# (nombre, bytes, última modificación). Tamaños reales de las muestras; el resto es verosímil.
_DIR = [("access.log", None, "2026-10-16 08:37"), ("bootstrap_enc.txt", 41216, "2026-10-02 21:05"),
        ("client64.exe", MUESTRAS["client64.exe"]["size"], "2026-10-03 22:40"),
        ("OneDrive.exe", MUESTRAS["OneDrive.exe"]["size"], "2026-10-04 14:22"),
        ("run.ps1", MUESTRAS["run.ps1"]["size"], "2026-10-04 18:40"),
        ("run2.ps1", MUESTRAS["run2.ps1"]["size"], "2026-10-04 18:56"), ("server.py", 6184, "2026-10-02 20:48")]


def index_html():
    """Listado al estilo de `python -m http.server`; el tamaño y la fecha van en el atributo title de cada enlace."""
    li = []
    for name, size, mt in _DIR:
        if size is None:
            size = os.path.getsize(os.path.join(FUENTES, "access_real_saneado.log"))
        li.append(f'<li><a href="{name}" title="{size} bytes, {mt} UTC">{name}</a></li>')
    return ('<!DOCTYPE HTML>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            "<title>Directory listing for /</title>\n</head>\n<body>\n<h1>Directory listing for /</h1>\n<hr>\n<ul>\n"
            + "\n".join(li) + "\n</ul>\n<hr>\n</body>\n</html>\n")


def ficha_muestras():
    m = MUESTRAS
    rows = [("OneDrive.exe", "OneDrive.exe"), ("client64.exe", "client64.exe"),
            ("DLL embebido en client64.exe", "client64_embedded.dll"), ("winpty-agent.exe", "winpty-agent.exe"),
            ("winpty.dll", "winpty.dll"), ("run.ps1", "run.ps1"), ("run2.ps1", "run2.ps1")]
    out = ["# Ficha de muestras del open directory", "",
           f"Servidor: `http://{OP_IP}:8090/`. No se entrega ningún binario del atacante: solo estos identificadores.", "",
           "| Muestra | Tamaño (bytes) | MD5 | SHA-1 | SHA-256 |", "| --- | --- | --- | --- | --- |"]
    for label, k in rows:
        v = m[k]
        out.append(f"| {label} | {v['size']} | `{v['md5']}` | `{v['sha1']}` | `{v['sha256']}` |")
    out += ["", "Notas:",
            "- `OneDrive.exe` es un loader .NET (`OriginalFileName` `ldr_win3.exe`, sin empresa ni descripción).",
            "- `client64.exe` es un ejecutable Go con cgo ofuscado; el DLL va comprimido dentro.",
            "- `run.ps1` y `run2.ps1`: hashes de los ficheros publicados en el directorio.",
            "- `server.py` y `bootstrap_enc.txt` figuran en el listado pero no se analizaron.", ""]
    return "\n".join(out)


def aviso_cert_eml():
    msg = EmailMessage()
    msg["From"] = "CERT de coordinación <incidentes@cert-coordinacion.example>"
    msg["To"] = "seguridad@kelbrook.example"
    msg["Subject"] = f"Aviso: posible compromiso en {KB_PUBLIC}"
    msg["Date"] = format_datetime(datetime(2026, 10, 19, 9, 10, 0, tzinfo=timezone(timedelta(hours=2))))
    msg["Message-ID"] = "<20261019091000.4f2a@cert-coordinacion.example>"
    msg.set_content(
        "Buenos días:\n\n"
        f"Durante la revisión de un servidor expuesto en Internet ({OP_IP}) hemos encontrado un directorio abierto en "
        f"http://{OP_IP}:8090/ con un registro de accesos (access.log). Lo copiamos el 16/10/2026 entre las 08:36 y las "
        f"08:37 UTC desde {CERT_IP}.\n\n"
        f"En ese registro aparece la dirección pública {KB_PUBLIC}, que según WHOIS pertenece a su organización, "
        "realizando peticiones al servidor el 04/10/2026 a partir de las 18:53 UTC.\n\n"
        "Les rogamos que investiguen el equipo asociado a esa dirección y nos confirmen si procede.\n\n"
        "Un saludo,\nCERT de coordinación\n")
    return msg.as_bytes()
