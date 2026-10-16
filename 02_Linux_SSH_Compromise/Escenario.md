---
tags:
  - DFIR/Simulacion
  - DFIR/Linux
  - DFIR/Network
dificultad: Media
---

# Escenario 02 — Acceso no autorizado al servidor de base de datos de Kelbrook Medical

## 🎯 Estado inicial

> Kelbrook Medical Partners sufrió el 23 de septiembre de 2026 una intrusión en su portal de pacientes (`web01`). IT rotó las contraseñas del panel de administración y dio el incidente por cerrado.
>
> El 30 de septiembre a las 08:10 UTC, la DBA nota al revisar el servidor de base de datos `db01` (`10.20.30.20`) una entrada en `/etc/cron.d` que no reconoce. Avisa a seguridad. A las 08:30 se recoge un triage rápido del sistema en caliente y se pide al proveedor la captura del sensor de la VLAN de datos de la noche anterior.
>
> `db01` es un Ubuntu 22.04 con MariaDB. Aloja la base de datos del portal (`kb_portal`) y la de historias clínicas (`kb_clinica`). Para mantenimiento remoto, el cortafuegos del proveedor reenvía el puerto `TCP/2222` público al `22` de `db01`.
>
> Tu trabajo es reconstruir qué pasó: cómo entraron, hasta dónde llegaron, qué dejaron para volver y qué se llevaron.

## 📦 Evidencias

| Evidencia | Ruta | Origen |
| --- | --- | --- |
| Captura de red | `captura/vlan-datos-2026-09-29.pcap` | Sensor de la VLAN de datos (puerto espejo del switch de `db01`), 2026-09-29 22:00 → 2026-09-30 03:00 UTC |
| Triage del host | `triage/db01-triage-2026-09-30.tar.gz` | Recogido en caliente a las 08:30 UTC con los mtimes originales |

Contenido del triage:

```
var/log/auth.log  var/log/syslog  var/log/wtmp  var/log/btmp  var/log/lastlog
etc/passwd  etc/shadow  etc/group  etc/sudoers  etc/sudoers.d/
etc/crontab  etc/cron.d/  var/spool/cron/crontabs/
etc/ssh/sshd_config  etc/profile.d/history.sh  etc/os-release  etc/hostname
root/.bash_history  root/.ssh/
home/*/.bash_history
usr/local/bin/db-backup.sh
```

Activos relevantes:

| Activo | IP | Rol |
| --- | --- | --- |
| `db01` | `10.20.30.20` | Servidor de base de datos (Ubuntu 22.04, MariaDB 10.6, OpenSSH) |
| `web01` | `10.20.30.10` | Portal web, cliente de MariaDB |
| `nas01` | `10.20.30.40` | NAS de copias de seguridad |
| `ws-it-02` | `10.20.30.55` | Puesto de trabajo de la DBA |
| `dns01` | `10.20.30.2` | Resolvedor interno |
| `fw01` | `10.20.30.1` | Cortafuegos y puerta de enlace |

## ❓ Preguntas

1. ¿Qué usuario, desde qué IP y a qué hora (UTC) consiguió el atacante su primer acceso interactivo a `db01`?
2. Antes de entrar, probó otros cuatro nombres de usuario. ¿Cuáles, y cuáles de ellos no existían en `db01`?
3. Otra IP acumula muchos más fallos de autenticación que el atacante. ¿Cuál es, cuántos intentos hizo y por qué se descarta como origen de la intrusión?
4. ¿Qué relación tiene este acceso con el incidente del 23 de septiembre en `web01`?
5. ¿Cómo pasó el atacante de su usuario inicial a `root`? Cita la línea de `auth.log` que lo demuestra.
6. ¿Qué configuración del sistema lo hizo posible y en qué fichero está?
7. ¿Qué cuenta nueva se creó, con qué UID, en qué grupo se metió y a qué hora?
8. ¿Qué clave SSH se añadió, a qué cuenta, y cuál es el comentario de la clave?
9. ¿Qué mecanismo de ejecución periódica dejó el atacante, cada cuánto se dispara y a dónde conecta?
10. ¿A qué hora se ejecutó por primera vez ese mecanismo y cuántas veces aparece en la captura?
11. ¿Qué datos se sacaron de `db01`, por qué protocolo, hacia dónde y cuánto ocupaba el fichero?
12. ¿Cuántos pacientes contiene el volcado exfiltrado?
13. ¿En qué directorio preparó el atacante los ficheros antes de sacarlos y qué hizo con él después?
14. El historial de comandos del usuario inicial no muestra nada de esa noche. ¿Por qué, y con qué otras fuentes se reconstruye lo que hizo?
15. ¿Cuánto duró la sesión inicial del atacante, cuándo volvió y con qué método se autenticó la segunda vez?
16. En la captura hay una transferencia SSH saliente de `db01` mucho mayor que la exfiltración. ¿Qué es y cómo se descarta?

## 📝 Entregable sugerido

Línea temporal del ataque (hora UTC, origen, acción, evidencia), lista de IOCs, inventario de los mecanismos de persistencia que hay que eliminar y tres recomendaciones concretas de remediación.
