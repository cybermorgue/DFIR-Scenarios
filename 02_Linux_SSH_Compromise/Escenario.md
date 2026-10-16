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
> El 30 de septiembre a primera hora, la DBA entra en el servidor de base de datos `db01` (`10.20.30.20`) y encuentra en `/etc/cron.d` una entrada que no reconoce. Avisa a seguridad. Siguiendo sus indicaciones, a las 08:28 UTC lanza desde su propia sesión un script de recogida en caliente y se pide al proveedor la captura del sensor de la VLAN de datos de la noche anterior.
>
> `db01` es un Ubuntu 22.04 con MariaDB y el reloj en UTC. Aloja la base de datos del portal (`kb_portal`) y la de historias clínicas (`kb_clinica`). Para mantenimiento remoto, el cortafuegos del proveedor reenvía el puerto `TCP/2222` público al `22` de `db01`.
>
> Tu trabajo es reconstruir qué pasó: cómo entraron, hasta dónde llegaron, qué dejaron para volver y qué se llevaron.

## 📦 Evidencias

| Evidencia | Ruta | Origen |
| --- | --- | --- |
| Captura de red | `captura/vlan-datos-2026-09-29.pcap` | Sensor de la VLAN de datos (puerto espejo del switch de `db01`), 2026-09-29 22:00 → 2026-09-30 03:00 UTC |
| Triage del host | `triage/db01-triage-2026-09-30.tar.gz` | Script de recogida en caliente, 2026-09-30 08:28 UTC. Conserva mtimes, modos y propietarios |

Contenido del triage:

```
db01-triage-2026-09-30/
├── fs/                 copia de ficheros del sistema
│   ├── etc/            passwd shadow group gshadow sudoers sudoers.d/ crontab cron.d/
│   │                   ssh/sshd_config bash.bashrc mysql/mariadb.conf.d/ os-release hostname
│   ├── root/           .bash_history .viminfo .ssh/
│   ├── home/*/         .bash_history y .ssh/ de cada usuario
│   ├── var/log/        auth.log syslog syslog.1 wtmp btmp lastlog
│   ├── var/tmp/        solo el directorio
│   └── usr/local/bin/db-backup.sh
├── live/               salida de date, who, ps auxf, ss -tanp, ls de directorios temporales y stat
└── manifest.sha256
```

Para leer los binarios de sesión:

```bash
last -F -w -f fs/var/log/wtmp
lastb -F -w -f fs/var/log/btmp
sudo lastlog -R "$PWD/fs"      # o utmpdump / un parser propio para lastlog
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
5. ¿Cómo pasó el atacante de su usuario inicial a `root`? Cita la línea de `auth.log` que lo demuestra y el otro artefacto que muestra cómo obtuvo la shell.
6. ¿Qué configuración del sistema lo hizo posible y en qué fichero está?
7. ¿Qué cuenta nueva se creó, con qué UID, en qué grupo se metió y a qué hora?
8. ¿Qué clave SSH se añadió, a qué cuenta y con qué comentario? ¿Dónde se ve que se usó después?
9. ¿Qué mecanismo de ejecución periódica dejó el atacante, cada cuánto se dispara y a dónde conecta?
10. ¿A qué hora se ejecutó por primera vez ese mecanismo y cuántas veces aparece en la captura?
11. ¿Qué datos se sacaron de `db01`, por qué protocolo, hacia dónde y cuánto ocupaba el fichero?
12. ¿Cuántos pacientes contiene el volcado exfiltrado?
13. ¿En qué directorio preparó el atacante los ficheros antes de sacarlos y qué hizo con él después?
14. El historial de comandos del usuario inicial apenas muestra nada de esa noche. ¿Qué queda, por qué, y con qué otras fuentes se reconstruye lo que hizo?
15. ¿Cuánto duró la sesión inicial del atacante, cuándo volvió y con qué método se autenticó la segunda vez?
16. En la captura hay una transferencia SSH saliente de `db01` mucho mayor que la exfiltración. ¿Qué es y cómo se descarta?

### Extra (difícil)

17. ¿Qué contraseña asignó el atacante a la cuenta nueva?
18. Sin descifrar nada, ¿cómo separas en la captura las conexiones SSH del atacante, del escáner y de la DBA? Da para cada uno el banner del cliente y su HASSH.

## 📝 Entregable sugerido

Línea temporal del ataque (hora UTC, origen, acción, evidencia), lista de IOCs, inventario de los mecanismos de persistencia que hay que eliminar y tres recomendaciones concretas de remediación. Separa en la línea temporal lo que hizo el atacante de lo que hizo el equipo de respuesta.
