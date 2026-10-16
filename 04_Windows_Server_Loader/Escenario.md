---
tags:
  - DFIR/Simulacion
  - DFIR/Windows
  - DFIR/Malware
  - DFIR/ThreatIntel
dificultad: Por determinar
---

# Escenario 04 — El servidor que nadie toca

## 🎯 Estado inicial

> El lunes 19 de octubre de 2026, a las 09:10 (hora peninsular), el CERT de coordinación avisa por correo a Kelbrook Medical Partners. Durante la revisión de un servidor expuesto en Internet han encontrado un *open directory* con herramientas de malware y, por descuido de su dueño, el registro de accesos de su propio servidor de telemetría. En ese registro aparece la IP pública de Kelbrook. El CERT lo copió el 16 de octubre y ha tardado tres días en revisarlo, atribuir las IPs con WHOIS y avisar a los afectados.
>
> La IP pública de Kelbrook es la del NAT de la DMZ y también la dirección publicada de `int01`, el motor de integración que recibe los resultados de analíticas de Laboratorios Ardeal en formato HL7. `int01` ejecuta NextGen Mirth Connect 4.4.0 como servicio de Windows y nadie lo toca desde hace tiempo: «el Mirth no se toca».
>
> A las 13:20 (11:20 UTC) IT entra por RDP en `int01` y lanza una recogida con KAPE a un disco externo. Con las prisas no usa `KapeTriage`, sino un target propio. También exporta los logs de conexiones de `fw01` hasta ese momento y guarda la captura de red que Suricata hizo en `ids01` al disparar una alerta.
>
> `int01` es un Windows Server 2019 unido al dominio `KELBROOK`, con Sysmon. No hay EDR ni SOC 24/7.
>
> Tu trabajo es determinar si `int01` está comprometido, reconstruir qué pasó desde el principio, saber qué datos salieron y entregar lo necesario para contener el incidente y decidir sobre la notificación.

> ⚠️ **`104.234.26.225` es infraestructura real de un atacante.** No la visites, no la escanees y no abras sus puertos desde un equipo de trabajo. Todo lo que necesitas está en las evidencias.

## 📦 Evidencias

| Evidencia | Ruta | Origen |
| --- | --- | --- |
| Aviso del CERT | `inteligencia/aviso_CERT_2026-10-19.eml` | Correo recibido el 19/10 a las 09:10 (hora local) |
| Open directory | `inteligencia/opendir_104.234.26.225_8090/` | Listado (`index.html`), copia del `access.log` y ficha con los hashes de las muestras. **No se entrega ningún binario del atacante** |
| Triage de `int01` | `triage/INT01_triage.zip` | Salida de KAPE con un target propio, 19/10 a las 11:20 UTC. Conserva los timestamps originales |
| Log de `fw01` | `red/fw01_2026-09-01_2026-10-19.log` | Una línea por conexión que toca a `int01`, del 01/09 al 19/10 a las 11:20 UTC |
| Captura de `ids01` | `red/ids01_alerta_2026-10-04_8084.pcap` | Solo la sesión que disparó la alerta «TCP saliente a puerto no estándar con *payload* de alta entropía» |

Contenido del triage:

```
INT01/
├── *_ConsoleLog.txt  *_CopyLog.csv
└── C/
    ├── Windows/System32/winevt/Logs/   Security, System, Application, Sysmon,
    │                                   PowerShell/Operational, Windows PowerShell, Defender
    ├── Windows/System32/config/        SYSTEM, SOFTWARE
    ├── Windows/appcompat/Programs/     Amcache.hve
    ├── Windows/Prefetch/
    └── Program Files/Mirth Connect/    logs/mirth.log (+ rotado), conf/mirth.properties
```

El `access.log` del operador va en UTC y sin zona horaria. El resto de fuentes están en UTC salvo que se indique lo contrario; los EVTX y las colmenas guardan UTC aunque el equipo use la hora peninsular.

Herramientas recomendadas: las EZ Tools de Eric Zimmerman (EvtxECmd, RECmd o Registry Explorer, AmcacheParser), Timeline Explorer, Wireshark, `jq`/`awk` y CyberChef. En Linux sirven `evtx_dump`, `python-evtx`, `regipy` y `tshark`.

Activos relevantes:

| Activo | IP | Rol |
| --- | --- | --- |
| `int01.kelbrook.internal` | `10.20.30.30` | Motor de integración HL7 (Mirth Connect 4.4.0). Windows Server 2019 Standard |
| IP pública de Kelbrook | `192.0.2.25` | NAT de salida de la DMZ e IP publicada de `int01` |
| `fw01` | `10.20.30.1` | Cortafuegos y NAT. Publica `6661/tcp` (solo desde Ardeal) y `8443/tcp` (regla temporal `TMP-soporte-mirth`, abierta desde marzo para el soporte del integrador) |
| `ids01` | `10.20.30.250` | Suricata en un puerto espejo de la DMZ. Las alertas van a un buzón que nadie lee |
| `dc01` / `dns01` | `10.20.30.3` / `10.20.30.2` | Controlador de dominio y resolvedor interno |
| Laboratorios Ardeal | `198.51.100.140` | Cliente legítimo: envía HL7 por MLLP a `6661` en horario laboral |
| CERT | `203.0.113.77` | Quien copió el *open directory* el 16/10 |

`adm.jtorres` es el técnico de IT que entra por RDP los martes a revisar los canales de Mirth.

## ❓ Preguntas

Da las horas en UTC salvo que la pregunta pida otra cosa.

1. ¿Qué IP externa explotó `int01`, a través de qué servicio y de qué vulnerabilidad? ¿A qué hora lo hizo? Indica además cómo comprobó antes que el servidor era vulnerable.
2. ¿Con qué cuenta se ejecutó el código del atacante y qué valor de `$env:USERNAME` delata eso en el `access.log`?
3. ¿Cuántas veces ejecutó el atacante `run.ps1` y por qué no funcionó? Llega hasta la causa concreta.
4. ¿Qué excepción reportó `run2.ps1` al servidor del operador y qué hizo este después? ¿Cuántos segundos pasaron?
5. ¿Qué `OriginalFileName` y qué SHA-256 tiene el `OneDrive.exe` que se ejecutó, y por qué hay que desconfiar de él aunque se llame como un componente de Microsoft?
6. Decodifica el blob de los scripts. ¿Qué algoritmo y qué clave usa y cuánto mide el resultado?
7. ¿A qué IP y puerto conecta el shellcode y qué saludo envía? ¿Cómo resuelve las funciones de la API de Windows que necesita?
8. ¿Con qué clave llega cifrada la fase siguiente? Demuéstralo con la captura.
9. ¿Qué fichero, si existiera, impediría que el shellcode siguiera ejecutándose, y dónde estaría?
10. ¿Qué herramienta embebida usó el atacante para obtener una shell interactiva, desde qué ruta y qué procesos cuelgan de ella?
11. ¿Qué servicio instaló como persistencia, con qué binario, con qué cuenta y con qué opciones de recuperación? ¿Dónde lo ves?
12. ¿Qué datos se llevó, adónde, qué proceso los sacó y cuántos bytes salieron? ¿Cómo lo demuestras si no hay ninguna línea de comandos de subida?
13. En el `access.log`, ¿cuál de todas las ejecuciones corresponde a un operador con las manos en el teclado y cuáles parecen sandboxes o análisis automáticos? ¿Qué rasgos lo demuestran?
14. ¿Por qué no hay Prefetch y dónde se demuestra la ejecución en su lugar?
15. ¿Debe Kelbrook notificar a la AEPD según el RGPD? ¿En qué plazo y contado desde cuándo? ¿Debe comunicarlo también a los pacientes?
16. ¿Qué le falta al triage para responder con certeza qué contenía el fichero exfiltrado y qué hizo la fase en memoria? ¿Qué habrías recogido tú?
17. ¿Qué dice la versión de PowerShell del *User-Agent* sobre el estado de parches de `int01`?

### Extra (difícil)

18. Hay una única línea del `access.log` que no puede ser real. ¿Cuál es y cómo se sabe?
19. `OneDrive.exe` murió con un reinicio. ¿Cuándo, quién lo provocó y qué quedó después?

## 📝 Entregable sugerido

- Una línea temporal en UTC que separe lo que hizo el atacante de lo que es actividad legítima (Ardeal, IT, mantenimiento).
- La lista de IOCs (red, host y ficheros).
- Las acciones de contención y erradicación, en orden.
- Una valoración razonada de la notificación a la AEPD y a los interesados.
- Tres recomendaciones concretas para que no se repita.
