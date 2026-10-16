---
tags:
  - DFIR/Simulacion
  - DFIR/Windows
  - DFIR/Email
dificultad: Fácil
---

# Escenario 03 — La factura de Ardeal

## 🎯 Estado inicial

> El martes 13 de octubre de 2026, a las 11:41 (hora peninsular), Lucía Marín, de facturación de Kelbrook Medical Partners, abre un ticket a IT. Esa mañana le había llegado una factura rectificativa de Laboratorios Ardeal, el laboratorio que procesa las analíticas de la clínica. Al abrir el adjunto no vio la factura que esperaba. Hacia las 11:20 llamó a Ardeal para pedir que se la reenviaran y le dijeron que no le habían mandado nada.
>
> A las 11:52 IT desconecta el cable de red de su puesto, `KB-FIN-WS03`. A las 12:10 un técnico lanza en el equipo una recogida con KAPE desde un USB. Además, IT descarga desde el portal de seguridad de Microsoft 365 el correo que reportó Lucía y, para comparar, una factura legítima anterior de Ardeal.
>
> `KB-FIN-WS03` es un Windows 11 Pro unido al dominio `KELBROOK`, con Sysmon desplegado por GPO. Lucía trabaja con una cuenta de usuario estándar.
>
> Tu trabajo es confirmar si fue un phishing, reconstruir qué pasó en el equipo desde que se abrió el adjunto, determinar si salieron datos de la organización y entregar lo necesario para contener el incidente.

## 📦 Evidencias

| Evidencia | Ruta | Origen |
| --- | --- | --- |
| Correo reportado | `correo/reportado_Factura_rectificativa_ARD-2026-0917.eml` | Descargado del portal de seguridad de Microsoft 365 |
| Correo de referencia | `correo/referencia_Factura_ARD-2026-0884.eml` | Factura legítima de Ardeal del 05/10, descargada del mismo portal |
| Triage del puesto | `triage/KB-FIN-WS03_triage.zip` | Salida de KAPE (target propio `KB-Triage`), 13/10 a las 12:10 hora local. Conserva los timestamps originales |

Contenido del triage:

```
KB-FIN-WS03/
├── *_ConsoleLog.txt  *_CopyLog.csv
└── C/
    ├── Windows/System32/winevt/Logs/   Security, System, Application, Sysmon,
    │                                   PowerShell/Operational, Windows PowerShell, Defender
    ├── Windows/System32/config/        SYSTEM, SOFTWARE
    ├── Windows/appcompat/Programs/     Amcache.hve
    ├── Windows/Prefetch/
    └── Users/<perfil>/                 NTUSER.DAT, Recent, historial de Edge, historial de PSReadLine
```

Herramientas recomendadas: las EZ Tools de Eric Zimmerman (EvtxECmd, RECmd o Registry Explorer, PECmd, LECmd, AmcacheParser), Timeline Explorer y cualquier visor de `.eml`. En Linux sirven `evtx_dump`, `regipy`, los parsers de libyal (`pyevtx`, `pyregf`, `pyscca`, `pylnk`) y `sqlite3`.

Activos relevantes:

| Activo | IP | Rol |
| --- | --- | --- |
| `KB-FIN-WS03` | `10.20.30.61` | Puesto de Lucía Marín (`KELBROOK\lmarin`) |
| `dc01` | `10.20.30.3` | Controlador de dominio y DNS de los puestos |
| `fs01` | `10.20.30.45` | Servidor de ficheros. El recurso `\\fs01\Facturacion` guarda conciliaciones con proveedores y las remesas SEPA de recibos domiciliados de pacientes (nombre, DNI e IBAN) |
| `fw01` | `10.20.30.1` | Cortafuegos y puerta de enlace |

Laboratorios Ardeal escribe siempre desde `administracion@ardeal-labs.net`.

## ❓ Preguntas

Da las horas en UTC salvo que la pregunta pida otra cosa.

1. ¿Qué dirección de remitente usa el correo reportado y en qué se diferencia del dominio real del proveedor?
2. SPF, DKIM y DMARC dan *pass*. ¿Por qué eso no demuestra que el correo sea legítimo? Señala al menos dos diferencias de cabeceras con el correo de referencia.
3. ¿Desde qué IP pública se conectó el remitente a su servidor de correo para enviar el mensaje?
4. ¿Qué contiene en realidad el adjunto y qué truco usa para pasar por un PDF?
5. ¿Qué ejecuta el acceso directo? Decodifica el comando y resume paso a paso lo que hace.
6. ¿A qué hora abrió Lucía el adjunto y en qué carpeta lo dejó Outlook?
7. ¿Qué proceso lanzó PowerShell y desde qué ruta se ejecutó realmente el acceso directo?
8. ¿Qué ejecutable se instaló, en qué ruta, con qué SHA-256 y a qué hora se ejecutó por primera vez?
9. El nombre y la ruta imitan a OneDrive. ¿Qué datos de las evidencias demuestran que no es software de Microsoft?
10. ¿Qué mecanismo de persistencia dejó y dónde lo encuentras en el registro?
11. ¿Con qué dominio e IP se comunica el implante y cada cuánto?
12. Enumera en orden, con hora UTC, los comandos que lanzó el operador a través del implante. ¿Qué buscaba?
13. ¿Qué datos se llevó, cómo los empaquetó, por dónde los sacó y qué hizo después con el fichero?
14. ¿Qué actividad de las evidencias corresponde al equipo de IT y no al atacante?
15. ¿En qué zona horaria está configurado el equipo y a qué hora local abrió Lucía el adjunto?

### Extra (difícil)

16. Los metadatos del acceso directo delatan el equipo donde se creó. ¿Qué nombre de máquina y qué MAC aparecen, y qué te dice esa MAC?
17. Sin acceso a `fs01`, ¿qué ficheros concretos se llevó?

## 📝 Entregable sugerido

- Una línea temporal en UTC que separe lo que hizo el atacante, lo que hizo Lucía y lo que hizo IT.
- La lista de IOCs.
- Las acciones de contención y erradicación.
- Una valoración razonada de si hay que notificar la brecha a la AEPD.
- Tres recomendaciones concretas para que no se repita.
