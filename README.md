# DFIR-Scenarios

Escenarios sintéticos de DFIR para practicar análisis forense y correlación de evidencias, al estilo de un Sherlock. Cada carpeta numerada es un caso autocontenido. Los escenarios comparten un mismo universo ficticio, Kelbrook Medical, y pueden encadenarse, pero cada uno se resuelve solo con sus evidencias.

## Estructura de cada escenario

| Fichero | Qué es |
| --- | --- |
| `Escenario.md` | Brief del caso y preguntas a responder. Sin respuestas. |
| `Solucion.md` | Respuestas razonadas, con los filtros y comandos que las demuestran. |
| `captura/*.pcap` | La captura de red del sensor, si el caso la incluye. |
| `logs/` o `triage/` | Logs de los sistemas afectados o un triage del host empaquetado, de la misma línea temporal que la captura. |
| `generar_escenario.py` | Script que regenera las evidencias desde cero (necesita `scapy`). |

## Reglas del material

- **Todo es inventado.** Dominios, empresas, personas, credenciales y datos son ficticios. Los dominios se han elegido para que parezcan reales pero no existen.
- **IPs de documentación.** Lo externo usa los rangos RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); lo interno, `10.20.30.0/24`. Nada apunta a infraestructura real.
- **Las evidencias se corroboran.** Se generan desde la misma línea temporal, así que cada petición del PCAP tiene su línea en los logs y viceversa. Pivotar entre fuentes es parte del ejercicio.
- **Reproducible.** Cada escenario lleva su generador con semilla fija, de modo que las evidencias se pueden regenerar y auditar.

## Escenarios

| # | Carpeta | Dificultad | Tema | Técnicas que aparecen |
| --- | --- | --- | --- | --- |
| 01 | [01_Web_Exploitation](01_Web_Exploitation/Escenario.md) | Fácil | Intrusión a un portal web de pacientes | Enumeración de directorios, XSS reflejado, LFI, SQLi (error-based, boolean, UNION), uso de credenciales robadas, robo de datos vía panel |
| 02 | [02_Linux_SSH_Compromise](02_Linux_SSH_Compromise/Escenario.md) | Media | Acceso por SSH al servidor de base de datos | Reutilización de credenciales, escalada por sudo y vim, cuenta y clave SSH de persistencia, cron de mando, volcado y exfiltración por HTTP, borrado de historial |

## Cómo trabajarlos

1. Lee `Escenario.md` y responde las preguntas solo con las evidencias de la carpeta.
2. Anota, para cada respuesta, el filtro de Wireshark o el comando que la demuestra.
3. Compara con `Solucion.md`. Lo que no coincida es lo que hay que repasar.

## Regenerar un escenario

```bash
pip install scapy
cd 01_Web_Exploitation      # o cualquier otro escenario
python3 generar_escenario.py
```

Los escenarios a partir del 02 son reproducibles byte a byte: dos ejecuciones generan ficheros idénticos.

## Licencia

Apache 2.0. Ver [LICENSE](LICENSE).
