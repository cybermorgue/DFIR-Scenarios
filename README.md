# DFIR-Scenarios

Escenarios sintéticos de DFIR para practicar análisis forense y correlación de evidencias, al estilo de un Sherlock. Cada carpeta numerada es un caso autocontenido. Los escenarios comparten un mismo universo ficticio, Kelbrook Medical, y pueden encadenarse, pero cada uno se resuelve solo con sus evidencias.

## Estructura de cada escenario

| Fichero | Qué es |
| --- | --- |
| `Escenario.md` | Brief del caso y preguntas a responder. Sin respuestas. |
| `Solucion.md` | Respuestas razonadas, con los filtros y comandos que las demuestran. |
| `captura/*.pcap` | La captura de red del sensor, si el caso la incluye. |
| `correo/*.eml` | Correos exportados del buzón, si el caso parte de un phishing. |
| `logs/` o `triage/` | Logs de los sistemas afectados o un triage del host empaquetado, de la misma línea temporal que el resto de evidencias. |
| `generar_escenario.py` | Script que regenera las evidencias desde cero. |

## Reglas del material

- **Todo es inventado.** Dominios, empresas, personas, credenciales y datos son ficticios. Los dominios se han elegido para que parezcan reales pero no existen.
- **IPs de documentación, con una excepción.** Lo interno y lo inventado usan `10.20.30.0/24` y los rangos RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Un escenario puede incluir **IPs, dominios y subdominios reales** cuando sean IOCs de una campaña real, porque trabajar con IOCs reales es útil incluso en entrenamiento. Cada escenario indica qué es real y qué es inventado, y avisa de no interactuar con esa infraestructura.
- **Las evidencias se corroboran.** Se generan desde la misma línea temporal, así que cada petición del PCAP tiene su línea en los logs, cada proceso de Sysmon su 4688, y viceversa. Pivotar entre fuentes es parte del ejercicio.
- **Reproducible.** Cada escenario lleva su generador con semilla fija, de modo que las evidencias se pueden regenerar y auditar.

## Escenarios

| # | Carpeta | Dificultad | Tema | Técnicas que aparecen |
| --- | --- | --- | --- | --- |
| 01 | [01_Web_Exploitation](01_Web_Exploitation/Escenario.md) | Fácil | Intrusión a un portal web de pacientes | Enumeración de directorios, XSS reflejado, LFI, SQLi (error-based, boolean, UNION), uso de credenciales robadas, robo de datos vía panel |
| 02 | [02_Linux_SSH_Compromise](02_Linux_SSH_Compromise/Escenario.md) | Media | Acceso por SSH al servidor de base de datos | Reutilización de credenciales, escalada por sudo y vim, cuenta y clave SSH de persistencia, cron de mando, volcado y exfiltración por HTTP, borrado de historial |
| 03 | [03_Windows_Phishing](03_Windows_Phishing/Escenario.md) | Fácil | Spear phishing contra facturación con un falso proveedor | Typosquatting con SPF/DKIM/DMARC válidos, ZIP con LNK disfrazado de PDF, PowerShell codificado, implante en `AppData` que imita a OneDrive, persistencia en la clave `Run` de HKCU, C2 por HTTPS, enumeración del dominio con binarios nativos, robo de remesas SEPA de un recurso compartido |
| 04 | [04_Windows_Server_Loader](04_Windows_Server_Loader/Escenario.md) | Por determinar | Servidor de integración HL7 comprometido y loader en memoria (campaña real) | RCE en Mirth Connect (CVE-2023-43208), scripts de PowerShell con un bug, loader .NET con shellcode cifrado, shell con winpty, servicio de persistencia, exfiltración a un bucket de OSS por el propio implante, reinicio que borra la evidencia de memoria, triage incompleto, RGPD |

## Cómo trabajarlos

1. Lee `Escenario.md` y responde las preguntas solo con las evidencias de la carpeta.
2. Anota, para cada respuesta, el filtro de Wireshark o el comando que la demuestra.
3. Compara con `Solucion.md`. Lo que no coincida es lo que hay que repasar.

## Regenerar un escenario

```bash
pip install scapy           # solo para los escenarios con PCAP (01 y 02)
cd 01_Web_Exploitation      # o cualquier otro escenario
python3 generar_escenario.py
```

El generador del 03 solo usa la biblioteca estándar de Python: escribe EVTX, colmenas de registro, Prefetch, LNK e historial de Edge en su formato nativo de Windows.

El generador del 04 también solo usa la biblioteca estándar. Para ejecutar sus tests (`python -m pytest tests -q` desde `04_Windows_Server_Loader`) hacen falta `pytest`, `python-evtx` y `regipy`. Con `tests/.prohibidos.txt` (local, no versionado) el test de saneado comprueba además una lista de nombres que no deben aparecer en ninguna salida.

Los escenarios a partir del 02 son reproducibles byte a byte: dos ejecuciones generan ficheros idénticos.

## Licencia

Apache 2.0. Ver [LICENSE](LICENSE).
