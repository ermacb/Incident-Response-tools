@echo off
setlocal enabledelayedexpansion
title Deteccion de Movimiento Lateral - IR (CSIRT)

:: ===== VERIFICAR PRIVILEGIOS DE ADMINISTRADOR =====
echo [*] Verificando privilegios...
net session >nul 2>&1
if %errorLevel% neq 0 (
    color 0C
    echo.
    echo ========================================
    echo [!] ERROR: PRIVILEGIOS INSUFICIENTES
    echo ========================================
    echo.
    echo Este script REQUIERE privilegios de Administrador
    echo para recopilar informacion de seguridad.
    echo.
    echo Por favor:
    echo 1. Cierra esta ventana
    echo 2. Click derecho en el script
    echo 3. Selecciona "Ejecutar como administrador"
    echo.
    echo ========================================
    pause
    exit /b 1
)

echo [+] Privilegios de administrador: OK
echo.

:: Crear carpeta de salida
set timestamp=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set timestamp=%timestamp: =0%
set outputDir=C:\IR_LateralMovement\LateralMovement_%timestamp%
mkdir "%outputDir%" 2>nul

echo ========================================
echo   CSIRT - Deteccion Movimiento Lateral
echo ========================================
echo [+] Directorio de salida: %outputDir%
echo [+] Inicio: %date% %time%
echo ========================================
echo.

:: Log de ejecución
set logFile=%outputDir%\execution.log
echo Inicio de deteccion: %date% %time% > "%logFile%"
echo Hostname: %COMPUTERNAME% >> "%logFile%"
echo Usuario: %USERNAME% >> "%logFile%"
echo. >> "%logFile%"

:: ===== SESIONES ACTIVAS =====
echo [*] [1/14] Analizando sesiones activas...
echo [%date% %time%] Active Sessions >> "%logFile%"

:: Método 1: qwinsta (con ruta completa)
echo === Sesiones Locales (qwinsta) === > "%outputDir%\Active_Sessions.txt"
%SystemRoot%\System32\qwinsta.exe >> "%outputDir%\Active_Sessions.txt" 2>&1
if errorlevel 1 (
    echo [!] qwinsta no disponible >> "%outputDir%\Active_Sessions.txt"
    echo [!] qwinsta error >> "%logFile%"
)

:: Método 2: query session (alternativa)
echo. >> "%outputDir%\Active_Sessions.txt"
echo === Query Session === >> "%outputDir%\Active_Sessions.txt"
%SystemRoot%\System32\query.exe session >> "%outputDir%\Active_Sessions.txt" 2>&1

:: Método 3: query user
echo. >> "%outputDir%\Active_Sessions.txt"
echo === Query User === >> "%outputDir%\Active_Sessions.txt"
%SystemRoot%\System32\query.exe user >> "%outputDir%\Active_Sessions.txt" 2>&1

:: Método 4: WMIC
echo. >> "%outputDir%\Active_Sessions.txt"
echo === WMIC Computersystem === >> "%outputDir%\Active_Sessions.txt"
wmic computersystem get username >> "%outputDir%\Active_Sessions.txt" 2>&1

echo [+] Sesiones activas: OK

:: ===== CONEXIONES SMB =====
echo [*] [2/14] Recopilando conexiones SMB...
echo [%date% %time%] SMB Connections >> "%logFile%"

echo === Net Session === > "%outputDir%\Net_Sessions.txt"
net session >> "%outputDir%\Net_Sessions.txt" 2>&1
if errorlevel 1 (
    echo [!] No hay sesiones SMB activas o acceso denegado >> "%outputDir%\Net_Sessions.txt"
    echo [!] net session error >> "%logFile%"
)

echo. >> "%outputDir%\Net_Sessions.txt"
echo === WMIC NetLogin === >> "%outputDir%\Net_Sessions.txt"
wmic netlogin get name,numberoflogons,lastlogon /format:list >> "%outputDir%\Net_Sessions.txt" 2>&1

echo === Net Use === > "%outputDir%\SMB_Mapped_Drives.txt"
net use >> "%outputDir%\SMB_Mapped_Drives.txt" 2>&1

echo === Net Share === > "%outputDir%\SMB_Shares.txt"
net share >> "%outputDir%\SMB_Shares.txt" 2>&1

echo === Net File === > "%outputDir%\SMB_Open_Files.txt"
net file >> "%outputDir%\SMB_Open_Files.txt" 2>&1
if errorlevel 1 (
    echo [!] No hay archivos abiertos o acceso denegado >> "%outputDir%\SMB_Open_Files.txt"
)

echo [+] Conexiones SMB: OK

:: ===== RECURSOS COMPARTIDOS =====
echo [*] [3/14] Analizando acceso a recursos compartidos...
echo [%date% %time%] Shared Resources >> "%logFile%"

wmic netuse get * /format:list > "%outputDir%\Network_Resources.txt" 2>&1
wmic share get * /format:list > "%outputDir%\Shared_Resources.txt" 2>&1

echo [+] Recursos compartidos: OK

:: ===== BUSCAR PSEXEC =====
echo [*] [4/14] Buscando evidencia de PsExec...
echo [%date% %time%] PsExec Detection >> "%logFile%"

echo === PsExec Service === > "%outputDir%\PsExec_Detection.txt"
sc query | findstr /i "psexesvc" >> "%outputDir%\PsExec_Detection.txt" 2>&1
if errorlevel 1 (
    echo [+] No se encontro servicio PsExec >> "%outputDir%\PsExec_Detection.txt"
) else (
    echo [!] ALERTA: Servicio PsExec DETECTADO! >> "%outputDir%\PsExec_Detection.txt"
    echo [!] ALERTA: PsExec detectado! >> "%logFile%"
)

echo. >> "%outputDir%\PsExec_Detection.txt"
echo === PsExec Process === >> "%outputDir%\PsExec_Detection.txt"
tasklist | findstr /i "psexe" >> "%outputDir%\PsExec_Detection.txt" 2>&1
if errorlevel 1 (
    echo [+] No se encontro proceso PsExec >> "%outputDir%\PsExec_Detection.txt"
) else (
    echo [!] ALERTA: Proceso PsExec DETECTADO! >> "%outputDir%\PsExec_Detection.txt"
    echo [!] ALERTA: Proceso PsExec detectado! >> "%logFile%"
)

echo. >> "%outputDir%\PsExec_Detection.txt"
echo === Archivos PsExec === >> "%outputDir%\PsExec_Detection.txt"
dir C:\Windows\*.exe | findstr /i "psexe" >> "%outputDir%\PsExec_Detection.txt" 2>&1
dir C:\Windows\System32\*.exe | findstr /i "psexe" >> "%outputDir%\PsExec_Detection.txt" 2>&1

echo [+] Busqueda PsExec: OK

:: ===== HERRAMIENTAS DE ADMINISTRACION REMOTA =====
echo [*] [5/14] Buscando herramientas de administracion remota...
echo [%date% %time%] Remote Admin Tools >> "%logFile%"

echo === Remote Admin Tools Detection === > "%outputDir%\Remote_Admin_Tools.txt"
echo [*] Buscando PSTools... >> "%outputDir%\Remote_Admin_Tools.txt"
tasklist | findstr /i "psexec psfile pskill pslist psloggedon pspasswd" >> "%outputDir%\Remote_Admin_Tools.txt" 2>&1

echo [*] Buscando WinRM... >> "%outputDir%\Remote_Admin_Tools.txt"
sc query winrm >> "%outputDir%\Remote_Admin_Tools.txt" 2>&1

echo [*] Buscando RemoteRegistry... >> "%outputDir%\Remote_Admin_Tools.txt"
sc query RemoteRegistry >> "%outputDir%\Remote_Admin_Tools.txt" 2>&1

echo [*] Buscando RDP... >> "%outputDir%\Remote_Admin_Tools.txt"
sc query TermService >> "%outputDir%\Remote_Admin_Tools.txt" 2>&1

echo [+] Herramientas remotas: OK

:: ===== TAREAS PROGRAMADAS =====
echo [*] [6/14] Analizando tareas programadas...
echo [%date% %time%] Scheduled Tasks >> "%logFile%"

schtasks /query /fo LIST /v > "%outputDir%\Scheduled_Tasks.txt" 2>&1
schtasks /query /fo CSV /v > "%outputDir%\Scheduled_Tasks.csv" 2>&1

:: Buscar tareas sospechosas
echo === Tareas sospechosas === > "%outputDir%\Suspicious_Tasks.txt"
schtasks /query /fo LIST /v | findstr /i "powershell cmd wscript cscript" >> "%outputDir%\Suspicious_Tasks.txt" 2>&1

echo [+] Tareas programadas: OK

:: ===== EVENTOS DE LOGON =====
echo [*] [7/14] Extrayendo eventos de logon...
echo [%date% %time%] Logon Events >> "%logFile%"

:: Event ID 4624 - Successful logon
wevtutil qe Security "/q:*[System[(EventID=4624)]]" /f:text /c:500 > "%outputDir%\Logon_Events_4624.txt" 2>&1

:: Event ID 4625 - Failed logon
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /f:text /c:200 > "%outputDir%\Failed_Logon_4625.txt" 2>&1

:: Event ID 4672 - Special privileges
wevtutil qe Security "/q:*[System[(EventID=4672)]]" /f:text /c:200 > "%outputDir%\Special_Privileges_4672.txt" 2>&1

:: Event ID 4648 - Explicit logon
wevtutil qe Security "/q:*[System[(EventID=4648)]]" /f:text /c:200 > "%outputDir%\Explicit_Logon_4648.txt" 2>&1

echo [+] Eventos de logon: OK

:: ===== EVENTOS DE RDP =====
echo [*] [8/14] Analizando conexiones RDP...
echo [%date% %time%] RDP Events >> "%logFile%"

:: Event 1149 - RDP successful connection
wevtutil qe "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /c:200 /f:text > "%outputDir%\RDP_Events_1149.txt" 2>&1

:: Event 21 - Session logon succeeded
wevtutil qe "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /c:200 /f:text > "%outputDir%\RDP_Session_Events.txt" 2>&1

:: Estado del servicio RDP
echo === RDP Service Status === > "%outputDir%\RDP_Service.txt"
sc query TermService >> "%outputDir%\RDP_Service.txt" 2>&1
reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections >> "%outputDir%\RDP_Service.txt" 2>&1

echo [+] RDP: OK

:: ===== PROCESOS DE ADMINISTRACION REMOTA =====
echo [*] [9/14] Buscando procesos de administracion remota...
echo [%date% %time%] Remote Admin Processes >> "%logFile%"

tasklist /v | findstr /i "psexec wmic mstsc powershell winrs" > "%outputDir%\Remote_Admin_Processes.txt" 2>&1
wmic process where "name='powershell.exe' or name='wmic.exe' or name='mstsc.exe'" get ProcessId,Name,CommandLine /format:list > "%outputDir%\Remote_Processes_Detail.txt" 2>&1

echo [+] Procesos remotos: OK

:: ===== CONEXIONES DE RED =====
echo [*] [10/14] Analizando conexiones de red...
echo [%date% %time%] Network Connections >> "%logFile%"

netstat -ano > "%outputDir%\Network_Connections.txt" 2>&1
netstat -ano | findstr "ESTABLISHED" > "%outputDir%\Established_Connections.txt" 2>&1
netstat -anob > "%outputDir%\Network_With_Process.txt" 2>&1

:: Puertos comunes de lateral movement
echo === Puertos sospechosos === > "%outputDir%\Suspicious_Ports.txt"
netstat -ano | findstr ":445 :135 :139 :3389 :5985 :5986" >> "%outputDir%\Suspicious_Ports.txt" 2>&1

echo [+] Conexiones de red: OK

:: ===== USUARIOS CON SESIONES =====
echo [*] [11/14] Listando usuarios con sesiones...
echo [%date% %time%] User Sessions >> "%logFile%"

wmic netlogin get * /format:list > "%outputDir%\Network_Logons.txt" 2>&1
wmic logon get * /format:list > "%outputDir%\Logon_Sessions.txt" 2>&1

echo [+] Sesiones de usuario: OK

:: ===== SERVICIOS REMOTOS =====
echo [*] [12/14] Verificando servicios de administracion remota...
echo [%date% %time%] Remote Services >> "%logFile%"

echo === WinRM Service === > "%outputDir%\Remote_Services.txt"
sc query winrm >> "%outputDir%\Remote_Services.txt" 2>&1
sc qc winrm >> "%outputDir%\Remote_Services.txt" 2>&1

echo. >> "%outputDir%\Remote_Services.txt"
echo === RemoteRegistry Service === >> "%outputDir%\Remote_Services.txt"
sc query RemoteRegistry >> "%outputDir%\Remote_Services.txt" 2>&1
sc qc RemoteRegistry >> "%outputDir%\Remote_Services.txt" 2>&1

echo. >> "%outputDir%\Remote_Services.txt"
echo === RDP Service === >> "%outputDir%\Remote_Services.txt"
sc query TermService >> "%outputDir%\Remote_Services.txt" 2>&1
sc qc TermService >> "%outputDir%\Remote_Services.txt" 2>&1

echo. >> "%outputDir%\Remote_Services.txt"
echo === Server Service === >> "%outputDir%\Remote_Services.txt"
sc query LanmanServer >> "%outputDir%\Remote_Services.txt" 2>&1

echo [+] Servicios remotos: OK

:: ===== WMI ACTIVITY =====
echo [*] [13/14] Analizando actividad WMI...
echo [%date% %time%] WMI Activity >> "%logFile%"

wmic process where "name='wmiprvse.exe'" get ProcessId,CommandLine /format:list > "%outputDir%\WMI_Processes.txt" 2>&1
wevtutil qe "Microsoft-Windows-WMI-Activity/Operational" /c:100 /f:text > "%outputDir%\WMI_Events.txt" 2>&1

echo [+] WMI: OK

:: ===== COMANDOS REMOTOS EJECUTADOS =====
echo [*] [14/14] Buscando comandos remotos ejecutados...
echo [%date% %time%] Remote Commands >> "%logFile%"

:: Event ID 4688 - Process creation
wevtutil qe Security "/q:*[System[(EventID=4688)]]" /f:text /c:100 > "%outputDir%\Process_Creation_Events.txt" 2>&1

:: PowerShell events
wevtutil qe "Microsoft-Windows-PowerShell/Operational" /c:200 /f:text > "%outputDir%\PowerShell_Events.txt" 2>&1

:: Event ID 5140 - Network share access
wevtutil qe Security "/q:*[System[(EventID=5140)]]" /f:text /c:200 > "%outputDir%\Share_Access_Events_5140.txt" 2>&1

echo [+] Comandos remotos: OK

:: ===== ANALISIS DE ACCESOS A RECURSOS ADMINISTRATIVOS =====
echo.
echo [*] Analizando accesos a recursos administrativos (ADMIN$, C$, IPC$)...
echo [%date% %time%] Admin Share Access >> "%logFile%"

wevtutil qe Security "/q:*[System[(EventID=5140)] and EventData[Data[@Name='ShareName']='\\*$']]" /f:text /c:200 > "%outputDir%\Admin_Share_Access.txt" 2>&1

echo [+] Accesos administrativos: OK

:: ===== RESUMEN Y ESTADISTICAS =====
echo.
echo ========================================
echo [+] Deteccion de movimiento lateral completada!
echo ========================================
echo [%date% %time%] Analysis Complete >> "%logFile%"

:: Generar resumen
echo. > "%outputDir%\SUMMARY.txt"
echo ======================================== >> "%outputDir%\SUMMARY.txt"
echo   RESUMEN DE DETECCION >> "%outputDir%\SUMMARY.txt"
echo ======================================== >> "%outputDir%\SUMMARY.txt"
echo Fecha: %date% %time% >> "%outputDir%\SUMMARY.txt"
echo Hostname: %COMPUTERNAME% >> "%outputDir%\SUMMARY.txt"
echo Usuario: %USERNAME% >> "%outputDir%\SUMMARY.txt"
echo. >> "%outputDir%\SUMMARY.txt"
echo INDICADORES CRITICOS: >> "%outputDir%\SUMMARY.txt"
echo. >> "%outputDir%\SUMMARY.txt"

:: Verificar si PsExec fue detectado
findstr /i "ALERTA" "%outputDir%\PsExec_Detection.txt" > nul 2>&1
if not errorlevel 1 (
    echo [!] ALERTA: PsExec detectado >> "%outputDir%\SUMMARY.txt"
    color 0E
)

:: Contar sesiones activas
for /f %%a in ('type "%outputDir%\Active_Sessions.txt" ^| find /c /v ""') do set sessionCount=%%a
echo - Sesiones activas: %sessionCount% lineas >> "%outputDir%\SUMMARY.txt"

:: Contar conexiones establecidas
for /f %%a in ('type "%outputDir%\Established_Connections.txt" 2^>nul ^| find /c /v ""') do set connCount=%%a
echo - Conexiones ESTABLISHED: %connCount% >> "%outputDir%\SUMMARY.txt"

echo. >> "%outputDir%\SUMMARY.txt"
echo RECOMENDACIONES: >> "%outputDir%\SUMMARY.txt"
echo 1. Revisar eventos de logon 4624/4625 >> "%outputDir%\SUMMARY.txt"
echo 2. Verificar conexiones RDP >> "%outputDir%\SUMMARY.txt"
echo 3. Analizar accesos a recursos compartidos >> "%outputDir%\SUMMARY.txt"
echo 4. Correlacionar con otros sistemas de la red >> "%outputDir%\SUMMARY.txt"
echo. >> "%outputDir%\SUMMARY.txt"

type "%outputDir%\SUMMARY.txt"

echo.
echo [+] Archivos guardados en: %outputDir%
echo [!] Revisa manualmente los archivos para identificar actividad sospechosa
echo.
echo [+] Fin de ejecucion: %date% %time% >> "%logFile%"

:: Contar archivos generados
set filecount=0
for %%f in ("%outputDir%\*.*") do set /a filecount+=1
echo [+] Total de archivos generados: %filecount%
echo [+] Total de archivos: %filecount% >> "%logFile%"

echo.
pause