@echo off
setlocal enabledelayedexpansion
title Recoleccion de Informacion del Sistema - IR (CSIRT)

:: Verificar privilegios de administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ADVERTENCIA: Este script debe ejecutarse como Administrador
    echo [!] Algunas funciones pueden no estar disponibles
    echo.
    timeout /t 3 >nul
)

:: Crear carpeta de salida con timestamp
set timestamp=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set timestamp=%timestamp: =0%
set outputDir=C:\IR_Collection_%timestamp%
mkdir "%outputDir%" 2>nul

echo ========================================
echo   CSIRT - Recoleccion de Informacion
echo ========================================
echo [+] Carpeta de salida: %outputDir%
echo [+] Inicio: %date% %time%
echo ========================================
echo.

:: Log de ejecución
set logFile=%outputDir%\execution.log
echo Inicio de recoleccion: %date% %time% > "%logFile%"

:: ===== INFORMACION DEL SISTEMA =====
echo [*] [1/15] Recopilando informacion del sistema...
echo [%date% %time%] SystemInfo >> "%logFile%"
systeminfo > "%outputDir%\SystemInfo.txt" 2>&1
if errorlevel 1 (
    echo [!] Error en systeminfo >> "%logFile%"
) else (
    echo [+] SystemInfo: OK
)

wmic computersystem get * /format:list > "%outputDir%\ComputerSystem.txt" 2>&1
wmic bios get * /format:list > "%outputDir%\BIOS.txt" 2>&1
wmic os get * /format:list > "%outputDir%\OS_Info.txt" 2>&1
hostname > "%outputDir%\Hostname.txt"
ver > "%outputDir%\WindowsVersion.txt"

:: ===== INFORMACION DE RED =====
echo [*] [2/15] Recopilando configuracion de red...
echo [%date% %time%] Network Config >> "%logFile%"
ipconfig /all > "%outputDir%\NetworkConfig.txt" 2>&1
ipconfig /displaydns > "%outputDir%\DNS_Cache.txt" 2>&1
arp -a > "%outputDir%\ARP_Cache.txt" 2>&1
route print > "%outputDir%\RoutingTable.txt" 2>&1
netstat -ano > "%outputDir%\NetStat_All.txt" 2>&1
netstat -anob > "%outputDir%\NetStat_WithProcess.txt" 2>&1
nbtstat -c > "%outputDir%\NBT_Cache.txt" 2>&1
wmic nicconfig get * /format:list > "%outputDir%\NIC_Config.txt" 2>&1
echo [+] Network Config: OK

:: ===== USUARIOS Y GRUPOS =====
echo [*] [3/15] Recopilando informacion de usuarios...
echo [%date% %time%] Users and Groups >> "%logFile%"
net user > "%outputDir%\NetUsers.txt" 2>&1
net localgroup > "%outputDir%\LocalGroups.txt" 2>&1
net localgroup administrators > "%outputDir%\Administrators.txt" 2>&1
net localgroup users > "%outputDir%\Users.txt" 2>&1
net localgroup "Remote Desktop Users" > "%outputDir%\RDP_Users.txt" 2>&1
wmic useraccount get * /format:list > "%outputDir%\UserAccounts.txt" 2>&1
whoami /all > "%outputDir%\CurrentUser_Full.txt" 2>&1
echo [+] Users and Groups: OK

:: ===== SESIONES ACTIVAS (CON MULTIPLES METODOS) =====
echo [*] [4/15] Recopilando sesiones activas...
echo [%date% %time%] Active Sessions >> "%logFile%"
echo === Metodo 1: qwinsta === > "%outputDir%\ActiveSessions.txt"
qwinsta >> "%outputDir%\ActiveSessions.txt" 2>&1

echo. >> "%outputDir%\ActiveSessions.txt"
echo === Metodo 2: query user === >> "%outputDir%\ActiveSessions.txt"
%SystemRoot%\System32\query.exe user >> "%outputDir%\ActiveSessions.txt" 2>&1

echo. >> "%outputDir%\ActiveSessions.txt"
echo === Metodo 3: net session === >> "%outputDir%\ActiveSessions.txt"
net session >> "%outputDir%\ActiveSessions.txt" 2>&1

echo. >> "%outputDir%\ActiveSessions.txt"
echo === Metodo 4: WMIC === >> "%outputDir%\ActiveSessions.txt"
wmic netlogin get name,lastlogon,badpasswordcount /format:list >> "%outputDir%\ActiveSessions.txt" 2>&1
wmic computersystem get username /format:list >> "%outputDir%\ActiveSessions.txt" 2>&1
echo [+] Active Sessions: OK

:: ===== SERVICIOS =====
echo [*] [5/15] Recopilando servicios...
echo [%date% %time%] Services >> "%logFile%"
sc query type= service state= all > "%outputDir%\Services_Query.txt" 2>&1
net start > "%outputDir%\Services_Running.txt" 2>&1
wmic service get name,displayname,pathname,startmode,state,processid /format:list > "%outputDir%\Services_Detail.txt" 2>&1
echo [+] Services: OK

:: ===== PROCESOS =====
echo [*] [6/15] Recopilando procesos...
echo [%date% %time%] Processes >> "%logFile%"
tasklist > "%outputDir%\Processes.txt" 2>&1
tasklist /v > "%outputDir%\Processes_Verbose.txt" 2>&1
tasklist /svc > "%outputDir%\Processes_Services.txt" 2>&1
tasklist /m > "%outputDir%\Processes_Modules.txt" 2>&1
wmic process get * /format:list > "%outputDir%\Processes_Detail.txt" 2>&1
wmic process get processid,parentprocessid,name,executablepath,commandline /format:csv > "%outputDir%\Processes_Tree.csv" 2>&1
echo [+] Processes: OK

:: ===== DRIVERS =====
echo [*] [7/15] Recopilando drivers...
echo [%date% %time%] Drivers >> "%logFile%"
driverquery > "%outputDir%\Drivers.txt" 2>&1
driverquery /v > "%outputDir%\Drivers_Verbose.txt" 2>&1
driverquery /fo csv /v > "%outputDir%\Drivers.csv" 2>&1
echo [+] Drivers: OK

:: ===== SOFTWARE INSTALADO =====
echo [*] [8/15] Recopilando software instalado...
echo [%date% %time%] Installed Software >> "%logFile%"
wmic product get name,version,vendor,installdate /format:list > "%outputDir%\InstalledSoftware_WMIC.txt" 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall > "%outputDir%\InstalledSoftware_Reg64.txt" 2>&1
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall > "%outputDir%\InstalledSoftware_Reg32.txt" 2>&1
echo [+] Installed Software: OK

:: ===== TAREAS PROGRAMADAS =====
echo [*] [9/15] Recopilando tareas programadas...
echo [%date% %time%] Scheduled Tasks >> "%logFile%"
schtasks /query > "%outputDir%\ScheduledTasks.txt" 2>&1
schtasks /query /fo LIST /v > "%outputDir%\ScheduledTasks_Verbose.txt" 2>&1
echo [+] Scheduled Tasks: OK

:: ===== ELEMENTOS DE INICIO =====
echo [*] [10/15] Recopilando elementos de inicio...
echo [%date% %time%] Startup Items >> "%logFile%"
wmic startup get * /format:list > "%outputDir%\StartupItems.txt" 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run > "%outputDir%\Registry_Run_HKLM.txt" 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce > "%outputDir%\Registry_RunOnce_HKLM.txt" 2>&1
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run > "%outputDir%\Registry_Run_HKCU.txt" 2>&1
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce > "%outputDir%\Registry_RunOnce_HKCU.txt" 2>&1
echo [+] Startup Items: OK

:: ===== FIREWALL =====
echo [*] [11/15] Recopilando configuracion de firewall...
echo [%date% %time%] Firewall >> "%logFile%"
netsh advfirewall show allprofiles > "%outputDir%\Firewall_Status.txt" 2>&1
netsh advfirewall firewall show rule name=all > "%outputDir%\Firewall_Rules.txt" 2>&1
netsh advfirewall show currentprofile > "%outputDir%\Firewall_CurrentProfile.txt" 2>&1
echo [+] Firewall: OK

:: ===== RECURSOS COMPARTIDOS =====
echo [*] [12/15] Recopilando recursos compartidos...
echo [%date% %time%] Shares >> "%logFile%"
net share > "%outputDir%\Shares.txt" 2>&1
net use > "%outputDir%\MappedDrives.txt" 2>&1
net file > "%outputDir%\OpenFiles.txt" 2>&1
wmic share get * /format:list > "%outputDir%\Shares_Detail.txt" 2>&1
echo [+] Shares: OK

:: ===== VARIABLES DE ENTORNO =====
echo [*] [13/15] Recopilando variables de entorno...
echo [%date% %time%] Environment >> "%logFile%"
set > "%outputDir%\EnvironmentVariables.txt" 2>&1
echo [+] Environment: OK

:: ===== DISCOS =====
echo [*] [14/15] Recopilando informacion de almacenamiento...
echo [%date% %time%] Disks >> "%logFile%"
wmic logicaldisk get * /format:list > "%outputDir%\LogicalDisks.txt" 2>&1
wmic diskdrive get * /format:list > "%outputDir%\PhysicalDisks.txt" 2>&1
wmic partition get * /format:list > "%outputDir%\Partitions.txt" 2>&1
fsutil fsinfo drives > "%outputDir%\Drives.txt" 2>&1
echo [+] Disks: OK

:: ===== EVENTOS DE SEGURIDAD (ultimos 100) =====
echo [*] [15/15] Extrayendo eventos de seguridad...
echo [%date% %time%] Security Events >> "%logFile%"
wevtutil qe Security /c:100 /rd:true /f:text > "%outputDir%\SecurityEvents.txt" 2>&1
wevtutil qe System /c:100 /rd:true /f:text > "%outputDir%\SystemEvents.txt" 2>&1
wevtutil qe Application /c:100 /rd:true /f:text > "%outputDir%\ApplicationEvents.txt" 2>&1
echo [+] Events: OK

:: ===== RESUMEN =====
echo.
echo ========================================
echo [+] Recoleccion completada!
echo ========================================
echo [+] Fin: %date% %time% >> "%logFile%"
echo [+] Archivos guardados en: %outputDir%
echo.

:: Contar archivos generados
set filecount=0
for %%f in ("%outputDir%\*.*") do set /a filecount+=1
echo [+] Total de archivos generados: %filecount%
echo [+] Total de archivos generados: %filecount% >> "%logFile%"

echo.
echo [+] Presiona cualquier tecla para abrir la carpeta de evidencia...
pause >nul
explorer "%outputDir%"