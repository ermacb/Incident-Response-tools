@echo off
setlocal enabledelayedexpansion
title Analisis Detallado de Procesos - IR

set timestamp=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set timestamp=%timestamp: =0%
set outputDir=C:\IR_ProcessAnalysis\ProcessAnalysis_%timestamp%
mkdir "%outputDir%"

echo [+] Iniciando analisis detallado de procesos...
echo [+] Directorio de salida: %outputDir%
echo.

:: Lista de procesos basica
echo [*] Recopilando lista de procesos...
tasklist > "%outputDir%\Processes.txt"
tasklist /v > "%outputDir%\Processes_Verbose.txt"
tasklist /svc > "%outputDir%\Processes_Services.txt"
tasklist /m > "%outputDir%\Processes_DLLs.txt"

:: Informacion detallada con WMIC
echo [*] Recopilando informacion detallada con WMIC...
wmic process get * /format:list > "%outputDir%\Processes_WMIC_Full.txt"
wmic process get ProcessId,Name,ExecutablePath,CommandLine,CreationDate,ParentProcessId /format:csv > "%outputDir%\Processes_Detail.csv"

:: Arbol de procesos
echo [*] Generando arbol de procesos...
wmic process get ProcessId,ParentProcessId,Name,ExecutablePath /format:csv > "%outputDir%\Process_Tree.csv"

:: Servicios en ejecucion
echo [*] Recopilando servicios...
sc query type= service state= all > "%outputDir%\Services_All.txt"
net start > "%outputDir%\Services_Running.txt"
wmic service get Name,DisplayName,PathName,StartMode,State,ProcessId /format:csv > "%outputDir%\Services_Detail.csv"

:: Drivers cargados
echo [*] Listando drivers cargados...
driverquery /v > "%outputDir%\Drivers.txt"
driverquery /fo csv /v > "%outputDir%\Drivers.csv"

:: Procesos con conexiones de red
echo [*] Identificando procesos con conexiones de red...
netstat -anob > "%outputDir%\Processes_Network.txt"

:: Buscar procesos sospechosos en ubicaciones temporales
echo [*] Buscando procesos en ubicaciones sospechosas...
wmic process where "ExecutablePath like '%%Temp%%' or ExecutablePath like '%%tmp%%'" get ProcessId,Name,ExecutablePath /format:list > "%outputDir%\Processes_TEMP.txt"
wmic process where "ExecutablePath like '%%AppData%%'" get ProcessId,Name,ExecutablePath /format:list > "%outputDir%\Processes_AppData.txt"
wmic process where "ExecutablePath like '%%Public%%'" get ProcessId,Name,ExecutablePath /format:list > "%outputDir%\Processes_Public.txt"

:: Procesos del SYSTEM
echo [*] Identificando procesos del SYSTEM...
wmic process where "Caption like '%%svchost%%'" get ProcessId,Name,CommandLine /format:list > "%outputDir%\Svchost_Processes.txt"

:: Handles abiertos
echo [*] Listando handles (requiere handle.exe de Sysinternals)...
if exist "%SystemRoot%\System32\handle.exe" (
    handle.exe -a > "%outputDir%\Handles.txt"
) else (
    echo Handle.exe no encontrado - omitiendo >> "%outputDir%\Handles.txt"
)

:: Tareas programadas
echo [*] Recopilando tareas programadas...
schtasks /query /fo LIST /v > "%outputDir%\Scheduled_Tasks.txt"

:: Autorun entries
echo [*] Recopilando elementos de inicio...
wmic startup get * /format:list > "%outputDir%\Startup_Items.txt"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run > "%outputDir%\Registry_Run_HKLM.txt"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run > "%outputDir%\Registry_Run_HKCU.txt"

:: WMI persistence
echo [*] Verificando persistencia via WMI...
wmic /namespace:\\root\subscription PATH __EventFilter GET * /format:list > "%outputDir%\WMI_EventFilters.txt"
wmic /namespace:\\root\subscription PATH CommandLineEventConsumer GET * /format:list > "%outputDir%\WMI_Consumers.txt"

:: Performance counters
echo [*] Recopilando contadores de rendimiento...
typeperf "\Processor(_Total)\%% Processor Time" -sc 1 > "%outputDir%\CPU_Usage.txt"
typeperf "\Memory\Available MBytes" -sc 1 > "%outputDir%\Memory_Available.txt"

echo.
echo [+] Analisis de procesos completado!
echo [+] Resultados en: %outputDir%
echo.
pause