@echo off
setlocal enabledelayedexpansion
title Memory Dump - Incident Response (CSIRT)

:: ===== VERIFICAR PRIVILEGIOS DE ADMINISTRADOR =====
echo [*] Verificando privilegios de administrador...
net session >nul 2>&1
if %errorLevel% neq 0 (
    color 0C
    echo.
    echo ========================================
    echo [!] ERROR: PRIVILEGIOS INSUFICIENTES
    echo ========================================
    echo.
    echo Este script REQUIERE privilegios de Administrador
    echo para realizar memory dumps.
    echo.
    echo Por favor:
    echo 1. Cierra esta ventana
    echo 2. Click derecho en el script
    echo 3. Selecciona "Ejecutar como administrador"
    echo.
    pause
    exit /b 1
)

echo [+] Privilegios de administrador: OK
echo.

set timestamp=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set timestamp=%timestamp: =0%
set outputDir=C:\MemoryDumps\MemDump_%timestamp%
mkdir "%outputDir%" 2>nul

echo ========================================
echo   CSIRT - Memory Dump Collection
echo ========================================
echo [+] Directorio de salida: %outputDir%
echo [+] Inicio: %date% %time%
echo ========================================
echo.
echo [!] NOTA: El dump de LSASS puede ser bloqueado por:
echo     - Windows Defender
echo     - Credential Guard
echo     - Protected Process Light (PPL)
echo     - Otras soluciones EDR/AV
echo.

:: Log de ejecución
set logFile=%outputDir%\execution.log
echo Inicio de memory dump: %date% %time% > "%logFile%"
echo Hostname: %COMPUTERNAME% >> "%logFile%"
echo Usuario: %USERNAME% >> "%logFile%"
echo. >> "%logFile%"

:: ===== OBTENER PID DE LSASS =====
echo [*] Identificando proceso LSASS...
for /f "tokens=2" %%a in ('tasklist /fi "imagename eq lsass.exe" ^| find "lsass.exe"') do (
    set lsassPID=%%a
)

if not defined lsassPID (
    echo [!] ERROR: No se pudo encontrar el proceso LSASS
    echo [!] ERROR: LSASS no encontrado >> "%logFile%"
    goto :SKIP_LSASS
)

echo [+] LSASS PID: %lsassPID%
echo LSASS PID: %lsassPID% >> "%logFile%"

:: ===== METODO 1: RUNDLL32 (COMSVCS) =====
echo.
echo [*] Metodo 1: Intentando dump con rundll32 (comsvcs.dll)...
echo [%date% %time%] Metodo 1: rundll32 >> "%logFile%"

rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump %lsassPID% "%outputDir%\lsass_comsvcs.dmp" full 2>nul

if exist "%outputDir%\lsass_comsvcs.dmp" (
    echo [+] Dump de LSASS exitoso con rundll32!
    echo [+] Archivo: lsass_comsvcs.dmp
    echo [+] Metodo 1 exitoso >> "%logFile%"
    set LSASS_DUMPED=1
) else (
    echo [!] Metodo 1 fallo - Acceso denegado o bloqueado por AV/EDR
    echo [!] Metodo 1 fallo >> "%logFile%"
    set LSASS_DUMPED=0
)

:: ===== METODO 2: PROCDUMP (SI ESTA DISPONIBLE) =====
if !LSASS_DUMPED! equ 0 (
    echo.
    echo [*] Metodo 2: Intentando con ProcDump de Sysinternals...
    echo [%date% %time%] Metodo 2: ProcDump >> "%logFile%"
    
    if exist "%SystemRoot%\System32\procdump.exe" (
        procdump.exe -ma %lsassPID% "%outputDir%\lsass_procdump.dmp" -accepteula 2>nul
        if exist "%outputDir%\lsass_procdump.dmp" (
            echo [+] Dump de LSASS exitoso con ProcDump!
            echo [+] Metodo 2 exitoso >> "%logFile%"
            set LSASS_DUMPED=1
        ) else (
            echo [!] Metodo 2 fallo
            echo [!] Metodo 2 fallo >> "%logFile%"
        )
    ) else (
        echo [!] ProcDump no encontrado en System32
        echo [!] Descarga desde: https://docs.microsoft.com/sysinternals/downloads/procdump
        echo [!] ProcDump no disponible >> "%logFile%"
    )
)

:: ===== METODO 3: TASK MANAGER API =====
if !LSASS_DUMPED! equ 0 (
    echo.
    echo [*] Metodo 3: Dump manual necesario via Task Manager
    echo [!] Los metodos automaticos fueron bloqueados
    echo.
    echo INSTRUCCIONES MANUALES:
    echo 1. Abrir Task Manager (Ctrl+Shift+Esc)
    echo 2. Ir a la pestaña "Detalles"
    echo 3. Buscar "lsass.exe"
    echo 4. Click derecho ^> "Create dump file"
    echo 5. Copiar el archivo dump a: %outputDir%
    echo.
    echo [!] Metodo 3: Manual requerido >> "%logFile%"
)

:SKIP_LSASS

:: ===== VERIFICAR SI CREDENTIAL GUARD ESTA ACTIVO =====
echo.
echo [*] Verificando protecciones de sistema...
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" >nul 2>&1
if %errorlevel% equ 0 (
    echo [!] ADVERTENCIA: Credential Guard puede estar activo
    echo [!] Esto previene el dump de credenciales de LSASS
    echo [!] Credential Guard detectado >> "%logFile%"
) else (
    echo [+] Credential Guard no detectado
)

:: Verificar RunAsPPL (Protected Process Light)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPL" >nul 2>&1
if %errorlevel% equ 0 (
    echo [!] ADVERTENCIA: LSASS esta corriendo como Protected Process (PPL)
    echo [!] Esto bloquea el acceso para hacer dumps
    echo [!] PPL activo en LSASS >> "%logFile%"
) else (
    echo [+] PPL no detectado en LSASS
)

:: ===== DUMP DE OTROS PROCESOS CRITICOS =====
echo.
echo ========================================
echo [*] Generando dumps de otros procesos criticos...
echo ========================================

:: Array de procesos a dumpear
set processes=svchost explorer winlogon services csrss

for %%p in (%processes%) do (
    echo.
    echo [*] Dumping proceso: %%p
    
    :: Obtener primer PID del proceso
    for /f "tokens=2" %%a in ('tasklist /fi "imagename eq %%p.exe" ^| find "%%p.exe"') do (
        set procPID=%%a
        goto :FOUND_PID
    )
    :FOUND_PID
    
    if defined procPID (
        echo [+] PID de %%p: !procPID!
        
        :: Intentar dump con rundll32
        rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump !procPID! "%outputDir%\%%p_!procPID!.dmp" full 2>nul
        
        if exist "%outputDir%\%%p_!procPID!.dmp" (
            echo [+] Dump exitoso: %%p_!procPID!.dmp
        ) else (
            echo [!] Dump fallo para %%p
        )
        set procPID=
    ) else (
        echo [!] No se encontro proceso %%p
    )
)

:: ===== INFORMACION DE PROCESOS =====
echo.
echo [*] Recopilando informacion de procesos en memoria...
tasklist /v > "%outputDir%\ProcessList.txt" 2>&1
wmic process get * /format:list > "%outputDir%\ProcessDetail.txt" 2>&1
tasklist /m > "%outputDir%\LoadedDLLs.txt" 2>&1

:: ===== INFORMACION DE MEMORIA =====
echo [*] Recopilando informacion de memoria del sistema...
wmic memorychip get * /format:list > "%outputDir%\MemoryHardware.txt" 2>&1
wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /format:list > "%outputDir%\MemoryStatus.txt" 2>&1
systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory" > "%outputDir%\MemoryInfo.txt" 2>&1

:: ===== DRIVERS CARGADOS =====
echo [*] Listando drivers cargados en memoria...
driverquery /v > "%outputDir%\Drivers.txt" 2>&1
driverquery /fo csv /v > "%outputDir%\Drivers.csv" 2>&1

:: ===== HANDLES ABIERTOS =====
echo [*] Listando handles (requiere handle.exe de Sysinternals)...
if exist "%SystemRoot%\System32\handle.exe" (
    handle.exe -a > "%outputDir%\Handles.txt" 2>&1
    echo [+] Handles exportados
) else (
    echo [!] handle.exe no encontrado
    echo [!] Descarga desde: https://docs.microsoft.com/sysinternals/downloads/handle
)

:: ===== RESUMEN =====
echo.
echo ========================================
echo [+] Captura de memoria completada
echo ========================================

:: Generar resumen
echo. > "%outputDir%\SUMMARY.txt"
echo ======================================== >> "%outputDir%\SUMMARY.txt"
echo   RESUMEN DE MEMORY DUMP >> "%outputDir%\SUMMARY.txt"
echo ======================================== >> "%outputDir%\SUMMARY.txt"
echo Fecha: %date% %time% >> "%outputDir%\SUMMARY.txt"
echo Hostname: %COMPUTERNAME% >> "%outputDir%\SUMMARY.txt"
echo. >> "%outputDir%\SUMMARY.txt"

:: Listar archivos .dmp creados
echo DUMPS GENERADOS: >> "%outputDir%\SUMMARY.txt"
dir /b "%outputDir%\*.dmp" >> "%outputDir%\SUMMARY.txt" 2>nul
if errorlevel 1 (
    echo [!] No se generaron dumps >> "%outputDir%\SUMMARY.txt"
    echo.
    echo [!] ADVERTENCIA: No se pudieron generar dumps
    echo [!] Posibles causas:
    echo     1. Windows Defender bloqueando
    echo     2. Credential Guard activo
    echo     3. EDR/AV bloqueando
    echo     4. LSASS protegido (PPL)
    echo.
    echo RECOMENDACIONES:
    echo 1. Deshabilitar temporalmente Windows Defender Real-Time Protection
    echo 2. Usar Mimikatz con bypass de protecciones
    echo 3. Ejecutar desde Windows PE/WinRE
    echo 4. Usar herramientas forenses especializadas
) else (
    echo.
    echo [+] Dumps guardados exitosamente
)

echo. >> "%outputDir%\SUMMARY.txt"
echo ANALISIS RECOMENDADO: >> "%outputDir%\SUMMARY.txt"
echo - Volatility Framework >> "%outputDir%\SUMMARY.txt"
echo - WinDbg >> "%outputDir%\SUMMARY.txt"
echo - Mimikatz (sekurlsa::minidump) >> "%outputDir%\SUMMARY.txt"
echo - Rekall >> "%outputDir%\SUMMARY.txt"
echo. >> "%outputDir%\SUMMARY.txt"

type "%outputDir%\SUMMARY.txt"

echo.
echo [+] Fin de ejecucion: %date% %time% >> "%logFile%"
echo [+] Archivos guardados en: %outputDir%
echo.
echo [!] IMPORTANTE: Estos dumps contienen credenciales sensibles
echo [!] Mantener en almacenamiento seguro y cifrado
echo [!] Eliminar despues del analisis
echo.
pause