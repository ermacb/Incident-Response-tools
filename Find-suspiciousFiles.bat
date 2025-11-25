@echo off
setlocal enabledelayedexpansion
title Busqueda de Archivos Sospechosos - IR

set timestamp=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set timestamp=%timestamp: =0%
set outputDir=C:\IR_SuspiciousFiles\Scan_%timestamp%
mkdir "%outputDir%"

echo [+] Iniciando busqueda de archivos sospechosos...
echo [+] Directorio de salida: %outputDir%
echo.

:: Buscar archivos ejecutables recientes
echo [*] Buscando archivos ejecutables recientes...
forfiles /P C:\ /S /M *.exe /D -7 /C "cmd /c echo @path @fdate @ftime" 2>nul > "%outputDir%\RecentEXE.txt"
forfiles /P C:\ /S /M *.dll /D -7 /C "cmd /c echo @path @fdate @ftime" 2>nul > "%outputDir%\RecentDLL.txt"

:: Buscar scripts
echo [*] Buscando scripts recientes...
forfiles /P C:\ /S /M *.bat /D -7 /C "cmd /c echo @path @fdate @ftime" 2>nul > "%outputDir%\RecentBAT.txt"
forfiles /P C:\ /S /M *.cmd /D -7 /C "cmd /c echo @path @fdate @ftime" 2>nul > "%outputDir%\RecentCMD.txt"
forfiles /P C:\ /S /M *.ps1 /D -7 /C "cmd /c echo @path @fdate @ftime" 2>nul > "%outputDir%\RecentPS1.txt"
forfiles /P C:\ /S /M *.vbs /D -7 /C "cmd /c echo @path @fdate @ftime" 2>nul > "%outputDir%\RecentVBS.txt"

:: Buscar en rutas sospechosas
echo [*] Buscando archivos en rutas sospechosas...
dir "%TEMP%\*.exe" /s /b > "%outputDir%\TEMP_EXE.txt" 2>nul
dir "%TEMP%\*.dll" /s /b > "%outputDir%\TEMP_DLL.txt" 2>nul
dir "%APPDATA%\*.exe" /s /b > "%outputDir%\APPDATA_EXE.txt" 2>nul
dir "C:\Users\Public\*.exe" /s /b > "%outputDir%\Public_EXE.txt" 2>nul
dir "C:\ProgramData\*.exe" /s /b > "%outputDir%\ProgramData_EXE.txt" 2>nul

:: Buscar extensiones de ransomware
echo [*] Buscando extensiones de ransomware...
dir C:\*.encrypted /s /b > "%outputDir%\Ransomware_encrypted.txt" 2>nul
dir C:\*.locked /s /b > "%outputDir%\Ransomware_locked.txt" 2>nul
dir C:\*.crypto /s /b > "%outputDir%\Ransomware_crypto.txt" 2>nul

:: Archivos ocultos
echo [*] Buscando archivos ocultos...
dir C:\*.* /s /a:h /b > "%outputDir%\HiddenFiles.txt" 2>nul

:: Archivos sin extensión
echo [*] Buscando archivos sin extensión en ubicaciones críticas...
dir "%TEMP%\*." /s /b > "%outputDir%\NoExtension_TEMP.txt" 2>nul
dir "%APPDATA%\*." /s /b > "%outputDir%\NoExtension_APPDATA.txt" 2>nul

echo.
echo [+] Busqueda completada!
echo [+] Resultados en: %outputDir%
echo.
pause