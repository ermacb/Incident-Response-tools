@echo off
setlocal enabledelayedexpansion
title Analisis de Conexiones de Red - IR

set timestamp=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set timestamp=%timestamp: =0%
set outputDir=C:\IR_NetworkAnalysis\NetAnalysis_%timestamp%
mkdir "%outputDir%"

echo [+] Iniciando analisis de conexiones de red...
echo [+] Directorio de salida: %outputDir%
echo.

:: Conexiones activas
echo [*] Recopilando conexiones activas...
netstat -ano > "%outputDir%\Netstat_All.txt"
netstat -anob > "%outputDir%\Netstat_WithProcess.txt"
netstat -anof > "%outputDir%\Netstat_WithFQDN.txt"

:: Conexiones establecidas
echo [*] Filtrando conexiones ESTABLISHED...
netstat -ano | findstr "ESTABLISHED" > "%outputDir%\Established_Connections.txt"

:: Puertos en escucha
echo [*] Identificando puertos en escucha...
netstat -ano | findstr "LISTENING" > "%outputDir%\Listening_Ports.txt"

:: Estadisticas de protocolo
echo [*] Recopilando estadisticas de protocolos...
netstat -s > "%outputDir%\Protocol_Statistics.txt"

:: Tabla de enrutamiento
echo [*] Capturando tabla de enrutamiento...
route print > "%outputDir%\Routing_Table.txt"
netstat -r > "%outputDir%\Routing_Table_Detail.txt"

:: Cache ARP
echo [*] Capturando cache ARP...
arp -a > "%outputDir%\ARP_Cache.txt"

:: Cache DNS
echo [*] Capturando cache DNS...
ipconfig /displaydns > "%outputDir%\DNS_Cache.txt"

:: Configuracion de red
echo [*] Recopilando configuracion de red...
ipconfig /all > "%outputDir%\IPConfig.txt"

:: Configuracion de firewall
echo [*] Recopilando configuracion de firewall...
netsh advfirewall show allprofiles > "%outputDir%\Firewall_Status.txt"
netsh advfirewall firewall show rule name=all verbose > "%outputDir%\Firewall_Rules.txt"

:: Configuracion de proxy
echo [*] Verificando configuracion de proxy...
netsh winhttp show proxy > "%outputDir%\Proxy_Config.txt"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable > "%outputDir%\Proxy_Registry.txt"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer >> "%outputDir%\Proxy_Registry.txt"

:: Recursos compartidos
echo [*] Recopilando recursos compartidos...
net share > "%outputDir%\Shares.txt"
net use > "%outputDir%\Mapped_Drives.txt"

:: Sesiones SMB
echo [*] Recopilando sesiones SMB...
net session > "%outputDir%\SMB_Sessions.txt"
net file > "%outputDir%\Open_Files.txt"

:: WMIC network info
echo [*] Recopilando informacion adicional de red...
wmic nicconfig get * /format:list > "%outputDir%\NIC_Config.txt"
wmic netuse get * /format:list > "%outputDir%\Network_Usage.txt"

:: Analisis de procesos con conexiones
echo [*] Listando procesos con conexiones de red...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr "ESTABLISHED"') do (
    tasklist /FI "PID eq %%a" /V >> "%outputDir%\Processes_With_Connections.txt"
)

:: Buscar conexiones a puertos sospechosos
echo [*] Buscando conexiones a puertos sospechosos...
netstat -ano | findstr ":4444 :5555 :6666 :7777 :8888 :31337 :12345" > "%outputDir%\Suspicious_Ports.txt"

echo.
echo [+] Analisis de red completado!
echo [+] Resultados en: %outputDir%
echo.
pause