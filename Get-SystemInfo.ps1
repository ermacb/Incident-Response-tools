<#
.SYNOPSIS
    Recopila información detallada del sistema - Versión robusta
.DESCRIPTION
    Script mejorado con manejo de errores y métodos alternativos
.AUTHOR
    Betto - CSIRT México
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IR_Collection"
)

# Función para ejecutar comandos con manejo de errores
function Invoke-SafeCommand {
    param(
        [string]$Description,
        [scriptblock]$Command,
        [string]$OutputFile
    )
    
    try {
        Write-Host "  [*] $Description" -ForegroundColor Cyan
        & $Command | Out-File $OutputFile -ErrorAction Stop
        Write-Host "    [+] Completado" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "    [!] Error: $_" -ForegroundColor Red
        "Error ejecutando comando: $_" | Out-File $OutputFile
        return $false
    }
}

# Crear carpeta de salida
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "$OutputPath`_$timestamp"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CSIRT - Recolección de Información" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[+] Carpeta de salida: $outputDir" -ForegroundColor Green
Write-Host "[+] Inicio: $(Get-Date)" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

# Log de ejecución
$logFile = "$outputDir\execution.log"
"Inicio: $(Get-Date)" | Out-File $logFile
"Hostname: $env:COMPUTERNAME" | Out-File $logFile -Append
"Usuario: $env:USERNAME" | Out-File $logFile -Append
"`n" | Out-File $logFile -Append

# ===== 1. INFORMACIÓN DEL SISTEMA =====
Write-Host "[1/15] Información del Sistema" -ForegroundColor Yellow

Invoke-SafeCommand -Description "ComputerInfo" -OutputFile "$outputDir\SystemInfo.txt" -Command {
    Get-ComputerInfo
}

Invoke-SafeCommand -Description "SystemInfo (CMD)" -OutputFile "$outputDir\SystemInfo_Detail.txt" -Command {
    systeminfo
}

Invoke-SafeCommand -Description "BIOS Info" -OutputFile "$outputDir\BIOS.txt" -Command {
    Get-CimInstance -ClassName Win32_BIOS
}

Invoke-SafeCommand -Description "OS Info" -OutputFile "$outputDir\OS_Info.txt" -Command {
    Get-CimInstance -ClassName Win32_OperatingSystem
}

# ===== 2. INFORMACIÓN DE RED =====
Write-Host "`n[2/15] Configuración de Red" -ForegroundColor Yellow

Invoke-SafeCommand -Description "IPConfig" -OutputFile "$outputDir\NetworkConfig.txt" -Command {
    ipconfig /all
}

Invoke-SafeCommand -Description "IP Addresses" -OutputFile "$outputDir\IPAddresses.txt" -Command {
    Get-NetIPAddress
}

Invoke-SafeCommand -Description "Routing Table" -OutputFile "$outputDir\RoutingTable.txt" -Command {
    Get-NetRoute
}

Invoke-SafeCommand -Description "ARP Cache" -OutputFile "$outputDir\ARP_Cache.txt" -Command {
    arp -a
}

Invoke-SafeCommand -Description "DNS Cache" -OutputFile "$outputDir\DNS_Cache.txt" -Command {
    Get-DnsClientCache
}

# ===== 3. USUARIOS Y SESIONES =====
Write-Host "`n[3/15] Usuarios y Sesiones" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Local Users" -OutputFile "$outputDir\LocalUsers.txt" -Command {
    Get-LocalUser | Select-Object *
}

Invoke-SafeCommand -Description "Administrators" -OutputFile "$outputDir\Administrators.txt" -Command {
    Get-LocalGroupMember -Group "Administrators"
}

# Sesiones activas - Múltiples métodos
Write-Host "  [*] Sesiones Activas (múltiples métodos)" -ForegroundColor Cyan

# Método 1: quser
try {
    $quserPath = "$env:SystemRoot\System32\quser.exe"
    if (Test-Path $quserPath) {
        & $quserPath 2>&1 | Out-File "$outputDir\ActiveSessions_quser.txt"
        Write-Host "    [+] quser: OK" -ForegroundColor Green
    }
} catch {
    "quser error: $_" | Out-File "$outputDir\ActiveSessions_quser.txt"
    Write-Host "    [!] quser: Error" -ForegroundColor Red
}

# Método 2: qwinsta
try {
    $qwinstaPath = "$env:SystemRoot\System32\qwinsta.exe"
    if (Test-Path $qwinstaPath) {
        & $qwinstaPath 2>&1 | Out-File "$outputDir\ActiveSessions_qwinsta.txt"
        Write-Host "    [+] qwinsta: OK" -ForegroundColor Green
    }
} catch {
    "qwinsta error: $_" | Out-File "$outputDir\ActiveSessions_qwinsta.txt"
    Write-Host "    [!] qwinsta: Error" -ForegroundColor Red
}

# Método 3: WMI Logon Sessions
try {
    Get-CimInstance -ClassName Win32_LogonSession | 
        Out-File "$outputDir\LogonSessions_WMI.txt"
    Write-Host "    [+] WMI LogonSession: OK" -ForegroundColor Green
} catch {
    "WMI error: $_" | Out-File "$outputDir\LogonSessions_WMI.txt"
    Write-Host "    [!] WMI LogonSession: Error" -ForegroundColor Red
}

# Método 4: WMI Logged On User
try {
    Get-CimInstance -ClassName Win32_LoggedOnUser | 
        Select-Object Antecedent, Dependent | 
        Out-File "$outputDir\LoggedOnUsers_WMI.txt"
    Write-Host "    [+] WMI LoggedOnUser: OK" -ForegroundColor Green
} catch {
    "WMI error: $_" | Out-File "$outputDir\LoggedOnUsers_WMI.txt"
    Write-Host "    [!] WMI LoggedOnUser: Error" -ForegroundColor Red
}

# Método 5: Usuario actual
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
"Usuario ejecutando script: $currentUser" | Out-File "$outputDir\CurrentUser.txt"
"Privilegios: $([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" | 
    Out-File "$outputDir\CurrentUser.txt" -Append

# Net users
net user | Out-File "$outputDir\NetUsers.txt"

# ===== 4. TAREAS PROGRAMADAS =====
Write-Host "`n[4/15] Tareas Programadas" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Scheduled Tasks" -OutputFile "$outputDir\ScheduledTasks.txt" -Command {
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | 
        Select-Object TaskName, TaskPath, State, Author, Date
}

Invoke-SafeCommand -Description "Scheduled Tasks Detail" -OutputFile "$outputDir\ScheduledTasks_Detail.txt" -Command {
    schtasks /query /fo LIST /v
}

# ===== 5. SERVICIOS =====
Write-Host "`n[5/15] Servicios" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Services" -OutputFile "$outputDir\Services.txt" -Command {
    Get-Service | Select-Object Name, DisplayName, Status, StartType
}

Invoke-SafeCommand -Description "Services Detail" -OutputFile "$outputDir\Services_Detail.txt" -Command {
    Get-CimInstance Win32_Service | 
        Select-Object Name, DisplayName, State, PathName, StartMode, StartName, ProcessId
}

# ===== 6. SOFTWARE INSTALADO =====
Write-Host "`n[6/15] Software Instalado" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Installed Software (64-bit)" -OutputFile "$outputDir\InstalledSoftware_64.txt" -Command {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}

Invoke-SafeCommand -Description "Installed Software (32-bit)" -OutputFile "$outputDir\InstalledSoftware_32.txt" -Command {
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}

# ===== 7. AUTORUN/STARTUP =====
Write-Host "`n[7/15] Elementos de Inicio" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Startup Commands" -OutputFile "$outputDir\StartupItems.txt" -Command {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
}

Invoke-SafeCommand -Description "Registry Run (HKLM)" -OutputFile "$outputDir\Registry_Run_HKLM.txt" -Command {
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
}

Invoke-SafeCommand -Description "Registry Run (HKCU)" -OutputFile "$outputDir\Registry_Run_HKCU.txt" -Command {
    Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
}

# ===== 8. PROCESOS =====
Write-Host "`n[8/15] Procesos" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Process List" -OutputFile "$outputDir\ProcessList.txt" -Command {
    Get-Process | Select-Object ProcessName, Id, Path, Company, Description, StartTime
}

Invoke-SafeCommand -Description "Process Details" -OutputFile "$outputDir\ProcessDetails.csv" -Command {
    Get-Process | Select-Object ProcessName, Id, Path, Company, Description, 
        @{Name="WorkingSetMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}, 
        @{Name="CPU";Expression={$_.CPU}}, StartTime |
        Export-Csv "$outputDir\ProcessDetails.csv" -NoTypeInformation
}

# ===== 9. CONEXIONES DE RED =====
Write-Host "`n[9/15] Conexiones de Red" -ForegroundColor Yellow

Invoke-SafeCommand -Description "TCP Connections" -OutputFile "$outputDir\TCP_Connections.txt" -Command {
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
}

Invoke-SafeCommand -Description "Netstat" -OutputFile "$outputDir\Netstat.txt" -Command {
    netstat -ano
}

# ===== 10. LOGS DE SEGURIDAD =====
Write-Host "`n[10/15] Logs de Seguridad" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Security Events" -OutputFile "$outputDir\SecurityLog.csv" -Command {
    Get-WinEvent -LogName Security -MaxEvents 500 | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv "$outputDir\SecurityLog.csv" -NoTypeInformation
}

Invoke-SafeCommand -Description "System Events" -OutputFile "$outputDir\SystemLog.csv" -Command {
    Get-WinEvent -LogName System -MaxEvents 500 | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv "$outputDir\SystemLog.csv" -NoTypeInformation
}

# ===== 11. FIREWALL =====
Write-Host "`n[11/15] Firewall" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Firewall Rules" -OutputFile "$outputDir\FirewallRules.txt" -Command {
    Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | 
        Select-Object DisplayName, Direction, Action, Enabled
}

Invoke-SafeCommand -Description "Firewall Status" -OutputFile "$outputDir\FirewallStatus.txt" -Command {
    netsh advfirewall show allprofiles
}

# ===== 12. VARIABLES DE ENTORNO =====
Write-Host "`n[12/15] Variables de Entorno" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Environment Variables" -OutputFile "$outputDir\EnvironmentVariables.txt" -Command {
    Get-ChildItem Env:
}

# ===== 13. ALMACENAMIENTO =====
Write-Host "`n[13/15] Almacenamiento" -ForegroundColor Yellow

Invoke-SafeCommand -Description "Volumes" -OutputFile "$outputDir\Volumes.txt" -Command {
    Get-Volume
}

Invoke-SafeCommand -Description "Disks" -OutputFile "$outputDir\Disks.txt" -Command {
    Get-Disk
}

Invoke-SafeCommand -Description "Partitions" -OutputFile "$outputDir\Partitions.txt" -Command {
    Get-Partition
}

# ===== 14. DRIVERS =====
Write-Host "`n[14/15] Drivers" -ForegroundColor Yellow

Invoke-SafeCommand -Description "System Drivers" -OutputFile "$outputDir\Drivers.txt" -Command {
    Get-WindowsDriver -Online -All
}

# ===== 15. HASHES DE INTEGRIDAD =====
Write-Host "`n[15/15] Generando Hashes" -ForegroundColor Yellow

$files = Get-ChildItem -Path $outputDir -File
$hashFile = "$outputDir\FileHashes.txt"
"=== HASHES DE INTEGRIDAD ===" | Out-File $hashFile
"Fecha: $(Get-Date)" | Out-File $hashFile -Append
"Total archivos: $($files.Count)" | Out-File $hashFile -Append
"`n" | Out-File $hashFile -Append

foreach ($file in $files) {
    if ($file.Name -ne "FileHashes.txt") {
        try {
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
            "$($file.Name): $($hash.Hash)" | Out-File $hashFile -Append
        } catch {
            "$($file.Name): Error calculando hash" | Out-File $hashFile -Append
        }
    }
}

# ===== RESUMEN FINAL =====
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "[+] Recolección completada!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[+] Archivos generados: $($files.Count)" -ForegroundColor Green
Write-Host "[+] Ubicación: $outputDir" -ForegroundColor Cyan
Write-Host "[+] Fin: $(Get-Date)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

"Fin: $(Get-Date)" | Out-File $logFile -Append
"Archivos generados: $($files.Count)" | Out-File $logFile -Append