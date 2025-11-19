# ============================================
# Script de Simulacion: Reconocimiento
# Proposito: Ejercicio Table Top - NO MALICIOSO
# Uso: SOLO en entornos de prueba autorizados
# ============================================

Write-Host "=== SIMULACION DE RECONOCIMIENTO INICIADA ===" -ForegroundColor Yellow
Write-Host "Este script genera actividad de reconocimiento para entrenamiento SOC" -ForegroundColor Cyan

# 1. Enumeracion de Sistema
Write-Host "`n[+] Fase 1: Recoleccion de Informacion del Sistema" -ForegroundColor Green

# Informacion basica del sistema
$sysInfo = @{
    ComputerName = $env:COMPUTERNAME
    Username = $env:USERNAME
    Domain = $env:USERDOMAIN
    OSVersion = [System.Environment]::OSVersion.VersionString
    Architecture = [System.Environment]::Is64BitOperatingSystem
    CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

# Guardar informacion en archivo temporal (simulacion de staging)
$outputPath = "$env:TEMP\sysinfo_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$sysInfo | Out-File -FilePath $outputPath

Write-Host "[*] Informacion del sistema recolectada: $outputPath" -ForegroundColor Yellow

# 2. Enumeracion de Procesos Sensibles
Write-Host "`n[+] Fase 2: Enumeracion de Procesos" -ForegroundColor Green

$targetProcesses = @('lsass', 'winlogon', 'services', 'svchost')
foreach ($proc in $targetProcesses) {
    try {
        $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($processes) {
            Write-Host "[*] Proceso detectado: $proc (PID: $($processes[0].Id))" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Error al enumerar proceso: $proc" -ForegroundColor Red
    }
}

# 3. Enumeracion de Red
Write-Host "`n[+] Fase 3: Reconocimiento de Red" -ForegroundColor Green

# Obtener configuracion de red
$networkConfig = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -notlike '127.*'}
foreach ($adapter in $networkConfig) {
    Write-Host "[*] Interface: $($adapter.InterfaceAlias) - IP: $($adapter.IPAddress)" -ForegroundColor Yellow
}

# Enumeracion de conexiones activas
Write-Host "`n[*] Conexiones de red activas:" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort -First 10

# 4. Enumeracion de Usuarios y Grupos
Write-Host "`n[+] Fase 4: Enumeracion de Usuarios" -ForegroundColor Green

# Usuarios locales
$localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon
Write-Host "[*] Usuarios locales encontrados: $($localUsers.Count)" -ForegroundColor Yellow

# Grupos locales con privilegios
$adminGroup = Get-LocalGroupMember -Group "Administradores" -ErrorAction SilentlyContinue
if ($adminGroup) {
    Write-Host "[*] Miembros del grupo Administradores: $($adminGroup.Count)" -ForegroundColor Yellow
}

# 5. Enumeracion de Recursos Compartidos
Write-Host "`n[+] Fase 5: Enumeracion de Recursos Compartidos" -ForegroundColor Green

try {
    $shares = Get-SmbShare
    foreach ($share in $shares) {
        Write-Host "[*] Recurso compartido: $($share.Name) - Ruta: $($share.Path)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] No se pudieron enumerar recursos compartidos" -ForegroundColor Red
}

# 6. Busqueda de Archivos Sensibles (simulacion)
Write-Host "`n[+] Fase 6: Busqueda de Archivos de Interes" -ForegroundColor Green

$searchPaths = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop"
)

$interestingExtensions = @('*.txt', '*.docx', '*.xlsx', '*.pdf', '*.config')

foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        foreach ($ext in $interestingExtensions) {
            $files = Get-ChildItem -Path $path -Filter $ext -Recurse -ErrorAction SilentlyContinue -Depth 1 | Select-Object -First 5
            if ($files) {
                Write-Host "[*] Archivos $ext encontrados en $path" -ForegroundColor Yellow
            }
        }
    }
}

# 7. Enumeracion de Tareas Programadas
Write-Host "`n[+] Fase 7: Enumeracion de Tareas Programadas" -ForegroundColor Green

$tasks = Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName, State -First 10
Write-Host "[*] Tareas programadas activas: $($tasks.Count)" -ForegroundColor Yellow

# 8. Informacion de Software Instalado
Write-Host "`n[+] Fase 8: Software Instalado" -ForegroundColor Green

$software = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
            Select-Object DisplayName, DisplayVersion -First 10
Write-Host "[*] Software detectado: $($software.Count) aplicaciones" -ForegroundColor Yellow

# Resumen
Write-Host "`n=== SIMULACION DE RECONOCIMIENTO COMPLETADA ===" -ForegroundColor Green
Write-Host "[!] IMPORTANTE: Eliminar archivos temporales creados en: $env:TEMP" -ForegroundColor Magenta
Write-Host "[!] Este script es solo para entrenamiento y deteccion" -ForegroundColor Magenta

# Cleanup opcional
# Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
