<#
.SYNOPSIS
    Obtiene memory dump para análisis forense
.DESCRIPTION
    Genera dumps de memoria usando múltiples métodos
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\MemoryDumps",
    [Parameter(Mandatory=$false)]
    [switch]$FullDump
)

Write-Host "[+] Iniciando captura de memoria..." -ForegroundColor Green

# Crear directorio de salida
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$dumpDir = "$OutputPath\MemDump_$timestamp"
New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null

# Método 1: Usar DumpIt (si está disponible)
if (Test-Path ".\DumpIt.exe") {
    Write-Host "[*] Ejecutando DumpIt..." -ForegroundColor Yellow
    Start-Process -FilePath ".\DumpIt.exe" -ArgumentList "/O $dumpDir\memory.dmp /T RAW /Q" -Wait
}

# Método 2: Windows Memory Dump usando Task Manager API
Write-Host "[*] Generando dumps de procesos críticos..." -ForegroundColor Yellow
$criticalProcesses = @("lsass", "svchost", "explorer", "services")

foreach ($procName in $criticalProcesses) {
    try {
        $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $dumpFile = "$dumpDir\$($proc.Name)_$($proc.Id).dmp"
            Write-Host "  [*] Dumping $($proc.Name) (PID: $($proc.Id))..." -ForegroundColor Cyan
            
            # Usar rundll32 para crear minidump
            rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $proc.Id $dumpFile full
            
            if (Test-Path $dumpFile) {
                Write-Host "    [+] Dump creado: $dumpFile" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "    [-] Error al dumpear $procName : $_" -ForegroundColor Red
    }
}

# Método 3: Captura de memoria usando WinPmem (si está disponible)
if (Test-Path ".\winpmem.exe") {
    Write-Host "[*] Ejecutando WinPmem..." -ForegroundColor Yellow
    Start-Process -FilePath ".\winpmem.exe" -ArgumentList "$dumpDir\memory_raw.aff4" -Wait
}

# Método 4: Información de memoria del sistema
Write-Host "[*] Recopilando información de memoria..." -ForegroundColor Yellow
Get-CimInstance -ClassName Win32_PhysicalMemory | Out-File "$dumpDir\MemoryHardware.txt"
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory | Out-File "$dumpDir\MemoryStatus.txt"

# Método 5: Listar módulos cargados en memoria
Write-Host "[*] Listando módulos en memoria..." -ForegroundColor Yellow
Get-Process | ForEach-Object {
    try {
        $_ | Select-Object ProcessName, Id, @{Name="Modules"; Expression={($_.Modules | Select-Object -ExpandProperty ModuleName) -join ", "}}
    } catch {}
} | Out-File "$dumpDir\LoadedModules.txt"

# Hash de los dumps
Write-Host "[*] Generando hashes de integridad..." -ForegroundColor Yellow
$dumpFiles = Get-ChildItem -Path $dumpDir -Filter "*.dmp" -File
foreach ($file in $dumpFiles) {
    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
    "$($file.Name): $($hash.Hash)" | Out-File "$dumpDir\DumpHashes.txt" -Append
}

Write-Host "[+] Captura de memoria completada!" -ForegroundColor Green
Write-Host "[+] Dumps guardados en: $dumpDir" -ForegroundColor Cyan
Write-Host "[!] IMPORTANTE: Analizar con Volatility, Rekall o WinDbg" -ForegroundColor Yellow