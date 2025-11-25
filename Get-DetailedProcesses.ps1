<#
.SYNOPSIS
    Análisis forense detallado de procesos
.DESCRIPTION
    Recopila información exhaustiva de procesos para análisis de malware e incidentes
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IR_ProcessAnalysis"
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "$OutputPath\ProcessAnalysis_$timestamp"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "[+] Iniciando análisis detallado de procesos..." -ForegroundColor Green

# 1. Lista completa de procesos con detalles
Write-Host "[*] Recopilando información básica de procesos..." -ForegroundColor Yellow
$processes = Get-Process | Select-Object `
    ProcessName, Id, 
    @{Name="ParentProcessId";Expression={$_.Parent.Id}},
    @{Name="ParentProcess";Expression={
        try { (Get-Process -Id $_.Parent.Id -ErrorAction SilentlyContinue).ProcessName } catch { "N/A" }
    }},
    Path, Company, Description, Product, ProductVersion, FileVersion,
    @{Name="Threads";Expression={$_.Threads.Count}},
    @{Name="Handles";Expression={$_.HandleCount}},
    @{Name="WorkingSetMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}},
    @{Name="PrivateMemoryMB";Expression={[math]::Round($_.PrivateMemorySize64/1MB,2)}},
    @{Name="VirtualMemoryMB";Expression={[math]::Round($_.VirtualMemorySize64/1MB,2)}},
    @{Name="CPU";Expression={$_.CPU}},
    StartTime,
    @{Name="CommandLine";Expression={
        try { (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine } catch { "N/A" }
    }}

$processes | Export-Csv "$outputDir\Processes_Full.csv" -NoTypeInformation

# 2. Procesos sin firma digital o firma no confiable
Write-Host "[*] Identificando procesos sin firma válida..." -ForegroundColor Yellow
$unsignedProcesses = $processes | Where-Object {$_.Path -ne $null} | ForEach-Object {
    try {
        $signature = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
        if ($signature.Status -ne "Valid") {
            $_ | Select-Object ProcessName, Id, Path, @{Name="SignatureStatus";Expression={$signature.Status}}
        }
    } catch {}
}
$unsignedProcesses | Export-Csv "$outputDir\Unsigned_Processes.csv" -NoTypeInformation

# 3. Procesos ejecutándose desde ubicaciones sospechosas
Write-Host "[*] Detectando procesos en ubicaciones sospechosas..." -ForegroundColor Yellow
$suspiciousLocations = @(
    $env:TEMP, $env:TMP, $env:APPDATA, $env:LOCALAPPDATA,
    "C:\Users\Public", "C:\ProgramData", "C:\Windows\Temp",
    "C:\Recycle", "C:\$Recycle.Bin"
)

$suspiciousProcesses = $processes | Where-Object {
    $path = $_.Path
    if ($path) {
        $suspiciousLocations | Where-Object { $path -like "$_*" }
    }
}
$suspiciousProcesses | Export-Csv "$outputDir\Suspicious_Location_Processes.csv" -NoTypeInformation

# 4. Procesos sin descripción o empresa
Write-Host "[*] Identificando procesos sin metadatos..." -ForegroundColor Yellow
$noMetadata = $processes | Where-Object {
    [string]::IsNullOrWhiteSpace($_.Company) -or [string]::IsNullOrWhiteSpace($_.Description)
}
$noMetadata | Export-Csv "$outputDir\No_Metadata_Processes.csv" -NoTypeInformation

# 5. Procesos con alto consumo de recursos
Write-Host "[*] Identificando procesos con alto consumo..." -ForegroundColor Yellow
$highCPU = $processes | Where-Object {$_.CPU -gt 60} | Sort-Object CPU -Descending
$highMemory = $processes | Sort-Object WorkingSetMB -Descending | Select-Object -First 20

$highCPU | Export-Csv "$outputDir\High_CPU_Processes.csv" -NoTypeInformation
$highMemory | Export-Csv "$outputDir\High_Memory_Processes.csv" -NoTypeInformation

# 6. Árbol de procesos (relación padre-hijo)
Write-Host "[*] Construyendo árbol de procesos..." -ForegroundColor Yellow
$processTree = Get-CimInstance Win32_Process | Select-Object `
    ProcessId, Name, ParentProcessId, 
    @{Name="ParentName";Expression={
        $parentId = $_.ParentProcessId
        (Get-CimInstance Win32_Process -Filter "ProcessId = $parentId" -ErrorAction SilentlyContinue).Name
    }},
    CommandLine, ExecutablePath, CreationDate

$processTree | Export-Csv "$outputDir\Process_Tree.csv" -NoTypeInformation

# 7. Procesos inyectados o con DLLs sospechosas
Write-Host "[*] Analizando módulos cargados por procesos..." -ForegroundColor Yellow
$processModules = @()
foreach ($proc in (Get-Process | Where-Object {$_.Modules.Count -gt 0})) {
    try {
        foreach ($module in $proc.Modules) {
            $processModules += [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                PID = $proc.Id
                ModuleName = $module.ModuleName
                ModulePath = $module.FileName
                ModuleSize = $module.Size
            }
        }
    } catch {}
}
$processModules | Export-Csv "$outputDir\Process_Modules.csv" -NoTypeInformation

# DLLs en ubicaciones sospechosas
$suspiciousDLLs = $processModules | Where-Object {
    $path = $_.ModulePath
    if ($path) {
        $suspiciousLocations | Where-Object { $path -like "$_*" }
    }
}
$suspiciousDLLs | Export-Csv "$outputDir\Suspicious_DLLs.csv" -NoTypeInformation

# 8. Conexiones de red por proceso
Write-Host "[*] Asociando conexiones de red con procesos..." -ForegroundColor Yellow
$netConnections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        ProcessName = $proc.ProcessName
        PID = $_.OwningProcess
        ProcessPath = $proc.Path
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort = $_.RemotePort
        State = $_.State
    }
}
$netConnections | Export-Csv "$outputDir\Process_Network_Connections.csv" -NoTypeInformation

# 9. Procesos con privilegios elevados
Write-Host "[*] Identificando procesos con privilegios elevados..." -ForegroundColor Yellow
$elevatedProcesses = Get-CimInstance Win32_Process | Where-Object {
    $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
    $owner.Domain -eq "NT AUTHORITY" -or $owner.User -eq "SYSTEM"
} | Select-Object ProcessId, Name, CommandLine

$elevatedProcesses | Export-Csv "$outputDir\Elevated_Processes.csv" -NoTypeInformation

# 10. Servicios en ejecución con detalle
Write-Host "[*] Recopilando servicios en ejecución..." -ForegroundColor Yellow
Get-CimInstance Win32_Service | Where-Object {$_.State -eq "Running"} | Select-Object `
    Name, DisplayName, PathName, State, StartMode, StartName, ProcessId,
    @{Name="ProcessName";Expression={
        (Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue).ProcessName
    }} | Export-Csv "$outputDir\Running_Services.csv" -NoTypeInformation

# 11. Hash de ejecutables en ejecución
Write-Host "[*] Calculando hashes de ejecutables..." -ForegroundColor Yellow
$processHashes = $processes | Where-Object {$_.Path -and (Test-Path $_.Path)} | ForEach-Object {
    try {
        $hash = Get-FileHash -Path $_.Path -Algorithm SHA256 -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            ProcessName = $_.ProcessName
            PID = $_.Id
            Path = $_.Path
            SHA256 = $hash.Hash
        }
    } catch {}
}
$processHashes | Export-Csv "$outputDir\Process_Hashes.csv" -NoTypeInformation

# 12. Procesos ocultos o técnicas de evasión
Write-Host "[*] Buscando técnicas de evasión..." -ForegroundColor Yellow
$hiddenProcesses = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "^\s+\." -or 
    $_.ExecutablePath -match "^\s+" -or
    [string]::IsNullOrWhiteSpace($_.ExecutablePath)
} | Select-Object ProcessId, Name, CommandLine, ExecutablePath

$hiddenProcesses | Export-Csv "$outputDir\Hidden_Processes.csv" -NoTypeInformation

# 13. WMI Event Consumers (persistencia común)
Write-Host "[*] Verificando WMI Event Consumers..." -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | 
    Select-Object Name, Query | Export-Csv "$outputDir\WMI_EventFilters.csv" -NoTypeInformation

Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | 
    Select-Object Name, CommandLineTemplate | Export-Csv "$outputDir\WMI_CommandLineConsumers.csv" -NoTypeInformation

# 14. Resumen y alertas
Write-Host "[*] Generando resumen..." -ForegroundColor Yellow
$summary = @"
=== RESUMEN DE ANÁLISIS DE PROCESOS ===
Fecha: $(Get-Date)
Host: $env:COMPUTERNAME

ESTADÍSTICAS:
- Total de procesos: $($processes.Count)
- Procesos sin firma válida: $($unsignedProcesses.Count)
- Procesos en ubicaciones sospechosas: $($suspiciousProcesses.Count)
- Procesos sin metadatos: $($noMetadata.Count)
- DLLs sospechosas: $($suspiciousDLLs.Count)
- Procesos con privilegios del SYSTEM: $($elevatedProcesses.Count)
- Procesos ocultos detectados: $($hiddenProcesses.Count)

TOP 10 PROCESOS POR USO DE MEMORIA:
$($highMemory | Select-Object -First 10 | Format-Table ProcessName, Id, WorkingSetMB, Path | Out-String)

PROCESOS SOSPECHOSOS IDENTIFICADOS:
$($suspiciousProcesses | Format-Table ProcessName, Id, Path | Out-String)

PROCESOS SIN FIRMA DIGITAL:
$($unsignedProcesses | Format-Table ProcessName, Id, Path, SignatureStatus | Out-String)
"@

$summary | Out-File "$outputDir\Summary.txt"

Write-Host "[+] Análisis de procesos completado!" -ForegroundColor Green
Write-Host "[+] Resultados en: $outputDir" -ForegroundColor Cyan

if ($suspiciousProcesses.Count -gt 0 -or $unsignedProcesses.Count -gt 5) {
    Write-Host "[!] ALERTA: Se detectaron procesos sospechosos que requieren investigación" -ForegroundColor Red
}