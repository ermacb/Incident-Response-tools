# Master-IR-Collection.ps1
<#
.SYNOPSIS
    Script maestro de recolección para CSIRT
.DESCRIPTION
    Ejecuta todos los scripts de IR y empaqueta evidencia
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$IncidentID,
    [Parameter(Mandatory=$false)]
    [string]$Analyst = $env:USERNAME
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$evidenceRoot = "C:\CSIRT_Evidence\$IncidentID`_$timestamp"
New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null

# Log de auditoría
$auditLog = "$evidenceRoot\AUDIT_LOG.txt"
@"
========================================
CSIRT EVIDENCE COLLECTION LOG
========================================
Incident ID: $IncidentID
Analyst: $Analyst
Collection Start: $(Get-Date)
Hostname: $env:COMPUTERNAME
IP Address: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).IPAddress)
OS: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
========================================
"@ | Out-File $auditLog

Write-Host "[+] CSIRT Evidence Collection - Incident: $IncidentID" -ForegroundColor Cyan
Write-Host "[+] Analyst: $Analyst" -ForegroundColor Cyan

# Ejecutar todos los módulos
$modules = @(
    @{Name="System Info"; Script="Get-SystemInfo.ps1"},
    @{Name="Memory Dump"; Script="Get-MemoryDump.ps1"},
    @{Name="Suspicious Files"; Script="Find-SuspiciousFiles.ps1"},
    @{Name="Network Connections"; Script="Get-NetworkConnections.ps1"},
    @{Name="Process Analysis"; Script="Get-DetailedProcesses.ps1"},
    @{Name="Lateral Movement"; Script="Detect-LateralMovement.ps1"}
)

foreach ($module in $modules) {
    Write-Host "`n[*] Executing: $($module.Name)..." -ForegroundColor Yellow
    "$(Get-Date) - Starting: $($module.Name)" | Out-File $auditLog -Append
    
    try {
        & ".\$($module.Script)" -OutputPath $evidenceRoot
        "$(Get-Date) - Completed: $($module.Name)" | Out-File $auditLog -Append
        Write-Host "  [+] $($module.Name) completed" -ForegroundColor Green
    } catch {
        "$(Get-Date) - ERROR in $($module.Name): $_" | Out-File $auditLog -Append
        Write-Host "  [-] Error in $($module.Name): $_" -ForegroundColor Red
    }
}

# Generar hash del paquete completo
Write-Host "`n[*] Generando hashes de integridad..." -ForegroundColor Yellow
$hashFile = "$evidenceRoot\EVIDENCE_HASHES.txt"
Get-ChildItem -Path $evidenceRoot -Recurse -File | ForEach-Object {
    $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
    "$($_.FullName): $($hash.Hash)" | Out-File $hashFile -Append
}

# Chain of Custody
$custodyLog = "$evidenceRoot\CHAIN_OF_CUSTODY.txt"
@"
========================================
CHAIN OF CUSTODY
========================================
Incident ID: $IncidentID
Evidence Collected By: $Analyst
Collection Date/Time: $(Get-Date)
System: $env:COMPUTERNAME
Evidence Location: $evidenceRoot

Digital Signature (SHA256):
$((Get-FileHash -Path $hashFile -Algorithm SHA256).Hash)

========================================
Transfer Log:
========================================
Date/Time | From | To | Purpose
========================================

"@ | Out-File $custodyLog

"$(Get-Date) - Collection completed successfully" | Out-File $auditLog -Append

Write-Host "`n[+] Evidence collection completed!" -ForegroundColor Green
Write-Host "[+] Evidence package: $evidenceRoot" -ForegroundColor Cyan
Write-Host "[!] Remember to document in chain of custody" -ForegroundColor Yellow