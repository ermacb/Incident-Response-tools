<#
.SYNOPSIS
    Detecta indicadores de movimiento lateral
.DESCRIPTION
    Analiza logs, sesiones, autenticaciones y actividad de red para identificar movimiento lateral
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IR_LateralMovement",
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 7
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "$OutputPath\LateralMovement_$timestamp"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "[+] Iniciando detección de movimiento lateral..." -ForegroundColor Green

# 1. Análisis de eventos de autenticación
Write-Host "[*] Analizando eventos de autenticación..." -ForegroundColor Yellow

# Event ID 4624: Successful Logon
$logons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID = $_.Id
            TargetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            LogonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
            SourceIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
            WorkstationName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'WorkstationName'} | Select-Object -ExpandProperty '#text'
            AuthenticationPackage = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'AuthenticationPackageName'} | Select-Object -ExpandProperty '#text'
        }
    }
$logons | Export-Csv "$outputDir\Logon_Events_4624.csv" -NoTypeInformation

# Event ID 4625: Failed Logon
$failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            SourceIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
            WorkstationName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'WorkstationName'} | Select-Object -ExpandProperty '#text'
            FailureReason = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'FailureReason'} | Select-Object -ExpandProperty '#text'
        }
    }
$failedLogons | Export-Csv "$outputDir\Failed_Logon_Events_4625.csv" -NoTypeInformation

# 2. Logons de tipo 3 (Network) y tipo 10 (RemoteInteractive/RDP)
Write-Host "[*] Detectando logons remotos..." -ForegroundColor Yellow
$remoteLogons = $logons | Where-Object {$_.LogonType -eq "3" -or $_.LogonType -eq "10"}
$remoteLogons | Export-Csv "$outputDir\Remote_Logons.csv" -NoTypeInformation

# Agrupar por usuario y origen
$logonsByUser = $remoteLogons | Group-Object TargetUser, SourceIP | 
    Select-Object @{Name="User";Expression={$_.Name.Split(',')[0].Trim()}},
                  @{Name="SourceIP";Expression={$_.Name.Split(',')[1].Trim()}},
                  Count |
    Sort-Object Count -Descending
$logonsByUser | Export-Csv "$outputDir\Logons_By_User_And_Source.csv" -NoTypeInformation

# 3. Uso de credenciales administrativas
Write-Host "[*] Analizando uso de credenciales administrativas..." -ForegroundColor Yellow
$adminLogons = $logons | Where-Object {
    $_.TargetUser -like "*admin*" -or 
    $_.TargetUser -eq "Administrator" -or
    $_.TargetUser -like "*adm*"
}
$adminLogons | Export-Csv "$outputDir\Admin_Logons.csv" -NoTypeInformation

# Event ID 4672: Special Privileges Assigned
$specialPrivileges = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            SubjectUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
            Privileges = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'PrivilegeList'} | Select-Object -ExpandProperty '#text'
        }
    }
$specialPrivileges | Export-Csv "$outputDir\Special_Privileges_4672.csv" -NoTypeInformation

# 4. Sesiones SMB activas
Write-Host "[*] Analizando sesiones SMB..." -ForegroundColor Yellow
try {
    Get-SmbSession | Select-Object SessionId, ClientComputerName, ClientUserName, NumOpens, SecondsIdle, SecondsExists |
        Export-Csv "$outputDir\SMB_Sessions.csv" -NoTypeInformation
} catch {
    Write-Host "  [!] No se pudieron obtener sesiones SMB" -ForegroundColor Red
}

# Recursos compartidos accedidos
Get-SmbShare | Export-Csv "$outputDir\SMB_Shares.csv" -NoTypeInformation
net use | Out-File "$outputDir\Net_Use.txt"
net session | Out-File "$outputDir\Net_Session.txt"

# 5. Actividad de PsExec
Write-Host "[*] Buscando evidencia de PsExec..." -ForegroundColor Yellow
$psexecService = Get-Service | Where-Object {$_.Name -like "*PSEXESVC*"}
if ($psexecService) {
    $psexecService | Export-Csv "$outputDir\PsExec_Service_Detected.csv" -NoTypeInformation
    Write-Host "  [!] ALERTA: Servicio PsExec detectado!" -ForegroundColor Red
}

# Buscar PSEXESVC en eventos
$psexecEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue |
    Where-Object {$_.Message -like "*PSEXESVC*"}
$psexecEvents | Select-Object TimeCreated, Id, Message | Export-Csv "$outputDir\PsExec_Events.csv" -NoTypeInformation

# 6. Ejecución remota (WMI, WMIC, PowerShell Remoting)
Write-Host "[*] Detectando ejecución remota..." -ForegroundColor Yellow

# Event ID 4688: Process Creation (si está habilitado)
$processCreation = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match "wmic|powershell|psexec|winrs|winrm"
    } | ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            SubjectUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
            NewProcess = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'} | Select-Object -ExpandProperty '#text'
            CommandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
        }
    }
$processCreation | Export-Csv "$outputDir\Remote_Execution_Commands.csv" -NoTypeInformation

# PowerShell Remoting Events
$psRemoting = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103,4104; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue |
    Where-Object {$_.Message -match "Enter-PSSession|Invoke-Command|New-PSSession"}
$psRemoting | Select-Object TimeCreated, Id, Message | Export-Csv "$outputDir\PowerShell_Remoting.csv" -NoTypeInformation

# WMI Activity
$wmiActivity = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue
$wmiActivity | Select-Object TimeCreated, Id, Message | Export-Csv "$outputDir\WMI_Activity.csv" -NoTypeInformation

# 7. Scheduled Tasks creadas remotamente
Write-Host "[*] Analizando tareas programadas..." -ForegroundColor Yellow
# Event ID 4698: Scheduled Task Created
$scheduledTaskCreated = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TaskName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TaskName'} | Select-Object -ExpandProperty '#text'
            SubjectUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
        }
    }
$scheduledTaskCreated | Export-Csv "$outputDir\Scheduled_Tasks_Created.csv" -NoTypeInformation

# 8. Pass-the-Hash detection (Logon Type 3 con NTLM)
Write-Host "[*] Detectando posibles ataques Pass-the-Hash..." -ForegroundColor Yellow
$pthSuspicious = $logons | Where-Object {
    $_.LogonType -eq "3" -and 
    $_.AuthenticationPackage -eq "NTLM" -and
    $_.WorkstationName -ne "" -and
    $_.SourceIP -ne "-"
}
$pthSuspicious | Export-Csv "$outputDir\Possible_Pass_The_Hash.csv" -NoTypeInformation

if ($pthSuspicious.Count -gt 0) {
    Write-Host "  [!] ALERTA: Detectados $($pthSuspicious.Count) eventos sospechosos de Pass-the-Hash" -ForegroundColor Red
}

# 9. Herramientas de movimiento lateral conocidas
Write-Host "[*] Buscando herramientas de movimiento lateral..." -ForegroundColor Yellow
$lateralTools = @("psexec", "psexesvc", "paexec", "winexesvc", "remcom", "winrs", "wmic")
$runningTools = @()

foreach ($tool in $lateralTools) {
    $proc = Get-Process -Name $tool -ErrorAction SilentlyContinue
    if ($proc) {
        $runningTools += $proc | Select-Object ProcessName, Id, Path, StartTime
    }
}
$runningTools | Export-Csv "$outputDir\Lateral_Movement_Tools_Running.csv" -NoTypeInformation

# 10. Conexiones a ADMIN$, C$, IPC$
Write-Host "[*] Analizando conexiones a recursos administrativos..." -ForegroundColor Yellow
# Event ID 5140: Network Share Access
$shareAccess = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $shareName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ShareName'} | Select-Object -ExpandProperty '#text'
        if ($shareName -match "ADMIN\$|C\$|IPC\$") {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                SubjectUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
                ShareName = $shareName
                SourceAddress = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
            }
        }
    }
$shareAccess | Export-Csv "$outputDir\Admin_Share_Access.csv" -NoTypeInformation

# 11. RDP Connections
Write-Host "[*] Analizando conexiones RDP..." -ForegroundColor Yellow
$rdpLogons = $logons | Where-Object {$_.LogonType -eq "10"}
$rdpLogons | Export-Csv "$outputDir\RDP_Connections.csv" -NoTypeInformation

# Event ID 1149: RDP Connection
$rdpEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ID=1149; StartTime=(Get-Date).AddDays(-$DaysBack)} -ErrorAction SilentlyContinue
$rdpEvents | Select-Object TimeCreated, Message | Export-Csv "$outputDir\RDP_Events_1149.csv" -NoTypeInformation

# 12. Resumen de Indicadores
Write-Host "[*] Generando resumen de indicadores..." -ForegroundColor Yellow
$summary = @"
=== RESUMEN DE DETECCIÓN DE MOVIMIENTO LATERAL ===
Fecha: $(Get-Date)
Host: $env:COMPUTERNAME
Período analizado: Últimos $DaysBack días

ESTADÍSTICAS:
- Total de logons exitosos: $($logons.Count)
- Logons remotos (Tipo 3 y 10): $($remoteLogons.Count)
- Logons administrativos: $($adminLogons.Count)
- Intentos de logon fallidos: $($failedLogons.Count)
- Posibles Pass-the-Hash: $($pthSuspicious.Count)
- Accesos a shares administrativos: $($shareAccess.Count)
- Conexiones RDP: $($rdpLogons.Count)
- Herramientas de movimiento lateral: $($runningTools.Count)

TOP USUARIOS CON MÁS LOGONS REMOTOS:
$($logonsByUser | Select-Object -First 10 | Format-Table | Out-String)

LOGONS ADMINISTRATIVOS RECIENTES:
$($adminLogons | Select-Object -First 10 | Format-Table TimeCreated, TargetUser, SourceIP, LogonType | Out-String)

INDICADORES DE COMPROMISO:
$( if ($pthSuspicious.Count -gt 0) { "- ALERTA: Posibles ataques Pass-the-Hash detectados`n" } )
$( if ($psexecService) { "- ALERTA: PsExec detectado en el sistema`n" } )
$( if ($runningTools.Count -gt 0) { "- ALERTA: Herramientas de movimiento lateral en ejecución`n" } )
$( if ($shareAccess.Count -gt 50) { "- ALERTA: Alto volumen de accesos a shares administrativos`n" } )

RECOMENDACIONES:
1. Revisar todos los logons administrativos remotos
2. Verificar el uso legítimo de herramientas de administración remota
3. Correlacionar con logs de otros sistemas de la red
4. Verificar integridad de cuentas privilegiadas
5. Revisar políticas de acceso a recursos compartidos
"@

$summary | Out-File "$outputDir\Summary.txt"

Write-Host "[+] Detección de movimiento lateral completada!" -ForegroundColor Green
Write-Host "[+] Resultados en: $outputDir" -ForegroundColor Cyan

# Alertas críticas
$criticalAlerts = 0
if ($pthSuspicious.Count -gt 0) { $criticalAlerts++ }
if ($psexecService) { $criticalAlerts++ }
if ($runningTools.Count -gt 0) { $criticalAlerts++ }

if ($criticalAlerts -gt 0) {
    Write-Host "`n[!!!] ALERTA CRÍTICA: Se detectaron $criticalAlerts indicadores de movimiento lateral" -ForegroundColor Red
    Write-Host "[!!!] Se recomienda investigación inmediata" -ForegroundColor Red
}