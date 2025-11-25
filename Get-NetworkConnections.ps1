<#
.SYNOPSIS
    Analiza conexiones de red activas y sospechosas
.DESCRIPTION
    Recopila información detallada de conexiones de red para identificar comunicaciones maliciosas
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IR_NetworkAnalysis"
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "$OutputPath\NetAnalysis_$timestamp"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "[+] Iniciando análisis de conexiones de red..." -ForegroundColor Green

# 1. Conexiones activas con detalle de proceso
Write-Host "[*] Recopilando conexiones activas..." -ForegroundColor Yellow
$connections = Get-NetTCPConnection | Where-Object {$_.State -ne "Bound"} | Select-Object `
    LocalAddress, LocalPort, RemoteAddress, RemotePort, State, 
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
    @{Name="PID";Expression={$_.OwningProcess}},
    @{Name="ProcessPath";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}},
    CreationTime

$connections | Export-Csv "$outputDir\ActiveConnections.csv" -NoTypeInformation
$connections | Format-Table -AutoSize | Out-File "$outputDir\ActiveConnections.txt"

# 2. Conexiones ESTABLISHED (activas actualmente)
Write-Host "[*] Filtrando conexiones ESTABLISHED..." -ForegroundColor Yellow
$established = $connections | Where-Object {$_.State -eq "Established"}
$established | Export-Csv "$outputDir\EstablishedConnections.csv" -NoTypeInformation

# Agrupar por proceso
$byProcess = $established | Group-Object Process | Select-Object Count, Name, @{Name="Connections";Expression={$_.Group | Select-Object RemoteAddress, RemotePort}}
$byProcess | ConvertTo-Json -Depth 3 | Out-File "$outputDir\ConnectionsByProcess.json"

# 3. Conexiones sospechosas (puertos no estándar, IPs externas)
Write-Host "[*] Identificando conexiones sospechosas..." -ForegroundColor Yellow
$suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 12345, 54321)
$suspiciousConnections = $connections | Where-Object {
    $suspiciousPorts -contains $_.RemotePort -or
    $suspiciousPorts -contains $_.LocalPort -or
    ($_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "127.0.0.1")
}
$suspiciousConnections | Export-Csv "$outputDir\SuspiciousConnections.csv" -NoTypeInformation

# 4. Listening ports (puertos en escucha)
Write-Host "[*] Identificando puertos en escucha..." -ForegroundColor Yellow
$listening = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object `
    LocalAddress, LocalPort,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
    @{Name="PID";Expression={$_.OwningProcess}},
    @{Name="ProcessPath";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}

$listening | Export-Csv "$outputDir\ListeningPorts.csv" -NoTypeInformation
$listening | Format-Table -AutoSize | Out-File "$outputDir\ListeningPorts.txt"

# 5. Conexiones UDP
Write-Host "[*] Recopilando conexiones UDP..." -ForegroundColor Yellow
Get-NetUDPEndpoint | Select-Object `
    LocalAddress, LocalPort,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
    @{Name="PID";Expression={$_.OwningProcess}},
    @{Name="ProcessPath";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} |
    Export-Csv "$outputDir\UDPConnections.csv" -NoTypeInformation

# 6. Netstat completo
Write-Host "[*] Ejecutando netstat completo..." -ForegroundColor Yellow
netstat -anob | Out-File "$outputDir\Netstat_Full.txt"

# 7. Tabla de enrutamiento
Write-Host "[*] Capturando tabla de enrutamiento..." -ForegroundColor Yellow
Get-NetRoute | Export-Csv "$outputDir\RoutingTable.csv" -NoTypeInformation
route print | Out-File "$outputDir\RoutingTable.txt"

# 8. Caché ARP
Write-Host "[*] Capturando caché ARP..." -ForegroundColor Yellow
Get-NetNeighbor | Export-Csv "$outputDir\ARP_Cache.csv" -NoTypeInformation
arp -a | Out-File "$outputDir\ARP_Cache.txt"

# 9. Caché DNS
Write-Host "[*] Capturando caché DNS..." -ForegroundColor Yellow
Get-DnsClientCache | Select-Object Entry, Name, Type, TimeToLive, Data | Export-Csv "$outputDir\DNS_Cache.csv" -NoTypeInformation
ipconfig /displaydns | Out-File "$outputDir\DNS_Cache.txt"

# 10. Configuración de interfaces de red
Write-Host "[*] Recopilando configuración de interfaces..." -ForegroundColor Yellow
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Export-Csv "$outputDir\NetworkAdapters.csv" -NoTypeInformation
Get-NetIPAddress | Export-Csv "$outputDir\IPAddresses.csv" -NoTypeInformation
ipconfig /all | Out-File "$outputDir\IPConfig.txt"

# 11. Reglas de firewall activas
Write-Host "[*] Exportando reglas de firewall..." -ForegroundColor Yellow
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | Select-Object `
    DisplayName, Direction, Action, Enabled, Profile, 
    @{Name="RemoteAddress";Expression={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress}},
    @{Name="RemotePort";Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).RemotePort}} |
    Export-Csv "$outputDir\FirewallRules_Active.csv" -NoTypeInformation

# 12. Proxies y configuración de red
Write-Host "[*] Verificando configuración de proxy..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Out-File "$outputDir\ProxySettings.txt"
netsh winhttp show proxy | Out-File "$outputDir\WinHTTP_Proxy.txt" -Append

# 13. SMB Shares y conexiones
Write-Host "[*] Recopilando información de SMB..." -ForegroundColor Yellow
Get-SmbConnection | Export-Csv "$outputDir\SMB_Connections.csv" -NoTypeInformation
Get-SmbShare | Export-Csv "$outputDir\SMB_Shares.csv" -NoTypeInformation
net use | Out-File "$outputDir\MappedDrives.txt"
net share | Out-File "$outputDir\SharedResources.txt"

# 14. Análisis de tráfico por destino
Write-Host "[*] Analizando destinos de conexiones..." -ForegroundColor Yellow
$remoteAddresses = $established | Where-Object {$_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "127.0.0.1"} | 
    Group-Object RemoteAddress | 
    Select-Object Name, Count, @{Name="Processes";Expression={($_.Group | Select-Object -Unique Process).Process -join ", "}} |
    Sort-Object Count -Descending

$remoteAddresses | Export-Csv "$outputDir\TopRemoteAddresses.csv" -NoTypeInformation

# 15. Detectar beaconing (comunicación periódica C2)
Write-Host "[*] Buscando patrones de beaconing..." -ForegroundColor Yellow
$beaconing = $established | Group-Object Process, RemoteAddress, RemotePort | 
    Where-Object {$_.Count -gt 3} |
    Select-Object @{Name="Process";Expression={$_.Name.Split(',')[0].Trim()}},
                  @{Name="RemoteAddress";Expression={$_.Name.Split(',')[1].Trim()}},
                  @{Name="RemotePort";Expression={$_.Name.Split(',')[2].Trim()}},
                  Count

if ($beaconing) {
    $beaconing | Export-Csv "$outputDir\PossibleBeaconing.csv" -NoTypeInformation
    Write-Host "[!] Se detectaron posibles patrones de beaconing!" -ForegroundColor Red
}

# 16. Resumen ejecutivo
Write-Host "[*] Generando resumen..." -ForegroundColor Yellow
$summary = @"
=== RESUMEN DE ANÁLISIS DE CONEXIONES DE RED ===
Fecha: $(Get-Date)
Host: $env:COMPUTERNAME

ESTADÍSTICAS:
- Total de conexiones TCP: $($connections.Count)
- Conexiones ESTABLISHED: $($established.Count)
- Conexiones sospechosas: $($suspiciousConnections.Count)
- Puertos en escucha: $($listening.Count)
- Posibles beaconing: $($beaconing.Count)

TOP 10 PROCESOS CON MÁS CONEXIONES:
$($byProcess | Select-Object -First 10 | Format-Table | Out-String)

TOP 10 DESTINOS REMOTOS:
$($remoteAddresses | Select-Object -First 10 | Format-Table | Out-String)

CONEXIONES SOSPECHOSAS DETECTADAS:
$($suspiciousConnections | Format-Table Process, PID, RemoteAddress, RemotePort | Out-String)
"@

$summary | Out-File "$outputDir\Summary.txt"

Write-Host "[+] Análisis de red completado!" -ForegroundColor Green
Write-Host "[+] Resultados en: $outputDir" -ForegroundColor Cyan

if ($suspiciousConnections.Count -gt 0) {
    Write-Host "[!] ALERTA: Se detectaron $($suspiciousConnections.Count) conexiones sospechosas" -ForegroundColor Red
}