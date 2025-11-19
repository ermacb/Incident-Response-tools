# ============================================
# Script de Simulación: Movimiento Lateral
# Propósito: Ejercicio Table Top - NO MALICIOSO
# Uso: SOLO en entornos de prueba autorizados
# ============================================

Write-Host "=== SIMULACIÓN DE MOVIMIENTO LATERAL INICIADA ===" -ForegroundColor Yellow
Write-Host "Simulando técnicas de propagación y movimiento en red" -ForegroundColor Cyan

# 1. Descubrimiento de Red
Write-Host "`n[+] Fase 1: Descubrimiento de Red Local" -ForegroundColor Green

Write-Host "[*] Obteniendo configuración de red local..." -ForegroundColor Yellow

# Obtener información de adaptadores de red
$networkAdapters = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -notlike '127.*'}

foreach ($adapter in $networkAdapters) {
    Write-Host "[*] Interface: $($adapter.InterfaceAlias)" -ForegroundColor Yellow
    Write-Host "    IP: $($adapter.IPAddress)" -ForegroundColor Yellow
    Write-Host "    Prefijo: $($adapter.PrefixLength)" -ForegroundColor Yellow
}

# Calcular rango de red
if ($networkAdapters) {
    $localIP = $networkAdapters[0].IPAddress
    $subnet = $localIP.Substring(0, $localIP.LastIndexOf('.'))
    Write-Host "`n[*] Subnet detectada: $subnet.0/24" -ForegroundColor Yellow
}

# 2. Escaneo de Hosts Activos
Write-Host "`n[+] Fase 2: Escaneo de Hosts en Red Local" -ForegroundColor Green

Write-Host "[*] Escaneando rango local (primeros 10 hosts)..." -ForegroundColor Yellow

$activeHosts = @()

for ($i = 1; $i -le 10; $i++) {
    $targetIP = "$subnet.$i"
    Write-Host "[*] Probando: $targetIP" -ForegroundColor DarkGray
    
    try {
        $ping = Test-Connection -ComputerName $targetIP -Count 1 -TimeoutSeconds 1 -ErrorAction SilentlyContinue
        
        if ($ping) {
            Write-Host "[+] Host activo encontrado: $targetIP" -ForegroundColor Green
            $activeHosts += $targetIP
            
            # Intentar resolver nombre NetBIOS
            try {
                $hostname = [System.Net.Dns]::GetHostEntry($targetIP).HostName
                Write-Host "    Hostname: $hostname" -ForegroundColor Cyan
            } catch {
                Write-Host "    Hostname: No resuelto" -ForegroundColor DarkGray
            }
        }
    } catch {
        # Silencioso
    }
}

Write-Host "`n[*] Total de hosts activos detectados: $($activeHosts.Count)" -ForegroundColor Yellow

# 3. Enumeración de Recursos Compartidos (SMB)
Write-Host "`n[+] Fase 3: Enumeración de Recursos Compartidos SMB" -ForegroundColor Green

foreach ($host in $activeHosts) {
    Write-Host "`n[*] Enumerando recursos en: $host" -ForegroundColor Yellow
    
    try {
        # Intentar listar recursos compartidos
        $shares = Get-SmbShare -CimSession $host -ErrorAction SilentlyContinue
        
        if ($shares) {
            foreach ($share in $shares) {
                Write-Host "[+] Recurso compartido: \\$host\$($share.Name)" -ForegroundColor Green
                Write-Host "    Descripción: $($share.Description)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "[!] No se pudieron enumerar recursos (acceso denegado)" -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Error al conectar con $host" -ForegroundColor Red
    }
}

# 4. Intento de Conexión SMB a Recursos Administrativos
Write-Host "`n[+] Fase 4: Prueba de Acceso a Recursos Administrativos" -ForegroundColor Green

$adminShares = @('C$', 'ADMIN$', 'IPC$')

foreach ($host in $activeHosts) {
    Write-Host "`n[*] Probando recursos administrativos en: $host" -ForegroundColor Yellow
    
    foreach ($share in $adminShares) {
        $path = "\\$host\$share"
        
        try {
            Write-Host "[*] Intentando: $path" -ForegroundColor Yellow
            $access = Test-Path $path -ErrorAction SilentlyContinue
            
            if ($access) {
                Write-Host "[+] ACCESO EXITOSO: $path" -ForegroundColor Red
            } else {
                Write-Host "[!] Acceso denegado: $path" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "[!] Error al acceder: $path" -ForegroundColor Red
        }
        
        Start-Sleep -Milliseconds 500
    }
}

# 5. Simulación de Pass-the-Hash (Sin credenciales reales)
Write-Host "`n[+] Fase 5: Simulación de Ataque Pass-the-Hash" -ForegroundColor Green

Write-Host "[!] ALERTA: Técnica típica de movimiento lateral detectada" -ForegroundColor Red
Write-Host "[*] Herramientas comunes: mimikatz, Invoke-Mimikatz, PsExec" -ForegroundColor Yellow
Write-Host "[*] SIMULADO - No se usan credenciales reales" -ForegroundColor Green

# Simular búsqueda de procesos LSASS
Write-Host "`n[*] Buscando proceso LSASS..." -ForegroundColor Yellow
try {
    $lsass = Get-Process -Name lsass -ErrorAction SilentlyContinue
    if ($lsass) {
        Write-Host "[+] Proceso LSASS encontrado (PID: $($lsass.Id))" -ForegroundColor Yellow
        Write-Host "[!] En ataque real: Volcado de memoria para extracción de credenciales" -ForegroundColor Red
    }
} catch {
    Write-Host "[!] No se pudo acceder al proceso LSASS" -ForegroundColor Red
}

# 6. Simulación de PSExec / Remote Execution
Write-Host "`n[+] Fase 6: Simulación de Ejecución Remota" -ForegroundColor Green

foreach ($host in $activeHosts) {
    Write-Host "`n[*] Intentando ejecución remota en: $host" -ForegroundColor Yellow
    
    # Simular PSExec
    Write-Host "[*] Método: PSExec / WMI / PsRemoting" -ForegroundColor Yellow
    
    try {
        # Probar WinRM (PowerShell Remoting)
        $winrmTest = Test-WSMan -ComputerName $host -ErrorAction SilentlyContinue
        
        if ($winrmTest) {
            Write-Host "[+] WinRM habilitado en $host" -ForegroundColor Red
            Write-Host "[!] Posible vector de movimiento lateral" -ForegroundColor Red
        } else {
            Write-Host "[!] WinRM no disponible en $host" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[!] No se pudo probar WinRM en $host" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 1
}

# 7. Enumeración de Sesiones Activas
Write-Host "`n[+] Fase 7: Enumeración de Sesiones Activas" -ForegroundColor Green

Write-Host "[*] Buscando sesiones de usuario en equipo local..." -ForegroundColor Yellow

try {
    # Obtener sesiones de usuario local
    $sessions = quser 2>$null
    
    if ($sessions) {
        Write-Host "[+] Sesiones activas encontradas:" -ForegroundColor Green
        $sessions | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    } else {
        Write-Host "[*] No se encontraron sesiones adicionales" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] No se pudieron enumerar sesiones" -ForegroundColor Red
}

# 8. Simulación de Credenciales en Memoria
Write-Host "`n[+] Fase 8: Búsqueda de Credenciales en Memoria" -ForegroundColor Green

Write-Host "[!] ALERTA: Búsqueda de credenciales en memoria" -ForegroundColor Red
Write-Host "[*] Ubicaciones típicas:" -ForegroundColor Yellow
Write-Host "    - Proceso LSASS" -ForegroundColor DarkGray
Write-Host "    - Credential Manager" -ForegroundColor DarkGray
Write-Host "    - Registry SAM" -ForegroundColor DarkGray

# Intentar listar credenciales guardadas (solo listar, no extraer)
try {
    Write-Host "`n[*] Enumerando credenciales guardadas..." -ForegroundColor Yellow
    $creds = cmdkey /list 2>$null
    
    if ($creds) {
        Write-Host "[+] Credenciales en Credential Manager detectadas" -ForegroundColor Yellow
    } else {
        Write-Host "[*] No se encontraron credenciales guardadas" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Error al enumerar credenciales" -ForegroundColor Red
}

# 9. Simulación de WMI para Ejecución Remota
Write-Host "`n[+] Fase 9: Simulación de WMI Remote Execution" -ForegroundColor Green

foreach ($host in $activeHosts) {
    Write-Host "`n[*] Probando WMI en: $host" -ForegroundColor Yellow
    
    try {
        # Intentar conexión WMI
        $wmi = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $host -ErrorAction SilentlyContinue
        
        if ($wmi) {
            Write-Host "[+] Conexión WMI exitosa" -ForegroundColor Red
            Write-Host "    OS: $($wmi.Caption)" -ForegroundColor Cyan
            Write-Host "    Version: $($wmi.Version)" -ForegroundColor Cyan
            Write-Host "[!] Posible ejecución remota via WMI" -ForegroundColor Red
        } else {
            Write-Host "[!] WMI no accesible en $host" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[!] Error de conexión WMI a $host" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 1
}

# 10. Simulación de RDP Lateral Movement
Write-Host "`n[+] Fase 10: Detección de Servicios RDP" -ForegroundColor Green

foreach ($host in $activeHosts) {
    Write-Host "[*] Probando puerto RDP (3389) en: $host" -ForegroundColor Yellow
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($host, 3389, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)
        
        if ($wait) {
            $tcpClient.EndConnect($connect)
            Write-Host "[+] Puerto RDP abierto en $host" -ForegroundColor Red
            Write-Host "[!] Posible vector de movimiento lateral" -ForegroundColor Red
        } else {
            Write-Host "[!] Puerto RDP cerrado en $host" -ForegroundColor DarkGray
        }
        
        $tcpClient.Close()
    } catch {
        Write-Host "[!] No se pudo conectar a $host:3389" -ForegroundColor DarkGray
    }
}

# 11. Enumeración de Domain Controllers (si es dominio)
Write-Host "`n[+] Fase 11: Búsqueda de Controladores de Dominio" -ForegroundColor Green

try {
    $domain = $env:USERDOMAIN
    Write-Host "[*] Dominio actual: $domain" -ForegroundColor Yellow
    
    if ($domain -ne $env:COMPUTERNAME) {
        Write-Host "[*] Equipo está en dominio" -ForegroundColor Yellow
        
        # Intentar encontrar DC
        try {
            $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
            
            foreach ($controller in $dc) {
                Write-Host "[+] Domain Controller encontrado: $($controller.Name)" -ForegroundColor Red
                Write-Host "    IP: $($controller.IPAddress)" -ForegroundColor Cyan
            }
        } catch {
            Write-Host "[!] No se pudo enumerar Domain Controllers" -ForegroundColor Red
        }
    } else {
        Write-Host "[*] Equipo no está en dominio (WorkGroup)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Error al verificar dominio" -ForegroundColor Red
}

# 12. Simulación de Kerberoasting
Write-Host "`n[+] Fase 12: Simulación de Kerberoasting" -ForegroundColor Green

Write-Host "[!] ALERTA: Técnica de ataque a Kerberos detectada" -ForegroundColor Red
Write-Host "[*] Kerberoasting permite extraer hashes de cuentas de servicio" -ForegroundColor Yellow
Write-Host "[*] SIMULADO - No se extraen tickets reales" -ForegroundColor Green

# Intentar listar SPNs (si está en dominio)
try {
    Write-Host "`n[*] Buscando Service Principal Names (SPNs)..." -ForegroundColor Yellow
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(servicePrincipalName=*)"
    $searcher.SearchScope = "Subtree"
    
    $results = $searcher.FindAll()
    
    if ($results.Count -gt 0) {
        Write-Host "[+] SPNs encontrados: $($results.Count)" -ForegroundColor Yellow
        Write-Host "[!] Posible objetivo para Kerberoasting" -ForegroundColor Red
    } else {
        Write-Host "[*] No se encontraron SPNs (posiblemente no está en dominio)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] No se pudieron enumerar SPNs" -ForegroundColor Red
}

# 13. Creación de Log de Actividad
Write-Host "`n[+] Fase 13: Registro de Actividad de Movimiento Lateral" -ForegroundColor Green

$lateralMovementLog = @"
=== LOG DE MOVIMIENTO LATERAL ===
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Equipo Origen: $env:COMPUTERNAME
Usuario: $env:USERNAME
Dominio: $env:USERDOMAIN

ACTIVIDADES DETECTADAS:
- Escaneo de red local
- Enumeración de hosts activos: $($activeHosts.Count)
- Intentos de acceso a recursos compartidos
- Pruebas de servicios remotos (WMI, WinRM, RDP)
- Enumeración de sesiones de usuario
- Búsqueda de credenciales en memoria
- Enumeración de Domain Controllers

HOSTS OBJETIVO:
$($activeHosts | ForEach-Object { "  - $_" })

INDICADORES DE COMPROMISO:
- Múltiples conexiones SMB en corto tiempo
- Escaneos de puerto sistemáticos
- Intentos de acceso a recursos administrativos
- Consultas WMI a múltiples hosts
- Enumeración de servicios de dominio

TÉCNICAS MITRE ATT&CK:
- T1018: Remote System Discovery
- T1021: Remote Services
- T1047: Windows Management Instrumentation
- T1003: OS Credential Dumping
- T1558: Steal or Forge Kerberos Tickets

================================
"@

Write-Host $lateralMovementLog -ForegroundColor Cyan

# Guardar log
$logPath = "$env:TEMP\lateral_movement_log_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
$lateralMovementLog | Out-File -FilePath $logPath

Write-Host "[*] Log guardado en: $logPath" -ForegroundColor Yellow

# Resumen
Write-Host "`n=== SIMULACIÓN DE MOVIMIENTO LATERAL COMPLETADA ===" -ForegroundColor Green
Write-Host "`n[!] INDICADORES CRÍTICOS A MONITOREAR:" -ForegroundColor Magenta
Write-Host "  1. Múltiples conexiones SMB a diferentes hosts" -ForegroundColor White
Write-Host "  2. Escaneos de puertos RDP (3389)" -ForegroundColor White
Write-Host "  3. Intentos de acceso a recursos administrativos (C$, ADMIN$)" -ForegroundColor White
Write-Host "  4. Uso de WMI o PowerShell Remoting" -ForegroundColor White
Write-Host "  5. Enumeración de Domain Controllers" -ForegroundColor White
Write-Host "  6. Acceso al proceso LSASS" -ForegroundColor White
Write-Host "  7. Consultas de SPNs (posible Kerberoasting)" -ForegroundColor White
Write-Host "  8. Comandos net use, net view, nltest" -ForegroundColor White
Write-Host "  9. Múltiples autenticaciones fallidas" -ForegroundColor White
Write-Host " 10. Uso de herramientas como PSExec, Mimikatz" -ForegroundColor White

Write-Host "`n[!] HERRAMIENTAS DE DETECCIÓN RECOMENDADAS:" -ForegroundColor Magenta
Write-Host "  - Sysmon (Event ID 1, 3, 10, 22)" -ForegroundColor White
Write-Host "  - Windows Event Logs (4624, 4625, 4672, 4768, 4769)" -ForegroundColor White
Write-Host "  - Network Traffic Analysis (Zeek, Suricata)" -ForegroundColor White
Write-Host "  - EDR Solutions (CrowdStrike, SentinelOne, MS Defender ATP)" -ForegroundColor White
