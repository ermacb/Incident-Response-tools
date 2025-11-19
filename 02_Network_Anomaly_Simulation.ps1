# ============================================
# Script de Simulación: Tráfico Anómalo y C2
# Propósito: Ejercicio Table Top - NO MALICIOSO
# Uso: SOLO en entornos de prueba autorizados
# ============================================

Write-Host "=== SIMULACIÓN DE TRÁFICO ANÓMALO INICIADA ===" -ForegroundColor Yellow
Write-Host "Generando patrones de comunicación sospechosos para detección" -ForegroundColor Cyan

# 1. Simulación de Beaconing (Comunicación periódica tipo C2)
Write-Host "`n[+] Fase 1: Simulación de Beaconing C2" -ForegroundColor Green

$beaconUrls = @(
    "http://example.com/api/check",  # URLs de ejemplo, no maliciosas
    "http://httpbin.org/get",
    "http://postman-echo.com/get"
)

Write-Host "[*] Iniciando beacons periódicos (5 intentos)..." -ForegroundColor Yellow

for ($i = 1; $i -le 5; $i++) {
    $randomUrl = $beaconUrls | Get-Random
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    try {
        Write-Host "[$timestamp] Beacon $i -> $randomUrl" -ForegroundColor Yellow
        
        # Simulación de datos enviados
        $computerName = $env:COMPUTERNAME
        $userName = $env:USERNAME
        $beaconData = @{
            host = $computerName
            user = $userName
            timestamp = $timestamp
            beacon_id = $i
        }
        
        # Intento de conexión (fallará en entorno aislado, pero genera logs)
        $response = Invoke-WebRequest -Uri $randomUrl -Method GET -TimeoutSec 3 -ErrorAction SilentlyContinue
        Write-Host "[+] Respuesta recibida: $($response.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Beacon falló (esperado en entorno controlado)" -ForegroundColor Red
    }
    
    # Intervalo aleatorio entre 5-15 segundos (típico de C2)
    $sleepTime = Get-Random -Minimum 5 -Maximum 15
    Write-Host "[*] Esperando $sleepTime segundos..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $sleepTime
}

# 2. Simulación de DNS Tunneling
Write-Host "`n[+] Fase 2: Simulación de DNS Tunneling" -ForegroundColor Green

$suspiciousDomains = @(
    "data123456789abcdef.example.com",
    "query-longstring-suspicious.example.com",
    "tunnel-test-beacon.example.com"
)

foreach ($domain in $suspiciousDomains) {
    try {
        Write-Host "[*] Consulta DNS sospechosa: $domain" -ForegroundColor Yellow
        Resolve-DnsName -Name $domain -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Host "[!] Consulta DNS falló (esperado)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}

# 3. Simulación de Tráfico a Puertos No Comunes
Write-Host "`n[+] Fase 3: Conexiones a Puertos Sospechosos" -ForegroundColor Green

$suspiciousPorts = @(4444, 5555, 8080, 9999, 31337)  # Puertos comúnmente usados por malware

foreach ($port in $suspiciousPorts) {
    try {
        Write-Host "[*] Intentando conexión a localhost:$port" -ForegroundColor Yellow
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect("127.0.0.1", $port)
        $client.Close()
        Write-Host "[+] Conexión exitosa al puerto $port" -ForegroundColor Green
    } catch {
        Write-Host "[!] No se pudo conectar al puerto $port (esperado)" -ForegroundColor Red
    }
}

# 4. Simulación de Transferencia de Datos Grandes
Write-Host "`n[+] Fase 4: Simulación de Transferencia de Volumen Anómalo" -ForegroundColor Green

# Crear archivo temporal grande
$tempFile = "$env:TEMP\large_transfer_$(Get-Date -Format 'yyyyMMddHHmmss').tmp"
$dataSize = 10MB  # 10MB de datos aleatorios

Write-Host "[*] Generando archivo de datos simulados ($($dataSize/1MB)MB)..." -ForegroundColor Yellow

try {
    $randomData = [byte[]]::new($dataSize)
    (New-Object System.Random).NextBytes($randomData)
    [System.IO.File]::WriteAllBytes($tempFile, $randomData)
    
    Write-Host "[+] Archivo generado: $tempFile" -ForegroundColor Green
    
    # Simular múltiples lecturas (como exfiltración)
    Write-Host "[*] Simulando lecturas múltiples del archivo..." -ForegroundColor Yellow
    for ($i = 1; $i -le 3; $i++) {
        $data = [System.IO.File]::ReadAllBytes($tempFile)
        Write-Host "[*] Lectura $i completada ($($data.Length) bytes)" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
} catch {
    Write-Host "[!] Error en simulación de transferencia" -ForegroundColor Red
}

# 5. Simulación de User-Agent Sospechoso
Write-Host "`n[+] Fase 5: Tráfico HTTP con User-Agent Anómalo" -ForegroundColor Green

$suspiciousUserAgents = @(
    "Microsoft BITS/7.5",  # Usado por malware
    "Python-urllib/2.7",   # Scripts automatizados
    "Go-http-client/1.1",  # Cliente personalizado
    "curl/7.64.1"          # Herramienta de línea de comandos
)

foreach ($ua in $suspiciousUserAgents) {
    try {
        Write-Host "[*] Request con User-Agent: $ua" -ForegroundColor Yellow
        $headers = @{
            'User-Agent' = $ua
        }
        Invoke-WebRequest -Uri "http://httpbin.org/user-agent" -Headers $headers -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Host "[!] Request falló" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}

# 6. Simulación de Actividad Fuera de Horario
Write-Host "`n[+] Fase 6: Marcador de Actividad Temporal" -ForegroundColor Green

$currentHour = (Get-Date).Hour
$isOffHours = ($currentHour -lt 7 -or $currentHour -gt 19)

if ($isOffHours) {
    Write-Host "[!] ALERTA: Actividad detectada fuera de horario laboral" -ForegroundColor Red
} else {
    Write-Host "[*] Actividad durante horario laboral (simulando actividad nocturna)" -ForegroundColor Yellow
}

Write-Host "[*] Timestamp de actividad: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow

# 7. Simulación de Múltiples Procesos PowerShell
Write-Host "`n[+] Fase 7: Creación de Procesos Anidados" -ForegroundColor Green

Write-Host "[*] Iniciando procesos PowerShell secundarios..." -ForegroundColor Yellow

# Crear scripts temporales que se ejecutan y terminan
$scriptBlock = {
    Write-Host "[Proceso Hijo] Ejecutándose..." -ForegroundColor Cyan
    Start-Sleep -Seconds 3
    Write-Host "[Proceso Hijo] Finalizando..." -ForegroundColor Cyan
}

for ($i = 1; $i -le 3; $i++) {
    Write-Host "[*] Lanzando proceso hijo $i" -ForegroundColor Yellow
    Start-Job -ScriptBlock $scriptBlock | Out-Null
    Start-Sleep -Seconds 1
}

# Esperar y limpiar jobs
Start-Sleep -Seconds 5
Get-Job | Remove-Job -Force

# Cleanup
Write-Host "`n[*] Limpiando archivos temporales..." -ForegroundColor Yellow
if (Test-Path $tempFile) {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

Write-Host "`n=== SIMULACIÓN DE TRÁFICO ANÓMALO COMPLETADA ===" -ForegroundColor Green
Write-Host "[!] Revisar logs de red y firewall para detectar patrones" -ForegroundColor Magenta
Write-Host "[!] Buscar: beaconing regular, puertos inusuales, volumen de datos" -ForegroundColor Magenta
