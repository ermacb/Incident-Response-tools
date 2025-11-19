# ============================================
# Script de Simulación: Ransomware (SIN CIFRADO)
# Propósito: Ejercicio Table Top - NO MALICIOSO
# Uso: SOLO en entornos de prueba autorizados
# ============================================

Write-Host "=== SIMULACIÓN DE RANSOMWARE INICIADA ===" -ForegroundColor Red
Write-Host "IMPORTANTE: Este script NO cifra archivos reales" -ForegroundColor Yellow
Write-Host "Simula comportamiento de ransomware para detección" -ForegroundColor Cyan

# Configuración de simulación
$simulationPath = "$env:TEMP\RansomwareSimulation_$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $simulationPath -Force | Out-Null

# 1. Fase de Reconocimiento (Pre-Cifrado)
Write-Host "`n[+] Fase 1: Reconocimiento del Sistema" -ForegroundColor Green

Write-Host "[*] Enumerando volúmenes y unidades..." -ForegroundColor Yellow
$volumes = Get-Volume | Where-Object {$_.DriveLetter -ne $null}
foreach ($vol in $volumes) {
    Write-Host "[*] Unidad: $($vol.DriveLetter):\ - Tamaño: $([math]::Round($vol.Size/1GB,2)) GB - Libre: $([math]::Round($vol.SizeRemaining/1GB,2)) GB" -ForegroundColor Yellow
}

Write-Host "[*] Identificando directorios críticos..." -ForegroundColor Yellow
$criticalPaths = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Pictures",
    "$env:USERPROFILE\Downloads"
)

foreach ($path in $criticalPaths) {
    if (Test-Path $path) {
        $fileCount = (Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue).Count
        Write-Host "[*] $path - Archivos: $fileCount" -ForegroundColor Yellow
    }
}

# 2. Eliminación de Shadow Copies (Comportamiento típico)
Write-Host "`n[+] Fase 2: Intento de Eliminación de Shadow Copies" -ForegroundColor Green

Write-Host "[!] ALERTA: Comando típico de ransomware detectado" -ForegroundColor Red
Write-Host "[*] Comando simulado: vssadmin delete shadows /all /quiet" -ForegroundColor Yellow
Write-Host "[*] NO EJECUTADO - Solo simulación" -ForegroundColor Green

# Listar shadow copies sin eliminarlas
try {
    $shadows = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue
    if ($shadows) {
        Write-Host "[*] Shadow Copies encontradas: $($shadows.Count)" -ForegroundColor Yellow
    } else {
        Write-Host "[*] No se encontraron Shadow Copies" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] No se pudo enumerar Shadow Copies" -ForegroundColor Red
}

# 3. Deshabilitación de Herramientas de Seguridad (Simulado)
Write-Host "`n[+] Fase 3: Intentos de Evasión de Seguridad" -ForegroundColor Green

$defenderChecks = @(
    "Windows Defender - Estado",
    "Firewall - Configuración",
    "Windows Update - Servicio"
)

foreach ($check in $defenderChecks) {
    Write-Host "[*] Verificando: $check" -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

# Verificar Defender sin modificarlo
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        Write-Host "[*] Windows Defender está: $($defenderStatus.AntivirusEnabled)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] No se pudo verificar Windows Defender" -ForegroundColor Red
}

# 4. Creación de Archivos de Prueba para "Cifrado"
Write-Host "`n[+] Fase 4: Preparación de Archivos de Prueba" -ForegroundColor Green

$testFiles = @(
    "documento_importante.docx",
    "presentacion.pptx",
    "reporte_financiero.xlsx",
    "foto_vacaciones.jpg",
    "proyecto.pdf",
    "base_datos.sql",
    "configuracion.xml",
    "contrato.pdf"
)

Write-Host "[*] Creando archivos de prueba en: $simulationPath" -ForegroundColor Yellow

foreach ($file in $testFiles) {
    $filePath = Join-Path $simulationPath $file
    "Este es un archivo de prueba para simulación de ransomware" | Out-File -FilePath $filePath
    Write-Host "[+] Creado: $file" -ForegroundColor Green
}

# 5. Simulación de "Cifrado" (Renombrado solamente)
Write-Host "`n[+] Fase 5: Simulación de Proceso de Cifrado" -ForegroundColor Green
Write-Host "[!] NO SE CIFRA NADA - Solo se renombran archivos" -ForegroundColor Yellow

$ransomExtension = ".locked"
$encryptedCount = 0

$files = Get-ChildItem -Path $simulationPath -File

foreach ($file in $files) {
    try {
        # Simular proceso de "cifrado" con pausa
        Write-Host "[*] Procesando: $($file.Name)" -ForegroundColor Yellow
        Start-Sleep -Milliseconds 500
        
        # Renombrar archivo (simula cifrado)
        $newName = $file.Name + $ransomExtension
        $newPath = Join-Path $simulationPath $newName
        
        Rename-Item -Path $file.FullName -NewName $newName -Force
        Write-Host "[+] Renombrado: $($file.Name) -> $newName" -ForegroundColor Red
        
        $encryptedCount++
    } catch {
        Write-Host "[!] Error procesando: $($file.Name)" -ForegroundColor Red
    }
}

Write-Host "`n[*] Archivos procesados: $encryptedCount" -ForegroundColor Yellow

# 6. Creación de Nota de Rescate
Write-Host "`n[+] Fase 6: Generación de Nota de Rescate" -ForegroundColor Green

$ransomNote = @"
!!!!! ATENCIÓN !!!!!

Sus archivos han sido CIFRADOS

Todos sus documentos, fotos, bases de datos y otros archivos importantes
han sido cifrados con un algoritmo de cifrado fuerte.

La única manera de recuperar sus archivos es obtener la clave de descifrado.

Para obtener la clave de descifrado deberá:

1. Contactar a: recovery@example.com
2. ID de su equipo: $env:COMPUTERNAME
3. Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

ADVERTENCIAS:
- No intente descifrar los archivos por su cuenta
- No elimine este archivo o no podrá recuperar sus datos
- No apague el equipo
- No use herramientas de recuperación

Tiene 72 horas para contactarnos.

================================
ESTO ES UNA SIMULACIÓN
NO HAY CIFRADO REAL
ARCHIVOS NO ESTÁN EN RIESGO
================================
"@

# Crear múltiples copias de la nota (comportamiento típico)
$noteLocations = @(
    "$simulationPath\README_DECRYPT.txt",
    "$env:USERPROFILE\Desktop\README_DECRYPT.txt",
    "$env:TEMP\README_DECRYPT.txt"
)

foreach ($location in $noteLocations) {
    try {
        $ransomNote | Out-File -FilePath $location -Force
        Write-Host "[+] Nota de rescate creada en: $location" -ForegroundColor Red
    } catch {
        Write-Host "[!] No se pudo crear nota en: $location" -ForegroundColor Yellow
    }
}

# 7. Cambio de Fondo de Pantalla (Comportamiento típico)
Write-Host "`n[+] Fase 7: Intento de Cambio de Fondo de Pantalla" -ForegroundColor Green
Write-Host "[*] SIMULADO - No se cambia el fondo real" -ForegroundColor Yellow

# 8. Modificación de Registro (Simulado)
Write-Host "`n[+] Fase 8: Simulación de Persistencia" -ForegroundColor Green
Write-Host "[*] Ubicaciones típicas de persistencia (NO MODIFICADO):" -ForegroundColor Yellow
Write-Host "  - HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor DarkGray
Write-Host "  - HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor DarkGray
Write-Host "  - Carpeta de Inicio" -ForegroundColor DarkGray

# 9. Comunicación con C2 (Simulado)
Write-Host "`n[+] Fase 9: Intento de Comunicación con C2" -ForegroundColor Green

$c2Servers = @(
    "http://example-c2-server.com/api/register",
    "http://192.168.1.100:8080/checkin"
)

foreach ($server in $c2Servers) {
    try {
        Write-Host "[*] Intentando comunicación con: $server" -ForegroundColor Yellow
        
        $victimInfo = @{
            computer_id = $env:COMPUTERNAME
            user = $env:USERNAME
            files_encrypted = $encryptedCount
            timestamp = (Get-Date).ToString()
        }
        
        # Intento de conexión (fallará en red aislada)
        Write-Host "[!] Datos que se intentarían enviar:" -ForegroundColor Red
        $victimInfo | Format-Table -AutoSize
        
    } catch {
        Write-Host "[!] Comunicación fallida (esperado)" -ForegroundColor Red
    }
}

# 10. Eliminación de Logs del Sistema (Simulado)
Write-Host "`n[+] Fase 10: Intento de Eliminación de Logs" -ForegroundColor Green
Write-Host "[!] ALERTA: Comando típico de ransomware" -ForegroundColor Red
Write-Host "[*] Comando simulado: wevtutil cl System" -ForegroundColor Yellow
Write-Host "[*] NO EJECUTADO - Solo simulación" -ForegroundColor Green

# Listar logs sin eliminarlos
try {
    $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object {$_.RecordCount -gt 0} | Select-Object -First 5
    Write-Host "[*] Logs del sistema encontrados: $($logs.Count)" -ForegroundColor Yellow
} catch {
    Write-Host "[!] No se pudieron enumerar logs" -ForegroundColor Red
}

# 11. Indicadores de Compromiso
Write-Host "`n[+] Fase 11: Generación de Indicadores" -ForegroundColor Green

$iocs = @"
=== INDICADORES DE COMPROMISO (IOCs) ===

Archivos Creados:
- README_DECRYPT.txt (múltiples ubicaciones)
- Archivos con extensión .locked

Modificaciones:
- $encryptedCount archivos renombrados
- Notas de rescate en Desktop y Temp

Comportamientos Detectables:
- Enumeración de volúmenes
- Consulta de Shadow Copies
- Renombrado masivo de archivos
- Creación de múltiples archivos de texto idénticos
- Intentos de comunicación externa

Comandos Típicos de Ransomware (simulados):
- vssadmin delete shadows
- wevtutil cl
- bcdedit /set {default} recoveryenabled no

Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Sistema: $env:COMPUTERNAME
Usuario: $env:USERNAME
========================================
"@

Write-Host $iocs -ForegroundColor Cyan

# Guardar IOCs
$iocPath = "$env:TEMP\ransomware_iocs_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
$iocs | Out-File -FilePath $iocPath
Write-Host "[*] IOCs guardados en: $iocPath" -ForegroundColor Yellow

# 12. Proceso de "Recuperación"
Write-Host "`n[+] Fase 12: Proceso de Recuperación Simulada" -ForegroundColor Green
Write-Host "[*] Restaurando nombres originales de archivos..." -ForegroundColor Yellow

Start-Sleep -Seconds 2

$lockedFiles = Get-ChildItem -Path $simulationPath -Filter "*$ransomExtension"

foreach ($file in $lockedFiles) {
    try {
        $originalName = $file.Name -replace [regex]::Escape($ransomExtension), ""
        $originalPath = Join-Path $simulationPath $originalName
        
        Rename-Item -Path $file.FullName -NewName $originalName -Force
        Write-Host "[+] Restaurado: $($file.Name) -> $originalName" -ForegroundColor Green
    } catch {
        Write-Host "[!] Error restaurando: $($file.Name)" -ForegroundColor Red
    }
}

# Limpieza
Write-Host "`n[*] Limpiando archivos de simulación..." -ForegroundColor Yellow
Start-Sleep -Seconds 1

if (Test-Path $simulationPath) {
    Remove-Item $simulationPath -Recurse -Force -ErrorAction SilentlyContinue
}

# Eliminar notas de rescate
foreach ($location in $noteLocations) {
    if (Test-Path $location) {
        Remove-Item $location -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== SIMULACIÓN DE RANSOMWARE COMPLETADA ===" -ForegroundColor Green
Write-Host "`n[!] INDICADORES CRÍTICOS A MONITOREAR:" -ForegroundColor Magenta
Write-Host "  1. Eliminación de Shadow Copies (vssadmin)" -ForegroundColor White
Write-Host "  2. Modificación masiva/renombrado de archivos" -ForegroundColor White
Write-Host "  3. Creación de archivos README o notas de rescate" -ForegroundColor White
Write-Host "  4. Deshabilitación de servicios de seguridad" -ForegroundColor White
Write-Host "  5. Comandos bcdedit para deshabilitar recuperación" -ForegroundColor White
Write-Host "  6. Eliminación de logs del sistema" -ForegroundColor White
Write-Host "  7. Acceso a múltiples archivos en corto tiempo" -ForegroundColor White
Write-Host "  8. Procesos PowerShell con actividad de archivos masiva" -ForegroundColor White

Write-Host "`n[!] RECORDATORIO: Ningún archivo real fue cifrado" -ForegroundColor Green
