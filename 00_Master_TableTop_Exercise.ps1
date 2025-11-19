# ============================================
# Script Maestro: Table Top Exercise
# Proposito: Ejecutar simulaciones de manera controlada
# Uso: SOLO en entornos de prueba autorizados
# ============================================

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "          EJERCICIO TABLE TOP - SIMULACION SOC                " -ForegroundColor Cyan
Write-Host "                                                               " -ForegroundColor Cyan
Write-Host "  ADVERTENCIA: Solo para entornos de prueba autorizados       " -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

Write-Host "`n[!] IMPORTANTE: Este script ejecutara simulaciones de ataques" -ForegroundColor Yellow
Write-Host "[!] NO ejecutar en entornos de produccion" -ForegroundColor Red
Write-Host "[!] Asegurese de tener autorizacion por escrito" -ForegroundColor Red

# Verificacion de confirmacion
Write-Host "`nEsta seguro de que desea continuar? (SI/NO): " -NoNewline -ForegroundColor Yellow
$confirmation = Read-Host

if ($confirmation -ne "SI") {
    Write-Host "`n[*] Simulacion cancelada por el usuario" -ForegroundColor Yellow
    exit
}

# Informacion del entorno
Write-Host "`n[*] Informacion del Entorno:" -ForegroundColor Cyan
Write-Host "    Equipo: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "    Usuario: $env:USERNAME" -ForegroundColor White
Write-Host "    Dominio: $env:USERDOMAIN" -ForegroundColor White
Write-Host "    Fecha y Hora: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

# Crear directorio de logs
$logDir = "$env:TEMP\TableTop_Exercise_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Write-Host "`n[*] Logs se guardaran en: $logDir" -ForegroundColor Cyan

# Menu de simulaciones
Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "    SELECCIONE SIMULACIONES A EJECUTAR        " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

Write-Host "`n1. Reconocimiento del Sistema" -ForegroundColor White
Write-Host "   - Enumeracion de sistema, procesos, red, usuarios" -ForegroundColor DarkGray
Write-Host "   - Duracion aproximada: 2-3 minutos" -ForegroundColor DarkGray

Write-Host "`n2. Trafico Anomalo y C2" -ForegroundColor White
Write-Host "   - Beaconing, DNS tunneling, puertos sospechosos" -ForegroundColor DarkGray
Write-Host "   - Duracion aproximada: 3-5 minutos" -ForegroundColor DarkGray

Write-Host "`n3. Exfiltracion de Datos" -ForegroundColor White
Write-Host "   - Compresion, HTTP POST, DNS, ICMP, SMB" -ForegroundColor DarkGray
Write-Host "   - Duracion aproximada: 3-4 minutos" -ForegroundColor DarkGray

Write-Host "`n4. Simulacion de Ransomware (SIN CIFRADO)" -ForegroundColor White
Write-Host "   - Shadow copies, renombrado, notas de rescate" -ForegroundColor DarkGray
Write-Host "   - Duracion aproximada: 3-4 minutos" -ForegroundColor DarkGray

Write-Host "`n5. Movimiento Lateral" -ForegroundColor White
Write-Host "   - Escaneo de red, SMB, WMI, RDP, credenciales" -ForegroundColor DarkGray
Write-Host "   - Duracion aproximada: 4-5 minutos" -ForegroundColor DarkGray

Write-Host "`n6. EJECUTAR TODAS (Kill Chain Completa)" -ForegroundColor Yellow
Write-Host "   - Simula un ataque completo paso a paso" -ForegroundColor DarkGray
Write-Host "   - Duracion aproximada: 15-20 minutos" -ForegroundColor DarkGray

Write-Host "`n0. Salir" -ForegroundColor Red

Write-Host "`n[?] Ingrese su opcion (separadas por coma para multiples, ej: 1,3,4): " -NoNewline -ForegroundColor Yellow
$selection = Read-Host

# Procesar seleccion
$options = $selection -split ',' | ForEach-Object { $_.Trim() }

# Funcion para ejecutar script con logging
function Invoke-SimulationScript {
    param(
        [string]$ScriptName,
        [string]$ScriptPath,
        [string]$LogPath
    )
    
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "  EJECUTANDO: $ScriptName" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    
    $startTime = Get-Date
    
    try {
        # Ejecutar script y capturar salida
        $output = & $ScriptPath 2>&1
        
        # Guardar log
        $logContent = "=== $ScriptName ===" + "`n"
        $logContent += "Inicio: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" + "`n"
        $logContent += "Fin: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" + "`n"
        $logContent += "Duracion: $((New-TimeSpan -Start $startTime -End (Get-Date)).TotalSeconds) segundos" + "`n`n"
        $logContent += "=== SALIDA DEL SCRIPT ===" + "`n"
        $logContent += $($output | Out-String)
        $logContent += "`n================================"
        
        $logContent | Out-File -FilePath $LogPath -Encoding UTF8
        
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        Write-Host "`n[+] Simulacion completada en $([math]::Round($duration, 2)) segundos" -ForegroundColor Green
        Write-Host "[*] Log guardado en: $LogPath" -ForegroundColor Cyan
        
        return $true
    } catch {
        Write-Host "`n[!] Error al ejecutar $ScriptName" -ForegroundColor Red
        Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Definir scripts
$scripts = @{
    "1" = @{
        Name = "Reconocimiento del Sistema"
        Path = ".\01_Reconnaissance_Simulation.ps1"
        Log = "$logDir\01_Reconnaissance.log"
    }
    "2" = @{
        Name = "Trafico Anomalo y C2"
        Path = ".\02_Network_Anomaly_Simulation.ps1"
        Log = "$logDir\02_Network_Anomaly.log"
    }
    "3" = @{
        Name = "Exfiltracion de Datos"
        Path = ".\03_Data_Exfiltration_Simulation.ps1"
        Log = "$logDir\03_Data_Exfiltration.log"
    }
    "4" = @{
        Name = "Simulacion de Ransomware"
        Path = ".\04_Ransomware_Simulation.ps1"
        Log = "$logDir\04_Ransomware.log"
    }
    "5" = @{
        Name = "Movimiento Lateral"
        Path = ".\05_Lateral_Movement_Simulation.ps1"
        Log = "$logDir\05_Lateral_Movement.log"
    }
}

# Ejecutar simulaciones seleccionadas
$executed = @()
$failed = @()

foreach ($option in $options) {
    if ($option -eq "0") {
        Write-Host "`n[*] Saliendo..." -ForegroundColor Yellow
        exit
    }
    
    if ($option -eq "6") {
        # Ejecutar todas en orden
        Write-Host "`n[*] Ejecutando Kill Chain Completa..." -ForegroundColor Yellow
        Write-Host "[*] Pausa de 5 segundos entre cada fase..." -ForegroundColor Yellow
        
        foreach ($key in 1..5) {
            $script = $scripts["$key"]
            
            if (Test-Path $script.Path) {
                $result = Invoke-SimulationScript -ScriptName $script.Name -ScriptPath $script.Path -LogPath $script.Log
                
                if ($result) {
                    $executed += $script.Name
                } else {
                    $failed += $script.Name
                }
                
                # Pausa entre fases
                if ($key -lt 5) {
                    Write-Host "`n[*] Esperando 5 segundos antes de la siguiente fase..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 5
                }
            } else {
                Write-Host "`n[!] Script no encontrado: $($script.Path)" -ForegroundColor Red
                $failed += $script.Name
            }
        }
        break
    }
    
    # Ejecutar script individual
    if ($scripts.ContainsKey($option)) {
        $script = $scripts[$option]
        
        if (Test-Path $script.Path) {
            $result = Invoke-SimulationScript -ScriptName $script.Name -ScriptPath $script.Path -LogPath $script.Log
            
            if ($result) {
                $executed += $script.Name
            } else {
                $failed += $script.Name
            }
        } else {
            Write-Host "`n[!] Script no encontrado: $($script.Path)" -ForegroundColor Red
            $failed += $script.Name
        }
    } else {
        Write-Host "`n[!] Opcion invalida: $option" -ForegroundColor Red
    }
}

# Resumen final
Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "              RESUMEN DEL EJERCICIO            " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

Write-Host "`n[*] Simulaciones Ejecutadas: $($executed.Count)" -ForegroundColor Green
foreach ($sim in $executed) {
    Write-Host "    [+] $sim" -ForegroundColor Green
}

if ($failed.Count -gt 0) {
    Write-Host "`n[!] Simulaciones Fallidas: $($failed.Count)" -ForegroundColor Red
    foreach ($sim in $failed) {
        Write-Host "    [!] $sim" -ForegroundColor Red
    }
}

Write-Host "`n[*] Directorio de Logs: $logDir" -ForegroundColor Cyan

# Generar reporte consolidado
$reportPath = "$logDir\REPORTE_CONSOLIDADO.txt"

$reportHeader = "===============================================`n"
$reportHeader += "  REPORTE CONSOLIDADO - TABLE TOP EXERCISE`n"
$reportHeader += "===============================================`n`n"

$reportInfo = "INFORMACION GENERAL:`n"
$reportInfo += "--------------------`n"
$reportInfo += "Fecha y Hora: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
$reportInfo += "Equipo: $env:COMPUTERNAME`n"
$reportInfo += "Usuario: $env:USERNAME`n"
$reportInfo += "Dominio: $env:USERDOMAIN`n`n"

$reportExecuted = "SIMULACIONES EJECUTADAS:`n"
$reportExecuted += "-----------------------`n"
$reportExecuted += "Total: $($executed.Count)`n"
foreach ($sim in $executed) {
    $reportExecuted += "OK $sim`n"
}
$reportExecuted += "`n"

$reportFailed = "SIMULACIONES FALLIDAS:`n"
$reportFailed += "---------------------`n"
$reportFailed += "Total: $($failed.Count)`n"
foreach ($sim in $failed) {
    $reportFailed += "X $sim`n"
}
$reportFailed += "`n"

$reportIOC = "INDICADORES DE COMPROMISO GENERADOS:`n"
$reportIOC += "------------------------------------`n"
$reportIOC += "1. RECONOCIMIENTO:`n"
$reportIOC += "   - Enumeracion de sistema, red y usuarios`n"
$reportIOC += "   - Archivos temporales creados en $env:TEMP`n`n"
$reportIOC += "2. TRAFICO ANOMALO:`n"
$reportIOC += "   - Beaconing periodico`n"
$reportIOC += "   - Consultas DNS sospechosas`n"
$reportIOC += "   - Conexiones a puertos no estandar`n`n"
$reportIOC += "3. EXFILTRACION:`n"
$reportIOC += "   - Archivos comprimidos`n"
$reportIOC += "   - POST requests con datos`n"
$reportIOC += "   - DNS queries con datos codificados`n`n"
$reportIOC += "4. RANSOMWARE:`n"
$reportIOC += "   - Archivos renombrados con extension .locked`n"
$reportIOC += "   - Notas de rescate (README_DECRYPT.txt)`n"
$reportIOC += "   - Consultas a Shadow Copies`n`n"
$reportIOC += "5. MOVIMIENTO LATERAL:`n"
$reportIOC += "   - Escaneo de red local`n"
$reportIOC += "   - Intentos de acceso SMB`n"
$reportIOC += "   - Enumeracion de servicios remotos`n`n"

$reportLogs = "LOGS GENERADOS:`n"
$reportLogs += "--------------`n"
$reportLogs += "Ubicacion: $logDir`n"
$logFiles = Get-ChildItem $logDir -File
foreach ($file in $logFiles) {
    $reportLogs += "- $($file.Name)`n"
}
$reportLogs += "`n"

$reportRecommendations = "RECOMENDACIONES POST-EJERCICIO:`n"
$reportRecommendations += "-------------------------------`n"
$reportRecommendations += "1. Revisar logs del SIEM/XDR para detectar alertas generadas`n"
$reportRecommendations += "2. Verificar eventos de Windows (Event Viewer)`n"
$reportRecommendations += "3. Analizar trafico de red capturado`n"
$reportRecommendations += "4. Evaluar tiempo de deteccion y respuesta`n"
$reportRecommendations += "5. Documentar gaps en la deteccion`n"
$reportRecommendations += "6. Actualizar playbooks de respuesta a incidentes`n`n"

$reportCleanup = "PASOS DE LIMPIEZA:`n"
$reportCleanup += "-----------------`n"
$reportCleanup += "1. Verificar archivos temporales en $env:TEMP`n"
$reportCleanup += "2. Eliminar directorio: $logDir`n"
$reportCleanup += "3. Limpiar logs de eventos (opcional en entorno de prueba)`n"
$reportCleanup += "4. Restaurar configuraciones modificadas`n`n"

$reportFooter = "===============================================`n"
$reportFooter += "    FIN DEL REPORTE - EJERCICIO TABLE TOP`n"
$reportFooter += "===============================================`n"

$fullReport = $reportHeader + $reportInfo + $reportExecuted + $reportFailed + $reportIOC + $reportLogs + $reportRecommendations + $reportCleanup + $reportFooter

$fullReport | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "`n[*] Reporte consolidado generado: $reportPath" -ForegroundColor Cyan

# Abrir directorio de logs
Write-Host "`n[?] Desea abrir el directorio de logs? (S/N): " -NoNewline -ForegroundColor Yellow
$openLogs = Read-Host

if ($openLogs -eq "S" -or $openLogs -eq "s") {
    Start-Process explorer.exe -ArgumentList $logDir
}

Write-Host "`n[+] Ejercicio Table Top completado exitosamente" -ForegroundColor Green
Write-Host "[*] Revise los logs y alertas generadas en su sistema de monitoreo" -ForegroundColor Cyan
Write-Host "`nGracias por usar el simulador de Table Top Exercise!" -ForegroundColor Cyan
