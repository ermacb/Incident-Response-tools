<#
.SYNOPSIS
    Busca archivos sospechosos en el sistema
.DESCRIPTION
    Identifica archivos por extensión, fecha, ubicación y características sospechosas
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IR_SuspiciousFiles",
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 7
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "$OutputPath\Scan_$timestamp"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "[+] Iniciando búsqueda de archivos sospechosos..." -ForegroundColor Green

# Extensiones sospechosas
$suspiciousExtensions = @(
    "*.exe", "*.dll", "*.scr", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js", "*.jar",
    "*.hta", "*.msi", "*.com", "*.pif", "*.lnk", "*.reg", "*.tmp", "*.dat"
)

# Extensiones de malware conocidas
$malwareExtensions = @(
    "*.encrypted", "*.locked", "*.crypto", "*.cerber", "*.locky", "*.zepto",
    "*.odin", "*.thor", "*.aesir", "*.zzzzz", "*.micro", "*.cryp1", "*.crypt",
    "*.cryptolocker", "*.cryptowall", "*.vault", "*.petya", "*.wannacry"
)

# 1. Buscar por extensiones sospechosas
Write-Host "[*] Buscando archivos por extensiones sospechosas..." -ForegroundColor Yellow
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -gt 0}

foreach ($drive in $drives) {
    Write-Host "  [*] Escaneando unidad: $($drive.Root)" -ForegroundColor Cyan
    
    foreach ($ext in $suspiciousExtensions) {
        try {
            Get-ChildItem -Path $drive.Root -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force |
                Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$DaysBack)} |
                Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime |
                Export-Csv "$outputDir\SuspiciousFiles_$($ext.Replace('*.','')).csv" -Append -NoTypeInformation
        } catch {}
    }
}

# 2. Buscar extensiones de ransomware
Write-Host "[*] Buscando extensiones de ransomware..." -ForegroundColor Yellow
foreach ($drive in $drives) {
    foreach ($ext in $malwareExtensions) {
        try {
            Get-ChildItem -Path $drive.Root -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force |
                Select-Object FullName, Length, CreationTime, LastWriteTime |
                Export-Csv "$outputDir\Ransomware_Files.csv" -Append -NoTypeInformation
        } catch {}
    }
}

# 3. Archivos modificados recientemente
Write-Host "[*] Buscando archivos modificados recientemente..." -ForegroundColor Yellow
foreach ($drive in $drives) {
    try {
        Get-ChildItem -Path $drive.Root -Recurse -ErrorAction SilentlyContinue -Force |
            Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$DaysBack) -and !$_.PSIsContainer} |
            Select-Object FullName, Length, Extension, CreationTime, LastWriteTime, Attributes |
            Export-Csv "$outputDir\RecentlyModified.csv" -NoTypeInformation
    } catch {}
}

# 4. Rutas sospechosas
Write-Host "[*] Buscando archivos en rutas sospechosas..." -ForegroundColor Yellow
$suspiciousPaths = @(
    "$env:TEMP",
    "$env:TMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "C:\Users\Public",
    "C:\ProgramData",
    "C:\Windows\Temp",
    "C:\Windows\System32\Tasks",
    "C:\Windows\Tasks"
)

foreach ($path in $suspiciousPaths) {
    if (Test-Path $path) {
        Write-Host "  [*] Escaneando: $path" -ForegroundColor Cyan
        Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Force |
            Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$DaysBack) -and !$_.PSIsContainer} |
            Select-Object FullName, Length, Extension, CreationTime, LastWriteTime |
            Export-Csv "$outputDir\SuspiciousPaths.csv" -Append -NoTypeInformation
    }
}

# 5. Archivos ocultos
Write-Host "[*] Buscando archivos ocultos..." -ForegroundColor Yellow
foreach ($drive in $drives) {
    try {
        Get-ChildItem -Path $drive.Root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {$_.Attributes -match "Hidden" -and !$_.PSIsContainer} |
            Select-Object FullName, Length, Attributes, CreationTime, LastWriteTime |
            Export-Csv "$outputDir\HiddenFiles.csv" -Append -NoTypeInformation
    } catch {}
}

# 6. Archivos sin extensión
Write-Host "[*] Buscando archivos sin extensión..." -ForegroundColor Yellow
foreach ($drive in $drives) {
    try {
        Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue -Force |
            Where-Object {[string]::IsNullOrEmpty($_.Extension) -and $_.Length -gt 0} |
            Select-Object FullName, Length, CreationTime, LastWriteTime |
            Export-Csv "$outputDir\FilesWithoutExtension.csv" -Append -NoTypeInformation
    } catch {}
}

# 7. Archivos ejecutables fuera de Program Files
Write-Host "[*] Buscando ejecutables fuera de ubicaciones estándar..." -ForegroundColor Yellow
Get-ChildItem -Path C:\ -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue -Force |
    Where-Object {$_.FullName -notmatch "Program Files" -and $_.FullName -notmatch "Windows" -and $_.LastWriteTime -gt (Get-Date).AddDays(-$DaysBack)} |
    Select-Object FullName, Length, CreationTime, LastWriteTime, @{Name="FileHash";Expression={(Get-FileHash $_.FullName -Algorithm SHA256).Hash}} |
    Export-Csv "$outputDir\ExecutablesOutsideStandardPaths.csv" -NoTypeInformation

# 8. Archivos con doble extensión
Write-Host "[*] Buscando archivos con doble extensión..." -ForegroundColor Yellow
foreach ($drive in $drives) {
    try {
        Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue -Force |
            Where-Object {$_.Name -match '\.\w+\.\w+$'} |
            Select-Object FullName, Name, Length, CreationTime, LastWriteTime |
            Export-Csv "$outputDir\DoubleExtension.csv" -Append -NoTypeInformation
    } catch {}
}

# 9. Archivos muy grandes (posibles dumps o archivos cifrados)
Write-Host "[*] Buscando archivos muy grandes..." -ForegroundColor Yellow
foreach ($drive in $drives) {
    try {
        Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue -Force |
            Where-Object {$_.Length -gt 100MB} |
            Select-Object FullName, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB,2)}}, CreationTime, LastWriteTime |
            Sort-Object SizeMB -Descending |
            Export-Csv "$outputDir\LargeFiles.csv" -NoTypeInformation
    } catch {}
}

# 10. Generar resumen
Write-Host "[*] Generando resumen..." -ForegroundColor Yellow
$summary = @"
=== RESUMEN DE BÚSQUEDA DE ARCHIVOS SOSPECHOSOS ===
Fecha: $(Get-Date)
Días analizados: $DaysBack días hacia atrás
Unidades escaneadas: $($drives.Count)

Archivos encontrados por categoría:
"@
$summary | Out-File "$outputDir\Summary.txt"

$csvFiles = Get-ChildItem -Path $outputDir -Filter "*.csv"
foreach ($csv in $csvFiles) {
    $count = (Import-Csv $csv.FullName).Count
    "- $($csv.BaseName): $count archivos" | Out-File "$outputDir\Summary.txt" -Append
}

Write-Host "[+] Búsqueda completada!" -ForegroundColor Green
Write-Host "[+] Resultados en: $outputDir" -ForegroundColor Cyan
Write-Host "[!] Revisa los archivos CSV para análisis detallado" -ForegroundColor Yellow