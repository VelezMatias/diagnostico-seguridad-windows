# ===============================
# Windows 11 Security Diagnostic Script V 1.01
# ===============================
# Guarda todo en: C:\Informe_de_Seguridad\
# Ejecutar en PowerShell como Administrador

# ==== Configuración inicial ====
$fecha = Get-Date -Format "yyyyMMdd_HHmmss"
$baseDir = "C:\Informe_de_Seguridad"
$base = "$baseDir\SecurityCheck_$fecha"

# Crear carpeta principal si no existe
if (!(Test-Path -Path $baseDir)) {
    New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
}

# Crear subcarpeta para este informe
New-Item -ItemType Directory -Force -Path $base | Out-Null
$reporte = "$base\SecurityReport.txt"

# Crear archivo vacío con codificación UTF-8
"" | Out-File -FilePath $reporte -Encoding utf8

Function Write-Log($text) {
    $linea = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $text
    Write-Host $linea
    $linea | Out-File -FilePath $reporte -Append -Encoding utf8
}

Write-Log "=== INICIO DEL INFORME DE SEGURIDAD ($fecha) ==="

# ==== 1. Información del sistema ====
Write-Log "`n--- INFORMACIÓN DEL SISTEMA ---"
systeminfo | Out-File "$base\systeminfo.txt" -Encoding utf8
Get-Content "$base\systeminfo.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 2. Procesos activos y firmas digitales ====
Write-Log "`n--- PROCESOS ACTIVOS ---"
$procesos = Get-Process | Where-Object { $_.Path -ne $null } | ForEach-Object {
    try {
        $sig = (Get-AuthenticodeSignature $_.Path).Status
    }
    catch {
        $sig = "Error"
    }
    "{0,-6} {1,-30} {2,-60} {3}" -f $_.Id, $_.ProcessName, $_.Path, $sig
}
$procesos | Out-File "$base\processes.txt" -Encoding utf8
$procesos | Out-File $reporte -Append -Encoding utf8

# ==== 3. Conexiones de red ====
Write-Log "`n--- CONEXIONES DE RED ACTIVAS ---"
netstat -ano | Out-File "$base\netstat.txt" -Encoding utf8
Get-Content "$base\netstat.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 4. Servicios y drivers ====
Write-Log "`n--- SERVICIOS ---"
Get-CimInstance Win32_Service |
Select-Object Name, DisplayName, State, StartMode, PathName |
Out-File "$base\services.txt" -Encoding utf8
Get-Content "$base\services.txt" | Out-File $reporte -Append -Encoding utf8

Write-Log "`n--- DRIVERS RECIENTES ---"
Get-ChildItem C:\Windows\System32\drivers |
Sort-Object LastWriteTime -Descending |
Select-Object Name, LastWriteTime |
Out-File "$base\drivers.txt" -Encoding utf8
Get-Content "$base\drivers.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 5. Tareas programadas ====
Write-Log "`n--- TAREAS PROGRAMADAS (NO MICROSOFT) ---"
Get-ScheduledTask | Where-Object { $_.TaskName -notlike "Microsoft*" } |
Select-Object TaskName, State, @{n = "Accion"; e = { $_.Actions | % { $_.Execute } } } |
Out-File "$base\tasks.txt" -Encoding utf8
Get-Content "$base\tasks.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 6. Programas de inicio ====
Write-Log "`n--- PROGRAMAS DE INICIO (REGISTRO) ---"
$runHKLM = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | Out-String
$runHKCU = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | Out-String
"HKLM:\Run`n$runHKLM" | Out-File $reporte -Append -Encoding utf8
"HKCU:\Run`n$runHKCU" | Out-File $reporte -Append -Encoding utf8

# ==== 7. Usuarios locales ====
Write-Log "`n--- USUARIOS LOCALES ---"
Get-LocalUser | Select-Object Name, Enabled, LastLogon |
Out-File "$base\users.txt" -Encoding utf8
Get-Content "$base\users.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 8. Eventos de inicio de sesión ====
Write-Log "`n--- ÚLTIMOS 50 EVENTOS DE INICIO DE SESIÓN ---"
Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4624 } -MaxEvents 50 |
Select-Object TimeCreated, Message |
Out-File "$base\logons.txt" -Encoding utf8
Get-Content "$base\logons.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 9. Firewall activo ====
Write-Log "`n--- CONFIGURACIÓN DEL FIREWALL ---"
Get-NetFirewallProfile | Out-File "$base\firewall.txt" -Encoding utf8
Get-Content "$base\firewall.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 10. Hosts y DNS ====
Write-Log "`n--- ARCHIVO HOSTS ---"
Get-Content C:\Windows\System32\drivers\etc\hosts |
Out-File "$base\hosts.txt" -Encoding utf8
Get-Content "$base\hosts.txt" | Out-File $reporte -Append -Encoding utf8

Write-Log "`n--- CONFIGURACIÓN DNS ---"
ipconfig /all | Out-File "$base\dns.txt" -Encoding utf8
Get-Content "$base\dns.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 11. Integridad del sistema ====
Write-Log "`n--- VERIFICACIÓN DE ARCHIVOS DE SISTEMA ---"
sfc /scannow | Out-File "$base\sfc.txt" -Encoding utf8
Get-Content "$base\sfc.txt" | Out-File $reporte -Append -Encoding utf8

Write-Log "`n--- DISM CheckHealth ---"
DISM /Online /Cleanup-Image /CheckHealth | Out-File "$base\dism.txt" -Encoding utf8
Get-Content "$base\dism.txt" | Out-File $reporte -Append -Encoding utf8

# ==== 12. Compresión ====
Write-Log "`n--- COMPRESIÓN FINAL ---"
try {
    if (Test-Path "${base}.zip") { Remove-Item "${base}.zip" -Force }
    Compress-Archive -Path $base -DestinationPath "${base}.zip" -Force
}
catch {
    Write-Log "Error durante la compresión: $_"
}

Write-Log "`n=== INFORME COMPLETADO ==="
Write-Host "Informe generado: ${base}.zip"

# ==== 13. Abrir carpeta ====
Start-Process explorer.exe $baseDir

# ==== 14. Generar resumen de seguridad ====
$summaryFile = "$base\Resumen.txt"
$resumen = @()
$resumen += "=== RESUMEN DE SEGURIDAD ==="
$resumen += "Fecha: $fecha"
$resumen += "-------------------------------------------"

# Revisar estado del firewall
$fw = Get-Content "$base\firewall.txt" -ErrorAction SilentlyContinue
if ($fw -match "True" -and $fw -notmatch "False") {
    $resumen += "Firewall: activo en todos los perfiles."
}
else {
    $resumen += "Firewall: uno o más perfiles desactivados o sin respuesta."
}

# Revisar integridad de sistema (SFC/DISM)
$sfc = Get-Content "$base\sfc.txt" -ErrorAction SilentlyContinue
if ($sfc -match "corrupt" -or $sfc -match "repair") {
    $resumen += "Integridad del sistema: archivos dañados detectados."
}
else {
    $resumen += "Integridad del sistema: sin daños."
}

$dism = Get-Content "$base\dism.txt" -ErrorAction SilentlyContinue
if ($dism -match "repairable") {
    $resumen += "DISM: imagen del sistema necesita reparación."
}
else {
    $resumen += "DISM: sin problemas detectados."
}

# Revisar procesos sin firma digital
$proc = Get-Content "$base\processes.txt" -ErrorAction SilentlyContinue
if ($proc -match "UnknownError" -or $proc -match "NotSigned" -or $proc -match "Error") {
    $resumen += "Procesos sin firma digital detectados (ver processes.txt)."
}
else {
    $resumen += "Procesos: todos firmados digitalmente."
}

# Revisar hosts
$hosts = Get-Content "$base\hosts.txt" -ErrorAction SilentlyContinue
if ($hosts | Where-Object { $_ -match "^[0-9]" -and $_ -notmatch "127.0.0.1|::1" }) {
    $resumen += "Archivo hosts: contiene redirecciones no estándar."
}
else {
    $resumen += "Archivo hosts: sin entradas sospechosas."
}

# Revisar servicios
$services = Get-Content "$base\services.txt" -ErrorAction SilentlyContinue
if ($services -match "Stopped" -and $services -match "StartMode\s+Auto") {
    $resumen += "Servicios automáticos detenidos (ver services.txt)."
}
else {
    $resumen += "Servicios: funcionamiento normal."
}

# Generar resultado final
$resumen += "-------------------------------------------"
if ($resumen -match "detectados" -or $resumen -match "desactivados" -or $resumen -match "reparación") {
    $resumen += "Estado general: Se detectaron posibles anomalías. Revisar los archivos indicados."
}
else {
    $resumen += "Estado general: Sin amenazas detectadas."
}

# Guardar resumen
$resumen | Out-File -FilePath $summaryFile -Encoding utf8
Write-Host "`nResumen generado: $summaryFile"
Write-Log "`n=== ANÁLISIS FINAL COMPLETADO ==="
