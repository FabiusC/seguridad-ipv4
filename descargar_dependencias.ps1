# Script para descargar dependencias sin Maven
$libDir = "d:\Usuarios\fabio\OneDrive\Documents\Programas\Java\filtro_seguridad_ipv4\lib"

# URLs de las dependencias
$dependencies = @(
    "https://repo1.maven.org/maven2/org/pcap4j/pcap4j-core/1.8.2/pcap4j-core-1.8.2.jar",
    "https://repo1.maven.org/maven2/org/pcap4j/pcap4j-packetfactory-static/1.8.2/pcap4j-packetfactory-static-1.8.2.jar",
    "https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.13.0/jna-5.13.0.jar",
    "https://repo1.maven.org/maven2/net/java/dev/jna/jna-platform/5.13.0/jna-platform-5.13.0.jar",
    "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar",
    "https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/1.7.36/slf4j-simple-1.7.36.jar"
)

Write-Host "Descargando dependencias..." -ForegroundColor Green

foreach ($url in $dependencies) {
    $fileName = [System.IO.Path]::GetFileName($url)
    $filePath = Join-Path $libDir $fileName
    
    Write-Host "Descargando $fileName..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $url -OutFile $filePath -UseBasicParsing
        Write-Host "✓ $fileName descargado" -ForegroundColor Green
    } catch {
        Write-Host "✗ Error descargando $fileName : $_" -ForegroundColor Red
    }
}

Write-Host "`nDependencias descargadas en: $libDir" -ForegroundColor Cyan
Write-Host "Ahora puedes compilar con: javac -cp `"src\main\java;lib\*`" ..." -ForegroundColor Cyan
