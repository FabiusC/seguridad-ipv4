@echo off
echo ====================================================
echo           FIREWALL IEEE 802.3 / IPv4 GUI
echo ====================================================
echo.

rem Verificar que existe la clase compilada
if not exist target\classes\com\tallerredes\FirewallGUI.class (
    echo ERROR: No se encuentra FirewallGUI.class
    echo Ejecuta primero: compilar_gui.bat
    pause
    exit /b 1
)

echo [INFO] Iniciando Firewall con Interfaz Grafica...
echo.
echo REQUISITOS:
echo ✓ Ejecutar como Administrador
echo ✓ Tener WinPcap o Npcap instalado
echo ✓ Seleccionar interfaz de red activa
echo.
echo FUNCIONALIDADES GUI:
echo • Tabla en tiempo real de paquetes capturados
echo • Estadisticas visuales de trafico filtrado
echo • Log de eventos de seguridad
echo • Analisis de campos IEEE 802.3 / IPv4
echo • Deteccion de herramientas de hacking
echo • Codificacion por colores segun protocolo
echo.
echo Presiona cualquier tecla para iniciar...
pause > nul

rem Configurar classpath con dependencias locales
set CLASSPATH=target\classes;lib\*

rem Ejecutar con configuracion de memoria
java -Xmx512m -cp %CLASSPATH% com.tallerredes.FirewallGUI

echo.
echo ====================================================
echo              SESION TERMINADA
echo ====================================================
pause
