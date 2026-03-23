@echo off
echo ====================================================
echo           COMPILACION DE FIREWALL GUI
echo ====================================================
echo.

rem Limpiar directorio target
if exist target rmdir /s /q target
mkdir target\classes

echo [PASO 1] Compilando FirewallGUI con dependencias existentes...
javac -cp "lib\*" -d target\classes src\main\java\com\tallerredes\FirewallGUI.java

if errorlevel 1 (
    echo ERROR: Fallo en la compilacion
    echo Verifica que Java este instalado y en el PATH
    pause
    exit /b 1
)

echo.
echo [PASO 2] Verificando archivos compilados...
if exist target\classes\com\tallerredes\FirewallGUI.class (
    echo ✓ FirewallGUI compilado correctamente
) else (
    echo ✗ Error al compilar FirewallGUI
    pause
    exit /b 1
)

echo.
echo ====================================================
echo          COMPILACION COMPLETADA EXITOSAMENTE
echo ====================================================
echo.
echo ARCHIVO DISPONIBLE:
echo   - FirewallGUI.class (Interfaz grafica)
echo.
echo Para ejecutar la aplicacion:
echo   ejecutar_gui.bat
echo.
pause
