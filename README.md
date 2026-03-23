# Firewall IEEE 802.3 / IPv4 - GUI Application

## Descripción

Aplicación de firewall con interfaz gráfica que analiza el tráfico de red en tiempo real, detectando amenazas mediante el análisis de campos IPv4 y Ethernet. Incluye detección de herramientas de hacking mediante patrones sospechosos en campos ID de paquetes IPv4.

## Requisitos

- **Java**: JDK 11 o superior
- **Sistema**: Windows 10/11
- **Npcap**: Para captura de paquetes (instalar desde https://npcap.com/)
- **Privilegios**: Ejecutar como Administrador

## Ejecución Rápida

**IMPORTANTE**: Siempre ejecutar desde una consola en **modo Administrador**

### Opción 1: Usar scripts incluidos

```bash
# 1. Compilar la aplicación
compilar_gui.bat

# 2. Ejecutar la aplicación (desde consola como Administrador)
ejecutar_gui.bat
```

### Opción 2: Comando directo (Recomendado)

```bash
# Ejecutar directamente desde consola como Administrador
java -Xmx512m -cp "target\classes;lib\*" com.tallerredes.FirewallGUI
```

### Opción 3: Comandos manuales completos

```bash
# 1. Descargar dependencias (primera vez)
powershell -ExecutionPolicy Bypass -File descargar_dependencias.ps1

# 2. Compilar
javac -cp "lib\*" -d target\classes src\main\java\com\tallerredes\FirewallGUI.java

# 3. Ejecutar como Administrador
java -Xmx512m -cp "target\classes;lib\*" com.tallerredes.FirewallGUI
```

### Pasos para ejecutar correctamente:

1. **Abrir PowerShell como Administrador** (clic derecho → "Ejecutar como administrador")
2. **Navegar al directorio del proyecto**: `cd "ruta\al\proyecto"`
3. **Ejecutar el comando**: `java -Xmx512m -cp "target\classes;lib\*" com.tallerredes.FirewallGUI`

## Características

### Análisis de Seguridad

- **Detección de IPv6**: Bloqueo automático por EtherType 0x86DD
- **Control de protocolos**: Bloqueo de GRE, ESP, AH
- **Validación TTL**: Rango válido 1-128
- **Anti-fragmentación**: Bloqueo de paquetes fragmentados
- **Detección de herramientas de hacking**: Análisis de campos ID sospechosos

### Detección de Herramientas de Hacking

- **0xDEAD**: Metasploit/Exploit frameworks
- **0xBEEF**: Browser Exploitation Framework
- **0x1337**: Herramientas con firma LEET
- **0x0000**: Port scanners (nmap/masscan)
- **0xFFFF**: Posibles buffer overflow/exploits

### Interfaz Gráfica

- **Tabla de paquetes**: Visualización en tiempo real
- **Código de colores**: Verde (ICMP), Azul (TCP), Amarillo (UDP), Rojo (Bloqueado)
- **Estadísticas**: Contadores de permitidos/bloqueados
- **Log de eventos**: Registro detallado con timestamp

## Uso de la Aplicación

1. **Ejecutar como Administrador** (obligatorio)
2. **Seleccionar interfaz de red** activa
3. **Iniciar captura** con el botón correspondiente
4. **Observar análisis** de paquetes en tiempo real
5. **Revisar estadísticas** y log de eventos

## Estructura del Proyecto

```
filtro_seguridad_ipv4/
├── src/main/java/com/tallerredes/
│   └── FirewallGUI.java           # Aplicación principal
├── lib/                           # Dependencias (pcap4j, JNA, SLF4J)
├── pom.xml                        # Configuración Maven
├── compilar_gui.bat              # Script de compilación
├── ejecutar_gui.bat              # Script de ejecución
└── descargar_dependencias.ps1    # Descarga automática de librerías
```

## Solución de Problemas

### "No se encontraron interfaces de red"

- **Instalar Npcap** desde https://npcap.com/
- **Ejecutar como Administrador** (OBLIGATORIO)
- Verificar que la interfaz de red esté activa

### "Java no reconocido"

- Instalar JDK 11 o superior
- Configurar JAVA_HOME y PATH del sistema

### "Error de dependencias"

- Ejecutar `descargar_dependencias.ps1`
- Verificar que exista el directorio `lib/` con los JARs

### "Access denied" o problemas de permisos

- **Abrir PowerShell/CMD como Administrador**
- Verificar que Npcap esté instalado correctamente
- En Windows 11: Settings → Privacy & Security → Windows Security → Virus & threat protection → Exclusions (agregar la carpeta del proyecto)

### El script ejecutar_gui.bat se cuelga

- **Usar el comando directo** desde consola como Administrador:
  ```bash
  java -Xmx512m -cp "target\classes;lib\*" com.tallerredes.FirewallGUI
  ```

## Estados de Paquetes

| Estado           | Color        | Descripción                        |
| ---------------- | ------------ | ---------------------------------- |
| HACKING TOOL  | Rojo intenso | Herramienta de hacking detectada   |
| BLOQUEADO        | Rojo claro   | Violación de política de seguridad |
| PERMITIDO (ICMP) | Verde        | Tráfico ICMP normal                |
| PERMITIDO (TCP)  | Azul         | Tráfico TCP normal                 |
| PERMITIDO (UDP)  | Amarillo     | Tráfico UDP normal                 |

# 2. Compilar el proyecto

compilar_gui.bat

# 3. Verificar que no hay errores

````

### Modos de Ejecución

#### 1. Interfaz Gráfica (Recomendado)

```bash
ejecutar_gui.bat
````

**Características:**

- ✅ Interfaz visual intuitiva
- ✅ Tabla de paquetes en tiempo real
- ✅ Estadísticas gráficas
- ✅ Log de eventos de seguridad
- ✅ Codificación por colores
- ✅ Ideal para capturas de pantalla

**Uso:**

1. Ejecutar como administrador
2. Seleccionar interfaz de red activa
3. Hacer clic en "Iniciar Captura"
4. Observar análisis en tiempo real

#### Estados de Paquetes

- **PERMITIDO**: Paquete pasó todos los filtros
- **BLOQUEADO**: Paquete violó una o más reglas
- **SOSPECHOSO**: Paquete con patrones anómalos

#### Razones de Bloqueo Comunes

- `IPv6 bloqueado (EtherType: 0x86DD)`
- `TTL anómalo: [valor]`
- `Protocolo [X] no permitido`
- `Paquete fragmentado detectado`
- `Tamaño excesivo: [X] bytes`

### Configuración Avanzada

#### Personalizar Reglas

Editar `SecurityConfig.java`:

```java
// Protocolos bloqueados
BLOCKED_PROTOCOLS = {47, 50, 51}; // GRE, ESP, AH

// Rango TTL válido
MIN_TTL = 1;
MAX_TTL = 128;

// Tamaño máximo de paquete
MAX_PACKET_SIZE = 1500;
```

#### Rate Limiting

```java
// Paquetes por segundo por IP
RATE_LIMIT = 100;
RATE_WINDOW = 1000; // ms
```

## 👨‍💻 Autor

Desarrollado como solución de seguridad para la asignatura Redes de Comunicaciones 3 por Fabio Andres Hurtado Cardona
