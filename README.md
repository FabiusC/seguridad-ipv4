# 🔒 Firewall IEEE 802.3 / IPv4 - GUI Application

## Descripción

Aplicación de firewall con interfaz gráfica que analiza el tráfico de red en tiempo real, detectando amenazas mediante el análisis de campos IPv4 y Ethernet. Incluye detección de herramientas de hacking mediante patrones sospechosos en campos ID de paquetes IPv4.

## 📋 Requisitos

- **Java**: JDK 11 o superior
- **Sistema**: Windows 10/11
- **Npcap**: Para captura de paquetes (instalar desde https://npcap.com/)
- **Privilegios**: Ejecutar como Administrador

## 🚀 Ejecución Rápida

⚠️ **IMPORTANTE**: Siempre ejecutar desde una consola en **modo Administrador**

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

### 🔑 Pasos para ejecutar correctamente:

1. **Abrir PowerShell como Administrador** (clic derecho → "Ejecutar como administrador")
2. **Navegar al directorio del proyecto**: `cd "ruta\al\proyecto"`
3. **Ejecutar el comando**: `java -Xmx512m -cp "target\classes;lib\*" com.tallerredes.FirewallGUI`

## 🔧 Características

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

## 🎯 Uso de la Aplicación

1. **Ejecutar como Administrador** (obligatorio)
2. **Seleccionar interfaz de red** activa
3. **Iniciar captura** con el botón correspondiente
4. **Observar análisis** de paquetes en tiempo real
5. **Revisar estadísticas** y log de eventos

## 📁 Estructura del Proyecto

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

## ⚠️ Solución de Problemas

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

## 📈 Estados de Paquetes

| Estado           | Color        | Descripción                        |
| ---------------- | ------------ | ---------------------------------- |
| 🚨 HACKING TOOL  | Rojo intenso | Herramienta de hacking detectada   |
| BLOQUEADO        | Rojo claro   | Violación de política de seguridad |
| PERMITIDO (ICMP) | Verde        | Tráfico ICMP normal                |
| PERMITIDO (TCP)  | Azul         | Tráfico TCP normal                 |
| PERMITIDO (UDP)  | Amarillo     | Tráfico UDP normal                 |

# 2. Compilar el proyecto

compilar_gui.bat

# 3. Verificar que no hay errores

````

### 🚀 Modos de Ejecución

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

#### 2. Consola con Colores

```bash
ejecutar.bat ScreenshotFirewall
```

**Características:**

- ✅ Salida colorizada en terminal
- ✅ Análisis detallado de campos
- ✅ Estadísticas en tiempo real
- ✅ Ideal para documentación

#### 3. Consola Básica

```bash
ejecutar.bat SimpleFirewall
```

**Características:**

- ✅ Implementación minimalista
- ✅ Bajo uso de recursos
- ✅ Salida de texto simple

#### 4. Versión Avanzada

```bash
ejecutar.bat App
```

**Características:**

- ✅ Todas las funcionalidades
- ✅ Análisis profundo
- ✅ Configuración avanzada

#### 5. Generador de Tráfico

```bash
ejecutar.bat TrafficGenerator
```

**Características:**

- ✅ Genera tráfico de prueba
- ✅ Múltiples protocolos
- ✅ Patrones sospechosos
- ✅ Útil para testing

### 📊 Interpretación de Resultados

#### Códigos de Color (GUI)

- 🟢 **Verde (ICMP)**: Tráfico ICMP permitido
- 🔵 **Azul (TCP)**: Tráfico TCP permitido
- 🟡 **Amarillo (UDP)**: Tráfico UDP permitido
- 🔴 **Rojo (Bloqueado)**: Paquetes bloqueados por políticas

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

### 🔧 Configuración Avanzada

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

### 🐛 Solución de Problemas

#### Error: "No se encontraron interfaces de red"

**Causa**: WinPcap/Npcap no instalado o no funcionando
**Solución**:

1. Reinstalar Npcap con modo WinPcap activado
2. Ejecutar como administrador
3. Verificar que la interfaz de red esté activa

#### Error: "Java no reconocido"

**Causa**: Java no instalado o no en PATH
**Solución**:

1. Instalar JDK 11+
2. Configurar JAVA_HOME
3. Agregar Java al PATH del sistema

#### Error: "Maven no encontrado"

**Causa**: Maven no instalado
**Solución**:

1. Instalar Maven
2. Configurar MAVEN_HOME
3. Agregar Maven al PATH

#### Rendimiento Lento

**Causa**: Alto volumen de tráfico
**Solución**:

1. Aumentar memoria: `-Xmx512m`
2. Filtrar interfaces específicas
3. Usar modo consola básica

#### No Aparecen Paquetes

**Causa**: Interfaz incorrecta o sin tráfico
**Solución**:

1. Verificar interfaz seleccionada
2. Generar tráfico con `TrafficGenerator`
3. Verificar conectividad de red

### 📈 Monitoreo y Estadísticas

#### Métricas Importantes

- **Total de paquetes**: Contador general
- **Permitidos**: Paquetes que pasaron filtros
- **Bloqueados**: Paquetes rechazados
- **Tasa de bloqueo**: Porcentaje de tráfico filtrado

#### Análisis de Logs

Los logs incluyen:

- Timestamp del evento
- Tipo de evento (ALLOW/BLOCK)
- Razón específica del bloqueo
- Campos analizados

### 🎯 Casos de Uso Específicos

#### Detección de Herramientas de Hacking

El sistema detecta:

- **Nmap**: Valores ID específicos (0x0000, 0x1234)
- **hping3**: TTL modificado
- **Scapy**: Patrones anómalos
- **Metasploit**: Flags específicos

#### Análisis Forense

- Registro completo de eventos
- Correlación temporal de ataques
- Identificación de patrones de intrusión
- Análisis de fingerprinting de OS

#### Seguridad Corporativa

- Bloqueo de túneles no autorizados
- Control granular de protocolos
- Monitoreo de tráfico interno
- Detección de dispositivos comprometidos

### 📱 Funciones por Interfaz

#### FirewallGUI (Interfaz Gráfica)

- ✅ Tabla visual de paquetes capturados
- ✅ Panel de estadísticas en tiempo real
- ✅ Log de eventos con timestamp
- ✅ Controles de captura (Start/Stop/Clear)
- ✅ Información de reglas activas
- ✅ Codificación por colores según protocolo

#### ScreenshotFirewall (Consola Colorizada)

- ✅ Salida con códigos ANSI de color
- ✅ Análisis detallado de cada paquete
- ✅ Formato estructurado para documentación
- ✅ Estadísticas actualizadas cada 10 paquetes

#### SimpleFirewall (Consola Básica)

- ✅ Implementación minimalista
- ✅ Análisis esencial de campos
- ✅ Bajo consumo de recursos
- ✅ Salida de texto plano

### 💡 Consejos de Uso

#### Para Documentación

1. Usar `FirewallGUI` para capturas de pantalla principales
2. Usar `ScreenshotFirewall` para salidas de consola coloridas
3. Ejecutar `TrafficGenerator` simultáneamente para generar eventos
4. Capturar diferentes estados: normal, bloqueado, sospechoso

#### Para Análisis de Seguridad

1. Monitorear durante períodos prolongados
2. Analizar patrones de TTL para fingerprinting
3. Observar picos en tráfico bloqueado
4. Correlacionar eventos con logs del sistema

#### Para Testing

1. Usar `TrafficGenerator` para generar tráfico controlado
2. Verificar que se bloqueen protocolos configurados
3. Probar con diferentes interfaces de red
4. Validar rate limiting con tráfico intensivo

### 📞 Soporte

Para problemas técnicos:

1. Verificar que se cumplan todos los requisitos
2. Revisar logs de error en la consola
3. Comprobar privilegios de administrador
4. Validar configuración de red

**Documentación adicional**: Consultar `SOLUCION.md` para detalles técnicos completos.

## 🎯 Campos Analizados

### Capa de Enlace (IEEE 802.3)

- **EtherType**: Control de protocolos permitidos en la red
- **Direcciones MAC**: Detección de patrones anómalos y posible spoofing
- **Patrones de Broadcast/Multicast**: Identificación de tráfico sospechoso

### Capa de Red (IPv4)

- **Protocol**: Control granular de protocolos IP permitidos
- **TTL (Time To Live)**: Detección de ataques y fingerprinting de SO
- **Flags de Fragmentación**: Control de paquetes fragmentados
- **Total Length**: Prevención de ataques DoS por tamaño
- **Type of Service/DSCP**: Control de calidad de servicio
- **Identification**: Detección de herramientas de hacking
- **IHL (Internet Header Length)**: Detección de opciones anómalas
- **Version**: Verificación de versión IP

## 🛡️ Características de Seguridad

### 1. **Rate Limiting por IP**

- Controla el número de paquetes por segundo por IP de origen
- Previene ataques de flooding y DoS

### 2. **Análisis de Fragmentación**

- Detecta ataques basados en fragmentación IPv4
- Configurable para bloquear todos los paquetes fragmentados

### 3. **Fingerprinting de Sistema Operativo**

- Identifica el SO basándose en valores TTL característicos
- Útil para detección de anomalías en la red

### 4. **Detección de Herramientas de Hacking**

- Identifica patrones en campos ID y TOS usados por herramientas conocidas
- Detecta valores sospechosos en campos IPv4

### 5. **Control de Protocolos**

- Lista blanca/negra de protocolos IP permitidos
- Control de EtherTypes permitidos

## 🔧 Configuración

La configuración se realiza a través de la clase `SecurityConfig.java`:

```java
// Protocolos IP bloqueados
BLOCKED_IP_PROTOCOLS = [47, 50, 51] // GRE, ESP, AH

// Rango TTL válido
MIN_ALLOWED_TTL = 1
MAX_ALLOWED_TTL = 128

// Control de tamaño
MAX_ALLOWED_PACKET_SIZE = 1500

// Rate limiting
MAX_PACKETS_PER_SECOND = 100
```

# � FIREWALL AVANZADO IEEE 802.3 / IPv4

## Descripción del Proyecto

Esta aplicación implementa un sistema de seguridad informática avanzado que utiliza campos no convencionales de las tramas IEEE 802.3 (Ethernet) y los datagramas IPv4 para detectar y bloquear amenazas de red. A diferencia de los firewalls tradicionales que se basan principalmente en direcciones IP y puertos, este sistema analiza campos como:

- **TTL (Time To Live)**: Para detectar anomalías y fingerprinting de SO
- **EtherType**: Control de protocolos permitidos en la capa de enlace
- **Protocol**: Control granular de protocolos IP
- **Flags de Fragmentación**: Prevención de ataques de fragmentación
- **Total Length**: Prevención de ataques DoS por tamaño
- **Identification**: Detección de herramientas de hacking

## 🎯 Campos Analizados para Seguridad

### Capa de Enlace (IEEE 802.3)

- **EtherType (16 bits)**: Identifica el protocolo de capa superior
  - 0x0800 = IPv4 (permitido)
  - 0x0806 = ARP (permitido)
  - 0x86DD = IPv6 (bloqueado por defecto)

### Capa de Red (IPv4)

- **Protocol (8 bits)**: Identifica el protocolo de capa superior
  - 1 = ICMP, 6 = TCP, 17 = UDP (permitidos)
  - 47 = GRE, 50 = ESP, 51 = AH (bloqueados)

- **TTL (8 bits)**: Controla el tiempo de vida del paquete
  - Rango válido: 1-128
  - Valores fuera del rango indican anomalías

- **Flags (3 bits)**: Controla la fragmentación
  - DF (Don't Fragment), MF (More Fragments)
  - Fragmentación bloqueada por defecto

- **Total Length (16 bits)**: Tamaño total del datagrama
  - Máximo permitido: 1500 bytes
  - Previene ataques de buffer overflow

- **Identification (16 bits)**: Identificador único del datagrama
  - Valores 0x0000 y 0xFFFF considerados sospechosos

## 🚀 Instalación y Ejecución

### Prerrequisitos

1. **Java 8 o superior**
2. **WinPcap o Npcap** (para Windows)
   - Descargar desde: https://npcap.com/
3. **Privilegios de administrador** (requerido para captura de paquetes)

### Opción 1: Ejecutar con Scripts (Recomendado)

1. **Compilar el proyecto:**

   ```batch
   compilar.bat
   ```

2. **Ejecutar como administrador:**
   ```batch
   ejecutar.bat
   ```

### Opción 2: Compilación Manual

1. **Descargar dependencias pcap4j:**
   - Las dependencias se descargan automáticamente si tienes Maven instalado
   - O descarga manualmente los JARs de pcap4j

2. **Compilar:**

   ```bash
   javac -cp "pcap4j-core-1.8.2.jar;pcap4j-packetfactory-static-1.8.2.jar" src/main/java/com/tallerredes/*.java
   ```

3. **Ejecutar:**
   ```bash
   java -cp ".;pcap4j-core-1.8.2.jar;pcap4j-packetfactory-static-1.8.2.jar" com.tallerredes.SimpleFirewall
   ```

## 📊 Ejemplo de Salida

```
================================================================
           FIREWALL AVANZADO IEEE 802.3 / IPv4
      Analisis de seguridad basado en campos no estandar
================================================================

Interfaces de red disponibles:
   [1] eth0 - Ethernet Adapter (UP RUNNING)
   [2] lo - Loopback Interface (UP RUNNING LOOPBACK)

Interfaz seleccionada: eth0 - Ethernet Adapter
Aplicando filtro: ip or arp

Iniciando sistema de monitoreo...
Presiona Ctrl+C para salir

PAQUETE #1
ESTADO: PERMITIDO
   Ethernet - Tipo: 0x800 (IPv4)
   IPv4 - Proto: TCP | TTL: 64 | Len: 60 | ID: 12345
   TCP: Puerto 54321 -> 443
   Tamaño total: 60 bytes

PAQUETE #2
ESTADO: BLOQUEADO
   BLOQUEADO: Paquetes fragmentados no permitidos
   IPv4 - Proto: TCP | TTL: 64 | Len: 1500 | ID: 12346
   Tamaño total: 1500 bytes
```

## 🔧 Configuración Avanzada

El sistema incluye múltiples archivos para diferentes niveles de funcionalidad:

### SimpleFirewall.java

- Implementación básica y fácil de entender
- Reglas de seguridad esenciales
- Ideal para aprender y hacer pruebas

### App.java + SecurityAnalyzer.java + SecurityConfig.java

- Implementación completa y avanzada
- Sistema de rate limiting
- Configuración flexible
- Logging detallado

## 🛡️ Reglas de Seguridad Implementadas

### 1. **Control de Protocolos**

```java
// Protocolos bloqueados
if (protocol == 47 || protocol == 50 || protocol == 51) {
    return true; // Bloquear GRE, ESP, AH
}
```

### 2. **Validación de TTL**

```java
// TTL fuera del rango normal
if (ttl > 128 || ttl < 1) {
    return true; // Posible anomalía
}
```

### 3. **Control de Fragmentación**

```java
// Bloquear paquetes fragmentados
if (moreFragments || fragmentOffset > 0) {
    return true; // Prevenir ataques de fragmentación
}
```

### 4. **Control de Tamaño**

```java
// Paquetes demasiado grandes
if (totalLength > 1500) {
    return true; // Prevenir ataques DoS
}
```

## 🌐 Casos de Uso

### Red LAN Corporativa

- Monitoreo de tráfico interno
- Detección de dispositivos no autorizados
- Control de protocolos permitidos

### Entorno Cloud/Virtualizado

- Análisis de tráfico entre instancias
- Detección de movimiento lateral
- Cumplimiento de políticas de seguridad

### Red Doméstica/SOHO

- Protección contra malware
- Monitoreo de dispositivos IoT
- Análisis forense simple

## ⚠️ Limitaciones y Consideraciones

1. **Rendimiento**: La captura de paquetes puede impactar el rendimiento
2. **Falsos Positivos**: Algunas aplicaciones legítimas pueden ser bloqueadas
3. **Privilegios**: Requiere ejecución como administrador
4. **Compatibilidad**: Diseñado para Windows con Npcap/WinPcap

## 📚 Fundamentos Técnicos

Este firewall se basa en el análisis de campos específicos de los protocolos de red:

### Trama Ethernet IEEE 802.3

```
[Preámbulo][SFD][MAC Dest][MAC Orig][EtherType][Datos][FCS]
                                     ^^^^^^^^
                            Campo analizado para seguridad
```

### Datagrama IPv4

```
[Ver][IHL][TOS][Total Length][ID][Flags][Fragment Offset][TTL][Protocol][Checksum][IP Src][IP Dst][Datos]
          ^^^  ^^^^^^^^^^^^   ^^  ^^^^^                    ^^^  ^^^^^^^^
                           Campos analizados para seguridad
```

## 🔍 Detección de Amenazas

El sistema puede detectar:

- **Escaneo de puertos** (patrones TTL anómalos)
- **Ataques de fragmentación** (fragmentos IP maliciosos)
- **Tunneling no autorizado** (protocolos GRE/ESP/AH)
- **Ataques DoS** (paquetes oversized)
- **Herramientas de hacking** (campos ID sospechosos)

## 👨‍💻 Desarrollo y Contribuciones

El proyecto está estructurado de manera modular para facilitar:

- Adición de nuevas reglas de seguridad
- Integración con otros sistemas
- Extensión para IPv6
- Implementación de machine learning

## 📜 Licencia

Este proyecto es de código abierto y se proporciona con fines educativos y de investigación en seguridad informática.

---

_Desarrollado como solución avanzada de seguridad de red para análisis de protocolos IEEE 802.3 e IPv4_

## 📊 Salida del Sistema

La aplicación muestra:

- Información de interfaces de red disponibles
- Análisis detallado de cada paquete capturado
- Decisiones de seguridad (PERMITIDO/BLOQUEADO)
- Estadísticas en tiempo real
- Advertencias de seguridad

### Ejemplo de Salida

```
╔══════════════════════════════════════════════════════════════╗
║          🔒 FIREWALL AVANZADO IEEE 802.3 / IPv4 🔒           ║
║      Análisis de seguridad basado en campos no estándar     ║
╚══════════════════════════════════════════════════════════════╝

📋 CONFIGURACIÓN DE SEGURIDAD ACTIVA:
   • Protocolos bloqueados: [47, 50, 51]
   • TTL válido: 1 - 128
   • Tamaño máximo: 1500 bytes
   • Fragmentación: Bloqueada
   • Rate limit: 100 pps

📦 PAQUETE #1 [14:30:25.123]
✅ ESTADO: PERMITIDO
📊 DETALLES DEL PAQUETE:
   Tamaño total: 74 bytes
   🔗 Ethernet: IPv4 | SRC: aa:bb:cc:dd:ee:ff | DST: 11:22:33:44:55:66
   🌐 IPv4: TCP | SRC: 192.168.1.100 | DST: 8.8.8.8 | TTL: 64 | ID: 12345
   🔌 TCP: Puerto 54321 → 443 | Flags: SYN | Seq: 1000000 | Win: 65535
```

## 🔍 Casos de Uso

### Entornos LAN

- Detección de dispositivos no autorizados
- Identificación de patrones de tráfico anómalos
- Control de protocolos permitidos en la red local

### Entornos Cloud

- Monitoreo de instancias en la nube
- Detección de ataques de red lateral
- Análisis forense de tráfico

### Internet/WAN

- Análisis de tráfico entrante
- Detección de scans de red
- Identificación de herramientas de reconocimiento

## 🛠️ Extensiones Posibles

1. **Logging Avanzado**: Implementar logging a archivo, syslog o base de datos
2. **Dashboard Web**: Crear interfaz web para monitoreo en tiempo real
3. **Alertas**: Sistema de notificaciones por email/SMS
4. **Machine Learning**: Implementar detección de anomalías con ML
5. **IPv6**: Extender soporte para IPv6
6. **API REST**: Proporcionar API para integración con otros sistemas

## ⚠️ Consideraciones de Seguridad

- Ejecutar con privilegios mínimos necesarios
- Revisar regularmente las reglas de seguridad
- Monitorear logs por falsos positivos
- Actualizar listas de patrones conocidos
- Considerar el impacto en el rendimiento de red

## 📚 Referencias

- IEEE 802.3 Standard (Ethernet)
- RFC 791 (IPv4)
- RFC 1349 (Type of Service)
- RFC 2474 (DSCP)
- PCAP4J Documentation

## 👨‍💻 Autor

Desarrollado como solución avanzada de seguridad de red basada en análisis de campos no convencionales de protocolos de red.
