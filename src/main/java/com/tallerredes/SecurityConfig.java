package com.tallerredes;

import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;

/**
 * Configuración de seguridad para el firewall IEEE 802.3 / IPv4
 * Esta clase centraliza todas las reglas de seguridad basadas en campos
 * no convencionales de las tramas Ethernet e IPv4.
 */
public class SecurityConfig {

    // === CONFIGURACIÓN ETHERNET (IEEE 802.3) ===

    /**
     * EtherTypes bloqueados (campo Type en cabecera Ethernet)
     * 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP
     */
    public static final Set<Integer> BLOCKED_ETHERNET_TYPES = new HashSet<>(Arrays.asList(
    // Puedes agregar tipos específicos aquí para bloquear
    // 0x86DD // IPv6 (descomenta para bloquear IPv6)
    ));

    /**
     * EtherTypes permitidos explícitamente
     */
    public static final Set<Integer> ALLOWED_ETHERNET_TYPES = new HashSet<>(Arrays.asList(
            0x0800, // IPv4
            0x0806 // ARP
    ));

    // === CONFIGURACIÓN IPv4 ===

    /**
     * Protocolos IP bloqueados (campo Protocol en cabecera IPv4)
     * 1=ICMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP, 51=AH
     */
    public static final Set<Integer> BLOCKED_IP_PROTOCOLS = new HashSet<>(Arrays.asList(
            47, // GRE (Generic Routing Encapsulation)
            50, // ESP (Encapsulating Security Protocol)
            51 // AH (Authentication Header)
    ));

    /**
     * Protocolos IP permitidos explícitamente
     */
    public static final Set<Integer> ALLOWED_IP_PROTOCOLS = new HashSet<>(Arrays.asList(
            1, // ICMP
            6, // TCP
            17 // UDP
    ));

    // === CONFIGURACIÓN TTL (Time To Live) ===

    /**
     * TTL máximo permitido (campo TTL en cabecera IPv4)
     * Valores altos pueden indicar ataques de amplificación
     */
    public static final int MAX_ALLOWED_TTL = 128;

    /**
     * TTL mínimo permitido
     * Valores muy bajos pueden indicar ataques de red local
     */
    public static final int MIN_ALLOWED_TTL = 1;

    // === CONFIGURACIÓN DE TAMAÑO ===

    /**
     * Tamaño máximo de paquete permitido (campo Total Length)
     * Para prevenir ataques de buffer overflow
     */
    public static final int MAX_ALLOWED_PACKET_SIZE = 1500;

    /**
     * Tamaño mínimo de paquete permitido
     */
    public static final int MIN_ALLOWED_PACKET_SIZE = 20; // Cabecera IPv4 mínima

    // === CONFIGURACIÓN DE FRAGMENTACIÓN ===

    /**
     * Permitir paquetes fragmentados
     */
    public static final boolean ALLOW_FRAGMENTED_PACKETS = false;

    /**
     * Tamaño máximo de fragmento permitido
     */
    public static final int MAX_FRAGMENT_SIZE = 576;

    // === CONFIGURACIÓN TOS/DSCP ===

    /**
     * Valores TOS/DSCP bloqueados (campo TOS en cabecera IPv4)
     */
    public static final Set<Integer> BLOCKED_TOS_VALUES = new HashSet<>(Arrays.asList(
            0xE0, // Network Control (111 en precedencia)
            0xC0 // Internetwork Control (110 en precedencia)
    ));

    // === CONFIGURACIÓN DE IDENTIFICACIÓN ===

    /**
     * Valores de identificación sospechosos
     */
    public static final Set<Integer> SUSPICIOUS_ID_VALUES = new HashSet<>(Arrays.asList(
            0x0000, // ID = 0 (sospechoso)
            0xFFFF, // ID = máximo (sospechoso)
            0x1234, // Patrones comunes en herramientas de hacking
            0xDEAD,
            0xBEEF));

    // === CONFIGURACIÓN DE TIEMPO ===

    /**
     * Límite de paquetes por segundo por IP (rate limiting)
     */
    public static final int MAX_PACKETS_PER_SECOND = 100;

    /**
     * Ventana de tiempo para rate limiting (milisegundos)
     */
    public static final long RATE_LIMIT_WINDOW_MS = 1000;

    // === MÉTODOS DE CONFIGURACIÓN AVANZADA ===

    /**
     * Verifica si un EtherType está permitido
     */
    public static boolean isEtherTypeAllowed(int etherType) {
        if (!BLOCKED_ETHERNET_TYPES.isEmpty() && BLOCKED_ETHERNET_TYPES.contains(etherType)) {
            return false;
        }
        if (!ALLOWED_ETHERNET_TYPES.isEmpty()) {
            return ALLOWED_ETHERNET_TYPES.contains(etherType);
        }
        return true; // Permitir por defecto si no hay lista de permitidos
    }

    /**
     * Verifica si un protocolo IP está permitido
     */
    public static boolean isProtocolAllowed(int protocol) {
        if (!BLOCKED_IP_PROTOCOLS.isEmpty() && BLOCKED_IP_PROTOCOLS.contains(protocol)) {
            return false;
        }
        if (!ALLOWED_IP_PROTOCOLS.isEmpty()) {
            return ALLOWED_IP_PROTOCOLS.contains(protocol);
        }
        return true; // Permitir por defecto si no hay lista de permitidos
    }

    /**
     * Verifica si el TTL está en el rango permitido
     */
    public static boolean isTTLValid(int ttl) {
        return ttl >= MIN_ALLOWED_TTL && ttl <= MAX_ALLOWED_TTL;
    }

    /**
     * Verifica si el tamaño del paquete es válido
     */
    public static boolean isPacketSizeValid(int size) {
        return size >= MIN_ALLOWED_PACKET_SIZE && size <= MAX_ALLOWED_PACKET_SIZE;
    }

    /**
     * Verifica si el valor TOS es sospechoso
     */
    public static boolean isTOSSuspicious(int tos) {
        return BLOCKED_TOS_VALUES.contains(tos & 0xFF);
    }

    /**
     * Verifica si el ID es sospechoso
     */
    public static boolean isIDSuspicious(int id) {
        return SUSPICIOUS_ID_VALUES.contains(id & 0xFFFF);
    }

    /**
     * Obtiene descripción de un protocolo IP
     */
    public static String getProtocolDescription(int protocol) {
        switch (protocol) {
            case 1:
                return "ICMP";
            case 6:
                return "TCP";
            case 17:
                return "UDP";
            case 47:
                return "GRE";
            case 50:
                return "ESP";
            case 51:
                return "AH";
            case 89:
                return "OSPF";
            case 132:
                return "SCTP";
            default:
                return "Protocolo " + protocol;
        }
    }

    /**
     * Obtiene descripción de un EtherType
     */
    public static String getEtherTypeDescription(int etherType) {
        switch (etherType) {
            case 0x0800:
                return "IPv4";
            case 0x0806:
                return "ARP";
            case 0x86DD:
                return "IPv6";
            case 0x8100:
                return "VLAN";
            case 0x88A8:
                return "Service VLAN";
            default:
                return "EtherType 0x" + Integer.toHexString(etherType);
        }
    }
}
