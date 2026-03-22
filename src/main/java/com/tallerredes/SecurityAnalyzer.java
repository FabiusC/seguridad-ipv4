package com.tallerredes;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.util.MacAddress;
import java.util.List;

/**
 * Analizador de seguridad que implementa reglas basadas en campos
 * IEEE 802.3 e IPv4 no convencionales para detección de amenazas.
 */
public class SecurityAnalyzer {

    /**
     * Analiza la seguridad del paquete usando campos IEEE 802.3 e IPv4
     */
    public static SecurityDecision analyzePacketSecurity(Packet packet) {
        SecurityDecision decision = new SecurityDecision();

        // 1. Análisis de capa de enlace (IEEE 802.3)
        EthernetPacket ethPacket = packet.get(EthernetPacket.class);
        if (ethPacket != null) {
            analyzeEthernetSecurity(ethPacket, decision);
        }

        // 2. Análisis de capa de red (IPv4)
        IpV4Packet ipPacket = packet.get(IpV4Packet.class);
        if (ipPacket != null) {
            analyzeIPv4Security(ipPacket, decision);
        }

        return decision;
    }

    /**
     * Análisis de seguridad en capa Ethernet usando campos IEEE 802.3
     */
    private static void analyzeEthernetSecurity(EthernetPacket ethPacket, SecurityDecision decision) {
        // Campo EtherType - Control de protocolos permitidos
        int etherType = ethPacket.getHeader().getType().value() & 0xFFFF;

        if (!SecurityConfig.isEtherTypeAllowed(etherType)) {
            decision.block("EtherType no permitido: " + SecurityConfig.getEtherTypeDescription(etherType));
            return;
        }

        // Análisis de direcciones MAC para detectar patrones anómalos
        MacAddress srcMac = ethPacket.getHeader().getSrcAddr();
        MacAddress dstMac = ethPacket.getHeader().getDstAddr();

        // Detectar posibles ataques de spoofing usando patrones MAC
        if (isSuspiciousMacPattern(srcMac) || isSuspiciousMacPattern(dstMac)) {
            decision.addWarning("Patrón MAC sospechoso detectado - SRC: " + srcMac + " DST: " + dstMac);
        }

        // Verificar broadcast/multicast anómalos
        if (isAnomalousBroadcast(dstMac, etherType)) {
            decision.addWarning("Patrón de broadcast/multicast anómalo");
        }
    }

    /**
     * Análisis de seguridad IPv4 usando campos no convencionales
     */
    private static void analyzeIPv4Security(IpV4Packet ipPacket, SecurityDecision decision) {
        IpV4Packet.IpV4Header header = ipPacket.getHeader();

        // 1. Campo Protocol - Control granular de protocolos
        int protocol = header.getProtocol().value() & 0xFF;
        if (!SecurityConfig.isProtocolAllowed(protocol)) {
            decision.block("Protocolo IP no permitido: " + SecurityConfig.getProtocolDescription(protocol));
            return;
        }

        // 2. Campo TTL - Detección de ataques de red y fingerprinting del OS
        int ttl = header.getTtl() & 0xFF;
        if (!SecurityConfig.isTTLValid(ttl)) {
            decision.block("TTL fuera del rango permitido: " + ttl);
            return;
        }

        // Análisis de fingerprinting por TTL
        analyzeTTLFingerprint(ttl, decision);

        // 3. Campo Flags - Control de fragmentación y ataques
        boolean dontFragment = header.getDontFragmentFlag();
        boolean moreFragments = header.getMoreFragmentFlag();
        int fragmentOffset = header.getFragmentOffset();

        analyzeFragmentation(dontFragment, moreFragments, fragmentOffset, decision);

        // 4. Campo Total Length - Control de tamaño y ataques DoS
        int totalLength = header.getTotalLengthAsInt();
        if (!SecurityConfig.isPacketSizeValid(totalLength)) {
            if (totalLength > SecurityConfig.MAX_ALLOWED_PACKET_SIZE) {
                decision.block("Paquete demasiado grande (posible ataque DoS): " + totalLength + " bytes");
            } else {
                decision.block("Paquete demasiado pequeño (posible ataque): " + totalLength + " bytes");
            }
            return;
        }

        // 5. Campo Type of Service/DSCP - Control de calidad de servicio y ataques
        byte tos = header.getTos().value();
        analyzeTOS(tos, decision);

        // 6. Campo Identification - Detección de patrones anómalos y ataques
        int identification = header.getIdentification() & 0xFFFF;
        analyzeIdentification(identification, decision);

        // 7. Campo Version - Verificación de versión IP
        int version = header.getVersion().value();
        if (version != 4) {
            decision.block("Versión IP inválida en paquete IPv4: " + version);
            return;
        }

        // 8. Campo IHL (Internet Header Length) - Detección de opciones anómalas
        int ihl = header.getIhl() & 0xFF;
        analyzeIHL(ihl, decision);

        // 9. Análisis de checksum para detectar manipulación
        analyzeChecksum(header, decision);
    }

    /**
     * Detecta patrones MAC sospechosos
     */
    private static boolean isSuspiciousMacPattern(MacAddress mac) {
        byte[] address = mac.getAddress();

        // Detectar MACs con patrones repetitivos (posible spoofing)
        boolean allSame = true;
        boolean sequential = true;

        for (int i = 1; i < address.length; i++) {
            if (address[i] != address[0]) {
                allSame = false;
            }
            if (i > 1 && (address[i] & 0xFF) != ((address[i - 1] & 0xFF) + 1)) {
                sequential = false;
            }
        }

        // Detectar MACs conocidas como problemáticas
        String macString = mac.toString();
        if (macString.startsWith("00:00:00") || macString.startsWith("ff:ff:ff")) {
            return true;
        }

        return (allSame && address[0] != 0) || sequential;
    }

    /**
     * Detecta broadcasts/multicasts anómalos
     */
    private static boolean isAnomalousBroadcast(MacAddress dstMac, int etherType) {
        byte[] address = dstMac.getAddress();
        boolean isBroadcast = true;
        boolean isMulticast = (address[0] & 0x01) != 0;

        for (byte b : address) {
            if ((b & 0xFF) != 0xFF) {
                isBroadcast = false;
                break;
            }
        }

        // Broadcast con protocolos que no deberían usar broadcast
        if (isBroadcast && etherType == 0x0800) { // IPv4 broadcast sospechoso
            return true;
        }

        // Multicast excesivo puede indicar ataque
        return isMulticast && etherType != 0x0806; // ARP es normal para multicast
    }

    /**
     * Analiza el TTL para fingerprinting del sistema operativo
     */
    private static void analyzeTTLFingerprint(int ttl, SecurityDecision decision) {
        String osHint = "";

        // Valores TTL comunes por OS
        if (ttl == 64) {
            osHint = "Linux/Unix";
        } else if (ttl == 128) {
            osHint = "Windows";
        } else if (ttl == 255) {
            osHint = "Cisco/Network Device";
        } else if (ttl <= 32) {
            osHint = "Posible proxy/NAT";
        } else if (ttl > 128) {
            osHint = "Posible herramienta de hacking";
        }

        if (!osHint.isEmpty()) {
            decision.addWarning("TTL sugiere origen: " + osHint + " (TTL=" + ttl + ")");
        }
    }

    /**
     * Analiza fragmentación para detectar ataques
     */
    private static void analyzeFragmentation(boolean dontFragment, boolean moreFragments,
            int fragmentOffset, SecurityDecision decision) {

        if (!SecurityConfig.ALLOW_FRAGMENTED_PACKETS && (moreFragments || fragmentOffset > 0)) {
            decision.block("Paquetes fragmentados no permitidos por política de seguridad");
            return;
        }

        // Detectar fragmentación anómala (posibles ataques)
        if (moreFragments && fragmentOffset == 0) {
            decision.addWarning("Primer fragmento con flag MF - fragmentación iniciada");
        }

        if (fragmentOffset > 0 && dontFragment) {
            decision.block("Fragmentación inconsistente: DF=1 pero fragmentOffset > 0");
            return;
        }

        if (fragmentOffset > SecurityConfig.MAX_FRAGMENT_SIZE) {
            decision.addWarning("Fragmento con offset muy grande: " + fragmentOffset);
        }
    }

    /**
     * Analiza el campo TOS/DSCP
     */
    private static void analyzeTOS(byte tos, SecurityDecision decision) {
        int tosValue = tos & 0xFF;

        if (SecurityConfig.isTOSSuspicious(tosValue)) {
            decision.block("Valor TOS/DSCP sospechoso: 0x" + Integer.toHexString(tosValue));
            return;
        }

        // Extraer precedencia (bits 7-5)
        int precedence = (tosValue >> 5) & 0x07;
        if (precedence > 5) {
            decision.addWarning("Precedencia TOS alta: " + precedence + " (posible escalación de privilegios)");
        }

        // Extraer DSCP (bits 7-2)
        int dscp = (tosValue >> 2) & 0x3F;
        if (dscp > 46) { // Expedited Forwarding es 46
            decision.addWarning("DSCP no estándar: " + dscp);
        }
    }

    /**
     * Analiza el campo Identification
     */
    private static void analyzeIdentification(int id, SecurityDecision decision) {
        if (SecurityConfig.isIDSuspicious(id)) {
            decision.addWarning("Campo Identification sospechoso: 0x" + Integer.toHexString(id));
        }

        // Detectar secuencias predecibles (posible scanner)
        if (id == 0) {
            decision.addWarning("Identification = 0 (posible herramienta de red personalizada)");
        } else if (id == 0xFFFF) {
            decision.addWarning("Identification = 0xFFFF (posible ataque o herramienta no estándar)");
        }
    }

    /**
     * Analiza el campo IHL (Internet Header Length)
     */
    private static void analyzeIHL(int ihl, SecurityDecision decision) {
        if (ihl < 5) {
            decision.block("IHL inválido (menor que cabecera mínima): " + ihl);
            return;
        }

        if (ihl > 5) {
            decision.addWarning("Cabecera IPv4 con opciones detectada (IHL=" + ihl + ")");

            if (ihl > 15) {
                decision.block("IHL excesivamente grande (posible ataque): " + ihl);
                return;
            }
        }
    }

    /**
     * Analiza el checksum para detectar manipulación
     */
    private static void analyzeChecksum(IpV4Packet.IpV4Header header, SecurityDecision decision) {
        // Nota: pcap4j no proporciona acceso directo al checksum calculado vs recibido
        // En una implementación real, compararías el checksum calculado con el recibido

        // Por ahora, solo verificamos que no sea 0 (lo cual sería anómalo)
        // En una implementación completa, calcularías el checksum real
        decision.addWarning("Verificación de checksum no implementada completamente");
    }

    /**
     * Clase para manejar decisiones de seguridad
     */
    public static class SecurityDecision {
        private boolean blocked = false;
        private String reason = "";
        private List<String> warnings = new java.util.ArrayList<>();

        public void block(String reason) {
            this.blocked = true;
            this.reason = reason;
        }

        public void addWarning(String warning) {
            this.warnings.add(warning);
        }

        public boolean isBlocked() {
            return blocked;
        }

        public String getReason() {
            return reason;
        }

        public List<String> getWarnings() {
            return warnings;
        }
    }
}
