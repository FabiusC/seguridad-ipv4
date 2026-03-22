package com.tallerredes;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class App {

    // Sistema de rate limiting por IP
    private static final Map<String, RateLimitCounter> rateLimitMap = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try {
            System.out.println("================================================================");
            System.out.println("           FIREWALL AVANZADO IEEE 802.3 / IPv4                 ");
            System.out.println("      Analisis de seguridad basado en campos no estandar       ");
            System.out.println("================================================================");
            System.out.println();

            displaySecurityConfiguration();

            // Seleccionar interfaz de red automáticamente
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            PcapNetworkInterface nif = selectNetworkInterface(allDevs);

            if (nif == null) {
                System.err.println("ERROR: No se pudo encontrar una interfaz de red valida.");
                return;
            }
            int snapLen = 65536;
            int timeout = 10;

            // Abrir la interfaz en modo promiscuo
            System.out.println("🔧 Configurando interfaz de red...");
            PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

            // Filtro para capturar tráfico relevante
            String filter = "ip or arp or icmp";
            System.out.println("🔍 Aplicando filtro: " + filter);
            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

            // Crear el analizador de seguridad avanzado
            PacketListener securityAnalyzer = new AdvancedSecurityAnalyzer();

            System.out.println("\n🚀 Iniciando sistema de monitoreo...");
            System.out.println("📊 Presiona Ctrl+C para generar reporte y salir\n");
            System.out.println("" + "=".repeat(80));

            handle.loop(-1, securityAnalyzer);
            handle.close();

        } catch (Exception e) {
            System.err.println("❌ Error crítico del sistema: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Muestra la configuración de seguridad activa
     */
    private static void displaySecurityConfiguration() {
        System.out.println("📋 CONFIGURACIÓN DE SEGURIDAD ACTIVA:");
        System.out.println("   • Protocolos bloqueados: " + SecurityConfig.BLOCKED_IP_PROTOCOLS);
        System.out
                .println("   • TTL válido: " + SecurityConfig.MIN_ALLOWED_TTL + " - " + SecurityConfig.MAX_ALLOWED_TTL);
        System.out.println("   • Tamaño máximo: " + SecurityConfig.MAX_ALLOWED_PACKET_SIZE + " bytes");
        System.out.println(
                "   • Fragmentación: " + (SecurityConfig.ALLOW_FRAGMENTED_PACKETS ? "Permitida" : "Bloqueada"));
        System.out.println("   • Rate limit: " + SecurityConfig.MAX_PACKETS_PER_SECOND + " pps");
        System.out.println();
    }

    /**
     * Selecciona la interfaz de red más apropiada
     */
    private static PcapNetworkInterface selectNetworkInterface(List<PcapNetworkInterface> allDevs) {
        if (allDevs == null || allDevs.isEmpty()) {
            return null;
        }

        System.out.println("🌐 Interfaces de red disponibles:");

        // Buscar una interfaz activa y funcionando
        PcapNetworkInterface selectedInterface = null;
        for (int i = 0; i < allDevs.size(); i++) {
            PcapNetworkInterface dev = allDevs.get(i);
            String status = "";

            if (dev.isUp())
                status += "UP ";
            if (dev.isRunning())
                status += "RUNNING ";
            if (dev.isLoopBack())
                status += "LOOPBACK ";

            System.out.println("   [" + (i + 1) + "] " + dev.getName() +
                    " - " + (dev.getDescription() != null ? dev.getDescription() : "Sin descripción") +
                    " (" + status.trim() + ")");

            // Seleccionar la primera interfaz que esté UP y RUNNING pero no sea LOOPBACK
            if (selectedInterface == null && dev.isUp() && dev.isRunning() && !dev.isLoopBack()) {
                selectedInterface = dev;
            }
        }

        if (selectedInterface == null) {
            selectedInterface = allDevs.get(0);
        }

        System.out.println("\n✅ Interfaz seleccionada: " + selectedInterface.getName() +
                " - " + selectedInterface.getDescription());
        return selectedInterface;
    }

    /**
     * Analizador de seguridad avanzado
     */
    static class AdvancedSecurityAnalyzer implements PacketListener {
        private int packetCount = 0;
        private int blockedCount = 0;
        private int allowedCount = 0;

        @Override
        public void gotPacket(Packet packet) {
            packetCount++;
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));

            System.out.println("\n📦 PAQUETE #" + packetCount + " [" + timestamp + "]");

            // Análisis de seguridad multicapa
            SecurityAnalyzer.SecurityDecision decision = SecurityAnalyzer.analyzePacketSecurity(packet);

            // Aplicar rate limiting
            applyRateLimiting(packet, decision);

            if (decision.isBlocked()) {
                blockedCount++;
                System.out.println("🚫 ESTADO: BLOQUEADO");
                System.out.println("   Razón: " + decision.getReason());

                if (!decision.getWarnings().isEmpty()) {
                    System.out.println("⚠️  Advertencias adicionales:");
                    for (String warning : decision.getWarnings()) {
                        System.out.println("   • " + warning);
                    }
                }

                logSecurityEvent(packet, decision, timestamp);
            } else {
                allowedCount++;
                System.out.println("✅ ESTADO: PERMITIDO");

                if (!decision.getWarnings().isEmpty()) {
                    System.out.println("⚠️  Advertencias:");
                    for (String warning : decision.getWarnings()) {
                        System.out.println("   • " + warning);
                    }
                }
            }

            displayDetailedPacketInfo(packet);

            // Mostrar estadísticas cada 10 paquetes
            if (packetCount % 10 == 0) {
                displayStatistics();
            }
        }

        /**
         * Aplica rate limiting basado en IP de origen
         */
        private void applyRateLimiting(Packet packet, SecurityAnalyzer.SecurityDecision decision) {
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket != null) {
                String srcIP = ipPacket.getHeader().getSrcAddr().getHostAddress();

                RateLimitCounter counter = rateLimitMap.computeIfAbsent(srcIP,
                        k -> new RateLimitCounter());

                if (counter.exceedsLimit()) {
                    decision.block("Rate limit excedido para IP: " + srcIP);
                }
            }
        }

        /**
         * Muestra información detallada del paquete
         */
        private void displayDetailedPacketInfo(Packet packet) {
            System.out.println("📊 DETALLES DEL PAQUETE:");
            System.out.println("   Tamaño total: " + packet.length() + " bytes");

            // Información Ethernet
            EthernetPacket ethPacket = packet.get(EthernetPacket.class);
            if (ethPacket != null) {
                int etherType = ethPacket.getHeader().getType().value() & 0xFFFF;
                System.out.println("   🔗 Ethernet: " +
                        SecurityConfig.getEtherTypeDescription(etherType) +
                        " | SRC: " + ethPacket.getHeader().getSrcAddr() +
                        " | DST: " + ethPacket.getHeader().getDstAddr());
            }

            // Información IPv4
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket != null) {
                IpV4Packet.IpV4Header header = ipPacket.getHeader();
                int protocol = header.getProtocol().value() & 0xFF;

                System.out.println("   🌐 IPv4: " +
                        SecurityConfig.getProtocolDescription(protocol) +
                        " | SRC: " + header.getSrcAddr().getHostAddress() +
                        " | DST: " + header.getDstAddr().getHostAddress() +
                        " | TTL: " + (header.getTtl() & 0xFF) +
                        " | ID: " + (header.getIdentification() & 0xFFFF));

                // Información específica del protocolo
                displayProtocolSpecificInfo(packet);
            }
        }

        /**
         * Muestra información específica del protocolo de transporte
         */
        private void displayProtocolSpecificInfo(Packet packet) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                TcpPacket.TcpHeader header = tcpPacket.getHeader();
                System.out.println("   🔌 TCP: Puerto " + header.getSrcPort().valueAsInt() +
                        " → " + header.getDstPort().valueAsInt() +
                        " | Flags: " + getTcpFlags(header) +
                        " | Seq: " + header.getSequenceNumberAsLong() +
                        " | Win: " + header.getWindowAsInt());
            }

            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                UdpPacket.UdpHeader header = udpPacket.getHeader();
                System.out.println("   📡 UDP: Puerto " + header.getSrcPort().valueAsInt() +
                        " → " + header.getDstPort().valueAsInt() +
                        " | Longitud: " + header.getLengthAsInt());
            }

            IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
            if (icmpPacket != null) {
                System.out.println("   📬 ICMP: Tipo " + icmpPacket.getHeader().getType().value() +
                        " | Código " + icmpPacket.getHeader().getCode().value());
            }
        }

        /**
         * Obtiene las flags TCP en formato legible
         */
        private String getTcpFlags(TcpPacket.TcpHeader header) {
            StringBuilder flags = new StringBuilder();
            if (header.getUrg())
                flags.append("URG ");
            if (header.getAck())
                flags.append("ACK ");
            if (header.getPsh())
                flags.append("PSH ");
            if (header.getRst())
                flags.append("RST ");
            if (header.getSyn())
                flags.append("SYN ");
            if (header.getFin())
                flags.append("FIN ");
            return flags.toString().trim();
        }

        /**
         * Registra eventos de seguridad
         */
        private void logSecurityEvent(Packet packet, SecurityAnalyzer.SecurityDecision decision, String timestamp) {
            // Aquí podrías implementar logging a archivo, syslog, base de datos, etc.
            System.out.println("📝 Evento registrado en log de seguridad");
        }

        /**
         * Muestra estadísticas del sistema
         */
        private void displayStatistics() {
            System.out.println("\n" + "─".repeat(50));
            System.out.println("📈 ESTADÍSTICAS:");
            System.out.println("   Total procesados: " + packetCount);
            System.out.println("   ✅ Permitidos: " + allowedCount + " (" +
                    String.format("%.1f", (allowedCount * 100.0) / packetCount) + "%)");
            System.out.println("   🚫 Bloqueados: " + blockedCount + " (" +
                    String.format("%.1f", (blockedCount * 100.0) / packetCount) + "%)");
            System.out.println("   🕒 Rate limits activos: " + rateLimitMap.size());
            System.out.println("─".repeat(50));
        }
    }

    /**
     * Contador para rate limiting
     */
    static class RateLimitCounter {
        private long lastReset = System.currentTimeMillis();
        private int packetCount = 0;

        public synchronized boolean exceedsLimit() {
            long now = System.currentTimeMillis();

            // Reset counter si ha pasado la ventana de tiempo
            if (now - lastReset > SecurityConfig.RATE_LIMIT_WINDOW_MS) {
                packetCount = 0;
                lastReset = now;
            }

            packetCount++;
            return packetCount > SecurityConfig.MAX_PACKETS_PER_SECOND;
        }
    }
}
