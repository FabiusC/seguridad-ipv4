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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Firewall con salida optimizada para screenshots y documentación
 */
public class ScreenshotFirewall {

    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_PURPLE = "\u001B[35m";
    private static final String ANSI_CYAN = "\u001B[36m";
    private static final String ANSI_WHITE = "\u001B[37m";

    public static void main(String[] args) {
        try {
            printHeader();

            // Seleccionar interfaz de red
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            PcapNetworkInterface nif = selectNetworkInterface(allDevs);

            if (nif == null) {
                System.err.println(ANSI_RED + "ERROR: No se encontro interfaz de red valida." + ANSI_RESET);
                return;
            }

            // Configurar captura
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            handle.setFilter("ip or arp", BpfCompileMode.OPTIMIZE);

            // Crear analizador
            PacketListener analyzer = new VisualAnalyzer();

            printStartMessage();
            handle.loop(-1, analyzer);
            handle.close();

        } catch (Exception e) {
            System.err.println(ANSI_RED + "ERROR: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        }
    }

    private static void printHeader() {
        System.out.println(ANSI_CYAN + "╔════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    " + ANSI_WHITE + "FIREWALL IEEE 802.3 / IPv4" + ANSI_CYAN
                + "                        ║");
        System.out.println("║              " + ANSI_YELLOW + "Analisis de Seguridad por Campos No Estandar" + ANSI_CYAN
                + "              ║");
        System.out.println("╚════════════════════════════════════════════════════════════════════════╝" + ANSI_RESET);
        System.out.println();

        System.out.println(ANSI_BLUE + "CAMPOS ANALIZADOS:" + ANSI_RESET);
        System.out.println("  • EtherType (IEEE 802.3) - Control de protocolos de enlace");
        System.out.println("  • Protocol (IPv4) - Control de protocolos de red");
        System.out.println("  • TTL - Deteccion de anomalias y fingerprinting");
        System.out.println("  • Flags - Prevencion de ataques de fragmentacion");
        System.out.println("  • Total Length - Control de tamano de paquetes");
        System.out.println("  • Identification - Deteccion de herramientas de hacking");
        System.out.println();
    }

    private static void printStartMessage() {
        System.out.println(ANSI_GREEN + "SISTEMA INICIADO - Monitoreando trafico de red..." + ANSI_RESET);
        System.out.println(ANSI_YELLOW + "Presiona Ctrl+C para detener" + ANSI_RESET);
        System.out.println("═".repeat(80));
        System.out.println();
    }

    private static PcapNetworkInterface selectNetworkInterface(List<PcapNetworkInterface> allDevs) {
        if (allDevs == null || allDevs.isEmpty())
            return null;

        System.out.println(ANSI_BLUE + "INTERFACES DE RED:" + ANSI_RESET);
        PcapNetworkInterface selected = null;

        for (int i = 0; i < allDevs.size(); i++) {
            PcapNetworkInterface dev = allDevs.get(i);
            String status = dev.isUp() && dev.isRunning() && !dev.isLoopBack() ? ANSI_GREEN + "ACTIVA" + ANSI_RESET
                    : ANSI_RED + "INACTIVA" + ANSI_RESET;

            System.out.println("  [" + (i + 1) + "] " + dev.getName() + " - " + status);

            if (selected == null && dev.isUp() && dev.isRunning() && !dev.isLoopBack()) {
                selected = dev;
            }
        }

        if (selected == null && !allDevs.isEmpty())
            selected = allDevs.get(0);

        if (selected != null) {
            System.out.println(ANSI_GREEN + "INTERFAZ SELECCIONADA: " + selected.getName() + ANSI_RESET);
        }

        System.out.println();
        return selected;
    }

    static class VisualAnalyzer implements PacketListener {
        private int packetCount = 0;
        private int allowedCount = 0;
        private int blockedCount = 0;
        private DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

        @Override
        public void gotPacket(Packet packet) {
            packetCount++;
            String timestamp = LocalDateTime.now().format(timeFormatter);

            PacketAnalysisResult result = analyzePacket(packet);
            displayPacketAnalysis(packet, result, timestamp);

            if (result.isBlocked()) {
                blockedCount++;
            } else {
                allowedCount++;
            }

            // Mostrar estadisticas cada 5 paquetes
            if (packetCount % 5 == 0) {
                displayStatistics();
            }
        }

        private PacketAnalysisResult analyzePacket(Packet packet) {
            PacketAnalysisResult result = new PacketAnalysisResult();

            // Analisis Ethernet
            EthernetPacket ethPacket = packet.get(EthernetPacket.class);
            if (ethPacket != null) {
                analyzeEthernet(ethPacket, result);
            }

            // Analisis IPv4
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket != null) {
                analyzeIPv4(ipPacket, result);
            }

            return result;
        }

        private void analyzeEthernet(EthernetPacket ethPacket, PacketAnalysisResult result) {
            int etherType = ethPacket.getHeader().getType().value() & 0xFFFF;
            result.etherType = String.format("0x%04X", etherType);
            result.etherTypeDesc = getEtherTypeDescription(etherType);

            // Reglas de filtrado
            if (etherType == 0x86DD) {
                result.blockReason = "IPv6 no permitido (EtherType)";
                result.blocked = true;
                result.riskLevel = "ALTO";
            }
        }

        private void analyzeIPv4(IpV4Packet ipPacket, PacketAnalysisResult result) {
            IpV4Packet.IpV4Header header = ipPacket.getHeader();

            // Protocol
            int protocol = header.getProtocol().value() & 0xFF;
            result.protocol = protocol;
            result.protocolDesc = getProtocolDescription(protocol);

            // TTL
            result.ttl = header.getTtl() & 0xFF;

            // Total Length
            result.totalLength = header.getTotalLengthAsInt();

            // Identification
            result.identification = String.format("0x%04X", header.getIdentification() & 0xFFFF);

            // Flags
            result.dontFragment = header.getDontFragmentFlag();
            result.moreFragments = header.getMoreFragmentFlag();
            result.fragmentOffset = header.getFragmentOffset();

            // IP addresses
            result.srcIP = header.getSrcAddr().getHostAddress();
            result.dstIP = header.getDstAddr().getHostAddress();

            // Aplicar reglas de seguridad
            applySecurityRules(result);
        }

        private void applySecurityRules(PacketAnalysisResult result) {
            // Regla 1: Protocolos bloqueados
            if (result.protocol == 47 || result.protocol == 50 || result.protocol == 51) {
                result.blockReason = "Protocolo " + result.protocolDesc + " bloqueado";
                result.blocked = true;
                result.riskLevel = "ALTO";
                return;
            }

            // Regla 2: TTL anomalo
            if (result.ttl > 128 || result.ttl < 1) {
                result.blockReason = "TTL anomalo (" + result.ttl + ")";
                result.blocked = true;
                result.riskLevel = "MEDIO";
                return;
            }

            // Regla 3: Paquetes demasiado grandes
            if (result.totalLength > 1500) {
                result.blockReason = "Paquete demasiado grande (" + result.totalLength + " bytes)";
                result.blocked = true;
                result.riskLevel = "MEDIO";
                return;
            }

            // Regla 4: Fragmentacion
            if (result.moreFragments || result.fragmentOffset > 0) {
                result.blockReason = "Paquete fragmentado detectado";
                result.blocked = true;
                result.riskLevel = "ALTO";
                return;
            }

            // Regla 5: IDs sospechosos
            if ("0x0000".equals(result.identification) || "0xFFFF".equals(result.identification) ||
                    "0x1234".equals(result.identification) || "0xDEAD".equals(result.identification)) {
                result.blockReason = "ID sospechoso (" + result.identification + ")";
                result.blocked = true;
                result.riskLevel = "MEDIO";
                return;
            }

            // Advertencias (no bloquean)
            if (result.ttl == 64) {
                result.warnings.add("Posible sistema Linux/Unix");
            } else if (result.ttl == 128) {
                result.warnings.add("Posible sistema Windows");
            } else if (result.ttl == 255) {
                result.warnings.add("Posible dispositivo de red");
            }

            result.riskLevel = "BAJO";
        }

        private void displayPacketAnalysis(Packet packet, PacketAnalysisResult result, String timestamp) {
            String status = result.isBlocked() ? ANSI_RED + "BLOQUEADO" + ANSI_RESET
                    : ANSI_GREEN + "PERMITIDO" + ANSI_RESET;

            String riskColor = getRiskColor(result.riskLevel);

            System.out.println("┌─ PAQUETE #" + packetCount + " [" + timestamp + "] ─ " + status + " ─ Riesgo: "
                    + riskColor + result.riskLevel + ANSI_RESET);

            if (result.etherType != null) {
                System.out.println("│ " + ANSI_BLUE + "Ethernet:" + ANSI_RESET + " Tipo=" + result.etherType + " ("
                        + result.etherTypeDesc + ")");
            }

            if (result.protocol != 0) {
                System.out
                        .println("│ " + ANSI_PURPLE + "IPv4:" + ANSI_RESET + " " + result.srcIP + " → " + result.dstIP);
                System.out.println(
                        "│       Protocolo=" + result.protocol + " (" + result.protocolDesc + "), TTL=" + result.ttl +
                                ", Longitud=" + result.totalLength + ", ID=" + result.identification);

                if (result.dontFragment || result.moreFragments || result.fragmentOffset > 0) {
                    System.out.println("│       Flags: DF=" + result.dontFragment + ", MF=" + result.moreFragments +
                            ", Offset=" + result.fragmentOffset);
                }
            }

            // Mostrar detalles del protocolo de transporte
            displayTransportInfo(packet);

            if (result.isBlocked()) {
                System.out.println("│ " + ANSI_RED + "RAZON DE BLOQUEO:" + ANSI_RESET + " " + result.blockReason);
            }

            for (String warning : result.warnings) {
                System.out.println("│ " + ANSI_YELLOW + "ADVERTENCIA:" + ANSI_RESET + " " + warning);
            }

            System.out.println("└" + "─".repeat(70));
            System.out.println();
        }

        private void displayTransportInfo(Packet packet) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                TcpPacket.TcpHeader header = tcpPacket.getHeader();
                String flags = getTcpFlags(header);
                System.out.println(
                        "│ " + ANSI_CYAN + "TCP:" + ANSI_RESET + " Puerto " + header.getSrcPort().valueAsInt() +
                                " → " + header.getDstPort().valueAsInt() + " [" + flags + "]");
            }

            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                UdpPacket.UdpHeader header = udpPacket.getHeader();
                System.out.println(
                        "│ " + ANSI_CYAN + "UDP:" + ANSI_RESET + " Puerto " + header.getSrcPort().valueAsInt() +
                                " → " + header.getDstPort().valueAsInt() + ", Longitud=" + header.getLengthAsInt());
            }

            IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
            if (icmpPacket != null) {
                System.out.println(
                        "│ " + ANSI_CYAN + "ICMP:" + ANSI_RESET + " Tipo=" + icmpPacket.getHeader().getType().value() +
                                ", Codigo=" + icmpPacket.getHeader().getCode().value());
            }
        }

        private String getTcpFlags(TcpPacket.TcpHeader header) {
            StringBuilder flags = new StringBuilder();
            if (header.getSyn())
                flags.append("SYN ");
            if (header.getAck())
                flags.append("ACK ");
            if (header.getFin())
                flags.append("FIN ");
            if (header.getRst())
                flags.append("RST ");
            if (header.getPsh())
                flags.append("PSH ");
            if (header.getUrg())
                flags.append("URG ");
            return flags.toString().trim();
        }

        private void displayStatistics() {
            double allowedPercent = (allowedCount * 100.0) / packetCount;
            double blockedPercent = (blockedCount * 100.0) / packetCount;

            System.out.println(ANSI_WHITE + "╔═══════════════════ ESTADISTICAS ═══════════════════╗" + ANSI_RESET);
            System.out.println(ANSI_WHITE + "║" + ANSI_RESET + " Total procesados: " + String.format("%6d", packetCount)
                    + "                        " + ANSI_WHITE + "║" + ANSI_RESET);
            System.out.println(ANSI_WHITE + "║" + ANSI_RESET + " " + ANSI_GREEN + "Permitidos:" + ANSI_RESET + " "
                    + String.format("%6d", allowedCount) + " (" + String.format("%5.1f%%", allowedPercent)
                    + ")              " + ANSI_WHITE + "║" + ANSI_RESET);
            System.out.println(ANSI_WHITE + "║" + ANSI_RESET + " " + ANSI_RED + "Bloqueados:" + ANSI_RESET + " "
                    + String.format("%6d", blockedCount) + " (" + String.format("%5.1f%%", blockedPercent)
                    + ")              " + ANSI_WHITE + "║" + ANSI_RESET);
            System.out.println(ANSI_WHITE + "╚════════════════════════════════════════════════════╝" + ANSI_RESET);
            System.out.println();
        }

        private String getRiskColor(String riskLevel) {
            switch (riskLevel) {
                case "ALTO":
                    return ANSI_RED;
                case "MEDIO":
                    return ANSI_YELLOW;
                case "BAJO":
                    return ANSI_GREEN;
                default:
                    return ANSI_WHITE;
            }
        }

        private String getProtocolDescription(int protocol) {
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
                default:
                    return "Protocolo " + protocol;
            }
        }

        private String getEtherTypeDescription(int etherType) {
            switch (etherType) {
                case 0x0800:
                    return "IPv4";
                case 0x0806:
                    return "ARP";
                case 0x86DD:
                    return "IPv6";
                case 0x8100:
                    return "VLAN";
                default:
                    return "Tipo " + Integer.toHexString(etherType);
            }
        }
    }

    static class PacketAnalysisResult {
        boolean blocked = false;
        String blockReason = "";
        String riskLevel = "BAJO";
        java.util.List<String> warnings = new java.util.ArrayList<>();

        // Ethernet fields
        String etherType;
        String etherTypeDesc;

        // IPv4 fields
        int protocol;
        String protocolDesc;
        int ttl;
        int totalLength;
        String identification;
        boolean dontFragment;
        boolean moreFragments;
        int fragmentOffset;
        String srcIP;
        String dstIP;

        boolean isBlocked() {
            return blocked;
        }
    }
}
