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

/**
 * Firewall avanzado que analiza campos IEEE 802.3 e IPv4 para seguridad
 */
public class SimpleFirewall {

    public static void main(String[] args) {
        try {
            System.out.println("================================================================");
            System.out.println("           FIREWALL AVANZADO IEEE 802.3 / IPv4                 ");
            System.out.println("      Analisis de seguridad basado en campos no estandar       ");
            System.out.println("================================================================");
            System.out.println();

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
            System.out.println("Configurando interfaz de red...");
            PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

            // Filtro para capturar tráfico relevante
            String filter = "ip or arp";
            System.out.println("Aplicando filtro: " + filter);
            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

            // Crear el analizador de seguridad
            PacketListener analyzer = new FirewallAnalyzer();

            System.out.println("\nIniciando sistema de monitoreo...");
            System.out.println("Presiona Ctrl+C para salir\n");
            System.out.println("================================================================================");

            handle.loop(-1, analyzer);
            handle.close();

        } catch (Exception e) {
            System.err.println("ERROR critico del sistema: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Selecciona la interfaz de red más apropiada
     */
    private static PcapNetworkInterface selectNetworkInterface(List<PcapNetworkInterface> allDevs) {
        if (allDevs == null || allDevs.isEmpty()) {
            return null;
        }

        System.out.println("Interfaces de red disponibles:");

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
                    " - " + (dev.getDescription() != null ? dev.getDescription() : "Sin descripcion") +
                    " (" + status.trim() + ")");

            if (selectedInterface == null && dev.isUp() && dev.isRunning() && !dev.isLoopBack()) {
                selectedInterface = dev;
            }
        }

        if (selectedInterface == null && !allDevs.isEmpty()) {
            selectedInterface = allDevs.get(0);
        }

        if (selectedInterface != null) {
            System.out.println("\nInterfaz seleccionada: " + selectedInterface.getName() +
                    " - " + selectedInterface.getDescription());
        }
        return selectedInterface;
    }

    /**
     * Analizador de seguridad que implementa las reglas del firewall
     */
    static class FirewallAnalyzer implements PacketListener {
        private int packetCount = 0;
        private int blockedCount = 0;
        private int allowedCount = 0;

        @Override
        public void gotPacket(Packet packet) {
            packetCount++;

            System.out.println("\nPAQUETE #" + packetCount);

            // Análisis de seguridad
            boolean blocked = analyzePacket(packet);

            if (blocked) {
                blockedCount++;
                System.out.println("ESTADO: BLOQUEADO");
            } else {
                allowedCount++;
                System.out.println("ESTADO: PERMITIDO");
            }

            displayPacketInfo(packet);

            // Mostrar estadísticas cada 10 paquetes
            if (packetCount % 10 == 0) {
                displayStatistics();
            }
        }

        /**
         * Analiza el paquete y determina si debe ser bloqueado
         */
        private boolean analyzePacket(Packet packet) {
            // Análisis de capa Ethernet (IEEE 802.3)
            EthernetPacket ethPacket = packet.get(EthernetPacket.class);
            if (ethPacket != null) {
                if (analyzeEthernet(ethPacket)) {
                    return true; // Bloquear
                }
            }

            // Análisis de capa IPv4
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket != null) {
                if (analyzeIPv4(ipPacket)) {
                    return true; // Bloquear
                }
            }

            return false; // Permitir
        }

        /**
         * Analiza campos de la trama Ethernet
         */
        private boolean analyzeEthernet(EthernetPacket ethPacket) {
            int etherType = ethPacket.getHeader().getType().value() & 0xFFFF;

            // Ejemplo: Bloquear ciertos EtherTypes
            if (etherType == 0x86DD) { // IPv6 bloqueado
                System.out.println("   BLOQUEADO: IPv6 no permitido");
                return true;
            }

            System.out.println("   Ethernet - Tipo: 0x" + Integer.toHexString(etherType) +
                    " (" + getEtherTypeDescription(etherType) + ")");
            return false;
        }

        /**
         * Analiza campos del datagrama IPv4
         */
        private boolean analyzeIPv4(IpV4Packet ipPacket) {
            IpV4Packet.IpV4Header header = ipPacket.getHeader();

            // Campo Protocol - Bloquear protocolos específicos
            int protocol = header.getProtocol().value() & 0xFF;
            if (protocol == 47 || protocol == 50 || protocol == 51) { // GRE, ESP, AH
                System.out.println("   BLOQUEADO: Protocolo " + protocol + " no permitido");
                return true;
            }

            // Campo TTL - Detección de anomalías
            int ttl = header.getTtl() & 0xFF;
            if (ttl > 128 || ttl < 1) {
                System.out.println("   BLOQUEADO: TTL fuera del rango permitido: " + ttl);
                return true;
            }

            // Campo Total Length - Control de tamaño
            int totalLength = header.getTotalLengthAsInt();
            if (totalLength > 1500) {
                System.out.println("   BLOQUEADO: Paquete demasiado grande: " + totalLength + " bytes");
                return true;
            }

            // Campo Flags - Control de fragmentación
            boolean moreFragments = header.getMoreFragmentFlag();
            int fragmentOffset = header.getFragmentOffset();

            if (moreFragments || fragmentOffset > 0) {
                System.out.println("   BLOQUEADO: Paquetes fragmentados no permitidos");
                return true;
            }

            // Campo Identification - Detección de patrones sospechosos
            int identification = header.getIdentification() & 0xFFFF;
            if (identification == 0 || identification == 0xFFFF) {
                System.out.println("   ADVERTENCIA: Campo Identification sospechoso: " + identification);
            }

            System.out.println("   IPv4 - Proto: " + getProtocolDescription(protocol) +
                    " | TTL: " + ttl + " | Len: " + totalLength +
                    " | ID: " + identification);
            return false;
        }

        /**
         * Muestra información detallada del paquete
         */
        private void displayPacketInfo(Packet packet) {
            System.out.println("   Tamaño total: " + packet.length() + " bytes");

            // Información específica del protocolo de transporte
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                TcpPacket.TcpHeader header = tcpPacket.getHeader();
                System.out.println("   TCP: Puerto " + header.getSrcPort().valueAsInt() +
                        " -> " + header.getDstPort().valueAsInt());
            }

            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                UdpPacket.UdpHeader header = udpPacket.getHeader();
                System.out.println("   UDP: Puerto " + header.getSrcPort().valueAsInt() +
                        " -> " + header.getDstPort().valueAsInt());
            }

            IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
            if (icmpPacket != null) {
                System.out.println("   ICMP: Tipo " + icmpPacket.getHeader().getType().value());
            }
        }

        /**
         * Muestra estadísticas del sistema
         */
        private void displayStatistics() {
            System.out.println("\n" + "-".repeat(50));
            System.out.println("ESTADISTICAS:");
            System.out.println("   Total procesados: " + packetCount);
            System.out.println("   Permitidos: " + allowedCount + " (" +
                    String.format("%.1f", (allowedCount * 100.0) / packetCount) + "%)");
            System.out.println("   Bloqueados: " + blockedCount + " (" +
                    String.format("%.1f", (blockedCount * 100.0) / packetCount) + "%)");
            System.out.println("-".repeat(50));
        }

        /**
         * Obtiene descripción de un protocolo
         */
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
                default:
                    return "Protocolo " + protocol;
            }
        }

        /**
         * Obtiene descripción de un EtherType
         */
        private String getEtherTypeDescription(int etherType) {
            switch (etherType) {
                case 0x0800:
                    return "IPv4";
                case 0x0806:
                    return "ARP";
                case 0x86DD:
                    return "IPv6";
                default:
                    return "EtherType 0x" + Integer.toHexString(etherType);
            }
        }
    }
}
