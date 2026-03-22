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

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Interfaz grafica para el firewall IEEE 802.3 / IPv4
 */
public class FirewallGUI extends JFrame {

    private JTable packetTable;
    private DefaultTableModel tableModel;
    private JLabel statusLabel;
    private JLabel statsLabel;
    private JButton startButton;
    private JButton stopButton;
    private JTextArea logArea;
    private JProgressBar progressBar;

    private PcapHandle handle;
    private Thread captureThread;
    private boolean capturing = false;
    private int packetCount = 0;
    private int allowedCount = 0;
    private int blockedCount = 0;

    public FirewallGUI() {
        initializeUI();
    }

    private void initializeUI() {
        setTitle("Firewall IEEE 802.3 / IPv4 - Analisis de Seguridad");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Panel superior con controles
        JPanel controlPanel = createControlPanel();
        add(controlPanel, BorderLayout.NORTH);

        // Panel central con tabla de paquetes
        JPanel centerPanel = createCenterPanel();
        add(centerPanel, BorderLayout.CENTER);

        // Panel inferior con estadisticas y log
        JPanel bottomPanel = createBottomPanel();
        add(bottomPanel, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(null);
        setExtendedState(JFrame.MAXIMIZED_BOTH);
    }

    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new FlowLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Control de Captura"));
        panel.setBackground(new Color(240, 248, 255));

        startButton = new JButton("Iniciar Captura");
        startButton.setIcon(new ImageIcon(createIcon(Color.GREEN)));
        startButton.addActionListener(e -> startCapture());

        stopButton = new JButton("Detener Captura");
        stopButton.setIcon(new ImageIcon(createIcon(Color.RED)));
        stopButton.addActionListener(e -> stopCapture());
        stopButton.setEnabled(false);

        JButton clearButton = new JButton("Limpiar");
        clearButton.setIcon(new ImageIcon(createIcon(Color.ORANGE)));
        clearButton.addActionListener(e -> clearData());

        statusLabel = new JLabel("Estado: Detenido");
        statusLabel.setFont(new Font("Arial", Font.BOLD, 14));

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(false);
        progressBar.setStringPainted(true);
        progressBar.setString("Listo");

        panel.add(startButton);
        panel.add(stopButton);
        panel.add(clearButton);
        panel.add(Box.createHorizontalStrut(20));
        panel.add(statusLabel);
        panel.add(Box.createHorizontalStrut(20));
        panel.add(new JLabel("Progreso:"));
        panel.add(progressBar);

        return panel;
    }

    private JPanel createCenterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Analisis de Paquetes"));

        // Crear tabla
        String[] columnNames = {
                "#", "Timestamp", "Protocolo", "IP Origen", "IP Destino",
                "Puerto Orig", "Puerto Dest", "TTL", "Tamano", "Estado", "Razon/Campo Analizado"
        };

        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        packetTable = new JTable(tableModel);
        packetTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        packetTable.setRowHeight(25);
        packetTable.setGridColor(Color.LIGHT_GRAY);
        packetTable.setSelectionBackground(new Color(173, 216, 230));

        // Configurar colores para estados
        packetTable.setDefaultRenderer(Object.class, new PacketTableCellRenderer());

        JScrollPane scrollPane = new JScrollPane(packetTable);
        scrollPane.setPreferredSize(new Dimension(1200, 400));

        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Panel de estadisticas
        JPanel statsPanel = new JPanel(new GridLayout(1, 4));
        statsPanel.setBorder(BorderFactory.createTitledBorder("Estadisticas en Tiempo Real"));
        statsPanel.setBackground(new Color(245, 245, 245));

        statsLabel = new JLabel("<html><center><b>Total: 0</b><br>Permitidos: 0<br>Bloqueados: 0</center></html>");
        statsLabel.setHorizontalAlignment(SwingConstants.CENTER);
        statsLabel.setBorder(BorderFactory.createEtchedBorder());

        JLabel fieldsLabel = new JLabel("<html><center><b>Campos Analizados</b><br>" +
                "• EtherType (IEEE 802.3)<br>" +
                "• Protocol, TTL, Flags (IPv4)<br>" +
                "• Total Length, ID (IPv4)</center></html>");
        fieldsLabel.setHorizontalAlignment(SwingConstants.CENTER);
        fieldsLabel.setBorder(BorderFactory.createEtchedBorder());

        JLabel rulesLabel = new JLabel("<html><center><b>Reglas Activas</b><br>" +
                "• Bloqueo IPv6 (EtherType)<br>" +
                "• Bloqueo GRE/ESP/AH<br>" +
                "• Control TTL (1-128)<br>" +
                "• Anti-fragmentacion</center></html>");
        rulesLabel.setHorizontalAlignment(SwingConstants.CENTER);
        rulesLabel.setBorder(BorderFactory.createEtchedBorder());

        JLabel riskLabel = new JLabel("<html><center><b>Niveles de Riesgo</b><br>" +
                "<font color='green'>BAJO: Trafico normal</font><br>" +
                "<font color='orange'>MEDIO: Sospechoso</font><br>" +
                "<font color='red'>ALTO: Bloqueado</font></center></html>");
        riskLabel.setHorizontalAlignment(SwingConstants.CENTER);
        riskLabel.setBorder(BorderFactory.createEtchedBorder());

        statsPanel.add(statsLabel);
        statsPanel.add(fieldsLabel);
        statsPanel.add(rulesLabel);
        statsPanel.add(riskLabel);

        // Area de log
        logArea = new JTextArea(8, 50);
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        logArea.setBackground(Color.BLACK);
        logArea.setForeground(Color.GREEN);
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setBorder(BorderFactory.createTitledBorder("Log de Eventos"));

        panel.add(statsPanel, BorderLayout.NORTH);
        panel.add(logScrollPane, BorderLayout.CENTER);

        return panel;
    }

    private Image createIcon(Color color) {
        BufferedImage img = new BufferedImage(16, 16, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = img.createGraphics();
        g2d.setColor(color);
        g2d.fillOval(2, 2, 12, 12);
        g2d.setColor(Color.BLACK);
        g2d.drawOval(2, 2, 12, 12);
        g2d.dispose();
        return img;
    }

    private void startCapture() {
        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (allDevs == null || allDevs.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No se encontraron interfaces de red", "Error",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            PcapNetworkInterface nif = selectInterface(allDevs);
            if (nif == null)
                return;

            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            handle.setFilter("ip or arp", BpfCompileMode.OPTIMIZE);

            capturing = true;
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            statusLabel.setText("Estado: Capturando en " + nif.getName());
            progressBar.setIndeterminate(true);
            progressBar.setString("Capturando...");

            logEvent("INICIO", "Captura iniciada en interfaz: " + nif.getName());

            captureThread = new Thread(() -> {
                try {
                    handle.loop(-1, new GUIPacketListener());
                } catch (Exception e) {
                    if (capturing) {
                        logEvent("ERROR", "Error en captura: " + e.getMessage());
                    }
                }
            });

            captureThread.start();

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error al iniciar captura: " + e.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void stopCapture() {
        capturing = false;

        if (handle != null) {
            try {
                handle.breakLoop();
                handle.close();
            } catch (Exception e) {
                logEvent("ERROR", "Error al cerrar captura: " + e.getMessage());
            }
        }

        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        statusLabel.setText("Estado: Detenido");
        progressBar.setIndeterminate(false);
        progressBar.setString("Detenido");

        logEvent("STOP", "Captura detenida");
    }

    private void clearData() {
        tableModel.setRowCount(0);
        logArea.setText("");
        packetCount = 0;
        allowedCount = 0;
        blockedCount = 0;
        updateStats();
        logEvent("CLEAR", "Datos limpiados");
    }

    private PcapNetworkInterface selectInterface(List<PcapNetworkInterface> allDevs) {
        String[] options = new String[allDevs.size()];
        for (int i = 0; i < allDevs.size(); i++) {
            PcapNetworkInterface dev = allDevs.get(i);
            String status = dev.isUp() && dev.isRunning() ? " (ACTIVA)" : " (INACTIVA)";
            options[i] = dev.getName() + " - "
                    + (dev.getDescription() != null ? dev.getDescription() : "Sin descripcion") + status;
        }

        String selected = (String) JOptionPane.showInputDialog(
                this,
                "Selecciona la interfaz de red:",
                "Seleccion de Interfaz",
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);

        if (selected != null) {
            for (int i = 0; i < options.length; i++) {
                if (options[i].equals(selected)) {
                    return allDevs.get(i);
                }
            }
        }

        return null;
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            double allowedPercent = packetCount > 0 ? (allowedCount * 100.0) / packetCount : 0;
            double blockedPercent = packetCount > 0 ? (blockedCount * 100.0) / packetCount : 0;

            statsLabel.setText(String.format(
                    "<html><center><b>Total: %d</b><br>" +
                            "<font color='green'>Permitidos: %d (%.1f%%)</font><br>" +
                            "<font color='red'>Bloqueados: %d (%.1f%%)</font></center></html>",
                    packetCount, allowedCount, allowedPercent, blockedCount, blockedPercent));
        });
    }

    private void logEvent(String type, String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
            logArea.append(String.format("[%s] %s: %s\n", timestamp, type, message));
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    class GUIPacketListener implements PacketListener {
        @Override
        public void gotPacket(Packet packet) {
            if (!capturing)
                return;

            packetCount++;

            SwingUtilities.invokeLater(() -> {
                analyzeAndDisplayPacket(packet);
                updateStats();
            });
        }
    }

    private void analyzeAndDisplayPacket(Packet packet) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
        String protocol = "UNKNOWN";
        String srcIP = "-";
        String dstIP = "-";
        String srcPort = "-";
        String dstPort = "-";
        String ttl = "-";
        String size = String.valueOf(packet.length());
        String status = "PERMITIDO";
        String reason = "Trafico normal";
        Color rowColor = Color.WHITE;

        // Analisis Ethernet
        EthernetPacket ethPacket = packet.get(EthernetPacket.class);
        if (ethPacket != null) {
            int etherType = ethPacket.getHeader().getType().value() & 0xFFFF;
            if (etherType == 0x86DD) {
                status = "BLOQUEADO";
                reason = "IPv6 bloqueado (EtherType: 0x86DD)";
                rowColor = new Color(255, 200, 200);
                blockedCount++;
                logEvent("BLOCK", "IPv6 bloqueado - EtherType: 0x86DD");
            }
        }

        // Analisis IPv4
        IpV4Packet ipPacket = packet.get(IpV4Packet.class);
        if (ipPacket != null) {
            IpV4Packet.IpV4Header header = ipPacket.getHeader();

            srcIP = header.getSrcAddr().getHostAddress();
            dstIP = header.getDstAddr().getHostAddress();
            ttl = String.valueOf(header.getTtl() & 0xFF);

            int protocolNum = header.getProtocol().value() & 0xFF;
            protocol = getProtocolDescription(protocolNum);

            // Verificar reglas de seguridad
            if (protocolNum == 47 || protocolNum == 50 || protocolNum == 51) {
                status = "BLOQUEADO";
                reason = "Protocolo " + protocol + " no permitido";
                rowColor = new Color(255, 200, 200);
                blockedCount++;
                logEvent("BLOCK", "Protocolo bloqueado: " + protocol);
            } else if ((header.getTtl() & 0xFF) > 128 || (header.getTtl() & 0xFF) < 1) {
                status = "BLOQUEADO";
                reason = "TTL anomalo: " + ttl;
                rowColor = new Color(255, 200, 200);
                blockedCount++;
                logEvent("BLOCK", "TTL anomalo: " + ttl);
            } else if (header.getTotalLengthAsInt() > 1500) {
                status = "BLOQUEADO";
                reason = "Paquete demasiado grande: " + header.getTotalLengthAsInt() + " bytes";
                rowColor = new Color(255, 200, 200);
                blockedCount++;
                logEvent("BLOCK", "Paquete grande bloqueado: " + header.getTotalLengthAsInt() + " bytes");
            } else if (header.getMoreFragmentFlag() || header.getFragmentOffset() > 0) {
                status = "BLOQUEADO";
                reason = "Paquete fragmentado detectado";
                rowColor = new Color(255, 200, 200);
                blockedCount++;
                logEvent("BLOCK", "Fragmentacion detectada");
            } else {
                allowedCount++;
                reason = "Analisis: Proto=" + protocol + ", TTL=" + ttl + ", Tam=" + size;

                // Colores segun el protocolo cuando es permitido
                if (protocolNum == 1)
                    rowColor = new Color(200, 255, 200); // ICMP - verde claro
                else if (protocolNum == 6)
                    rowColor = new Color(200, 200, 255); // TCP - azul claro
                else if (protocolNum == 17)
                    rowColor = new Color(255, 255, 200); // UDP - amarillo claro
            }
        } else {
            allowedCount++;
        }

        // Obtener puertos para TCP/UDP
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            srcPort = String.valueOf(tcpPacket.getHeader().getSrcPort().valueAsInt());
            dstPort = String.valueOf(tcpPacket.getHeader().getDstPort().valueAsInt());
        }

        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null) {
            srcPort = String.valueOf(udpPacket.getHeader().getSrcPort().valueAsInt());
            dstPort = String.valueOf(udpPacket.getHeader().getDstPort().valueAsInt());
        }

        // Agregar fila a la tabla
        Object[] row = {
                packetCount, timestamp, protocol, srcIP, dstIP,
                srcPort, dstPort, ttl, size, status, reason
        };

        tableModel.addRow(row);

        // Scroll hacia abajo
        packetTable.scrollRectToVisible(packetTable.getCellRect(packetTable.getRowCount() - 1, 0, true));

        // Limitar filas en tabla para rendimiento
        if (tableModel.getRowCount() > 1000) {
            tableModel.removeRow(0);
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
            default:
                return "Proto-" + protocol;
        }
    }

    // Renderer personalizado para colores de filas
    class PacketTableCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {

            Component comp = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                String status = (String) table.getValueAt(row, 9); // Columna de estado

                if ("BLOQUEADO".equals(status)) {
                    comp.setBackground(new Color(255, 200, 200));
                } else {
                    String protocol = (String) table.getValueAt(row, 2);
                    if ("ICMP".equals(protocol)) {
                        comp.setBackground(new Color(200, 255, 200));
                    } else if ("TCP".equals(protocol)) {
                        comp.setBackground(new Color(200, 200, 255));
                    } else if ("UDP".equals(protocol)) {
                        comp.setBackground(new Color(255, 255, 200));
                    } else {
                        comp.setBackground(Color.WHITE);
                    }
                }
            }

            return comp;
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new FirewallGUI().setVisible(true);
        });
    }
}
