package com.tallerredes;

import java.net.*;
import java.io.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Generador de trafico de red para demostrar el filtrado del firewall
 */
public class TrafficGenerator {

    private static final String[] TEST_IPS = {
            "8.8.8.8", // Google DNS
            "1.1.1.1", // Cloudflare DNS
            "208.67.222.222", // OpenDNS
            "127.0.0.1" // Localhost
    };

    private static final int[] TEST_PORTS = {
            80, 443, 53, 22, 21, 23, 25, 110, 143, 993, 995
    };

    public static void main(String[] args) {
        System.out.println("================================================================");
        System.out.println("           GENERADOR DE TRAFICO PARA DEMOSTRACION");
        System.out.println("================================================================");
        System.out.println();

        TrafficGenerator generator = new TrafficGenerator();
        generator.startTrafficGeneration();
    }

    public void startTrafficGeneration() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(4);

        System.out.println("Iniciando generacion de trafico de prueba...");
        System.out.println("Este trafico sera analizado por el firewall\n");

        // TCP connections
        scheduler.scheduleAtFixedRate(() -> {
            generateTcpTraffic();
        }, 0, 3, TimeUnit.SECONDS);

        // UDP traffic
        scheduler.scheduleAtFixedRate(() -> {
            generateUdpTraffic();
        }, 1, 4, TimeUnit.SECONDS);

        // ICMP traffic (ping)
        scheduler.scheduleAtFixedRate(() -> {
            generateIcmpTraffic();
        }, 2, 5, TimeUnit.SECONDS);

        // Suspicious traffic (que sera bloqueado)
        scheduler.scheduleAtFixedRate(() -> {
            generateSuspiciousTraffic();
        }, 5, 10, TimeUnit.SECONDS);

        System.out.println("Trafico generandose...");
        System.out.println("Ejecuta ScreenshotFirewall en otra terminal para ver el filtrado");
        System.out.println("Presiona Ctrl+C para detener");

        // Keep running
        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {
            scheduler.shutdown();
        }
    }

    private void generateTcpTraffic() {
        try {
            String ip = TEST_IPS[(int) (Math.random() * TEST_IPS.length)];
            int port = TEST_PORTS[(int) (Math.random() * TEST_PORTS.length)];

            System.out.println("[TCP] Conectando a " + ip + ":" + port);

            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(ip, port), 2000);

            if (socket.isConnected()) {
                // Enviar algunos datos
                OutputStream out = socket.getOutputStream();
                out.write("GET / HTTP/1.1\r\nHost: test\r\n\r\n".getBytes());
                out.flush();

                Thread.sleep(100);
                socket.close();
                System.out.println("[TCP] Conexion cerrada");
            }

        } catch (Exception e) {
            System.out.println("[TCP] Error (esperado): " + e.getMessage());
        }
    }

    private void generateUdpTraffic() {
        try {
            String ip = TEST_IPS[(int) (Math.random() * TEST_IPS.length)];
            int port = 53; // DNS

            System.out.println("[UDP] Enviando a " + ip + ":" + port);

            DatagramSocket socket = new DatagramSocket();

            // DNS query simulada
            byte[] dnsQuery = {
                    0x12, 0x34, // Transaction ID
                    0x01, 0x00, // Flags
                    0x00, 0x01, // Questions
                    0x00, 0x00, // Answer RRs
                    0x00, 0x00, // Authority RRs
                    0x00, 0x00, // Additional RRs
                    // Query: google.com
                    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
                    0x03, 0x63, 0x6f, 0x6d,
                    0x00, // End of name
                    0x00, 0x01, // Type A
                    0x00, 0x01 // Class IN
            };

            DatagramPacket packet = new DatagramPacket(
                    dnsQuery, dnsQuery.length,
                    InetAddress.getByName(ip), port);

            socket.send(packet);
            socket.close();
            System.out.println("[UDP] Paquete enviado");

        } catch (Exception e) {
            System.out.println("[UDP] Error: " + e.getMessage());
        }
    }

    private void generateIcmpTraffic() {
        try {
            String ip = TEST_IPS[(int) (Math.random() * TEST_IPS.length)];
            System.out.println("[ICMP] Ping a " + ip);

            ProcessBuilder pb = new ProcessBuilder("ping", "-n", "1", ip);
            Process process = pb.start();
            process.waitFor(3, TimeUnit.SECONDS);

            System.out.println("[ICMP] Ping completado");

        } catch (Exception e) {
            System.out.println("[ICMP] Error: " + e.getMessage());
        }
    }

    private void generateSuspiciousTraffic() {
        System.out.println("[SUSPICIOUS] Generando trafico sospechoso que sera bloqueado...");

        // Intentar crear trafico que active las reglas del firewall
        try {
            // Esto generara trafico que podria ser bloqueado
            generateFragmentedTraffic();
            generateLargePackets();

        } catch (Exception e) {
            System.out.println("[SUSPICIOUS] Error generando trafico sospechoso: " + e.getMessage());
        }
    }

    private void generateFragmentedTraffic() {
        System.out.println("[FRAGMENT] Intentando generar trafico fragmentado...");
        // Nota: Generar trafico fragmentado a proposito es complejo en Java
        // Este metodo es principalmente informativo
    }

    private void generateLargePackets() {
        try {
            System.out.println("[LARGE] Intentando enviar paquetes grandes...");

            DatagramSocket socket = new DatagramSocket();

            // Crear un paquete UDP grande (mayor a 1500 bytes)
            byte[] largeData = new byte[2000];
            for (int i = 0; i < largeData.length; i++) {
                largeData[i] = (byte) (i % 256);
            }

            DatagramPacket packet = new DatagramPacket(
                    largeData, largeData.length,
                    InetAddress.getByName("127.0.0.1"), 12345);

            socket.send(packet);
            socket.close();
            System.out.println("[LARGE] Paquete grande enviado (sera fragmentado por el sistema)");

        } catch (Exception e) {
            System.out.println("[LARGE] Error: " + e.getMessage());
        }
    }
}
