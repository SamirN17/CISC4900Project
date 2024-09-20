import java.util.Scanner;
import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class PortScanner {
    public static void main(String[] args) {
        System.err.println("VulnerabilityScan: Port Scanner Initialized.");

        Scanner scanner = new Scanner(System.in);

        // IP address is input, and returned if it is an invalid IP Address
        System.out.println("Enter target IP Address: ");
        String ipAddress = scanner.nextLine();
        if (!isValidIPAddress(ipAddress)) {
            System.out.println("Invalid IP address. Please enter a valid IP address.");
            return;
        }

        System.out.println("Enter start port: ");
        int startPort = scanner.nextInt();
        System.err.println("Enter end port: ");
        int endPort = scanner.nextInt();
        
        ExecutorService executorService = Executors.newFixedThreadPool(10);

        System.err.printf("Scanning %s from port %d to port %d...%n\n", ipAddress, startPort, endPort);
        for (int port = startPort; port <= endPort; port++) {
            int currentPort = port;
            executorService.submit(() -> scanPortAndGrabBanner(ipAddress, currentPort));
        }

        executorService.shutdown();
        scanner.close();
    }

    public static boolean isValidIPAddress(String ipAddress) {
        try {
            InetSocketAddress inet = new InetSocketAddress(ipAddress, 0);
            return !inet.isUnresolved();
        } catch (Exception e) {
            return false;
        }
    }

    public static void scanPortAndGrabBanner(String ipAddress, int port) {
    try {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(ipAddress, port), 200);  

        System.out.printf("Port %d is OPEN on %s%n", port, ipAddress);

        if (port == 80) {
            socket.connect(new InetSocketAddress(ipAddress, port), 200);
            grabHttpBanner(socket);
        } else if (port == 21) {
            socket.connect(new InetSocketAddress(ipAddress, port), 400);
            grabFtpBanner(socket);
        } else if (port == 22) {
            socket.connect(new InetSocketAddress(ipAddress, port), 800);
            grabSshBanner(socket);
        }

        socket.close();
        } catch (IOException e) {
           System.out.printf("Port %d is CLOSED or unreachable%n", port);
        }
    }

    public static void grabHttpBanner(Socket socket) {
        try {
            String httpRequest = "GET / HTTP/1.1\r\nHost: " + socket.getInetAddress().getHostName() + "\r\n\r\n";
            socket.getOutputStream().write(httpRequest.getBytes());

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;

            System.out.println("HTTP Banner: ");
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
            }
        } catch (IOException e) {
            System.out.println("Error reading HTTP banner.");
        }
    }

    public static void grabFtpBanner(Socket socket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;

            System.out.println("FTP Banner: ");
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
            }
        } catch (IOException e) {
            System.out.println("Error reading FTP banner.");
        }
    }

    public static void grabSshBanner(Socket socket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;

            System.out.println("SSH Banner: ");
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
            }
        } catch (IOException e) {
            System.out.println("Error reading SSH banner.");
        }
    }
}