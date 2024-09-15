import java.util.Scanner;
import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;

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
        

        System.err.printf("Scanning %s from port %d to port %d...%n\n", ipAddress, startPort, endPort);
        for (int port = startPort; port <= endPort; port++) {
            scanPort(ipAddress, port);
        }
    }

    public static boolean isValidIPAddress(String ipAddress) {
        try {
            InetAddress inet = InetAddress.getByName(ipAddress);
            return inet != null;
        } catch (Exception e) {
            return false;
        }
    }

    public static void scanPort(String ipAddress, int port) {
        try{
            Socket socket = new Socket(ipAddress, port);
            System.out.printf("Port %d is open.%n", port);
            socket.close();
        } catch (IOException e) {
            System.out.printf("Port %d is closed.%n", port);
        }
    }
}