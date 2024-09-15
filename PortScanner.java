import java.util.Scanner;
import java.io.IOException;
import java.net.Socket;

public class PortScanner {
    public static void main(String[] args) {
        System.err.println("VulnerabilityScan: Port Scanner Initialized.");

        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter target IP Address: ");
        String ipAddress = scanner.nextLine();

        System.out.println("Enter start port: ");
        // if (scanner.hasNextInt()) {
        //     int port = scanner.nextInt();
        //     System.out.println("You entered: " + port);
        // } else {
        //     System.out.println("Invalid input. Please enter a valid port number.");
        // }
        int startPort = scanner.nextInt();
        System.err.println("Enter end port: ");
        int endPort = scanner.nextInt();
        

        // System.err.println("Scanning: " + ipAddress + " from port " + startPort + " to port " + endPort);

        for (int port = startPort; port <= endPort; port++) {
            try {
                Socket socket = new Socket(ipAddress, port);
                System.out.println("Port " + port + " is open.");
                socket.close();
            } catch (IOException e) {
                System.out.println("Port " + port + " is closed.");
            }
        }
    }
}