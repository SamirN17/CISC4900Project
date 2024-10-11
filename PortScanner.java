import java.util.Scanner;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.HashMap;
import java.util.Map;
import java.io.*;


public class PortScanner {

    // Lists to track open and closed ports for the current scan
    private static List<String> openPorts = new ArrayList<>();
    private static List<String> closedPorts = new ArrayList<>();

    // Database of known vulnerabilities, loaded from the CSV file
    private static Map<String, String> vulnerabilityDatabase = new HashMap<>();

    public static void main(String[] args) {
        System.err.println("VulnerabilityScan: Port Scanner Initialized.");

        Scanner scanner = new Scanner(System.in);

        // Load vulnerability database
        loadVulnerabilityDatabase("vulnerabilities.csv");

        // IP address is input, and checked if it is a invalid IP Address
        System.out.println("Enter target IP Address: ");
        String ipAddress = scanner.nextLine();
        if (!isValidIPAddress(ipAddress)) {
            System.out.println("Invalid IP address. Please enter a valid IP address.");
            return;
        }

        // Port range is input
        System.out.println("Enter start port: ");
        int startPort = scanner.nextInt();
        System.out.println("Enter end port: ");
        int endPort = scanner.nextInt();
        
        // Initializes a thread pool with a fixed number of threads for scanning ports concurrently
        ExecutorService executorService = Executors.newFixedThreadPool(10);

        // Starts scanning the range of ports on the target IP address
        System.out.printf("Scanning %s from port %d to port %d...%n\n", ipAddress, startPort, endPort);
        for (int port = startPort; port <= endPort; port++) {
            int currentPort = port;

            // This submits a port scanning task to the thread pool for each port in the range
            executorService.submit(() -> scanPortAndGrabBanner(ipAddress, currentPort));
        }

        executorService.shutdown();

        // This watches for tasks that take too long to finish and forces the thread pool to shut down
        try {
            if (!executorService.awaitTermination(1, TimeUnit.MINUTES)) {
                System.out.println("Some tasks took too long to finish. Forcing shutdown.");
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }

        printSummary();

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

    // ------------------ PORT SCANNER METHOD --------------------------------------------------------

    // Scans a given port and attempts to grab the service banner if the port is open
    public static void scanPortAndGrabBanner(String ipAddress, int port) {
        try {

            // Creates a socket and attempts to connect to the specified port, with a timeout of 2 seconds
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(ipAddress, port), 2000);
   

            // if (port == 80) {
            //     socket.connect(new InetSocketAddress(ipAddress, port), 300);
            //     grabHttpBanner(socket);
            // } else if (port == 21) {
            //     socket.connect(new InetSocketAddress(ipAddress, port), 500);
            //     grabFtpBanner(socket);
            // } else if (port == 22) {
            //     socket.connect(new InetSocketAddress(ipAddress, port), 1000);
            //     grabSshBanner(socket);
            // } else if (port == 25) {
            //     socket.connect(new InetSocketAddress(ipAddress, port), 700);
            //     grabSmtpBanner(socket);
            // } else if (port == 443) {
            //     socket.connect(new InetSocketAddress(ipAddress, port), 3000);
            //     grabHttpsBanner(socket);
            // } else {
            //     socket.connect(new InetSocketAddress(ipAddress, port), 2000); // Increase timeout for other ports
            // }

            // if the port is open, add it to the list and attempt to grab a banner
            String openMessage = String.format("Port %d is OPEN on %s", port, ipAddress);
            System.out.println(openMessage);
            openPorts.add(openMessage);

            switch(port) {
                case 21:
                    grabFtpBanner(socket);
                    break;
                case 22:
                    grabSshBanner(socket);
                    break;
                case 25:
                    grabSmtpBanner(socket);
                    break;
                case 80:
                    grabHttpBanner(socket);
                    break;
                case 443:
                    grabHttpsBanner(socket);
                    break;
                default:
                    System.out.printf("Attempted connection to %s on port %d.\n", ipAddress, port);
                    break;
            }

            socket.close();
        } catch (IOException e) {

            // If the port is closed or unreachable, add it to the closed port list
            String errorMessage = String.format("Port %d is CLOSED or unreachable on %s", port, ipAddress);
            System.out.println(errorMessage);
            closedPorts.add(errorMessage);
        }
    }

    // ------------------ BANNER GRABBER METHODS --------------------------------------------------------

    public static void grabHttpBanner(Socket socket) {
        try {
            String httpRequest = "GET / HTTP/1.1\r\nHost: " + socket.getInetAddress().getHostAddress() + "\r\n\r\n";
            socket.getOutputStream().write(httpRequest.getBytes());

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;
            StringBuilder banner = new StringBuilder();

            System.out.println("HTTP Banner: ");
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
                banner.append(responseLine).append("\n");
            }

            matchVulnerabilities("Apache", extractVersion(banner.toString()));

        } catch (IOException e) {
            System.out.println("Error reading HTTP banner.");
        }
    }

    public static void grabFtpBanner(Socket socket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;
            StringBuilder banner = new StringBuilder();

            System.out.println("FTP Banner: ");
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
                banner.append(responseLine).append("\n");
            }

            matchVulnerabilities("FTP", extractVersion(banner.toString()));

        } catch (IOException e) {
            System.out.println("Error reading FTP banner.");
        }
    }

    public static void grabSshBanner(Socket socket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;
            StringBuilder banner = new StringBuilder();

            System.out.println("SSH Banner: ");
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
                banner.append(responseLine).append("\n");
            }

            matchVulnerabilities("OpenSSH", extractVersion(banner.toString()));
            
        } catch (IOException e) {
            System.out.println("Error reading SSH banner.");
        }
    }

    public static void grabSmtpBanner(Socket socket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;
            StringBuilder banner = new StringBuilder();

            System.out.println("SMTP Banner: ");
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
                banner.append(responseLine).append("\n");
            }

            matchVulnerabilities("SMTP", extractVersion(banner.toString()));

        } catch (IOException e) {
            System.out.println("Error reading SMTP banner.");
        }
    }

    public static void grabHttpsBanner(Socket socket) {
        try {
            System.out.println("HTTPS Banner is encrypted, attempting to connect to " + socket.getInetAddress());
        } catch (Exception e) {
            System.out.println("Unable to connect to HTTPS service.");
        }
    }

    public static void printSummary() {
        System.out.println("\n------------- SUMMARY -------------");

        System.out.println("Open ports detected: ");
        for (String open : openPorts) {
            System.out.println(open);
        }

        System.out.println("\nClosed ports detected: ");
        for (String closed : closedPorts) {
            System.out.println(closed);
        }

        System.out.println("------------- END OF SCAN RESULTS -------------");
    }

    // ------------------ VULNERABILITY DATABASE METHODS --------------------------------------------------------

    public static void logToFile(String logMessage) {
        try (FileWriter out = new FileWriter("scan_results.txt", true)) {
            out.write(logMessage + "\n");
        } catch (IOException e) {
            System.out.println("Error writing to file.");
        }
    }

    public static void loadVulnerabilityDatabase(String fileName) {
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                String service = parts[0].trim();
                String version = parts[1].trim();
                String cve = parts[2].trim();
                String description = parts[3].trim();
                vulnerabilityDatabase.put(service + version, cve + ": " + description);
            }
        } catch (IOException e) {
            System.out.println("Error loading vulnerability database.");
        }
    }

    public static void matchVulnerabilities(String service, String version) {
        String key = service + version;
        if (vulnerabilityDatabase.containsKey(key)) {
            System.out.println("**** VULNERABILITIY IDENTIFIED ****: " + vulnerabilityDatabase.get(key));
        } else {
            System.out.println("No known vulnerabilities identified for the service and version: " + service + version);
        }
    }

    public static String extractVersion(String banner) {
        if (banner.contains("/")) {
            String[] parts = banner.split("/");
            if (parts.length > 1) {
                return parts[1].split(" ")[0];
            }
        }
        return "Unknown";
    }
}