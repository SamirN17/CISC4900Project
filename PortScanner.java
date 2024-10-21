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
import java.util.*;
import java.util.Collections;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;


public class PortScanner {

    // Lists to track open and closed ports for the current scan
    private static List<String> openPorts = Collections.synchronizedList(new ArrayList<>());
    private static List<String> closedPorts = Collections.synchronizedList(new ArrayList<>());

    // Database of known vulnerabilities, loaded from the CSV file
    private static Map<String, String> vulnerabilityDatabase = new HashMap<>();

    private static final String LOG_FILE = "scan_log.txt";
    private static final String REPORT_FILE = "scan_report.csv";

    public static void main(String[] args) {
        // Shows the main menu
        showMenu();
    }

    public static void showMenu() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("============================================");
            System.out.println("Wlecome to the VulnerabilityScan Menu");
            System.out.println("1. Start a port scan");
            System.out.println("2. View known vulnerabilities");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");
            int option = scanner.nextInt();
            switch (option) {
                case 1:
                    startScan();
                    break;
                case 2:
                    printVulnerabilityDatabase();
                    break;
                case 3:
                    System.out.println("Exiting the program.");
                    System.exit(0);
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
    }

    public static void startScan() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\nPort Scan Selected");
        System.out.println("==================");
        
        loadVulnerabilityDatabase("vulnerabilities.csv");

        System.out.print("Enter target IP Address: ");
        String ipAddress = scanner.nextLine();
        if (!isValidIPAddress(ipAddress)) {
            System.out.println("Invalid IP address. Please enter a valid IP address.");
            logError("Invalid IP address entered: " + ipAddress);
            return;
        }

        System.out.print("Enter start port: ");
        int startPort = scanner.nextInt();
        System.out.print("Enter end port: ");
        int endPort = scanner.nextInt();

        ExecutorService executorService = Executors.newFixedThreadPool(10);
        System.out.printf("Scanning %s from port %d to port %d...\n\n", ipAddress, startPort, endPort);

        for (int port = startPort; port <= endPort; port++) {
            int currentPort = port;
            executorService.submit(() -> scanPortAndGrabBanner(ipAddress, currentPort));
        }

        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(2, TimeUnit.MINUTES)) {
                System.out.println("Some tasks took too long to finish. Forcing shutdown.");
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }

        System.out.println("Would you like to save the scan report to a file? (yes/no)");
        Scanner scanner2 = new Scanner(System.in);
        String saveToFile = scanner2.nextLine();
        if (saveToFile.equalsIgnoreCase("yes")) {
            generateReport(ipAddress);
        } else {
            printSummary();
        }
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
        int retries = 3;
        while (retries > 0) {
            try {

                // Creates a socket and attempts to connect to the specified port, with a timeout of 2 seconds
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(ipAddress, port), 2000);


                // if the port is open, add it to the list and attempt to grab a banner
                String openMessage = String.format("Port %d is OPEN on %s", port, ipAddress);
                System.out.println(openMessage);
                openPorts.add(openMessage);

                switch (port) {
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
                break;

            } catch (IOException e) {
                retries--;
                if (retries == 0) {
                    String errorMessage = String.format("Port %d is CLOSED or unreachable on %s", port, ipAddress);
                    System.out.println(errorMessage);
                    closedPorts.add(errorMessage);
                    logError("Error connecting to port " + port + ": " + e.getMessage());
                } else {
                    logError("Retry attempt #" + (3 - retries) + " for port " + port);
                }
            }
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
            logError("Error reading HTTP banner: " + e.getMessage());
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

            if (banner.length() > 0) {
                System.out.println("Extracted FTP Banner: " + banner.toString());
                matchVulnerabilities("FTP", extractVersion(banner.toString()));
            } else {
                System.out.println("No FTP banner detected.");
            }

        } catch (IOException e) {
            System.out.println("Error reading FTP banner.");
            logError("Error reading FTP banner: " + e.getMessage());
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

            if (banner.length() > 0) {
                System.out.println("Extracted SSH Banner: " + banner.toString());
                matchVulnerabilities("OpenSSH", extractVersion(banner.toString()));
            } else {
                System.out.println("No SSH banner detected.");
            }            

        } catch (IOException e) {
            System.out.println("Error reading SSH banner.");
            logError("Error reading SSH banner: " + e.getMessage());
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
            logError("Error reading SMTP banner: " + e.getMessage());
        }
    }

    public static void grabHttpsBanner(Socket socket) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                    socket.getInetAddress().getHostAddress(),
                    socket.getPort());
    
            sslSocket.startHandshake();
    
            SSLSession session = sslSocket.getSession();
    
            System.out.println("HTTPS Banner: SSL Handshake successful.");
            System.out.println("Connected to: " + session.getPeerHost());
            System.out.println("SSL Protocol: " + session.getProtocol());
            System.out.println("Cipher Suite: " + session.getCipherSuite());
    
            Certificate[] serverCerts = session.getPeerCertificates();
            for (Certificate cert : serverCerts) {
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    
                    X500Principal issuer = x509Cert.getIssuerX500Principal();
                    X500Principal subject = x509Cert.getSubjectX500Principal();
    
                    System.out.println("Server Certificate Subject: " + subject.getName());
                    System.out.println("Issuer: " + issuer.getName());
                    System.out.println("Serial Number: " + x509Cert.getSerialNumber());
                    System.out.println("Valid From: " + x509Cert.getNotBefore());
                    System.out.println("Valid Until: " + x509Cert.getNotAfter());
                }
            }
    
            sslSocket.close();
        } catch (Exception e) {
            System.out.println("Unable to connect to HTTPS service or retrieve banner. Error: " + e.getMessage());
            logError("Error reading HTTPS banner: " + e.getMessage());
        }
    }

    // ------------------ VULNERABILITY DATABASE METHODS --------------------------------------------------------
    public static void loadVulnerabilityDatabase(String fileName) {
        File file = new File(fileName);
        if (!file.exists()) {
            System.out.println("Vulnerability database file not found: " + fileName);
            logError("Vulnerability database file not found: " + fileName);
            return;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line;
            reader.readLine();
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");

                if (parts.length < 5) {
                    System.out.println("Invalid line in vulnerability database: " + line);
                    continue;
                }

                String service = parts[0].trim();
                String version = parts[1].trim();
                String cve = parts[2].trim();
                String description = parts[3].trim();
                String severity = parts[4].trim();

                String key = service + version;
                vulnerabilityDatabase.put(key, cve + ": " + description + " (Severity: " + severity + ")");
                System.out.println("Loaded vulnerability: " + service + " " + version + " -> " + cve + " (Severity: " + severity + ")");
            }
        } catch (IOException e) {
            System.out.println("Error loading vulnerability database.");
            logError("Error loading vulnerability database: " + e.getMessage());
        }
    }

    public static void matchVulnerabilities(String service, String version) {
       String key = service + version;
        if (vulnerabilityDatabase.containsKey(key)) {
            System.out.println("**** VULNERABILITY IDENTIFIED ****: " + vulnerabilityDatabase.get(key));
            logError("Vulnerability identified: " + vulnerabilityDatabase.get(key));
        } else {
            System.out.println("No known vulnerabilities identified for: " + service + " " + version);
        }
    }    

    public static String extractVersion(String banner) {
        String version = "Unknown";

        if (banner.contains("/")) {
            String[] parts = banner.split("/");
            if (parts.length > 1) {
                String[] versionParts = parts[1].split(" ");
                version = versionParts[0].trim();
            }
        } else if (banner.contains("_")) {
            String[] parts = banner.split("_");
            if (parts.length > 1) {
                version = parts[1].split(" ")[0].trim();
            }
        }
        return version;
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

    public static void logError(String errorMessage) {
        try (FileWriter out = new FileWriter(LOG_FILE, true)) {
            out.write(errorMessage + "\n");
        } catch (IOException e) {
            System.out.println("Error writing to file.");
        }
    }

    public static void printVulnerabilityDatabase() {
        if (vulnerabilityDatabase.isEmpty()) {
            System.out.println("No vulnerabilities found in the database.");
        } else {
            System.out.println("\nKnown Vulnerabilities: ");
            for (Map.Entry<String, String> entry : vulnerabilityDatabase.entrySet()) {
                System.out.println("Service: " + entry.getKey() + " - " + entry.getValue());
            }
        }
    }

    public static void generateReport(String ipAddress) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(REPORT_FILE))) {
            writer.println("Scan Report for IP: " + ipAddress);
            writer.println("Date/Time: " + java.time.LocalDateTime.now());
            writer.println("------------- SCAN RESULTS -------------");
            writer.println("Port,Status,Service,Version,Vulnerability,Severity");
            writer.println("Open ports:");
            for (String openPort : openPorts) {
                writer.println(openPort);
            }
            writer.println("Closed Ports:");
            for (String closedPort : closedPorts) {
                writer.println(closedPort);
            }
            writer.println("------------- END OF SCAN REPORT -------------\n");
            System.out.println("Report generated successfully as " + REPORT_FILE);
        } catch (IOException e) {
            System.out.println("Error generating report.");
            logError("error generating report: " + e.getMessage());
        }
    }
}