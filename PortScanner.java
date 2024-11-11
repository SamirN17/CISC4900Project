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

    // Stores banners
    private static Map<String, String> banners = new HashMap<>();

    // private static final String LOG_FILE = "scan_log.txt";
    private static final String REPORT_FILE = "scan_report.csv";

    public static void startScan(String ipAddress, int startPort, int endPort) {
        openPorts.clear();
        closedPorts.clear();

        ExecutorService executorService = Executors.newFixedThreadPool(10);

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
    }

    public static List<String> getOpenPorts() {
        return new ArrayList<>(openPorts);
    }

    public static List<String> getClosedPorts() {
        return new ArrayList<>(closedPorts);
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

    public static void scanPortAndGrabBanner(String ipAddress, int port) {
        int retries = 3;
        while (retries > 0) {
            try {
                Socket socket = new Socket();
                InetSocketAddress address = new InetSocketAddress(ipAddress, port);
    
                if (tryConnectWithRetry(socket, address, 3)) {
                    String openMessage = String.format("Port %d is OPEN on %s", port, ipAddress);
                    System.out.println(openMessage);
                    openPorts.add(openMessage);
    
                    String banner = "No banner grabbed";
                    switch (port) {
                        case 21:
                            banner = grabFtpBanner(socket);
                            break;
                        case 22:
                            banner = grabSshBanner(socket);
                            break;
                        case 25:
                            banner = grabSmtpBanner(socket);
                            break;
                        case 80:
                            banner = grabHttpBanner(socket);
                            break;
                        case 443:
                            banner = grabHttpsBanner(socket);
                            break;
                        default:
                            System.out.printf("No specific banner grabber for port %d on %s\n", port, ipAddress);
                            break;
                    }
    
                    banners.put(String.valueOf(port), banner);
                    matchVulnerabilities(getServiceFromPort(port), extractService(banner));

                    socket.close();
                    break;
                } else {
                    String errorMessage = String.format("Port %d is CLOSED or unreachable on %s", port, ipAddress);
                    System.out.println(errorMessage);
                    closedPorts.add(errorMessage);
                    break;
                }
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
    
    public static void showProgress(int currentPort, int startPort, int endPort) {
        int totalPorts = endPort - startPort + 1;
        int scannedPorts = currentPort - startPort + 1;
        int progress = (scannedPorts * 100) / totalPorts;
        System.out.printf("Progress: %d%% (%d/%d ports scanned)\r", progress, scannedPorts, totalPorts);
    }
    

    // ------------------ BANNER GRABBER METHODS --------------------------------------------------------

    public static String grabHttpBanner(Socket socket) {
        StringBuilder banner = new StringBuilder();
        try {
            String httpRequest = "GET / HTTP/1.1\r\nHost: " + socket.getInetAddress().getHostAddress() + "\r\n\r\n";
            socket.getOutputStream().write(httpRequest.getBytes());

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
                banner.append(responseLine).append(" ");
            }

            matchVulnerabilities("Apache", extractVersion(banner.toString()));

        } catch (IOException e) {
            System.out.println("Error reading HTTP banner.");
            logError("Error reading HTTP banner: " + e.getMessage());
        }
        return banner.toString().trim();
    }

    public static String grabFtpBanner(Socket socket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String banner = reader.readLine();
            if (banner != null && !banner.isEmpty()) {
                System.out.println("FTP Banner: " + banner);
                return banner;
            } else {
                return "No FTP banner detected.";
            }
        } catch (IOException e) {
            logError("Error reading FTP banner: " + e.getMessage());
            return "Error reading FTP banner.";
        }
    }
    
    public static String grabSshBanner(Socket socket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String banner = reader.readLine();
            if (banner != null && !banner.isEmpty()) {
                System.out.println("SSH Banner: " + banner);
                return banner;
            } else {
                return "No SSH banner detected.";
            }
        } catch (IOException e) {
            logError("Error reading SSH banner: " + e.getMessage());
            return "Error reading SSH banner.";
        }
    }
    
    public static String grabSmtpBanner(Socket socket) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            String banner = reader.readLine();
            System.out.println("SMTP Banner: " + banner);
            return banner != null ? banner : "No SMTP banner grabbed";
        } catch (IOException e) {
            System.out.println("Error reading SMTP banner.");
            return "Error reading SMTP banner.";
        }
    }

    public static String grabHttpsBanner(Socket socket) {
        StringBuilder banner = new StringBuilder();
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
        return banner.toString().trim();
    }

    public static boolean tryConnectWithRetry(Socket socket, InetSocketAddress address, int retries) {
        while (retries > 0) {
            try {
                socket.connect(address, 2000); // 2-second timeout
                return true;
            } catch (IOException e) {
                retries--;
                System.out.println("Retrying connection to " + address + " (" + retries + " retries left)");
            }
        }
        return false;
    }

    public static String getServiceFromPort(int port) {
        switch (port) {
            case 21:
                return "FTP";
            case 22:
                return "OpenSSH";
            case 25:
                return "SMTP";
            case 80:
                return "Apache";
            case 443:
                return "HTTPS";
            default:
                return "Unknown Service";
        }
    }
    
    public static String getPortDetails(String portInfo) {
        String[] parts = portInfo.split(" ");
        return parts[1]; // Assuming "Port <port> is OPEN" format
    }
    
    public static void retryOpenPorts() {
        if (closedPorts.isEmpty()) {
            System.out.println("No previously closed ports to retry.");
            return;
        }
    
        System.out.println("\nRetrying closed ports...");
        List<String> failedPorts = new ArrayList<>();
        
        for (String closedPortEntry : closedPorts) {
            String[] parts = closedPortEntry.split(" ");
            String portString = parts[1];  
            int port = Integer.parseInt(portString);
    
            try {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress("127.0.0.1", port), 2000);
                System.out.printf("Port %d is now OPEN.\n", port);
                openPorts.add("Port " + port + " is OPEN");
                closedPorts.remove(closedPortEntry);
                socket.close();
            } catch (IOException e) {
                System.out.printf("Port %d is still CLOSED.\n", port);
                failedPorts.add(closedPortEntry);
            }
        }
    
        closedPorts.clear();
        closedPorts.addAll(failedPorts);
    
        System.out.println("\nRetry scan complete.");
        printSummary();
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

    public static String extractService(String banner) {
        if (banner.contains("/")) {
            return banner.split("/")[0].trim();
        }
        return "Unknown Service";
    }

    public static String getPortFromMessage(String message) {
        try {
            String[] parts = message.split(" ");
            return parts[1];
        } catch (ArrayIndexOutOfBoundsException e) {
            logError("Error extracting port from message: " + message + " - " + e.getMessage());
            return "Unknown";
        }
    }

    public static String getBanner(String portMessage) {
        String port = getPortFromMessage(portMessage);
        return banners.getOrDefault(port, "No banner grabbed");
    }

    public static String getVulnerability(String portMessage) {
        String port = getPortFromMessage(portMessage);
        String banner = getBanner(portMessage);
    
        String service = extractService(banner);
        String version = extractVersion(banner);
    
        String key = service + version;
        return vulnerabilityDatabase.getOrDefault(key, "No known vulnerabilities found");
    }
    

    // ------------------ LOGGING METHODS --------------------------------------------------------

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
        try (FileWriter out = new FileWriter("scan_log.txt", true)) {
            out.write(java.time.LocalDateTime.now() + " - " + errorMessage + "\n");
        } catch (IOException e) {
            System.out.println("Error writing to log file: " + e.getMessage());
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

    public static void generateCSVReport(String ipAddress) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("scan_results.csv"))) {
            writer.println("IP Address,Port,Status,Banner,Vulnerability");

            for (String openPort : openPorts) {
                writer.printf("%s,%s,OPEN,%s,%s\n", ipAddress, getPortFromMessage(openPort), getBanner(openPort), getVulnerability(openPort));
            }

            for (String closedPort : closedPorts) {
                writer.printf("%s,%s,CLOSED,,\n", ipAddress, getPortFromMessage(closedPort));
            }

            System.out.println("CSV report generated successfully.");
        } catch (IOException e) {
            System.out.println("Error generating CSV report.");
            logError("Error generating CSV report: " + e.getMessage());
        }
    }
    
    public static void generateJSONReport(String ipAddress) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("scan_report.json"))) {
            writer.println("{");
            writer.printf("  \"IP Address\": \"%s\",\n", ipAddress);
            writer.printf("  \"Date/Time\": \"%s\",\n", java.time.LocalDateTime.now());
            
            writer.println("  \"Open Ports\": [");
            for (int i = 0; i < openPorts.size(); i++) {
                String openPort = openPorts.get(i);
                String port = getPortFromMessage(openPort);
                String banner = getBanner(port);
                String vulnerability = getVulnerability(port);
                writer.printf("    {\"Port\": \"%s\", \"Status\": \"OPEN\", \"Banner\": \"%s\", \"Vulnerability\": \"%s\"}", port, banner, vulnerability);
                if (i < openPorts.size() - 1) writer.print(",");
                writer.println();
            }
            writer.println("  ],");
            
            writer.println("  \"Closed Ports\": [");
            for (int i = 0; i < closedPorts.size(); i++) {
                String closedPort = closedPorts.get(i);
                String port = getPortFromMessage(closedPort);
                writer.printf("    {\"Port\": \"%s\", \"Status\": \"CLOSED\"}", port);
                if (i < closedPorts.size() - 1) writer.print(",");
                writer.println();
            }
            writer.println("  ]");
            writer.println("}");
            
            System.out.println("JSON report generated successfully as scan_report.json");
        } catch (IOException e) {
            System.out.println("Error generating JSON report.");
            logError("Error generating JSON report: " + e.getMessage());
        }
    }
            
    public static String checkVulnerability(String port, String banner) {
        // Extract the service name and version from the banner
        String service = getServiceFromBanner(banner);
        String version = extractVersionFromBanner(banner);
    
        // If either service or version is unknown, return a default message
        if (service.equals("Unknown") || version.equals("Unknown")) {
            return "No known vulnerabilities found.";
        }
    
        // Construct a key based on service and version
        String key = service + version;
    
        // Check if the key exists in the vulnerability database
        if (vulnerabilityDatabase.containsKey(key)) {
            return vulnerabilityDatabase.get(key);
        } else {
            return "No known vulnerabilities found.";
        }
    }    

    public static String getServiceFromBanner(String banner) {
        if (banner.contains("Apache")) return "Apache";
        if (banner.contains("OpenSSH")) return "OpenSSH";
        if (banner.contains("MySQL")) return "MySQL";
        if (banner.contains("FTP")) return "FTP";
        if (banner.contains("SMTP")) return "SMTP";
        return "Unknown";
    }    
    
    public static String extractVersionFromBanner(String banner) {
    String version = "Unknown";

    String[] tokens = banner.split("[ /]");
    for (String token : tokens) {
        if (token.matches("\\d+\\.\\d+(\\.\\d+)?")) {
            version = token;
            break;
        }
    }
    return version;
}

    public static String outputFormat = "console";

    public static void viewPreviousReport() {
        try (BufferedReader reader = new BufferedReader(new FileReader(REPORT_FILE))) {
            System.out.println("\nPrevious Scan Report:");
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            System.out.println("No previous report found or error reading report file.");
            logError("Error reading previous report: " + e.getMessage());
        }
    }    

    public static void chooseOutputFormat(String format) {
        switch (format.toLowerCase()) {
            case "console":
                outputFormat = "console";
                System.out.println("Output format set to Console.");
                break;
            case "csv":
                outputFormat = "csv";
                System.out.println("Output format set to CSV File.");
                break;
            case "json":
                outputFormat = "json";
                System.out.println("Output format set to JSON File.");
                break;
            default:
                System.out.println("Invalid format. Defaulting to Console.");
                outputFormat = "console";
        }
    }
    
    public static void generateReport(String ipAddress) {
        switch (outputFormat) {
            case "console":
                printSummary();  // Print results to the console
                break;
            case "csv":
                generateCSVReport(ipAddress);
                break;
            case "json":
                generateJSONReport(ipAddress);
                break;
        }
    }    
}

// Obsolete methods saved just in case:
    // public static void generateJSONReport(String ipAddress) {
    //     String jsonFile = "scan_report.json";
    //     try (PrintWriter writer = new PrintWriter(new FileWriter(jsonFile))) {
    //         writer.println("{");
    //         writer.printf("  \"IP Address\": \"%s\",\n", ipAddress);
    //         writer.printf("  \"Date/Time\": \"%s\",\n", java.time.LocalDateTime.now());
            
    //         writer.println("  \"Open Ports\": [");
    //         for (int i = 0; i < openPorts.size(); i++) {
    //             String openPort = openPorts.get(i);
    //             String port = getPortDetails(openPort);
    //             String banner = banners.getOrDefault(port, "No banner grabbed");
    //             String vulnerability = "No known vulnerabilities found";
    //             String description = "";
    //             String severity = "";
    
    //             if (!banner.equals("No banner grabbed")) {
    //                 String service = getServiceFromBanner(banner);
    //                 String version = extractVersion(banner);
    //                 String key = service + version;
    
    //                 if (vulnerabilityDatabase.containsKey(key)) {
    //                     String[] vulnInfo = vulnerabilityDatabase.get(key).split(": ");
    //                     vulnerability = vulnInfo[0];
    //                     description = vulnInfo[1].split(" \\(Severity: ")[0];
    //                     severity = vulnInfo[1].split(" \\(Severity: ")[1].replace(")", "");
    //                 }
    //             }
    
    //             writer.printf("    {\"Port\": \"%s\", \"Status\": \"OPEN\", \"Banner\": \"%s\", \"Vulnerability\": \"%s\", \"Description\": \"%s\", \"Severity\": \"%s\"}", 
    //                           port, banner, vulnerability, description, severity);
    //             if (i < openPorts.size() - 1) writer.print(",");
    //             writer.println();
    //         }
    //         writer.println("  ],");
    
    //         writer.println("  \"Closed Ports\": [");
    //         for (int i = 0; i < closedPorts.size(); i++) {
    //             String closedPort = closedPorts.get(i);
    //             String port = getPortDetails(closedPort);
    
    //             writer.printf("    {\"Port\": \"%s\", \"Status\": \"CLOSED\"}", port);
    //             if (i < closedPorts.size() - 1) writer.print(",");
    //             writer.println();
    //         }
    //         writer.println("  ]");
    //         writer.println("}");
            
    //         System.out.println("JSON Report generated successfully as " + jsonFile);
    //     } catch (IOException e) {
    //         System.out.println("Error generating JSON report.");
    //         logError("Error generating JSON report: " + e.getMessage());
    //     }
    // }

        // public static void generateCSVReport(String ipAddress) {
    //     String csvFile = "scan_results.csv";
    //     try (PrintWriter writer = new PrintWriter(new FileWriter(csvFile))) {
    //         writer.println("IP Address,Port,Status,Banner,Vulnerability,Description,Severity");
    
    //         for (String openPort : openPorts) {
    //             String[] parts = openPort.split(" ");
    //             String port = parts[1];
    //             String banner = banners.getOrDefault(port, "No banner grabbed");
    //             String vulnerability = "No known vulnerabilities found";
    //             String description = "";
    //             String severity = "";
    
    //             if (!banner.equals("No banner grabbed")) {
    //                 String service = getServiceFromBanner(banner);
    //                 String version = extractVersion(banner);
    //                 String key = service + version;
    
    //                 if (vulnerabilityDatabase.containsKey(key)) {
    //                     String[] vulnInfo = vulnerabilityDatabase.get(key).split(": ");
    //                     vulnerability = vulnInfo[0];
    //                     description = vulnInfo[1].split(" \\(Severity: ")[0];
    //                     severity = vulnInfo[1].split(" \\(Severity: ")[1].replace(")", "");
    //                 }
    //             }
    
    //             writer.printf("%s,%s,OPEN,%s,%s,%s,%s\n", ipAddress, port, banner, vulnerability, description, severity);
    //         }
    
    //         for (String closedPort : closedPorts) {
    //             String[] parts = closedPort.split(" ");
    //             String port = parts[1];
    //             writer.printf("%s,%s,CLOSED,,,\n", ipAddress, port);
    //         }
    
    //         System.out.println("CSV report generated successfully as " + csvFile);
    //     } catch (IOException e) {
    //         System.out.println("Error generating CSV report.");
    //         logError("Error generating CSV report: " + e.getMessage());
    //     }
    // }

        // public static void chooseOutputFormat() {
    //     Scanner scanner = new Scanner(System.in);
    //     System.out.println("\nChoose Output Format:");
    //     System.out.println("1. Console");
    //     System.out.println("2. CSV File");
    //     System.out.println("3. JSON File");
    //     System.out.print("Enter your choice: ");
        
    //     int formatOption = scanner.nextInt();
    //     scanner.nextLine();
        
    //     switch (formatOption) {
    //         case 1:
    //             outputFormat = "console";
    //             System.out.println("Output format set to Console.");
    //             break;
    //         case 2:
    //             outputFormat = "csv";
    //             System.out.println("Output format set to CSV File.");
    //             break;
    //         case 3:
    //             outputFormat = "json";
    //             System.out.println("Output format set to JSON File.");
    //             break;
    //         default:
    //             System.out.println("Invalid option. Defaulting to Console.");
    //             outputFormat = "console";
    //     }
    // }

        // public static void main(String[] args) {
    //     // Shows the main menu
    //     showMenu();
    // }

    // public static void showMenu() {
    //     Scanner scanner = new Scanner(System.in);
    //     while (true) {
    //         System.out.println("============================================");
    //         System.out.println("Welcome to VulnerabilityScan");
    //         System.out.println("1. Start a port scan");
    //         System.out.println("2. View known vulnerabilities");
    //         System.out.println("3. Configure settings");
    //         System.out.println("4. Choose output format");
    //         System.out.println("5. View previous scan report");
    //         System.out.println("6. Retry scanning closed ports");
    //         System.out.println("7. Exit");
    //         System.out.print("Choose an option: ");
    //         int option = scanner.nextInt();
            
    //         switch (option) {
    //             case 1:
    //                 startScan();
    //                 break;
    //             case 2:
    //                 printVulnerabilityDatabase();
    //                 break;
    //             case 3:
    //                 configureSettings(scanner);
    //                 break;
    //             case 4:
    //                 chooseOutputFormat();
    //                 break;
    //             case 5:
    //                 viewPreviousReport();
    //                 break;
    //             case 6:
    //                 retryOpenPorts();
    //                 break;
    //             case 7:
    //                 System.out.println("Exiting the program.");
    //                 System.exit(0);
    //             default:
    //                 System.out.println("Invalid option. Please try again.");
    //         }
    //     }
    // }

    // public static void configureSettings(Scanner scanner) {
    //     System.out.print("Enter new timeout value (ms): ");
    //     int timeout = scanner.nextInt();
    //     System.out.print("Enter number of connection retries: ");
    //     int retries = scanner.nextInt();
    //     System.out.println("Settings updated: Timeout = " + timeout + "ms, Retries = " + retries);
    // }

    // public static void startScan() {
    //     Scanner scanner = new Scanner(System.in);
    //     System.out.println("\nPort Scan Selected");
    //     System.out.println("==================");
        
    //     loadVulnerabilityDatabase("vulnerabilities.csv");

    //     System.out.print("Enter target IP Address: ");
    //     String ipAddress = scanner.nextLine();
    //     if (!isValidIPAddress(ipAddress)) {
    //         System.out.println("Invalid IP address. Please enter a valid IP address.");
    //         logError("Invalid IP address entered: " + ipAddress);
    //         return;
    //     }

    //     System.out.print("Enter start port: ");
    //     int startPort = scanner.nextInt();
    //     System.out.print("Enter end port: ");
    //     int endPort = scanner.nextInt();

    //     ExecutorService executorService = Executors.newFixedThreadPool(10);
    //     System.out.printf("Scanning %s from port %d to port %d...\n\n", ipAddress, startPort, endPort);

    //     for (int port = startPort; port <= endPort; port++) {
    //         int currentPort = port;
    //         executorService.submit(() -> scanPortAndGrabBanner(ipAddress, currentPort));
    //         showProgress(currentPort, startPort, endPort);
    //     }

    //     executorService.shutdown();
    //     try {
    //         if (!executorService.awaitTermination(1, TimeUnit.MINUTES)) {
    //             System.out.println("Some tasks took too long to finish. Forcing shutdown.");
    //             executorService.shutdownNow();
    //         }
    //     } catch (InterruptedException e) {
    //         executorService.shutdownNow();
    //     }

    //     System.out.println("Would you like to save the scan report to a file? (yes/no)");
    //     Scanner scanner2 = new Scanner(System.in);
    //     String saveToFile = scanner2.nextLine();
    //     if (saveToFile.equalsIgnoreCase("yes")) {
    //         switch (outputFormat.toLowerCase()) {
    //             case "csv":
    //                 generateCSVReport(ipAddress);
    //                 break;
    //             case "json":
    //                 generateJSONReport(ipAddress);
    //                 break;
    //             default:
    //                 printSummary();
    //                 System.out.println("Report printed to console as no file format was selected.");
    //                 break;
    //         }
    //     } else {
    //         printSummary();
    //     }
    // }