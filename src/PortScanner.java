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

    private static final String REPORT_FILE = "scan_report.csv";


    // Starts a port scan for the given IP address and port range.
    public static void startScan(String ipAddress, int startPort, int endPort) {
        openPorts.clear();
        closedPorts.clear();

        // Loads the vulnerability database
        vulnerabilityDatabase = VulnerabilityLoader.loadVulnerabilities("C:\\Users\\Samir\\CISC4900Project\\src\\vulnerabilities.csv");        
        System.out.println("Vulnerability database loaded successfully.");


        // Uses a thread pool to handle multi-threaded port scanning
        ExecutorService executorService = Executors.newFixedThreadPool(10);

        // Submits scan tasks for each port in the range
        for (int port = startPort; port <= endPort; port++) {
            int currentPort = port;
            executorService.submit(() -> scanPortAndGrabBanner(ipAddress, currentPort));
        }

        // Waits for the scan to finish or time out
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

    // Returns a list of open ports identified in the scan.
    public static List<String> getOpenPorts() {
        return new ArrayList<>(openPorts);
    }

    // Returns a list of closed ports identified in the scan.
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

    // ------------------ PAUSE/RESUME SCAN FUNCTIONS --------------------------------------------------------

    private static volatile boolean isPaused = false;

    public static synchronized void pauseScan() {
        isPaused = true;
    }
    
    public static synchronized void resumeScan() {
        isPaused = false;
        synchronized (PortScanner.class) {
            PortScanner.class.notifyAll();
        }
    }
    
    public static synchronized void checkPause() {
        while (isPaused) {
            try {
                synchronized (PortScanner.class) {
                    PortScanner.class.wait();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    //  ------------------ SCAN PORTS AND GRAB BANNERS --------------------------------------------------------
    
    public static void scanPortAndGrabBanner(String ipAddress, int port) {
        // Prevents duplicate scanning for the same port
        if (openPorts.contains(String.format("Port %d is OPEN on %s", port, ipAddress))) {
            System.out.println("Port " + port + " is already scanned as OPEN.");
            return;
        }
    
        int retries = 3; // Retry count for connecting to the port
        while (retries > 0) {
            checkPause();
            try {
                // Establishes a socket connection to the port
                Socket socket = new Socket();
                InetSocketAddress address = new InetSocketAddress(ipAddress, port);
    
                if (tryConnectWithRetry(socket, address, 3)) {
                    // If connection is successful, mark the port as open
                    String openMessage = String.format("Port %d is OPEN on %s", port, ipAddress);
                    System.out.println(openMessage);
                    openPorts.add(openMessage);
    
                    // Attempts to grab the banner based on the port number
                    String banner = "No banner grabbed";
                    switch (port) {
                        case 21 -> banner = grabFtpBanner(socket);
                        case 22 -> banner = grabSshBanner(socket);
                        case 25 -> banner = grabSmtpBanner(socket);
                        case 80 -> banner = grabHttpBanner(socket);
                        case 443 -> banner = grabHttpsBanner(socket);
                        default -> System.out.printf("No specific banner grabber for port %d on %s\n", port, ipAddress);
                    }
    
                    banners.put(String.valueOf(port), banner); // Store the banner
    
                    // Extracts service and version from the banner
                    String service = extractService(banner);
                    String version = extractVersion(banner);
                    System.out.println("Banner: " + banner);
                    System.out.println("Extracted Service: " + service);
                    System.out.println("Extracted Version: " + version);

                    // Matches vulnerabilities using the service and version
                    String key = (service + version).toLowerCase().replaceAll("\\s+", "");
                    System.out.println("Constructed Key for Database Lookup: " + key);
    
                    // Checks if the key exists in the vulnerability database
                    if (vulnerabilityDatabase.containsKey(key)) {
                        String vulnerability = vulnerabilityDatabase.get(key);
                        System.out.println("**** VULNERABILITY IDENTIFIED ****: " + vulnerability);
                    } else {
                        System.out.println("No vulnerabilities found for the key: " + key);
                        System.out.println("Service " + service + " is not in the vulnerability database.");
                    }
    
                    matchVulnerabilities(service, version);
    
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
                    // Keeps track of retries, and logs the errors
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
    
    public static void scanCommonPorts(String ipAddress, int[] ports) {
        openPorts.clear();
        closedPorts.clear();
    
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        for (int port : ports) {
            executorService.submit(() -> scanPortAndGrabBanner(ipAddress, port));
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
    
    // Shows how many ports have been scanned
    public static void showProgress(int currentPort, int startPort, int endPort) {
        int totalPorts = endPort - startPort + 1;
        int scannedPorts = currentPort - startPort + 1;
        int progress = (scannedPorts * 100) / totalPorts;
        System.out.printf("Progress: %d%% (%d/%d ports scanned)\r", progress, scannedPorts, totalPorts);
    }
    
    

    // ------------------ BANNER GRABBER METHODS --------------------------------------------------------

    // Grabs the HTTP banner by sending a GET request.
    public static String grabHttpBanner(Socket socket) {
        StringBuilder banner = new StringBuilder();
        try {
            String httpRequest = "GET / HTTP/1.1\r\nHost: " + socket.getInetAddress().getHostAddress() + "\r\n\r\n";
            socket.getOutputStream().write(httpRequest.getBytes());
    
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String responseLine;
            while ((responseLine = reader.readLine()) != null && !responseLine.isEmpty()) {
                System.out.println(responseLine);
                banner.append(responseLine).append("\n");
            }
    
            return banner.toString().trim();
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

    // HTTPS banners are encrypted by default, so this is a basic way to "grab" the banner
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
                socket.connect(address, 2000);
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
        return parts[1];
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
        System.out.println("Attempting to load vulnerability database from: " + fileName);
        File file = new File(fileName);
        if (!file.exists()) {
            System.out.println("Vulnerability database file not found: " + fileName);
            return;
        }  

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            reader.readLine();
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length < 5) {
                    System.out.println("Invalid line in database: " + line);
                    continue;
                }
            
                String service = parts[0].trim().toLowerCase();
                String version = parts[1].trim().toLowerCase();
                String key = (service.toLowerCase() + version.toLowerCase()).replaceAll("\\s+", "");
                String cve = parts[2].trim();
                String description = parts[3].trim();
                String severity = parts[4].trim();
                vulnerabilityDatabase.put(key, cve + ": " + description + " (Severity: " + severity + ")");
                System.out.println("Loaded vulnerability: " + key + " -> " + vulnerabilityDatabase.get(key));
            }

            System.out.println("Loaded Vulnerability Keys: " + vulnerabilityDatabase.keySet());
        } catch (IOException e) {
            System.out.println("Error loading vulnerability database: " + e.getMessage());
        }
    }

    public static String constructKey(String service, String version) {
        return (service.toLowerCase() + version.toLowerCase()).replaceAll("\\s+", "");
    }

    public static String matchVulnerabilities(String service, String version) {
        String key = constructKey(service, version);
        System.out.println("Constructed Key for Database Lookup: " + key);

        if (vulnerabilityDatabase.containsKey(key)) {
            String vulnerability = vulnerabilityDatabase.get(key);
            System.out.println("**** VULNERABILITY IDENTIFIED ****: " + vulnerability);
            return vulnerability;
        } else {
            System.out.println("No vulnerabilities found for the key: " + key);
            System.out.println("Service " + service + " is not in the vulnerability database.");
            System.out.println("Consider adding it to the database if relevant vulnerabilities are discovered.");
            return "No known vulnerabilities found";
        }
    }
                                                        
    public static String extractService(String banner) {
        if (banner.contains("OpenSSH")) return "OpenSSH";
        if (banner.contains("Apache")) return "Apache";
        if (banner.contains("FTP")) return "FTP";
        if (banner.contains("SMTP")) return "SMTP";
        return "Unknown Service";
    }
                
    public static String extractVersion(String banner) {
        if (banner.contains("OpenSSH")) {
            String[] parts = banner.split("-");
            for (String part : parts) {
                if (part.contains("OpenSSH")) {
                    String[] tokens = part.split("_for_Windows_"); // Splits Windows-specific part
                    if (tokens.length > 1) {
                        String version = tokens[1].trim();
                        if (version.matches("\\d+\\.\\d+(\\.\\d+)?")) { // Checks for version format
                            return version;
                        }
                    }
                }
            }
        }
        String[] tokens = banner.split("[ /()]");
        for (String token : tokens) {
            if (token.matches("\\d+\\.\\d+(\\.\\d+)?")) {
                return token;
            }
        }

        return "Unknown Version";
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
        String banner = getBanner(portMessage);
    
        String service = extractService(banner);
        String version = extractVersion(banner);
    
        System.out.println("Extracted Service: " + service);
        System.out.println("Extracted Version: " + version);
    
        String key = (service + version).toLowerCase().replaceAll("\\s+", "");
    
        if (vulnerabilityDatabase.containsKey(key)) {
            String localVulnerability = vulnerabilityDatabase.get(key);
            System.out.println("Vulnerability Found in Local Database: " + localVulnerability);
            return localVulnerability;
        } else {
            System.out.println("No vulnerabilities found for: " + service + " " + version);
            return "No known vulnerabilities found";
        }
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


    // ------------------ REPORT GENERATION METHODS --------------------------------------------------------
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
                String banner = banners.getOrDefault(port, "No banner grabbed");
                String vulnerability = getVulnerability(openPort);
                
                writer.printf("    {\"Port\": \"%s\", \"Status\": \"OPEN\", \"Banner\": \"%s\", \"Vulnerability\": \"%s\"}",
                    port, banner, vulnerability);
    
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
            System.out.println("Error generating JSON report: " + e.getMessage());
        }
    }
        
    public static void generateXMLReport(String ipAddress) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("scan_report.xml"))) {
            writer.println("<ScanReport>");
            writer.printf("  <IPAddress>%s</IPAddress>\n", ipAddress);
            writer.printf("  <DateTime>%s</DateTime>\n", java.time.LocalDateTime.now());
    
            writer.println("  <OpenPorts>");
            for (String openPort : getOpenPorts()) {
                String port = getPortFromMessage(openPort);
                String banner = getBanner(openPort);
                String vulnerability = getVulnerability(openPort);
                writer.printf("    <Port number=\"%s\">\n", port);
                writer.printf("      <Status>OPEN</Status>\n");
                writer.printf("      <Banner>%s</Banner>\n", banner);
                writer.printf("      <Vulnerability>%s</Vulnerability>\n", vulnerability);
                writer.println("    </Port>");
            }
            writer.println("  </OpenPorts>");
    
            writer.println("  <ClosedPorts>");
            for (String closedPort : getClosedPorts()) {
                String port = getPortFromMessage(closedPort);
                writer.printf("    <Port number=\"%s\">\n", port);
                writer.printf("      <Status>CLOSED</Status>\n");
                writer.println("    </Port>");
            }
            writer.println("  </ClosedPorts>");
            writer.println("</ScanReport>");
    
            System.out.println("XML report generated successfully.");
        } catch (IOException e) {
            System.out.println("Error generating XML report.");
            logError("Error generating XML report: " + e.getMessage());
        }
    }    
            
    public static String checkVulnerability(String port, String banner) {
        // Extracts the service name and version from the banner
        String service = getServiceFromBanner(banner);
        String version = extractVersionFromBanner(banner);
    
        // If either service or version is unknown, return a default message
        if (service.equals("Unknown") || version.equals("Unknown")) {
            return "No known vulnerabilities found.";
        }
    
        // Constructs a key based on service and version
        String key = (service + version).toLowerCase().replaceAll("\\s+", "");
            
        // Checks if the key exists in the vulnerability database
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
                printSummary();
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