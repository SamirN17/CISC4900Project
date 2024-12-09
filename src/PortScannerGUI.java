import javafx.application.Application;
import javafx.concurrent.Task;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

import java.io.File;

public class PortScannerGUI extends Application {

    // Boolean flag to manage pause/resume functionality
    private boolean isPaused = false;

    @Override
    public void start(Stage primaryStage) {
        // Creates a tabbed interface for switching between the tutorial and the port scanner
        TabPane tabPane = new TabPane();

        // Tutorial tab with instructions on how to use the application
        Tab tutorialTab = new Tab("Tutorial");
        tutorialTab.setClosable(false); // Prevents the tab from being closed
        tutorialTab.setContent(createTutorialContent());

        // Port scanner tab with the main functionality
        Tab scannerTab = new Tab("Port Scanner");
        scannerTab.setClosable(false);
        scannerTab.setContent(createPortScannerContent(primaryStage));

        tabPane.getTabs().addAll(tutorialTab, scannerTab);

        // Main layout with a menu bar and the tab pane
        VBox root = new VBox(createMenuBar(primaryStage), tabPane);
        Scene scene = new Scene(root, 800, 600);

        primaryStage.setTitle("Port Scanner Application");
        primaryStage.setScene(scene);
        primaryStage.show();
    }


    // Creates the menu bar with File and Help menus.
    private MenuBar createMenuBar(Stage primaryStage) {
        MenuBar menuBar = new MenuBar();

        // File menu with an option to exit the application
        Menu fileMenu = new Menu("File");
        MenuItem exitItem = new MenuItem("Exit");
        exitItem.setOnAction(e -> primaryStage.close());
        fileMenu.getItems().add(exitItem);

        Menu helpMenu = new Menu("Help");
        MenuItem aboutItem = new MenuItem("About");
        aboutItem.setOnAction(e -> showAboutDialog());
        helpMenu.getItems().add(aboutItem);

        menuBar.getMenus().addAll(fileMenu, helpMenu);
        return menuBar;
    }

    // Creates the tutorial content with instructions on how to use the application
    private VBox createTutorialContent() {
        Label tutorialLabel = new Label(
            "Welcome to the Port Scanner Application!\n\n" +
            "How to use the application:\n" +
            "1. Switch to the 'Port Scanner' tab.\n" +
            "2. Enter the IP address and port range to scan.\n" +
            "3. Select the output format (Console, CSV, JSON, or XML).\n" +
            "4. Load the vulnerability database using the 'Load Database' button.\n" +
            "5. Start the scan. Pause or resume as needed.\n" +
            "6. View the results in the specified format.\n\n" +
            "Note: Ensure you have permission to scan the target IPs."
        );
        tutorialLabel.setWrapText(true);

        VBox tutorialLayout = new VBox(10, tutorialLabel);
        tutorialLayout.setStyle("-fx-padding: 20;");
        return tutorialLayout;
    }

    // Creates the content for the Port Scanner tab
    private VBox createPortScannerContent(Stage primaryStage) {
        TextField ipAddressField = new TextField();
        ipAddressField.setPromptText("Enter IP Address");
    
        TextField startPortField = new TextField();
        startPortField.setPromptText("Enter Start Port");
    
        TextField endPortField = new TextField();
        endPortField.setPromptText("Enter End Port");
    
        ComboBox<String> formatDropdown = new ComboBox<>();
        formatDropdown.getItems().addAll("Console", "CSV File", "JSON File", "XML File");
        formatDropdown.setValue("Console");
    
        Button loadDatabaseButton = new Button("Load Database");
        Button startScanButton = new Button("Start Scan");
        Button pauseScanButton = new Button("Pause Scan");
        Button resumeScanButton = new Button("Resume Scan");
    
        TextArea outputArea = new TextArea();
        outputArea.setEditable(false);
    
        // Progress bar to indicate scanning progress
        ProgressBar progressBar = new ProgressBar();
        progressBar.setVisible(false);
    
        // Loads the vulnerability database with a default path, must be changed if exported to other files
        loadDatabaseButton.setOnAction(e -> {
            String defaultPath = "C:\\Users\\Samir\\CISC4900Project\\src\\vulnerabilities.csv";
            File file = new File(defaultPath);
            if (file.exists()) {
                PortScanner.loadVulnerabilityDatabase(defaultPath);
                outputArea.appendText("Vulnerability database loaded successfully from: " + defaultPath + "\n");
            } else {
                outputArea.appendText("Default vulnerability database not found at: " + defaultPath + "\n");
            }
        });
    
        startScanButton.setOnAction(e -> startScan(ipAddressField, startPortField, endPortField, formatDropdown, outputArea, progressBar));
        pauseScanButton.setOnAction(e -> isPaused = true);
        resumeScanButton.setOnAction(e -> synchronizedResume());
    
        // Arranges all the elements in a vertical layout
        VBox layout = new VBox(10, ipAddressField, startPortField, endPortField, formatDropdown,
                loadDatabaseButton, startScanButton, pauseScanButton, resumeScanButton, progressBar, outputArea);
        layout.setStyle("-fx-padding: 20;");
        return layout;
    }
    
    // Resumes the scanning process
    private void synchronizedResume() {
        synchronized (this) {
            isPaused = false;
            notifyAll();
        }
    }

    private void startScan(TextField ipAddressField, TextField startPortField, TextField endPortField, ComboBox<String> formatDropdown, TextArea outputArea, ProgressBar progressBar) {
        try {
            String ipAddress = ipAddressField.getText();
            int startPort = Integer.parseInt(startPortField.getText());
            int endPort = Integer.parseInt(endPortField.getText());

            if (startPort > endPort) {
                showAlert(Alert.AlertType.ERROR, "Invalid Input", "Start port must be less than or equal to end port.");
                return;
            }

            Task<Void> scanTask = new Task<>() {
                @Override
                protected Void call() {
                    int totalPorts = endPort - startPort + 1;
                    for (int port = startPort; port <= endPort; port++) {
                        synchronized (this) {
                            while (isPaused) {
                                try {
                                    wait();
                                } catch (InterruptedException e) {
                                    Thread.currentThread().interrupt();
                                    return null;
                                }
                            }
                        }
                        PortScanner.scanPortAndGrabBanner(ipAddress, port);
                        updateProgress(port - startPort + 1, totalPorts);
                    }
                    return null;
                }
            };

            progressBar.setVisible(true);
            progressBar.progressProperty().bind(scanTask.progressProperty());
            outputArea.clear();

            new Thread(scanTask).start();
        } catch (NumberFormatException ex) {
            showAlert(Alert.AlertType.ERROR, "Invalid Input", "Please enter valid numbers for port range.");
        }
    }

    private void showAboutDialog() {
        String aboutText = "Port Scanner Application v1.0\n" +
                "Developed by: Samir Ndreci\n" +
                "Features:\n" +
                "- Multi-threaded port scanning\n" +
                "- JSON, CSV, and XML report generation\n" +
                "- Vulnerability detection and customizable filters.";
        showAlert(Alert.AlertType.INFORMATION, "About", aboutText);
    }

    private void showAlert(Alert.AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
