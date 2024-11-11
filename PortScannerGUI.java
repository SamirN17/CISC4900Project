

import javafx.application.Application;
import javafx.concurrent.Task;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import javafx.scene.paint.Color;

public class PortScannerGUI extends Application {

    @Override
    public void start(Stage primaryStage) {
        TextField ipAddressField = new TextField();
        ipAddressField.setPromptText("Enter IP Address");

        TextField startPortField = new TextField();
        startPortField.setPromptText("Enter Start Port");

        TextField endPortField = new TextField();
        endPortField.setPromptText("Enter End Port");

        ComboBox<String> formatDropdown = new ComboBox<>();
        formatDropdown.getItems().addAll("Console", "CSV File", "JSON File");
        formatDropdown.setValue("Console");

        Button startScanButton = new Button("Start Scan");
        Button viewOpenPortsButton = new Button("View Open Ports");
        Button viewClosedPortsButton = new Button("View Closed Ports");

        TextArea outputArea = new TextArea();
        outputArea.setEditable(false);

        ProgressBar progressBar = new ProgressBar();
        progressBar.setVisible(false);

startScanButton.setOnAction(e -> {
    try {
        String ipAddress = ipAddressField.getText();
        int startPort = Integer.parseInt(startPortField.getText());
        int endPort = Integer.parseInt(endPortField.getText());

        if (startPort > endPort) {
            showAlert(Alert.AlertType.ERROR, "Invalid Input", "Start port must be less than or equal to end port.");
            return;
        }

        progressBar.setVisible(true);
        outputArea.clear(); // Clear previous output
        String selectedFormat = formatDropdown.getValue();

        Task<Void> scanTask = new Task<>() {
            @Override
            protected Void call() {
                PortScanner.startScan(ipAddress, startPort, endPort);
                return null;
            }
        };

        scanTask.setOnSucceeded(event -> {
            progressBar.setVisible(false);

            switch (selectedFormat.toLowerCase()) {
                case "csv file":
                    PortScanner.generateCSVReport(ipAddress);
                    outputArea.appendText("Results saved to CSV file.\n");
                    break;
                case "json file":
                    PortScanner.generateJSONReport(ipAddress);
                    outputArea.appendText("Results saved to JSON file.\n");
                    break;
                default:
                    PortScanner.printSummary();
                    outputArea.appendText("Results displayed in console.\n");
                    break;
            }
        });

        scanTask.setOnFailed(event -> {
            progressBar.setVisible(false);
            showAlert(Alert.AlertType.ERROR, "Scan Failed", "An error occurred during the scan.");
        });

        new Thread(scanTask).start();

    } catch (NumberFormatException ex) {
        showAlert(Alert.AlertType.ERROR, "Invalid Input", "Please enter valid numbers for port range.");
    }
});

        VBox layout = new VBox(10);
        layout.getChildren().addAll(
            ipAddressField, startPortField, endPortField, formatDropdown, startScanButton,
            viewOpenPortsButton, viewClosedPortsButton, progressBar, outputArea
        );

        Scene scene = new Scene(layout, 400, 500);
        primaryStage.setTitle("Port Scanner");
        primaryStage.setScene(scene);
        primaryStage.show();
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
