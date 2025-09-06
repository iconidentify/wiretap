package com.wiretap.web;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Stage;
import javafx.scene.effect.DropShadow;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Modern JavaFX GUI window for WireTap server status and proxy monitoring
 * Features Material Design-inspired UI with Gluon tooling compatibility
 */
public class ServerGUI extends Application {
    private static int httpPort;
    private static int proxyPort;

    public static void setHttpPort(int port) {
        httpPort = port;
    }

    public static void setProxyPort(int port) {
        proxyPort = port;
    }

    private static HttpApp staticHttpApp;

    public static void setStaticHttpApp(HttpApp app) {
        staticHttpApp = app;
    }

    private Stage primaryStage;
    private final CountDownLatch closeLatch;
    private final AtomicBoolean isRunning;
    private HttpApp httpApp;

    // UI Components
    private Circle statusIndicator;
    private Circle proxyStatusLed;
    private TextField proxyListenField;
    private TextField proxyHostField;
    private TextField proxyPortField;
    private Button startProxyButton;
    private Button stopProxyButton;

    // Status display components for dynamic updates
    private Label framesValueLabel;
    private Timer updateTimer;
    private VBox statusCardContainer;


    public ServerGUI() {
        // Default constructor required by JavaFX Application
        this.closeLatch = new CountDownLatch(1);
        this.isRunning = new AtomicBoolean(true);
    }

    public ServerGUI(int httpPort, int proxyPort) {
        ServerGUI.httpPort = httpPort;
        ServerGUI.proxyPort = proxyPort;
        this.closeLatch = new CountDownLatch(1);
        this.isRunning = new AtomicBoolean(true);
    }

    public static void launchGUI(int httpPort, int proxyPort) {
        ServerGUI.httpPort = httpPort;
        ServerGUI.proxyPort = proxyPort;
        Application.launch(ServerGUI.class);
    }

    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        this.primaryStage.setTitle("WireTap - AOL Protocol Analyzer");
        this.primaryStage.setScene(createScene());
        this.primaryStage.setOnCloseRequest(e -> shutdown());

        // Set the HttpApp reference from the static variable
        this.httpApp = staticHttpApp;

        // Start the update timer for dynamic status updates
        startUpdateTimer();

        this.primaryStage.show();
    }

    public void setHttpApp(HttpApp httpApp) {
        this.httpApp = httpApp;
    }

    private Scene createScene() {
        // Modern Material Design color scheme
        Color primaryColor = Color.web("#1976D2");        // Material Blue
        Color successColor = Color.web("#4CAF50");        // Material Green
        Color backgroundColor = Color.web("#FAFAFA");     // Light gray background
        Color cardColor = Color.web("#F5F5F5");           // Card background

        // Root layout
        BorderPane root = new BorderPane();
        root.setStyle("-fx-background-color: " + toHex(backgroundColor) + ";");

        // Header - Modern Material Design style
        HBox header = createHeader(primaryColor, successColor);
        root.setTop(header);

        // Main content
        VBox content = new VBox(20);
        content.setPadding(new Insets(24));
        content.setStyle("-fx-background-color: " + toHex(backgroundColor) + ";");

        // Server status card (refreshable container)
        statusCardContainer = new VBox();
        statusCardContainer.getChildren().add(createStatusCard(primaryColor));
        content.getChildren().add(statusCardContainer);

        // Proxy control card
        VBox proxyCard = createProxyControlCard(primaryColor, cardColor);
        content.getChildren().add(proxyCard);

        ScrollPane scrollPane = new ScrollPane(content);
        scrollPane.setFitToWidth(true);
        scrollPane.setStyle("-fx-background-color: " + toHex(backgroundColor) + ";");
        root.setCenter(scrollPane);

        // Footer - Modern action button
        HBox footer = createFooter(primaryColor);
        root.setBottom(footer);

        return new Scene(root, 500, 600);
    }

    private HBox createHeader(Color primaryColor, Color successColor) {
        HBox header = new HBox();
        header.setPadding(new Insets(16));
        header.setStyle("-fx-background-color: " + toHex(primaryColor) + ";");
        header.setAlignment(Pos.CENTER_LEFT);

        // Add subtle shadow effect
        DropShadow shadow = new DropShadow();
        shadow.setColor(Color.BLACK);
        shadow.setRadius(5);
        shadow.setOffsetX(0);
        shadow.setOffsetY(2);
        header.setEffect(shadow);

        Label titleLabel = new Label("WireTap");
        titleLabel.setFont(Font.font("System", FontWeight.BOLD, 20));
        titleLabel.setTextFill(Color.WHITE);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        statusIndicator = new Circle(6);
        statusIndicator.setFill(successColor);

        HBox statusBox = new HBox(8);
        statusBox.setAlignment(Pos.CENTER);
        statusBox.getChildren().addAll(new Label("Status:"), statusIndicator);

        header.getChildren().addAll(titleLabel, spacer, statusBox);

        return header;
    }

    private VBox createStatusCard(Color primaryColor) {
        VBox card = new VBox(12);
        card.setPadding(new Insets(20));
        card.setStyle("-fx-background-color: white; -fx-background-radius: 8; -fx-effect: dropshadow(three-pass-box, rgba(0,0,0,0.1), 4, 0, 0, 2);");

        Label cardTitle = new Label("Server Status");
        cardTitle.setFont(Font.font("System", FontWeight.BOLD, 16));
        cardTitle.setTextFill(Color.web("#424242"));

        // HTTP Server Status - use the actual port from the HTTP app
        int actualHttpPort = httpApp != null ? httpApp.getHttpPort() : httpPort;
        HBox httpStatus = createStatusRow("HTTP Server", "Port " + actualHttpPort, Color.web("#4CAF50"));

        // Proxy Server Status - use the actual listening port from the active proxy
        int actualListenPort = httpApp != null ? httpApp.getCurrentProxyListenPort() : -1;
        String proxyStatusText = actualListenPort > 0 ? "Port " + actualListenPort : "Not Running";
        HBox proxyStatus = createStatusRow("AOL Proxy", proxyStatusText, Color.web("#FF9800"));

        // AOL Frames Counter
        HBox framesStatus = createStatusRow("Total AOL Frames", "0", Color.web("#2196F3"), true);

        card.getChildren().addAll(cardTitle, new Separator(), httpStatus, proxyStatus, framesStatus);

        return card;
    }

    private HBox createStatusRow(String title, String value, Color indicatorColor) {
        return createStatusRow(title, value, indicatorColor, false);
    }

    private HBox createStatusRow(String title, String value, Color indicatorColor, boolean isFramesCounter) {
        HBox row = new HBox(12);
        row.setAlignment(Pos.CENTER_LEFT);

        Circle indicator = new Circle(4);
        indicator.setFill(indicatorColor);

        Label titleLabel = new Label(title);
        titleLabel.setFont(Font.font("System", FontWeight.MEDIUM, 14));

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Label valueLabel = new Label(value);
        valueLabel.setFont(Font.font("System", 12));
        valueLabel.setTextFill(Color.web("#757575"));

        // Store reference to frames counter label
        if (isFramesCounter) {
            framesValueLabel = valueLabel;
        }

        row.getChildren().addAll(indicator, titleLabel, spacer, valueLabel);

        return row;
    }

    private VBox createProxyControlCard(Color primaryColor, Color cardColor) {
        VBox card = new VBox(16);
        card.setPadding(new Insets(20));
        card.setStyle("-fx-background-color: white; -fx-background-radius: 8; -fx-effect: dropshadow(three-pass-box, rgba(0,0,0,0.1), 4, 0, 0, 2);");

        Label cardTitle = new Label("AOL Proxy Control");
        cardTitle.setFont(Font.font("System", FontWeight.BOLD, 16));
        cardTitle.setTextFill(Color.web("#424242"));

        // Destination configuration
        GridPane destGrid = new GridPane();
        destGrid.setHgap(12);
        destGrid.setVgap(8);

        Label destLabel = new Label("Destination:");
        destLabel.setFont(Font.font("System", FontWeight.MEDIUM, 14));

        proxyHostField = new TextField(loadPreference("proxy.host", "127.0.0.1"));
        proxyHostField.setPromptText("Host");
        proxyHostField.setPrefWidth(120);

        Label colonLabel = new Label(":");
        colonLabel.setFont(Font.font("System", FontWeight.BOLD, 14));

        proxyPortField = new TextField(loadPreference("proxy.destination.port", "5190"));
        proxyPortField.setPromptText("Port");
        proxyPortField.setPrefWidth(80);

        destGrid.add(destLabel, 0, 0);
        destGrid.add(proxyHostField, 1, 0);
        destGrid.add(colonLabel, 2, 0);
        destGrid.add(proxyPortField, 3, 0);

        // Listen configuration
        GridPane listenGrid = new GridPane();
        listenGrid.setHgap(12);
        listenGrid.setVgap(8);

        Label listenLabel = new Label("Listen Port:");
        listenLabel.setFont(Font.font("System", FontWeight.MEDIUM, 14));

        proxyListenField = new TextField(loadPreference("proxy.listen.port", "5132"));
        proxyListenField.setPromptText("Port");
        proxyListenField.setPrefWidth(120);

        listenGrid.add(listenLabel, 0, 0);
        listenGrid.add(proxyListenField, 1, 0);

        // Control buttons
        HBox buttonBox = createControlButtons(primaryColor);

        card.getChildren().addAll(cardTitle, new Separator(), destGrid, listenGrid, buttonBox);

        return card;
    }

    private HBox createControlButtons(Color primaryColor) {
        HBox buttonBox = new HBox(12);
        buttonBox.setAlignment(Pos.CENTER_LEFT);

        // Status LED
        proxyStatusLed = new Circle(6);
        proxyStatusLed.setFill(Color.web("#9E9E9E")); // Gray when stopped

        // Start button
        startProxyButton = new Button("▶ Start Proxy");
        startProxyButton.setStyle("-fx-background-color: " + toHex(primaryColor) + "; -fx-text-fill: white; -fx-background-radius: 4;");
        startProxyButton.setFont(Font.font("System", FontWeight.MEDIUM, 13));
        startProxyButton.setPrefWidth(120);
        startProxyButton.setOnAction(e -> startProxy());

        // Stop button
        stopProxyButton = new Button("⏹ Stop Proxy");
        stopProxyButton.setStyle("-fx-background-color: #757575; -fx-text-fill: white; -fx-background-radius: 4;");
        stopProxyButton.setFont(Font.font("System", FontWeight.MEDIUM, 13));
        stopProxyButton.setPrefWidth(120);
        stopProxyButton.setDisable(true);
        stopProxyButton.setOnAction(e -> stopProxy());

        buttonBox.getChildren().addAll(proxyStatusLed, startProxyButton, stopProxyButton);

        return buttonBox;
    }


    private HBox createFooter(Color primaryColor) {
        HBox footer = new HBox();
        footer.setPadding(new Insets(16));
        footer.setStyle("-fx-background-color: #E0E0E0;");
        footer.setAlignment(Pos.CENTER);

        Button openBrowserButton = new Button("🌐 Open Web Interface");
        openBrowserButton.setStyle("-fx-background-color: " + toHex(primaryColor) + "; -fx-text-fill: white; -fx-background-radius: 6;");
        openBrowserButton.setFont(Font.font("System", FontWeight.BOLD, 14));
        openBrowserButton.setPrefWidth(200);
        openBrowserButton.setPrefHeight(40);
        openBrowserButton.setOnAction(e -> openWebInterface());

        footer.getChildren().add(openBrowserButton);

        return footer;
    }

    private void openWebInterface() {
        try {
            // Use JavaFX HostServices instead of AWT Desktop for native image compatibility
            int actualHttpPort = httpApp != null ? httpApp.getHttpPort() : httpPort;
            String url = "http://localhost:" + actualHttpPort;
            // Use the inherited getHostServices() method from Application
            if (getHostServices() != null) {
                getHostServices().showDocument(url);
            } else {
                // Fallback: try to use ProcessBuilder to open URL
                String os = System.getProperty("os.name").toLowerCase();
                ProcessBuilder pb;

                if (os.contains("mac")) {
                    pb = new ProcessBuilder("open", url);
                } else if (os.contains("win")) {
                    pb = new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url);
                } else {
                    pb = new ProcessBuilder("xdg-open", url);
                }

                pb.start();
            }
        } catch (Exception ex) {
            showAlert(Alert.AlertType.ERROR, "Error", "Could not open browser: " + ex.getMessage());
        }
    }

    private void showAlert(Alert.AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private String toHex(Color color) {
        return String.format("#%02X%02X%02X",
            (int)(color.getRed() * 255),
            (int)(color.getGreen() * 255),
            (int)(color.getBlue() * 255));
    }

    // Preference persistence methods
    private String loadPreference(String key, String defaultValue) {
        try {
            Path configPath = getConfigFilePath();
            if (Files.exists(configPath)) {
                Properties props = new Properties();
                try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
                    props.load(fis);
                    return props.getProperty(key, defaultValue);
                }
            }
        } catch (Exception e) {
            // Silently ignore preference loading errors
        }
        return defaultValue;
    }

    private void savePreference(String key, String value) {
        try {
            Path configPath = getConfigFilePath();
            Files.createDirectories(configPath.getParent());

            Properties props = new Properties();

            // Load existing properties if file exists
            if (Files.exists(configPath)) {
                try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
                    props.load(fis);
                }
            }

            // Set the new property
            props.setProperty(key, value);

            // Save back to file
            try (FileOutputStream fos = new FileOutputStream(configPath.toFile())) {
                props.store(fos, "WireTap Preferences");
            }
        } catch (Exception e) {
            // Silently ignore preference saving errors
        }
    }

    private Path getConfigFilePath() {
        String userHome = System.getProperty("user.home");
        return Paths.get(userHome, ".wiretap", "preferences.properties");
    }

    // Dynamic status update methods
    private void startUpdateTimer() {
        updateTimer = new Timer(true); // Daemon timer
        updateTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                updateFramesCounter();
            }
        }, 1000, 1000); // Update every second
    }

    private void updateFramesCounter() {
        if (framesValueLabel != null && httpApp != null) {
            Platform.runLater(() -> {
                try {
                    long totalFrames = httpApp.getTotalFramesProcessed();
                    framesValueLabel.setText(formatNumberWithCommas(totalFrames));
                } catch (Exception e) {
                    // Silently ignore update errors
                    framesValueLabel.setText("0");
                }
            });
        }
    }

    private String formatNumberWithCommas(long number) {
        return java.text.NumberFormat.getInstance().format(number);
    }

    private void stopUpdateTimer() {
        if (updateTimer != null) {
            updateTimer.cancel();
            updateTimer = null;
        }
    }

    private void refreshStatusCard() {
        if (statusCardContainer != null) {
            Platform.runLater(() -> {
                statusCardContainer.getChildren().clear();
                statusCardContainer.getChildren().add(createStatusCard(Color.web("#2196F3")));
            });
        }
    }


    public void waitForClose() throws InterruptedException {
        closeLatch.await();
    }

    public void shutdown() {
        // Stop the update timer
        stopUpdateTimer();

        Platform.runLater(() -> {
            isRunning.set(false);
            if (primaryStage != null) {
                primaryStage.hide();
            }
            closeLatch.countDown();
            Platform.exit();
        });
    }

    private void startProxy() {
        String listenPortText = proxyListenField.getText().trim();
        String host = proxyHostField.getText().trim();
        String portText = proxyPortField.getText().trim();

        if (listenPortText.isEmpty() || host.isEmpty() || portText.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "Invalid Input", "Please enter listen port, host and port.");
            return;
        }

        try {
            int listenPort = Integer.parseInt(listenPortText);
            int port = Integer.parseInt(portText);
            if (httpApp != null) {
                boolean success = httpApp.startProxy(listenPort, host, port);
                if (success) {
                    // Save preferences when proxy starts successfully
                    savePreference("proxy.listen.port", listenPortText);
                    savePreference("proxy.host", host);
                    savePreference("proxy.destination.port", portText);
                    updateProxyUI(true, host + ":" + port);
                } else {
                    showAlert(Alert.AlertType.ERROR, "Proxy Error", "Failed to start proxy. Please check the configuration.");
                }
            }
        } catch (NumberFormatException e) {
            showAlert(Alert.AlertType.ERROR, "Invalid Input", "Ports must be valid numbers.");
        }
    }

    private void stopProxy() {
        if (httpApp != null) {
            boolean success = httpApp.stopProxy();
            if (success) {
                updateProxyUI(false, null);
            } else {
                showAlert(Alert.AlertType.ERROR, "Proxy Error", "Failed to stop proxy.");
            }
        }
    }

    public void updateProxyUI(boolean isRunning, String destination) {
        Platform.runLater(() -> {
            startProxyButton.setDisable(isRunning);
            stopProxyButton.setDisable(!isRunning);

            // LED indicator for proxy status
            if (proxyStatusLed != null) {
                if (isRunning) {
                    proxyStatusLed.setFill(Color.web("#4CAF50")); // Green when running
                } else {
                    proxyStatusLed.setFill(Color.web("#9E9E9E")); // Gray when stopped
                }
            }

            // Update main status indicator
            if (statusIndicator != null) {
            if (isRunning && destination != null && !destination.isEmpty()) {
                    statusIndicator.setFill(Color.web("#4CAF50")); // Green
            } else if (isRunning) {
                    statusIndicator.setFill(Color.web("#FF9800")); // Orange
            } else {
                    statusIndicator.setFill(Color.web("#9E9E9E")); // Gray
                }
            }

            // Refresh the status card to show updated proxy port
            refreshStatusCard();
        });
    }


    // Public methods for HttpApp to call
    public void updateProxyStatus(boolean isRunning, String destination) {
        updateProxyUI(isRunning, destination);
    }
}
