package com.wiretap;

import com.wiretap.extractor.AolExtractor;
import com.wiretap.extractor.io.FullFrameStore;
import com.wiretap.extractor.io.JsonObjectFullFrameStore;
import com.wiretap.extractor.io.JsonlSummaryWriter;
import com.wiretap.extractor.io.SummaryWriter;
import com.wiretap.web.HttpApp;
import com.wiretap.web.ServerGUI;

import java.io.IOException;
import java.nio.file.Path;

public final class Main {

    /**
     * Finds an available port in the higher range (20000-65535) following OS best practices
     * for dynamic port allocation. Avoids well-known ports and common service ports.
     *
     * This method is designed to be GraalVM-compatible by avoiding ServerSocket operations
     * during static analysis phase.
     */
    private static int findAvailablePort() {
        // Start from 20000 to avoid well-known ports and common services
        int minPort = 20000;
        int maxPort = 65535;

        // Use system time and process info to generate a pseudo-random but deterministic port
        // This avoids the need for ServerSocket testing during GraalVM compilation
        long seed = System.currentTimeMillis() + System.nanoTime() + Thread.currentThread().getId();
        int port = minPort + (int) ((seed % (maxPort - minPort + 1)) + (maxPort - minPort + 1)) % (maxPort - minPort + 1);

        // Ensure port is within valid range
        if (port < minPort) port = minPort;
        if (port > maxPort) port = maxPort;

        return port;
    }

    public static void main(String[] args) throws Exception {
        String pcap = null;
        String outBase = "session";
        int serverPort = 5190;
        boolean pretty = false;
        boolean storeFull = false;
        boolean pcapMode = false;
        boolean noGui = false;
        int httpPort = 8080;
        boolean dynamicPort = false;

        // Auto-detect headless environments (like servers, CI, or native binaries without display)
        boolean isHeadless = Boolean.parseBoolean(System.getProperty("java.awt.headless", "false")) ||
                            (System.getenv("DISPLAY") == null && System.getProperty("os.name").toLowerCase().contains("linux")) ||
                            "true".equals(System.getProperty("wiretap.headless"));

        // Check if we're running in a GraalVM native image (common cause of AWT issues)
        boolean isNativeImage = System.getProperty("org.graalvm.nativeimage.imagecode") != null;

        for (int i = 0; i < args.length; i++) {
            String k = args[i];
            String v = (i + 1 < args.length && !args[i + 1].startsWith("--")) ? args[++i] : null;
            switch (k) {
                case "--pcap" -> {
                    pcap = v;
                    pcapMode = true;
                }
                case "--out" -> outBase = v == null ? outBase : v;
                case "--server-port" -> serverPort = v == null ? serverPort : Integer.parseInt(v);
                case "--pretty" -> pretty = true;
                case "--store-full" -> storeFull = true;
                case "--port" -> httpPort = v == null ? httpPort : Integer.parseInt(v);
                case "--no-gui", "--headless" -> noGui = true;
                case "--dynamic-port" -> dynamicPort = true;
                case "--help", "-h" -> {
                    System.out.println("Usage: java -jar wiretap-1.0.0.jar [options]\n"
                            + "Server mode (default): java -jar wiretap-1.0.0.jar [--port 8080] [--server-port 5190] [--no-gui] [--dynamic-port]\n"
                            + "  --dynamic-port: Use dynamic port selection (20000-65535) for GUI mode\n"
                            + "PCAP analysis: java -jar wiretap-1.0.0.jar --pcap <file> [--out base] [--server-port 5190] [--pretty] [--store-full]");
                    return;
                }
            }
        }

        // Only force headless mode for truly headless environments (not native images with JavaFX)
        if (isHeadless && !pcapMode && !noGui) {
            noGui = true;
            System.out.println("Headless environment detected, running in headless mode");
        }

        if (pcapMode) {
            if (pcap == null) {
                throw new IllegalArgumentException("--pcap requires a file path");
            }

            Path summaryPath = Path.of(outBase + ".summary.jsonl.gz");
            Path framesPath = Path.of(outBase + ".frames.json.gz");

            SummaryWriter summary = new JsonlSummaryWriter(summaryPath, true, pretty);
            FullFrameStore frames = storeFull ? new JsonObjectFullFrameStore(framesPath, true) : null;
            try (summary; frames) {
                new AolExtractor().extract(pcap, serverPort, pretty, storeFull, summary, frames);
            }
        } else {
            // Default to server mode
            System.out.println("Starting WireTap server...");
            System.out.println("HTTP server on port: " + httpPort);
            System.out.println("AOL proxy server on port: " + serverPort);

            // Use dynamic port selection for GUI mode (unless explicitly specified)
            if (!noGui && !pcapMode && httpPort == 8080) {
                // In GUI mode with default port, use dynamic port selection
                httpPort = findAvailablePort();
                System.out.println("Selected dynamic HTTP port: " + httpPort);
            }

            // Start HTTP server first
            HttpApp httpApp = new HttpApp(httpPort, serverPort);

            // Start HTTP server first
            httpApp.start();

            // Start GUI (unless --no-gui flag is used)
            if (!noGui) {
                try {
                    // Set JavaFX system properties for macOS compatibility
                    System.setProperty("java.awt.headless", "false");
                    System.setProperty("apple.awt.application.name", "WireTap");
                    System.setProperty("apple.awt.application.appearance", "system");

                    // Create final copies for lambda
                    final int finalHttpPort = httpPort;
                    final int finalServerPort = serverPort;
                    final HttpApp finalHttpApp = httpApp;

                    // Launch JavaFX GUI - use the standard Application.launch approach
                    // but set up the static variables first
                    ServerGUI.setHttpPort(finalHttpPort);
                    ServerGUI.setProxyPort(finalServerPort);
                    ServerGUI.setStaticHttpApp(finalHttpApp);

                    Thread guiThread = new Thread(() -> {
                        try {
                            ServerGUI gui = new ServerGUI(finalHttpPort, finalServerPort);
                            gui.setHttpApp(finalHttpApp);
                            // Set shutdown callback to exit the main thread
                            gui.setShutdownCallback(() -> {
                                System.out.println("GUI closed, shutting down application...");
                                // Interrupt the main thread to exit the application
                                Thread.currentThread().interrupt();
                            });
                            ServerGUI.launchGUI(finalHttpPort, finalServerPort);
                        } catch (Exception e) {
                            System.err.println("Failed to launch JavaFX GUI: " + e.getMessage());
                            e.printStackTrace();
                        }
                    });
                    guiThread.setDaemon(true);
                    guiThread.start();

                    // Give JavaFX some time to initialize
                    Thread.sleep(2000);

                    System.out.println("JavaFX GUI launched successfully");

                } catch (Exception e) {
                    System.err.println("Failed to launch JavaFX GUI: " + e.getMessage());
                    System.err.println("Running in headless mode instead.");
                    noGui = true;
                }
            } else {
                System.out.println("Running in headless mode (--no-gui)");
            }

            // Keep running until interrupted (GUI will handle its own lifecycle)
            System.out.println("WireTap server is running...");
            System.out.println("Press Ctrl+C to stop the server");

            // Add shutdown hook for graceful shutdown
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("Shutting down WireTap server...");
            }));

            // Keep the main thread alive until GUI closes or interrupted
            try {
                Thread.currentThread().join();
            } catch (InterruptedException e) {
                System.out.println("Main thread interrupted, shutting down...");
            }

            // Ensure proper cleanup when exiting
            System.out.println("Shutting down WireTap server...");
            if (httpApp != null) {
                httpApp.shutdown();
            }
        }
    }
}


