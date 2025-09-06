package com.wiretap;

import com.wiretap.extractor.AolExtractor;
import com.wiretap.extractor.io.FullFrameStore;
import com.wiretap.extractor.io.JsonObjectFullFrameStore;
import com.wiretap.extractor.io.JsonlSummaryWriter;
import com.wiretap.extractor.io.SummaryWriter;
import com.wiretap.web.HttpApp;
import com.wiretap.web.ServerGUI;

import java.nio.file.Path;

public final class Main {
    public static void main(String[] args) throws Exception {
        String pcap = null;
        String outBase = "session";
        int serverPort = 5190;
        boolean pretty = false;
        boolean storeFull = false;
        boolean pcapMode = false;
        boolean noGui = false;
        int httpPort = 8080;

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
                case "--help", "-h" -> {
                    System.out.println("Usage: java -jar wiretap-1.0.0.jar [options]\n"
                            + "Server mode (default): java -jar wiretap-1.0.0.jar [--port 8080] [--server-port 5190] [--no-gui]\n"
                            + "PCAP analysis: java -jar wiretap-1.0.0.jar --pcap <file> [--out base] [--server-port 5190] [--pretty] [--store-full]");
                    return;
                }
            }
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

            // Start HTTP server first
            HttpApp httpApp = new HttpApp(httpPort, serverPort);

            // Start GUI (unless --no-gui flag is used)
            ServerGUI gui = null;
            if (!noGui) {
                gui = new ServerGUI(httpPort, serverPort);
                gui.setHttpApp(httpApp);
                httpApp.setGUI(gui);
                gui.show();
            } else {
                System.out.println("Running in headless mode (--no-gui)");
            }

            // Start HTTP server
            httpApp.start();

            // Keep running until GUI is closed (or indefinitely in headless mode)
            if (gui != null) {
                gui.waitForClose();
                System.out.println("Shutting down WireTap server...");
                System.exit(0);
            } else {
                // In headless mode, keep running indefinitely
                System.out.println("Press Ctrl+C to stop the server");
                // Add shutdown hook for graceful shutdown
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("Shutting down WireTap server...");
                }));
                // Keep the main thread alive
                Thread.currentThread().join();
            }
        }
    }
}


