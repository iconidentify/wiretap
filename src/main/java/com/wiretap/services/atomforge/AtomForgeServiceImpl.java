package com.wiretap.services.atomforge;

import com.wiretap.core.JsonUtil;
import com.wiretap.core.WireTapLog;
import com.wiretap.extractor.FrameSummary;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Implementation of AtomForgeService using Java 11+ HttpClient.
 */
public final class AtomForgeServiceImpl implements AtomForgeService {

    private final HttpClient httpClient;
    private final ExecutorService executor;
    private final AtomicReference<AtomForgeConfig> configRef;
    private final AtomicReference<HealthCheckResult> lastHealthCheck;

    public AtomForgeServiceImpl() {
        this.executor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "atomforge-worker");
            t.setDaemon(true);
            return t;
        });
        this.httpClient = HttpClient.newBuilder()
            .executor(executor)
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        this.configRef = new AtomicReference<>(AtomForgeConfig.builder().build());
        this.lastHealthCheck = new AtomicReference<>(HealthCheckResult.failure("Not checked yet"));
    }

    @Override
    public void configure(AtomForgeConfig config) {
        configRef.set(config);
        WireTapLog.debug("AtomForge configured: " + config);

        // Don't trigger health check here - let the periodic timer handle it
        // This prevents disconnect/reconnect cycles during proxy start/stop
        if (!config.isEnabled()) {
            lastHealthCheck.set(HealthCheckResult.failure("Disabled"));
        }
    }

    @Override
    public AtomForgeConfig getConfiguration() {
        return configRef.get();
    }

    @Override
    public CompletableFuture<HealthCheckResult> checkHealth() {
        AtomForgeConfig config = configRef.get();

        if (!config.isEnabled()) {
            HealthCheckResult result = HealthCheckResult.failure("AtomForge is disabled");
            lastHealthCheck.set(result);
            return CompletableFuture.completedFuture(result);
        }

        try {
            String healthUrl = config.getUrl() + "/health";
            WireTapLog.debug("AtomForge: Sending async HTTP GET to: " + healthUrl);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(healthUrl))
                .timeout(Duration.ofSeconds(config.getTimeoutSeconds()))
                .GET()
                .build();

            // Use async HTTP call that returns a proper CompletableFuture
            return httpClient.sendAsync(
                request,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            ).thenApply(response -> {
                WireTapLog.debug("AtomForge: Received HTTP response: status=" + response.statusCode());
                WireTapLog.debug("AtomForge: Response body: " + response.body());

                HealthCheckResult result;
                if (response.statusCode() == 200) {
                    // Simple manual parsing to avoid JsonUtil array handling issues
                    String body = response.body();
                    String version = extractJsonValue(body, "\"version\"");
                    String daemonStatus = "unknown";

                    // Find daemon.health.status
                    int daemonStart = body.indexOf("\"daemon\":");
                    if (daemonStart > 0) {
                        int healthStart = body.indexOf("\"health\":", daemonStart);
                        if (healthStart > 0) {
                            int statusStart = body.indexOf("\"status\":", healthStart);
                            if (statusStart > 0) {
                                daemonStatus = extractJsonValue(body.substring(statusStart), "\"status\"");
                            }
                        }
                    }

                    result = HealthCheckResult.success(version, daemonStatus);
                    WireTapLog.debug("AtomForge: Health check SUCCESS: version=" + version + ", daemonStatus=" + daemonStatus);
                } else {
                    result = HealthCheckResult.failure(
                        "HTTP " + response.statusCode() + ": " + response.body()
                    );
                    WireTapLog.warn("AtomForge: Health check FAILED - non-200 status: " + result);
                }

                lastHealthCheck.set(result);
                return result;
            }).exceptionally(e -> {
                WireTapLog.error("AtomForge: Health check FAILED - exception thrown", e);
                String errorMessage = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                HealthCheckResult result = HealthCheckResult.failure(errorMessage);
                lastHealthCheck.set(result);
                return result;
            });
        } catch (Exception e) {
            // Handle synchronous exceptions (e.g., invalid URL)
            WireTapLog.error("AtomForge: Health check FAILED - setup exception", e);
            HealthCheckResult result = HealthCheckResult.failure(e.getMessage());
            lastHealthCheck.set(result);
            return CompletableFuture.completedFuture(result);
        }
    }

    @Override
    public String decompileSingleFrame(FrameSummary frame) {
        AtomForgeConfig config = configRef.get();

        if (!config.isEnabled()) {
            return "// AtomForge is disabled";
        }

        if (!isAvailable()) {
            return "// AtomForge is not available";
        }

        if (frame == null || frame.fullHex == null) {
            return "// No frame data available";
        }

        try {
            // Build JSONL with single frame
            String jsonlContent = frame.toJson(false) + "\n";

            // Create multipart boundary
            String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();

            // Build multipart body
            StringBuilder bodyBuilder = new StringBuilder();
            bodyBuilder.append("--").append(boundary).append("\r\n");
            bodyBuilder.append("Content-Disposition: form-data; name=\"file\"; filename=\"frame.jsonl\"\r\n");
            bodyBuilder.append("Content-Type: application/x-ndjson\r\n\r\n");
            bodyBuilder.append(jsonlContent);
            bodyBuilder.append("\r\n--").append(boundary).append("--\r\n");

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getUrl() + "/decompile-jsonl"))
                .timeout(Duration.ofSeconds(config.getTimeoutSeconds()))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofString(bodyBuilder.toString(), StandardCharsets.UTF_8))
                .build();

            HttpResponse<String> response = httpClient.send(
                request,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );

            if (response.statusCode() == 200) {
                // Parse response to get decompiled source
                WireTapLog.debug("AtomForge: Response body: " + response.body());
                String decompiledCode = extractJsonValue(response.body(), "\"source\"");
                WireTapLog.debug("AtomForge: Extracted source: " + (decompiledCode != null ? decompiledCode.substring(0, Math.min(50, decompiledCode.length())) + "..." : "null"));
                return decompiledCode != null && !decompiledCode.equals("unknown")
                    ? decompiledCode
                    : "// Decompilation returned no code";
            } else {
                return "// HTTP " + response.statusCode() + ": " + response.body();
            }
        } catch (Exception e) {
            WireTapLog.error("Decompilation failed for single frame", e);
            return "// Error: " + e.getMessage();
        }
    }

    @Override
    public String decompileMultipleFrames(List<FrameSummary> frames) {
        AtomForgeConfig config = configRef.get();

        if (!config.isEnabled()) {
            return "// AtomForge is disabled";
        }

        if (!isAvailable()) {
            return "// AtomForge is not available";
        }

        if (frames == null || frames.isEmpty()) {
            return "// No frames provided";
        }

        try {
            // Build JSONL with all frames
            StringBuilder jsonlContent = new StringBuilder();
            for (FrameSummary frame : frames) {
                if (frame != null && frame.fullHex != null) {
                    jsonlContent.append(frame.toJson(false)).append("\n");
                }
            }

            if (jsonlContent.length() == 0) {
                return "// No valid frame data available";
            }

            // Create multipart boundary
            String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();

            // Build multipart body
            StringBuilder bodyBuilder = new StringBuilder();
            bodyBuilder.append("--").append(boundary).append("\r\n");
            bodyBuilder.append("Content-Disposition: form-data; name=\"file\"; filename=\"stream.jsonl\"\r\n");
            bodyBuilder.append("Content-Type: application/x-ndjson\r\n\r\n");
            bodyBuilder.append(jsonlContent);
            bodyBuilder.append("\r\n--").append(boundary).append("--\r\n");

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getUrl() + "/decompile-jsonl"))
                .timeout(Duration.ofSeconds(config.getTimeoutSeconds()))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofString(bodyBuilder.toString(), StandardCharsets.UTF_8))
                .build();

            WireTapLog.debug("AtomForge: Decompiling " + frames.size() + " frames");
            HttpResponse<String> response = httpClient.send(
                request,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );

            if (response.statusCode() == 200) {
                // Parse response to get decompiled source
                WireTapLog.debug("AtomForge: Response body: " + response.body());
                String decompiledCode = extractJsonValue(response.body(), "\"source\"");
                WireTapLog.debug("AtomForge: Extracted source: " + (decompiledCode != null ? decompiledCode.substring(0, Math.min(50, decompiledCode.length())) + "..." : "null"));
                return decompiledCode != null && !decompiledCode.equals("unknown")
                    ? decompiledCode
                    : "// Decompilation returned no code";
            } else {
                return "// HTTP " + response.statusCode() + ": " + response.body();
            }
        } catch (Exception e) {
            WireTapLog.error("Decompilation failed for multiple frames", e);
            return "// Error: " + e.getMessage();
        }
    }

    @Override
    public boolean isAvailable() {
        HealthCheckResult result = lastHealthCheck.get();
        return result != null && result.isAvailable();
    }

    @Override
    public void shutdown() {
        WireTapLog.debug("Shutting down AtomForge service");
        executor.shutdown();
    }

    /**
     * Unescapes JSON string escape sequences.
     * Converts \" to ", \\ to \, \n to newline, etc.
     */
    private static String unescapeJson(String s) {
        if (s == null || s.isEmpty()) return s;

        StringBuilder result = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case '"':
                        result.append('"');
                        i += 2;
                        break;
                    case '\\':
                        result.append('\\');
                        i += 2;
                        break;
                    case 'n':
                        result.append('\n');
                        i += 2;
                        break;
                    case 'r':
                        result.append('\r');
                        i += 2;
                        break;
                    case 't':
                        result.append('\t');
                        i += 2;
                        break;
                    case 'u':
                        // Unicode escape sequence
                        if (i + 5 < s.length()) {
                            try {
                                String hex = s.substring(i + 2, i + 6);
                                int codePoint = Integer.parseInt(hex, 16);
                                result.append((char) codePoint);
                                i += 6;
                            } catch (NumberFormatException e) {
                                // Invalid unicode escape - keep as-is
                                result.append(c);
                                i++;
                            }
                        } else {
                            // Incomplete unicode escape
                            result.append(c);
                            i++;
                        }
                        break;
                    default:
                        // Unknown escape sequence - keep the backslash
                        result.append(c);
                        i++;
                        break;
                }
            } else {
                result.append(c);
                i++;
            }
        }
        return result.toString();
    }

    /**
     * Simple JSON value extractor for health check response.
     * Extracts the value after a given key (e.g., "version":"2.0.0" returns "2.0.0")
     */
    private static String extractJsonValue(String json, String key) {
        int keyIndex = json.indexOf(key);
        if (keyIndex < 0) return "unknown";

        int colonIndex = json.indexOf(":", keyIndex);
        if (colonIndex < 0) return "unknown";

        int valueStart = colonIndex + 1;
        while (valueStart < json.length() && (json.charAt(valueStart) == ' ' || json.charAt(valueStart) == '\t')) {
            valueStart++;
        }

        if (valueStart >= json.length()) return "unknown";

        char firstChar = json.charAt(valueStart);
        if (firstChar == '"') {
            // String value - need to handle escaped quotes
            int i = valueStart + 1;
            while (i < json.length()) {
                char c = json.charAt(i);
                if (c == '\\') {
                    // Skip the next character (it's escaped)
                    i += 2;
                } else if (c == '"') {
                    // Found unescaped closing quote - extract and unescape
                    String rawValue = json.substring(valueStart + 1, i);
                    return unescapeJson(rawValue);
                } else {
                    i++;
                }
            }
            return "unknown"; // No closing quote found
        } else {
            // Non-string value (number, boolean, etc.)
            int valueEnd = valueStart;
            while (valueEnd < json.length()) {
                char c = json.charAt(valueEnd);
                if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\n' || c == '\r') {
                    break;
                }
                valueEnd++;
            }
            return json.substring(valueStart, valueEnd);
        }
    }
}
