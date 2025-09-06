package com.wiretap.web;

import com.wiretap.extractor.AolExtractor;
import com.wiretap.extractor.io.SummaryWriter;
import com.wiretap.extractor.io.WriterSummaryWriter;
import com.wiretap.core.JsonUtil;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.List;

public final class HttpApp {
    private final int httpPort;
    private final int aolServerPort;
    private volatile TcpProxyService proxy;
    private final CaptureLibrary captureLibrary;
    private ServerGUI gui;

    public HttpApp(int httpPort, int aolServerPort) {
        this.httpPort = httpPort;
        this.aolServerPort = aolServerPort;
        this.captureLibrary = new CaptureLibrary();
    }

    public void setGUI(ServerGUI gui) {
        this.gui = gui;
    }

    public void start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(httpPort), 0);

        server.createContext("/", new StaticHandler("/public/index.html"));
        server.createContext("/assets/", new StaticDirHandler("/public"));
        server.createContext("/api/tokens", new TokensHandler());
        server.createContext("/api/protocols", new ProtocolsHandler());
        server.createContext("/api/atoms", new AtomsHandler());
        server.createContext("/api/live", new SseLiveHandler());
        server.createContext("/api/proxy/start", new ProxyStartHandler());
        server.createContext("/api/proxy/stop", new ProxyStopHandler());
        server.createContext("/api/proxy/status", new ProxyStatusHandler());
        server.createContext("/api/sessions", new SessionsHandler());
        server.createContext("/api/sessions/", new SessionHandler());
        server.createContext("/api/proxy-config", new ProxyConfigHandler());
        server.createContext("/api/upload", new UploadHandler(aolServerPort));
        // Use a cached thread pool so long-lived SSE connections don't starve other endpoints
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("HTTP server started on http://localhost:" + httpPort);
    }

    private static final class StaticHandler implements HttpHandler {
        private final String resourcePath;

        private StaticHandler(String resourcePath) {
            this.resourcePath = resourcePath;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }
            sendResource(exchange, resourcePath);
        }
    }

    private final class ProxyStartHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { sendStatus(exchange, 405, "Method Not Allowed"); return; }
            String qs = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            java.util.Map<String,String> form = parseForm(qs);
            int listen = parseInt(form.getOrDefault("listen", String.valueOf(aolServerPort)), aolServerPort);
            String host = form.getOrDefault("host", "127.0.0.1");
            int port = parseInt(form.getOrDefault("port", "5190"), 5190);
            synchronized (HttpApp.this) {
                if (proxy != null && proxy.isRunning()) { proxy.close(); }
                proxy = new TcpProxyService(listen, host, port);
                proxy.start();
                if (gui != null) {
                    gui.updateProxyStatus(true, host + ":" + port);
                }
            }
            byte[] b = ("{\"ok\":true,\"listen\":"+listen+",\"dest\":\""+host+":"+port+"\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, b.length);
            exchange.getResponseBody().write(b);
            exchange.close();
        }
    }

    private final class ProxyStopHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { sendStatus(exchange, 405, "Method Not Allowed"); return; }
            // Close proxy asynchronously so this handler returns immediately
            TcpProxyService toClose = null;
            synchronized (HttpApp.this) { if (proxy != null) { toClose = proxy; proxy = null; } }
            if (toClose != null) {
                TcpProxyService finalToClose = toClose;
                new Thread(() -> {
                    try {
                        finalToClose.close();
                        if (gui != null) {
                            gui.updateProxyStatus(false, "Stopped");
                        }
                    } catch (Exception ignored) {}
                }, "aol-proxy-stop").start();
            } else {
                if (gui != null) {
                    gui.updateProxyStatus(false, "Not running");
                }
            }
            byte[] b = "{\"ok\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, b.length);
            exchange.getResponseBody().write(b);
            exchange.close();
        }
    }

    private final class ProxyStatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) { sendStatus(exchange, 405, "Method Not Allowed"); return; }
            synchronized (HttpApp.this) {
                boolean isRunning = proxy != null && proxy.isRunning();
                byte[] b = ("{\"running\":" + isRunning + "}").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(200, b.length);
                exchange.getResponseBody().write(b);
                exchange.close();
            }
        }
    }

    private static java.util.Map<String,String> parseForm(String body) {
        java.util.Map<String,String> m = new java.util.HashMap<>();
        for (String pair : body.split("&")) {
            if (pair.isEmpty()) continue;
            String[] kv = pair.split("=",2);
            String k = java.net.URLDecoder.decode(kv[0], java.nio.charset.StandardCharsets.UTF_8);
            String v = kv.length>1? java.net.URLDecoder.decode(kv[1], java.nio.charset.StandardCharsets.UTF_8) : "";
            m.put(k, v);
        }
        return m;
    }

    private static int parseInt(String s, int def) {
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    // Minimal Server-Sent Events handler for live frames. A companion sniffer can publish lines to this bus.
    private static final class SseLiveHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }

            Headers h = exchange.getResponseHeaders();
            h.set("Content-Type", "text/event-stream; charset=utf-8");
            h.set("Cache-Control", "no-cache");
            h.set("Connection", "keep-alive");
            h.set("Access-Control-Allow-Origin", "*");
            h.set("Access-Control-Allow-Headers", "Cache-Control");

            try {
                exchange.sendResponseHeaders(200, 0);
            } catch (IOException e) {
                System.err.println("[SSE] Failed to send response headers: " + e.getMessage());
                return;
            }

            OutputStream os = exchange.getResponseBody();
            AtomicBoolean open = new AtomicBoolean(true);
            Object writeLock = new Object();

            LiveBus.Subscriber sub = LiveBus.subscribe(line -> {
                if (!open.get()) return;
                synchronized (writeLock) {
                    try {
                        if (open.get()) {
                            byte[] data = ("data: " + line + "\n\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                            os.write(data);
                            os.flush();
                        }
                    } catch (IOException e) {
                        System.err.println("[SSE] Write error, closing connection: " + e.getMessage());
                        open.set(false);
                    }
                }
            });

            try {
                // Keep open until client disconnects
                while (open.get() && !Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            } finally {
                open.set(false);
                LiveBus.unsubscribe(sub);
                synchronized (writeLock) {
                    try {
                        os.close();
                    } catch (IOException ignored) {}
                }
                try {
                    exchange.close();
                } catch (Exception ignored) {}
            }
        }
    }

    private static final class StaticDirHandler implements HttpHandler {
        private final String baseResource;

        private StaticDirHandler(String baseResource) {
            this.baseResource = baseResource;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }
            String path = exchange.getRequestURI().getPath();
            String rel = path.replaceFirst("^/assets", "");
            String resource = baseResource + rel;
            sendResource(exchange, resource);
        }
    }

    private static final class UploadHandler implements HttpHandler {
        private final int aolServerPort;

        private UploadHandler(int aolServerPort) {
            this.aolServerPort = aolServerPort;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }

            // Read entire request body into a temp file (pcap files are typically a few MBs)
            Path tmp = Files.createTempFile("upload", ".pcap");
            try (InputStream in = exchange.getRequestBody(); OutputStream out = Files.newOutputStream(tmp)) {
                in.transferTo(out);
            }

            Headers resp = exchange.getResponseHeaders();
            resp.set("Content-Type", "application/x-ndjson; charset=utf-8");
            resp.set("X-Content-Type-Options", "nosniff");

            // Chunked response for streaming lines
            exchange.sendResponseHeaders(200, 0);

            try (OutputStream os = exchange.getResponseBody();
                 OutputStreamWriter osw = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
                boolean pretty = false;
                SummaryWriter writer = new WriterSummaryWriter(osw, pretty);
                new AolExtractor().extract(tmp.toString(), aolServerPort, false, false, writer, null);
                // SummaryWriter will flush lines; when extractor returns, we're done.
            } catch (Exception e) {
                // Best-effort error body (after headers already sent)
                e.printStackTrace();
            } finally {
                try { Files.deleteIfExists(tmp); } catch (IOException ignored) {}
                exchange.close();
            }
        }
    }

    private static final class TokensHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }
            Path tokens = Path.of("protocol/tokens.json");
            if (!Files.exists(tokens)) {
                sendStatus(exchange, 404, "tokens.json not found");
                return;
            }
            byte[] data = Files.readAllBytes(tokens);
            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, data.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(data);
            } finally {
                exchange.close();
            }
        }
    }

    private static final class ProtocolsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }
            Path file = Path.of("protocol/protocols.json");
            if (!Files.exists(file)) { sendStatus(exchange, 404, "protocols.json not found"); return; }
            byte[] data = Files.readAllBytes(file);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, data.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(data); }
            finally { exchange.close(); }
        }
    }

    private static final class AtomsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }
            Path file = Path.of("protocol/atoms.jsonl");
            if (!Files.exists(file)) { sendStatus(exchange, 404, "atoms.jsonl not found"); return; }
            exchange.getResponseHeaders().set("Content-Type", "application/x-ndjson; charset=utf-8");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream os = exchange.getResponseBody()) {
                Files.copy(file, os);
            } finally {
                exchange.close();
            }
        }
    }



    private static void sendResource(HttpExchange exchange, String resourcePath) throws IOException {
        InputStream is = HttpApp.class.getResourceAsStream(resourcePath);
        if (is == null) {
            sendStatus(exchange, 404, "Not Found");
            return;
        }
        byte[] bytes;
        try (is) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            is.transferTo(bos);
            bytes = bos.toByteArray();
        }
        String contentType = guessContentType(resourcePath);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        addCors(headers);
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        } finally {
            exchange.close();
        }
    }

    private static void addCors(Headers headers) {
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type");
    }

    private static void sendStatus(HttpExchange exchange, int status, String message) throws IOException {
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        addCors(exchange.getResponseHeaders());
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        } finally {
            exchange.close();
        }
    }

    private static String guessContentType(String path) {
        String type = URLConnection.guessContentTypeFromName(path);
        if (type != null) return type;
        if (path.endsWith(".js")) return "text/javascript; charset=utf-8";
        if (path.endsWith(".css")) return "text/css; charset=utf-8";
        if (path.endsWith(".html")) return "text/html; charset=utf-8";
        return "application/octet-stream";
    }
    
    // Session management handlers
    private final class SessionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                List<CaptureLibrary.CaptureSession> sessions = captureLibrary.getAllSessions();
                String json = JsonUtil.toJson(sessions);
                byte[] data = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(200, data.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(data);
                } finally {
                    exchange.close();
                }
            } else if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Create new session
                String body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                java.util.Map<String, Object> request = JsonUtil.fromJson(body);
                
                String name = (String) request.get("name");
                String source = (String) request.get("source");
                Boolean isLive = (Boolean) request.get("isLive");
                
                if (name == null || source == null || isLive == null) {
                    sendStatus(exchange, 400, "name, source, and isLive required");
                    return;
                }
                
                CaptureLibrary.CaptureSession session = captureLibrary.createSession(name, source, isLive);
                String json = JsonUtil.toJson(session);
                byte[] data = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(200, data.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(data);
                } finally {
                    exchange.close();
                }
            } else {
                sendStatus(exchange, 405, "Method Not Allowed");
            }
        }
    }
    
    private final class SessionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            String path = exchange.getRequestURI().getPath();
            String sessionId = path.substring("/api/sessions/".length()).split("/")[0];
            
            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Load session (this already loads frames from file)
                System.out.println("[DEBUG] Loading session: " + sessionId);
                CaptureLibrary.CaptureSession session = captureLibrary.loadSession(sessionId);
                if (session == null) {
                    System.out.println("[DEBUG] Session not found: " + sessionId);
                    sendStatus(exchange, 404, "Session not found");
                    return;
                }
                
                System.out.println("[DEBUG] Session loaded with " + session.frameCount + " frames");

                String json = JsonUtil.toJson(session);
                byte[] data = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                System.out.println("[DEBUG] Sending session response: " + data.length + " bytes");
                
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(200, data.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(data);
                } finally {
                    exchange.close();
                }
            } else if ("POST".equalsIgnoreCase(exchange.getRequestMethod()) && path.endsWith("/save")) {
                // Save session
                // Read frame data from request body
                String body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                if (!body.isEmpty()) {
                    try {
                        // For now, skip frame parsing as it's complex - we'll handle this differently
                        System.err.println("Frame data parsing not yet implemented in JsonUtil");
                    } catch (Exception e) {
                        System.err.println("Failed to parse frame data: " + e.getMessage());
                    }
                }
                
                boolean saved = captureLibrary.saveSession(sessionId);
                if (!saved) {
                    sendStatus(exchange, 404, "Session not found");
                    return;
                }
                
                exchange.sendResponseHeaders(200, 0);
                exchange.close();
            } else if ("DELETE".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Delete session
                boolean deleted = captureLibrary.deleteSession(sessionId);
                if (!deleted) {
                    sendStatus(exchange, 404, "Session not found");
                    return;
                }
                
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
            } else {
                sendStatus(exchange, 405, "Method Not Allowed");
            }
        }
    }
    
    private final class ProxyConfigHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            
            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Load proxy configuration
                try {
                    Path configPath = Path.of("captures/proxy-config.json");
                    if (Files.exists(configPath)) {
                        byte[] data = Files.readAllBytes(configPath);
                        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                        exchange.sendResponseHeaders(200, data.length);
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(data);
                        } finally {
                            exchange.close();
                        }
                    } else {
                        // Return default configuration
                        java.util.Map<String, Object> defaultConfig = new java.util.HashMap<>();
                        defaultConfig.put("listen", aolServerPort);
                        defaultConfig.put("host", "127.0.0.1");
                        defaultConfig.put("port", 5190);

                        String json = JsonUtil.toJson(defaultConfig);
                        byte[] data = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        
                        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                        exchange.sendResponseHeaders(200, data.length);
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(data);
                        } finally {
                            exchange.close();
                        }
                    }
                } catch (Exception e) {
                    sendStatus(exchange, 500, "Failed to load proxy configuration: " + e.getMessage());
                }
            } else if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Save proxy configuration
                try {
                    String body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    java.util.Map<String, Object> config = JsonUtil.fromJson(body);
                    
                    // Ensure captures directory exists
                    Path capturesDir = Path.of("captures");
                    if (!Files.exists(capturesDir)) {
                        Files.createDirectories(capturesDir);
                    }
                    
                    Path configPath = capturesDir.resolve("proxy-config.json");
                    try (java.io.BufferedWriter writer = Files.newBufferedWriter(configPath)) {
                        writer.write(JsonUtil.toJsonPretty(config));
                    }
                    
                    exchange.sendResponseHeaders(200, 0);
                    exchange.close();
                } catch (Exception e) {
                    sendStatus(exchange, 500, "Failed to save proxy configuration: " + e.getMessage());
                }
            } else {
                sendStatus(exchange, 405, "Method Not Allowed");
            }
        }
    }

}


