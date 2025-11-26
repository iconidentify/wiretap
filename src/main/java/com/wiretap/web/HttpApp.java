package com.wiretap.web;

import com.wiretap.core.WireTapLog;
import com.wiretap.extractor.AolExtractor;
import com.wiretap.extractor.FrameSummary;
import com.wiretap.extractor.io.SummaryWriter;
import com.wiretap.extractor.io.WriterSummaryWriter;
import com.wiretap.core.JsonUtil;
import com.wiretap.services.atomforge.AtomForgeService;
import com.wiretap.services.atomforge.HealthCheckResult;
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
import java.util.ArrayList;
import java.util.List;

import com.wiretap.session.SessionInfo;
import com.wiretap.session.SessionManager;

public final class HttpApp {
    private final int httpPort;
    private final int aolServerPort;
    private volatile TcpProxyService proxy;
    private ServerGUI gui;
    private AtomForgeService atomForgeService;

    // Session management - disk-based persistence for unlimited frames
    private SessionManager sessionManager;

    // Static reference to current instance for LiveBus
    private static HttpApp currentInstance;

    public HttpApp(int httpPort, int aolServerPort) {
        this.httpPort = httpPort;
        this.aolServerPort = aolServerPort;
    }

    public void setGUI(ServerGUI gui) {
        this.gui = gui;
    }

    public void setAtomForgeService(AtomForgeService service) {
        this.atomForgeService = service;
    }

    // Session frame management methods
    public void addSessionFrame(String frame) {
        if (sessionManager != null) {
            sessionManager.addFrame(frame);
        }
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    public long getTotalFramesProcessed() {
        return sessionManager != null ? sessionManager.getCurrentFrameCount() : 0;
    }

    public SessionInfo getCurrentSessionInfo() {
        return sessionManager != null ? sessionManager.getCurrentSession() : null;
    }

    public int getCurrentProxyListenPort() {
        synchronized (HttpApp.this) {
            return proxy != null ? proxy.getListenPort() : -1;
        }
    }

    public int getHttpPort() {
        return httpPort;
    }

    public static HttpApp getCurrentInstance() {
        return currentInstance;
    }

    public boolean startProxy(String host, int port) {
        return startProxy(aolServerPort, host, port);
    }


    public boolean startProxy(int listenPort, String host, int port) {
        try {
            synchronized (HttpApp.this) {
                if (proxy != null && proxy.isRunning()) {
                    proxy.close();
                }
                proxy = new TcpProxyService(listenPort, host, port);
                proxy.start();

                // Start a new session for this proxy run
                if (sessionManager != null) {
                    try {
                        sessionManager.startSession();
                        WireTapLog.info("New capture session started");
                    } catch (IOException e) {
                        WireTapLog.error("Failed to start session", e);
                    }
                }

                if (gui != null) {
                    gui.updateProxyStatus(true, host + ":" + port);
                }
                return true;
            }
        } catch (Exception e) {
            System.err.println("Failed to start proxy: " + e.getMessage());
            return false;
        }
    }

    public boolean stopProxy() {
        try {
            synchronized (HttpApp.this) {
                if (proxy != null) {
                    TcpProxyService toClose = proxy;
                    proxy = null;
                    toClose.close();
                }
                // Stop the session (data persists on disk, NOT deleted)
                if (sessionManager != null) {
                    try {
                        SessionInfo ended = sessionManager.stopSession();
                        if (ended != null) {
                            WireTapLog.info("Session stopped: " + ended.getId() +
                                          ", frames: " + ended.getFrameCount());
                        }
                    } catch (IOException e) {
                        WireTapLog.error("Failed to stop session", e);
                    }
                }
                if (gui != null) {
                    gui.updateProxyUI(false, null);
                }
                return true;
            }
        } catch (Exception e) {
            System.err.println("Failed to stop proxy: " + e.getMessage());
            return false;
        }
    }

    public void shutdown() {
        System.out.println("Shutting down HTTP server...");

        // Stop the proxy first
        stopProxy();

        // Stop AtomForge service
        if (atomForgeService != null) {
            atomForgeService.shutdown();
        }

        // Close session manager
        if (sessionManager != null) {
            try {
                sessionManager.close();
            } catch (IOException e) {
                WireTapLog.error("Failed to close session manager", e);
            }
        }

        // Stop the HTTP server
        if (server != null) {
            server.stop(0); // Stop immediately
            System.out.println("HTTP server stopped");
        }

        // Clear the current instance reference
        currentInstance = null;
    }

    private HttpServer server;

    public void start() throws IOException {
        // Set this as the current instance for LiveBus
        currentInstance = this;

        // Initialize session manager for disk-based session persistence
        try {
            sessionManager = new SessionManager();
            WireTapLog.info("Session storage: " + sessionManager.getSessionsDirectory());
        } catch (IOException e) {
            WireTapLog.error("Failed to initialize session manager", e);
            // Continue without session persistence
        }

        server = HttpServer.create(new InetSocketAddress(httpPort), 0);

        server.createContext("/", new StaticHandler("/public/index.html"));
        server.createContext("/assets/", new StaticDirHandler("/public"));
        server.createContext("/api/tokens", new TokensHandler());
        server.createContext("/api/protocols", new ProtocolsHandler());
        server.createContext("/api/atoms", new AtomsHandler());
        server.createContext("/api/live", new SseLiveHandler());
        server.createContext("/api/session/frames", new SessionFramesHandler());
        server.createContext("/api/sessions", new SessionsHandler());
        server.createContext("/api/sessions/current", new CurrentSessionHandler());
        server.createContext("/api/sessions/clear", new ClearSessionHandler());
        server.createContext("/api/proxy/start", new ProxyStartHandler());
        server.createContext("/api/proxy/stop", new ProxyStopHandler());
        server.createContext("/api/proxy/status", new ProxyStatusHandler());
        server.createContext("/api/connections", new ConnectionsHandler());
        server.createContext("/api/upload", new UploadHandler(aolServerPort));
        server.createContext("/api/decompile-frame", new DecompileFrameHandler());
        server.createContext("/api/decompile-stream", new DecompileStreamHandler());
        server.createContext("/api/atomforge/health", new AtomForgeHealthHandler());
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

            // Use the main startProxy method to ensure session is started
            boolean started = startProxy(listen, host, port);

            StringBuilder json = new StringBuilder("{\"ok\":").append(started);
            json.append(",\"listen\":").append(listen);
            json.append(",\"dest\":\"").append(host).append(":").append(port).append("\"");

            // Include session info if available
            SessionInfo session = getCurrentSessionInfo();
            if (session != null) {
                json.append(",\"sessionId\":\"").append(session.getId()).append("\"");
            }
            json.append("}");

            byte[] b = json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
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

            // Get session info before stopping (for response)
            SessionInfo session = getCurrentSessionInfo();
            String sessionId = session != null ? session.getId() : null;
            long frameCount = session != null ? session.getFrameCount() : 0;

            // Use stopProxy which properly closes the session
            stopProxy();

            StringBuilder json = new StringBuilder("{\"ok\":true");
            if (sessionId != null) {
                json.append(",\"sessionId\":\"").append(sessionId).append("\"");
                json.append(",\"frameCount\":").append(frameCount);
            }
            json.append("}");

            byte[] b = json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
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
                StringBuilder json = new StringBuilder("{\"running\":");
                json.append(isRunning);

                // Include connection information if proxy is running
                if (isRunning && proxy != null) {
                    ConnectionRegistry registry = proxy.getConnectionRegistry();
                    json.append(",\"connections\":");
                    json.append(registry.toJson());
                }

                json.append("}");
                byte[] b = json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
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

    private final class ConnectionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }

            synchronized (HttpApp.this) {
                if (proxy != null && proxy.isRunning()) {
                    ConnectionRegistry registry = proxy.getConnectionRegistry();
                    String json = registry.toJson();
                    byte[] b = json.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    exchange.sendResponseHeaders(200, b.length);
                    exchange.getResponseBody().write(b);
                } else {
                    // No proxy running
                    String json = "{\"connections\":[],\"totalConnections\":0,\"activeConnections\":0,\"totalFrames\":0}";
                    byte[] b = json.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    exchange.sendResponseHeaders(200, b.length);
                    exchange.getResponseBody().write(b);
                }
                exchange.close();
            }
        }
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

    private final class UploadHandler implements HttpHandler {
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
                new AolExtractor().extract(tmp.toString(), aolServerPort, false, true, writer, null);
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
    

    /**
     * Streams session frames as JSONL directly from disk.
     * Supports query parameters:
     * - sessionId: Specific session ID (defaults to current session)
     * - connectionId: Filter by connection ID
     */
    private final class SessionFramesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }

            if (sessionManager == null) {
                sendStatus(exchange, 503, "Session manager not available");
                return;
            }

            // Parse query parameters
            String query = exchange.getRequestURI().getQuery();
            String sessionId = null;
            String connectionIdFilter = null;

            if (query != null) {
                for (String param : query.split("&")) {
                    String[] keyValue = param.split("=", 2);
                    if (keyValue.length == 2) {
                        String key = keyValue[0];
                        String value = java.net.URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                        if ("sessionId".equals(key)) {
                            sessionId = value;
                        } else if ("connectionId".equals(key)) {
                            connectionIdFilter = value;
                        }
                    }
                }
            }

            // Default to current session if no sessionId specified
            if (sessionId == null) {
                SessionInfo current = sessionManager.getCurrentSession();
                if (current != null) {
                    sessionId = current.getId();
                } else {
                    // No active session - return empty JSONL
                    exchange.getResponseHeaders().set("Content-Type", "application/x-ndjson; charset=utf-8");
                    exchange.sendResponseHeaders(200, 0);
                    exchange.getResponseBody().close();
                    exchange.close();
                    return;
                }
            }

            // Stream frames directly from disk as JSONL
            exchange.getResponseHeaders().set("Content-Type", "application/x-ndjson; charset=utf-8");
            exchange.sendResponseHeaders(200, 0); // Chunked encoding

            try (OutputStream os = exchange.getResponseBody()) {
                long count = sessionManager.streamSessionFrames(sessionId, os, connectionIdFilter);
                WireTapLog.debug("SessionFrames: streamed " + count + " frames for session " + sessionId);
            } catch (IOException e) {
                WireTapLog.error("Failed to stream session frames", e);
                // Response already started, can't send error status
            } finally {
                exchange.close();
            }
        }
    }

    /**
     * Lists all sessions with metadata.
     */
    private final class SessionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }

            if (sessionManager == null) {
                sendJson(exchange, "{\"sessions\":[],\"error\":\"Session manager not available\"}");
                return;
            }

            try {
                List<SessionInfo> sessions = sessionManager.listSessions();
                StringBuilder json = new StringBuilder("{\"sessions\":[");
                for (int i = 0; i < sessions.size(); i++) {
                    if (i > 0) json.append(",");
                    json.append(sessions.get(i).toJson());
                }
                json.append("],\"totalDiskUsage\":").append(sessionManager.getTotalDiskUsage());
                json.append(",\"sessionsDirectory\":\"").append(escapeJson(sessionManager.getSessionsDirectory().toString())).append("\"");
                json.append("}");
                sendJson(exchange, json.toString());
            } catch (IOException e) {
                sendJson(exchange, "{\"sessions\":[],\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    /**
     * Returns the current active session info.
     */
    private final class CurrentSessionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }

            if (sessionManager == null) {
                sendJson(exchange, "{\"active\":false,\"error\":\"Session manager not available\"}");
                return;
            }

            SessionInfo current = sessionManager.getCurrentSession();
            if (current != null) {
                StringBuilder json = new StringBuilder("{\"active\":true,\"session\":");
                json.append(current.toJson());
                json.append("}");
                sendJson(exchange, json.toString());
            } else {
                // Check for recoverable sessions
                try {
                    List<SessionInfo> recoverable = sessionManager.findRecoverableSessions();
                    if (!recoverable.isEmpty()) {
                        SessionInfo toRecover = recoverable.get(0);
                        StringBuilder json = new StringBuilder("{\"active\":false,\"recoverable\":true,\"session\":");
                        json.append(toRecover.toJson());
                        json.append("}");
                        sendJson(exchange, json.toString());
                    } else {
                        sendJson(exchange, "{\"active\":false}");
                    }
                } catch (IOException e) {
                    sendJson(exchange, "{\"active\":false,\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
                }
            }
        }
    }

    /**
     * Clears a session or all sessions.
     * POST /api/sessions/clear - Clear all non-active sessions
     * POST /api/sessions/clear?sessionId=xxx - Clear specific session
     */
    private final class ClearSessionHandler implements HttpHandler {
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

            if (sessionManager == null) {
                sendJson(exchange, "{\"success\":false,\"error\":\"Session manager not available\"}");
                return;
            }

            // Parse query for specific sessionId
            String query = exchange.getRequestURI().getQuery();
            String sessionId = null;
            if (query != null && query.contains("sessionId=")) {
                for (String param : query.split("&")) {
                    String[] keyValue = param.split("=", 2);
                    if (keyValue.length == 2 && "sessionId".equals(keyValue[0])) {
                        sessionId = java.net.URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                        break;
                    }
                }
            }

            try {
                if (sessionId != null) {
                    // Delete specific session
                    boolean deleted = sessionManager.deleteSession(sessionId);
                    sendJson(exchange, "{\"success\":" + deleted + ",\"deleted\":1}");
                } else {
                    // Clear all sessions
                    int deleted = sessionManager.clearAllSessions();
                    sendJson(exchange, "{\"success\":true,\"deleted\":" + deleted + "}");
                }
            } catch (IOException e) {
                sendJson(exchange, "{\"success\":false,\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    private final class DecompileFrameHandler implements HttpHandler {
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

            try {
                if (atomForgeService == null) {
                    WireTapLog.warn("DecompileFrame: AtomForge service not initialized");
                    sendJson(exchange, "{\"success\":false,\"error\":\"AtomForge service not initialized\"}");
                    return;
                }

                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                WireTapLog.debug("DecompileFrame: Received request, body length: " + (body != null ? body.length() : 0));

                if (body == null || body.trim().isEmpty()) {
                    WireTapLog.warn("DecompileFrame: Empty request body");
                    sendJson(exchange, "{\"success\":false,\"error\":\"Empty request body\"}");
                    return;
                }

                // Manual JSON parsing to extract fullHex field (avoids broken JsonUtil parser)
                String fullHex = null;
                int fullHexIndex = body.indexOf("\"fullHex\"");
                if (fullHexIndex >= 0) {
                    int colonIndex = body.indexOf(":", fullHexIndex);
                    if (colonIndex >= 0) {
                        int quoteStart = body.indexOf("\"", colonIndex);
                        if (quoteStart >= 0) {
                            int quoteEnd = body.indexOf("\"", quoteStart + 1);
                            if (quoteEnd >= 0) {
                                fullHex = body.substring(quoteStart + 1, quoteEnd);
                            }
                        }
                    }
                }

                WireTapLog.debug("DecompileFrame: Extracted fullHex: " + (fullHex != null ? fullHex.substring(0, Math.min(20, fullHex.length())) + "..." : "null"));

                if (fullHex == null || fullHex.isEmpty()) {
                    WireTapLog.warn("DecompileFrame: Missing or empty fullHex parameter");
                    sendJson(exchange, "{\"success\":false,\"error\":\"Missing fullHex parameter\"}");
                    return;
                }

                // Create minimal FrameSummary with just fullHex
                FrameSummary frame = new FrameSummary();
                frame.fullHex = fullHex;

                // Decompile synchronously
                WireTapLog.debug("DecompileFrame: Calling AtomForge decompileSingleFrame...");
                String fdoSource = atomForgeService.decompileSingleFrame(frame);
                WireTapLog.debug("DecompileFrame: Decompilation completed, result length: " + (fdoSource != null ? fdoSource.length() : 0));

                // Return result
                StringBuilder json = new StringBuilder("{\"success\":true");
                json.append(",\"fdoSource\":\"").append(escapeJson(fdoSource)).append("\"");
                json.append("}");
                sendJson(exchange, json.toString());
            } catch (Exception e) {
                String errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getName();
                WireTapLog.error("DecompileFrame: Error during decompilation", e);
                sendJson(exchange, "{\"success\":false,\"error\":\"" + escapeJson(errorMsg) + "\"}");
            } finally {
                exchange.close();
            }
        }
    }

    private final class DecompileStreamHandler implements HttpHandler {
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

            try {
                if (atomForgeService == null) {
                    WireTapLog.warn("DecompileStream: AtomForge service not initialized");
                    sendJson(exchange, "{\"success\":false,\"error\":\"AtomForge service not initialized\"}");
                    return;
                }

                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                WireTapLog.debug("DecompileStream: Received request, body length: " + (body != null ? body.length() : 0));

                if (body == null || body.trim().isEmpty()) {
                    WireTapLog.warn("DecompileStream: Empty request body");
                    sendJson(exchange, "{\"success\":false,\"error\":\"Empty request body\"}");
                    return;
                }

                // Parse JSON array of frame hex strings
                // Expected format: {"frames": ["5A...", "5A...", ...]}
                List<FrameSummary> framesToDecompile = new ArrayList<>();

                // Find the "frames" array in JSON
                int framesIndex = body.indexOf("\"frames\"");
                if (framesIndex >= 0) {
                    int colonIndex = body.indexOf(":", framesIndex);
                    if (colonIndex >= 0) {
                        int arrayStart = body.indexOf("[", colonIndex);
                        if (arrayStart >= 0) {
                            int arrayEnd = body.lastIndexOf("]");
                            if (arrayEnd > arrayStart) {
                                String arrayContent = body.substring(arrayStart + 1, arrayEnd);

                                // Parse hex strings from array (simple parser for quoted strings)
                                int pos = 0;
                                while (pos < arrayContent.length()) {
                                    int quoteStart = arrayContent.indexOf("\"", pos);
                                    if (quoteStart < 0) break;

                                    int quoteEnd = arrayContent.indexOf("\"", quoteStart + 1);
                                    if (quoteEnd < 0) break;

                                    String hexString = arrayContent.substring(quoteStart + 1, quoteEnd);
                                    if (!hexString.isEmpty()) {
                                        FrameSummary frame = new FrameSummary();
                                        frame.fullHex = hexString;
                                        framesToDecompile.add(frame);
                                    }

                                    pos = quoteEnd + 1;
                                }
                            }
                        }
                    }
                }

                WireTapLog.debug("DecompileStream: Parsed " + framesToDecompile.size() + " frames from request");

                if (framesToDecompile.isEmpty()) {
                    sendJson(exchange, "{\"success\":false,\"error\":\"No frames provided or invalid format\"}");
                    return;
                }

                // Decompile all frames
                WireTapLog.debug("DecompileStream: Calling AtomForge decompileMultipleFrames...");
                String fdoSource = atomForgeService.decompileMultipleFrames(framesToDecompile);
                WireTapLog.debug("DecompileStream: Decompilation completed, result length: " + (fdoSource != null ? fdoSource.length() : 0));

                // Return result with frame count
                StringBuilder json = new StringBuilder("{\"success\":true");
                json.append(",\"fdoSource\":\"").append(escapeJson(fdoSource)).append("\"");
                json.append(",\"frameCount\":").append(framesToDecompile.size());
                json.append("}");
                sendJson(exchange, json.toString());
            } catch (Exception e) {
                String errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getName();
                WireTapLog.error("DecompileStream: Error during decompilation", e);
                sendJson(exchange, "{\"success\":false,\"error\":\"" + escapeJson(errorMsg) + "\"}");
            } finally {
                exchange.close();
            }
        }
    }

    private final class AtomForgeHealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCors(exchange.getResponseHeaders());
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendStatus(exchange, 405, "Method Not Allowed");
                return;
            }

            if (atomForgeService == null) {
                sendJson(exchange, "{\"available\":false,\"error\":\"AtomForge service not initialized\"}");
                return;
            }

            atomForgeService.checkHealth().thenAccept(result -> {
                try {
                    StringBuilder json = new StringBuilder("{\"available\":");
                    json.append(result.isAvailable());
                    if (result.isAvailable()) {
                        json.append(",\"version\":\"").append(escapeJson(result.getVersion())).append("\"");
                        json.append(",\"daemon_status\":\"").append(escapeJson(result.getDaemonStatus())).append("\"");
                    } else {
                        json.append(",\"error\":\"").append(escapeJson(result.getErrorMessage())).append("\"");
                    }
                    json.append("}");
                    sendJson(exchange, json.toString());
                } catch (Exception e) {
                    try {
                        sendStatus(exchange, 500, "Internal Server Error");
                    } catch (IOException ignored) {}
                }
            }).exceptionally(ex -> {
                try {
                    sendStatus(exchange, 500, "Health check failed: " + ex.getMessage());
                } catch (IOException ignored) {}
                return null;
            });
        }
    }


    private void sendJson(HttpExchange exchange, String json) throws IOException {
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(data);
        }
        exchange.close();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

}


