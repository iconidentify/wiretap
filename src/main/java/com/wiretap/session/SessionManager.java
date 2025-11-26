package com.wiretap.session;

import com.wiretap.core.WireTapLog;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Manages session lifecycle, storage directories, and provides APIs for
 * creating, listing, and recovering sessions.
 * <p>
 * Session files are stored in platform-specific user data directories:
 * - macOS: ~/Library/Application Support/WireTap/sessions/
 * - Linux: ~/.local/share/wiretap/sessions/
 * - Windows: %APPDATA%/WireTap/sessions/
 */
public final class SessionManager implements Closeable {
    private static final String APP_NAME = "WireTap";
    private static final String SESSIONS_DIR = "sessions";
    private static final String JSONL_EXTENSION = ".jsonl";
    private static final String META_EXTENSION = ".meta.json";

    private final Path sessionsDirectory;
    private volatile SessionWriter currentWriter;
    private volatile SessionInfo currentSession;

    public SessionManager() throws IOException {
        this.sessionsDirectory = determineSessionsDirectory();
        ensureDirectoryExists(sessionsDirectory);
        WireTapLog.info("SessionManager initialized: " + sessionsDirectory);
    }

    /**
     * Creates a SessionManager with a custom directory (for testing).
     */
    public SessionManager(Path customDirectory) throws IOException {
        this.sessionsDirectory = customDirectory;
        ensureDirectoryExists(sessionsDirectory);
        WireTapLog.info("SessionManager initialized with custom path: " + sessionsDirectory);
    }

    /**
     * Starts a new capture session.
     * If a session is already active, it will be closed first.
     *
     * @return The new session info
     */
    public synchronized SessionInfo startSession() throws IOException {
        // Close existing session if any
        if (currentWriter != null) {
            stopSession();
        }

        // Generate new session
        String sessionId = SessionInfo.generateId();
        SessionInfo info = new SessionInfo(sessionId);

        // Create session files
        Path sessionFile = sessionsDirectory.resolve(sessionId + JSONL_EXTENSION);
        currentWriter = new SessionWriter(sessionFile, info);
        currentSession = info;

        // Save initial metadata
        saveMetadata(info);

        WireTapLog.info("Session started: " + sessionId);
        return info;
    }

    /**
     * Stops the current session.
     *
     * @return The ended session info, or null if no session was active
     */
    public synchronized SessionInfo stopSession() throws IOException {
        if (currentWriter == null) {
            return null;
        }

        SessionWriter writer = currentWriter;
        SessionInfo info = currentSession;

        currentWriter = null;
        currentSession = null;

        // Close the writer (this marks the session as ended)
        writer.close();

        // Update metadata
        saveMetadata(info);

        WireTapLog.info("Session stopped: " + info.getId() + ", frames: " + info.getFrameCount());
        return info;
    }

    /**
     * Adds a frame to the current session.
     *
     * @param jsonlLine The frame JSONL line
     * @return true if the frame was written, false if no session is active
     */
    public boolean addFrame(String jsonlLine) {
        SessionWriter writer = currentWriter;
        if (writer == null) {
            return false;
        }
        writer.append(jsonlLine);
        return true;
    }

    /**
     * Returns the current active session info, or null if no session is active.
     */
    public SessionInfo getCurrentSession() {
        return currentSession;
    }

    /**
     * Checks if a session is currently active.
     */
    public boolean hasActiveSession() {
        return currentSession != null;
    }

    /**
     * Returns the frame count for the current session.
     */
    public long getCurrentFrameCount() {
        SessionWriter writer = currentWriter;
        return writer != null ? writer.getFrameCount() : 0;
    }

    /**
     * Returns the file size for the current session.
     */
    public long getCurrentFileSizeBytes() {
        SessionInfo info = currentSession;
        return info != null ? info.getFileSizeBytes() : 0;
    }

    /**
     * Lists all sessions (most recent first).
     */
    public List<SessionInfo> listSessions() throws IOException {
        List<SessionInfo> sessions = new ArrayList<>();

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(sessionsDirectory, "*" + META_EXTENSION)) {
            for (Path metaFile : stream) {
                try {
                    String json = Files.readString(metaFile, StandardCharsets.UTF_8);
                    SessionInfo info = SessionInfo.fromJson(json);
                    sessions.add(info);
                } catch (Exception e) {
                    WireTapLog.warn("Failed to load session metadata: " + metaFile + " - " + e.getMessage());
                }
            }
        }

        // Sort by start time, most recent first
        sessions.sort(Comparator.comparing(SessionInfo::getStartTime).reversed());
        return sessions;
    }

    /**
     * Gets session info by ID.
     */
    public SessionInfo getSession(String sessionId) throws IOException {
        Path metaFile = sessionsDirectory.resolve(sessionId + META_EXTENSION);
        if (!Files.exists(metaFile)) {
            return null;
        }
        String json = Files.readString(metaFile, StandardCharsets.UTF_8);
        return SessionInfo.fromJson(json);
    }

    /**
     * Streams session frames to an output stream.
     * This reads directly from disk without loading everything into memory.
     *
     * @param sessionId The session ID
     * @param output The output stream to write to
     * @param connectionIdFilter Optional connection ID filter (null for all frames)
     * @return The number of frames written
     */
    public long streamSessionFrames(String sessionId, OutputStream output, String connectionIdFilter)
            throws IOException {
        Path sessionFile = sessionsDirectory.resolve(sessionId + JSONL_EXTENSION);
        if (!Files.exists(sessionFile)) {
            throw new IOException("Session file not found: " + sessionId);
        }

        long count = 0;
        try (BufferedReader reader = Files.newBufferedReader(sessionFile, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Apply connection filter if specified
                if (connectionIdFilter != null && !connectionIdFilter.isEmpty()) {
                    if (!line.contains("\"connectionId\":\"" + connectionIdFilter + "\"")) {
                        continue;
                    }
                }

                output.write(line.getBytes(StandardCharsets.UTF_8));
                output.write('\n');
                count++;

                // Periodic flush for streaming
                if (count % 100 == 0) {
                    output.flush();
                }
            }
        }

        output.flush();
        return count;
    }

    /**
     * Counts frames in a session, optionally filtered by connection.
     */
    public long countSessionFrames(String sessionId, String connectionIdFilter) throws IOException {
        Path sessionFile = sessionsDirectory.resolve(sessionId + JSONL_EXTENSION);
        if (!Files.exists(sessionFile)) {
            return 0;
        }

        long count = 0;
        try (BufferedReader reader = Files.newBufferedReader(sessionFile, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (connectionIdFilter != null && !connectionIdFilter.isEmpty()) {
                    if (!line.contains("\"connectionId\":\"" + connectionIdFilter + "\"")) {
                        continue;
                    }
                }
                count++;
            }
        }
        return count;
    }

    /**
     * Deletes a session by ID.
     *
     * @return true if the session was deleted
     */
    public boolean deleteSession(String sessionId) throws IOException {
        // Can't delete the current session
        if (currentSession != null && currentSession.getId().equals(sessionId)) {
            throw new IOException("Cannot delete active session. Stop the session first.");
        }

        Path sessionFile = sessionsDirectory.resolve(sessionId + JSONL_EXTENSION);
        Path metaFile = sessionsDirectory.resolve(sessionId + META_EXTENSION);

        boolean deleted = false;
        if (Files.exists(sessionFile)) {
            Files.delete(sessionFile);
            deleted = true;
        }
        if (Files.exists(metaFile)) {
            Files.delete(metaFile);
            deleted = true;
        }

        if (deleted) {
            WireTapLog.info("Deleted session: " + sessionId);
        }
        return deleted;
    }

    /**
     * Clears all sessions except the current active one.
     *
     * @return The number of sessions deleted
     */
    public int clearAllSessions() throws IOException {
        List<SessionInfo> sessions = listSessions();
        int deleted = 0;

        for (SessionInfo session : sessions) {
            if (currentSession != null && currentSession.getId().equals(session.getId())) {
                continue; // Skip active session
            }
            try {
                if (deleteSession(session.getId())) {
                    deleted++;
                }
            } catch (IOException e) {
                WireTapLog.warn("Failed to delete session: " + session.getId() + " - " + e.getMessage());
            }
        }

        return deleted;
    }

    /**
     * Gets the sessions directory path.
     */
    public Path getSessionsDirectory() {
        return sessionsDirectory;
    }

    /**
     * Returns total disk usage of all sessions.
     */
    public long getTotalDiskUsage() throws IOException {
        long total = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(sessionsDirectory)) {
            for (Path file : stream) {
                if (Files.isRegularFile(file)) {
                    total += Files.size(file);
                }
            }
        }
        return total;
    }

    /**
     * Finds any sessions that were left active (from crash recovery).
     * These can be offered to the user for restoration.
     */
    public List<SessionInfo> findRecoverableSessions() throws IOException {
        return listSessions().stream()
                .filter(SessionInfo::isActive)
                .collect(Collectors.toList());
    }

    /**
     * Recovers an interrupted session by marking it as ended.
     */
    public SessionInfo recoverSession(String sessionId) throws IOException {
        SessionInfo info = getSession(sessionId);
        if (info == null) {
            return null;
        }

        if (info.isActive()) {
            // Count actual frames in file
            long actualFrameCount = countSessionFrames(sessionId, null);

            // Update metadata
            Path sessionFile = sessionsDirectory.resolve(sessionId + JSONL_EXTENSION);
            long fileSize = Files.exists(sessionFile) ? Files.size(sessionFile) : 0;

            SessionInfo recovered = new SessionInfo(
                    info.getId(),
                    info.getStartTime(),
                    java.time.Instant.now(),
                    actualFrameCount,
                    fileSize,
                    false // Mark as no longer active
            );

            saveMetadata(recovered);
            WireTapLog.info("Recovered session: " + sessionId + ", frames: " + actualFrameCount);
            return recovered;
        }

        return info;
    }

    @Override
    public synchronized void close() throws IOException {
        if (currentWriter != null) {
            stopSession();
        }
        WireTapLog.info("SessionManager closed");
    }

    // ========== Private Helpers ==========

    private void saveMetadata(SessionInfo info) throws IOException {
        Path metaFile = sessionsDirectory.resolve(info.getId() + META_EXTENSION);
        Files.writeString(metaFile, info.toJson(), StandardCharsets.UTF_8);
    }

    private static void ensureDirectoryExists(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            Files.createDirectories(dir);
        }
    }

    /**
     * Determines the platform-specific sessions directory.
     */
    private static Path determineSessionsDirectory() {
        String os = System.getProperty("os.name", "").toLowerCase();
        Path baseDir;

        if (os.contains("mac")) {
            // macOS: ~/Library/Application Support/WireTap/sessions/
            String home = System.getProperty("user.home");
            baseDir = Path.of(home, "Library", "Application Support", APP_NAME);
        } else if (os.contains("win")) {
            // Windows: %APPDATA%/WireTap/sessions/
            String appData = System.getenv("APPDATA");
            if (appData == null || appData.isEmpty()) {
                appData = System.getProperty("user.home");
            }
            baseDir = Path.of(appData, APP_NAME);
        } else {
            // Linux/Unix: ~/.local/share/wiretap/sessions/
            String home = System.getProperty("user.home");
            baseDir = Path.of(home, ".local", "share", APP_NAME.toLowerCase());
        }

        return baseDir.resolve(SESSIONS_DIR);
    }
}
