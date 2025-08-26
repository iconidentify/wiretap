package com.wiretap.web;

import com.wiretap.extractor.FrameSummary;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages capture sessions and persistence for the AOL analyzer.
 */
public class CaptureLibrary {
    private static final String LIBRARY_DIR = "captures";
    private static final String SESSIONS_FILE = "sessions.json";

    private final Path libraryPath;
    private final Path sessionsPath;
    private final Gson gson;
    private final AtomicLong sessionIdCounter;

    // In-memory session cache
    private final Map<String, CaptureSession> activeSessions = new ConcurrentHashMap<>();
    
    public CaptureLibrary() {
        this.libraryPath = Paths.get(LIBRARY_DIR);
        this.sessionsPath = libraryPath.resolve(SESSIONS_FILE);
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.sessionIdCounter = new AtomicLong(System.currentTimeMillis());

        try {
            Files.createDirectories(libraryPath);
            loadSessions();
        } catch (IOException e) {
            System.err.println("Failed to initialize capture library: " + e.getMessage());
        }
    }
    
    /**
     * Creates a new capture session.
     */
    public CaptureSession createSession(String name, String source, boolean isLive) {
        String id = generateSessionId();
        CaptureSession session = new CaptureSession(
            id, name, source, isLive, 
            Instant.now().toString(), 
            new ArrayList<>(), 
            new ArrayList<>()
        );
        activeSessions.put(id, session);
        return session;
    }
    
    /**
     * Adds frames to an existing session.
     */
    public void addFrames(String sessionId, List<FrameSummary> frames) {
        CaptureSession session = activeSessions.get(sessionId);
        if (session != null) {
            session.frames.addAll(frames);
            session.frameCount = session.frames.size();
            session.lastUpdated = Instant.now().toString();
        }
    }
    
    /**
     * Saves a session to disk.
     */
    public boolean saveSession(String sessionId) {
        CaptureSession session = activeSessions.get(sessionId);
        if (session == null) return false;
        
        try {
            // Save session metadata
            session.lastSaved = Instant.now().toString();
            saveSessions();
            
            // Save frames to separate file
            Path framesPath = libraryPath.resolve(sessionId + ".jsonl");
            try (BufferedWriter writer = Files.newBufferedWriter(framesPath)) {
                for (FrameSummary frame : session.frames) {
                    writer.write(gson.toJson(frame));
                    writer.newLine();
                }
            }
            
            return true;
        } catch (IOException e) {
            System.err.println("Failed to save session " + sessionId + ": " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Loads a session from disk.
     */
    public CaptureSession loadSession(String sessionId) {
        System.out.println("[DEBUG] CaptureLibrary.loadSession called for: " + sessionId);
        try {
            // First check if session exists in memory
            CaptureSession existingSession = activeSessions.get(sessionId);
            if (existingSession != null) {
                System.out.println("[DEBUG] Session found in memory: " + sessionId);
                // Load frames if not already loaded
                if (existingSession.frames == null || existingSession.frames.isEmpty()) {
                    loadFramesForSession(existingSession);
                }
                return existingSession;
            }
            
            // Session not in memory, try to load from sessions.json first
            try {
                loadSessions(); // Reload sessions from disk
                existingSession = activeSessions.get(sessionId);
                if (existingSession != null) {
                    System.out.println("[DEBUG] Session found in sessions.json: " + sessionId);
                    loadFramesForSession(existingSession);
                    return existingSession;
                }
            } catch (IOException e) {
                System.err.println("Failed to reload sessions from disk: " + e.getMessage());
            }
            
            // If we get here, the session doesn't exist
            System.out.println("[DEBUG] Session not found: " + sessionId);
            return null;
            
        } catch (Exception e) {
            System.err.println("Failed to load session " + sessionId + ": " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Loads frames for an existing session from disk.
     */
    private void loadFramesForSession(CaptureSession session) {
        try {
            Path framesPath = libraryPath.resolve(session.id + ".jsonl");
            System.out.println("[DEBUG] Loading frames from: " + framesPath);
            if (!Files.exists(framesPath)) {
                System.out.println("[DEBUG] Frames file does not exist: " + framesPath);
                session.frames = new ArrayList<>();
                session.frameCount = 0;
                return;
            }
            
            List<FrameSummary> frames = new ArrayList<>();
            try (BufferedReader reader = Files.newBufferedReader(framesPath)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        FrameSummary frame = gson.fromJson(line, FrameSummary.class);
                        frames.add(frame);
                    }
                }
            }
            
            session.frames = frames;
            session.frameCount = frames.size();
            System.out.println("[DEBUG] Loaded " + frames.size() + " frames for session " + session.id);
            
        } catch (IOException e) {
            System.err.println("Failed to load frames for session " + session.id + ": " + e.getMessage());
            session.frames = new ArrayList<>();
            session.frameCount = 0;
        }
    }
    
    
    /**
     * Gets all saved sessions.
     */
    public List<CaptureSession> getAllSessions() {
        return new ArrayList<>(activeSessions.values());
    }
    
    /**
     * Deletes a session.
     */
    public boolean deleteSession(String sessionId) {
        try {
            activeSessions.remove(sessionId);

            // Delete files
            Path framesPath = libraryPath.resolve(sessionId + ".jsonl");
            Files.deleteIfExists(framesPath);

            saveSessions();
            return true;
        } catch (IOException e) {
            System.err.println("Failed to delete session " + sessionId + ": " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Gets the library path for external access.
     */
    public Path getLibraryPath() {
        return libraryPath;
    }
    
    private String generateSessionId() {
        return "session_" + sessionIdCounter.getAndIncrement();
    }
    
    private void loadSessions() throws IOException {
        if (!Files.exists(sessionsPath)) return;
        
        try (BufferedReader reader = Files.newBufferedReader(sessionsPath)) {
            List<CaptureSession> sessions = gson.fromJson(reader, new TypeToken<List<CaptureSession>>(){}.getType());
            if (sessions != null) {
                for (CaptureSession session : sessions) {
                    activeSessions.put(session.id, session);
                }
            }
        }
    }
    
    private void saveSessions() throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(sessionsPath)) {
            gson.toJson(new ArrayList<>(activeSessions.values()), writer);
        }
    }
    
    
    // Data classes
    public static class CaptureSession {
        public String id;
        public String name;
        public String source; // "pcap", "live", "file"
        public boolean isLive;
        public String createdAt;
        public String lastUpdated;
        public String lastSaved;
        public int frameCount;
        public List<String> tags;
        public List<FrameSummary> frames; // Only in memory, not serialized
        
        public CaptureSession(String id, String name, String source, boolean isLive, 
                            String createdAt, List<FrameSummary> frames, List<String> tags) {
            this.id = id;
            this.name = name;
            this.source = source;
            this.isLive = isLive;
            this.createdAt = createdAt;
            this.lastUpdated = createdAt;
            this.frames = frames;
            this.tags = tags;
            this.frameCount = frames.size();
        }
    }
}
